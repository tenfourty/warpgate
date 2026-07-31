use std::borrow::Cow;
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Future, FutureExt};
use russh::keys::{PublicKey, PublicKeyBase64};
use russh::server::ChannelOpenHandle;
use russh::{ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Sig};
use termcolor::Color;
use time::OffsetDateTime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, broadcast, oneshot};
use tracing::*;
use url::Url;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::eventhub::{EventHub, EventSender};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Secret, SessionId, TargetOptions, WarpgateError};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::step_up::{get_pubkey_last_sso_at, is_fresh, update_pubkey_last_sso_at};
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{self, TerminalRecorder, TrafficConnectionParams, TrafficRecorder};
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, Services, TargetAuthorization, WarpgateServerHandle,
    authorize_for_target, authorize_for_target_by_name, authorize_ticket, consume_ticket,
};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;

use super::channel_registry::{Channel, ChannelRegistry};
use super::channel_writer::ChannelWriter;
use super::event_intake::EventIntake;
use super::russh_handler::ServerHandlerEvent;
use super::service_output::ServiceOutput;
use super::session_handle::SessionHandleCommand;
use crate::server::get_allowed_auth_methods;
use crate::server::service_output::{VisualConnectionChainItem, paint_fg};
use crate::server::target_menu::{MenuEvent, spawn_target_menu_loop};
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCCommandReply,
    RCEvent, RCState, RemoteClient, ResolvedSshChainHost, ServerChannelId, SshClientError,
    SshRecordingMetadata, X11Request, resolve_ssh_chain,
};

const EVENT_QUEUE_CAPACITY: usize = 128;

/// Cap on how deep [`ServerSession::send_command_and_wait`] may re-enter itself
/// before it stops dispatching events and buffers them instead. Ordinary
/// traffic stays at a depth of one or two; the cap only exists so a flood of
/// concurrent channel requests can't grow the stack without bound.
const MAX_NESTED_COMMAND_WAITS: usize = 16;

/// How long a teardown waits for queued writes to reach the client before
/// giving up on them.
const DISCONNECT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum TargetSelection {
    None,
    Menu,
    NotFound(String),
    /// Carries the proof of authorization, which carries the target — so being
    /// in this state at all means authorization was checked for exactly the
    /// host we're about to dial.
    Found(TargetAuthorization),
}

#[derive(Debug)]
pub enum Event {
    Command(SessionHandleCommand),
    ServerHandler(ServerHandlerEvent),
    ConsoleInput(Bytes),
    ServiceOutput(Bytes),
    Client(RCEvent),
    MenuRedraw(u16, u16),
    Menu(MenuEvent),
    ServerChannelOpenResult(Uuid, Result<ServerChannelId, russh::Error>),
}

/// State of an in-flight auto-continue web-approval wait, carried across
/// keyboard-interactive rounds.
///
/// `waits_used` is deliberately **not** here: this struct is dropped on every
/// terminal return, so a counter living here would reset and the cap could
/// never fire. It lives on [`ServerSession`] instead.
struct WebApprovalWait {
    /// Early-wake signal for this state id. `Option` so a `Closed` receiver can
    /// be dropped — a `select!` on a permanently-closed receiver returns
    /// instantly and would spin rounds at client RTT.
    receiver: Option<broadcast::Receiver<AuthResult>>,
    /// Identifies the auth state this wait is bound to. `AuthState` carries no
    /// id of its own at v0.28.6, so the wait is keyed on the security key the
    /// state generates for itself — freshly random per state, and the very
    /// string the user is asked to match in the browser. A round whose current
    /// state shows a different key discards the wait, so one principal's
    /// approval can never wake another principal's session.
    identification_string: String,
    /// Budget expiry, set lazily at the first zero-prompt round so that time
    /// spent typing an OTP does not eat the SSO budget.
    deadline: Option<Instant>,
    round: u8,
    /// Single source of truth for whether the approval URL has been emitted.
    url_shown: bool,
    /// Set on the round that delivered the not-confirmed message; the next
    /// round rejects.
    farewell: bool,
}

struct PendingKeyboardInteractiveAuth {
    otp_prompt_sent: bool,
    web_approval_wait: Option<WebApprovalWait>,
}

impl PendingKeyboardInteractiveAuth {
    const fn fresh() -> Self {
        Self {
            otp_prompt_sent: false,
            web_approval_wait: None,
        }
    }
}

/// How many browser-approval waits one TCP connection may start.
///
/// This is the **only** bound on a keyboard-interactive web-approval round —
/// both the auto-continue path (where a wait is a live broadcast subscription)
/// and the manual Press-Enter path (where the wait is the human) are charged
/// against it. There is deliberately no second, per-round counter: one lived on
/// `PendingKeyboardInteractiveAuth`, which is dropped by every terminal return,
/// so it reset whenever it mattered.
///
/// This is the server-owned bound. The client's `number_of_password_prompts` is
/// not a control we own, and russh's `max_auth_attempts` is a dead field —
/// declared and defaulted, but nothing in the crate enforces it.
const MAX_WEB_AUTH_WAITS: u8 = 3;

/// Charge one wait against the per-connection budget, returning the new count
/// and whether the cap has been exceeded.
///
/// Increment-before-compare is deliberate: it permits exactly
/// [`MAX_WEB_AUTH_WAITS`] waits and rejects at the start of the next one. The
/// add saturates because post-cap attempts keep incrementing before they are
/// rejected, and a wrapping `u8` would silently hand the client a fresh budget.
const fn bump_waits(used: u8) -> (u8, bool) {
    let used = used.saturating_add(1);
    (used, used > MAX_WEB_AUTH_WAITS)
}

/// Consume the previous round's pending state and produce this round's, moving
/// the web-approval wait — and therefore its live broadcast receiver — forward.
///
/// The previous struct is consumed by value here rather than by a closure that
/// only borrows what it needs, which is what makes the receiver actually
/// survive: dropped, it leaves zero subscribers at the moment `complete()`
/// sends, and the approval is only noticed at the next poll tick.
fn carry_forward(previous: PendingKeyboardInteractiveAuth) -> PendingKeyboardInteractiveAuth {
    PendingKeyboardInteractiveAuth {
        otp_prompt_sent: false,
        web_approval_wait: previous.web_approval_wait,
    }
}

enum ProbeState {
    /// New session
    NoAttempt,
    /// Charged with suspicious probing
    Probe {
        username: String,
        method: &'static str,
    },
    /// Vindicated by a successful auth or guilty as charged with a failed login
    Settled,
}

struct CachedSuccessfulTicketAuth {
    ticket: Secret<String>,
    user_info: AuthStateUserInfo,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum TrafficRecorderKey {
    Tcp(String, u32),
    Socket(String),
}

pub struct ServerSession {
    pub id: SessionId,
    user_info: Option<AuthStateUserInfo>,
    authentication_type: Option<String>,
    session_handle: Option<russh::server::Handle>,
    channels: ChannelRegistry,
    /// Client-side events for channel ids no registered channel carries yet.
    /// They can only refer to a server-initiated open whose
    /// [`Event::ServerChannelOpenResult`] hasn't been processed — until it is,
    /// the client id (and thus the owning channel) is unknown, so unlike
    /// target-side events they can't be held on the channel itself.
    deferred_server_events: Vec<ServerHandlerEvent>,
    /// Events taken off the queue past [`MAX_NESTED_COMMAND_WAITS`], replayed by
    /// the main event loop once the nesting unwinds.
    pending_events: VecDeque<Event>,
    /// Nesting depth of [`Self::send_command_and_wait`]. A handler dispatched
    /// from a wait can await a command of its own, so the pump re-enters itself
    /// one stack level deeper per concurrent request.
    command_wait_depth: usize,
    rc_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    target: TargetSelection,
    traffic_recorders: HashMap<TrafficRecorderKey, TrafficRecorder>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
    intake: EventIntake<Event>,
    service_output: ServiceOutput,
    channel_writer: ChannelWriter,
    /// Cached auth state together with the target name it was created for. The
    /// state's `target_name` is fixed at construction and scopes web approvals,
    /// so it can only be reused for that same target.
    auth_state: Option<(Arc<Mutex<AuthState>>, String)>,
    keyboard_interactive_state: Option<PendingKeyboardInteractiveAuth>,
    cached_successful_ticket_auth: Option<CachedSuccessfulTicketAuth>,
    allowed_auth_methods: MethodSet,
    host_key_trust_prompt_active: Arc<AtomicBool>,
    /// Track the state of a client snooping around pre-auth
    probe: ProbeState,
    /// Browser-approval waits started on this connection, on either the
    /// auto-continue or the manual Press-Enter path.
    ///
    /// This lives here, not on `PendingKeyboardInteractiveAuth`, because that
    /// struct is re-stored only on the `Auth::Partial` path and dropped by every
    /// terminal return — a counter there would reset on the next
    /// keyboard-interactive attempt and the cap could never fire. `ServerSession`
    /// is constructed once per accepted TCP stream and dies with the connection,
    /// so the count survives `self.auth_state = None`, every terminal reject, and
    /// any number of fresh `USERAUTH_REQUEST`s.
    web_auth_waits_used: u8,
}

fn session_debug_tag(id: &SessionId, remote_address: &SocketAddr) -> String {
    format!("[{id} - {remote_address}]")
}

fn format_web_auth_instructions(login_url: Option<Url>, identification_string: &str) -> String {
    let spaced_key = identification_string
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let url_line = login_url.map(|u| format!("{u}\n")).unwrap_or_default();
    format!(
        "-----------------------------------------------------------------------\n\
         Please verify the SSH authentication request in your browser.\n\
         {url_line}\n\
         Make sure you're seeing this security key: {spaced_key}\n\
         -----------------------------------------------------------------------\n"
    )
}

fn reject_with_allowed_auth_methods(allowed_auth_methods: MethodSet) -> russh::server::Auth {
    russh::server::Auth::Reject {
        proceed_with_methods: Some(allowed_auth_methods),
        partial_success: false,
    }
}

/// Whether a `WebUserApproval` sitting in `valid_credentials` is evidence that
/// *this* attempt just completed a step-up SSO handshake.
///
/// Two consumers, one question. The freshness gate skips its `last_sso_at` read
/// when the answer is true, and the accept path stamps `last_sso_at` only when
/// the answer is true.
///
/// An approval injected by the web-approval grace-period bypass answers false.
/// It was granted for an earlier attempt - possibly a different session
/// entirely - so counting it would both let the gate through without an SSO
/// handshake and re-stamp the clock, and chained reconnects inside the grace
/// window would slide the step-up window forward forever. A user whose
/// `credential_policy.ssh` legitimately lists `WebUserApproval` reaches exactly
/// that combination, because a policy-raised `Need` is bypassable by design.
const fn web_approval_proves_step_up(approval_present: bool, approval_was_bypassed: bool) -> bool {
    approval_present && !approval_was_bypassed
}

/// How long one auto-continue round waits before handing a packet back to the
/// client.
///
/// A server→client packet has to cross the wire well inside the client's
/// read deadline — an `ServerAliveInterval 30` × `ServerAliveCountMax 3` client
/// gives a 90 s ceiling — and russh cannot emit anything while an auth handler
/// future is pending. Keeping each wait short is also what bounds how long the
/// session's serialized event loop is held, so `Close` and `Disconnect` are
/// serviced within one round.
const WEB_AUTH_POLL_CADENCE: Duration = Duration::from_secs(10);

/// Text shown when the browser approval never arrived within the budget. It has
/// to travel in a final zero-prompt `Auth::Partial`, because `Auth::Reject`
/// carries no message field.
const WEB_AUTH_NOT_CONFIRMED_MESSAGE: &str =
    "\n[!] Browser authentication was not confirmed, please try again.\n";

/// Whether a web-approval round has produced the whole `Auth` reply itself, or
/// whether the caller should keep assembling one.
enum WebApprovalRoundOutcome {
    Continue,
    Return(russh::server::Auth),
}

/// What an auto-continue web-approval round should do next.
#[derive(Debug, PartialEq, Eq)]
enum WebAuthStep {
    Accept,
    PollAgain { include_url: bool },
    Reject { message: Option<String> },
}

/// The whole decision of an auto-continue round, as a pure function.
///
/// It takes the **verdict** that `try_auth_lazy` just returned, never a raw
/// wake event: being woken is not evidence of approval, since the completion
/// signal fires on a browser *rejection* as well. Only an explicit `Accepted`
/// can accept.
///
/// It takes `url_shown` rather than a round number so that URL emission has
/// exactly one source of truth, and it deliberately takes no wait counter — the
/// per-connection wait cap is enforced on the wait-creation path, before this
/// function is reached.
fn next_web_auth_step(
    now: Instant,
    deadline: Option<Instant>,
    url_shown: bool,
    verdict: &AuthResult,
) -> WebAuthStep {
    match verdict {
        // Wins even over an expired budget: by now `_auth_accept`, `complete()`
        // and the `last_sso_at` stamp have already run, so rejecting on a stale
        // deadline would discard a completed authentication.
        AuthResult::Accepted { .. } => WebAuthStep::Accept,
        AuthResult::Rejected => WebAuthStep::Reject { message: None },
        AuthResult::Need(_) => {
            if deadline.is_some_and(|deadline| now >= deadline) {
                WebAuthStep::Reject {
                    message: Some(WEB_AUTH_NOT_CONFIRMED_MESSAGE.to_owned()),
                }
            } else {
                WebAuthStep::PollAgain {
                    include_url: !url_shown,
                }
            }
        }
    }
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", session_debug_tag(&self.id, &self.remote_address))
    }
}

impl ServerSession {
    pub async fn start(
        remote_address: SocketAddr,
        services: &Services,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
        mut handler_event_rx: UnboundedReceiver<ServerHandlerEvent>,
    ) -> Result<impl Future<Output = Result<()>> + use<>> {
        let id = server_handle.lock().await.id();

        let span_ = info_span!("SSH", session=%id);
        let _enter = span_.enter();

        let mut rc_handles = RemoteClient::create(id, services.clone())?;

        let (hub, event_sender) = EventHub::setup(EVENT_QUEUE_CAPACITY);
        let control_events = hub
            .subscribe(|e| !matches!(e, Event::ConsoleInput(_) | Event::Client(_)))
            .await;
        let target_events = hub.subscribe(|e| matches!(e, Event::Client(_))).await;
        let channel_writer = ChannelWriter::new();
        let intake = EventIntake::new(control_events, target_events, channel_writer.data_slots());

        let mut this = Self {
            id,
            user_info: None,
            authentication_type: None,
            session_handle: None,
            channels: ChannelRegistry::new(),
            deferred_server_events: vec![],
            pending_events: VecDeque::new(),
            command_wait_depth: 0,
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            services: services.clone(),
            server_handle,
            target: TargetSelection::None,
            traffic_recorders: HashMap::new(),
            hub,
            event_sender: event_sender.clone(),
            intake,
            service_output: ServiceOutput::new(),
            channel_writer,
            auth_state: None,
            keyboard_interactive_state: None,
            cached_successful_ticket_auth: None,
            allowed_auth_methods: get_allowed_auth_methods(services).await?,
            host_key_trust_prompt_active: Arc::new(AtomicBool::new(false)),
            probe: ProbeState::NoAttempt,
            web_auth_waits_used: 0,
        };

        let mut so_rx = this.service_output.subscribe();
        let so_sender = event_sender.clone();
        tokio::spawn(async move {
            loop {
                match so_rx.recv().await {
                    Ok(data) => {
                        if so_sender
                            .send_once(Event::ServiceOutput(data))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(_) => (),
                }
            }
        });

        let name = format!("SSH {id} session control");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    if sender.send_once(Event::Command(command)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let name = format!("SSH {id} client events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(e) = rc_handles.event_rx.recv().await {
                    if sender.send_once(Event::Client(e)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let name = format!("SSH {id} server handler events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender: EventSender<Event> = event_sender.clone();
            async move {
                while let Some(e) = handler_event_rx.recv().await {
                    if sender.send_once(Event::ServerHandler(e)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let inactivity_timeout = services.config.lock().await.store.ssh.inactivity_timeout;

        Ok(async move {
            let result = loop {
                if let Some(event) = this.pending_events.pop_front() {
                    if let Err(error) = this.handle_event(event).await {
                        break Err(error);
                    }
                    continue;
                }
                let next_event_fut = this.get_next_event();
                match tokio::time::timeout(inactivity_timeout, next_event_fut).await {
                    Ok(Some(event)) => {
                        if let Err(error) = this.handle_event(event).await {
                            break Err(error);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(_) => {
                        info!("Closing the session due to inactivity");
                        let _ = this.emit_service_message("Closing the session due to inactivity");
                        this.request_disconnect();
                        this.disconnect_server().await;
                        break Ok(());
                    }
                }
            };
            debug!("No more events");
            this.settle_failed_probe().await;
            result?;
            Ok::<_, anyhow::Error>(())
        })
    }

    async fn get_next_event(&mut self) -> Option<Event> {
        self.intake.next().await
    }

    /// Based on the global params (#1957)
    fn supported_credential_kinds(&self) -> Vec<CredentialKind> {
        let mut kinds = vec![];
        if self.allowed_auth_methods.contains(&MethodKind::Password) {
            kinds.push(CredentialKind::Password);
        }
        if self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            kinds.push(CredentialKind::PublicKey);
        }
        if self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            kinds.push(CredentialKind::Totp);
            kinds.push(CredentialKind::WebUserApproval);
        }
        kinds
    }

    /// `rate_limit_credential_type` is forwarded to `Services::create_auth_state`
    /// so an unknown username is recorded as a failed attempt for IP blocking —
    /// `None` for benign contexts (public-key offers) that must not be counted.
    async fn get_auth_state(
        &mut self,
        username: &str,
        target_name: &str,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
        // The cached state may only be reused for the same username *and* the
        // same target: its `target_name` scopes web approvals, so switching
        // targets on one connection must not carry over the previous target's
        // approval.
        if let Some((state, cached_target)) = &self.auth_state
            && cached_target == target_name
            && username_eq_ci(&state.lock().await.user_info().username, username)
        {
            return Ok(state.clone());
        }

        let state = self
            .services
            .create_auth_state(
                &self.id,
                username,
                crate::PROTOCOL_NAME,
                target_name,
                &self.supported_credential_kinds(),
                Some(self.remote_address.ip()),
                rate_limit_credential_type,
            )
            .await?;
        self.auth_state = Some((state.clone(), target_name.to_string()));
        Ok(state)
    }

    /// SSH counts only password/OTP guesses toward rate-limiting — public-key
    /// offers legitimately fail as clients try each agent key in turn, so they
    /// aren't counted as brute-force attempts.
    const fn rate_limited_credential_type(credential: &AuthCredential) -> Option<&'static str> {
        match credential {
            AuthCredential::Password(_) => Some("password"),
            AuthCredential::Otp(_) => Some("otp"),
            _ => None,
        }
    }

    async fn record_failed_login_attempt(&mut self, username: &str, credential_type: &str) {
        self.probe = ProbeState::Settled;
        let _ = self
            .services
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: username.to_string(),
                remote_ip: self.remote_address.ip(),
                protocol: crate::PROTOCOL_NAME,
                credential_type: credential_type.to_string(),
            })
            .await;
    }

    fn note_probe(&mut self, selector: &AuthSelector, method: &'static str) {
        if let AuthSelector::User { username, .. } = selector
            && !matches!(self.probe, ProbeState::Settled)
        {
            self.probe = ProbeState::Probe {
                username: username.clone(),
                method,
            };
        }
    }

    /// At session end, record a failure if session only did
    /// unsuccessful probes
    async fn settle_failed_probe(&mut self) {
        if self.user_info.is_some() {
            return;
        }
        if let ProbeState::Probe { username, method } = &self.probe {
            let (username, method) = (username.clone(), *method);
            self.record_failed_login_attempt(&username, method).await;
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(user_info) = &self.user_info {
            info_span!("SSH", session=%self.id, session_username=%user_info.username, %client_ip)
        } else {
            info_span!("SSH", session=%self.id, %client_ip)
        }
    }

    fn map_channel(&self, ch: ServerChannelId) -> Result<Uuid, WarpgateError> {
        self.channels
            .uuid_for(ch)
            .ok_or(WarpgateError::InconsistentState(
                "Tried to map unknown channel ID".into(),
            ))
    }

    fn map_channel_reverse(&self, ch: &Uuid) -> Result<ServerChannelId> {
        self.channels
            .get(ch)
            .and_then(Channel::server_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    /// The client-facing handle and channel id a target-side channel writes
    /// to. `None` once the client session is gone — everything queued for it
    /// is dropped, so callers just skip the write.
    fn client_channel(&self, channel: &Uuid) -> Result<Option<(russh::server::Handle, ChannelId)>> {
        let server_channel_id = self.map_channel_reverse(channel)?;
        Ok(self
            .session_handle
            .clone()
            .map(|handle| (handle, server_channel_id.0)))
    }

    /// Opens a server->client channel in the background and delivers the
    /// resulting channel id back into the event loop as an event. Awaiting
    /// the client's confirmation inline would deadlock: the russh session
    /// loop might itself be blocked on a handler event that this event loop
    /// hasn't gotten to yet (#1459). The registry entry created here is what
    /// holds the channel's target-side events back until the open resolves.
    fn open_server_channel_in_background(
        &mut self,
        id: Uuid,
        open: impl Future<Output = Result<russh::Channel<russh::server::Msg>, russh::Error>>
        + Send
        + 'static,
    ) {
        self.channels.begin_server_open(id);
        let sender = self.event_sender.clone();
        tokio::spawn(async move {
            let result = open.await.map(|channel| ServerChannelId(channel.id()));
            let _ = sender
                .send_once(Event::ServerChannelOpenResult(id, result))
                .await;
        });
    }

    pub fn emit_pty_output(&self, data: &[u8]) -> Result<()> {
        let channels = self
            .channels
            .values()
            .filter(|c| c.has_pty())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();
        for channel in channels {
            if let Some(session) = self.session_handle.clone() {
                self.channel_writer.write(session, channel.0, data, None)?;
            }
        }
        Ok(())
    }

    pub fn emit_service_message(&self, msg: &str) -> Result<()> {
        debug!("Service message: {}", msg);

        let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        let output = format!(
            "{} {}\r\n",
            paint_fg(Color::Blue, false, "● Warpgate:"),
            msg.replace('\n', "\r\n")
        );
        self.emit_pty_output(output.as_bytes())
    }

    pub fn emit_pty_error(&self, msg: &str) -> Result<()> {
        if self.service_output.progress_visible() {
            self.service_output.stop_progress();
            let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        }
        let output = format!("{} {msg}\r\n", paint_fg(Color::Red, false, "● Warpgate:"));
        self.emit_pty_output(output.as_bytes())
    }

    async fn fail_on_channel_writer_error(&mut self, error: anyhow::Error) -> Result<()> {
        warn!(?error, "Failed to send SSH channel data");
        self.request_disconnect();
        self.disconnect_server().await;
        Err(error)
    }

    /// Start connecting to the target if we aren't already.
    ///
    /// Timing of this call is important because if the client connection is
    /// an interactive session *in principle* (e.g a normal interactive OpenSSH
    /// session but maybe with some port forwards or agent)
    /// Ideally, it needs to be called by the time we already have the interactive
    /// channel open if we will ever have one to prevent bugs like
    /// https://github.com/warp-tech/warpgate/issues/1286
    /// where a PTY channel is required for the host key prompt, but we've connected
    /// faster than the client could open one.
    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        let target = match &self.target {
            TargetSelection::None => {
                anyhow::bail!("Invalid session state (target not set)")
            }
            TargetSelection::Menu => return Ok(()),
            TargetSelection::NotFound(name) => {
                let name = name.clone();
                self.emit_service_message(&format!("Selected target not found: {name}"))?;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {name}");
            }
            TargetSelection::Found(authorization) => Some(authorization.clone()),
        };

        if let Some(authorization) = target
            && self.rc_state == RCState::NotInitialized
        {
            self.connect_remote(&authorization).await?;
        }

        Ok(())
    }

    /// Dialling takes the authorization proof rather than a bare target, so the host we
    /// connect to is necessarily the one that was authorized, for the user it was
    /// authorized for.
    async fn connect_remote(&mut self, authorization: &TargetAuthorization) -> Result<()> {
        let ssh_chain = resolve_ssh_chain(
            &self.services,
            authorization.target().id,
            Some(&authorization.user_info().username),
        )
        .await?;

        let visual_chain = self.make_visual_connection_chain(&ssh_chain[..]).await?;
        self.rc_state = RCState::Connecting;
        self.send_command(RCCommand::Connect(
            ssh_chain.into_iter().map(|x| x.ssh_options).collect(),
        ))
        .map_err(|_| anyhow::anyhow!("cannot send command"))?;
        self.emit_pty_output(b"\r\n")?;
        self.service_output.start_progress(visual_chain).await;
        Ok(())
    }

    async fn make_visual_connection_chain(
        &self,
        ssh_chain: &[ResolvedSshChainHost],
    ) -> Result<Vec<VisualConnectionChainItem>, WarpgateError> {
        let maybe_ext_url =
            construct_external_url(None, &*self.services.config.lock().await, None).await;
        let warpgate_item = match maybe_ext_url {
            Ok(url) => VisualConnectionChainItem::Link {
                text: "Warpgate".into(),
                url: url.to_string(),
            },
            Err(_) => VisualConnectionChainItem::Text("Warpgate".into()),
        };

        let mut display = vec![VisualConnectionChainItem::Text("You".into()), warpgate_item];
        display.extend(
            ssh_chain
                .iter()
                .map(|host| VisualConnectionChainItem::Text(host.name.clone())),
        );

        Ok(display)
    }

    async fn handle_menu_event(&mut self, action: MenuEvent) -> Result<()> {
        match action {
            MenuEvent::Render(data) => {
                self.emit_pty_output(&data)?;
            }
            MenuEvent::Abort => {
                self.emit_service_message("Session closed")?;
                self.request_disconnect();
                self.disconnect_server().await;
            }
            MenuEvent::Selected(target) => {
                let user_info = self
                    .user_info
                    .clone()
                    .ok_or(WarpgateError::InconsistentState("No user info".into()))?;
                // The menu list was authorized when it was built; permissions
                // may have changed while it was open, so re-check on selection.
                let target_name = target.name.clone();
                let identity = AuthorizedIdentity::for_authenticated_session(
                    user_info.clone(),
                    crate::PROTOCOL_NAME,
                );
                let Some(authorization) =
                    authorize_for_target(self.services.config_provider.as_ref(), &identity, target)
                        .await?
                else {
                    warn!(
                        "Target {} not authorized for user {}",
                        target_name, user_info.username
                    );
                    self.emit_service_message(&format!("Access to {target_name} denied"))?;
                    self.request_disconnect();
                    self.disconnect_server().await;
                    return Ok(());
                };
                let _ = self
                    .server_handle
                    .lock()
                    .await
                    .set_target(authorization.target())
                    .await;
                self.target = TargetSelection::Found(authorization);
                // clear screen ; cursor to 1;1
                self.emit_pty_output(b"\x1b[2J\x1b[H")?;
                self.maybe_connect_remote().await?;
            }
        }

        Ok(())
    }

    fn handle_event<'a>(
        &'a mut self,
        event: Event,
    ) -> Pin<Box<dyn Future<Output = Result<(), WarpgateError>> + Send + 'a>> {
        async move {
            match event {
                Event::Client(RCEvent::Done) => Err(WarpgateError::SessionEnd)?,
                Event::ServerHandler(ServerHandlerEvent::Disconnect) => {
                    Err(WarpgateError::SessionEnd)?;
                }
                Event::Client(e) => {
                    let e = if let Some(ch) = e.channel()
                        && let Some(channel) = self.channels.get_mut(&ch)
                    {
                        match channel.try_defer(e) {
                            Ok(()) => {
                                debug!(channel=%ch, "Deferring event until the channel open resolves");
                                return Ok(());
                            }
                            Err(e) => e,
                        }
                    } else {
                        e
                    };
                    debug!(event=?e, "Event");
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_remote_event(e).instrument(span).await {
                        error!("Client event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServerHandler(e) => {
                    // An event for a channel id no registered channel carries can
                    // only refer to a pending server-initiated open: the client
                    // learns of such channels no earlier than from the confirmation
                    // that resolves the open. Without any open in flight an unknown
                    // id is simply bogus and is left to the handler to reject.
                    if let Some(ch) = e.existing_channel()
                        && self.channels.uuid_for(ch).is_none()
                        && self.channels.has_opening()
                    {
                        debug!(channel=%ch.0, event=?e, "Deferring event until the channel open resolves");
                        self.deferred_server_events.push(e);
                        return Ok(());
                    }
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_server_handler_event(e).instrument(span).await {
                        error!("Server event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::Command(command) => {
                    debug!(?command, "Session control");
                    if let Err(err) = self.handle_session_control(command).await {
                        error!("Command handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServiceOutput(data) => {
                    if let Some(frame) = self.service_output.take_frame(&data) {
                        let _ = self.emit_pty_output(&frame);
                    }
                }
                Event::Menu(action) => {
                    if let Err(err) = self.handle_menu_event(action).await {
                        error!(?err, "Menu loop action handler error");
                    }
                }
                Event::ServerChannelOpenResult(id, result) => {
                    match result {
                        Ok(server_channel_id) => {
                            if self.channels.assign_server_id(id, server_channel_id) {
                                self.confirm_channel_open(id).await?;
                            } else {
                                debug!(channel=%id, "Open resolved for an already-closed channel");
                                self.replay_deferred_server_events().await?;
                            }
                        }
                        Err(error) => {
                            warn!(channel=%id, ?error, "Failed to open a channel to the client");
                            // Tear the entry down now — its deferred events die
                            // with the open they were waiting on, and the
                            // target's eventual Close reply must find no
                            // Opening entry to be deferred onto.
                            self.channels.close(id);
                            let _ =
                                self.send_command(RCCommand::Channel(id, ChannelOperation::Close));
                            self.replay_deferred_server_events().await?;
                        }
                    }
                }
                Event::MenuRedraw(_, _) | Event::ConsoleInput(_) => (),
            }
            Ok(())
        }
        .boxed()
    }

    /// Confirm `channel` as open and re-dispatch everything held back while its
    /// open was in flight. Events whose channel is still opening are deferred
    /// again by [`Self::handle_event`], so overlapping opens replay safely.
    async fn confirm_channel_open(&mut self, channel: Uuid) -> Result<(), WarpgateError> {
        for event in self.channels.confirm(channel).unwrap_or_default() {
            self.handle_event(Event::Client(event)).await?;
        }
        self.replay_deferred_server_events().await
    }

    async fn replay_deferred_server_events(&mut self) -> Result<(), WarpgateError> {
        for event in std::mem::take(&mut self.deferred_server_events) {
            self.handle_event(Event::ServerHandler(event)).await?;
        }
        Ok(())
    }

    async fn start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        let menu_event_subscription = self
            .hub
            .subscribe(|e| matches!(e, Event::MenuRedraw(_, _) | Event::ConsoleInput(_)))
            .await;

        let username = self
            .user_info
            .as_ref()
            .map(|u| u.username.as_str())
            .ok_or(WarpgateError::InconsistentState("No username".into()))?;

        let ssh_targets = {
            self.services
                .config_provider
                .list_targets()
                .await?
                .into_iter()
                .filter_map(|target| match target.options.clone() {
                    TargetOptions::Ssh(options) => Some((target, options)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let mut authorized_targets = Vec::new();

        for (target, mut ssh_options) in ssh_targets {
            let is_authorized = self
                .services
                .config_provider
                .authorize_target(username, &target.name)
                .await?;

            if is_authorized {
                if ssh_options.username.is_empty() {
                    ssh_options.username = username.to_string();
                }
                authorized_targets.push((target, ssh_options));
            }
        }

        authorized_targets.sort_by(|(left, _), (right, _)| left.name.cmp(&right.name));

        let (terminal_width, terminal_height) = self
            .channels
            .get(&channel_id)
            .and_then(|c| c.pty_size.as_ref())
            .map_or((220, 24), |r| (r.col_width as u16, r.row_height as u16));

        spawn_target_menu_loop(
            self.id,
            username.to_string(),
            authorized_targets,
            menu_event_subscription,
            self.event_sender.clone(),
            terminal_width,
            terminal_height,
        )?;
        Ok(())
    }

    async fn maybe_start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        if matches!(self.target, TargetSelection::Menu)
            && self.channels.get(&channel_id).is_some_and(Channel::has_pty)
        {
            self.start_target_selection_menu(channel_id).await?;
        }

        Ok(())
    }

    async fn handle_server_handler_event(&mut self, event: ServerHandlerEvent) -> Result<()> {
        match event {
            ServerHandlerEvent::Authenticated(handle) => {
                self.session_handle = Some(handle.0);
            }

            ServerHandlerEvent::ChannelOpenSession(server_channel_id, reply) => {
                info!(channel=%server_channel_id.0, "Opening session channel");
                self._channel_open(
                    server_channel_id,
                    ChannelOperation::OpenShell,
                    None,
                    reply.0,
                )
                .await?;
            }

            ServerHandlerEvent::SubsystemRequest(server_channel_id, name, reply) => {
                return match self
                    ._channel_subsystem_request(server_channel_id, name)
                    .await
                {
                    Ok(()) => {
                        let _ = reply.send(true);
                        Ok(())
                    }
                    Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                        let _ = reply.send(false);
                        Ok(())
                    }
                    Err(x) => Err(x.into()),
                };
            }

            ServerHandlerEvent::PtyRequest(server_channel_id, request, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                let Some(channel_state) = self.channels.get_mut(&channel_id) else {
                    return Err(WarpgateError::InconsistentState(
                        "PTY requested for a channel that was never opened".into(),
                    )
                    .into());
                };
                channel_state.pty_size = Some(request.clone());
                channel_state.audit.on_resize(&request).await;

                self.send_command_and_wait(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestPty(request),
                ))
                .await?;
                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);
                // Waiting for the target above pumps the event loop, so the
                // channel may have been closed in the meantime — hence the
                // re-lookup instead of holding the entry across the await.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.mark_pty();
                }
                let _ = reply.send(());
            }

            ServerHandlerEvent::ShellRequest(server_channel_id, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                self.maybe_connect_remote().await?;
                self.maybe_start_target_selection_menu(channel_id).await?;

                self.inject_own_env(channel_id);

                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestShell,
                ));

                self.start_terminal_recording(
                    channel_id,
                    SshRecordingMetadata::Shell {
                        // HACK russh ChannelId is opaque except via Display
                        channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
                    },
                )
                .await;
                self.maybe_start_command_detector(channel_id);

                info!(%channel_id, "Opening shell");

                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);

                let _ = reply.send(true);
            }

            ServerHandlerEvent::AuthPublicKey(username, key, reply) => {
                let _ = reply.send(self._auth_publickey(username, key).await);
            }

            ServerHandlerEvent::AuthPublicKeyOffer(username, key, reply) => {
                let _ = reply.send(self._auth_publickey_offer(username, key).await);
            }

            ServerHandlerEvent::AuthPassword(username, password, reply) => {
                let _ = reply.send(self._auth_password(username, password).await);
            }

            ServerHandlerEvent::AuthKeyboardInteractive(username, responses, reply) => {
                let _ = reply.send(self._auth_keyboard_interactive(username, responses).await?);
            }

            ServerHandlerEvent::Data(channel, data, reply) => {
                self._data(channel, data).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExtendedData(channel, data, code, reply) => {
                self._extended_data(channel, code, data)?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelClose(channel, reply) => {
                self._channel_close(channel).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelEof(channel, reply) => {
                self._channel_eof(channel)?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::WindowChangeRequest(channel, request, reply) => {
                self._window_change_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::Signal(channel, signal, reply) => {
                self._channel_signal(channel, signal).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExecRequest(channel, data, reply) => {
                self._channel_exec_request(channel, data).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::ChannelOpenDirectTcpIp(channel, params, reply) => {
                self._channel_open_direct_tcpip(channel, params, reply.0)
                    .await?;
            }

            ServerHandlerEvent::ChannelOpenDirectStreamlocal(channel, path, reply) => {
                self._channel_open_direct_streamlocal(channel, path, reply.0)
                    .await?;
            }

            ServerHandlerEvent::EnvRequest(channel, name, value, reply) => {
                self._channel_env_request(channel, name, value).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::X11Request(channel, request, reply) => {
                self._channel_x11_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::TcpIpForward(address, port, reply) => {
                self._tcpip_forward(address, port).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::CancelTcpIpForward(address, port, reply) => {
                self._cancel_tcpip_forward(address, port).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::StreamlocalForward(socket_path, reply) => {
                self._streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::CancelStreamlocalForward(socket_path, reply) => {
                self._cancel_streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::AgentForward(channel, reply) => {
                self._agent_forward(channel).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::Disconnect => (),
        }

        Ok(())
    }

    pub async fn handle_session_control(&mut self, command: SessionHandleCommand) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ = self.emit_service_message("Session closed by admin");
                info!("Session closed by admin");
                self.request_disconnect();
                self.disconnect_server().await;
            }
        }
        Ok(())
    }

    pub async fn handle_remote_event(&mut self, event: RCEvent) -> Result<()> {
        match event {
            RCEvent::HopConnected => {
                self.service_output.notify_hop_connected().await;
            }
            RCEvent::State(state) => {
                self.rc_state = state;
                match &self.rc_state {
                    RCState::Connected => {
                        let msg = self
                            .service_output
                            .render_final_success_static_frame()
                            .await;
                        let _ = self.emit_pty_output(msg.as_bytes());
                    }
                    RCState::Disconnected => {
                        self.service_output.stop_progress();
                        self.disconnect_server().await;
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError(error) => {
                self.service_output.stop_progress();

                match error {
                    ConnectionError::HostKeyMismatch {
                        received_key_type,
                        received_key_base64,
                        known_key_type,
                        known_key_base64,
                    } => {
                        let _ = self.emit_pty_error("Host key doesn't match the stored one.");
                        let msg = format!(
                            concat!("Stored key   ({}): {}\n", "Received key ({}): {}",),
                            known_key_type,
                            known_key_base64,
                            received_key_type,
                            received_key_base64
                        );
                        self.emit_service_message(&msg)?;
                        self.emit_service_message(
                            "If you know that the key is correct (e.g. it has been changed),",
                        )?;
                        self.emit_service_message(
                            "you can remove the old key in the Warpgate management UI and try again",
                        )?;
                    }
                    ConnectionError::Authentication => {
                        let _ = self.emit_pty_error(
                            "SSH target rejected Warpgate's authentication request",
                        );
                    }
                    error => {
                        let _ = self.emit_pty_error(&format!("Target connection failed: {error}"));
                    }
                }
            }
            RCEvent::Error(e) => {
                self.service_output.stop_progress();
                let _ = self.emit_pty_error(&format!("Error: {e}"));
                self.disconnect_server().await;
            }
            RCEvent::Output(channel, data) => {
                if let Some(channel_state) = self.channels.get_mut(&channel) {
                    channel_state.audit.on_output(&data).await;

                    if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                        && let Err(error) = recorder.write_rx(&data).await
                    {
                        error!(%channel, ?error, "Failed to record traffic data");
                        channel_state.traffic_recorder = None;
                    }
                }

                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self.channel_writer.write(handle, id, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Success(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_success(handle, id)?;
                }
            }
            RCEvent::ChannelFailure(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_failure(handle, id)?;
                }
            }
            RCEvent::Close(channel) => {
                if let Ok(Some((handle, id))) = self.client_channel(&channel) {
                    let _ = self.channel_writer.close(handle, id);
                }
                self.channels.close(channel);
            }
            RCEvent::Eof(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.eof(handle, id)?;
                }
            }
            RCEvent::ExitStatus(channel, code) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_status(handle, id, code)?;
                }
            }
            RCEvent::ExitSignal {
                channel,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_signal(
                        handle,
                        id,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )?;
                }
            }
            RCEvent::ExtendedData { channel, data, ext } => {
                if let Some(channel_state) = self.channels.get_mut(&channel) {
                    channel_state.audit.on_error_output(&data).await;
                }
                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self
                        .channel_writer
                        .write_extended(handle, id, ext, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Done | RCEvent::HostKeyReceived(..) => {}
            RCEvent::HostKeyUnknown(key, _, _, reply) => {
                self.handle_unknown_host_key(key, reply).await?;
            }
            RCEvent::ForwardedTcpIp(id, params) => {
                if let Some(session) = self.session_handle.clone() {
                    let open_params = params.clone();
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_tcpip(
                                open_params.connected_address,
                                open_params.connected_port,
                                open_params.originator_address,
                                open_params.originator_port,
                            )
                            .await
                    });

                    let recorder = self
                        .traffic_recorder_for(
                            TrafficRecorderKey::Tcp(
                                params.originator_address.clone(),
                                params.originator_port,
                            ),
                            SshRecordingMetadata::ForwardedTcpIp {
                                host: params.originator_address,
                                port: params.originator_port as u16,
                            },
                        )
                        .await;
                    if let Some(recorder) = recorder {
                        #[allow(clippy::unwrap_used)]
                        let mut recorder = recorder.connection(TrafficConnectionParams::Tcp {
                            dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                            dst_port: params.connected_port as u16,
                            src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                            src_port: params.originator_port as u16,
                        });
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(channel=%id, ?error, "Failed to record connection setup");
                        }
                        if let Some(channel_state) = self.channels.get_mut(&id) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }
            }
            RCEvent::ForwardedStreamlocal(id, params) => {
                if let Some(session) = self.session_handle.clone() {
                    let socket_path = params.socket_path.clone();
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_streamlocal(socket_path)
                            .await
                    });

                    let recorder = self
                        .traffic_recorder_for(
                            TrafficRecorderKey::Socket(params.socket_path.clone()),
                            SshRecordingMetadata::ForwardedSocket {
                                path: params.socket_path.clone(),
                            },
                        )
                        .await;
                    if let Some(recorder) = recorder {
                        #[allow(clippy::unwrap_used)]
                        let mut recorder = recorder.connection(TrafficConnectionParams::Socket {
                            socket_path: params.socket_path,
                        });
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(channel=%id, ?error, "Failed to record connection setup");
                        }
                        if let Some(channel_state) = self.channels.get_mut(&id) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }
            }
            RCEvent::ForwardedAgent(id) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session.channel_open_agent().await
                    });
                }
            }
            RCEvent::X11(id, originator_address, originator_port) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_x11(originator_address, originator_port)
                            .await
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_unknown_host_key(
        &self,
        key: PublicKey,
        reply: oneshot::Sender<bool>,
    ) -> Result<()> {
        let mode = Parameters::Entity::get(&self.services.db)
            .await?
            .ssh_host_key_verification;

        // `Ignore` never gets here - the key is accepted without a lookup.
        if mode == SshHostKeyVerificationMode::AutoAccept {
            let _ = reply.send(true);
            info!("Accepted untrusted host key (auto-accept is enabled)");
            return Ok(());
        }

        if mode == SshHostKeyVerificationMode::AutoReject {
            let _ = reply.send(false);
            info!("Rejected untrusted host key (auto-reject is enabled)");
            return Ok(());
        }

        self.service_output.stop_progress();

        if !self.channels.values().any(Channel::has_pty) {
            warn!(
                "Target host key is not trusted, but there is no active PTY channel to show the trust prompt on."
            );
            warn!(
                "Connect to this target with an interactive session once to accept the host key."
            );
            self.request_disconnect();
            anyhow::bail!("No PTY channel to show an interactive prompt on")
        }

        self.emit_service_message(&format!(
            "Host key ({}): {}",
            key.algorithm(),
            key.public_key_base64()
        ))?;
        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.algorithm()
        ))?;
        self.emit_service_message("Trust this key? (y/n)")?;

        let mut sub = self
            .hub
            .subscribe(|e| matches!(e, Event::ConsoleInput(_)))
            .await;

        self.host_key_trust_prompt_active
            .store(true, Ordering::SeqCst);

        let service_output = self.service_output.clone();
        let prompt_active = self.host_key_trust_prompt_active.clone();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Some(Event::ConsoleInput(data)) => {
                        if &data[..] == b"y" {
                            let _ = reply.send(true);
                            break;
                        } else if &data[..] == b"n" {
                            let _ = reply.send(false);
                            break;
                        }
                    }
                    None => break,
                    _ => (),
                }
            }
            prompt_active.store(false, Ordering::SeqCst);
            service_output.show_progress();
        });

        Ok(())
    }

    async fn _channel_open_direct_tcpip(
        &mut self,
        channel: ServerChannelId,
        params: DirectTCPIPParams,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        info!(%channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);
        let key = TrafficRecorderKey::Tcp(params.host_to_connect.clone(), params.port_to_connect);
        let metadata = SshRecordingMetadata::DirectTcpIp {
            host: params.host_to_connect.clone(),
            port: params.port_to_connect as u16,
        };
        #[allow(clippy::unwrap_used)]
        let connection_params = TrafficConnectionParams::Tcp {
            dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
            dst_port: params.port_to_connect as u16,
            src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            src_port: params.originator_port as u16,
        };
        // Unlike a session channel — whose later shell/exec/subsystem request
        // dials the target — a direct channel is the whole interaction, so the
        // connection must be initiated here.
        let _ = self.maybe_connect_remote().await;
        self._channel_open(
            channel,
            ChannelOperation::OpenDirectTCPIP(params),
            Some((key, metadata, connection_params)),
            open_handle,
        )
        .await
    }

    async fn _channel_open_direct_streamlocal(
        &mut self,
        channel: ServerChannelId,
        path: String,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        info!(%channel, "Opening direct streamlocal channel to {}", path);
        let key = TrafficRecorderKey::Socket(path.clone());
        let metadata = SshRecordingMetadata::DirectSocket { path: path.clone() };
        let connection_params = TrafficConnectionParams::Socket {
            socket_path: path.clone(),
        };
        let _ = self.maybe_connect_remote().await;
        self._channel_open(
            channel,
            ChannelOperation::OpenDirectStreamlocal(path),
            Some((key, metadata, connection_params)),
            open_handle,
        )
        .await
    }

    /// Open a client-initiated channel towards the target and send the client
    /// its open confirmation from here, the session task. The
    /// [`ChannelState::Opening`] entry holds the target's output back until
    /// `accept()` has queued the confirmation, so server-speaks-first bytes
    /// never precede `CHANNEL_OPEN_CONFIRMATION` (#2328).
    async fn _channel_open(
        &mut self,
        channel: ServerChannelId,
        operation: ChannelOperation,
        recording: Option<(
            TrafficRecorderKey,
            SshRecordingMetadata,
            TrafficConnectionParams,
        )>,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        let uuid = self.channels.begin_client_open(channel);

        match self
            .send_command_and_wait(RCCommand::Channel(uuid, operation))
            .await
        {
            Ok(()) => {
                open_handle.accept().await;

                // The recorder is attached before the deferred output is
                // replayed, so the target's first bytes are recorded too.
                if let Some((key, metadata, connection_params)) = recording {
                    let recorder = self.traffic_recorder_for(key, metadata).await;
                    if let Some(recorder) = recorder {
                        let mut recorder = recorder.connection(connection_params);
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(%channel, ?error, "Failed to record connection setup");
                        }
                        if let Some(channel_state) = self.channels.get_mut(&uuid) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }

                self.confirm_channel_open(uuid).await?;
                Ok(())
            }
            Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                open_handle.reject(ChannelOpenFailure::ConnectFailed).await;
                self.channels.close(uuid);
                Ok(())
            }
            // Dropping `open_handle` auto-rejects the open, so the client always
            // gets a reply even on unexpected errors.
            Err(x) => {
                self.channels.close(uuid);
                Err(x.into())
            }
        }
    }

    async fn _window_change_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return Err(WarpgateError::InconsistentState(
                "Window change for a channel that was never opened".into(),
            )
            .into());
        };
        channel_state.pty_size = Some(request.clone());
        channel_state.audit.on_resize(&request).await;

        if matches!(self.target, TargetSelection::Menu) {
            let _ = self
                .event_sender
                .try_send_once(Event::MenuRedraw(
                    request.col_width as u16,
                    request.row_height as u16,
                ))
                .await;
        }

        if self.rc_state != RCState::Connected {
            return Ok(());
        }

        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(request),
        ))
        .await?;
        Ok(())
    }

    async fn _channel_exec_request(
        &mut self,
        server_channel_id: ServerChannelId,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        let command = std::str::from_utf8(&data).inspect_err(|_| {
            error!(channel=%channel_id, ?data, "Requested exec - invalid UTF-8");
        })?;
        info!(channel=%channel_id, command=%command, "Exec command");

        let is_scp = command == "scp" || command.starts_with("scp ");
        let _ = self.maybe_connect_remote().await;
        self.maybe_start_target_selection_menu(channel_id).await?;
        self.inject_own_env(channel_id);
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestExec(command.to_string()),
        ));

        let should_record = if is_scp {
            let db = &self.services.db;
            let should_record = Parameters::Entity::get(db)
                .await
                .map_or(true, |p| p.record_scp);

            if !should_record {
                info!(channel=%channel_id, "Not recording SCP exec session, command was '{command}'");
            }

            should_record
        } else {
            true
        };

        if should_record {
            self.start_terminal_recording(
                channel_id,
                SshRecordingMetadata::Exec {
                    // HACK russh ChannelId is opaque except via Display
                    channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
                },
            )
            .await;
        }
        Ok(())
    }

    async fn start_terminal_recording(&mut self, channel_id: Uuid, metadata: SshRecordingMetadata) {
        let recorder = async {
            let recorder = self
                .services
                .recordings
                .start::<TerminalRecorder, _>(&self.id, None, metadata)
                .await?;
            if let Some(request) = self
                .channels
                .get(&channel_id)
                .and_then(|c| c.pty_size.as_ref())
            {
                recorder
                    .write_pty_resize(request.col_width, request.row_height)
                    .await?;
            }
            Ok::<_, recordings::Error>(recorder)
        }
        .await;
        match recorder {
            Ok(recorder) => {
                // Starting the recording awaits, so the channel can be gone by
                // now — e.g. target selection failed and tore the session down.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.audit.set_recorder(recorder);
                } else {
                    debug!(channel=%channel_id, "Recording started for a channel that is already gone");
                }
            }
            Err(error) => match error {
                recordings::Error::Disabled => (),
                error => error!(channel=%channel_id, ?error, "Failed to start recording"),
            },
        }
    }

    fn maybe_start_command_detector(&mut self, channel_id: Uuid) {
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return;
        };
        if !channel_state.has_pty() {
            return;
        }
        let (cols, rows) = channel_state
            .pty_size
            .as_ref()
            .map_or((80, 24), PtyRequest::screen_size);
        channel_state.audit.start_command_detection(cols, rows);
    }

    async fn _channel_x11_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: X11Request,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "Requested X11");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestX11(request),
        ))
        .await?;
        Ok(())
    }

    async fn _channel_env_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
        value: String,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, %name, %value, "Environment");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestEnv(name, value),
        ))
        .await?;
        Ok(())
    }

    /// Inject Warpgate identity and custom environment variables into the downstream SSH session.
    /// Mirrors inject_own_headers() in the HTTP proxy.
    fn inject_own_env(&mut self, channel_id: Uuid) {
        // Collect all env vars first to avoid borrow conflicts with send_command
        let mut env_vars: Vec<(String, String)> = Vec::new();

        // Built-in: WARPGATE_USERNAME
        if let Some(ref user_info) = self.user_info {
            env_vars.push(("WARPGATE_USERNAME".to_string(), user_info.username.clone()));
        }

        // Built-in: WARPGATE_AUTHENTICATION_TYPE
        if let Some(ref auth_type) = self.authentication_type {
            env_vars.push((
                "WARPGATE_AUTHENTICATION_TYPE".to_string(),
                auth_type.clone(),
            ));
        }

        // Custom env vars from target SSH config
        if let TargetSelection::Found(ref authorization) = self.target
            && let TargetOptions::Ssh(ref ssh_options) = authorization.target().options
            && let Some(ref env) = ssh_options.env
        {
            for (name, value) in env {
                env_vars.push((name.clone(), value.clone()));
            }
        }

        // Send all env vars
        for (name, value) in env_vars {
            let _ = self.send_command(RCCommand::Channel(
                channel_id,
                ChannelOperation::RequestEnv(name, value),
            ));
        }
    }

    async fn traffic_recorder_for(
        &mut self,
        key: TrafficRecorderKey,
        metadata: SshRecordingMetadata,
    ) -> Option<&mut TrafficRecorder> {
        if let Vacant(e) = self.traffic_recorders.entry(key.clone()) {
            match self
                .services
                .recordings
                .start(&self.id, None, metadata)
                .await
            {
                Ok(recorder) => {
                    e.insert(recorder);
                }
                Err(recordings::Error::Disabled) => (),
                Err(error) => {
                    error!(?key, ?error, "Failed to start recording");
                }
            }
        }
        self.traffic_recorders.get_mut(&key)
    }

    pub async fn _channel_subsystem_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
    ) -> Result<(), SshClientError> {
        let channel_id = self.map_channel(server_channel_id)?;
        info!(channel=%channel_id, "Requesting subsystem {}", &name);
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestSubsystem(name),
        ))
        .await?;
        Ok(())
    }

    async fn _data(&mut self, server_channel_id: ServerChannelId, data: Bytes) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        if self.rc_state == RCState::Connecting && data.first() == Some(&3) {
            info!(channel=%channel_id, "User requested connection abort (Ctrl-C)");
            self.request_disconnect();
            return Ok(());
        }

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.audit.on_input(&data).await;

            if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                && let Err(error) = recorder.write_tx(&data).await
            {
                error!(channel=%channel_id, ?error, "Failed to record traffic data");
                channel_state.traffic_recorder = None;
            }
        }

        if self.channels.get(&channel_id).is_some_and(Channel::has_pty) {
            let _ = self
                .event_sender
                .try_send_once(Event::ConsoleInput(data.clone()))
                .await;

            // While a host-key trust prompt is waiting for 'y'/'n', do not forward
            // PTY input to the target channel. Otherwise the prompt-reply byte is
            // queued on the target channel and replays into the shell once the
            // target session opens. Note this runs ahead of the deliberate
            // early-stdin forward below (#2065) — that path exists for exec/scp
            // payloads, which never carry a PTY.
            if self.host_key_trust_prompt_active.load(Ordering::SeqCst) {
                return Ok(());
            }
        }

        // While the target selection menu is open, keystrokes drive the menu
        // (handled above) and there's no target to forward them to.
        // Otherwise forward the data even before the target connection is
        // established: the remote client buffers channel operations and
        // replays them in order once connected, so early stdin (e.g. rsync,
        // scp or Ansible pipelining payloads sent right after the exec
        // request) must not be dropped (#2065).
        if matches!(self.target, TargetSelection::Menu) {
            return Ok(());
        }

        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
        Ok(())
    }

    fn _extended_data(
        &self,
        server_channel_id: ServerChannelId,
        code: u32,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ExtendedData { ext: code, data },
        ));
        Ok(())
    }

    async fn _tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::ForwardTCPIP(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelTCPIPForward(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::StreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelStreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _agent_forward(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "Requested Agent Forwarding");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::AgentForward,
        ))
        .await?;
        Ok(())
    }

    async fn _auth_publickey_offer(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Client offers public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );
        self.note_probe(&selector, "public_key");

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        // Tickets aren't authenticated with public keys, and the eager auth path
        // consumes a ticket use. Running it here — during the unauthenticated
        // offer/query phase — would drain the ticket before the client actually
        // authenticates, so reject and let auth proceed via another method.
        if let AuthSelector::Ticket { .. } = selector {
            return russh::server::Auth::reject();
        }

        if matches!(
            self.try_validate_public_key_offer(
                &selector,
                Some(AuthCredential::PublicKey {
                    kind: key.algorithm(),
                    public_key_bytes: Bytes::from(key.public_key_bytes()),
                }),
            )
            .await,
            Ok(true)
        ) {
            return russh::server::Auth::Accept;
        }

        match self.try_auth_lazy(&selector, None).await {
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            _ => russh::server::Auth::reject(),
        }
    }

    async fn _auth_publickey(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );
        self.note_probe(&selector, "public_key");

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        let key = Some(AuthCredential::PublicKey {
            kind: key.algorithm(),
            public_key_bytes: Bytes::from(key.public_key_bytes()),
        });

        let result = self.try_auth_lazy(&selector, key.clone()).await;

        match result {
            Ok(AuthResult::Accepted { .. }) => {
                // Update last_used timestamp
                if let Err(err) = self
                    .services
                    .config_provider
                    .update_public_key_last_used(key.clone())
                    .await
                {
                    warn!(?err, "Failed to update last_used for public key");
                }
                russh::server::Auth::Accept
            }
            Ok(AuthResult::Rejected) => {
                reject_with_allowed_auth_methods(self.allowed_auth_methods.clone())
            }
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_password(
        &mut self,
        ssh_username: Secret<String>,
        password: Secret<String>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Password auth as {selector:?}");
        self.note_probe(&selector, "password");

        if !self.allowed_auth_methods.contains(&MethodKind::Password) {
            warn!("Client attempted password auth even though it was not advertised");
            if let AuthSelector::User { username, .. } = &selector {
                self.record_failed_login_attempt(username, "password").await;
            }
            return russh::server::Auth::reject();
        }

        let result = self
            .try_auth_lazy(&selector, Some(AuthCredential::Password(password)))
            .await;

        match result {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_keyboard_interactive(
        &mut self,
        ssh_username: Secret<String>,
        responses: Vec<Secret<String>>,
    ) -> Result<russh::server::Auth> {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Keyboard-interactive auth as {:?}", selector);
        self.note_probe(&selector, "keyboard_interactive");

        if !self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            warn!("Client attempted keyboard-interactive auth even though it was not advertised");
            return Ok(russh::server::Auth::reject());
        }

        let keyboard_interactive_state = self.keyboard_interactive_state.take();
        let maybe_otp_cred = if keyboard_interactive_state
            .as_ref()
            .is_some_and(|s| s.otp_prompt_sent)
        {
            responses.into_iter().next().map(AuthCredential::Otp)
        } else {
            None
        };
        // Destructure the taken struct exactly once and move its carried fields
        // forward, so an in-flight wait's broadcast receiver is not dropped at
        // the start of every round.
        let mut next_pending = keyboard_interactive_state
            .map_or_else(PendingKeyboardInteractiveAuth::fresh, carry_forward);

        Ok(match self.try_auth_lazy(&selector, maybe_otp_cred).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => {
                let mut auth_name = "Warpgate authentication".to_string();
                let mut auth_instructions = String::new();
                let mut auth_prompts = vec![];

                // Cloned, not borrowed: everything the round needs afterwards
                // wants `&mut self`, so no borrow of `self` may outlive this
                // point.
                let Some((auth_state, _)) = self.auth_state.clone() else {
                    return Ok(russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                };

                if kinds.contains(&CredentialKind::Totp) {
                    next_pending.otp_prompt_sent = true;
                    auth_name = "Two-factor authentication".into();
                    auth_prompts.push(("One-time password: ".into(), true));
                }

                if kinds.contains(&CredentialKind::WebUserApproval) {
                    // Two implementations, selected at configuration level.
                    // Within a connection there is no fallback: auto-continue
                    // never degrades to a manual prompt mid-flight, because a
                    // rarely-exercised degrade branch rots undetected.
                    let auto_continue = self
                        .services
                        .config
                        .lock()
                        .await
                        .store
                        .ssh
                        .web_auth_auto_continue;

                    let outcome = if auto_continue {
                        self.web_approval_round_auto(
                            &auth_state,
                            &selector,
                            &kinds,
                            &mut auth_name,
                            &mut auth_instructions,
                            &mut auth_prompts,
                            &mut next_pending,
                        )
                        .await?
                    } else {
                        self.web_approval_round_manual(
                            &auth_state,
                            &mut auth_instructions,
                            &mut auth_prompts,
                        )
                        .await
                    };

                    if let WebApprovalRoundOutcome::Return(auth) = outcome {
                        return Ok(auth);
                    }
                }

                if auth_prompts.is_empty() {
                    russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    }
                } else {
                    self.keyboard_interactive_state = Some(next_pending);
                    russh::server::Auth::Partial {
                        name: auth_name.into(),
                        instructions: auth_instructions.into(),
                        prompts: auth_prompts.into(),
                    }
                }
            }
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        })
    }

    /// Auto-continue web-approval round (`ssh.web_auth_auto_continue` on).
    ///
    /// Each round is one keyboard-interactive exchange. RFC 4256 §3.2 permits
    /// `num-prompts == 0` and §3.4 *requires* the client to answer with a
    /// zero-response message, so the client auto-acknowledges with no user
    /// interaction and hands the server a fresh round to work with. That is the
    /// whole point of this path: an AI agent or any other non-interactive SSH
    /// client never has to answer a `Press Enter when done: ` prompt.
    ///
    /// The four blocks below are mutually exclusive and each ends in a return.
    /// Read as sequential `if`s instead, the TOTP-plus-web case would fall out
    /// of the TOTP block into the new-wait test, find a matching wait and emit a
    /// zero-prompt round *instead of* the OTP prompt — so those users could
    /// never log in at all.
    #[allow(clippy::too_many_arguments)]
    async fn web_approval_round_auto(
        &mut self,
        auth_state: &Arc<Mutex<AuthState>>,
        selector: &AuthSelector,
        kinds: &HashSet<CredentialKind>,
        auth_name: &mut String,
        auth_instructions: &mut String,
        auth_prompts: &mut Vec<(Cow<'static, str>, bool)>,
        next_pending: &mut PendingKeyboardInteractiveAuth,
    ) -> Result<WebApprovalRoundOutcome> {
        let pending_wait = next_pending.web_approval_wait.take();
        // Copied out so no `AuthState` guard is alive past this statement.
        let identification_string = auth_state.lock().await.identification_string().to_owned();

        // 1. The not-confirmed message went out last round. Reject now, on the
        //    client's automatic empty response. Emitting no `Partial` is what
        //    stops this looping.
        if pending_wait.as_ref().is_some_and(|wait| wait.farewell) {
            return Ok(WebApprovalRoundOutcome::Return(
                russh::server::Auth::reject(),
            ));
        }

        // 2. TOTP is still outstanding, so this round keeps today's shape: the
        //    OTP prompt the caller queued, plus the URL in the instructions.
        //    Owned here rather than delegated to the manual round, because
        //    delegating would mean `subscribe()` never happens.
        if kinds.contains(&CredentialKind::Totp) {
            // Subscribed on the state itself: at v0.28.6 the change signal lives
            // on `AuthState`, not in a store-wide map, and sends happen under
            // the state's own lock — so subscribing here cannot miss a
            // transition and no signal entry is left behind to be vacuumed.
            let receiver = auth_state.lock().await.subscribe();
            let instructions = self.web_auth_instructions(auth_state).await;

            auth_instructions.push_str(&instructions);
            next_pending.web_approval_wait = Some(WebApprovalWait {
                receiver: Some(receiver),
                identification_string: identification_string.clone(),
                // Left unset: the budget starts at the first zero-prompt round,
                // so time spent typing the OTP does not eat it.
                deadline: None,
                round: 1,
                // This round printed the URL, so the first zero-prompt round
                // must suppress it or it goes out twice.
                url_shown: true,
                farewell: false,
            });

            return Ok(self.emit_round(
                std::mem::take(auth_name),
                std::mem::take(auth_instructions),
                std::mem::take(auth_prompts),
                next_pending,
            ));
        }

        // 3. No wait yet, or the carried one belongs to a different principal —
        //    `get_auth_state` mints a new `AuthState` when the username changes,
        //    while the carried receiver still points at the old channel. The
        //    mismatched wait is dropped here and a new one starts at round 1.
        let Some(mut wait) =
            pending_wait.filter(|wait| wait.identification_string == identification_string)
        else {
            // Charged on wait *creation* only, never per round: a per-round
            // increment against a cap of 3 would reject real users after roughly
            // 30 s, make the configured budget unreachable and turn the farewell
            // path into dead code. The count lives on `ServerSession`, so a
            // client alternating usernames to force this discard path inherits
            // it rather than resetting it.
            let (used, capped) = bump_waits(self.web_auth_waits_used);
            self.web_auth_waits_used = used;
            if capped {
                warn!(
                    waits_used = used,
                    "Too many browser-approval waits on this connection"
                );
                // Deliberately no `self.auth_state = None`: keeping
                // `get_auth_state`'s memoization means a capped client stops
                // allocating auth states, each of which the store retains for
                // ten minutes.
                return Ok(WebApprovalRoundOutcome::Return(
                    russh::server::Auth::reject(),
                ));
            }

            let receiver = auth_state.lock().await.subscribe();
            let instructions = self.web_auth_instructions(auth_state).await;

            auth_instructions.push_str(&instructions);
            next_pending.web_approval_wait = Some(WebApprovalWait {
                receiver: Some(receiver),
                identification_string,
                deadline: None,
                round: 1,
                url_shown: true,
                farewell: false,
            });

            return Ok(self.emit_round(
                std::mem::take(auth_name),
                std::mem::take(auth_instructions),
                // Zero prompts, and returning the reply from here is what keeps
                // it away from the caller's `auth_prompts.is_empty()` branch,
                // which rejects.
                std::mem::take(auth_prompts),
                next_pending,
            ));
        };

        // 4. Rounds 2..N: wait for the approval, then re-evaluate.
        //
        //    Nothing may be held across the wait — no mutex guard and no borrow
        //    of `self`. Awaiting inside the `AuthState` guard would block the
        //    browser's approve POST on the very lock this round is waiting for,
        //    and because the approve path takes the global `auth_state_store`
        //    lock while reaching for the per-state lock, one waiting SSH session
        //    would freeze SSH, HTTP, MySQL and Postgres auth gateway-wide.
        let web_auth_wait_timeout = self
            .services
            .config
            .lock()
            .await
            .store
            .ssh
            .web_auth_wait_timeout;

        let deadline = wait
            .deadline
            .unwrap_or_else(|| Instant::now() + web_auth_wait_timeout);
        wait.deadline = Some(deadline);

        // Clamped so a round never overruns the budget.
        let sleep_for =
            WEB_AUTH_POLL_CADENCE.min(deadline.saturating_duration_since(Instant::now()));

        // The signal is only an early-wake optimisation — the auth state is the
        // source of truth. A lost signal costs at most one round of latency,
        // never a hang and never a wrong verdict.
        match wait.receiver.as_mut() {
            Some(receiver) => {
                tokio::select! {
                    signal = receiver.recv() => {
                        if matches!(signal, Err(broadcast::error::RecvError::Closed)) {
                            // A closed receiver returns instantly from `select!`
                            // on every later round — spinning rounds at client
                            // RTT. Drop it and fall through to a plain clamped
                            // sleep. Nothing is lost: broadcast delivers a
                            // buffered value before reporting `Closed`, and the
                            // verdict below reads the state regardless.
                            // `Lagged` deliberately falls through instead: it
                            // means a transition was missed, and re-verifying is
                            // exactly the right response.
                            wait.receiver = None;
                        }
                    }
                    () = tokio::time::sleep(sleep_for) => {}
                }
            }
            None => tokio::time::sleep(sleep_for).await,
        }

        // Authoritative. The completion signal fires on a browser *rejection*
        // too, so being woken is not evidence of approval — only this verdict
        // can accept. Re-running the real path also keeps the `last_sso_at`
        // stamp exactly as it is today.
        let verdict = self.try_auth_lazy(selector, None).await?;

        match next_web_auth_step(Instant::now(), Some(deadline), wait.url_shown, &verdict) {
            WebAuthStep::Accept => Ok(WebApprovalRoundOutcome::Return(russh::server::Auth::Accept)),
            WebAuthStep::Reject { message: None } => Ok(WebApprovalRoundOutcome::Return(
                russh::server::Auth::reject(),
            )),
            WebAuthStep::Reject {
                message: Some(message),
            } => {
                // Two rounds, because `Auth::Reject` has no text field: the
                // message travels in a final zero-prompt `Partial` and block 1
                // rejects the client's automatic empty response.
                wait.farewell = true;
                next_pending.web_approval_wait = Some(wait);
                Ok(self.emit_round(String::new(), message, vec![], next_pending))
            }
            WebAuthStep::PollAgain { include_url } => {
                let instructions = if include_url {
                    self.web_auth_instructions(auth_state).await
                } else {
                    // Empty name and instructions: OpenSSH prints neither when
                    // they are empty, while PuTTY and Paramiko print the
                    // instruction field on *every* round — so a repeated URL
                    // would be printed once per round.
                    String::new()
                };
                wait.round = wait.round.saturating_add(1);
                wait.url_shown = true;
                next_pending.web_approval_wait = Some(wait);
                Ok(self.emit_round(String::new(), instructions, vec![], next_pending))
            }
        }
    }

    /// Build the browser-approval instructions block, with the login URL when
    /// one can be constructed.
    ///
    /// Every guard it takes is released before it returns, so it is safe to call
    /// on either side of a round wait — but never during one.
    async fn web_auth_instructions(&self, auth_state: &Arc<Mutex<AuthState>>) -> String {
        let identification_string = auth_state.lock().await.identification_string().to_owned();

        let ext_url = construct_external_url(None, &*self.services.config.lock().await, None)
            .await
            .inspect_err(|error| {
                warn!(?error, "Failed to construct external URL");
            })
            .ok();

        let auth_state = auth_state.lock().await;
        let login_url = ext_url.map(|ext_url| auth_state.construct_web_approval_url(ext_url));

        format_web_auth_instructions(login_url, &identification_string)
    }

    /// Store the pending state for the next round and emit the `Partial` that
    /// carries it.
    fn emit_round(
        &mut self,
        name: String,
        instructions: String,
        prompts: Vec<(Cow<'static, str>, bool)>,
        next_pending: &mut PendingKeyboardInteractiveAuth,
    ) -> WebApprovalRoundOutcome {
        self.keyboard_interactive_state = Some(std::mem::replace(
            next_pending,
            PendingKeyboardInteractiveAuth::fresh(),
        ));
        WebApprovalRoundOutcome::Return(russh::server::Auth::Partial {
            name: name.into(),
            instructions: instructions.into(),
            prompts: prompts.into(),
        })
    }

    /// Today's Press-Enter web-approval round, behaviour unchanged.
    ///
    /// `subscribe()` is deliberately never called on this path: doing so would
    /// create a `completion_signals` entry on every stale-pubkey login, which
    /// lives until `complete()` or `vacuum()` — a behavioural delta from today.
    async fn web_approval_round_manual(
        &mut self,
        auth_state: &Arc<Mutex<AuthState>>,
        auth_instructions: &mut String,
        auth_prompts: &mut Vec<(Cow<'static, str>, bool)>,
    ) -> WebApprovalRoundOutcome {
        // Charged first, so a capped client stops doing auth-state work. This
        // is the same per-connection budget the auto path charges — see
        // `MAX_WEB_AUTH_WAITS`.
        let is_retry = self.web_auth_waits_used > 0;
        let (used, capped) = bump_waits(self.web_auth_waits_used);
        self.web_auth_waits_used = used;
        if capped {
            warn!(
                waits_used = used,
                "Too many browser-approval waits on this connection"
            );
            self.auth_state = None;
            return WebApprovalRoundOutcome::Return(russh::server::Auth::reject());
        }

        let identification_string = auth_state.lock().await.identification_string().to_owned();

        let ext_url = construct_external_url(None, &*self.services.config.lock().await, None)
            .await
            .inspect_err(|error| {
                warn!(?error, "Failed to construct external URL");
            })
            .ok();

        let auth_state = auth_state.lock().await;
        let login_url = ext_url.map(|ext_url| auth_state.construct_web_approval_url(ext_url));

        auth_instructions.push_str(&format_web_auth_instructions(
            login_url,
            &identification_string,
        ));
        auth_prompts.push(("Press Enter when done: ".into(), true));

        if is_retry {
            auth_instructions.push_str(WEB_AUTH_NOT_CONFIRMED_MESSAGE);
        }

        WebApprovalRoundOutcome::Continue
    }

    fn get_remaining_auth_methods(&self, kinds: HashSet<CredentialKind>) -> MethodSet {
        let mut m = MethodSet::empty();

        for cred_kind in kinds {
            let method_kind = match cred_kind {
                CredentialKind::Password => MethodKind::Password,
                CredentialKind::Totp | CredentialKind::WebUserApproval | CredentialKind::Sso => {
                    MethodKind::KeyboardInteractive
                }
                CredentialKind::PublicKey => MethodKind::PublicKey,
                CredentialKind::Certificate => {
                    // Certificate authentication is not supported for SSH protocol
                    // This credential type is primarily for Kubernetes
                    continue;
                }
            };
            if self.allowed_auth_methods.contains(&method_kind) {
                m.push(method_kind);
            }
        }

        if m.contains(&MethodKind::KeyboardInteractive) {
            // Ensure keyboard-interactive is always the last method
            m.push(MethodKind::KeyboardInteractive);
        }

        m
    }

    async fn try_validate_public_key_offer(
        &self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<bool> {
        match selector {
            AuthSelector::User { username, .. } => {
                let cp = self.services.config_provider.clone();

                if let Some(credential) = credential {
                    return Ok(cp
                        .validate_credential(username, &credential)
                        .await?
                        .is_some());
                }

                Ok(false)
            }
            AuthSelector::Ticket { .. } => Ok(false),
        }
    }

    /// As try_auth_lazy is called multiple times, this memoization prevents
    /// consuming the ticket multiple times, depleting its uses.
    async fn try_auth_lazy(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        if let AuthSelector::Ticket { secret } = selector {
            if let Some(ref csta) = self.cached_successful_ticket_auth {
                // Only if the client hasn't maliciously changed the username
                // between auth attempts
                if &csta.ticket == secret {
                    return Ok(AuthResult::Accepted {
                        user_info: csta.user_info.clone(),
                    });
                }
            }

            let result = self.try_auth_eager(selector, credential).await?;
            if let AuthResult::Accepted { ref user_info } = result {
                self.cached_successful_ticket_auth = Some(CachedSuccessfulTicketAuth {
                    ticket: secret.clone(),
                    user_info: user_info.clone(),
                });
            }

            return Ok(result);
        }
        self.try_auth_eager(selector, credential).await
    }

    async fn try_auth_eager(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        let remote_ip = self.remote_address.ip();

        // Login protection applies to every auth path, tickets included:
        // reject attempts from blocked IPs before evaluating anything.
        if self
            .services
            .login_protection
            .check_ip_blocked(&remote_ip)
            .await?
            .is_some()
        {
            warn!(ip = %remote_ip, "SSH auth from blocked IP");
            return Ok(AuthResult::Rejected);
        }

        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                if self
                    .services
                    .login_protection
                    .check_user_locked(username)
                    .await?
                    .is_some()
                {
                    warn!(username = %username, "SSH auth for locked user");
                    return Ok(AuthResult::Rejected);
                }

                // Resolve default SSH target when no target is specified
                let resolved_target_name = if target_name.is_empty() {
                    let config = self.services.config.lock().await;
                    if let Some(ref default) = config.store.ssh.default_target {
                        info!("No target specified, using default SSH target: {}", default);
                        default.clone()
                    } else {
                        target_name.clone()
                    }
                } else {
                    target_name.clone()
                };

                let state_arc = self
                    .get_auth_state(
                        username,
                        target_name,
                        credential
                            .as_ref()
                            .and_then(Self::rate_limited_credential_type),
                    )
                    .await?;
                let mut state = state_arc.lock().await;

                if let Some(credential) = credential {
                    let credential_type = Self::rate_limited_credential_type(&credential);
                    let outcome = submit_credential(
                        &mut state,
                        credential,
                        self.services.config_provider.as_ref(),
                    )
                    .await?;

                    if outcome.is_valid() {
                        self.probe = ProbeState::Settled;
                    } else if let Some(credential_type) = credential_type {
                        self.record_failed_login_attempt(username, credential_type)
                            .await;
                    }
                }

                if matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval))
                {
                    drop(state);
                    self.services.try_web_approval_bypass(&state_arc).await?;
                    state = state_arc.lock().await;
                }

                let user_auth_result = state.verify();

                match user_auth_result {
                    AuthResult::Accepted { user_info } => {
                        // Successful auth clears the failed-attempt counters.
                        let _ = self
                            .services
                            .login_protection
                            .clear_failed_attempts(&remote_ip, &user_info.username)
                            .await;

                        // Step-up freshness gate (per-pubkey). If the config
                        // has `step_up_interval.ssh` set and a pubkey matched,
                        // require a `WebUserApproval` handshake at most every
                        // `interval`. A WebUserApproval already present in
                        // valid_credentials (user just finished the web
                        // approval in the keyboard-interactive loop) satisfies
                        // the gate and lets us stamp `last_sso_at` below.
                        //
                        // Defensive: if a pubkey matched but we don't have the
                        // row id (`credential_id == None`), treat the
                        // credential as stale so we force a fresh handshake
                        // rather than silently pass.
                        //
                        // Snapshot what the gate needs and drop the AuthState
                        // guard before taking the config lock, so AuthState
                        // stays the innermost lock in this module. Both reads
                        // are cheap: `matched_pubkey_id()` is Copy and
                        // `valid_credential_kinds()` clones a small HashSet.
                        let matched_pubkey_id = state.matched_pubkey_id();
                        let valid_kinds = state.valid_credential_kinds();
                        // A `WebUserApproval` that the grace-period bypass
                        // injected from a remembered approval is not proof that
                        // this attempt did an SSO handshake, so it must not
                        // satisfy the gate or move the clock below.
                        let approval_was_bypassed = state.web_approval_from_grace_bypass();
                        drop(state);

                        let step_up_ssh = {
                            let cfg = self.services.config.lock().await;
                            cfg.store.step_up_interval.as_ref().and_then(|s| s.ssh)
                        };
                        if let Some(interval) = step_up_ssh {
                            let has_stepup = web_approval_proves_step_up(
                                valid_kinds.contains(&CredentialKind::WebUserApproval),
                                approval_was_bypassed,
                            );
                            let pubkey_used = valid_kinds.contains(&CredentialKind::PublicKey);
                            if pubkey_used && !has_stepup {
                                let last = match matched_pubkey_id {
                                    Some(pubkey_id) => {
                                        get_pubkey_last_sso_at(&self.services.db, pubkey_id).await?
                                    }
                                    None => None,
                                };
                                if !is_fresh(last, interval, OffsetDateTime::now_utc()) {
                                    info!(
                                        username = %user_info.username,
                                        "SSH step-up required: pubkey last_sso_at is stale or missing"
                                    );
                                    // Flip the AuthState into step-up mode so
                                    // verify() reports Need(WebUserApproval) to
                                    // the browser approve page and to the
                                    // auth_state_store pending-request query.
                                    // Without this the UI sees Accepted, hides
                                    // the Authorize button, the approve POST
                                    // never fires, and SSH keyboard-interactive
                                    // loops until the client errors out with
                                    // "bad message during authentication".
                                    state_arc.lock().await.require_step_up();
                                    return Ok(AuthResult::Need(
                                        [CredentialKind::WebUserApproval].into_iter().collect(),
                                    ));
                                }
                            }
                        }

                        // Re-acquire for the rest of the accept path.
                        state = state_arc.lock().await;

                        let authorization = if resolved_target_name.is_empty() {
                            None
                        } else {
                            // The state is `Accepted` here, so this yields the sealed proof.
                            let Some(identity) = AuthorizedIdentity::from_auth_state(&state) else {
                                return Ok(AuthResult::Rejected);
                            };
                            let Some(authorization) = authorize_for_target_by_name(
                                self.services.config_provider.as_ref(),
                                &identity,
                                &resolved_target_name,
                            )
                            .await?
                            else {
                                warn!(
                                    "Target {} not authorized for user {}",
                                    resolved_target_name, username
                                );
                                return Ok(AuthResult::Rejected);
                            };
                            Some(authorization)
                        };
                        self._auth_accept(user_info.clone(), authorization).await?;
                        self.authentication_type = Some("user".to_string());

                        // Stamp last_sso_at on the exact pubkey row only when
                        // this accept was itself gated on a step-up - i.e.
                        // WebUserApproval was presented alongside the pubkey.
                        // Accepts that bypass the gate (step-up disabled, or
                        // still within a fresh window) must NOT refresh the
                        // clock, else the window gets silently extended on
                        // every reconnect and step-up never actually fires.
                        // That includes an approval injected by the web-approval
                        // grace period: it was granted for an earlier attempt,
                        // so stamping from it would let chained reconnects
                        // inside the grace window slide the step-up window
                        // forward forever with no SSO handshake at all.
                        if step_up_ssh.is_some()
                            && web_approval_proves_step_up(
                                valid_kinds.contains(&CredentialKind::WebUserApproval),
                                approval_was_bypassed,
                            )
                            && let Some(pubkey_id) = matched_pubkey_id
                            && let Err(error) = update_pubkey_last_sso_at(
                                &self.services.db,
                                pubkey_id,
                                OffsetDateTime::now_utc(),
                            )
                            .await
                        {
                            warn!(
                                %error,
                                %pubkey_id,
                                username = %user_info.username,
                                "Failed to stamp pubkey last_sso_at"
                            );
                        }

                        Ok(AuthResult::Accepted { user_info })
                    }
                    x => Ok(x),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(
                    &self.services.db,
                    &self.services.login_protection,
                    secret,
                    Some(remote_ip),
                    crate::PROTOCOL_NAME,
                )
                .await?
                {
                    Some((ticket, authorization)) => {
                        info!(
                            "Authorized for {} with a ticket",
                            authorization.target().name
                        );
                        consume_ticket(&self.services.db, &ticket.id).await?;
                        self.server_handle
                            .lock()
                            .await
                            .set_ticket_id(ticket.id)
                            .await?;
                        let user_info = authorization.user_info().clone();
                        self._auth_accept(user_info.clone(), Some(authorization))
                            .await?;
                        self.authentication_type = Some("ticket".to_string());

                        Ok(AuthResult::Accepted { user_info })
                    }
                    None => Ok(AuthResult::Rejected),
                }
            }
        }
    }

    async fn _auth_accept(
        &mut self,
        user_info: AuthStateUserInfo,
        authorization: Option<TargetAuthorization>,
    ) -> Result<(), WarpgateError> {
        self.user_info = Some(user_info.clone());
        let _ = self
            .server_handle
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await;

        let Some(authorization) = authorization else {
            self.target = TargetSelection::Menu;
            return Ok(());
        };

        // The authorization already carries the resolved target; all that's left is
        // that it be reachable over SSH.
        if !matches!(authorization.target().options, TargetOptions::Ssh(_)) {
            self.target = TargetSelection::NotFound(authorization.target().name.clone());
            warn!("Selected target is not an SSH target");
            return Ok(());
        }

        let _ = self
            .server_handle
            .lock()
            .await
            .set_target(authorization.target())
            .await;
        self.target = TargetSelection::Found(authorization);
        Ok(())
    }

    async fn _channel_close(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring close after backend shutdown");
            return Ok(());
        }

        let Ok(channel_id) = self.map_channel(server_channel_id) else {
            debug!(channel=%server_channel_id.0, "Channel already closed");
            return Ok(());
        };
        debug!(channel=%channel_id, "Closing channel");
        self.send_command_and_wait(RCCommand::Channel(channel_id, ChannelOperation::Close))
            .await?;
        self.channels.close(channel_id);
        Ok(())
    }

    fn _channel_eof(&self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring eof after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "EOF");
        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Eof));
        Ok(())
    }

    pub async fn _channel_signal(
        &mut self,
        server_channel_id: ServerChannelId,
        signal: Sig,
    ) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, ?signal, "Ignoring signal after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, ?signal, "Signal");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::Signal(signal),
        ))
        .await?;
        Ok(())
    }

    fn send_command(&self, command: RCCommand) -> Result<(), RCCommand> {
        self.rc_tx.send((command, None)).map_err(|e| e.0.0)
    }

    /// Send a command to the target and pump the event loop until its reply
    /// arrives on the oneshot.
    ///
    /// Pumping is not optional: the reply can depend on an event of our own —
    /// the target's unknown-host-key prompt is answered from
    /// [`Self::handle_unknown_host_key`], off this very queue — so merely
    /// draining the queue would deadlock. Past [`MAX_NESTED_COMMAND_WAITS`]
    /// events are buffered instead of dispatched, bounding the stack that the
    /// re-entrant handlers build up.
    async fn send_command_and_wait(&mut self, command: RCCommand) -> Result<(), SshClientError> {
        let (tx, rx) = oneshot::channel();
        let mut cmd = match self.rc_tx.send((command, Some(tx))) {
            Ok(()) => PendingCommand::Waiting(rx),
            Err(_) => PendingCommand::Failed,
        };

        self.command_wait_depth += 1;
        let result = loop {
            tokio::select! {
                result = &mut cmd => {
                    break result
                }
                event = self.get_next_event() => {
                    match event {
                        Some(event) => {
                            if self.command_wait_depth > MAX_NESTED_COMMAND_WAITS {
                                self.pending_events.push_back(event);
                            } else if let Err(error) = self.handle_event(event).await {
                                break Err(error.into());
                            }
                        }
                        None => break Err(SshClientError::MpscError),
                    }
                }
            }
        };
        self.command_wait_depth -= 1;
        result
    }

    pub fn _disconnect(&self) {
        debug!("Client disconnect requested");
        self.request_disconnect();
    }

    fn request_disconnect(&self) {
        debug!("Disconnecting");
        let _ = self.rc_abort_tx.send(());
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            let _ = self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        // Entries stay in place: several callers return into the running event
        // loop, which still needs the channels to record trailing output and to
        // map target events back to the client. Closing twice is harmless —
        // `session_handle` is cleared below, so the second pass sends nothing.
        let channels = self
            .channels
            .values()
            .filter(|channel| channel.is_open())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();

        if let Some(handle) = self.session_handle.clone() {
            for ch in channels {
                let _ = self.channel_writer.close(handle.clone(), ch.0);
            }
        }

        // Give queued writes — the closes above, and any error or timeout
        // notice emitted before them — a chance to reach the client. Bounded:
        // a client whose window is full never lets the queue drain, and this
        // runs on the event loop.
        let _ = tokio::time::timeout(DISCONNECT_FLUSH_TIMEOUT, self.channel_writer.flush()).await;

        self.session_handle = None;
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        let _ = self.rc_abort_tx.send(());
        info!("Closed session");
        debug!("Dropped");
    }
}

pub enum PendingCommand {
    Waiting(oneshot::Receiver<Result<(), SshClientError>>),
    Failed,
}

impl Future for PendingCommand {
    type Output = Result<(), SshClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Waiting(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(result) => {
                    Poll::Ready(result.unwrap_or(Err(SshClientError::MpscError)))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Failed => Poll::Ready(Err(SshClientError::MpscError)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    use russh::{MethodKind, MethodSet};
    use tokio::sync::broadcast;
    use uuid::Uuid;
    use warpgate_common::auth::{AuthResult, AuthStateUserInfo, CredentialKind};

    use super::{
        MAX_WEB_AUTH_WAITS, PendingKeyboardInteractiveAuth, WebApprovalWait, WebAuthStep,
        bump_waits, carry_forward, next_web_auth_step, reject_with_allowed_auth_methods,
        wait_for_state,
    };

    #[test]
    fn rejected_public_key_auth_advertises_only_configured_methods() {
        let configured_methods = MethodSet::from(&[MethodKind::PublicKey][..]);
        let auth = reject_with_allowed_auth_methods(configured_methods.clone());

        let russh::server::Auth::Reject {
            proceed_with_methods: Some(advertised_methods),
            ..
        } = auth
        else {
            panic!("expected an authentication rejection with advertised methods");
        };

        assert_eq!(advertised_methods, configured_methods);
        assert!(!advertised_methods.contains(&MethodKind::Password));
        assert!(!advertised_methods.contains(&MethodKind::KeyboardInteractive));
    }

    /// The step-up gate and the `last_sso_at` stamp must both refuse an
    /// approval that the grace-period bypass injected. Otherwise a user whose
    /// credential policy lists `WebUserApproval` re-stamps `last_sso_at` on
    /// every reconnect inside `web_approval_grace_period_seconds`, and the
    /// step-up interval never fires again.
    #[test]
    fn a_bypassed_web_approval_neither_satisfies_step_up_nor_stamps_last_sso_at() {
        // A real approval collected by this attempt: gate satisfied, stamp taken.
        assert!(super::web_approval_proves_step_up(true, false));

        // The same credential, injected by the grace-period bypass: neither.
        assert!(
            !super::web_approval_proves_step_up(true, true),
            "a grace-period bypass must not count as a step-up handshake, or \
             last_sso_at is re-stamped on every reconnect inside the window"
        );

        // No approval at all: the gate falls through to the freshness read.
        assert!(!super::web_approval_proves_step_up(false, false));
        assert!(!super::web_approval_proves_step_up(false, true));
    }

    fn accepted() -> AuthResult {
        AuthResult::Accepted {
            user_info: AuthStateUserInfo {
                id: Uuid::nil(),
                username: "someone".to_owned(),
            },
        }
    }

    fn need_web_approval() -> AuthResult {
        AuthResult::Need(
            [CredentialKind::WebUserApproval]
                .into_iter()
                .collect::<HashSet<_>>(),
        )
    }

    fn wait_bound_to(
        identification_string: &str,
        sender: &broadcast::Sender<AuthResult>,
    ) -> WebApprovalWait {
        WebApprovalWait {
            receiver: Some(sender.subscribe()),
            identification_string: identification_string.to_owned(),
            deadline: None,
            round: 7,
            url_shown: true,
            farewell: false,
        }
    }

    /// I3: a wait is bound to one principal. `get_auth_state` mints a new
    /// `AuthState` when the username changes, while a carried receiver still
    /// points at the previous state's channel — so a mismatching state key must
    /// discard the wait rather than let one principal's approval wake another's
    /// session.
    #[test]
    fn unit_web_auth_state_id_mismatch_discards_the_wait() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let mine = "1A2B";
        let theirs = "9F0E";

        let kept = wait_for_state(Some(wait_bound_to(mine, &sender)), mine)
            .expect("a wait bound to the current state must survive");
        assert_eq!(kept.round, 7);
        assert!(kept.receiver.is_some());

        assert!(
            wait_for_state(Some(kept), theirs).is_none(),
            "a wait bound to a different auth state must be discarded"
        );
    }

    /// I6: the wait counter lives on the connection, not on the wait, so the I3
    /// discard path inherits it. If a mid-connection username switch reset the
    /// budget, a client could alternate usernames to sustain waits — and each
    /// restart allocates an `AuthState` the store retains for ten minutes.
    #[test]
    fn unit_web_auth_discard_path_inherits_the_wait_counter() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);

        // Three waits already spent on this connection.
        let mut used = 0u8;
        for _ in 0..MAX_WEB_AUTH_WAITS {
            let (next, capped) = bump_waits(used);
            used = next;
            assert!(!capped);
        }

        // A username switch discards the carried wait entirely...
        assert!(wait_for_state(Some(wait_bound_to("1A2B", &sender)), "9F0E").is_none());

        // ...and the wait it forces is charged against the inherited count.
        let (used, capped) = bump_waits(used);
        assert_eq!(used, MAX_WEB_AUTH_WAITS + 1);
        assert!(capped, "a discard must not restart the wait budget");
    }

    /// I6: the cap counts **waits**, not rounds — three waits pass and the
    /// fourth rejects. A per-round increment would reject real users at roughly
    /// 30 s at the 10 s cadence, making the 2 m budget unreachable and the
    /// farewell path dead code.
    #[test]
    fn unit_web_auth_wait_cap_permits_exactly_three_waits() {
        assert_eq!(MAX_WEB_AUTH_WAITS, 3);
        assert_eq!(bump_waits(0), (1, false));
        assert_eq!(bump_waits(1), (2, false));
        assert_eq!(bump_waits(2), (3, false));
        assert_eq!(bump_waits(3), (4, true));
    }

    /// I6: the counter saturates rather than wrapping. Post-cap, every further
    /// attempt still increments before rejecting, so a wrapping `u8` would hand
    /// the client a fresh three-wait budget every ~256 attempts — silently,
    /// since the release profile sets no `overflow-checks`.
    #[test]
    fn unit_web_auth_wait_cap_saturates_instead_of_wrapping() {
        assert_eq!(bump_waits(u8::MAX), (u8::MAX, true));
        assert_ne!(bump_waits(u8::MAX).0, 0);
    }

    /// I4: the wait — and therefore its live broadcast receiver — has to survive
    /// being carried from one keyboard-interactive round to the next. The naive
    /// implementation drops the receiver every round, so there are zero
    /// subscribers at the moment `complete()` sends, `send()` returns `Err`,
    /// warpgate discards it, and approval is only noticed at the next tick.
    #[tokio::test]
    async fn unit_web_auth_wait_receiver_survives_a_round() {
        let (sender, _) = broadcast::channel::<AuthResult>(1);
        let previous = PendingKeyboardInteractiveAuth {
            otp_prompt_sent: true,
            web_approval_wait: Some(WebApprovalWait {
                receiver: Some(sender.subscribe()),
                identification_string: "AAAA".to_owned(),
                deadline: None,
                round: 1,
                url_shown: true,
                farewell: false,
            }),
        };

        let next = carry_forward(previous);

        let carried = next
            .web_approval_wait
            .expect("the wait must be carried into the next round");
        let mut receiver = carried
            .receiver
            .expect("the carried wait must still hold its receiver");

        sender
            .send(accepted())
            .expect("the carried receiver must still be subscribed");
        assert!(matches!(
            receiver.recv().await,
            Ok(AuthResult::Accepted { .. })
        ));
    }

    /// I2: an `Accepted` verdict is the only thing that accepts, and it does so
    /// unconditionally.
    #[test]
    fn unit_web_auth_accepted_verdict_accepts() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, Some(now + Duration::from_secs(60)), true, &accepted()),
            WebAuthStep::Accept
        );
    }

    /// Accept wins over an expired budget: by the time a verdict of `Accepted`
    /// exists, `_auth_accept`, `complete()` and the `last_sso_at` stamp have
    /// already run, so rejecting on a stale deadline would discard a completed
    /// authentication.
    #[test]
    fn unit_web_auth_accepted_beats_expired_deadline() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, Some(now - Duration::from_secs(1)), true, &accepted()),
            WebAuthStep::Accept
        );
    }

    /// I2: the browser-reject sequence — `api_reject_auth` fires the same wake
    /// signal as an approval, so a `Rejected` verdict must reject at once
    /// rather than waiting out the budget.
    #[test]
    fn unit_web_auth_rejected_verdict_rejects_immediately() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                true,
                &AuthResult::Rejected
            ),
            WebAuthStep::Reject { message: None }
        );
    }

    /// First zero-prompt round with budget left: poll again, carrying the URL.
    #[test]
    fn unit_web_auth_need_first_round_includes_url() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                false,
                &need_web_approval()
            ),
            WebAuthStep::PollAgain { include_url: true }
        );
    }

    /// I5 / SC2: once the URL has been shown, later rounds must suppress it —
    /// PuTTY and Paramiko print the instruction field on every round.
    #[test]
    fn unit_web_auth_need_later_round_suppresses_url() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(
                now,
                Some(now + Duration::from_secs(60)),
                true,
                &need_web_approval()
            ),
            WebAuthStep::PollAgain { include_url: false }
        );
    }

    /// A deadline that has not been set yet (the first zero-prompt round has
    /// not happened) can never expire.
    #[test]
    fn unit_web_auth_need_without_deadline_polls_again() {
        let now = Instant::now();
        assert_eq!(
            next_web_auth_step(now, None, false, &need_web_approval()),
            WebAuthStep::PollAgain { include_url: true }
        );
    }

    /// SC3: budget expiry rejects, and carries the not-confirmed text so it can
    /// be delivered in a farewell round (`Auth::Reject` has no message field).
    #[test]
    fn unit_web_auth_need_expired_deadline_rejects_with_message() {
        let now = Instant::now();
        let step = next_web_auth_step(
            now,
            Some(now - Duration::from_secs(1)),
            true,
            &need_web_approval(),
        );
        let WebAuthStep::Reject {
            message: Some(message),
        } = step
        else {
            panic!("expected a Reject carrying a message, got {step:?}");
        };
        assert!(
            message.contains("not confirmed"),
            "farewell message should carry the not-confirmed text, got {message:?}"
        );
    }

    /// Exact boundary: `now == deadline` is expired, matching the `now >= deadline`
    /// test in the spec algorithm.
    #[test]
    fn unit_web_auth_need_exact_boundary_deadline_rejects() {
        let now = Instant::now();
        assert!(matches!(
            next_web_auth_step(now, Some(now), true, &need_web_approval()),
            WebAuthStep::Reject { message: Some(_) }
        ));
    }
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, CredentialKind};
use warpgate_common::helpers::ipnet::WarpgateIpNet;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{SessionId, WarpgateError};

use crate::login_protection::{FailedAttemptInfo, LoginProtectionService};
use crate::{ConfigProvider, ConfigProviderEnum};

#[allow(clippy::unwrap_used)]
pub static TIMEOUT: LazyLock<Duration> = LazyLock::new(|| Duration::from_secs(60 * 10));

/// If the address is an IPv4-mapped IPv6 address (e.g. `::ffff:192.168.1.1`),
/// extract the inner IPv4 address. Otherwise return as-is.
const fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

/// Forwards web-approval requests from one auth state's change stream to the
/// store-wide `web_auth_request_signal`, which is what lets the web UI list
/// pending approvals. Spawned once per auth state.
async fn forward_web_auth_requests(
    mut state_change_rx: broadcast::Receiver<AuthResult>,
    web_auth_request_signal: broadcast::Sender<Uuid>,
    id: Uuid,
) {
    while let Ok(AuthResult::Need(result)) = state_change_rx.recv().await {
        if result.contains(&CredentialKind::WebUserApproval) {
            let _ = web_auth_request_signal.send(id);
        }
    }
}

/// Checks whether the given IP is allowed by the user's `allowed_ip_ranges` setting.
/// Returns `Ok(())` if access is allowed, or an appropriate `WarpgateError` if denied.
fn check_ip_allowed(
    allowed_ip_ranges: Option<&Vec<WarpgateIpNet>>,
    remote_ip: Option<IpAddr>,
    username: &str,
) -> Result<(), WarpgateError> {
    let Some(ranges) = allowed_ip_ranges else {
        return Ok(());
    };
    if ranges.is_empty() {
        return Ok(());
    }
    let Some(raw_ip) = remote_ip else {
        return Ok(());
    };
    let ip = normalize_ip(raw_ip);
    for network in ranges {
        if network.contains(&ip) {
            return Ok(());
        }
    }
    tracing::warn!(
        "Access denied for IP '{}' (not in any allowed range for user '{}')",
        ip,
        username
    );
    Err(WarpgateError::IpAddrNotAllowed(
        ip.to_string(),
        username.into(),
    ))
}

struct AuthCompletionSignal {
    sender: broadcast::Sender<AuthResult>,
    created_at: Instant,
}

impl AuthCompletionSignal {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > *TIMEOUT
    }
}

pub struct AuthStateStore {
    config_provider: Arc<Mutex<ConfigProviderEnum>>,
    login_protection: Arc<LoginProtectionService>,
    store: HashMap<Uuid, (Arc<Mutex<AuthState>>, Instant)>,
    completion_signals: HashMap<Uuid, AuthCompletionSignal>,
    web_auth_request_signal: broadcast::Sender<Uuid>,
}

impl AuthStateStore {
    pub fn new(
        config_provider: Arc<Mutex<ConfigProviderEnum>>,
        login_protection: Arc<LoginProtectionService>,
    ) -> Self {
        Self {
            store: HashMap::new(),
            config_provider,
            login_protection,
            completion_signals: HashMap::new(),
            web_auth_request_signal: broadcast::channel(100).0,
        }
    }

    /// Record a failed attempt for an unknown username so that username
    /// enumeration counts toward IP blocking, just like a wrong password would.
    ///
    /// `credential_type` is `None` for contexts that must not be penalised —
    /// notably SSH public-key offers, which legitimately fail as clients try
    /// each agent key in turn — in which case nothing is recorded.
    async fn record_unknown_user_attempt(
        &self,
        username: &str,
        protocol: &str,
        remote_ip: Option<IpAddr>,
        credential_type: Option<&str>,
    ) {
        let (Some(remote_ip), Some(credential_type)) = (remote_ip, credential_type) else {
            return;
        };
        let _ = self
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: username.to_string(),
                remote_ip,
                protocol: protocol.to_string(),
                credential_type: credential_type.to_string(),
            })
            .await;
    }

    pub fn contains_key(&self, id: &Uuid) -> bool {
        self.store.contains_key(id)
    }

    pub async fn all_pending_web_auths_for_user(
        &self,
        username: &str,
    ) -> Vec<Arc<Mutex<AuthState>>> {
        let mut results = vec![];
        for auth in self.store.values() {
            {
                let inner = auth.0.lock().await;
                if !username_eq_ci(&inner.user_info().username, username) {
                    continue;
                }
                let AuthResult::Need(need) = inner.verify() else {
                    continue;
                };
                if !need.contains(&CredentialKind::WebUserApproval) {
                    continue;
                }
            }
            results.push(auth.0.clone());
        }
        results
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<Mutex<AuthState>>> {
        self.store.get(id).map(|x| x.0.clone())
    }

    pub fn subscribe_web_auth_request(&self) -> broadcast::Receiver<Uuid> {
        self.web_auth_request_signal.subscribe()
    }

    pub async fn create(
        &mut self,
        session_id: Option<&SessionId>,
        username: &str,
        protocol: &str,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<(Uuid, Arc<Mutex<AuthState>>), WarpgateError> {
        let id = Uuid::new_v4();

        let Some(user) = self
            .config_provider
            .lock()
            .await
            .list_users()
            .await?
            .iter()
            .find(|u| username_eq_ci(&u.username, username))
            .cloned()
        else {
            self.record_unknown_user_attempt(
                username,
                protocol,
                remote_ip,
                rate_limit_credential_type,
            )
            .await;
            return Err(WarpgateError::UserNotFound(username.into()));
        };

        check_ip_allowed(user.allowed_ip_ranges.as_ref(), remote_ip, username)?;

        let policy = self
            .config_provider
            .lock()
            .await
            .get_credential_policy(username, supported_credential_types)
            .await?;
        let Some(policy) = policy else {
            self.record_unknown_user_attempt(
                username,
                protocol,
                remote_ip,
                rate_limit_credential_type,
            )
            .await;
            return Err(WarpgateError::UserNotFound(username.into()));
        };

        let (state_change_tx, state_change_rx) = broadcast::channel(1);
        let web_auth_request_signal = self.web_auth_request_signal.clone();
        tokio::spawn(forward_web_auth_requests(
            state_change_rx,
            web_auth_request_signal,
            id,
        ));

        let state = AuthState::new(
            id,
            session_id.copied(),
            remote_ip,
            (&user).into(),
            protocol.to_string(),
            policy,
            state_change_tx,
        );
        self.store
            .insert(id, (Arc::new(Mutex::new(state)), Instant::now()));

        #[allow(clippy::unwrap_used)]
        Ok((id, self.get(&id).unwrap()))
    }

    pub fn subscribe(&mut self, id: Uuid) -> broadcast::Receiver<AuthResult> {
        let signal = self.completion_signals.entry(id).or_insert_with(|| {
            let (sender, _) = broadcast::channel(1);
            AuthCompletionSignal {
                sender,
                created_at: Instant::now(),
            }
        });

        signal.sender.subscribe()
    }

    pub async fn complete(&mut self, id: &Uuid) {
        let Some((state, _)) = self.store.get(id) else {
            return;
        };
        if let Some(sig) = self.completion_signals.remove(id) {
            let _ = sig.sender.send(state.lock().await.verify());
        }
    }

    pub fn vacuum(&mut self) {
        self.store
            .retain(|_, (_, started_at)| started_at.elapsed() < *TIMEOUT);

        self.completion_signals
            .retain(|_, signal| !signal.is_expired());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::str::FromStr;

    use ipnet::IpNet;

    use super::*;

    /// Drives `forward_web_auth_requests` over a pre-loaded channel.
    ///
    /// The sender is dropped before the forwarder runs, so the receiver drains
    /// whatever is buffered and then observes `Closed` — which makes every case
    /// below deterministic, with no sleeps and no task scheduling races. A
    /// channel capacity of 1 matches production.
    async fn drain(sent: Vec<AuthResult>) -> Vec<Uuid> {
        let id = Uuid::new_v4();
        let (state_change_tx, state_change_rx) = broadcast::channel(1);
        let (signal_tx, mut signal_rx) = broadcast::channel(16);

        for value in sent {
            let _ = state_change_tx.send(value);
        }
        drop(state_change_tx);

        forward_web_auth_requests(state_change_rx, signal_tx, id).await;

        let mut fired = vec![];
        while let Ok(got) = signal_rx.try_recv() {
            fired.push(got);
        }
        fired
    }

    fn need_web_approval() -> AuthResult {
        AuthResult::Need(HashSet::from([CredentialKind::WebUserApproval]))
    }

    #[tokio::test]
    async fn unit_forwarder_survives_a_non_need_verdict() {
        // `Rejected` is not a web-approval request, but the state machine can
        // still emit a `Need` afterwards. Bailing out on the first non-`Need`
        // value strands the auth state with no signal ever sent.
        let fired = drain(vec![AuthResult::Rejected, need_web_approval()]).await;
        assert_eq!(fired.len(), 1, "signal must still fire after a non-Need verdict");
    }

    #[tokio::test]
    async fn unit_forwarder_survives_a_lagged_receiver() {
        // Capacity is 1, so pushing two values before the forwarder polls makes
        // the receiver lag and `recv()` yield `Err(Lagged)`. Treating that as
        // terminal kills the forwarder for the rest of the auth state's life.
        let fired = drain(vec![
            AuthResult::Rejected,
            AuthResult::Rejected,
            need_web_approval(),
        ])
        .await;
        assert_eq!(fired.len(), 1, "signal must still fire after a Lagged error");
    }

    #[tokio::test]
    async fn unit_forwarder_ignores_need_without_web_approval() {
        let fired = drain(vec![AuthResult::Need(HashSet::from([
            CredentialKind::Password,
        ]))])
        .await;
        assert!(
            fired.is_empty(),
            "a Need that does not ask for web approval must not signal"
        );
    }

    #[tokio::test]
    async fn unit_forwarder_exits_when_sender_is_dropped() {
        // `drain` awaits the forwarder to completion, so this test hanging
        // rather than failing is itself the regression signal for `Closed`
        // no longer terminating the loop.
        assert!(drain(vec![]).await.is_empty());
    }

    #[test]
    fn ip_allowed_no_restriction() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(check_ip_allowed(None, Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_allowed_no_remote_ip() {
        let range = Some(vec![IpNet::from_str("10.0.0.0/8").unwrap().into()]);
        assert!(check_ip_allowed(range.as_ref(), None, "user").is_ok());
    }

    #[test]
    fn ip_allowed_within_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_denied_outside_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let err = check_ip_allowed(range.as_ref(), Some(ip), "testuser").unwrap_err();
        assert!(
            matches!(err, WarpgateError::IpAddrNotAllowed(addr, user) if addr == "10.0.0.1" && user == "testuser")
        );
    }

    #[test]
    fn ip_allowed_exact_match() {
        let range = Some(vec![IpNet::from_str("10.20.30.40/32").unwrap().into()]);
        let ip: IpAddr = "10.20.30.40".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_denied_exact_mismatch() {
        let range = Some(vec![IpNet::from_str("10.20.30.40/32").unwrap().into()]);
        let ip: IpAddr = "10.20.30.41".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }

    #[test]
    fn ipv6_allowed_within_range() {
        let range = Some(vec![IpNet::from_str("fd00::/8").unwrap().into()]);
        let ip: IpAddr = "fd12:3456::1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv6_denied_outside_range() {
        let range = Some(vec![IpNet::from_str("fd00::/8").unwrap().into()]);
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }

    #[test]
    fn ip_allowed_both_none() {
        assert!(check_ip_allowed(None, None, "user").is_ok());
    }

    #[test]
    fn ip_allowed_empty_ranges_treated_as_no_restriction() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(check_ip_allowed(Some(&vec![]), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        // ::ffff:192.168.1.42 is the IPv4-mapped IPv6 form of 192.168.1.42
        let ip: IpAddr = "::ffff:192.168.1.42".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_denied_outside_ipv4_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }
}

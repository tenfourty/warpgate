use core::str;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::error::InternalServerError;
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Protocol, SessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
    X_WARPGATE_CLUSTER_IDENTITY, is_cluster_peer_request,
};
use warpgate_core::{ConfigProvider, vet_credential_bearer};
use warpgate_db_entities::User;
use warpgate_sso::WarpgateIdToken;

use crate::catchall::{
    PublicTargetDecision, is_warpgate_management_path, resolve_public_target_decision,
};
use crate::session::SessionStore;
use crate::step_up::{StepUpSessionExt, is_session_step_up_stale};

pub const PROTOCOL_NAME: Protocol = Protocol::Http;
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_SSO_LOGIN_STATE: &str = "auth_sso_login_state";
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";
pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

pub fn host_is_subdomain_of_or_equal(host: &str, base_domain: &str) -> bool {
    let base = base_domain.trim_start_matches('.');
    host == base || host.ends_with(&format!(".{base}"))
}

#[derive(Serialize, Deserialize)]
pub struct SsoLoginState {
    pub token: WarpgateIdToken,
    pub provider: String,
    pub supports_single_logout: bool,
}

pub trait SessionExt {
    fn get_target_name(&self) -> Option<String>;
    fn set_target_name(&self, target_name: String);
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    fn clear_auth(&self);
    /// The Warpgate session id of this browser session, once one has been
    /// registered for it. Unlike [`session_id_for_request`] this never creates
    /// one.
    fn get_session_id(&self) -> Option<SessionId>;

    fn get_sso_login_state(&self) -> Option<SsoLoginState>;
    fn set_sso_login_state(&self, token: SsoLoginState);
}

impl SessionExt for Session {
    fn get_target_name(&self) -> Option<String> {
        self.get(TARGET_SESSION_KEY)
    }

    fn set_target_name(&self, target_name: String) {
        self.set(TARGET_SESSION_KEY, target_name);
    }

    fn get_auth(&self) -> Option<SessionAuthorization> {
        self.get(AUTH_SESSION_KEY)
    }

    fn set_auth(&self, auth: SessionAuthorization) {
        self.set(AUTH_SESSION_KEY, auth);
    }

    fn clear_auth(&self) {
        self.remove(AUTH_SESSION_KEY);
    }

    fn get_session_id(&self) -> Option<SessionId> {
        self.get(crate::session::SESSION_ID_SESSION_KEY)
    }

    fn get_sso_login_state(&self) -> Option<SsoLoginState> {
        self.get::<String>(AUTH_SSO_LOGIN_STATE)
            .and_then(|x| serde_json::from_str(&x).ok())
    }

    fn set_sso_login_state(&self, state: SsoLoginState) {
        if let Ok(json) = serde_json::to_string(&state) {
            self.set(AUTH_SSO_LOGIN_STATE, json);
        }
    }
}

pub async fn is_user_admin(ctx: &AuthenticatedRequestContext) -> poem::Result<bool> {
    // A user is an administrator if they hold any admin permission. Resolved through the one
    // shared permission loader so this can't drift from the endpoint gate or the /info UI.
    Ok(warpgate_admin::api::admin_permission_set(ctx)
        .await
        .map_err(InternalServerError)?
        .is_admin())
}

/// Run the per-request authentication gate.
///
/// Returns `Ok(Ok(output))` when the request is authenticated (the wrapped
/// endpoint was called), or `Ok(Err(req))` when it is not — handing the
/// untouched `Request` back to the caller so it can build a redirect / 401
/// response (see `page_auth`, which needs the request to compute an SSO
/// auto-redirect on the unauthenticated path).
pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Result<E::Output, Request>> {
    let ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(&req).await?;
    let Some(ctx) = ctx else {
        return Ok(Err(req));
    };

    // Per-session SSO step-up gate. If the session is authed as a `User` (not
    // a ticket, not an API token) and the configured HTTP interval has elapsed
    // since the last SSO handshake on this session, forcibly re-auth: clear the
    // session auth + stamp, then return `None` so that the surrounding
    // `page_auth` / `endpoint_auth` wrapper redirects to the gateway login page
    // (which single-provider SSO deployments auto-forward to the IdP). Tickets /
    // tokens / anonymous fall through unchanged - we only pay the config-lock +
    // session-read cost on the `User` path to keep the hot path cheap for
    // token-authed traffic.
    if let RequestAuthorization::Session(session_auth @ SessionAuthorization::User { .. }) =
        &ctx.auth
    {
        // Pull the interval first; absent config -> feature off, skip the
        // session read entirely to keep the hot path cheap.
        let interval = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .step_up_interval
            .as_ref()
            .and_then(|s| s.http);
        if interval.is_some() {
            let session = <&Session>::from_request_without_body(&req).await?;
            let last_sso_at = session.get_last_sso_at();
            if is_session_step_up_stale(
                Some(session_auth),
                last_sso_at,
                interval,
                OffsetDateTime::now_utc(),
            ) {
                info!(
                    username = %session_auth.username(),
                    has_stamp = last_sso_at.is_some(),
                    "HTTP step-up required: session last_sso_at is stale or missing"
                );
                // Drop just the auth claims + stamp; keep the rest of the
                // session (e.g. SSO context set by `start_sso`) so the forced
                // re-login can still complete its OAuth handshake.
                session.clear_auth();
                session.clear_last_sso_at();
                return Ok(Err(req));
            }
        }
    }

    return ep.call(req).await.map(Ok);
}

// TODO unify both based on the accept header
pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint<Output = E::Output> {
    e.around(|ep, req| async move {
        _inner_auth(ep, req)
            .await?
            .map_err(|_req| poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        // Per-VM-proxy P0 (M9): public-target bypass. If the request resolves
        // to an HTTP target with `public: true`, anonymous and session-authed
        // clients are routed through to the catchall without the normal
        // session/role gate; admin/user/cluster tokens hit a public target
        // -> 401 (those tokens are not proxy-scoped). `page_auth` only wraps
        // the catchall mount, so this never runs on the `/@warpgate` routes.
        match try_public_target_bypass(&req).await? {
            PublicBypassOutcome::Bypass(synthetic_ctx) => {
                // Override any pre-existing AuthenticatedRequestContext with
                // the synthetic Ticket-style auth so the catchall's existing
                // Ticket arm (resolve by target_id, no role check) routes the
                // request to the resolved public target. `_inner_auth`'s SSO
                // step-up logic is gated on `Session(User { .. })` and so is
                // also skipped.
                return Ok(ep.data(synthetic_ctx).call(req).await?.into_response());
            }
            PublicBypassOutcome::Reject401 => {
                return Err(poem::Error::from_string(
                    "API tokens are not valid for public-target proxy access",
                    StatusCode::UNAUTHORIZED,
                ));
            }
            PublicBypassOutcome::NotApplicable => {}
        }

        match _inner_auth(ep, req).await? {
            Ok(output) => Ok(output.into_response()),
            Err(req) => {
                // Unauthenticated navigation. If the operator has opted into
                // single-provider SSO auto-redirect, jump straight to the IdP
                // authorize URL (preserving the original path) instead of
                // flashing the gateway login SPA. Otherwise fall through to the
                // existing gateway-redirect / 401 behaviour unchanged.
                if let Some(resp) = try_auto_sso_redirect(&req).await? {
                    return Ok(resp);
                }
                Ok(gateway_redirect(&req).into_response())
            }
        }
    })
}

/// Pure decision for the single-provider SSO auto-redirect. Kept side-effect
/// free so every branch can be unit-tested without a `Services` fixture.
///
/// Returns true iff the feature is enabled, exactly one SSO provider is
/// configured, the request is a top-level browser navigation, the break-glass
/// `?login=password` bypass is absent, and the target is not a Warpgate
/// management path.
pub(crate) const fn should_auto_sso_redirect(
    sso_auto_redirect_enabled: bool,
    sso_provider_count: usize,
    is_navigation: bool,
    has_password_bypass: bool,
    is_management_path: bool,
) -> bool {
    sso_auto_redirect_enabled
        && sso_provider_count == 1
        && is_navigation
        && !has_password_bypass
        && !is_management_path
}

/// Whether the request is a top-level browser navigation, using the same
/// `sec-fetch-mode` heuristic as [`gateway_redirect`] (header absent or
/// explicitly `navigate`).
fn request_is_navigation(req: &Request) -> bool {
    match req.headers().get(HeaderName::from_static("sec-fetch-mode")) {
        Some(mode) => mode == "navigate",
        None => true,
    }
}

/// Break-glass: a `?login=password` query param bypasses the auto-redirect so
/// an operator can always reach the SPA password login.
fn request_has_password_bypass(req: &Request) -> bool {
    req.uri().query().is_some_and(|q| {
        url::form_urlencoded::parse(q.as_bytes()).any(|(k, v)| k == "login" && v == "password")
    })
}

/// On the unauthenticated navigation path, consult the `sso_auto_redirect`
/// parameter + configured SSO providers and, when appropriate, initiate an SSO
/// login and return a 302 to the IdP authorize URL. Returns `Ok(None)` to let
/// the caller fall through to the normal gateway redirect / 401.
async fn try_auto_sso_redirect(req: &Request) -> poem::Result<Option<Response>> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;

    let is_navigation = request_is_navigation(req);
    let has_password_bypass = request_has_password_bypass(req);
    let is_management_path = is_warpgate_management_path(req.uri().path());

    // Cheap gates first — avoid the DB read + config lock unless the request
    // could actually be redirected.
    if !is_navigation || has_password_bypass || is_management_path {
        return Ok(None);
    }

    let sso_auto_redirect_enabled = ctx
        .parameters()
        .await
        .map_err(InternalServerError)?
        .sso_auto_redirect;

    // Read the sole provider's name (if exactly one), then drop the config
    // lock before calling the SSO helper, which re-locks it internally.
    let sole_provider = {
        let config = ctx.services().config.lock().await;
        let providers = &config.store.sso_providers;
        if should_auto_sso_redirect(
            sso_auto_redirect_enabled,
            providers.len(),
            is_navigation,
            has_password_bypass,
            is_management_path,
        ) {
            providers.first().map(|p| p.name.clone())
        } else {
            None
        }
    };

    let Some(provider_name) = sole_provider else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let next = req.original_uri().path_and_query().map(ToString::to_string);

    match crate::api::sso_provider_detail::start_sso_and_get_auth_url(
        req,
        session,
        ctx.0,
        &provider_name,
        next,
    )
    .await?
    {
        crate::api::sso_provider_detail::StartSsoOutcome::Ok(url) => {
            Ok(Some(Redirect::temporary(url).into_response()))
        }
        // Provider vanished between the count check and the start (race), or the
        // request host is incompatible with the provider's return-URL domain.
        // Fall through to the normal login page rather than erroring.
        _ => Ok(None),
    }
}

/// Result of `try_public_target_bypass`. See [`page_auth`] for how each
/// arm is handled. Kept private to this module because the synthetic
/// `AuthenticatedRequestContext` carries internal-only auth claims.
enum PublicBypassOutcome {
    /// Public target resolved; route through with the synthetic Ticket
    /// auth context so the catchall sees a target-scoped session.
    Bypass(AuthenticatedRequestContext),
    /// Public target resolved but the request carries an admin/user/cluster
    /// token — return 401.
    Reject401,
    /// No bypass applies; existing auth flow runs unchanged.
    NotApplicable,
}

/// Inspect the request and decide whether the public-target bypass should
/// fire. On `Bypass`, synthesises a `Ticket`-style `AuthenticatedRequestContext`
/// pinned to the resolved target row so the catchall's existing Ticket arm
/// proxies the request without role checks.
///
/// Synthetic auth uses `Uuid::nil()` and the username `"<public>"` —
/// neither is reachable through any normal credential path, so the
/// audit log surfaces the bypass rather than impersonating a real user.
async fn try_public_target_bypass(req: &Request) -> poem::Result<PublicBypassOutcome> {
    // Defence-in-depth: never bypass auth on Warpgate's own management
    // surfaces. At v0.28.6 `/@warpgate*` and `/_warpgate*` are nested ahead
    // of the catchall so `page_auth` should not see them, but the guard keeps
    // the guarantee from depending on routing order — even if an operator
    // mis-set `public: true` on a target with `external_host` matching the
    // Warpgate base host.
    if is_warpgate_management_path(req.uri().path()) {
        return Ok(PublicBypassOutcome::NotApplicable);
    }

    // UnauthenticatedRequestContext is attached globally by the
    // `.data(...)` call in `lib.rs::run`, so this extraction never fails
    // on the catchall route.
    let unauth_ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(req).await?;
    let host = unauth_ctx.trusted_host_header(req);

    // If `inject_request_authorization` already attached an
    // `AuthenticatedRequestContext`, use its `auth` so the decision helper
    // sees the real authorization state (admin/user tokens get rejected
    // at the bypass instead of silently proxying).
    let auth_ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(req)
        .await
        .ok()
        .flatten();
    let auth_ref = auth_ctx.as_deref().map(|c| &c.auth);

    let (resolved, decision) =
        resolve_public_target_decision(unauth_ctx.services(), host.as_deref(), auth_ref).await?;

    match decision {
        PublicTargetDecision::Bypass => {
            let (target, _opts) = resolved.expect("Bypass decision implies a resolved target");
            let synthetic_auth = RequestAuthorization::Session(SessionAuthorization::Ticket {
                user_id: Uuid::nil(),
                username: "<public>".into(),
                target_id: target.id,
            });
            Ok(PublicBypassOutcome::Bypass(
                unauth_ctx.to_authenticated(synthetic_auth),
            ))
        }
        PublicTargetDecision::Reject401 => Ok(PublicBypassOutcome::Reject401),
        PublicTargetDecision::NotApplicable => Ok(PublicBypassOutcome::NotApplicable),
    }
}

pub fn gateway_redirect(req: &Request) -> Response {
    // Only do a login redirect for document requests
    if let Some(mode) = req.headers().get(HeaderName::from_static("sec-fetch-mode"))
        && mode != "navigate"
    {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .finish();
    }

    let path = req
        .original_uri()
        .path_and_query()
        .map_or_else(String::new, ToString::to_string);

    let path = format!(
        "/@warpgate#/login?next={}",
        utf8_percent_encode(&path, NON_ALPHANUMERIC),
    );

    Redirect::temporary(path).into_response()
}

pub async fn get_or_create_auth_state_for_request(
    req: &Request,
    username: &str,
    ctx: &UnauthenticatedRequestContext,
    rate_limit_credential_type: Option<&str>,
) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
    let client_ip = get_client_ip_addr(req, ctx.services()).await;

    if let Some(state) = get_auth_state_for_request(req, ctx).await? {
        let reusable = {
            let state = state.lock().await;
            // A terminally rejected attempt can never accept another
            // credential, so a retry must start a fresh one.
            username_eq_ci(&state.user_info().username, username)
                && !matches!(state.verify(), AuthResult::Rejected)
        };
        if reusable {
            return Ok(state);
        }
    }

    // Pass the browser session id so the auth state is keyed by it: a web
    // approval landing on another node resolves the owner from the session's
    // `node_id` in the DB (see `api::auth::auth_state_owner`).
    let session_id = session_id_for_request(req, ctx).await?;

    let state = ctx
        .services()
        .create_auth_state(
            &session_id,
            username,
            crate::common::PROTOCOL_NAME,
            "",
            &[
                CredentialKind::Password,
                CredentialKind::Sso,
                CredentialKind::Totp,
            ],
            client_ip,
            rate_limit_credential_type,
        )
        .await?;

    Ok(state)
}

/// The login attempt in progress on this browser session, if any. Auth states
/// are keyed by session id, so the session itself is the lookup key and there is
/// nothing to keep in sync.
pub async fn get_auth_state_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<Option<Arc<Mutex<AuthState>>>, WarpgateError> {
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let Some(session_id) = session.get_session_id() else {
        return Ok(None);
    };

    Ok(ctx
        .services()
        .auth_state_store
        .lock()
        .await
        .get(&session_id))
}

pub async fn session_id_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<SessionId, WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;

    let server_handle = session_middleware
        .lock()
        .await
        .create_handle_for(req, ctx)
        .await
        .context("creating session handle")?;

    Ok(server_handle.lock().await.id())
}

pub async fn authorize_session(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    user_info: AuthStateUserInfo,
) -> Result<(), WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let server_handle = session_middleware
        .lock()
        .await
        .create_handle_for(req, ctx)
        .await
        .context("create_handle_for")?;
    server_handle
        .lock()
        .await
        .set_user_info(user_info.clone())
        .await?;
    session.set_auth(SessionAuthorization::User {
        user_id: user_info.id,
        username: user_info.username,
    });
    warpgate_common_http::auth::stamp_session_auth_time(session);

    Ok(())
}

/// Authorization for a request authenticated by the cluster token. The proxying
/// node forwards the acting user's id in `x-warpgate-cluster-identity` (see
/// `cluster_proxy::proxy_or_serve`), so the request runs here as that user;
/// without the header the peer acts as a bare cluster peer. An id that no
/// longer resolves to a user fails closed (unauthenticated).
async fn cluster_request_authorization(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> poem::Result<Option<RequestAuthorization>> {
    let Some(header) = req.headers().get(&X_WARPGATE_CLUSTER_IDENTITY) else {
        return Ok(Some(RequestAuthorization::ClusterToken));
    };
    let Some(user_id) = header.to_str().ok().and_then(|s| s.parse::<Uuid>().ok()) else {
        return Ok(None);
    };
    Ok(User::Entity::find_by_id(user_id)
        .one(&ctx.services().db)
        .await
        .map_err(poem::error::InternalServerError)?
        .map(|user| {
            RequestAuthorization::Session(SessionAuthorization::User {
                user_id: user.id,
                username: user.username,
            })
        }))
}

/// Resolves an API token to its user, applying the same account-status checks a
/// login goes through. `None` for an unknown token or for a user who may not
/// authenticate right now — the caller can't tell the two apart, by design.
async fn user_for_api_token(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    token: &str,
) -> Result<Option<warpgate_common::User>, WarpgateError> {
    let services = ctx.services();
    let remote_ip = get_client_ip_addr(req, services).await;

    // Checked ahead of the lookup so a blocked caller can't use this as a
    // token-existence oracle.
    if let Some(ip) = remote_ip
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await?
            .is_some()
    {
        tracing::warn!("API token presented from a blocked IP: {ip}");
        return Ok(None);
    }

    let Some(user) = services.config_provider.validate_api_token(token).await? else {
        return Ok(None);
    };

    if !vet_credential_bearer(&services.login_protection, &user, remote_ip).await? {
        return Ok(None);
    }

    Ok(Some(user))
}

pub async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    // Reinject a per-request copy so the parameter cache is request-scoped
    // rather than shared with the startup singleton.
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
        .await?
        .for_request();
    let session = <&Session>::from_request_without_body(&req).await?;
    let is_cluster_peer = is_cluster_peer_request(&req, &ctx.services().cluster_token);

    let mut session_auth = session.get_auth();
    // A forwarded request's Host is the cluster SNI name by construction, so the
    // origin check below would reject - and clear - a session that is fine.
    if session_auth.is_some() && !is_cluster_peer {
        let config = ctx.services().config.lock().await;
        if let Ok(base_url) = construct_external_url(None, &config, None).await
            && let Some(base_host) = base_url.host_str()
        {
            let request_host = ctx.trusted_hostname(&req);

            if let Some(host) = request_host {
                // Validate request host matches base host or is a subdomain/localhost
                let is_localhost = is_localhost_host(&host);
                let is_authorized = host == base_host
                    || host.ends_with(&format!(".{base_host}"))
                    || (is_localhost && base_host != "localhost" && base_host != "127.0.0.1");

                if !is_authorized {
                    tracing::warn!(
                        "Session cookie rejected: request host '{}' is not authorized (base host: '{}'). Clearing session.",
                        host,
                        base_host
                    );
                    session.clear();
                    session_auth = None;
                }
            }
        }
    }

    let auth = if let Some(auth) = session_auth {
        Some(RequestAuthorization::Session(auth))
    } else if is_cluster_peer {
        cluster_request_authorization(&ctx, &req).await?
    } else if let Some(token_from_header) = req.headers().get(&X_WARPGATE_TOKEN) {
        let token_from_header = token_from_header
            .to_str()
            .map_err(poem::error::BadRequest)?;
        if (*ctx.services().admin_token)
            .as_ref()
            .is_some_and(|admin_token| {
                // Use constant time comparison to prevent timing attacks
                admin_token
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(token_from_header.as_bytes())
                    .into()
            })
        {
            Some(RequestAuthorization::AdminToken)
        } else if let Some(user) = user_for_api_token(&req, &ctx, token_from_header).await? {
            Some(RequestAuthorization::UserToken {
                user_id: user.id,
                username: user.username,
            })
        } else {
            None
        }
    } else {
        None
    };

    if let Some(auth) = auth {
        // build context and attach it instead of raw authorization
        let actx = ctx.to_authenticated(auth);
        Ok(ep.data(actx).data(ctx).call(req).await?)
    } else {
        Ok(ep.data(ctx).call(req).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StatusCode, gateway_redirect, host_is_subdomain_of_or_equal, request_has_password_bypass,
        request_is_navigation, should_auto_sso_redirect,
    };

    #[test]
    fn gateway_redirect_navigation_redirects_to_login() {
        for mode in [None, Some("navigate")] {
            let mut req = poem::Request::builder().uri_str("/api/data");
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            let resp = gateway_redirect(&req.finish());
            assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(location.starts_with("/@warpgate#/login"));
        }
    }

    #[test]
    fn gateway_redirect_fetch_gets_401() {
        // https://github.com/warp-tech/warpgate/issues/1989
        for mode in ["cors", "same-origin", "no-cors"] {
            let req = poem::Request::builder()
                .uri_str("/api/data")
                .header("sec-fetch-mode", mode)
                .finish();
            let resp = gateway_redirect(&req);
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn auto_sso_redirect_happy_path() {
        // Enabled, exactly one provider, a navigation, no bypass, not a
        // management path → redirect.
        assert!(should_auto_sso_redirect(true, 1, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_disabled_by_default() {
        // Feature off → never redirect regardless of other inputs.
        assert!(!should_auto_sso_redirect(false, 1, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_requires_exactly_one_provider() {
        // Zero providers → nothing to redirect to.
        assert!(!should_auto_sso_redirect(true, 0, true, false, false));
        // Multiple providers → user must choose, keep the SPA.
        assert!(!should_auto_sso_redirect(true, 2, true, false, false));
    }

    #[test]
    fn auto_sso_redirect_only_on_navigation() {
        // Non-navigation (fetch/XHR) must not be hijacked into a 302.
        assert!(!should_auto_sso_redirect(true, 1, false, false, false));
    }

    #[test]
    fn auto_sso_redirect_break_glass_bypass() {
        // ?login=password forces the SPA login even when otherwise eligible.
        assert!(!should_auto_sso_redirect(true, 1, true, true, false));
    }

    #[test]
    fn auto_sso_redirect_skips_management_paths() {
        // Warpgate's own admin/gateway surfaces are never auto-redirected.
        assert!(!should_auto_sso_redirect(true, 1, true, false, true));
    }

    #[test]
    fn request_is_navigation_matches_gateway_redirect_heuristic() {
        // Header absent → treat as navigation.
        let req = poem::Request::builder().uri_str("/foo").finish();
        assert!(request_is_navigation(&req));
        // Explicit navigate → navigation.
        let req = poem::Request::builder()
            .uri_str("/foo")
            .header("sec-fetch-mode", "navigate")
            .finish();
        assert!(request_is_navigation(&req));
        // Any other mode → not a navigation.
        for mode in ["cors", "same-origin", "no-cors"] {
            let req = poem::Request::builder()
                .uri_str("/foo")
                .header("sec-fetch-mode", mode)
                .finish();
            assert!(!request_is_navigation(&req));
        }
    }

    #[test]
    fn request_has_password_bypass_detects_query() {
        let req = poem::Request::builder()
            .uri_str("/foo?login=password")
            .finish();
        assert!(request_has_password_bypass(&req));
        // Alongside other params.
        let req = poem::Request::builder()
            .uri_str("/foo?next=%2Fbar&login=password")
            .finish();
        assert!(request_has_password_bypass(&req));
        // Absent / different value.
        let req = poem::Request::builder().uri_str("/foo").finish();
        assert!(!request_has_password_bypass(&req));
        let req = poem::Request::builder().uri_str("/foo?login=sso").finish();
        assert!(!request_has_password_bypass(&req));
    }

    #[test]
    fn test_host_is_subdomain_of_or_equal() {
        assert!(host_is_subdomain_of_or_equal("example.com", "example.com"));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            "example.com"
        ));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            ".example.com"
        ));
        assert!(!host_is_subdomain_of_or_equal(
            "evil-example.com",
            "example.com"
        ));
    }
}

use core::str;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::error::InternalServerError;
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{ProtocolName, SessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::{User, UserAdminRoleAssignment};
use warpgate_sso::WarpgateIdToken;

use crate::catchall::{
    is_warpgate_management_path, resolve_public_target_decision, PublicTargetDecision,
};

use crate::session::SessionStore;
use crate::step_up::{is_session_step_up_stale, StepUpSessionExt};

pub const PROTOCOL_NAME: ProtocolName = "HTTP";
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_STATE_ID_SESSION_KEY: &str = "auth_state_id";
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
    fn get_auth_state_id(&self) -> Option<AuthStateId>;
    fn clear_auth_state(&self);

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

    fn get_auth_state_id(&self) -> Option<AuthStateId> {
        self.get(AUTH_STATE_ID_SESSION_KEY)
    }

    fn clear_auth_state(&self) {
        self.remove(AUTH_STATE_ID_SESSION_KEY);
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

pub async fn is_user_admin(ctx: &AuthenticatedRequestContext) -> poem::Result<bool> {
    // A user is considered an administrator if they have any admin role assigned.
    let services = ctx.services();

    // Admin tokens bypass the database check and are always full administrators.
    if matches!(ctx.auth, RequestAuthorization::AdminToken) {
        return Ok(true);
    }

    let username = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::User { username, .. })
        | RequestAuthorization::UserToken { username, .. } => username,
        RequestAuthorization::Session(SessionAuthorization::Ticket { .. }) => return Ok(false),
        RequestAuthorization::AdminToken => unreachable!(),
    };

    let db = services.db.lock().await;

    let Some(user_model) = User::Entity::find()
        .filter(User::Entity::username_eq_ci(username))
        .one(&*db)
        .await
        .map_err(InternalServerError)?
    else {
        return Ok(false);
    };

    let count: u64 = UserAdminRoleAssignment::Entity::find()
        .filter(UserAdminRoleAssignment::Column::UserId.eq(user_model.id))
        .count(&*db)
        .await
        .map_err(InternalServerError)?;

    Ok(count > 0)
}

pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Option<E::Output>> {
    let ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(&req).await?;
    let Some(ctx) = ctx else {
        return Ok(None);
    };

    // Per-session SSO step-up gate (spec A2). If the session is authed as a
    // `User` (not a ticket, not an API token) and the configured HTTP
    // interval has elapsed since the last SSO handshake on this session,
    // forcibly re-auth: clear the session auth + stamp, then return `None`
    // so that the surrounding `page_auth` / `endpoint_auth` wrapper redirects
    // to the gateway login page (which single-provider SSO deployments
    // auto-forward to the IdP). Tickets / tokens / anonymous fall through
    // unchanged — we only pay the config-lock + session-read cost on the
    // `User` path to keep the hot path cheap for token-authed traffic.
    if let RequestAuthorization::Session(session_auth @ SessionAuthorization::User { .. }) =
        &ctx.auth
    {
        // Pull the interval first; absent config → feature off, skip the
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
                return Ok(None);
            }
        }
    }
    return ep.call(req).await.map(Some);
}

// TODO unify both based on the accept header
pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint<Output = E::Output> {
    e.around(|ep, req| async move {
        _inner_auth(ep, req)
            .await?
            .ok_or_else(|| poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        // Per-VM-proxy P0 (M9): public-target bypass. If the request resolves
        // to an HTTP target with `public: true`, anonymous and session-authed
        // clients are routed through to the catchall without the normal
        // session/role gate; admin/user API tokens hit a public target
        // → 401 (tokens are admin-API-scoped). The lookup runs only on the
        // catchall path because `page_auth` only wraps the catchall mount —
        // the `/@warpgate` admin routes go through `endpoint_auth` instead
        // (per `lib.rs` mounting).
        match try_public_target_bypass(&req).await? {
            PublicBypassOutcome::Bypass(synthetic_ctx) => {
                // Override any pre-existing AuthenticatedRequestContext with
                // the synthetic Ticket-style auth so the catchall's existing
                // Ticket arm (need_role_auth = false, target_name from auth)
                // routes the request to the resolved public target without
                // running role checks. `_inner_auth`'s SSO step-up logic is
                // gated on `Session(User { .. })` and so is also skipped.
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

        let err_resp = gateway_redirect(&req).into_response();
        Ok(_inner_auth(ep, req)
            .await?
            .map_or(err_resp, IntoResponse::into_response))
    })
}

/// Result of `try_public_target_bypass`. See [`page_auth`] for how each
/// arm is handled. Kept private to this module because the synthetic
/// `AuthenticatedRequestContext` carries internal-only auth claims.
enum PublicBypassOutcome {
    /// Public target resolved; route through with the synthetic Ticket
    /// auth context so the catchall sees a target-scoped session.
    Bypass(AuthenticatedRequestContext),
    /// Public target resolved but the request carries an admin/user API
    /// token — return 401.
    Reject401,
    /// No bypass applies; existing auth flow runs unchanged.
    NotApplicable,
}

/// Inspect the request and decide whether the public-target bypass should
/// fire. On `Bypass`, synthesises a `Ticket`-style `AuthenticatedRequestContext`
/// pinned to the resolved target name so the catchall's existing Ticket arm
/// proxies the request without role checks.
///
/// Synthetic auth uses `Uuid::nil()` and the username `"<public>"` —
/// neither is reachable through any normal credential path, so the
/// audit log surfaces the bypass rather than impersonating a real user.
async fn try_public_target_bypass(req: &Request) -> poem::Result<PublicBypassOutcome> {
    // Defence-in-depth: never bypass auth on Warpgate's own management
    // surfaces. `page_auth` wraps both the catchall AND the admin static
    // page mount (`lib.rs:193-196`); even if an operator mis-set
    // `public: true` on a target with `external_host` matching the
    // Warpgate base host, the `/@warpgate*` and `/_warpgate*` routes
    // must not be served anonymously. The admin REST API stays
    // protected by `endpoint_auth`, but this guard prevents the HTML
    // shell from leaking via misconfiguration.
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
            let (target, _opts) =
                resolved.expect("Bypass decision implies a resolved target");
            let synthetic_auth = RequestAuthorization::Session(SessionAuthorization::Ticket {
                user_id: Uuid::nil(),
                username: "<public>".into(),
                target_name: target.name.clone(),
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
    let remote_ip = req.remote_addr().as_socket_addr().map(|a| a.ip());
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    if let Some(state) = get_auth_state_for_request(req, ctx).await? {
        let existing_matched = username_eq_ci(&state.lock().await.user_info().username, username);
        if existing_matched {
            return Ok(state);
        }
    }

    let mut store = ctx.services().auth_state_store.lock().await;
    let (id, state) = store
        .create(
            None,
            username,
            crate::common::PROTOCOL_NAME,
            &[
                CredentialKind::Password,
                CredentialKind::Sso,
                CredentialKind::Totp,
            ],
            remote_ip,
            rate_limit_credential_type,
        )
        .await?;

    {
        let session_id = session_id_for_request(req, ctx).await?;
        let mut state = state.lock().await;
        if state.session_id() != Some(&session_id) {
            state.set_session_id(session_id);
        }
    }

    session.set(AUTH_STATE_ID_SESSION_KEY, AuthStateId(id));
    Ok(state)
}

pub async fn get_auth_state_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<Option<Arc<Mutex<AuthState>>>, WarpgateError> {
    let store = ctx.services().auth_state_store.lock().await;
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    if let Some(id) = session.get_auth_state_id()
        && !store.contains_key(&id.0)
    {
        session.clear_auth_state();
    }

    if let Some(id) = session.get_auth_state_id() {
        let state = store.get(&id.0).ok_or(WarpgateError::InconsistentState(
            "unknown auth state id".into(),
        ))?;
        return Ok(Some(state));
    }

    Ok(None)
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

    Ok(())
}

pub async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
    let session = <&Session>::from_request_without_body(&req).await?;

    let mut session_auth = session.get_auth();
    if session_auth.is_some() {
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

    let auth = match session_auth {
        Some(auth) => Some(RequestAuthorization::Session(auth)),
        None => match req.headers().get(&X_WARPGATE_TOKEN) {
            Some(token_from_header) => {
                let token_from_header = token_from_header
                    .to_str()
                    .map_err(poem::error::BadRequest)?;
                if ctx
                    .services()
                    .admin_token
                    .lock()
                    .await
                    .as_deref()
                    .is_some_and(|admin_token| {
                        // Use constant time comparison to prevent timing attacks
                        admin_token
                            .as_bytes()
                            .ct_eq(token_from_header.as_bytes())
                            .into()
                    })
                {
                    Some(RequestAuthorization::AdminToken)
                } else if let Some(user) = ctx
                    .services()
                    .config_provider
                    .lock()
                    .await
                    .validate_api_token(token_from_header)
                    .await?
                {
                    Some(RequestAuthorization::UserToken {
                        user_id: user.id,
                        username: user.username,
                    })
                } else {
                    None
                }
            }
            None => None,
        },
    };

    if let Some(auth) = auth {
        // build context and attach it instead of raw authorization
        let ctx = ctx.to_authenticated(auth);
        Ok(ep.data(ctx).call(req).await?)
    } else {
        Ok(ep.call(req).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusCode, gateway_redirect, host_is_subdomain_of_or_equal};

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

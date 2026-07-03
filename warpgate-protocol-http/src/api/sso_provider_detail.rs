use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::Request;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::{Json, Response};
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use tracing::debug;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_db_entities::Parameters;
use warpgate_sso::{SsoClient, SsoLoginRequest, SsoReturnUrlDomainPreference};

use crate::api::sso_provider_list::is_safe_redirect_target;
use crate::common::{host_is_subdomain_of_or_equal, is_localhost_host, should_auto_sso_redirect};

pub struct Api;

#[derive(Object)]
struct StartSsoResponseParams {
    url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum StartSsoResponse {
    #[oai(status = 200)]
    Ok(Json<StartSsoResponseParams>),
    #[oai(status = 404)]
    NotFound,
    /// The request originates from a domain that has no cookie domain relationship
    /// with `external_host` while `return_url_domain` is `external_host`
    #[oai(status = 400)]
    IncompatibleSsoDomain,
}

#[derive(ApiResponse)]
enum AutoStartSsoResponse {
    /// Browser redirect — either straight to the IdP authorize URL (auto-SSO
    /// enabled, exactly one provider) or back to the gateway login SPA
    /// (feature off, not exactly one provider, or `?login=password`).
    #[oai(status = 302)]
    Redirect,
}

pub static SSO_CONTEXT_SESSION_KEY: &str = "sso_request";

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoContext {
    pub provider: String,
    pub request: SsoLoginRequest,
    pub next_url: Option<String>,
    pub supports_single_logout: bool,
    pub return_host: Option<String>,
}

/// Outcome of [`start_sso_and_get_auth_url`]. Mirrors the arms of
/// [`StartSsoResponse`] so both the OpenAPI handler and the auto-redirect
/// path in `common::page_auth` can share the login-initiation machinery.
pub(crate) enum StartSsoOutcome {
    /// Provider found; SSO context stored in the session. Carries the IdP
    /// authorize URL to redirect the browser to.
    Ok(String),
    /// No SSO provider with the given name is configured.
    NotFound,
    /// The request host has no cookie-domain relationship with `external_host`
    /// while the provider prefers `external_host` for its return URL.
    IncompatibleSsoDomain,
}

/// Begin an SSO login for `provider_name`: build the return URL, ask the IdP
/// client for an authorize URL, and stash the resulting [`SsoContext`] in the
/// session under [`SSO_CONTEXT_SESSION_KEY`] so `sso/return` can complete the
/// handshake. Extracted from `api_start_sso` so the unauthenticated
/// auto-redirect path can reuse it. Locks `config` internally — callers must
/// NOT hold the config lock.
pub(crate) async fn start_sso_and_get_auth_url(
    req: &Request,
    session: &Session,
    ctx: &UnauthenticatedRequestContext,
    provider_name: &str,
    next: Option<String>,
) -> Result<StartSsoOutcome, WarpgateError> {
    let config = ctx.services().config.lock().await;

    let Some(provider_config) = config
        .store
        .sso_providers
        .iter()
        .find(|p| p.name == *provider_name)
    else {
        return Ok(StartSsoOutcome::NotFound);
    };

    if matches!(
        provider_config.return_url_domain,
        SsoReturnUrlDomainPreference::ExternalHost
    ) && let (Some(request_host), Some(external_host)) = (
        ctx.trusted_hostname(req),
        config.store.external_host.as_deref(),
    ) && !is_localhost_host(&request_host)
        && !host_is_subdomain_of_or_equal(&request_host, external_host)
    {
        return Ok(StartSsoOutcome::IncompatibleSsoDomain);
    }

    let mut return_url = construct_external_url(
        match provider_config.return_url_domain {
            // Let `construct_external_url` fall back to config file
            SsoReturnUrlDomainPreference::ExternalHost => None,
            SsoReturnUrlDomainPreference::HostHeader => Some(req),
        },
        &config,
        provider_config.return_domain_whitelist.as_deref(),
    )
    .await?;
    return_url.set_path(&format!(
        "{}warpgate/api/sso/return",
        provider_config.return_url_prefix
    ));
    debug!("Return URL: {return_url}");

    let client = SsoClient::new(provider_config.provider.clone())?;

    let sso_req = client.start_login(return_url.to_string()).await?;
    let return_host = ctx.trusted_host_header(req);

    let url = sso_req.auth_url().to_string();
    session.set(
        SSO_CONTEXT_SESSION_KEY,
        SsoContext {
            provider: provider_name.to_owned(),
            request: sso_req,
            next_url: next,
            supports_single_logout: client.supports_single_logout().await?,
            return_host,
        },
    );

    Ok(StartSsoOutcome::Ok(url))
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers/:name/start",
        method = "get",
        operation_id = "start_sso"
    )]
    async fn api_start_sso(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        name: Path<String>,
        next: Query<Option<String>>,
    ) -> Result<StartSsoResponse, WarpgateError> {
        match start_sso_and_get_auth_url(req, session, ctx.0, &name.0, next.0).await? {
            StartSsoOutcome::Ok(url) => {
                Ok(StartSsoResponse::Ok(Json(StartSsoResponseParams { url })))
            }
            StartSsoOutcome::NotFound => Ok(StartSsoResponse::NotFound),
            StartSsoOutcome::IncompatibleSsoDomain => Ok(StartSsoResponse::IncompatibleSsoDomain),
        }
    }

    /// Server-side auto-SSO entry point.
    ///
    /// A front door that gates its own traffic and rides a `public` HTTP target
    /// (so Warpgate's own `page_auth` auto-redirect never sees the request —
    /// e.g. Cove's web UI) redirects unauthenticated browser navigations here
    /// instead of straight to the gateway login SPA. When the operator has
    /// opted into single-provider auto-redirect, this 302s directly to the IdP
    /// authorize URL — no SPA render, no button click. Otherwise (feature off,
    /// not exactly one provider, a provider/host mismatch, or the
    /// `?login=password` break-glass) it 302s to the normal gateway login page,
    /// preserving `next`.
    ///
    /// Unauthenticated by design (mirrors `/sso/providers` + `/sso/*/start`):
    /// it only ever *initiates* a login, and the resulting `next` is validated
    /// against [`is_safe_redirect_target`] before use.
    #[oai(
        path = "/sso/auto-start",
        method = "get",
        operation_id = "auto_start_sso"
    )]
    async fn api_auto_start_sso(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        next: Query<Option<String>>,
        login: Query<Option<String>>,
    ) -> Result<Response<AutoStartSsoResponse>, WarpgateError> {
        // Drop an unsafe `next` (javascript:, //host, …) rather than propagate
        // it into either redirect target.
        let next = next.0.filter(|n| is_safe_redirect_target(n));
        let has_password_bypass = login.0.as_deref() == Some("password");

        // Read the toggle + provider set, then decide. Mirrors
        // `common::try_auto_sso_redirect`, but for the public-target front door.
        let sole_provider = {
            let enabled = Parameters::Entity::get(&*ctx.services().db.lock().await)
                .await?
                .sso_auto_redirect;
            let config = ctx.services().config.lock().await;
            let providers = &config.store.sso_providers;
            if should_auto_sso_redirect(
                enabled,
                providers.len(),
                true,  // only reached as a top-level browser navigation
                has_password_bypass,
                false, // dedicated endpoint, not a management-path proxy hit
            ) {
                providers.first().map(|p| p.name.clone())
            } else {
                None
            }
        };

        if let Some(provider_name) = sole_provider
            && let StartSsoOutcome::Ok(url) =
                start_sso_and_get_auth_url(req, session, ctx.0, &provider_name, next.clone()).await?
        {
            return Ok(Response::new(AutoStartSsoResponse::Redirect).header("Location", url));
        }

        // Fallback: gateway login SPA, preserving `next` and the break-glass.
        let url = login_spa_fallback_url(next.as_deref(), has_password_bypass);
        Ok(Response::new(AutoStartSsoResponse::Redirect).header("Location", url))
    }
}

/// Build the gateway-login-SPA fallback URL for [`Api::api_auto_start_sso`],
/// preserving `next` (percent-encoded) and re-emitting the `?login=password`
/// break-glass. The re-emit is load-bearing: when auto-SSO is enabled with a
/// single provider, the SPA's own on-load auto-start (`Login.svelte`) would
/// otherwise immediately bounce the operator back to the IdP — so dropping the
/// break-glass here silently neuters it. `#` fragment routing matches what
/// `common::gateway_redirect` and cove-server emit. Pure so the round-trip is
/// unit-testable without a `Services` fixture.
fn login_spa_fallback_url(next: Option<&str>, has_password_bypass: bool) -> String {
    let mut url = match next {
        Some(n) => format!(
            "/@warpgate#/login?next={}",
            utf8_percent_encode(n, NON_ALPHANUMERIC)
        ),
        None => "/@warpgate#/login".to_owned(),
    };
    if has_password_bypass {
        url.push_str(if url.contains('?') {
            "&login=password"
        } else {
            "?login=password"
        });
    }
    url
}

#[cfg(test)]
mod tests {
    use super::login_spa_fallback_url;

    #[test]
    fn fallback_url_preserves_next_and_reemits_break_glass() {
        // No break-glass: encoded next, no login param.
        let u = login_spa_fallback_url(Some("/vms"), false);
        assert_eq!(u, "/@warpgate#/login?next=%2Fvms");
        assert!(!u.contains("login=password"));

        // Break-glass with a next → appended as an extra query param.
        let u = login_spa_fallback_url(Some("/vms"), true);
        assert!(u.starts_with("/@warpgate#/login?next=%2Fvms"), "got: {u}");
        assert!(u.ends_with("&login=password"), "got: {u}");

        // Break-glass with no next → starts the query string.
        assert_eq!(
            login_spa_fallback_url(None, true),
            "/@warpgate#/login?login=password"
        );

        // No next, no break-glass → bare login route.
        assert_eq!(login_spa_fallback_url(None, false), "/@warpgate#/login");
    }
}

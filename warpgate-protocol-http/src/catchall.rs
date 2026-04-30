use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{ConfigProvider, WarpgateServerHandle};

use crate::common::SessionExt;
use crate::proxy::{proxy_normal_request, proxy_websocket_request};

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-target")]
    warpgate_target: Option<String>,
}

pub fn target_select_redirect() -> Response {
    Redirect::temporary("/@warpgate").into_response()
}

#[handler]
pub async fn catchall_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    ctx: Data<&AuthenticatedRequestContext>,
    server_handle: Option<Data<&Arc<Mutex<WarpgateServerHandle>>>>,
) -> poem::Result<Response> {
    let target_and_options = get_target_for_request(req, &ctx).await?;
    let Some((target, options)) = target_and_options else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(target.name.clone());

    if let Some(server_handle) = server_handle {
        server_handle.lock().await.set_target(&target).await?;
    }

    let span = info_span!("", target=%target.name);

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &ctx, &options)
            .instrument(span)
            .await?
            .into_response(),
        None => proxy_normal_request(req, *ctx, body, &options)
            .instrument(span)
            .await?
            .into_response(),
    })
}

/// True when the request path targets one of Warpgate's own management
/// mounts (`/@warpgate*` or `/_warpgate*`).
///
/// `page_auth` wraps both the catchall AND the admin static-page mount
/// (`lib.rs:193-196`), so a misconfigured `public:true` target whose
/// `external_host` matches Warpgate's base host could otherwise serve
/// the admin HTML shell anonymously. The admin REST API stays protected
/// by `endpoint_auth`, but defence-in-depth requires this predicate so
/// that the public-target bypass never fires on management surfaces.
///
/// Pure free function so the unit tests in `public_target_tests` can
/// cover it directly without a real `Services` (same pattern as the
/// other catchall helpers).
pub(crate) fn is_warpgate_management_path(path: &str) -> bool {
    path == "/@warpgate"
        || path.starts_with("/@warpgate/")
        || path == "/_warpgate"
        || path.starts_with("/_warpgate/")
}

/// Outcome of consulting the public-target bypass on an incoming HTTP
/// request. Pure decision over the resolved target options and the request
/// authorization state — no async, no I/O — so it can be unit-tested
/// without spinning up a full `Services` fixture (per the T1 pattern of
/// extracting `resolve_trusted_host_header` from `auth.rs`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublicTargetDecision {
    /// `public: true` target with anonymous or session-authed client.
    /// `page_auth` skips `_inner_auth` and the catchall proxies straight
    /// through.
    Bypass,
    /// `public: true` target with admin or user API token. Tokens are
    /// admin-REST-scoped only — proxy access via token is rejected with
    /// 401 (per spec § 3.1, Q10).
    Reject401,
    /// Either no target matched the host, the matched target isn't HTTP,
    /// or it has `public: false`. Existing auth path runs unchanged.
    NotApplicable,
}

/// Decide how the public-target bypass should affect a request.
///
/// `target_opts` is the resolved HTTP target options (`None` means no host
/// match or non-HTTP target). `auth` is the request's authorization state
/// (`None` means anonymous — no `AuthenticatedRequestContext` was attached
/// upstream by `inject_request_authorization`).
///
/// Pure free function so unit tests don't need a real `Services` —
/// constructing `RequestAuthorization` and `TargetHTTPOptions` is enough.
pub(crate) fn decide_public_target_access(
    target_opts: Option<&TargetHTTPOptions>,
    auth: Option<&RequestAuthorization>,
) -> PublicTargetDecision {
    let Some(opts) = target_opts else {
        return PublicTargetDecision::NotApplicable;
    };
    if !opts.public {
        return PublicTargetDecision::NotApplicable;
    }
    match auth {
        // Anonymous (no auth context) and session-authed users bypass the
        // role check and reach the proxy.
        None | Some(RequestAuthorization::Session(_)) => PublicTargetDecision::Bypass,
        // Admin/user API tokens are scoped to the admin REST API; using
        // one against a public proxy target is a configuration error and
        // returns 401 explicitly rather than silently proxying.
        Some(RequestAuthorization::AdminToken)
        | Some(RequestAuthorization::UserToken { .. }) => PublicTargetDecision::Reject401,
    }
}

/// Look up an HTTP target whose `external_host` matches the given host
/// header (port-aware, since T1's port-aware match key took effect).
///
/// Pure over `targets` so unit tests don't need a real config provider.
/// The async caller is responsible for fetching the target list under
/// the config-provider lock.
pub(crate) fn find_http_target_by_external_host(
    targets: &[Target],
    host: &str,
) -> Option<(Target, TargetHTTPOptions)> {
    targets
        .iter()
        .filter_map(|t| match t.options {
            TargetOptions::Http(ref options) => Some((t, options)),
            _ => None,
        })
        .find(|(_, o)| o.external_host.as_deref() == Some(host))
        .map(|(t, o)| (t.clone(), o.clone()))
}

/// Async wrapper around the host→target lookup + `decide_public_target_access`
/// helpers. Used by `page_auth` (in `common.rs`) to skip the redirect-to-login
/// when a request resolves to a public target.
///
/// `host` is the trusted Host header (already resolved by the caller via
/// `UnauthenticatedRequestContext::trusted_host_header`, port-aware per T1)
/// so this helper stays a thin async glue and the pure logic lives in the
/// two helpers above. Returns the resolved target+options together with
/// the bypass decision so the caller can either short-circuit (Bypass),
/// reject (Reject401), or fall through to the existing auth path
/// (NotApplicable).
pub(crate) async fn resolve_public_target_decision(
    services: &warpgate_core::Services,
    host: Option<&str>,
    auth: Option<&RequestAuthorization>,
) -> poem::Result<(
    Option<(Target, TargetHTTPOptions)>,
    PublicTargetDecision,
)> {
    let Some(host) = host else {
        return Ok((None, PublicTargetDecision::NotApplicable));
    };
    let targets = services.config_provider.lock().await.list_targets().await?;
    let resolved = find_http_target_by_external_host(&targets, host);
    let opts = resolved.as_ref().map(|(_, o)| o);
    let decision = decide_public_target_access(opts, auth);
    Ok((resolved, decision))
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<(Target, TargetHTTPOptions)>> {
    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    let selected_target_name;
    let need_role_auth;

    let request_host = ctx.trusted_host_header(req);

    let host_based_target_name = if let Some(host) = request_host {
        let found = ctx
            .services()
            .config_provider
            .lock()
            .await
            .get_target_by_hostname(host.as_str())
            .await?
            .map(|t| t.name);
        if found.is_some() {
            debug!(
                "Host header matched HTTP target: host={} -> target={:?}",
                host, found
            );
        }
        found
    } else {
        None
    };

    let username = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            target_name,
            username,
            ..
        }) => {
            selected_target_name = Some(target_name.clone());
            need_role_auth = false;
            username
        }
        RequestAuthorization::Session(SessionAuthorization::User { username, .. }) => {
            need_role_auth = true;

            selected_target_name = if let Some(warpgate_target) = params.warpgate_target {
                Some(warpgate_target)
            } else if let Some(ref rebound_target) = host_based_target_name {
                Some(rebound_target.clone())
            } else {
                session.get_target_name()
            };
            username
        }
        RequestAuthorization::UserToken { .. } | RequestAuthorization::AdminToken => {
            return Ok(None);
        }
    };

    let domain_rebinding_configured = host_based_target_name.is_some();
    let final_target_name = selected_target_name.or(host_based_target_name);

    if let Some(target_name) = final_target_name {
        let target = {
            ctx.services()
                .config_provider
                .lock()
                .await
                .get_target_by_name(target_name.as_str())
                .await?
                .and_then(|t| match t.options {
                    TargetOptions::Http(ref options) => Some((t.clone(), options.clone())),
                    _ => None,
                })
        };

        if let Some(target) = target {
            if need_role_auth
                && !ctx
                    .services()
                    .config_provider
                    .lock()
                    .await
                    .authorize_target(username, &target.0.name)
                    .await?
            {
                return Ok(None);
            }

            return Ok(Some(target));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

#[cfg(test)]
mod public_target_tests {
    //! Per-VM-proxy P0 (M9): contract for the public-target bypass.
    //!
    //! These tests exercise the pure decision helpers
    //! (`decide_public_target_access`, `find_http_target_by_external_host`)
    //! directly, without spinning up a `Services` fixture — same pattern
    //! as the T1 port-aware-match-key tests in `warpgate-common-http/src/auth.rs`,
    //! which cover the host-resolution helpers that feed this gate.
    //!
    //! Contract under test:
    //!   * Anonymous + public:true → Bypass (proxy through).
    //!   * Session-authed + public:true → Bypass.
    //!   * Admin/User token + public:true → Reject401 (admin-API-scoped).
    //!   * public:false (default) → NotApplicable, regardless of auth.
    //!     This is the additive-default guarantee.
    //!   * No host match → NotApplicable.
    //!   * Lookup is HTTP-only and port-aware (T1 contract).

    use uuid::Uuid;
    use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, Tls};
    use warpgate_common_http::{RequestAuthorization, SessionAuthorization};

    use super::{
        decide_public_target_access, find_http_target_by_external_host,
        PublicTargetDecision,
    };

    fn http_opts(public: bool, external_host: Option<&str>) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: "http://upstream:80".into(),
            tls: Tls::default(),
            headers: None,
            external_host: external_host.map(str::to_string),
            public,
        }
    }

    fn http_target(name: &str, public: bool, external_host: Option<&str>) -> Target {
        Target {
            id: Uuid::nil(),
            name: name.into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(http_opts(public, external_host)),
            rate_limit_bytes_per_second: None,
            group_id: None,
        }
    }

    fn user_token() -> RequestAuthorization {
        RequestAuthorization::UserToken {
            user_id: Uuid::nil(),
            username: "alice".into(),
        }
    }

    fn session_user() -> RequestAuthorization {
        RequestAuthorization::Session(SessionAuthorization::User {
            user_id: Uuid::nil(),
            username: "alice".into(),
        })
    }

    // ─── decide_public_target_access ──────────────────────────────────────

    #[test]
    fn anonymous_on_public_target_bypasses() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        assert_eq!(
            decide_public_target_access(Some(&opts), None),
            PublicTargetDecision::Bypass,
            "anonymous request on public target must bypass auth — this is \
             the whole point of public:true (webhook destinations: Linear, \
             GitHub, Stripe). HMAC verification happens inside the VM.",
        );
    }

    #[test]
    fn session_user_on_public_target_bypasses() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = session_user();
        assert_eq!(
            decide_public_target_access(Some(&opts), Some(&auth)),
            PublicTargetDecision::Bypass,
            "session-authed user on public target also bypasses the role \
             check so the toggle is consistent regardless of who's hitting it.",
        );
    }

    #[test]
    fn admin_token_on_public_target_rejected_401() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::AdminToken;
        assert_eq!(
            decide_public_target_access(Some(&opts), Some(&auth)),
            PublicTargetDecision::Reject401,
            "admin tokens are admin-REST-API-scoped only; using one against \
             a public proxy target must 401 explicitly per spec § 3.1 Q10, \
             rather than silently proxying.",
        );
    }

    #[test]
    fn user_token_on_public_target_rejected_401() {
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = user_token();
        assert_eq!(
            decide_public_target_access(Some(&opts), Some(&auth)),
            PublicTargetDecision::Reject401,
            "user API tokens are also admin-REST-API-scoped — same reasoning \
             as AdminToken; spec lists both as 401 cases.",
        );
    }

    #[test]
    fn private_target_default_is_not_applicable() {
        // The additive-default guarantee. With public:false (the serde
        // default) the decision MUST be NotApplicable so the existing auth
        // path runs unchanged byte-for-byte.
        let opts = http_opts(false, Some("vm.example.com:3000"));
        for auth in [
            None,
            Some(session_user()),
            Some(user_token()),
            Some(RequestAuthorization::AdminToken),
        ] {
            assert_eq!(
                decide_public_target_access(Some(&opts), auth.as_ref()),
                PublicTargetDecision::NotApplicable,
                "public:false MUST never trigger the bypass — auth={auth:?}",
            );
        }
    }

    #[test]
    fn no_target_match_is_not_applicable() {
        // Host header didn't resolve to any HTTP target; the existing flow
        // (target_select_redirect / domain rebinding warnings) takes over.
        for auth in [
            None,
            Some(session_user()),
            Some(user_token()),
            Some(RequestAuthorization::AdminToken),
        ] {
            assert_eq!(
                decide_public_target_access(None, auth.as_ref()),
                PublicTargetDecision::NotApplicable,
            );
        }
    }

    #[test]
    fn session_ticket_on_public_target_also_bypasses() {
        // Tickets are a kind of session auth; they're already scoped to a
        // specific target name. They must not 401 against a public target —
        // they're session-class auth.
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_name: "vm-1".into(),
        });
        assert_eq!(
            decide_public_target_access(Some(&opts), Some(&auth)),
            PublicTargetDecision::Bypass,
        );
    }

    // ─── find_http_target_by_external_host ────────────────────────────────

    #[test]
    fn finds_http_target_by_exact_host_with_port() {
        // Locks in T1's port-aware-match-key contract: external_host
        // including port must match the request host header verbatim.
        let targets = vec![
            http_target("vm-1-3000", true, Some("vm-1.example.com:3000")),
            http_target("vm-1-8080", true, Some("vm-1.example.com:8080")),
        ];
        let (t, _) = find_http_target_by_external_host(&targets, "vm-1.example.com:3000")
            .expect("must match the :3000 target, not :8080");
        assert_eq!(t.name, "vm-1-3000");
    }

    #[test]
    fn returns_none_when_no_target_matches() {
        let targets = vec![http_target("vm-1", true, Some("vm-1.example.com:3000"))];
        assert!(
            find_http_target_by_external_host(&targets, "other.example.com:3000").is_none(),
        );
    }

    #[test]
    fn skips_non_http_targets() {
        // The lookup is HTTP-only; a coincidental SSH target with a
        // matching name must not be returned.
        use warpgate_common::{SSHTargetAuth, TargetSSHOptions};
        let ssh_target = Target {
            id: Uuid::nil(),
            name: "ssh-collision".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Ssh(TargetSSHOptions {
                host: "vm-1.example.com".into(),
                port: 22,
                username: "root".into(),
                allow_insecure_algos: None,
                auth: SSHTargetAuth::default(),
                env: None,
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
        };
        let targets = vec![ssh_target];
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000").is_none(),
            "non-HTTP targets must be skipped by the HTTP catchall lookup",
        );
    }

    #[test]
    fn ignores_targets_with_no_external_host() {
        let t = http_target("vm-1", true, None);
        let targets = vec![t];
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000").is_none(),
            "targets with external_host=None must not match any host; the \
             selectable-target redirect path handles those.",
        );
    }

    // ─── is_warpgate_management_path (defence-in-depth path guard) ──────

    #[test]
    fn warpgate_management_paths_are_guarded() {
        // Defence-in-depth: even if an operator misconfigures a
        // `public:true` target whose `external_host` matches Warpgate's
        // own base host, the management surfaces (`/@warpgate`, including
        // `/@warpgate/admin/*`) MUST NEVER be served anonymously by the
        // public-target bypass. The HTML shell would otherwise leak.
        for path in [
            "/@warpgate",
            "/@warpgate/",
            "/@warpgate/admin",
            "/@warpgate/admin/index.html",
            "/@warpgate/api/openapi.json",
        ] {
            assert!(
                super::is_warpgate_management_path(path),
                "{path} must be classified as a Warpgate management path \
                 and skip the public-target bypass",
            );
        }
    }

    #[test]
    fn underscore_warpgate_alias_is_also_guarded() {
        // `/_warpgate` is mounted alongside `/@warpgate` (lib.rs:233) as
        // an alternate prefix for environments where `@` is troublesome
        // (e.g. some proxies). Treat it identically.
        assert!(super::is_warpgate_management_path("/_warpgate"));
        assert!(super::is_warpgate_management_path("/_warpgate/admin"));
    }

    #[test]
    fn ordinary_paths_are_not_management_paths() {
        // Any path that doesn't sit under the management mount points is
        // eligible for the public-target bypass — webhook endpoints,
        // proxied app routes, root, etc.
        for path in [
            "/",
            "/webhooks/linear",
            "/api/v1/foo",
            "/atwarpgate",            // similar prefix, must NOT match
            "/some/@warpgate/nested", // segment elsewhere, must NOT match
            "/_warp/something",       // similar prefix, must NOT match
        ] {
            assert!(
                !super::is_warpgate_management_path(path),
                "{path} must not be classified as a management path — \
                 the bypass would never apply otherwise",
            );
        }
    }
}

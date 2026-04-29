use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, WarpgateServerHandle, authorize_for_target,
};

use crate::client_cache::HttpClientCache;
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
    http_client_cache: Data<&HttpClientCache>,
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
        None => proxy_normal_request(req, *ctx, body, &target.name, &options, *http_client_cache)
            .instrument(span)
            .await?
            .into_response(),
    })
}

/// True when the request path targets one of Warpgate's own management
/// mounts (`/@warpgate*` or `/_warpgate*`).
///
/// Defence-in-depth on the public-target bypass: a misconfigured
/// `public: true` target whose `external_host` matches Warpgate's base host
/// must never be able to serve a management surface anonymously. At v0.28.6
/// the two management prefixes are nested ahead of the catchall
/// (`lib.rs:294-298`), so `page_auth` should not see these paths at all —
/// this predicate keeps the guarantee independent of routing order.
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
/// without spinning up a full `Services` fixture.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublicTargetDecision {
    /// `public: true` target with anonymous or session-authed client.
    /// `page_auth` skips `_inner_auth` and the catchall proxies straight
    /// through.
    Bypass,
    /// `public: true` target with an admin, user or cluster token. Tokens are
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
        // Admin/user API tokens are scoped to the admin REST API, and the
        // cluster token to peer-to-peer traffic; using any of them against a
        // public proxy target is a configuration error and returns 401
        // explicitly rather than silently proxying.
        Some(
            RequestAuthorization::AdminToken
            | RequestAuthorization::UserToken { .. }
            | RequestAuthorization::ClusterToken,
        ) => PublicTargetDecision::Reject401,
    }
}

/// Filter a candidate target list down to an HTTP target whose
/// `external_host` matches the given host header verbatim (port-aware, since
/// T1's port-aware match key took effect).
///
/// Pure over `targets` so unit tests don't need a real config provider. The
/// async caller narrows the candidates first — `get_target_by_hostname` does
/// the indexed JSON-column lookup — and this helper enforces the HTTP-only
/// and exact-`external_host` half of the contract.
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
) -> poem::Result<(Option<(Target, TargetHTTPOptions)>, PublicTargetDecision)> {
    let Some(host) = host else {
        return Ok((None, PublicTargetDecision::NotApplicable));
    };
    let candidates: Vec<Target> = services
        .config_provider
        .get_target_by_hostname(host)
        .await?
        .into_iter()
        .collect();
    let resolved = find_http_target_by_external_host(&candidates, host);
    let opts = resolved.as_ref().map(|(_, o)| o);
    let decision = decide_public_target_access(opts, auth);
    Ok((resolved, decision))
}

/// Pairs a target with its HTTP options, discarding targets of other protocols.
fn as_http_target(target: Target) -> Option<(Target, TargetHTTPOptions)> {
    let TargetOptions::Http(ref options) = target.options else {
        return None;
    };
    let options = options.clone();
    Some((target, options))
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<(Target, TargetHTTPOptions)>> {
    let config_provider = ctx.services().config_provider.as_ref();

    // A ticket is bound to one target row, and it was authorized against that row
    // when the session was established. Resolving by id keeps the request from
    // steering it elsewhere — via query param, host rebinding or session state —
    // and survives the target being renamed.
    if let RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) = &ctx.auth
    {
        return Ok(config_provider
            .get_target_by_id(*target_id)
            .await?
            .and_then(as_http_target));
    }

    let RequestAuthorization::Session(SessionAuthorization::User { user_id, username }) = &ctx.auth
    else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    // Full Host header including `:port` — two HTTP targets may share a hostname
    // and differ only by port (per-VM proxy), and `get_target_by_hostname` matches
    // `external_host` verbatim.
    let request_host = ctx.trusted_host_header(req);

    let host_based_target = if let Some(host) = request_host {
        let found = config_provider
            .get_target_by_hostname(host.as_str())
            .await?;
        if found.is_some() {
            debug!(
                "Domain rebinding detected: host={} -> target={:?}",
                host,
                found.as_ref().map(|target| &target.name)
            );
        }
        found
    } else {
        None
    };

    let selected_target_name = if let Some(warpgate_target) = params.warpgate_target {
        Some(warpgate_target)
    } else if let Some(ref rebound_target) = host_based_target {
        Some(rebound_target.name.clone())
    } else {
        session.get_target_name()
    };

    let domain_rebinding_configured = host_based_target.is_some();
    let final_target_name = selected_target_name
        .or_else(|| host_based_target.as_ref().map(|target| target.name.clone()));

    if let Some(target_name) = final_target_name {
        let target =
            if let Some(target) = host_based_target.filter(|target| target.name == target_name) {
                Some(target)
            } else {
                config_provider
                    .get_target_by_name(target_name.as_str())
                    .await?
            };

        // Reached only for a `SessionAuthorization::User` (ticket sessions are
        // handled separately above), so the session is the prior-auth evidence.
        let identity = AuthorizedIdentity::for_authenticated_session(
            AuthStateUserInfo {
                id: *user_id,
                username: username.clone(),
            },
            crate::common::PROTOCOL_NAME,
        );

        if let Some(target) = target
            && let Some(authorization) =
                authorize_for_target(config_provider, &identity, target).await?
            && let Some(target_and_options) = as_http_target(authorization.into_parts().1)
        {
            return Ok(Some(target_and_options));
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
    //! as the T1 port-aware-match-key tests in
    //! `warpgate-common-http/src/request.rs`, which cover the host-resolution
    //! helper that feeds this gate.
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
        PublicTargetDecision, decide_public_target_access, find_http_target_by_external_host,
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

    fn target_with_options(name: &str, options: TargetOptions) -> Target {
        Target {
            id: Uuid::nil(),
            name: name.into(),
            description: String::new(),
            allow_roles: vec![],
            options,
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            ticket_max_uses: None,
        }
    }

    fn http_target(name: &str, public: bool, external_host: Option<&str>) -> Target {
        target_with_options(name, TargetOptions::Http(http_opts(public, external_host)))
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
             the whole point of public:true (webhook destinations). HMAC \
             verification happens inside the VM.",
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
    fn cluster_token_on_public_target_rejected_401() {
        // Upstream v0.28.x added a fourth `RequestAuthorization` arm for
        // peer-to-peer cluster traffic. It is not proxy-scoped either, so it
        // lands with the other token classes rather than silently bypassing.
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::ClusterToken;
        assert_eq!(
            decide_public_target_access(Some(&opts), Some(&auth)),
            PublicTargetDecision::Reject401,
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
        // specific target row. They must not 401 against a public target —
        // they're session-class auth.
        let opts = http_opts(true, Some("vm.example.com:3000"));
        let auth = RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_id: Uuid::nil(),
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
        assert!(find_http_target_by_external_host(&targets, "other.example.com:3000").is_none());
    }

    #[test]
    fn skips_non_http_targets() {
        // The lookup is HTTP-only; a coincidental SSH target with a
        // matching name must not be returned.
        use warpgate_common::{SSHTargetAuth, TargetSSHOptions};
        let ssh_target = target_with_options(
            "ssh-collision",
            TargetOptions::Ssh(TargetSSHOptions {
                host: "vm-1.example.com".into(),
                port: 22,
                username: "root".into(),
                allow_insecure_algos: None,
                auth: SSHTargetAuth::default(),
                jump_host: None,
                env: None,
            }),
        );
        let targets = vec![ssh_target];
        assert!(
            find_http_target_by_external_host(&targets, "vm-1.example.com:3000").is_none(),
            "non-HTTP targets must be skipped by the HTTP catchall lookup",
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
        // `/_warpgate` is mounted alongside `/@warpgate` as an alternate
        // prefix for environments where `@` is troublesome (e.g. some
        // proxies). Treat it identically.
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
            "/webhooks/incoming",
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
}

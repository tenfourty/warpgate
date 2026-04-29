use std::ops::Deref;

use poem::http::header::HOST;
use poem::http::uri::Scheme;
use poem::Request;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_common::http_headers::{X_FORWARDED_HOST, X_FORWARDED_PROTO};

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

/// Represents the source of authentication of a session
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SessionAuthorization {
    User {
        user_id: Uuid,
        username: String,
    },
    Ticket {
        user_id: Uuid,
        username: String,
        target_name: String,
    },
}

impl SessionAuthorization {
    pub const fn username(&self) -> &String {
        match self {
            Self::User { username, .. } | Self::Ticket { username, .. } => username,
        }
    }

    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::User { user_id, .. } | Self::Ticket { user_id, .. } => *user_id,
        }
    }
}

/// Represents the source of authentication in a request
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RequestAuthorization {
    Session(SessionAuthorization),
    UserToken { user_id: Uuid, username: String },
    AdminToken,
}

#[derive(Clone)]
pub struct UnauthenticatedRequestContext {
    services: warpgate_core::Services,
    should_trust_x_forwarded: bool,
}

/// Provided to API handlers as Data<>
impl UnauthenticatedRequestContext {
    pub async fn new(services: warpgate_core::Services) -> Self {
        let should_trust_x_forwarded = services
            .config
            .lock()
            .await
            .store
            .http
            .trust_x_forwarded_headers;
        Self {
            services,
            should_trust_x_forwarded,
        }
    }

    pub const fn services(&self) -> &warpgate_core::Services {
        &self.services
    }

    pub fn to_authenticated(&self, auth: RequestAuthorization) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            auth,
            inner: self.clone(),
        }
    }

    /// Returns the trusted full Host header value (including port if present),
    /// preferring X-Forwarded-Host if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_host_header(&self, req: &Request) -> Option<String> {
        let mut host = req.header(HOST).map(ToString::to_string).or_else(|| {
            let uri = req.original_uri();
            let h = uri.host()?;
            Some(match uri.port() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        });

        if self.should_trust_x_forwarded {
            if let Some(xfh) = req.header(&X_FORWARDED_HOST) {
                host = Some(xfh.to_string());
            }
        }

        host
    }

    /// Returns the trusted hostname only (port stripped),
    /// preferring X-Forwarded-Host if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_hostname(&self, req: &Request) -> Option<String> {
        self.trusted_host_header(req)
            .map(|h| h.split(':').next().unwrap_or(&h).to_string())
    }

    /// Returns the trusted protocol scheme for the request, preferring X-Forwarded-Proto
    /// if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_proto(&self, req: &Request) -> Scheme {
        let mut scheme = req
            .original_uri()
            .scheme()
            .cloned()
            .unwrap_or(Scheme::HTTPS);

        if self.should_trust_x_forwarded {
            if let Some(proto) = req.header(&X_FORWARDED_PROTO) {
                if let Ok(s) = Scheme::try_from(proto) {
                    scheme = s;
                }
            }
        }

        scheme
    }
}

#[derive(Clone)]
/// Provided to API handlers as Data<> when a request is authenticated
pub struct AuthenticatedRequestContext {
    pub auth: RequestAuthorization,
    inner: UnauthenticatedRequestContext,
}

impl Deref for AuthenticatedRequestContext {
    type Target = UnauthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl RequestAuthorization {
    /// Returns a username if one is present (admin token has none)
    pub const fn username(&self) -> Option<&String> {
        match self {
            Self::Session(auth) => Some(auth.username()),
            Self::UserToken { username, .. } => Some(username),
            Self::AdminToken => None,
        }
    }

    /// Returns a user ID if present in the authorization context.
    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::Session(auth) => auth.user_id(),
            Self::UserToken { user_id, .. } => *user_id,
            Self::AdminToken => Uuid::nil(),
        }
    }
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    //! Regression guard for the per-VM-proxy port-aware target match key.
    //!
    //! `catchall.rs` in `warpgate-protocol-http` switched from
    //! `trusted_hostname` to `trusted_host_header` so that two HTTP targets
    //! whose `external_host` only differs by `:port` route distinctly. These
    //! tests lock in the contract that the patch depends on:
    //!
    //!   * `trusted_host_header` returns the `Host` header verbatim
    //!     (preserving any `:port`).
    //!   * `trusted_hostname` strips the port.
    //!   * `X-Forwarded-Host` is honoured only when `trust_x_forwarded` is on,
    //!     and in that case the helper returns it verbatim too (port and all).
    //!
    //! These tests do not need a real `Services`, so they exercise the pure
    //! free-function helpers `resolve_trusted_host_header` /
    //! `resolve_trusted_hostname` directly. The `UnauthenticatedRequestContext`
    //! methods are thin wrappers around these helpers.

    use poem::Request;

    use super::{resolve_trusted_host_header, resolve_trusted_hostname};

    fn req_with_host(host: &str) -> Request {
        Request::builder().header("Host", host).finish()
    }

    fn req_with_host_and_xfh(host: &str, xfh: &str) -> Request {
        Request::builder()
            .header("Host", host)
            .header("X-Forwarded-Host", xfh)
            .finish()
    }

    #[test]
    fn trusted_host_header_preserves_port() {
        let req = req_with_host("vm.cove.example.com:3000");
        assert_eq!(
            resolve_trusted_host_header(&req, false),
            Some("vm.cove.example.com:3000".to_string()),
            "trusted_host_header must keep :port so the catchall can match \
             targets that only differ by external_host port",
        );
    }

    #[test]
    fn trusted_host_header_no_port_returns_bare_host() {
        let req = req_with_host("vm.cove.example.com");
        assert_eq!(
            resolve_trusted_host_header(&req, false),
            Some("vm.cove.example.com".to_string()),
        );
    }

    #[test]
    fn trusted_hostname_strips_port() {
        let req = req_with_host("vm.cove.example.com:3000");
        assert_eq!(
            resolve_trusted_hostname(&req, false),
            Some("vm.cove.example.com".to_string()),
            "trusted_hostname must strip :port — cookie-domain and base-host \
             validation rely on this and stay unchanged by the per-VM-proxy patch",
        );
    }

    #[test]
    fn header_and_hostname_diverge_when_port_present() {
        // The whole point of the catchall.rs:73 swap: with a Host header that
        // carries a port, the two helpers MUST return different strings, so
        // that the catchall's `external_host == request_host` comparison can
        // distinguish per-port targets.
        let req = req_with_host("vm.cove.example.com:3000");
        let with_port = resolve_trusted_host_header(&req, false);
        let without_port = resolve_trusted_hostname(&req, false);
        assert_ne!(
            with_port, without_port,
            "trusted_host_header and trusted_hostname must diverge for \
             host-with-port; otherwise the per-VM-proxy match collides",
        );
    }

    #[test]
    fn xfh_ignored_when_trust_disabled() {
        // Default proxy path: trust_x_forwarded_headers = false. The catchall
        // operates here, so X-Forwarded-Host must NOT override Host.
        let req = req_with_host_and_xfh("vm.cove.example.com:3000", "evil.example.com:9999");
        assert_eq!(
            resolve_trusted_host_header(&req, false),
            Some("vm.cove.example.com:3000".to_string()),
        );
    }

    #[test]
    fn xfh_used_verbatim_when_trust_enabled() {
        // When the operator opts in to trust_x_forwarded_headers (front-proxy
        // deployments), the helper returns XFH verbatim — including any port —
        // so per-VM-proxy routing still works behind a reverse proxy.
        let req = req_with_host_and_xfh("front.example.com", "vm.cove.example.com:3000");
        assert_eq!(
            resolve_trusted_host_header(&req, true),
            Some("vm.cove.example.com:3000".to_string()),
        );
    }
}

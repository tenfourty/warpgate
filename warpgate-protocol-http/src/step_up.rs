//! HTTP per-session step-up SSO freshness gate.
//!
//! Stage "A2 — HTTP per-session step-up auth" of the periodic step-up SSO
//! re-auth design (A1 SSH pubkey, A2 HTTP session, A3 Kubernetes cert).
//!
//! After a successful HTTP auth, check when the current Poem session last did
//! an SSO handshake. If stale (older than `step_up_interval.http` or never),
//! clear the auth claims and force fresh SSO before serving authenticated
//! pages. On successful SSO completion, the SSO return handler stamps
//! `last_sso_at` on the session.
//!
//! Scope (strict): User sessions only. Ticket auth / anonymous / admin-token
//! / user-token paths pass through untouched (step-up is SSO-gated, and those
//! paths have no SSO semantics).
//!
//! # Exempt-path invariant (critical)
//!
//! This gate only fires for routes wrapped in [`crate::common::page_auth`] or
//! [`crate::common::endpoint_auth`]. A set of routes MUST NOT be wrapped,
//! else a step-up clear-auth → redirect to login loops indefinitely (the
//! login flow itself would be re-auth-gated and clear its own session before
//! it can complete):
//!
//!   - `/@warpgate/api/sso/*` — SSO redirect start + IdP return callback
//!     (`api::sso_provider_detail`, `api::sso_provider_list`).
//!   - `/@warpgate/api/auth/*` — password / OTP login + logout
//!     (`api::auth::login`, `api::auth::otpLogin`, `api::auth::logout`).
//!   - `/@warpgate/api/info` — unauthenticated version / branding probe
//!     used by the login SPA before a session exists (`api::info::get_info`).
//!   - `/@warpgate/assets/*` — embedded JS / CSS / HTML static assets for
//!     the gateway + admin SPAs.
//!   - `/@warpgate` and `/@warpgate/` — gateway SPA shell
//!     (`src/gateway/index.html`, served as a plain embedded file).
//!   - `/@warpgate/api/playground`, `/@warpgate/api/openapi.json` — OpenAPI
//!     UI + spec.
//!
//! Route registration lives in the crate root (`at_warpgate_endpoints` in
//! `lib.rs`). If
//! you add an SSO, auth, info, or static-asset route there, do NOT attach
//! `page_auth` or `endpoint_auth` to it, and do not nest it under a parent
//! that wraps it. The intended wrapped surface is user-facing authenticated
//! content only: `/@warpgate/admin` (page), `/@warpgate/admin/api` (XHR),
//! the web-auth-requests SSE stream, and the catchall `/` target-proxy
//! route.
use std::time::Duration;

use poem::session::Session;
use time::OffsetDateTime;
use warpgate_common_http::SessionAuthorization;
use warpgate_core::auth::step_up::is_fresh;

/// Session claim key under which we persist the last SSO handshake timestamp
/// for the HTTP surface. Stored as `i64` unix seconds to sidestep
/// serialization of `OffsetDateTime` through Poem's session encoder (which
/// serializes claims via serde_json; plain integers round-trip cleanly across
/// cookie + memory storage backends without timezone / format concerns).
pub const LAST_SSO_AT_SESSION_KEY: &str = "last_sso_at";

/// Convenience accessors for the HTTP step-up clock on a Poem session.
pub trait StepUpSessionExt {
    /// Read the stamped `last_sso_at` off the session, if present and
    /// parseable as a valid `OffsetDateTime`.
    fn get_last_sso_at(&self) -> Option<OffsetDateTime>;

    /// Stamp `last_sso_at` on the session to `now`. Called from the SSO
    /// return handler after `authorize_session`.
    fn set_last_sso_at(&self, now: OffsetDateTime);

    /// Clear the stamp. Used when forcing re-SSO so the new login starts
    /// from a clean slate.
    fn clear_last_sso_at(&self);
}

impl StepUpSessionExt for Session {
    fn get_last_sso_at(&self) -> Option<OffsetDateTime> {
        let secs: i64 = self.get(LAST_SSO_AT_SESSION_KEY)?;
        OffsetDateTime::from_unix_timestamp(secs).ok()
    }

    fn set_last_sso_at(&self, now: OffsetDateTime) {
        self.set(LAST_SSO_AT_SESSION_KEY, now.unix_timestamp());
    }

    fn clear_last_sso_at(&self) {
        self.remove(LAST_SSO_AT_SESSION_KEY);
    }
}

/// Pure freshness decision for an HTTP session.
///
/// Returns `true` iff this request should be forced through a fresh SSO
/// handshake before serving content:
///
/// - `interval.is_none()` → feature disabled for HTTP → never stale.
/// - `auth` is not `SessionAuthorization::User` (anonymous, ticket) → pass
///   through; step-up does not apply (tickets have their own TTL and
///   lifecycle; anonymous has no auth to refresh).
/// - User session with fresh stamp within `interval` → not stale.
/// - User session with stale or missing stamp → stale, force re-SSO.
///
/// Delegates the freshness math to [`warpgate_core::auth::step_up::is_fresh`]
/// so that SSH (A1) and HTTP (A2) share a single boundary semantics (inclusive
/// at `now - interval`, future stamps treated as fresh for clock-skew
/// resilience).
#[must_use]
pub fn is_session_step_up_stale(
    auth: Option<&SessionAuthorization>,
    last_sso_at: Option<OffsetDateTime>,
    interval: Option<Duration>,
    now: OffsetDateTime,
) -> bool {
    let Some(interval) = interval else {
        return false;
    };
    match auth {
        Some(SessionAuthorization::User { .. }) => !is_fresh(last_sso_at, interval, now),
        Some(SessionAuthorization::Ticket { .. }) | None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common_http::SessionAuthorization;

    use super::is_session_step_up_stale;

    fn user_auth() -> SessionAuthorization {
        SessionAuthorization::User {
            user_id: Uuid::nil(),
            username: "alice".into(),
        }
    }

    fn ticket_auth() -> SessionAuthorization {
        SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_id: Uuid::nil(),
        }
    }

    fn now() -> OffsetDateTime {
        // Arbitrary fixed instant so tests don't drift with wall clock.
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn unit_http_step_up_disabled_passes() {
        // No interval configured: feature off, nothing is stale.
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            None,
            None,
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_anonymous_session_passes() {
        // No session auth at all (unauthenticated public endpoints): no
        // step-up check applies. Auth check is elsewhere.
        assert!(!is_session_step_up_stale(
            None,
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_ticket_session_passes() {
        // Ticket-authed sessions are exempt per spec: they hold their own
        // TTL / use counter and are not subject to SSO step-up.
        assert!(!is_session_step_up_stale(
            Some(&ticket_auth()),
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_fresh_stamp_passes() {
        let stamped = now() - time::Duration::minutes(30);
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_stale_stamp_is_stale() {
        let stamped = now() - time::Duration::hours(13);
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_cold_start_is_stale() {
        // User session authorized but no SSO stamp on session (e.g. first
        // visit after password-only login, which does not stamp). Forces
        // re-SSO.
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_exact_boundary_is_fresh() {
        // A stamp exactly one interval ago must count as fresh (inclusive
        // boundary — matches SSH A1 semantics via shared `is_fresh`).
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval;
        assert!(!is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(interval),
            now()
        ));
    }

    #[test]
    fn unit_http_step_up_user_one_second_past_boundary_is_stale() {
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval - time::Duration::seconds(1);
        assert!(is_session_step_up_stale(
            Some(&user_auth()),
            Some(stamped),
            Some(interval),
            now()
        ));
    }
}

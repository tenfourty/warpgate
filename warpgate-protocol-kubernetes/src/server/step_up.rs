//! Kubernetes per-cert step-up SSO freshness gate.
//!
//! Spec: `docs/superpowers/specs/2026-04-17-warpgate-periodic-sso-reauth.md`
//! §"Design: Commit A3 — Kubernetes per-cert step-up auth".
//!
//! After a client certificate successfully matches a `credentials_certificate`
//! row, check when that specific row last SSO'd. If stale (older than
//! `step_up_interval.kubernetes`, or never), force re-SSO by returning 401 to
//! kubectl with a `WWW-Authenticate: SSO <url>` header pointing at the
//! gateway's login page. Fresh → proceed to the proxy dispatch as normal.
//!
//! Scope (strict, per spec): Kubernetes cert auth only. Bearer-token API
//! access, Kubernetes IAM-role auth, and the SSH / HTTP / MySQL / Postgres
//! protocols all have their own gates (or don't use SSO at all). This module
//! knows only about `credentials_certificate.last_sso_at`.
//!
//! # Why per-cert rather than per-session
//!
//! kubectl has no session cookie. Each API request reauths with the same
//! client cert. The natural step-up clock is therefore on the cert row
//! itself — every cert holds its own 12h window, independent of other certs
//! on the same user (different laptop, different kubectl config, different
//! clock).
//!
//! # Stamp semantics
//!
//! A3 ships only the *gate* (stale → 401). The complementary stamp site
//! (updating `last_sso_at` after a successful SSO return) is deferred:
//! kubectl has no natural SSO return path, and the spec explicitly accepts
//! this: Kubernetes is "not actively used by Cove at the moment, but we
//! ship the feature for consistency." Operators can hand-stamp via SQL
//! (matching the live-test rollback recipe in the spec) until a real
//! kubectl OIDC flow is wired in. The `update_cert_last_sso_at` helper
//! in `warpgate-core::auth::step_up` exists for that future wiring.
use std::time::Duration;

use time::OffsetDateTime;
use warpgate_core::auth::step_up::is_fresh;

/// Pure freshness decision for a Kubernetes client cert.
///
/// Returns `true` iff this auth attempt should be rejected as stale (→ 401
/// + `WWW-Authenticate: SSO <url>` to prod the operator to re-SSO).
///
/// - `interval.is_none()` → feature disabled for Kubernetes → never stale.
/// - `Some(interval)` and the stamp is fresh (within `interval`, inclusive at
///   `now - interval`) → not stale.
/// - `Some(interval)` and stamp missing or older than `interval` → stale.
///
/// Delegates the freshness math to [`warpgate_core::auth::step_up::is_fresh`]
/// so SSH / HTTP / Kube share a single boundary semantics.
#[must_use]
pub fn is_cert_step_up_stale(
    last_sso_at: Option<OffsetDateTime>,
    interval: Option<Duration>,
    now: OffsetDateTime,
) -> bool {
    let Some(interval) = interval else {
        return false;
    };
    !is_fresh(last_sso_at, interval, now)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use time::OffsetDateTime;

    use super::is_cert_step_up_stale;

    fn now() -> OffsetDateTime {
        // Fixed instant so tests don't drift with wall clock.
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn unit_kube_step_up_disabled_passes() {
        // No interval configured: feature off, never stale regardless of stamp.
        assert!(!is_cert_step_up_stale(None, None, now()));
        assert!(!is_cert_step_up_stale(
            Some(now() - time::Duration::days(30)),
            None,
            now()
        ));
    }

    #[test]
    fn unit_kube_step_up_cold_start_is_stale() {
        // Cert has never SSO'd (NULL stamp). Must force re-SSO.
        assert!(is_cert_step_up_stale(
            None,
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_kube_step_up_fresh_stamp_passes() {
        let stamped = now() - time::Duration::hours(1);
        assert!(!is_cert_step_up_stale(
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_kube_step_up_stale_stamp_is_stale() {
        let stamped = now() - time::Duration::hours(13);
        assert!(is_cert_step_up_stale(
            Some(stamped),
            Some(Duration::from_secs(12 * 3600)),
            now()
        ));
    }

    #[test]
    fn unit_kube_step_up_exact_boundary_is_fresh() {
        // Inclusive boundary at `now - interval` (matches SSH A1 and HTTP A2
        // semantics via shared `is_fresh`).
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval;
        assert!(!is_cert_step_up_stale(Some(stamped), Some(interval), now()));
    }

    #[test]
    fn unit_kube_step_up_one_second_past_boundary_is_stale() {
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() - interval - time::Duration::seconds(1);
        assert!(is_cert_step_up_stale(Some(stamped), Some(interval), now()));
    }

    #[test]
    fn unit_kube_step_up_future_stamp_is_fresh() {
        // Defensive: a stamp in the future (clock skew across replicas) is
        // treated as fresh by `is_fresh`, so we don't punish operators for a
        // time-sync hiccup.
        let interval = Duration::from_secs(12 * 3600);
        let stamped = now() + time::Duration::minutes(5);
        assert!(!is_cert_step_up_stale(Some(stamped), Some(interval), now()));
    }
}

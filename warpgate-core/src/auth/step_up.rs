//! Step-up SSO freshness helpers for per-credential periodic re-auth.
//!
//! Protocol handlers consult these helpers to decide whether a given
//! credential row must force an SSO / `WebUserApproval` step-up before
//! accepting the session. Freshness is evaluated per credential row so that
//! e.g. pubkey A on laptop 1 and pubkey B on laptop 2 - or cert A on kubectl
//! config 1 and cert B on config 2 - hold independent clocks.
//!
//! Scope:
//! - SSH pubkey helpers (`get_pubkey_last_sso_at` /
//!   `update_pubkey_last_sso_at`) against `credentials_public_key`.
//! - Kubernetes cert helpers (`get_cert_last_sso_at` /
//!   `update_cert_last_sso_at`) against `credentials_certificate`.
//! - HTTP sessions are stamped on the Poem session claim instead of a DB row
//!   (see `warpgate-protocol-http::step_up`).
use std::time::Duration;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities as entities;

/// Decide whether a credential's last SSO handshake is still "fresh" for the
/// configured step-up interval.
///
/// - `None` -> never handshaked -> not fresh (forces step-up).
/// - `Some(ts)` within `interval` (inclusive at `now - interval`) -> fresh.
/// - `Some(ts)` older than `interval` -> not fresh.
///
/// `now` is taken as a parameter so callers (and tests) pin a reference
/// instant; callers in production pass `OffsetDateTime::now_utc()`.
#[must_use]
pub fn is_fresh(
    last_sso_at: Option<OffsetDateTime>,
    interval: Duration,
    now: OffsetDateTime,
) -> bool {
    let Some(last) = last_sso_at else {
        return false;
    };
    let Ok(interval_td) = time::Duration::try_from(interval) else {
        // Implausibly large Duration: treat the credential as stale so we
        // force a step-up rather than silently passing.
        return false;
    };
    now - last <= interval_td
}

/// Read the `last_sso_at` column for the given pubkey credential row.
///
/// Returns `Ok(None)` if the row exists but was never stamped, or if the row
/// no longer exists (defensive - a missing row cannot be fresh).
pub async fn get_pubkey_last_sso_at(
    db: &DatabaseConnection,
    pubkey_id: Uuid,
) -> Result<Option<OffsetDateTime>, WarpgateError> {
    let Some(row) = entities::PublicKeyCredential::Entity::find_by_id(pubkey_id)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    Ok(row.last_sso_at)
}

/// Stamp `last_sso_at` on the given pubkey credential row.
///
/// Idempotent and forward-only: later stamps always overwrite earlier ones.
/// Uses a single atomic UPDATE ... WHERE id = ? - one round trip, safe
/// against concurrent validate/stamp races. Returns the number of rows
/// affected; if the row vanished between validate and stamp (user deleted
/// the pubkey) the UPDATE affects zero rows. That's logged at debug and
/// treated as a benign no-op so the auth flow doesn't fail hard on a race.
pub async fn update_pubkey_last_sso_at(
    db: &DatabaseConnection,
    pubkey_id: Uuid,
    now: OffsetDateTime,
) -> Result<u64, WarpgateError> {
    let result = entities::PublicKeyCredential::Entity::update_many()
        .set(entities::PublicKeyCredential::ActiveModel {
            last_sso_at: Set(Some(now)),
            ..Default::default()
        })
        .filter(entities::PublicKeyCredential::Column::Id.eq(pubkey_id))
        .exec(db)
        .await?;

    if result.rows_affected == 0 {
        tracing::debug!(
            %pubkey_id,
            "update_pubkey_last_sso_at: row vanished between validate and stamp, no-op"
        );
    }
    Ok(result.rows_affected)
}

/// Read the `last_sso_at` column for the given cert credential row.
///
/// Returns `Ok(None)` if the row exists but was never stamped, or if the row
/// no longer exists (defensive - a missing row cannot be fresh).
///
/// Mirror of [`get_pubkey_last_sso_at`] against `credentials_certificate`,
/// consumed by the Kubernetes per-cert step-up gate.
pub async fn get_cert_last_sso_at(
    db: &DatabaseConnection,
    cert_id: Uuid,
) -> Result<Option<OffsetDateTime>, WarpgateError> {
    let Some(row) = entities::CertificateCredential::Entity::find_by_id(cert_id)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    Ok(row.last_sso_at)
}

/// Stamp `last_sso_at` on the given cert credential row.
///
/// Idempotent and forward-only: later stamps always overwrite earlier ones.
/// Uses a single atomic UPDATE ... WHERE id = ? - one round trip, safe
/// against concurrent validate/stamp races. Returns the number of rows
/// affected; if the row vanished between validate and stamp (operator deleted
/// the cert) the UPDATE affects zero rows. That's logged at debug and treated
/// as a benign no-op so the auth flow doesn't fail hard on a race.
///
/// Mirror of [`update_pubkey_last_sso_at`] against `credentials_certificate`.
pub async fn update_cert_last_sso_at(
    db: &DatabaseConnection,
    cert_id: Uuid,
    now: OffsetDateTime,
) -> Result<u64, WarpgateError> {
    let result = entities::CertificateCredential::Entity::update_many()
        .set(entities::CertificateCredential::ActiveModel {
            last_sso_at: Set(Some(now)),
            ..Default::default()
        })
        .filter(entities::CertificateCredential::Column::Id.eq(cert_id))
        .exec(db)
        .await?;

    if result.rows_affected == 0 {
        tracing::debug!(
            %cert_id,
            "update_cert_last_sso_at: row vanished between validate and stamp, no-op"
        );
    }
    Ok(result.rows_affected)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ActiveModelTrait, Database};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    fn hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    fn at(base: OffsetDateTime, offset_seconds: i64) -> OffsetDateTime {
        base + time::Duration::seconds(offset_seconds)
    }

    #[test]
    fn unit_is_fresh_none_never_handshaked_is_stale() {
        let now = OffsetDateTime::now_utc();
        assert!(!is_fresh(None, hours(12), now));
    }

    #[test]
    fn unit_is_fresh_recent_stamp_is_fresh() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -3600); // 1h ago
        assert!(is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_old_stamp_is_stale() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -13 * 3600); // 13h ago
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_exact_boundary_is_fresh() {
        // At exactly interval ago: still fresh (inclusive boundary).
        let now = OffsetDateTime::now_utc();
        let last = at(now, -12 * 3600);
        assert!(is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_one_second_past_boundary_is_stale() {
        let now = OffsetDateTime::now_utc();
        let last = at(now, -(12 * 3600 + 1));
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_one_ns_past_boundary_is_stale() {
        // Documented behaviour: the boundary is inclusive at `now - interval`
        // (see unit_is_fresh_exact_boundary_is_fresh). One nanosecond older
        // than that is therefore stale - there is no sub-second grace period.
        let now = OffsetDateTime::now_utc();
        let last = now - time::Duration::hours(12) - time::Duration::nanoseconds(1);
        assert!(!is_fresh(Some(last), hours(12), now));
    }

    #[test]
    fn unit_is_fresh_clock_skew_future_stamp_is_fresh() {
        // Defensive: if the stored stamp somehow lies in the future (clock
        // skew, timezone corruption), don't force an extra SSO prompt.
        // now - last is negative, which is <= interval_td -> fresh.
        let now = OffsetDateTime::now_utc();
        let last = at(now, 60); // 1 min in the future
        assert!(is_fresh(Some(last), hours(12), now));
    }

    async fn setup_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&conn).await.unwrap();
        conn
    }

    async fn insert_user_and_pubkey(db: &DatabaseConnection) -> Uuid {
        let user_id = Uuid::new_v4();
        entities::User::ActiveModel {
            id: Set(user_id),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await
        .unwrap();

        let pubkey_id = Uuid::new_v4();
        entities::PublicKeyCredential::ActiveModel {
            id: Set(pubkey_id),
            user_id: Set(user_id),
            label: Set("test".into()),
            date_added: Set(None),
            last_used: Set(None),
            last_sso_at: Set(None),
            openssh_public_key: Set("ssh-ed25519 AAAA".into()),
        }
        .insert(db)
        .await
        .unwrap();

        pubkey_id
    }

    #[tokio::test]
    async fn unit_get_pubkey_last_sso_at_returns_none_when_never_stamped() {
        let db = setup_db().await;
        let pubkey_id = insert_user_and_pubkey(&db).await;

        let got = get_pubkey_last_sso_at(&db, pubkey_id).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn unit_get_pubkey_last_sso_at_returns_none_for_missing_row() {
        let db = setup_db().await;
        let missing = Uuid::new_v4();

        let got = get_pubkey_last_sso_at(&db, missing).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn unit_update_pubkey_last_sso_at_roundtrip() {
        let db = setup_db().await;
        let pubkey_id = insert_user_and_pubkey(&db).await;

        let now = OffsetDateTime::now_utc();
        let rows_affected = update_pubkey_last_sso_at(&db, pubkey_id, now)
            .await
            .unwrap();
        assert_eq!(rows_affected, 1, "expected exactly one row updated");

        let got = get_pubkey_last_sso_at(&db, pubkey_id).await.unwrap();

        // Sub-second precision can get truncated by SQLite; compare at
        // whole-second granularity.
        let got = got.expect("expected Some(ts)");
        assert_eq!(got.unix_timestamp(), now.unix_timestamp());
    }

    #[tokio::test]
    async fn unit_update_pubkey_last_sso_at_missing_row_returns_zero() {
        // Defensive: row may have been deleted between validate and stamp.
        // The atomic UPDATE simply matches nothing - rows_affected == 0 and
        // we don't error, so the auth flow doesn't fail hard on a race.
        let db = setup_db().await;
        let missing = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let rows_affected = update_pubkey_last_sso_at(&db, missing, now).await.unwrap();
        assert_eq!(rows_affected, 0);
    }
}

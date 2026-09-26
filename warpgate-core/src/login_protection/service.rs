use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use time::OffsetDateTime;
use tracing::{debug, info};
use uuid::Uuid;
use warpgate_common::{Protocol, WarpgateError};
use warpgate_db_entities::{
    FailedLoginAttempt, IpBlock, Parameters, User, UserAdminRoleAssignment, UserLockout,
};

use super::cache::{IpBlockInfo, LoginProtectionCache, UserLockInfo};

/// IP rate-limiting thresholds, read from the `parameters` table. All durations
/// are stored as seconds.
#[derive(Clone, Debug)]
struct IpRateLimitConfig {
    max_attempts: u32,
    time_window_seconds: u32,
    base_block_duration_seconds: u32,
    block_duration_multiplier: f32,
    max_block_duration_seconds: u32,
    cooldown_reset_seconds: u32,
}

/// User-lockout thresholds, read from the `parameters` table. All durations are
/// stored as seconds.
#[derive(Clone, Debug)]
struct UserLockoutConfig {
    max_attempts: u32,
    time_window_seconds: u32,
    auto_unlock: bool,
    lockout_duration_seconds: u32,
    /// When set, users holding an admin role are never locked out (so an
    /// attacker can't lock an admin out by spamming their username).
    exempt_admins: bool,
}

/// Snapshot of login-protection settings, read fresh from the DB per call.
#[derive(Clone, Debug)]
struct LoginProtectionConfig {
    enabled: bool,
    retention_seconds: u32,
    ip_rate_limit: IpRateLimitConfig,
    user_lockout: UserLockoutConfig,
    /// Addresses in these networks are never blocked; their failed attempts
    /// still count towards the per-username limit.
    ip_exempt: Vec<IpNet>,
}

impl LoginProtectionConfig {
    fn is_ip_exempt(&self, ip: &IpAddr) -> bool {
        // An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d.
        let ip = ip.to_canonical();
        self.ip_exempt.iter().any(|network| network.contains(&ip))
    }
}

/// Information about a failed login attempt.
#[derive(Clone, Debug)]
pub struct FailedAttemptInfo {
    pub username: String,
    pub remote_ip: IpAddr,
    pub protocol: Protocol,
    pub credential_type: String,
}

/// Security status for the admin dashboard.
#[derive(Clone, Debug)]
pub struct SecurityStatus {
    pub blocked_ip_count: u64,
    pub locked_user_count: u64,
    pub failed_attempts_last_hour: u64,
    pub failed_attempts_last_24h: u64,
}

/// One row for the admin "blocked IPs" listing: the stored block plus
/// whether the address is currently on the exempt list.
///
/// `is_exempt` is computed with the exact same predicate,
/// `LoginProtectionConfig::is_ip_exempt`, that `check_ip_blocked` applies,
/// so a row can never disagree with what actually gets enforced: an exempt
/// address can still have a stale block row (written before it was
/// exempted, or before the exempt list changed), and this is what lets the
/// admin UI say so instead of implying the block is live.
#[derive(Clone, Debug)]
pub struct BlockedIpEntry {
    pub info: IpBlockInfo,
    pub is_exempt: bool,
}

/// Statistics from a cleanup run.
#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)]
pub struct CleanupStats {
    pub expired_blocks_removed: u64,
    pub expired_lockouts_removed: u64,
    pub old_attempts_removed: u64,
}

/// Central service for login protection logic.
///
/// Thresholds are **never cached** — every method reads `Parameters` from the
/// DB directly, matching the pattern used by every other warpgate parameter
/// (ssh_client_auth_*, ticket_*, record_scp, …). An admin saving new settings
/// takes effect on the very next login attempt with no restart.
///
/// Active blocks/lockouts are mirrored in an in-memory [`LoginProtectionCache`]
/// for the read path; the cache is warmed on startup and updated incrementally
/// as blocks/lockouts are created or cleared.
pub struct LoginProtectionService {
    db: DatabaseConnection,
    cache: LoginProtectionCache,
}

impl LoginProtectionService {
    /// Build a [`LoginProtectionConfig`] from a `Parameters` DB row.
    fn config_from_params(params: &Parameters::Model) -> LoginProtectionConfig {
        LoginProtectionConfig {
            enabled: params.login_protection_enabled,
            retention_seconds: params.login_protection_retention_seconds as u32,
            ip_rate_limit: IpRateLimitConfig {
                max_attempts: params.lp_ip_max_attempts as u32,
                time_window_seconds: params.lp_ip_time_window_seconds as u32,
                base_block_duration_seconds: params.lp_ip_base_block_duration_seconds as u32,
                block_duration_multiplier: params.lp_ip_block_duration_multiplier as f32,
                max_block_duration_seconds: params.lp_ip_max_block_duration_seconds as u32,
                cooldown_reset_seconds: params.lp_ip_cooldown_reset_seconds as u32,
            },
            user_lockout: UserLockoutConfig {
                max_attempts: params.lp_user_max_attempts as u32,
                time_window_seconds: params.lp_user_time_window_seconds as u32,
                auto_unlock: params.lp_user_auto_unlock,
                lockout_duration_seconds: params.lp_user_lockout_duration_seconds as u32,
                exempt_admins: params.lp_user_exempt_admins,
            },
            ip_exempt: params.lp_ip_exempt_networks(),
        }
    }

    /// Read the current config from the DB.
    async fn read_config(db: &DatabaseConnection) -> Result<LoginProtectionConfig, WarpgateError> {
        Ok(Self::config_from_params(
            &Parameters::Entity::get(db).await?,
        ))
    }

    /// Admin status of `username`: `None` if no such user exists, otherwise
    /// `Some(is_admin)`. Used to keep account lockout limited to real, non-admin
    /// accounts — locking a non-existent username is pointless, and admins must
    /// never be lockable by an attacker spamming their username.
    async fn user_admin_status<C: ConnectionTrait>(
        db: &C,
        username: &str,
    ) -> Result<Option<bool>, WarpgateError> {
        let Some(user) = User::Entity::find()
            .filter(User::Entity::username_eq_ci(username))
            .one(db)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            UserAdminRoleAssignment::Entity::find()
                .filter(UserAdminRoleAssignment::Column::UserId.eq(user.id))
                .exists(db)
                .await?,
        ))
    }

    /// Create the service and warm the cache from DB state.
    pub async fn new(db: DatabaseConnection) -> Result<Self, WarpgateError> {
        let cache = LoginProtectionCache::new();
        {
            let db_conn = &db;
            if Self::read_config(db_conn).await?.enabled {
                cache.load_from_db(db_conn).await?;
            }
        }
        Ok(Self { db, cache })
    }

    /// Check whether `ip` is currently blocked.
    pub async fn check_ip_blocked(
        &self,
        ip: &IpAddr,
    ) -> Result<Option<IpBlockInfo>, WarpgateError> {
        let db = &self.db;
        let config = Self::read_config(db).await?;
        // An exempt address is never reported blocked, even by a block row
        // written before it was added to the list.
        if !config.enabled || config.is_ip_exempt(ip) {
            return Ok(None);
        }

        if let Some(info) = self.cache.is_ip_blocked(ip).await {
            debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from cache)");
            return Ok(Some(info));
        }

        let now = OffsetDateTime::now_utc();
        let block = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .one(db)
            .await?;

        let Some(block) = block else {
            return Ok(None);
        };
        let info = IpBlockInfo {
            ip_address: *ip,
            blocked_at: block.blocked_at,
            expires_at: block.expires_at,
            block_count: block.block_count,
            reason: block.reason,
        };
        self.cache.block_ip(*ip, info.clone()).await;
        debug!(ip = %ip, expires_at = %info.expires_at, "IP is blocked (from DB)");
        Ok(Some(info))
    }

    /// Check whether `username` is currently locked. When admin exemption is
    /// enabled, admins are never reported as locked.
    pub async fn check_user_locked(
        &self,
        username: &str,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        let db = &self.db;
        let config = Self::read_config(db).await?;
        if !config.enabled {
            return Ok(None);
        }

        let info = if let Some(info) = self.cache.is_user_locked(username).await {
            Some(info)
        } else {
            let now = OffsetDateTime::now_utc();
            let lockout = UserLockout::Entity::find()
                .filter(UserLockout::Entity::username_eq_ci(username))
                .one(db)
                .await?
                .filter(|l| l.expires_at.is_none_or(|e| e > now));
            match lockout {
                Some(lockout) => {
                    let info = UserLockInfo {
                        username: lockout.username,
                        locked_at: lockout.locked_at,
                        expires_at: lockout.expires_at,
                        reason: lockout.reason,
                    };
                    self.cache
                        .lock_user(username.to_string(), info.clone())
                        .await;
                    Some(info)
                }
                None => None,
            }
        };

        // When exemption is enabled, never report an admin as locked.
        if info.is_some()
            && config.user_lockout.exempt_admins
            && Self::user_admin_status(db, username).await? == Some(true)
        {
            return Ok(None);
        }

        if info.is_some() {
            debug!(username = %username, "User is locked");
        }
        Ok(info)
    }

    /// Record a failed login attempt; may trigger an IP block or user lockout.
    pub async fn record_failed_attempt(
        &self,
        attempt: FailedAttemptInfo,
    ) -> Result<(), WarpgateError> {
        let db = &self.db;
        let config = Self::read_config(db).await?;
        if !config.enabled {
            return Ok(());
        }

        let txn = db.begin().await?;
        let now = OffsetDateTime::now_utc();

        FailedLoginAttempt::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(attempt.username.clone()),
            remote_ip: Set(attempt.remote_ip.to_string()),
            protocol: Set(attempt.protocol.name().to_owned()),
            credential_type: Set(attempt.credential_type.clone()),
            timestamp: Set(now),
        }
        .insert(&txn)
        .await?;

        // The attempt row above is still written for an exempt address, so the
        // per-username count below sees it; only the per-address block is skipped.
        let ip_exempt = config.is_ip_exempt(&attempt.remote_ip);
        let mut ip_count = 0;
        let mut new_block = None;
        if !ip_exempt {
            let ip_window_start =
                now - time::Duration::seconds(i64::from(config.ip_rate_limit.time_window_seconds));
            ip_count = FailedLoginAttempt::Entity::find()
                .filter(FailedLoginAttempt::Column::RemoteIp.eq(attempt.remote_ip.to_string()))
                .filter(FailedLoginAttempt::Column::Timestamp.gte(ip_window_start))
                .count(&txn)
                .await?;
            if ip_count >= u64::from(config.ip_rate_limit.max_attempts) {
                new_block =
                    Self::create_or_update_ip_block(&txn, &attempt.remote_ip, now, &config).await?;
            }
        }

        let user_window_start =
            now - time::Duration::seconds(i64::from(config.user_lockout.time_window_seconds));
        let user_count = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Entity::username_eq_ci(
                &attempt.username,
            ))
            .filter(FailedLoginAttempt::Column::Timestamp.gte(user_window_start))
            .count(&txn)
            .await?;
        // Lock real accounts over the threshold; skip non-existent usernames and
        // (unless exemption is disabled) admins.
        let new_lock = if user_count >= u64::from(config.user_lockout.max_attempts) {
            match Self::user_admin_status(&txn, &attempt.username).await? {
                None => None,
                Some(true) if config.user_lockout.exempt_admins => None,
                Some(_) => {
                    Self::create_user_lockout(
                        &txn,
                        &attempt.username,
                        user_count as i32,
                        now,
                        &config,
                    )
                    .await?
                }
            }
        } else {
            None
        };

        txn.commit().await?;

        // Reflect the new state in the cache without a full reload.
        if let Some(info) = new_block {
            self.cache.block_ip(attempt.remote_ip, info).await;
        }
        if let Some(info) = new_lock {
            self.cache.lock_user(attempt.username.clone(), info).await;
        }

        info!(
            ip = %attempt.remote_ip,
            username = %attempt.username,
            protocol = %attempt.protocol,
            ip_exempt,
            ip_attempt_count = ip_count,
            user_attempt_count = user_count,
            "Recorded failed login attempt"
        );

        Ok(())
    }

    async fn create_or_update_ip_block<C: ConnectionTrait>(
        db: &C,
        ip: &IpAddr,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<Option<IpBlockInfo>, WarpgateError> {
        let ip_str = ip.to_string();
        let existing = IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(&ip_str))
            .one(db)
            .await?;

        // A retry from an address that is still blocked leaves the block as it
        // is. Re-arming it on every attempt meant a client that kept retrying
        // was never let go.
        if existing.as_ref().is_some_and(|e| e.expires_at > now) {
            return Ok(None);
        }

        // Escalate the block count unless the IP has been quiet long enough.
        let cooldown =
            time::Duration::seconds(i64::from(config.ip_rate_limit.cooldown_reset_seconds));
        let block_count = match &existing {
            Some(e) if now - e.last_attempt_at <= cooldown => e.block_count + 1,
            _ => 1,
        };

        let block_duration = calculate_block_duration(block_count as u32, &config.ip_rate_limit);
        let expires_at =
            now + time::Duration::try_from(block_duration).unwrap_or(time::Duration::ZERO);
        let reason = format!(
            "Exceeded {} failed login attempts (block #{block_count})",
            config.ip_rate_limit.max_attempts
        );

        let model = IpBlock::ActiveModel {
            id: Set(existing.as_ref().map_or_else(Uuid::new_v4, |e| e.id)),
            ip_address: Set(ip_str),
            block_count: Set(block_count),
            blocked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(reason.clone()),
            last_attempt_at: Set(now),
        };
        if existing.is_some() {
            IpBlock::Entity::update(model).exec(db).await?;
        } else {
            model.insert(db).await?;
        }

        info!(
            ip = %ip,
            block_count,
            duration_minutes = block_duration.as_secs() / 60,
            expires_at = %expires_at,
            "IP blocked"
        );

        Ok(Some(IpBlockInfo {
            ip_address: *ip,
            blocked_at: now,
            expires_at,
            block_count,
            reason,
        }))
    }

    async fn create_user_lockout<C: ConnectionTrait>(
        db: &C,
        username: &str,
        failed_count: i32,
        now: OffsetDateTime,
        config: &LoginProtectionConfig,
    ) -> Result<Option<UserLockInfo>, WarpgateError> {
        let already_locked = UserLockout::Entity::find()
            .filter(UserLockout::Entity::username_eq_ci(username))
            .one(db)
            .await?
            .is_some();
        if already_locked {
            return Ok(None);
        }

        let expires_at = config.user_lockout.auto_unlock.then(|| {
            now + time::Duration::seconds(i64::from(config.user_lockout.lockout_duration_seconds))
        });
        let reason = format!(
            "Exceeded {} failed login attempts",
            config.user_lockout.max_attempts
        );

        UserLockout::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_string()),
            locked_at: Set(now),
            expires_at: Set(expires_at),
            reason: Set(reason.clone()),
            failed_attempt_count: Set(failed_count),
        }
        .insert(db)
        .await?;

        info!(
            username = %username,
            auto_unlock = config.user_lockout.auto_unlock,
            expires_at = ?expires_at,
            "User account locked"
        );

        Ok(Some(UserLockInfo {
            username: username.to_string(),
            locked_at: now,
            expires_at,
            reason,
        }))
    }

    /// Clear recorded failed attempts after a successful login, so a user who
    /// fumbled their password a few times isn't progressively penalised.
    pub async fn clear_failed_attempts(
        &self,
        ip: &IpAddr,
        username: &str,
    ) -> Result<(), WarpgateError> {
        let db = &self.db;
        if !Self::read_config(db).await?.enabled {
            return Ok(());
        }

        FailedLoginAttempt::Entity::delete_many()
            .filter(
                Condition::any()
                    .add(FailedLoginAttempt::Column::RemoteIp.eq(ip.to_string()))
                    .add(FailedLoginAttempt::Entity::username_eq_ci(username).into_condition()),
            )
            .exec(db)
            .await?;

        debug!(ip = %ip, username = %username, "Cleared failed attempts after successful login");
        Ok(())
    }

    /// Admin: unblock an IP and clear its attempt history.
    pub async fn unblock_ip(&self, ip: &IpAddr) -> Result<(), WarpgateError> {
        let db = &self.db;
        IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::IpAddress.eq(ip.to_string()))
            .exec(db)
            .await?;
        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::RemoteIp.eq(ip.to_string()))
            .exec(db)
            .await?;

        self.cache.unblock_ip(ip).await;
        info!(ip = %ip, "IP unblocked by admin");
        Ok(())
    }

    /// Admin: unlock a user account and clear its attempt history.
    pub async fn unlock_user(&self, username: &str) -> Result<(), WarpgateError> {
        let db = &self.db;
        UserLockout::Entity::delete_many()
            .filter(UserLockout::Entity::username_eq_ci(username))
            .exec(db)
            .await?;
        FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Entity::username_eq_ci(username))
            .exec(db)
            .await?;

        self.cache.unlock_user(username).await;
        info!(username = %username, "User unlocked by admin");
        Ok(())
    }

    /// Security status for the admin dashboard.
    pub async fn get_security_status(&self) -> Result<SecurityStatus, WarpgateError> {
        let db = &self.db;
        let now = OffsetDateTime::now_utc();

        let blocked_ip_count = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .count(db)
            .await?;

        let locked_user_count = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .count(db)
            .await?;

        let failed_attempts_last_hour = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(now - time::Duration::hours(1)))
            .count(db)
            .await?;

        let failed_attempts_last_24h = FailedLoginAttempt::Entity::find()
            .filter(FailedLoginAttempt::Column::Timestamp.gte(now - time::Duration::hours(24)))
            .count(db)
            .await?;

        Ok(SecurityStatus {
            blocked_ip_count,
            locked_user_count,
            failed_attempts_last_hour,
            failed_attempts_last_24h,
        })
    }

    /// List all currently blocked IPs, flagging any row whose address is on
    /// the exempt list (runcove-ljvj.24). `check_ip_blocked` already ignores
    /// such a row when deciding whether to enforce a block; this reuses that
    /// exact decision (`config.is_ip_exempt`) rather than a second copy of
    /// it, so the admin listing can never disagree with what is enforced.
    pub async fn list_blocked_ips(&self) -> Result<Vec<BlockedIpEntry>, WarpgateError> {
        let db = &self.db;
        let now = OffsetDateTime::now_utc();
        // Read once and reuse for every row, rather than once per row: the
        // exemption list does not change between the rows of one listing.
        let config = Self::read_config(db).await?;
        let blocks = IpBlock::Entity::find()
            .filter(IpBlock::Column::ExpiresAt.gt(now))
            .all(db)
            .await?;

        Ok(blocks
            .into_iter()
            .filter_map(|block| {
                let ip = block.ip_address.parse::<IpAddr>().ok()?;
                let is_exempt = config.is_ip_exempt(&ip);
                Some(BlockedIpEntry {
                    info: IpBlockInfo {
                        ip_address: ip,
                        blocked_at: block.blocked_at,
                        expires_at: block.expires_at,
                        block_count: block.block_count,
                        reason: block.reason,
                    },
                    is_exempt,
                })
            })
            .collect())
    }

    /// List all currently locked users.
    pub async fn list_locked_users(&self) -> Result<Vec<UserLockInfo>, WarpgateError> {
        let db = &self.db;
        let now = OffsetDateTime::now_utc();
        let lockouts = UserLockout::Entity::find()
            .filter(
                UserLockout::Column::ExpiresAt
                    .is_null()
                    .or(UserLockout::Column::ExpiresAt.gt(now)),
            )
            .all(db)
            .await?;

        Ok(lockouts
            .into_iter()
            .map(|l| UserLockInfo {
                username: l.username,
                locked_at: l.locked_at,
                expires_at: l.expires_at,
                reason: l.reason,
            })
            .collect())
    }

    /// Background cleanup: remove expired blocks, lockouts, and old attempts.
    /// Reads the enabled flag from the DB so it honours runtime config changes.
    pub async fn cleanup_expired(&self) -> Result<CleanupStats, WarpgateError> {
        let db = &self.db;
        let config = Self::read_config(db).await?;
        if !config.enabled {
            return Ok(CleanupStats {
                expired_blocks_removed: 0,
                expired_lockouts_removed: 0,
                old_attempts_removed: 0,
            });
        }

        let now = OffsetDateTime::now_utc();

        let expired_blocks = IpBlock::Entity::delete_many()
            .filter(IpBlock::Column::ExpiresAt.lt(now))
            .exec(db)
            .await?;

        let expired_lockouts = UserLockout::Entity::delete_many()
            .filter(UserLockout::Column::ExpiresAt.is_not_null())
            .filter(UserLockout::Column::ExpiresAt.lt(now))
            .exec(db)
            .await?;

        let retention_cutoff = now - time::Duration::seconds(i64::from(config.retention_seconds));
        let old_attempts = FailedLoginAttempt::Entity::delete_many()
            .filter(FailedLoginAttempt::Column::Timestamp.lt(retention_cutoff))
            .exec(db)
            .await?;

        self.cache.clear_expired().await;

        let stats = CleanupStats {
            expired_blocks_removed: expired_blocks.rows_affected,
            expired_lockouts_removed: expired_lockouts.rows_affected,
            old_attempts_removed: old_attempts.rows_affected,
        };

        if stats.expired_blocks_removed > 0
            || stats.expired_lockouts_removed > 0
            || stats.old_attempts_removed > 0
        {
            info!(
                expired_blocks = stats.expired_blocks_removed,
                expired_lockouts = stats.expired_lockouts_removed,
                old_attempts = stats.old_attempts_removed,
                "Login protection cleanup completed"
            );
        }

        Ok(stats)
    }
}

/// Block duration with exponential backoff:
/// `base * multiplier^(block_count - 1)`, capped at the configured maximum.
fn calculate_block_duration(block_count: u32, config: &IpRateLimitConfig) -> Duration {
    let base_secs = u64::from(config.base_block_duration_seconds);
    let max_secs = u64::from(config.max_block_duration_seconds);
    let factor = config
        .block_duration_multiplier
        .powi(block_count.saturating_sub(1).cast_signed());
    #[allow(clippy::cast_precision_loss)]
    let duration_secs = (base_secs as f32 * factor) as u64;
    Duration::from_secs(duration_secs.min(max_secs))
}

#[cfg(test)]
mod tests {
    use sea_orm::{Database, IntoActiveModel};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    // Documentation and private ranges only: this branch is public.
    const EXEMPT_V4: &str = "10.20.30.40";
    const OTHER_V4: &str = "192.0.2.10";

    async fn setup_db(exempt: &[&str]) -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        set_exempt(&db, exempt).await;

        User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();
        db
    }

    async fn set_exempt(db: &DatabaseConnection, exempt: &[&str]) {
        let mut params = Parameters::Entity::get(db)
            .await
            .unwrap()
            .into_active_model();
        params.login_protection_enabled = Set(true);
        params.lp_ip_exempt_cidrs = Set(serde_json::to_string(exempt).unwrap());
        params.update(db).await.unwrap();
    }

    async fn fail(service: &LoginProtectionService, ip: &str, times: usize) {
        for _ in 0..times {
            service
                .record_failed_attempt(FailedAttemptInfo {
                    username: "alice".into(),
                    remote_ip: ip.parse().unwrap(),
                    protocol: Protocol::Ssh,
                    credential_type: "password".into(),
                })
                .await
                .unwrap();
        }
    }

    async fn block_row(db: &DatabaseConnection, ip: &str) -> Option<IpBlock::Model> {
        IpBlock::Entity::find()
            .filter(IpBlock::Column::IpAddress.eq(ip))
            .one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn exempt_address_is_never_blocked() {
        let db = setup_db(&["10.0.0.0/8"]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        fail(&service, EXEMPT_V4, 20).await;

        assert!(
            service
                .check_ip_blocked(&EXEMPT_V4.parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(block_row(&db, EXEMPT_V4).await.is_none());
        // The attempts themselves are still on record.
        assert_eq!(FailedLoginAttempt::Entity::find().count(&db).await.unwrap(), 20);
    }

    #[tokio::test]
    async fn username_limit_still_applies_to_an_exempt_address() {
        let db = setup_db(&["10.0.0.0/8"]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        // lp_user_max_attempts defaults to 10.
        fail(&service, EXEMPT_V4, 10).await;

        assert!(service.check_user_locked("alice").await.unwrap().is_some());
        assert!(
            service
                .check_ip_blocked(&EXEMPT_V4.parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn address_outside_the_list_is_blocked_as_before() {
        let db = setup_db(&["10.0.0.0/8", "2001:db8::/32"]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        // lp_ip_max_attempts defaults to 5.
        fail(&service, OTHER_V4, 4).await;
        assert!(
            service
                .check_ip_blocked(&OTHER_V4.parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        fail(&service, OTHER_V4, 1).await;
        assert!(
            service
                .check_ip_blocked(&OTHER_V4.parse().unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn empty_list_blocks_every_address() {
        let db = setup_db(&[]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        fail(&service, EXEMPT_V4, 5).await;

        assert!(
            service
                .check_ip_blocked(&EXEMPT_V4.parse().unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn existing_block_is_ignored_once_the_address_is_exempt() {
        let db = setup_db(&[]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();
        let ip: IpAddr = EXEMPT_V4.parse().unwrap();

        fail(&service, EXEMPT_V4, 5).await;
        assert!(service.check_ip_blocked(&ip).await.unwrap().is_some());

        set_exempt(&db, &["10.20.0.0/16"]).await;

        // The row (and the cache entry) are still there, but no longer count.
        assert!(block_row(&db, EXEMPT_V4).await.is_some());
        assert!(service.check_ip_blocked(&ip).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_blocked_ips_flags_the_exempt_row_and_not_the_other() {
        // runcove-ljvj.24: the admin listing must flag a row whose address
        // is exempt, and must not flag one that is not.
        let db = setup_db(&[]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        // Block BOTH while neither is exempt yet: an already-exempt address
        // is never blocked in the first place (see the case above), so a
        // row that should end up flagged has to exist BEFORE the exemption
        // is added -- the same shape as the stale row Jeremy found live.
        fail(&service, EXEMPT_V4, 5).await;
        fail(&service, OTHER_V4, 5).await;
        assert!(block_row(&db, EXEMPT_V4).await.is_some());
        assert!(block_row(&db, OTHER_V4).await.is_some());

        set_exempt(&db, &["10.20.0.0/16"]).await; // covers EXEMPT_V4, not OTHER_V4

        let rows = service.list_blocked_ips().await.unwrap();
        assert_eq!(rows.len(), 2);
        let exempt_row = rows
            .iter()
            .find(|r| r.info.ip_address == EXEMPT_V4.parse::<IpAddr>().unwrap())
            .expect("the exempt address' row is missing from the listing");
        let other_row = rows
            .iter()
            .find(|r| r.info.ip_address == OTHER_V4.parse::<IpAddr>().unwrap())
            .expect("the non-exempt address' row is missing from the listing");
        assert!(exempt_row.is_exempt, "an exempt address' row must be flagged");
        assert!(!other_row.is_exempt, "a normal address' row must not be flagged");
    }

    #[tokio::test]
    async fn retries_from_a_blocked_address_do_not_move_its_block() {
        let db = setup_db(&[]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        fail(&service, OTHER_V4, 5).await;
        let first = block_row(&db, OTHER_V4).await.unwrap();
        assert_eq!(first.block_count, 1);

        fail(&service, OTHER_V4, 5).await;
        let after = block_row(&db, OTHER_V4).await.unwrap();

        assert_eq!(after, first);
        let cached = service
            .check_ip_blocked(&OTHER_V4.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cached.block_count, 1);
    }

    #[tokio::test]
    async fn ipv6_networks_are_exempt_too() {
        let db = setup_db(&["2001:db8:1::/48"]).await;
        let service = LoginProtectionService::new(db.clone()).await.unwrap();

        fail(&service, "2001:db8:1::5", 10).await;
        assert!(
            service
                .check_ip_blocked(&"2001:db8:1::5".parse().unwrap())
                .await
                .unwrap()
                .is_none()
        );

        fail(&service, "2001:db8:2::5", 5).await;
        assert!(
            service
                .check_ip_blocked(&"2001:db8:2::5".parse().unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }

    async fn config_with_stored_list(stored: &str) -> LoginProtectionConfig {
        let db = setup_db(&[]).await;
        let mut params = Parameters::Entity::get(&db).await.unwrap();
        params.lp_ip_exempt_cidrs = stored.into();
        LoginProtectionService::config_from_params(&params)
    }

    #[tokio::test]
    async fn ipv4_mapped_address_matches_an_ipv4_network() {
        let config = config_with_stored_list(r#"["10.0.0.0/8"]"#).await;
        assert!(config.is_ip_exempt(&"::ffff:10.1.2.3".parse().unwrap()));
        assert!(config.is_ip_exempt(&"10.1.2.3".parse().unwrap()));
        assert!(!config.is_ip_exempt(&"::ffff:192.0.2.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn unreadable_list_exempts_nothing() {
        for stored in ["", "not json", r#"["not-a-network"]"#] {
            let config = config_with_stored_list(stored).await;
            assert!(!config.is_ip_exempt(&"10.1.2.3".parse().unwrap()), "{stored}");
        }
    }

    fn default_config() -> IpRateLimitConfig {
        IpRateLimitConfig {
            max_attempts: 5,
            time_window_seconds: 900,
            base_block_duration_seconds: 1800,
            block_duration_multiplier: 2.0,
            max_block_duration_seconds: 86400,
            cooldown_reset_seconds: 86400,
        }
    }

    #[test]
    fn test_calculate_block_duration_first_block() {
        assert_eq!(
            calculate_block_duration(1, &default_config()).as_secs(),
            1800
        );
    }

    #[test]
    fn test_calculate_block_duration_second_block() {
        assert_eq!(
            calculate_block_duration(2, &default_config()).as_secs(),
            3600
        );
    }

    #[test]
    fn test_calculate_block_duration_third_block() {
        assert_eq!(
            calculate_block_duration(3, &default_config()).as_secs(),
            7200
        );
    }

    #[test]
    fn test_calculate_block_duration_fifth_block() {
        assert_eq!(
            calculate_block_duration(5, &default_config()).as_secs(),
            28800
        );
    }

    #[test]
    fn test_calculate_block_duration_capped_at_max() {
        assert_eq!(
            calculate_block_duration(10, &default_config()).as_secs(),
            86400
        );
    }

    #[test]
    fn test_calculate_block_duration_with_different_multiplier() {
        let mut config = default_config();
        config.block_duration_multiplier = 1.5;
        assert_eq!(calculate_block_duration(3, &config).as_secs(), 4050);
    }

    #[test]
    fn test_calculate_block_duration_zero_block_count() {
        assert_eq!(
            calculate_block_duration(0, &default_config()).as_secs(),
            1800
        );
    }
}

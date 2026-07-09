//! In-flight SSO handshake storage, kept deliberately OUT of the Poem session.
//!
//! Warpgate's `/sso/*/start` used to stash the SSO handshake (the
//! [`SsoLoginRequest`] carrying the OAuth CSRF `state`) in the Poem session
//! under a single key, and `/sso/return` read it back to run
//! `verify_state`. That is unsafe under concurrency:
//!
//!  * The session is a single read-modify-write blob per request. Two requests
//!    that race — trivially common once the session cookie is scoped to the
//!    parent domain and shared across every subdomain tab, plus the auto-SSO
//!    redirect and the SPA's background auth-state polls — clobber each other's
//!    session writes (last writer wins). The handshake stored by `/start` is
//!    dropped before the IdP callback arrives.
//!  * Even without the blob race, a single per-session slot means a second
//!    `/start` (another tab, a retry, the auto-SSO redirect) overwrites the
//!    first flow's `state`, so the first callback fails `verify_state` with
//!    "Invalid SSO state parameter".
//!
//! Keying handshakes by their (unguessable, single-use) `state` lets any number
//! of concurrent flows coexist. Binding each entry to the `SessionId` that
//! initiated it preserves the login-CSRF protection that per-session storage
//! gave us: a callback presenting a valid `state` from a different session is
//! rejected.

use std::collections::HashMap;
use std::sync::Arc;

use time::OffsetDateTime;
use tokio::sync::Mutex;
use warpgate_common::SessionId;

use crate::api::sso_provider_detail::SsoContext;

/// How long an in-flight handshake may sit between `/start` and the IdP
/// callback before it is treated as abandoned. Generous enough for a human
/// pausing at the IdP consent screen.
const TTL_SECONDS: i64 = 600;

/// Hard cap on concurrently-tracked handshakes so a flood of `/start` calls
/// cannot grow the map without bound. On overflow the oldest entry is evicted.
const MAX_ENTRIES: usize = 8192;

struct Entry<V> {
    value: V,
    session_id: SessionId,
    created: OffsetDateTime,
}

/// Concurrency-safe store for in-flight SSO login handshakes, keyed by the
/// OAuth `state` and bound to the initiating [`SessionId`]. See the module
/// docs for why this lives outside the Poem session.
pub struct SsoRequestStore<V = SsoContext> {
    inner: Arc<Mutex<HashMap<String, Entry<V>>>>,
}

// Manual `Clone` so the store is cloneable regardless of whether `V` is:
// only the `Arc` is cloned.
impl<V> Clone for SsoRequestStore<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V> Default for SsoRequestStore<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> SsoRequestStore<V> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Stash a handshake keyed by its `state`, bound to `session_id`.
    pub async fn insert(&self, state: String, value: V, session_id: SessionId) {
        self.insert_at(OffsetDateTime::now_utc(), state, value, session_id)
            .await;
    }

    /// Consume the handshake for `state` iff it exists, is unexpired, and was
    /// initiated by `session_id`. Returns `None` otherwise.
    pub async fn take(&self, state: &str, session_id: &SessionId) -> Option<V> {
        self.take_at(OffsetDateTime::now_utc(), state, session_id)
            .await
    }

    /// Drop expired entries. Called periodically from the HTTP server's
    /// housekeeping loop.
    pub async fn vacuum(&self) {
        self.vacuum_at(OffsetDateTime::now_utc()).await;
    }

    async fn insert_at(&self, now: OffsetDateTime, state: String, value: V, session_id: SessionId) {
        let mut map = self.inner.lock().await;
        // Opportunistically drop expired entries on every insert so an
        // abandoned-flow trickle can't accumulate between vacuum ticks.
        map.retain(|_, e| (now - e.created).whole_seconds() < TTL_SECONDS);
        // Stay bounded even under a flood of `/start`s: evict the oldest.
        if map.len() >= MAX_ENTRIES
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, e)| e.created)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        map.insert(
            state,
            Entry {
                value,
                session_id,
                created: now,
            },
        );
    }

    async fn take_at(&self, now: OffsetDateTime, state: &str, session_id: &SessionId) -> Option<V> {
        let mut map = self.inner.lock().await;
        // Read the facts we need, then drop the borrow before mutating `map`.
        let (expired, session_matches) = {
            let entry = map.get(state)?;
            (
                (now - entry.created).whole_seconds() >= TTL_SECONDS,
                entry.session_id == *session_id,
            )
        };
        if expired {
            map.remove(state);
            return None;
        }
        if !session_matches {
            // A valid `state` presented by a different session: reject the
            // login-CSRF attempt, but leave the entry so the genuine initiator
            // can still complete. `state` is unguessable, so this is not a
            // probing vector.
            return None;
        }
        map.remove(state).map(|e| e.value)
    }

    async fn vacuum_at(&self, now: OffsetDateTime) {
        self.inner
            .lock()
            .await
            .retain(|_, e| (now - e.created).whole_seconds() < TTL_SECONDS);
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;
    use uuid::Uuid;

    use super::*;

    fn base_ts() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[tokio::test]
    async fn unit_two_concurrent_flows_in_same_session_are_both_retrievable() {
        // The bug: the old per-session single slot meant a second /start
        // (auto-SSO redirect, another subdomain tab, a retry) clobbered the
        // first flow's `state`, so its callback failed "Invalid SSO state
        // parameter". Keyed-by-state storage must let both flows complete.
        let store: SsoRequestStore<u32> = SsoRequestStore::new();
        let sid = Uuid::new_v4();
        let now = base_ts();

        store.insert_at(now, "state-a".into(), 1, sid).await;
        store.insert_at(now, "state-b".into(), 2, sid).await;

        assert_eq!(store.take_at(now, "state-a", &sid).await, Some(1));
        assert_eq!(store.take_at(now, "state-b", &sid).await, Some(2));
    }

    #[tokio::test]
    async fn unit_state_is_bound_to_initiating_session() {
        // Preserves the login-CSRF protection of the state check (#1891): a
        // callback presenting a valid `state` from a *different* session must
        // be rejected, and must not consume the entry so the real initiator
        // can still complete.
        let store: SsoRequestStore<u32> = SsoRequestStore::new();
        let now = base_ts();
        let initiator = Uuid::new_v4();
        let other = Uuid::new_v4();

        store.insert_at(now, "state-a".into(), 1, initiator).await;

        assert_eq!(store.take_at(now, "state-a", &other).await, None);
        assert_eq!(store.take_at(now, "state-a", &initiator).await, Some(1));
    }

    #[tokio::test]
    async fn unit_expired_handshake_is_not_returned() {
        let store: SsoRequestStore<u32> = SsoRequestStore::new();
        let sid = Uuid::new_v4();
        let now = base_ts();

        store.insert_at(now, "state-a".into(), 1, sid).await;

        let later = now + Duration::seconds(TTL_SECONDS + 1);
        assert_eq!(store.take_at(later, "state-a", &sid).await, None);
    }

    #[tokio::test]
    async fn unit_take_consumes_the_handshake() {
        let store: SsoRequestStore<u32> = SsoRequestStore::new();
        let sid = Uuid::new_v4();
        let now = base_ts();

        store.insert_at(now, "state-a".into(), 1, sid).await;

        assert_eq!(store.take_at(now, "state-a", &sid).await, Some(1));
        assert_eq!(store.take_at(now, "state-a", &sid).await, None);
    }
}

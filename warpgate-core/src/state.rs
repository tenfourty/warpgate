use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::logging::AuditEvent;
use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    db: DatabaseConnection,
    // Node IDs are random
    node_id: Uuid,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
}

impl State {
    pub fn new(
        db: &DatabaseConnection,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
        node_id: Uuid,
    ) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        Arc::new(Mutex::new(Self {
            sessions: HashMap::new(),
            db: db.clone(),
            node_id,
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
        }))
    }

    pub async fn register_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: SessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let this_copy = this.clone();
        let mut self_ = this.lock().await;
        let id = uuid::Uuid::new_v4();

        let state = Arc::new(Mutex::new(SessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        self_.sessions.insert(id, state.clone());

        {
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(state
                    .lock()
                    .await
                    .remote_address
                    .map_or_else(String::new, |x| x.to_string())),
                protocol: Set(protocol.to_string()),
                node_id: Set(self_.node_id),
                ..Default::default()
            };

            let db = &self_.db;
            values
                .insert(db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        let _ = self_.change_sender.send(());

        Ok(Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            self_.db.clone(),
            this_copy,
            state,
            self_.rate_limiter_registry.clone(),
        ))))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    /// Removes a session that never completed authentication, deleting its row
    /// rather than marking it ended — see
    /// [`WarpgateServerHandle::mark_provisional`].
    pub async fn discard_session(&mut self, id: SessionId) {
        self.sessions.remove(&id);

        if let Err(error) = Session::Entity::delete_by_id(id).exec(&self.db).await {
            error!(%error, %id, "Could not delete session from the DB");
        }

        let _ = self.change_sender.send(());
    }

    pub async fn remove_session(&mut self, id: SessionId) {
        if let Some(session_state) = self.sessions.remove(&id) {
            let state_guard = session_state.lock().await;
            if let (Some(user_info), Some(target)) = (&state_guard.user_info, &state_guard.target) {
                AuditEvent::TargetSessionEnded {
                    session_id: id,
                    target_id: target.id,
                    target_name: target.name.clone(),
                    user_id: user_info.id,
                    username: user_info.username.clone(),
                }
                .emit();
            }
        }

        if let Err(error) = crate::db::mark_session_ended(&self.db, id).await {
            error!(%error, %id, "Could not update session in the DB");
        }

        let _ = self.change_sender.send(());
    }

    /// Close all active sessions on THIS node bound to the given user.
    ///
    /// A session handle only exists on the node owning its connection, so the
    /// admin API fans the same request out to the other cluster nodes.
    pub async fn close_sessions_for_user(&self, user_id: Uuid) {
        Self::close_sessions_for_user_in(&self.sessions, user_id).await;
    }

    /// Close all active sessions on THIS node bound to the given ticket.
    ///
    /// See [`Self::close_sessions_for_user`] for the cluster caveat.
    pub async fn close_sessions_for_ticket(&self, ticket_id: Uuid) {
        Self::close_sessions_for_ticket_in(&self.sessions, ticket_id).await;
    }

    async fn close_sessions_for_user_in(
        sessions: &HashMap<SessionId, Arc<Mutex<SessionState>>>,
        user_id: Uuid,
    ) {
        for state in sessions.values() {
            let mut guard = state.lock().await;
            let matches = guard.user_info.as_ref().is_some_and(|u| u.id == user_id);
            if matches {
                guard.handle.close();
            }
        }
    }

    async fn close_sessions_for_ticket_in(
        sessions: &HashMap<SessionId, Arc<Mutex<SessionState>>>,
        ticket_id: Uuid,
    ) {
        for state in sessions.values() {
            let mut guard = state.lock().await;
            if guard.ticket_id == Some(ticket_id) {
                guard.handle.close();
            }
        }
    }

    /// Update the in-memory `ticket_id` for a session and persist it to the
    /// `sessions.ticket_id` DB column. No-op if the session is not registered.
    pub async fn set_ticket_id_for_session(
        &self,
        session_id: SessionId,
        ticket_id: Uuid,
    ) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;
        use sea_orm::{ColumnTrait, QueryFilter};

        Self::set_ticket_id_for_session_in(&self.sessions, session_id, ticket_id).await;

        Session::Entity::update_many()
            .set(Session::ActiveModel {
                ticket_id: Set(Some(ticket_id)),
                ..Default::default()
            })
            .filter(Session::Column::Id.eq(session_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// In-memory update of a session's `ticket_id`. No-op if the session is
    /// not registered. Extracted for testability (no DB dependency).
    async fn set_ticket_id_for_session_in(
        sessions: &HashMap<SessionId, Arc<Mutex<SessionState>>>,
        session_id: SessionId,
        ticket_id: Uuid,
    ) {
        if let Some(state) = sessions.get(&session_id) {
            let mut guard = state.lock().await;
            guard.ticket_id = Some(ticket_id);
            guard.emit_change();
        }
    }
}

pub struct SessionState {
    pub remote_address: Option<SocketAddr>,
    pub user_info: Option<AuthStateUserInfo>,
    pub ticket_id: Option<Uuid>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

pub struct SessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
}

impl SessionState {
    fn new(init: SessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        Self {
            remote_address: init.remote_address,
            user_info: None,
            ticket_id: None,
            target: None,
            handle: init.handle,
            change_sender,
            rate_limiter_handles: vec![],
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct TestHandle {
        close_counter: Arc<AtomicUsize>,
    }

    impl SessionHandle for TestHandle {
        fn close(&mut self) {
            self.close_counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn mk_session_state(
        user_id: Option<Uuid>,
        ticket_id: Option<Uuid>,
        close_counter: Arc<AtomicUsize>,
    ) -> Arc<Mutex<SessionState>> {
        let (tx, _rx) = broadcast::channel(2);
        Arc::new(Mutex::new(SessionState {
            remote_address: None,
            user_info: user_id.map(|id| AuthStateUserInfo {
                id,
                username: format!("user-{id}"),
            }),
            ticket_id,
            target: None,
            handle: Box::new(TestHandle { close_counter }),
            change_sender: tx,
            rate_limiter_handles: vec![],
        }))
    }

    type SessionFixture = (SessionId, Option<Uuid>, Option<Uuid>, Arc<AtomicUsize>);

    fn mk_sessions_map(
        entries: Vec<SessionFixture>,
    ) -> HashMap<SessionId, Arc<Mutex<SessionState>>> {
        let mut map = HashMap::new();
        for (sid, uid, tid, counter) in entries {
            map.insert(sid, mk_session_state(uid, tid, counter));
        }
        map
    }

    #[tokio::test]
    async fn unit_close_sessions_for_user_closes_only_matching_sessions() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let s1_close = Arc::new(AtomicUsize::new(0));
        let s2_close = Arc::new(AtomicUsize::new(0));
        let s3_close = Arc::new(AtomicUsize::new(0));
        let s4_close = Arc::new(AtomicUsize::new(0));

        let sessions = mk_sessions_map(vec![
            (Uuid::new_v4(), Some(user_a), None, s1_close.clone()),
            (Uuid::new_v4(), Some(user_a), None, s2_close.clone()),
            (Uuid::new_v4(), Some(user_b), None, s3_close.clone()),
            (Uuid::new_v4(), None, None, s4_close.clone()),
        ]);

        State::close_sessions_for_user_in(&sessions, user_a).await;

        assert_eq!(s1_close.load(Ordering::SeqCst), 1);
        assert_eq!(s2_close.load(Ordering::SeqCst), 1);
        assert_eq!(s3_close.load(Ordering::SeqCst), 0);
        assert_eq!(s4_close.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unit_close_sessions_for_ticket_closes_only_matching_sessions() {
        let ticket_a = Uuid::new_v4();
        let ticket_b = Uuid::new_v4();

        let s1_close = Arc::new(AtomicUsize::new(0));
        let s2_close = Arc::new(AtomicUsize::new(0));
        let s3_close = Arc::new(AtomicUsize::new(0));

        let sessions = mk_sessions_map(vec![
            (Uuid::new_v4(), None, Some(ticket_a), s1_close.clone()),
            (Uuid::new_v4(), None, Some(ticket_b), s2_close.clone()),
            (Uuid::new_v4(), None, None, s3_close.clone()),
        ]);

        State::close_sessions_for_ticket_in(&sessions, ticket_a).await;

        assert_eq!(s1_close.load(Ordering::SeqCst), 1);
        assert_eq!(s2_close.load(Ordering::SeqCst), 0);
        assert_eq!(s3_close.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unit_set_ticket_id_for_session_sets_matching_and_ignores_unknown() {
        let ticket_a = Uuid::new_v4();
        let ticket_b = Uuid::new_v4();

        let s1_id = Uuid::new_v4();
        let s2_id = Uuid::new_v4();
        let s1_close = Arc::new(AtomicUsize::new(0));
        let s2_close = Arc::new(AtomicUsize::new(0));

        let sessions = mk_sessions_map(vec![
            (s1_id, None, None, s1_close.clone()),
            (s2_id, None, Some(ticket_b), s2_close.clone()),
        ]);

        // Sets ticket_id on the matching session.
        State::set_ticket_id_for_session_in(&sessions, s1_id, ticket_a).await;
        assert_eq!(
            sessions.get(&s1_id).unwrap().lock().await.ticket_id,
            Some(ticket_a)
        );
        // Other session is untouched.
        assert_eq!(
            sessions.get(&s2_id).unwrap().lock().await.ticket_id,
            Some(ticket_b)
        );

        // No-op for an unknown session_id (no panic, no mutation).
        let unknown = Uuid::new_v4();
        State::set_ticket_id_for_session_in(&sessions, unknown, ticket_a).await;
        assert_eq!(
            sessions.get(&s1_id).unwrap().lock().await.ticket_id,
            Some(ticket_a)
        );
        assert_eq!(
            sessions.get(&s2_id).unwrap().lock().await.ticket_id,
            Some(ticket_b)
        );

        // Sanity: no close() calls were made.
        assert_eq!(s1_close.load(Ordering::SeqCst), 0);
        assert_eq!(s2_close.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unit_close_sessions_for_user_no_matches_is_noop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let sessions = mk_sessions_map(vec![(
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            None,
            counter.clone(),
        )]);

        State::close_sessions_for_user_in(&sessions, Uuid::new_v4()).await;

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}

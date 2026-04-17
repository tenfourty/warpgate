use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, handler};
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Func;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::SessionSnapshot;

use super::pagination::{PaginatedResponse, PaginationParams};
use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::fan_out_to_peers;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<SessionSnapshot>>),
}

#[derive(ApiResponse)]
enum CloseAllSessionsResponse {
    #[oai(status = 201)]
    Ok,
}

#[derive(ApiResponse)]
enum CloseSessionsForResponse {
    #[oai(status = 201)]
    Ok,
}

#[OpenApi]
impl Api {
    #[allow(clippy::too_many_arguments)]
    #[oai(path = "/sessions", method = "get", operation_id = "get_sessions")]
    #[allow(clippy::too_many_arguments)]
    async fn api_get_all_sessions(
        &self,
        admin: AdminContext,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        active_only: Query<Option<bool>>,
        logged_in_only: Query<Option<bool>>,
        username: Query<Option<String>>,
    ) -> poem::Result<GetSessionsResponse> {
        use warpgate_db_entities::Session;

        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;
        let mut q = Session::Entity::find().order_by_desc(Session::Column::Started);

        if active_only.unwrap_or(false) {
            q = q.filter(Session::Column::Ended.is_null());
        }
        if logged_in_only.unwrap_or(false) {
            q = q.filter(Session::Column::Username.is_not_null());
        }
        if let Some(username_filter) = username.as_ref() {
            q = q.filter(
                Expr::expr(Func::lower(Expr::col(Session::Column::Username)))
                    .eq(username_filter.to_lowercase()),
            );
        }

        Ok(GetSessionsResponse::Ok(Json(
            PaginatedResponse::new(
                q,
                PaginationParams {
                    limit: *limit,
                    offset: *offset,
                },
                db,
                Into::into,
            )
            .await?,
        )))
    }

    #[oai(
        path = "/sessions",
        method = "delete",
        operation_id = "close_all_sessions"
    )]
    async fn api_close_all_sessions(
        &self,
        admin: ClusterOrAdminContext,
        session: &Session,
        req: &poem::Request,
        /// Close only this node's own sessions instead of the whole cluster's.
        /// Set on cluster-forwarded copies of the request.
        local_only: Query<Option<bool>>,
    ) -> poem::Result<CloseAllSessionsResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        {
            let state = admin.services().state.lock().await;
            for s in state.sessions.values() {
                s.lock().await.handle.close();
            }
        }

        session.purge();

        // A session's handle lives only on the node owning its connection, so
        // the request goes out to every other node too.
        if !local_only.unwrap_or(false) {
            close_on_peers(&admin, req).await;
        }

        Ok(CloseAllSessionsResponse::Ok)
    }

    /// Close this node's live sessions belonging to a user. The cluster-wide
    /// entry point is [`close_sessions_for_user`], which calls this on each peer.
    #[oai(
        path = "/sessions/for-user/:id",
        method = "delete",
        operation_id = "close_sessions_for_user"
    )]
    async fn api_close_sessions_for_user(
        &self,
        admin: ClusterOrAdminContext,
        id: Path<Uuid>,
    ) -> poem::Result<CloseSessionsForResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        admin
            .services()
            .state
            .lock()
            .await
            .close_sessions_for_user(id.0)
            .await;

        Ok(CloseSessionsForResponse::Ok)
    }

    /// Close this node's live sessions opened with a ticket. The cluster-wide
    /// entry point is [`close_sessions_for_ticket`].
    #[oai(
        path = "/sessions/for-ticket/:id",
        method = "delete",
        operation_id = "close_sessions_for_ticket"
    )]
    async fn api_close_sessions_for_ticket(
        &self,
        admin: ClusterOrAdminContext,
        id: Path<Uuid>,
    ) -> poem::Result<CloseSessionsForResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        admin
            .services()
            .state
            .lock()
            .await
            .close_sessions_for_ticket(id.0)
            .await;

        Ok(CloseSessionsForResponse::Ok)
    }
}

/// Close every live session belonging to `user_id`, on this node and on every peer.
pub(crate) async fn close_sessions_for_user(
    ctx: &AuthenticatedRequestContext,
    req: &poem::Request,
    user_id: Uuid,
) {
    ctx.services()
        .state
        .lock()
        .await
        .close_sessions_for_user(user_id)
        .await;
    close_on_peers_at(ctx, req, &format!("sessions/for-user/{user_id}")).await;
}

/// Close every live session opened with `ticket_id`, on this node and on every peer.
pub(crate) async fn close_sessions_for_ticket(
    ctx: &AuthenticatedRequestContext,
    req: &poem::Request,
    ticket_id: Uuid,
) {
    ctx.services()
        .state
        .lock()
        .await
        .close_sessions_for_ticket(ticket_id)
        .await;
    close_on_peers_at(ctx, req, &format!("sessions/for-ticket/{ticket_id}")).await;
}

/// Ask every other node to close its share of the sessions.
///
/// Best effort, for the same reason as [`close_on_peers`]: an unreachable peer is
/// logged rather than failing the delete that triggered this.
async fn close_on_peers_at(ctx: &AuthenticatedRequestContext, req: &poem::Request, suffix: &str) {
    for (hostname, response) in
        fan_out_to_peers(ctx, req, &admin_api_sibling_path(req, suffix)).await
    {
        if response.status() != StatusCode::CREATED {
            let status = response.status();
            warn!(node = %hostname, %status, "Failed to close sessions on a cluster node");
        }
    }
}

/// `/<mount>/admin/api/users/<id>` -> `/<mount>/admin/api/<suffix>`.
///
/// The admin API is mounted under two prefixes (`/@warpgate` and `/_warpgate`),
/// so the peer path is derived from the incoming request rather than hardcoded.
/// Both callers are two-segment routes (`users/:id`, `tickets/:id`).
fn admin_api_sibling_path(req: &poem::Request, suffix: &str) -> String {
    let path = req.original_uri().path();
    let base = path.rsplitn(3, '/').last().unwrap_or_default();
    format!("{base}/{suffix}")
}

/// Forward the close-all request to every other registered cluster node.
///
/// Best effort: a node's sessions get marked ended in the database anyway, so an
/// unreachable peer is logged, not raised.
async fn close_on_peers(ctx: &AuthenticatedRequestContext, req: &poem::Request) {
    // `local_only` stops the peers from fanning out again
    let path = format!("{}?local_only=true", req.original_uri().path());

    for (hostname, response) in fan_out_to_peers(ctx, req, &path).await {
        if response.status() != StatusCode::CREATED {
            let status = response.status();
            warn!(node = %hostname, %status, "Failed to close sessions on a cluster node");
        }
    }
}

#[handler]
pub async fn api_get_sessions_changes_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;

    let mut receiver = ctx.services().state.lock().await.subscribe();

    Ok(ws
        .on_upgrade(|socket| async move {
            let (mut sink, _) = socket.split();

            while receiver.recv().await.is_ok() {
                sink.send(Message::Text("".into())).await?;
            }

            Ok::<(), anyhow::Error>(())
        })
        .into_response())
}

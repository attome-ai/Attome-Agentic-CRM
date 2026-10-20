//! The shared inbox (roadmap C8-T1): the conversations each shared mailbox
//! routed (J2-T2, `inbound_mail_message`), newest first. A conversation is
//! the record a mailbox's messages went to: a ticket, a lead, or a
//! contact's log. These routes answer only which records and how many
//! messages; the inbox reads each record through the generic entity API,
//! so a record the agent may not read never shows.
//!
//! Both routes need `service_ticket.read`, the desk's own privilege.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `service_ticket.read`: who works the desk.
#[derive(Debug)]
pub struct TicketRead;

impl PrivilegeKey for TicketRead {
    const KEY: &'static str = "service_ticket.read";
}

/// The most mailboxes the inbox lists.
pub const MAX_MAILBOXES: i64 = 200;

/// One shared mailbox.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct InboxMailbox {
    pub id: Uuid,
    pub name: String,
}

/// One conversation: the record a mailbox's messages were routed to.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct InboxConversation {
    /// `service_ticket`, `lead` or `contact`.
    pub entity_name: String,
    pub record_id: Uuid,
    /// Messages routed to it from this mailbox.
    pub messages: i64,
    pub last_message_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/api/v1/service/inbox/mailboxes",
    operation_id = "list_service_inbox_mailboxes",
    tag = "service",
    responses(
        (status = 200, description = "The active shared mailboxes, by name", body = PaginatedResponse<InboxMailbox>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// List the shared mailboxes.
///
/// The active shared mailboxes (mailbox integration systems), by name, all
/// on one page.
async fn get_mailboxes(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TicketRead>>,
) -> Result<Json<PaginatedResponse<InboxMailbox>>, AppError> {
    let items: Vec<InboxMailbox> = sqlx::query_as(
        "SELECT id, COALESCE(name, id::text) AS name FROM integration_system \
          WHERE kind = 'mailbox' AND status = 'active' AND is_active IS NOT FALSE \
          ORDER BY name LIMIT $1",
    )
    .bind(MAX_MAILBOXES)
    .fetch_all(&state.base.db_readonly)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, MAX_MAILBOXES)))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InboxQuery {
    /// The shared mailbox (integration system id).
    pub mailbox: Uuid,
    /// One-based page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Conversations per page.
    pub page_size: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/service/inbox",
    operation_id = "list_service_inbox",
    tag = "service",
    params(InboxQuery),
    responses(
        (status = 200, description = "The mailbox's conversations, latest message first", body = PaginatedResponse<InboxConversation>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// List a shared mailbox's conversations.
///
/// Each record the mailbox's messages were routed to, with the message
/// count and the latest message's time, latest first.
async fn get_inbox(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TicketRead>>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<PaginatedResponse<InboxConversation>>, AppError> {
    let window = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let db = &state.base.db_readonly;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT DISTINCT entity_name, record_id FROM inbound_mail_message \
          WHERE system_id = $1 AND outcome = 'routed' AND record_id IS NOT NULL) c",
    )
    .bind(q.mailbox)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<InboxConversation> = sqlx::query_as(
        "SELECT entity_name, record_id, COUNT(*) AS messages, max(routed_at) AS last_message_at \
           FROM inbound_mail_message \
          WHERE system_id = $1 AND outcome = 'routed' AND record_id IS NOT NULL \
          GROUP BY entity_name, record_id \
          ORDER BY last_message_at DESC, record_id LIMIT $2 OFFSET $3",
    )
    .bind(q.mailbox)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service/inbox", get(get_inbox))
        .route("/api/v1/service/inbox/mailboxes", get(get_mailboxes))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_inbox, get_mailboxes),
    components(schemas(InboxConversation, InboxMailbox))
)]
pub(crate) struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

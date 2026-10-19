//! Chat channels, members and messages (roadmap C9-T1).
//!
//! **Access.** Every route takes the signed-in person from the session.
//! Membership is the gate: a channel the caller is not in reads as 404, its
//! messages included. A record channel also needs each member to be able to
//! read its record, checked when the channel is made and when someone joins.
//! An attached file must be an `attome_document` the poster may read.
//!
//! **Channels.** `direct` is one per pair of people (asking again returns the
//! same channel); `group` is named and open to members adding others;
//! `record` is a group about one record. The creator of a group or record
//! channel is its owner, who may remove others and set the retention period;
//! anyone may leave a group or record channel.
//!
//! **Messages.** A message may answer a top-level message (one level of
//! thread). Deleting one blanks its text unless a legal hold covers the
//! channel (then only the flag is set, and the text stays for the hold).
//!
//! **Audit.** Channel creation, membership, retention and every message are
//! business events in the transaction that writes them; marking a channel
//! read is the caller's own state and is not audited.

use attome_audit::security::{ExemptReason, x_audit, x_audit_exempt};
use attome_audit::{AuditCategory, AuditOperation, BusinessEvent};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Most members a channel is created with.
pub const MAX_MEMBERS: usize = 200;
/// Longest message.
pub const MAX_BODY_CHARS: usize = 8000;
const MAX_NAME_CHARS: usize = 200;
const MAX_RETENTION_DAYS: i32 = 3650;
const DEFAULT_MESSAGE_PAGE: i64 = 50;
const MAX_MESSAGE_PAGE: i64 = 200;
/// The document entity a message may attach.
const FILE_ENTITY: &str = "attome_document";

// ── Wire types ──────────────────────────────────────────────────────────────

/// `POST /api/v1/chat/channels`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewChannel {
    /// `direct`, `group` or `record`.
    pub kind: String,
    /// Required for a group; optional for a record channel.
    #[serde(default)]
    pub name: Option<String>,
    /// The other people: exactly one for `direct`.
    #[serde(default)]
    pub members: Vec<Uuid>,
    /// A record channel's record.
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub record_id: Option<Uuid>,
}

/// A channel as its member sees it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ChannelRow {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub entity_name: Option<String>,
    pub record_id: Option<Uuid>,
    pub retention_days: Option<i32>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    /// The caller's role: `owner` or `member`.
    pub role: String,
    pub members: Vec<Uuid>,
    pub last_message_at: Option<DateTime<Utc>>,
    /// Messages from others since the caller last marked the channel read.
    pub unread: i64,
}

/// `POST /api/v1/chat/channels/{id}/members`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddMember {
    pub user_id: Uuid,
}

/// `PUT /api/v1/chat/channels/{id}/retention`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRetention {
    /// Days messages are kept, 1 to 3650; none keeps them.
    pub days: Option<i32>,
}

/// `POST /api/v1/chat/channels/{id}/messages`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewMessage {
    pub body: String,
    /// The top-level message this answers.
    #[serde(default)]
    pub thread_root_id: Option<Uuid>,
    /// An `attome_document` the poster may read.
    #[serde(default)]
    pub file_id: Option<Uuid>,
}

/// One message.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct MessageRow {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub thread_root_id: Option<Uuid>,
    pub author_id: Uuid,
    /// Empty once deleted.
    pub body: String,
    pub file_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub deleted: bool,
    /// Replies to a top-level message.
    pub reply_count: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MessageQuery {
    /// The `next_cursor` of the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Messages per page, 1 to 200 (default 50).
    #[serde(default)]
    pub page_size: Option<i64>,
    /// A top-level message: list it and its replies, oldest first.
    #[serde(default)]
    pub thread: Option<Uuid>,
}

// ── Pure checks ─────────────────────────────────────────────────────────────

/// The two members of a direct channel as one key, whichever asked. Pure.
pub fn direct_key(a: Uuid, b: Uuid) -> String {
    if a <= b {
        format!("{a}:{b}")
    } else {
        format!("{b}:{a}")
    }
}

/// A checked channel request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedChannel {
    pub kind: String,
    pub name: Option<String>,
    /// The others, distinct, without the creator.
    pub members: Vec<Uuid>,
    pub record: Option<(String, Uuid)>,
}

/// Checks a channel request against the rules for its kind. Pure.
pub fn check_channel(body: &NewChannel, creator: Uuid) -> Result<CheckedChannel, AppError> {
    let mut members: Vec<Uuid> = Vec::new();
    for m in &body.members {
        if *m != creator && !m.is_nil() && !members.contains(m) {
            members.push(*m);
        }
    }
    if members.len() > MAX_MEMBERS {
        return Err(AppError::Validation(format!(
            "members: at most {MAX_MEMBERS}"
        )));
    }
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned);
    if name
        .as_deref()
        .is_some_and(|n| n.chars().count() > MAX_NAME_CHARS)
    {
        return Err(AppError::Validation(format!(
            "name: at most {MAX_NAME_CHARS} characters"
        )));
    }
    let record = match (body.entity.as_deref().map(str::trim), body.record_id) {
        (Some(e), Some(r)) if !e.is_empty() => Some((e.to_owned(), r)),
        _ => None,
    };
    match body.kind.as_str() {
        "direct" => {
            if members.len() != 1 {
                return Err(AppError::Validation(
                    "members: a direct channel names exactly one other person".into(),
                ));
            }
            Ok(CheckedChannel {
                kind: "direct".into(),
                name: None,
                members,
                record: None,
            })
        }
        "group" => {
            let name = name.ok_or_else(|| AppError::Validation("name: required".into()))?;
            Ok(CheckedChannel {
                kind: "group".into(),
                name: Some(name),
                members,
                record: None,
            })
        }
        "record" => {
            let record = record.ok_or_else(|| {
                AppError::Validation("entity and record_id: required for a record channel".into())
            })?;
            Ok(CheckedChannel {
                kind: "record".into(),
                name,
                members,
                record: Some(record),
            })
        }
        _ => Err(AppError::Validation(
            "kind: must be direct, group or record".into(),
        )),
    }
}

/// A message body, trimmed and within bounds. Pure.
pub fn check_body(body: &str) -> Result<&str, AppError> {
    let body = body.trim();
    if body.is_empty() || body.chars().count() > MAX_BODY_CHARS {
        return Err(AppError::Validation(format!(
            "body: 1 to {MAX_BODY_CHARS} characters"
        )));
    }
    Ok(body)
}

/// A retention period within bounds. Pure.
pub fn check_retention(days: Option<i32>) -> Result<Option<i32>, AppError> {
    match days {
        Some(d) if !(1..=MAX_RETENTION_DAYS).contains(&d) => Err(AppError::Validation(format!(
            "days: 1 to {MAX_RETENTION_DAYS}, or none to keep messages"
        ))),
        other => Ok(other),
    }
}

/// `base64url("{micros}:{uuid}")`.
pub fn encode_cursor(at: DateTime<Utc>, id: Uuid) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{}:{id}", at.timestamp_micros()))
}

pub fn decode_cursor(raw: &str) -> Result<(DateTime<Utc>, Uuid), AppError> {
    let invalid = || AppError::Validation("malformed cursor".into());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    let (micros, id) = text.split_once(':').ok_or_else(invalid)?;
    let at = micros
        .parse::<i64>()
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .ok_or_else(invalid)?;
    let id = Uuid::parse_str(id).map_err(|_| invalid())?;
    Ok((at, id))
}

// ── Shared reads ────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct Membership {
    kind: String,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    role: String,
}

/// The caller's membership of a live channel; anything else is 404.
async fn membership(
    state: &EngineState,
    channel: Uuid,
    user: Uuid,
) -> Result<Membership, AppError> {
    sqlx::query_as(
        "SELECT c.kind, c.entity_name, c.record_id, m.role \
           FROM chat_channel c JOIN chat_member m ON m.channel_id = c.id \
          WHERE c.id = $1 AND m.user_id = $2 AND c.archived_at IS NULL",
    )
    .bind(channel)
    .bind(user)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Whether `user` (resolved afresh) may read the record.
async fn user_can_read(
    state: &EngineState,
    user: Uuid,
    entity: &str,
    record: Uuid,
) -> Result<bool, AppError> {
    let Ok(ctx) = state.base.security.resolve_strict(user).await else {
        return Ok(false);
    };
    can_read(state, &ctx, entity, record).await
}

async fn can_read(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record: Uuid,
) -> Result<bool, AppError> {
    let Some(entity_id) = state.entities.load().get(entity).map(|m| m.entity_id) else {
        return Ok(false);
    };
    match attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity_id,
        entity,
        record,
        RecordAction::Read,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(AppError::NotFound | AppError::Forbidden) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Active people among `users`.
async fn active_users(state: &EngineState, users: &[Uuid]) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar("SELECT id FROM user_account WHERE id = ANY($1) AND is_active")
        .bind(users)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

fn event(entity: &str, id: Uuid, op: AuditOperation, name: &str, actor: Uuid) -> BusinessEvent {
    BusinessEvent::new(entity, id, op, name, actor)
}

async fn audit_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    event: BusinessEvent,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(tx, &attome_audit::audit_service(state), event)
        .await
        .map(|_| ())
}

async fn channel_row(
    state: &EngineState,
    channel: Uuid,
    user: Uuid,
) -> Result<ChannelRow, AppError> {
    sqlx::query_as(&format!(
        "{CHANNEL_SELECT} WHERE m.user_id = $1 AND c.id = $2"
    ))
    .bind(user)
    .bind(channel)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

const CHANNEL_SELECT: &str = "SELECT c.id, c.kind, c.name, c.entity_name, c.record_id, \
        c.retention_days, c.created_by, c.created_at, m.role, \
        ARRAY(SELECT x.user_id FROM chat_member x WHERE x.channel_id = c.id ORDER BY x.joined_at) \
            AS members, \
        (SELECT max(g.created_at) FROM chat_message g \
          WHERE g.channel_id = c.id AND g.deleted_at IS NULL) AS last_message_at, \
        (SELECT count(*) FROM chat_message u \
          WHERE u.channel_id = c.id AND u.deleted_at IS NULL AND u.author_id <> $1 \
            AND u.created_at > coalesce(m.last_read_at, '-infinity'::timestamptz)) AS unread \
   FROM chat_member m JOIN chat_channel c ON c.id = m.channel_id AND c.archived_at IS NULL";

// ── Channels ────────────────────────────────────────────────────────────────

/// Creates a channel (or, for a direct pair that already has one, returns
/// it).
pub async fn create_channel(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &NewChannel,
) -> Result<(StatusCode, ChannelRow), AppError> {
    let checked = check_channel(body, ctx.user_id)?;
    let active = active_users(state, &checked.members).await?;
    if let Some(missing) = checked.members.iter().find(|m| !active.contains(m)) {
        return Err(AppError::Validation(format!(
            "members: {missing} is not an active user"
        )));
    }
    if let Some((entity, record)) = &checked.record {
        if !can_read(state, ctx, entity, *record).await? {
            return Err(AppError::NotFound);
        }
        for member in &checked.members {
            if !user_can_read(state, *member, entity, *record).await? {
                return Err(AppError::Validation(format!(
                    "members: {member} cannot read this record"
                )));
            }
        }
    }
    let key = (checked.kind == "direct").then(|| direct_key(ctx.user_id, checked.members[0]));
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO chat_channel (kind, name, direct_key, entity_name, record_id, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (direct_key) WHERE kind = 'direct' DO NOTHING RETURNING id",
    )
    .bind(&checked.kind)
    .bind(&checked.name)
    .bind(&key)
    .bind(checked.record.as_ref().map(|r| r.0.as_str()))
    .bind(checked.record.as_ref().map(|r| r.1))
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = created else {
        // The pair already has its direct channel.
        drop(tx);
        let existing: Uuid = sqlx::query_scalar(
            "SELECT id FROM chat_channel WHERE kind = 'direct' AND direct_key = $1",
        )
        .bind(&key)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        return Ok((
            StatusCode::OK,
            channel_row(state, existing, ctx.user_id).await?,
        ));
    };
    let owner_role = if checked.kind == "direct" {
        "member"
    } else {
        "owner"
    };
    sqlx::query("INSERT INTO chat_member (channel_id, user_id, role) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(ctx.user_id)
        .bind(owner_role)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO chat_member (channel_id, user_id) SELECT $1, unnest($2::uuid[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(&checked.members)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit_in_tx(
        &mut tx,
        state,
        event(
            "chat_channel",
            id,
            AuditOperation::Create,
            "chat.channel_created",
            ctx.user_id,
        )
        .comment(format!(
            "{} channel with {} other member(s)",
            checked.kind,
            checked.members.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        channel_row(state, id, ctx.user_id).await?,
    ))
}

/// Starts a direct, group or record channel.
#[utoipa::path(
    post,
    path = "/api/v1/chat/channels",
    tag = "chat",
    request_body = NewChannel,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = ChannelRow),
        (status = 200, description = "The pair's existing direct channel", body = ChannelRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The record is not one the caller may read", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_channel(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<NewChannel>,
) -> Result<(StatusCode, Json<ChannelRow>), AppError> {
    let (status, row) = create_channel(&state, &ctx, &body).await?;
    Ok((status, Json(row)))
}

/// The caller's channels, most recently active first.
#[utoipa::path(
    get,
    path = "/api/v1/chat/channels",
    tag = "chat",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ChannelRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_channels(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ChannelRow>>, AppError> {
    let window = query.window();
    let items: Vec<ChannelRow> = sqlx::query_as(&format!(
        "{CHANNEL_SELECT} WHERE m.user_id = $1 \
         ORDER BY last_message_at DESC NULLS LAST, c.created_at DESC, c.id \
         LIMIT $2 OFFSET $3"
    ))
    .bind(ctx.user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat_member m JOIN chat_channel c ON c.id = m.channel_id \
          WHERE m.user_id = $1 AND c.archived_at IS NULL",
    )
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Adds someone to a group or record channel; any member may.
#[utoipa::path(
    post,
    path = "/api/v1/chat/channels/{id}/members",
    tag = "chat",
    params(("id" = Uuid, Path)),
    request_body = AddMember,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Added, or already a member"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such channel of the caller's", body = ErrorResponse),
        (status = 422, description = "A direct channel, an inactive user, or one who cannot read the record", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn add_member(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(channel): Path<Uuid>,
    Json(body): Json<AddMember>,
) -> Result<StatusCode, AppError> {
    let me = membership(&state, channel, ctx.user_id).await?;
    if me.kind == "direct" {
        return Err(AppError::Validation(
            "a direct channel has exactly its two people; start a group instead".into(),
        ));
    }
    if active_users(&state, &[body.user_id]).await?.is_empty() {
        return Err(AppError::Validation("user_id: not an active user".into()));
    }
    if let (Some(entity), Some(record)) = (me.entity_name.as_deref(), me.record_id) {
        if !user_can_read(&state, body.user_id, entity, record).await? {
            return Err(AppError::Validation(
                "user_id: cannot read this channel's record".into(),
            ));
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let added = sqlx::query(
        "INSERT INTO chat_member (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(channel)
    .bind(body.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if added == 0 {
        return Ok(StatusCode::NO_CONTENT);
    }
    audit_in_tx(
        &mut tx,
        &state,
        event(
            "chat_channel",
            channel,
            AuditOperation::Update,
            "chat.member_added",
            ctx.user_id,
        )
        .comment(format!("added {}", body.user_id)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Leaves a channel, or (its owner) removes someone from it.
#[utoipa::path(
    delete,
    path = "/api/v1/chat/channels/{id}/members/{user_id}",
    tag = "chat",
    params(("id" = Uuid, Path), ("user_id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Only the owner removes others", body = ErrorResponse),
        (status = 404, description = "No such channel or member", body = ErrorResponse),
        (status = 422, description = "A direct channel cannot be left", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn remove_member(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((channel, user)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let me = membership(&state, channel, ctx.user_id).await?;
    if me.kind == "direct" {
        return Err(AppError::Validation(
            "a direct channel cannot be left".into(),
        ));
    }
    if user != ctx.user_id && me.role != "owner" {
        return Err(AppError::Forbidden);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed = sqlx::query("DELETE FROM chat_member WHERE channel_id = $1 AND user_id = $2")
        .bind(channel)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    audit_in_tx(
        &mut tx,
        &state,
        event(
            "chat_channel",
            channel,
            AuditOperation::Update,
            "chat.member_removed",
            ctx.user_id,
        )
        .comment(format!("removed {user}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets how long the channel keeps messages (its owner only).
#[utoipa::path(
    put,
    path = "/api/v1/chat/channels/{id}/retention",
    tag = "chat",
    params(("id" = Uuid, Path)),
    request_body = SetRetention,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Set"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Only the owner sets retention", body = ErrorResponse),
        (status = 404, description = "No such channel of the caller's", body = ErrorResponse),
        (status = 422, description = "Days out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn set_retention(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(channel): Path<Uuid>,
    Json(body): Json<SetRetention>,
) -> Result<StatusCode, AppError> {
    let days = check_retention(body.days)?;
    let me = membership(&state, channel, ctx.user_id).await?;
    if me.role != "owner" && !ctx.is_admin {
        return Err(AppError::Forbidden);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE chat_channel SET retention_days = $2, row_version = row_version + 1 WHERE id = $1",
    )
    .bind(channel)
    .bind(days)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit_in_tx(
        &mut tx,
        &state,
        event(
            "chat_channel",
            channel,
            AuditOperation::Update,
            "chat.retention_set",
            ctx.user_id,
        )
        .comment(match days {
            Some(d) => format!("messages kept {d} days"),
            None => "messages kept".to_owned(),
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Messages ────────────────────────────────────────────────────────────────

const MESSAGE_SELECT: &str = "SELECT g.id, g.channel_id, g.thread_root_id, g.author_id, \
        CASE WHEN g.deleted_at IS NULL THEN g.body ELSE '' END AS body, \
        CASE WHEN g.deleted_at IS NULL THEN g.file_id END AS file_id, \
        g.created_at, g.deleted_at IS NOT NULL AS deleted, \
        (SELECT count(*) FROM chat_message r \
          WHERE r.thread_root_id = g.id AND r.deleted_at IS NULL) AS reply_count \
   FROM chat_message g";

/// A channel's messages: top-level ones newest first, or one thread oldest
/// first.
#[utoipa::path(
    get,
    path = "/api/v1/chat/channels/{id}/messages",
    tag = "chat",
    params(("id" = Uuid, Path), MessageQuery),
    responses(
        (status = 200, description = "Success", body = CursorPage<MessageRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such channel of the caller's", body = ErrorResponse),
        (status = 422, description = "Malformed cursor", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_messages(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(channel): Path<Uuid>,
    Query(query): Query<MessageQuery>,
) -> Result<Json<CursorPage<MessageRow>>, AppError> {
    membership(&state, channel, ctx.user_id).await?;
    let limit = query
        .page_size
        .unwrap_or(DEFAULT_MESSAGE_PAGE)
        .clamp(1, MAX_MESSAGE_PAGE);
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let (at, after) = cursor.map_or((None, None), |(t, i)| (Some(t), Some(i)));
    let mut rows: Vec<MessageRow> = match query.thread {
        // A thread reads forward from its root.
        Some(root) => sqlx::query_as(&format!(
            "{MESSAGE_SELECT} WHERE g.channel_id = $1 AND (g.id = $2 OR g.thread_root_id = $2) \
               AND ($3::timestamptz IS NULL OR (g.created_at, g.id) > ($3, $4)) \
             ORDER BY g.created_at, g.id LIMIT $5"
        ))
        .bind(channel)
        .bind(root)
        .bind(at)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        None => sqlx::query_as(&format!(
            "{MESSAGE_SELECT} WHERE g.channel_id = $1 AND g.thread_root_id IS NULL \
               AND ($2::timestamptz IS NULL OR (g.created_at, g.id) < ($2, $3)) \
             ORDER BY g.created_at DESC, g.id DESC LIMIT $4"
        ))
        .bind(channel)
        .bind(at)
        .bind(after)
        .bind(limit + 1)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?,
    };
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let next = (rows.len() > limit)
        .then(|| {
            rows.get(limit - 1)
                .map(|m| encode_cursor(m.created_at, m.id))
        })
        .flatten();
    rows.truncate(limit);
    Ok(Json(CursorPage::new(rows, next)))
}

/// Posts a message, optionally in a thread and with a document.
#[utoipa::path(
    post,
    path = "/api/v1/chat/channels/{id}/messages",
    tag = "chat",
    params(("id" = Uuid, Path)),
    request_body = NewMessage,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Posted", body = MessageRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such channel of the caller's", body = ErrorResponse),
        (status = 422, description = "Empty or long body, a thread root that is not a top-level message here, or a file the caller cannot read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_message(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(channel): Path<Uuid>,
    Json(body): Json<NewMessage>,
) -> Result<(StatusCode, Json<MessageRow>), AppError> {
    membership(&state, channel, ctx.user_id).await?;
    let text = check_body(&body.body)?;
    if let Some(root) = body.thread_root_id {
        let top_level: Option<bool> = sqlx::query_scalar(
            "SELECT thread_root_id IS NULL FROM chat_message \
              WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL",
        )
        .bind(root)
        .bind(channel)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if top_level != Some(true) {
            return Err(AppError::Validation(
                "thread_root_id: not a top-level message in this channel".into(),
            ));
        }
    }
    if let Some(file) = body.file_id {
        if !can_read(&state, &ctx, FILE_ENTITY, file).await? {
            return Err(AppError::Validation(
                "file_id: not a document you may read".into(),
            ));
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO chat_message (channel_id, thread_root_id, author_id, body, file_id) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(channel)
    .bind(body.thread_root_id)
    .bind(ctx.user_id)
    .bind(text)
    .bind(body.file_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit_in_tx(
        &mut tx,
        &state,
        event(
            "chat_message",
            id,
            AuditOperation::Create,
            "chat.message_posted",
            ctx.user_id,
        )
        .comment(format!("in channel {channel}")),
    )
    .await?;
    let row: MessageRow = sqlx::query_as(&format!("{MESSAGE_SELECT} WHERE g.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Deletes a message: its author or the channel's owner. Under a legal hold
/// the text is kept for the hold and only hidden.
#[utoipa::path(
    delete,
    path = "/api/v1/chat/channels/{id}/messages/{message_id}",
    tag = "chat",
    params(("id" = Uuid, Path), ("message_id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Delete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Neither the author nor the owner", body = ErrorResponse),
        (status = 404, description = "No such message in a channel of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn delete_message(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((channel, message)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let me = membership(&state, channel, ctx.user_id).await?;
    let author: Uuid = sqlx::query_scalar(
        "SELECT author_id FROM chat_message \
          WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL",
    )
    .bind(message)
    .bind(channel)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if author != ctx.user_id && me.role != "owner" {
        return Err(AppError::Forbidden);
    }
    let held = crate::retention::channel_held(&state, channel).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE chat_message \
            SET deleted_at = now(), \
                body = CASE WHEN $3 THEN body ELSE '' END, \
                file_id = CASE WHEN $3 THEN file_id END \
          WHERE id = $1 AND channel_id = $2 AND deleted_at IS NULL",
    )
    .bind(message)
    .bind(channel)
    .bind(held)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit_in_tx(
        &mut tx,
        &state,
        event(
            "chat_message",
            message,
            AuditOperation::Delete,
            "chat.message_deleted",
            ctx.user_id,
        )
        .comment(if held {
            "hidden; text kept under a legal hold".to_owned()
        } else {
            "text removed".to_owned()
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Marks the channel read up to now.
#[utoipa::path(
    post,
    path = "/api/v1/chat/channels/{id}/read",
    tag = "chat",
    params(("id" = Uuid, Path)),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::UserPreference,
        None,
        "the caller's own read marker"
    )))),
    responses(
        (status = 204, description = "Marked"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such channel of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn mark_read(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(channel): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let marked = sqlx::query(
        "UPDATE chat_member SET last_read_at = now() WHERE channel_id = $1 AND user_id = $2",
    )
    .bind(channel)
    .bind(ctx.user_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if marked == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/chat/channels",
            post(post_channel).get(list_channels),
        )
        .route("/api/v1/chat/channels/{id}/members", post(add_member))
        .route(
            "/api/v1/chat/channels/{id}/members/{user_id}",
            delete(remove_member),
        )
        .route("/api/v1/chat/channels/{id}/retention", put(set_retention))
        .route(
            "/api/v1/chat/channels/{id}/messages",
            get(list_messages).post(post_message),
        )
        .route(
            "/api/v1/chat/channels/{id}/messages/{message_id}",
            delete(delete_message),
        )
        .route("/api/v1/chat/channels/{id}/read", post(mark_read))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    post_channel,
    list_channels,
    add_member,
    remove_member,
    set_retention,
    list_messages,
    post_message,
    delete_message,
    mark_read
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod channels {
    use super::*;

    fn req(kind: &str, members: &[u128], name: Option<&str>) -> NewChannel {
        NewChannel {
            kind: kind.into(),
            name: name.map(Into::into),
            members: members.iter().map(|m| Uuid::from_u128(*m)).collect(),
            entity: None,
            record_id: None,
        }
    }

    #[test]
    fn channels_direct_is_one_per_pair() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert_eq!(direct_key(a, b), direct_key(b, a));
        let me = Uuid::from_u128(9);
        let ok = check_channel(&req("direct", &[2, 2, 9], None), me).unwrap();
        assert_eq!(ok.members, vec![b]);
        assert!(check_channel(&req("direct", &[1, 2], None), me).is_err());
        assert!(check_channel(&req("direct", &[9], None), me).is_err());
    }

    #[test]
    fn channels_group_and_record_need_their_fields() {
        let me = Uuid::from_u128(9);
        assert!(check_channel(&req("group", &[1], None), me).is_err());
        let g = check_channel(&req("group", &[1], Some("  Ops  ")), me).unwrap();
        assert_eq!(g.name.as_deref(), Some("Ops"));
        assert!(check_channel(&req("record", &[1], None), me).is_err());
        let mut r = req("record", &[1], None);
        r.entity = Some("account".into());
        r.record_id = Some(Uuid::from_u128(5));
        let r = check_channel(&r, me).unwrap();
        assert_eq!(r.record, Some(("account".to_owned(), Uuid::from_u128(5))));
        assert!(check_channel(&req("broadcast", &[], Some("x")), me).is_err());
        let many: Vec<u128> = (100..=(100 + MAX_MEMBERS as u128)).collect();
        assert!(check_channel(&req("group", &many, Some("big")), me).is_err());
    }

    #[test]
    fn channels_bodies_retention_and_cursors_are_checked() {
        assert_eq!(check_body("  hi  ").unwrap(), "hi");
        assert!(check_body("   ").is_err());
        assert!(check_body(&"x".repeat(MAX_BODY_CHARS + 1)).is_err());
        assert_eq!(check_retention(None).unwrap(), None);
        assert_eq!(check_retention(Some(30)).unwrap(), Some(30));
        assert!(check_retention(Some(0)).is_err());
        assert!(check_retention(Some(MAX_RETENTION_DAYS + 1)).is_err());
        let at = DateTime::<Utc>::from_timestamp_micros(1_700_000_000_123_456).unwrap();
        let id = Uuid::from_u128(77);
        assert_eq!(decode_cursor(&encode_cursor(at, id)).unwrap(), (at, id));
        assert!(decode_cursor("nope").is_err());
    }
}

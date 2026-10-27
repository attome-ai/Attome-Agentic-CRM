//! L7-T3: change-stream subscriptions for integration identities.
//!
//! An administrator subscribes a registered S2S client (S11) to entities
//! (`change_stream_subscription`, migration 0223): which entities, which
//! operations, which changed attributes, an optional rule condition over the
//! record (the V2 rule text the approval processes use), how much each event
//! carries (`id`, `changes` or `record`), and whether personal attributes
//! may be shown. The client then reads the stream as its service user, in
//! commit order with its own cursor:
//!
//! - `GET /api/v1/change-stream/{subscription}/events?cursor=&limit=` answers
//!   up to `limit` (at most 1000) events after the cursor and the cursor to
//!   resume from; without a cursor it starts now;
//! - `GET /api/v1/change-stream/{subscription}/sse?cursor=` sends the same
//!   events as server-sent events, polling the feed every two seconds, a
//!   page of at most 100 at a time, for up to fifteen minutes per
//!   connection (the client reconnects with the last event's id as cursor).
//!
//! Only the subscription's identity reads it (anyone else gets 404). Every
//! event goes through that identity's permissions: an entity it may not read
//! is skipped, a record it may not read now is skipped, and with `changes`
//! or `record` only the attributes its field security shows are listed.
//! Sensitive attributes are never shown, and personal ones only with
//! `allow_personal`. A delete is sent with ids only. A cursor whose events
//! were pruned from the feed, or a subscription that is inactive or past
//! `expires_at`, answers `410` with `resync_needed`: the client reloads and
//! starts from now. Reads are not audited; subscription changes are
//! Configuration events.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::change_feed::{CursorPosition, horizon};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The most events one read answers.
pub const MAX_LIMIT: i64 = 1000;
const DEFAULT_LIMIT: i64 = 100;
/// Feed rows scanned per read, at most, as a multiple of `limit`.
const SCAN_FACTOR: i64 = 5;
const SSE_PAGE: i64 = 100;
const SSE_POLL: Duration = Duration::from_secs(2);
const SSE_LIFETIME: Duration = Duration::from_secs(15 * 60);
const PAYLOADS: &[&str] = &["id", "changes", "record"];
const OPERATIONS: &[&str] = &[
    "create", "update", "delete", "restore", "merge", "purge", "schema",
];

// ── Subscriptions ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
#[schema(as = ChangeStreamSubscription)]
pub struct Subscription {
    pub id: Uuid,
    pub name: String,
    /// The S2S client (`s2s_client.id`) that reads it.
    pub client_ref: Uuid,
    /// The client's service user, as whom every event is filtered.
    pub service_user_ref: Uuid,
    pub entities: Vec<String>,
    pub operations: Option<Vec<String>>,
    pub changed_attributes: Option<Vec<String>>,
    pub condition: Option<String>,
    /// `id`, `changes` or `record`.
    pub payload: String,
    pub allow_personal: bool,
    pub is_active: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, client_ref, service_user_ref, entities, operations, \
                       changed_attributes, condition, payload, allow_personal, is_active, \
                       expires_at, row_version, created_at";

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubscriptionBody {
    pub name: String,
    pub client_ref: Uuid,
    pub entities: Vec<String>,
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub changed_attributes: Option<Vec<String>>,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default = "default_payload")]
    pub payload: String,
    #[serde(default)]
    pub allow_personal: bool,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_payload() -> String {
    "id".into()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubscriptionPatch {
    pub row_version: i64,
    pub name: Option<String>,
    pub entities: Option<Vec<String>>,
    pub operations: Option<Vec<String>>,
    pub changed_attributes: Option<Vec<String>>,
    pub condition: Option<String>,
    pub payload: Option<String>,
    pub allow_personal: Option<bool>,
    pub is_active: Option<bool>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RowVersionQuery {
    /// The subscription's current `row_version`.
    pub row_version: i64,
}

/// What a subscription's settings must be.
fn check(
    state: &EngineState,
    name: &str,
    entities: &[String],
    operations: Option<&[String]>,
    payload: &str,
    condition: Option<&str>,
) -> Result<(), AppError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(AppError::Validation("name is 1 to 200 characters".into()));
    }
    if entities.is_empty() || entities.len() > 50 {
        return Err(AppError::Validation(
            "a subscription names 1 to 50 entities".into(),
        ));
    }
    let registry = state.entities.load();
    if let Some(unknown) = entities.iter().find(|e| registry.get(e).is_none()) {
        return Err(AppError::Validation(format!(
            "{unknown:?} is not an entity"
        )));
    }
    if let Some(op) = operations
        .into_iter()
        .flatten()
        .find(|o| !OPERATIONS.contains(&o.as_str()))
    {
        return Err(AppError::Validation(format!(
            "{op:?} is not an operation (create, update, delete, restore, merge, purge, schema)"
        )));
    }
    if !PAYLOADS.contains(&payload) {
        return Err(AppError::Validation(
            "payload is id, changes or record".into(),
        ));
    }
    if let Some(condition) = condition
        && attome_rules::parse(condition).is_err()
    {
        return Err(AppError::Validation("condition does not parse".into()));
    }
    Ok(())
}

async fn client_service_user(state: &EngineState, client: Uuid) -> Result<Uuid, AppError> {
    let row: Option<(String, Option<Uuid>)> =
        sqlx::query_as("SELECT status, service_user_ref FROM s2s_client WHERE id = $1")
            .bind(client)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match row {
        Some((status, Some(user))) if status == "active" => Ok(user),
        Some(_) => Err(AppError::Validation(
            "the client is not active or has no service user".into(),
        )),
        None => Err(AppError::Validation("no such S2S client".into())),
    }
}

async fn load(state: &EngineState, id: Uuid) -> Result<Subscription, AppError> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM change_stream_subscription WHERE id = $1 AND NOT is_deleted"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn audit(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    actor: Uuid,
    operation: AuditOperation,
    id: Uuid,
    name: &'static str,
) -> Result<(), AppError> {
    write_security_event(
        tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            "change_stream_subscription",
            Some(id),
        )
        .named(name),
    )
    .await
    .map(|_| ())
}

/// List change-stream subscriptions
///
/// Lists change-stream subscriptions.
#[utoipa::path(
    get,
    path = "/api/v1/change-stream/subscriptions",
    operation_id = "change_stream_list_subscriptions",
    tag = "integration",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<Subscription>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_subscriptions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<Subscription>>, AppError> {
    let items: Vec<Subscription> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM change_stream_subscription WHERE NOT is_deleted \
          ORDER BY name, id LIMIT 500"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, 500)))
}

/// Subscribes an S2S client to changes.
///
/// The client reads the stream as its service user, through that user's
/// permissions.
#[utoipa::path(
    post,
    path = "/api/v1/change-stream/subscriptions",
    operation_id = "change_stream_create_subscription",
    tag = "integration",
    request_body = SubscriptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = Subscription),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SubscriptionBody>,
) -> Result<(StatusCode, Json<Subscription>), AppError> {
    check(
        &state,
        &body.name,
        &body.entities,
        body.operations.as_deref(),
        &body.payload,
        body.condition.as_deref(),
    )?;
    let service_user = client_service_user(&state, body.client_ref).await?;
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO change_stream_subscription \
             (id, name, client_ref, service_user_ref, entities, operations, changed_attributes, \
              condition, payload, allow_personal, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(body.client_ref)
    .bind(service_user)
    .bind(&body.entities)
    .bind(&body.operations)
    .bind(&body.changed_attributes)
    .bind(&body.condition)
    .bind(&body.payload)
    .bind(body.allow_personal)
    .bind(body.expires_at)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Create,
        id,
        "change_stream.subscribe",
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(load(&state, id).await?)))
}

/// Update a subscription
///
/// Changes a subscription. Send its `row_version`.
#[utoipa::path(
    patch,
    path = "/api/v1/change-stream/subscriptions/{id}",
    operation_id = "change_stream_update_subscription",
    tag = "integration",
    params(("id" = Uuid, Path, description = "The subscription")),
    request_body = SubscriptionPatch,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = Subscription),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<SubscriptionPatch>,
) -> Result<Json<Subscription>, AppError> {
    let current = load(&state, id).await?;
    let name = body.name.unwrap_or(current.name);
    let entities = body.entities.unwrap_or(current.entities);
    let operations = body.operations.or(current.operations);
    let changed = body.changed_attributes.or(current.changed_attributes);
    let condition = body.condition.or(current.condition);
    let payload = body.payload.unwrap_or(current.payload);
    check(
        &state,
        &name,
        &entities,
        operations.as_deref(),
        &payload,
        condition.as_deref(),
    )?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE change_stream_subscription \
            SET name = $2, entities = $3, operations = $4, changed_attributes = $5, \
                condition = $6, payload = $7, allow_personal = $8, is_active = $9, \
                expires_at = $10, row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $11 AND NOT is_deleted",
    )
    .bind(id)
    .bind(name.trim())
    .bind(&entities)
    .bind(&operations)
    .bind(&changed)
    .bind(&condition)
    .bind(&payload)
    .bind(body.allow_personal.unwrap_or(current.allow_personal))
    .bind(body.is_active.unwrap_or(current.is_active))
    .bind(body.expires_at.or(current.expires_at))
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict("row_version mismatch"));
    }
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        id,
        "change_stream.update",
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(load(&state, id).await?))
}

/// End a subscription
///
/// Ends a subscription.
#[utoipa::path(
    delete,
    path = "/api/v1/change-stream/subscriptions/{id}",
    operation_id = "change_stream_delete_subscription",
    tag = "integration",
    params(("id" = Uuid, Path, description = "The subscription"), RowVersionQuery),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(q): Query<RowVersionQuery>,
) -> Result<StatusCode, AppError> {
    load(&state, id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE change_stream_subscription \
            SET is_deleted = true, is_active = false, row_version = row_version + 1, \
                updated_at = now() \
          WHERE id = $1 AND row_version = $2 AND NOT is_deleted",
    )
    .bind(id)
    .bind(q.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::Conflict("row_version mismatch"));
    }
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::SoftDelete,
        id,
        "change_stream.unsubscribe",
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Reading ─────────────────────────────────────────────────────────────

/// One event as the subscriber sees it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StreamEvent {
    pub event_id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub operation: String,
    pub event_name: Option<String>,
    pub created_at: DateTime<Utc>,
    /// With `changes` or `record`: the changed attributes the identity may
    /// read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_attributes: Option<Vec<String>>,
    /// With `record`: the record as the identity reads it now.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub record: Option<Value>,
}

/// A page of the stream.
#[derive(Debug, Serialize, ToSchema)]
pub struct StreamPage {
    pub events: Vec<StreamEvent>,
    /// Where the next read resumes.
    pub next_cursor: String,
    /// More events may be waiting.
    pub has_more: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReadQuery {
    /// The previous read's `next_cursor`; absent to start from now.
    pub cursor: Option<String>,
    /// 1 to 1000 (default 100).
    pub limit: Option<i64>,
}

/// A stream read's outcome.
#[derive(Debug)]
pub enum Read {
    Page(StreamPage),
    /// The cursor's events are gone, or the subscription ended.
    ResyncNeeded(&'static str),
}

fn seal(position: CursorPosition) -> String {
    seal_with(position, None)
}

/// L7-T5: a cursor may carry the snapshot an export read in
/// (`xmin:xmax:xip,...`); until the position passes the snapshot's `xmax`,
/// events visible in it (already in the export) are skipped.
fn seal_with(position: CursorPosition, snapshot: Option<&str>) -> String {
    let base = format!(
        "cs:{}:{}",
        position.last_commit_xid,
        position
            .last_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    );
    attome_types::cursor::seal(&match snapshot {
        Some(snap) => format!("{base}:{snap}"),
        None => base,
    })
}

fn open(sealed: &str) -> Result<CursorPosition, AppError> {
    open_full(sealed).map(|(position, _)| position)
}

fn open_full(sealed: &str) -> Result<(CursorPosition, Option<String>), AppError> {
    let raw = attome_types::cursor::open(sealed)?;
    let rest = raw.strip_prefix("cs:").ok_or(AppError::InvalidCursor)?;
    let mut parts = rest.splitn(3, ':');
    let xid = parts.next().ok_or(AppError::InvalidCursor)?;
    let id = parts.next().ok_or(AppError::InvalidCursor)?;
    let snapshot = parts.next().map(str::to_owned);
    if let Some(snap) = &snapshot {
        snapshot_xmax(snap).ok_or(AppError::InvalidCursor)?;
    }
    Ok((
        CursorPosition {
            last_commit_xid: xid.parse().map_err(|_| AppError::InvalidCursor)?,
            last_id: if id.is_empty() {
                None
            } else {
                Some(Uuid::parse_str(id).map_err(|_| AppError::InvalidCursor)?)
            },
        },
        snapshot,
    ))
}

/// A `pg_snapshot` text's `(xmin, xmax)`, when it is one.
fn snapshot_bounds(snapshot: &str) -> Option<(i64, i64)> {
    let mut parts = snapshot.split(':');
    let xmin: i64 = parts.next()?.parse().ok()?;
    let xmax: i64 = parts.next()?.parse().ok()?;
    let xip = parts.next()?;
    let ok = parts.next().is_none()
        && xmin <= xmax
        && xip
            .split(',')
            .filter(|x| !x.is_empty())
            .all(|x| x.parse::<i64>().is_ok_and(|v| v >= xmin && v < xmax));
    ok.then_some((xmin, xmax))
}

fn snapshot_xmax(snapshot: &str) -> Option<i64> {
    snapshot_bounds(snapshot).map(|(_, xmax)| xmax)
}

/// L7-T5: the change-stream cursor that continues an export read in
/// `snapshot` (the `pg_current_snapshot()` of the export's own statement):
/// reading from it yields exactly the changes the export did not see, so
/// nothing is lost or sent twice.
pub fn export_token(snapshot: &str) -> Result<String, AppError> {
    let (xmin, _) = snapshot_bounds(snapshot)
        .ok_or_else(|| AppError::internal(format!("not a snapshot: {snapshot:?}")))?;
    Ok(seal_with(
        CursorPosition {
            last_commit_xid: xmin - 1,
            last_id: None,
        },
        Some(snapshot),
    ))
}

/// Whether an event passes the subscription's operation and attribute
/// filters. A changed-attribute filter applies to updates only.
pub fn passes_filters(sub: &Subscription, operation: &str, changed: &[String]) -> bool {
    if sub
        .operations
        .as_ref()
        .is_some_and(|ops| !ops.iter().any(|o| o == operation))
    {
        return false;
    }
    match &sub.changed_attributes {
        Some(wanted) if operation == "update" && !changed.is_empty() => {
            changed.iter().any(|c| wanted.contains(c))
        }
        _ => true,
    }
}

/// The attributes a subscriber may be shown: never a sensitive one, and a
/// personal one only with `allow_personal`.
pub fn shown_attributes(attrs: &[attome_core::AttrInfo], allow_personal: bool) -> HashSet<String> {
    attrs
        .iter()
        .filter(|a| !a.is_read_gated())
        .filter(|a| {
            allow_personal || a.data_classification == attome_core::DataClassification::General
        })
        .map(|a| a.logicalname.clone())
        .collect()
}

type FeedRow = (
    Uuid,
    String,
    Uuid,
    String,
    Option<String>,
    DateTime<Utc>,
    Vec<String>,
    i64,
);

/// Reads up to `limit` events of `sub` after `cursor`, as `ctx` (the
/// subscription's identity) may see them.
pub async fn read(
    state: &EngineState,
    ctx: &SecurityContext,
    sub: &Subscription,
    cursor: Option<&str>,
    limit: i64,
) -> Result<Read, AppError> {
    if !sub.is_active || sub.expires_at.is_some_and(|at| at <= Utc::now()) {
        return Ok(Read::ResyncNeeded("the subscription has ended"));
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let mut snapshot: Option<String>;
    let mut position = match cursor {
        None => {
            let start = horizon(&mut conn).await?;
            return Ok(Read::Page(StreamPage {
                events: Vec::new(),
                next_cursor: seal(start),
                has_more: false,
            }));
        }
        Some(sealed) => {
            let (position, snap) = open_full(sealed)?;
            snapshot = snap;
            position
        }
    };
    // A cursor past events the feed no longer holds cannot resume in order.
    if let Some(last) = position.last_id {
        let (kept, oldest): (bool, Option<i64>) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM entity_change_event WHERE id = $1), \
                    (SELECT min(commit_xid::text::bigint) FROM entity_change_event)",
        )
        .bind(last)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if !kept && oldest.is_some_and(|o| o > position.last_commit_xid) {
            return Ok(Read::ResyncNeeded(
                "the cursor is older than the change feed keeps",
            ));
        }
    }

    let registry = state.entities.load();
    let mut readable_entities: HashMap<String, Option<(Uuid, HashSet<String>)>> = HashMap::new();
    for entity in &sub.entities {
        let entry = match registry.get(entity) {
            Some(meta) if ctx.require(entity, "read").is_ok() => Some((
                meta.entity_id,
                shown_attributes(&meta.attrs, sub.allow_personal),
            )),
            _ => None,
        };
        readable_entities.insert(entity.clone(), entry);
    }
    drop(registry);

    let mut events = Vec::new();
    let mut scanned = 0;
    let mut exhausted = false;
    while (events.len() as i64) < limit && scanned < limit * SCAN_FACTOR {
        let batch = (limit - events.len() as i64).max(1);
        // L7-T6: schema changes to the subscribed entities interleave with
        // their record events in commit order.
        let rows: Vec<FeedRow> = sqlx::query_as(
            "SELECT id, entity_logicalname, record_id, operation, event_name, created_at, \
                    changed_attributes, commit_xid::text::bigint \
               FROM ( \
                 SELECT id, entity_logicalname, record_id, operation, event_name, created_at, \
                        changed_attributes, commit_xid \
                   FROM entity_change_event WHERE entity_logicalname = ANY($4) \
                 UNION ALL \
                 SELECT id, entity_logicalname, COALESCE(object_ref, id), 'schema', \
                        'schema.' || change, created_at, \
                        CASE WHEN field IS NULL THEN '{}'::text[] ELSE ARRAY[field] END, commit_xid \
                   FROM schema_change_event WHERE entity_logicalname = ANY($4) \
               ) f \
              WHERE (commit_xid > $1::text::xid8 \
                     OR (commit_xid = $1::text::xid8 AND id > $2)) \
                AND commit_xid < pg_snapshot_xmin(pg_current_snapshot()) \
                AND ($5::text IS NULL \
                     OR NOT pg_visible_in_snapshot(commit_xid, $5::text::pg_snapshot)) \
              ORDER BY commit_xid, id \
              LIMIT $3",
        )
        .bind(position.last_commit_xid.to_string())
        .bind(position.last_id.unwrap_or(Uuid::nil()))
        .bind(batch)
        .bind(&sub.entities)
        .bind(snapshot.as_deref())
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            let edge = horizon(&mut conn).await?;
            if edge.last_commit_xid > position.last_commit_xid {
                position = edge;
            }
            exhausted = true;
            break;
        }
        scanned += rows.len() as i64;
        let short = (rows.len() as i64) < batch;
        // The records this batch touches that the identity may read now.
        let mut visible: HashMap<String, HashSet<Uuid>> = HashMap::new();
        for (entity, entry) in &readable_entities {
            let Some((entity_id, _)) = entry else {
                continue;
            };
            let ids: Vec<Uuid> = rows
                .iter()
                .filter(|r| &r.1 == entity && !ids_only(&r.3))
                .map(|r| r.2)
                .collect();
            if !ids.is_empty() {
                visible.insert(
                    entity.clone(),
                    attome_records::changes::readable_ids(state, ctx, *entity_id, entity, &ids)
                        .await?,
                );
            }
        }
        for (id, entity, record_id, operation, event_name, created_at, changed, xid) in rows {
            position = CursorPosition {
                last_commit_xid: xid,
                last_id: Some(id),
            };
            let Some(Some((_, shown))) = readable_entities.get(&entity) else {
                continue;
            };
            if !passes_filters(sub, &operation, &changed) {
                continue;
            }
            let deleted = ids_only(&operation);
            if !deleted
                && !visible
                    .get(&entity)
                    .is_some_and(|ids| ids.contains(&record_id))
            {
                continue;
            }
            let needs_record = !deleted && (sub.payload != "id" || sub.condition.is_some());
            let record = if needs_record {
                match attome_records::entity_crud::read_record(state, ctx, &entity, record_id).await
                {
                    Ok(r) => Some(r.data().clone()),
                    Err(AppError::NotFound | AppError::Forbidden) => continue,
                    Err(e) => return Err(e),
                }
            } else {
                None
            };
            if let (Some(condition), Some(data)) = (&sub.condition, &record)
                && !crate::approval_process::admits(Some(condition.as_str()), data)
            {
                continue;
            }
            let record = record.map(|data| strip(data, shown));
            let changed_attributes = (sub.payload != "id" || operation == "schema").then(|| {
                changed
                    .iter()
                    .filter(|c| {
                        shown.contains(*c)
                            && record.as_ref().is_none_or(|r| r.get(c.as_str()).is_some())
                    })
                    .cloned()
                    .collect()
            });
            events.push(StreamEvent {
                event_id: id,
                entity,
                record_id,
                operation,
                event_name,
                created_at,
                changed_attributes,
                record: (sub.payload == "record").then_some(record).flatten(),
            });
            if events.len() as i64 >= limit {
                break;
            }
        }
        if short {
            exhausted = true;
            break;
        }
    }
    // Past the export snapshot's xmax, nothing more can be visible in it.
    if snapshot
        .as_deref()
        .and_then(snapshot_xmax)
        .is_some_and(|xmax| position.last_commit_xid >= xmax)
    {
        snapshot = None;
    }
    Ok(Read::Page(StreamPage {
        has_more: !exhausted,
        events,
        next_cursor: seal_with(position, snapshot.as_deref()),
    }))
}

/// A delete, an erasure (`purge`, `record.erased`) or a schema change is
/// sent with ids only: there is no record to read, or nothing of it to show.
pub fn ids_only(operation: &str) -> bool {
    matches!(operation, "delete" | "purge" | "schema")
}

/// Keeps only the attributes a subscriber may be shown (and the system
/// columns, which are not attributes).
fn strip(data: Value, shown: &HashSet<String>) -> Value {
    match data {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(k, _)| shown.contains(k) || SYSTEM_KEYS.contains(&k.as_str()))
                .collect::<Map<String, Value>>(),
        ),
        other => other,
    }
}

const SYSTEM_KEYS: &[&str] = &[
    "id",
    "created_at",
    "updated_at",
    "row_version",
    "owner_ref",
    "is_active",
];

fn resync(reason: &'static str) -> Response {
    (
        StatusCode::GONE,
        Json(json!({
            "error": "resync_needed",
            "code": "resync_needed",
            "status": 410,
            "message": reason,
            "detail": reason,
        })),
    )
        .into_response()
}

/// The subscription `ctx` reads; 404 for anyone but its identity.
async fn own_subscription(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<Subscription, AppError> {
    let sub = load(state, id).await?;
    if sub.service_user_ref != ctx.user_id {
        return Err(AppError::NotFound);
    }
    Ok(sub)
}

/// Read subscription events
///
/// Reads a subscription's events after a cursor.
///
/// Only the subscription's identity reads it. `410 resync_needed` when the
/// cursor is older than the change feed keeps, or the subscription ended.
#[utoipa::path(
    get,
    path = "/api/v1/change-stream/{subscription}/events",
    operation_id = "change_stream_read_events",
    tag = "integration",
    params(("subscription" = Uuid, Path, description = "The subscription"), ReadQuery),
    responses(
        (status = 200, description = "Events in commit order", body = StreamPage),
        (status = 400, description = "A cursor this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such subscription for the caller", body = ErrorResponse),
        (status = 410, description = "resync_needed", body = ErrorResponse),
        (status = 422, description = "limit out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn read_events(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<ReadQuery>,
) -> Result<Response, AppError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(AppError::Validation(format!("limit is 1 to {MAX_LIMIT}")));
    }
    let sub = own_subscription(&state, &ctx, id).await?;
    Ok(
        match read(&state, &ctx, &sub, q.cursor.as_deref(), limit).await? {
            Read::Page(page) => Json(page).into_response(),
            Read::ResyncNeeded(reason) => resync(reason),
        },
    )
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SseQuery {
    /// Where to start; absent to start from now.
    pub cursor: Option<String>,
}

/// Stream subscription events
///
/// Streams a subscription's events as server-sent events.
///
/// Each `change` event's `id` is the cursor after it; reconnect with it.
/// A `resync_needed` event ends the stream when the cursor is too old or the
/// subscription ended. A connection lasts up to fifteen minutes.
#[utoipa::path(
    get,
    path = "/api/v1/change-stream/{subscription}/sse",
    operation_id = "change_stream_stream_events",
    tag = "integration",
    params(("subscription" = Uuid, Path, description = "The subscription"), SseQuery),
    responses(
        (status = 200, description = "text/event-stream of change events"),
        (status = 400, description = "A cursor this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such subscription for the caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn stream_events(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(q): Query<SseQuery>,
) -> Result<Response, AppError> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    let sub = own_subscription(&state, &ctx, id).await?;
    if let Some(c) = q.cursor.as_deref() {
        open(c)?;
    }
    // The stream outlives the request: it holds its own resolved context.
    let ctx = state.base.security.resolve(ctx.user_id).await?;
    struct Pump {
        state: EngineState,
        ctx: std::sync::Arc<SecurityContext>,
        id: Uuid,
        cursor: Option<String>,
        pending: std::collections::VecDeque<Event>,
        started: tokio::time::Instant,
        done: bool,
    }
    let pump = Pump {
        state,
        ctx,
        id,
        cursor: q.cursor,
        pending: Default::default(),
        started: tokio::time::Instant::now(),
        done: false,
    };
    drop(sub);
    let stream = futures_util::stream::unfold(pump, |mut p| async move {
        loop {
            if let Some(event) = p.pending.pop_front() {
                return Some((Ok::<_, std::convert::Infallible>(event), p));
            }
            if p.done || p.started.elapsed() >= SSE_LIFETIME {
                return None;
            }
            let sub = match load(&p.state, p.id).await {
                Ok(sub) => sub,
                Err(_) => {
                    p.done = true;
                    p.pending
                        .push_back(Event::default().event("resync_needed").data("ended"));
                    continue;
                }
            };
            match read(&p.state, &p.ctx, &sub, p.cursor.as_deref(), SSE_PAGE).await {
                Ok(Read::Page(page)) => {
                    let first = p.cursor.is_none();
                    p.cursor = Some(page.next_cursor.clone());
                    if first {
                        p.pending.push_back(
                            Event::default()
                                .event("cursor")
                                .id(page.next_cursor.clone()),
                        );
                    }
                    let count = page.events.len();
                    for (i, event) in page.events.into_iter().enumerate() {
                        let data = serde_json::to_string(&event).unwrap_or_default();
                        let mut sse = Event::default().event("change").data(data);
                        if i + 1 == count {
                            sse = sse.id(page.next_cursor.clone());
                        }
                        p.pending.push_back(sse);
                    }
                    if count == 0 && !first {
                        tokio::time::sleep(SSE_POLL).await;
                    }
                }
                Ok(Read::ResyncNeeded(reason)) => {
                    p.done = true;
                    p.pending
                        .push_back(Event::default().event("resync_needed").data(reason));
                }
                Err(error) => {
                    tracing::warn!(subscription = %p.id, %error, "change stream read failed");
                    p.done = true;
                }
            }
        }
    });
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ErasureConfirmationBody {
    /// The `record.erased` events this subscriber has erased its copies for.
    pub event_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErasureConfirmations {
    /// Events newly confirmed (an already confirmed one is not counted again).
    pub confirmed: u64,
}

/// Confirms erased copies.
///
/// L7-T6: the subscription's identity confirms it erased its copy of each
/// erased record (`record.erased` events of its entities); the confirmations
/// are kept as evidence of the erasure's reach.
#[utoipa::path(
    post,
    path = "/api/v1/change-stream/{subscription}/erasure-confirmations",
    operation_id = "change_stream_confirm_erasures",
    tag = "integration",
    params(("subscription" = Uuid, Path, description = "The caller's change-stream subscription")),
    request_body = ErasureConfirmationBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Confirmed", body = ErasureConfirmations),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such subscription for the caller", body = ErrorResponse),
        (status = 422, description = "An id that is not an erasure of the subscription's entities", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm_erasures(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ErasureConfirmationBody>,
) -> Result<Json<ErasureConfirmations>, AppError> {
    let sub = own_subscription(&state, &ctx, id).await?;
    if body.event_ids.is_empty() || body.event_ids.len() > 1000 {
        return Err(AppError::Validation("event_ids holds 1 to 1000 ids".into()));
    }
    let erased: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id FROM entity_change_event \
          WHERE id = ANY($1) AND event_name = $2 AND entity_logicalname = ANY($3)",
    )
    .bind(&body.event_ids)
    .bind(attome_compliance::erasure_admin::ERASED_EVENT)
    .bind(&sub.entities)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if erased.len() != body.event_ids.iter().collect::<HashSet<_>>().len() {
        return Err(AppError::Validation(
            "every id is a record.erased event of the subscription's entities".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut confirmed = 0;
    for (event_id, entity, record_id) in &erased {
        confirmed += sqlx::query(
            "INSERT INTO change_stream_erasure_confirmation \
                 (subscription_ref, event_id, entity_logicalname, record_id, confirmed_by) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(event_id)
        .bind(entity)
        .bind(record_id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Update,
            ctx.user_id,
            "change_stream_subscription",
            Some(id),
        )
        .named("change_stream.erasure_confirmed")
        .comment(format!("{confirmed} erased copies confirmed")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(ErasureConfirmations { confirmed }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/change-stream/subscriptions",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/api/v1/change-stream/subscriptions/{id}",
            patch(update_subscription).delete(delete_subscription),
        )
        .route(
            "/api/v1/change-stream/{subscription}/events",
            get(read_events),
        )
        .route(
            "/api/v1/change-stream/{subscription}/sse",
            get(stream_events),
        )
        .route(
            "/api/v1/change-stream/{subscription}/erasure-confirmations",
            post(confirm_erasures),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_subscriptions,
        create_subscription,
        update_subscription,
        delete_subscription,
        read_events,
        stream_events,
        confirm_erasures
    ),
    components(schemas(
        Subscription,
        SubscriptionBody,
        SubscriptionPatch,
        StreamEvent,
        StreamPage
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(operations: Option<Vec<&str>>, changed: Option<Vec<&str>>) -> Subscription {
        Subscription {
            id: Uuid::nil(),
            name: "erp".into(),
            client_ref: Uuid::nil(),
            service_user_ref: Uuid::nil(),
            entities: vec!["invoice".into()],
            operations: operations.map(|v| v.into_iter().map(String::from).collect()),
            changed_attributes: changed.map(|v| v.into_iter().map(String::from).collect()),
            condition: None,
            payload: "changes".into(),
            allow_personal: false,
            is_active: true,
            expires_at: None,
            row_version: 0,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn change_stream_filters_by_operation_and_changed_attribute() {
        let s = sub(Some(vec!["update", "delete"]), Some(vec!["status"]));
        assert!(!passes_filters(&s, "create", &[]));
        assert!(passes_filters(&s, "update", &["status".into()]));
        assert!(!passes_filters(&s, "update", &["notes".into()]));
        assert!(
            passes_filters(&s, "delete", &[]),
            "the attribute filter is for updates"
        );
        assert!(passes_filters(&sub(None, None), "create", &[]));
    }

    #[test]
    fn change_stream_cursor_round_trips_and_is_its_own() {
        let position = CursorPosition {
            last_commit_xid: 42,
            last_id: Some(Uuid::now_v7()),
        };
        let back = open(&seal(position)).unwrap();
        assert_eq!(back.last_commit_xid, 42);
        assert_eq!(back.last_id, position.last_id);
        let token = export_token("100:105:101,103").unwrap();
        let (position, snapshot) = open_full(&token).unwrap();
        assert_eq!(position.last_commit_xid, 99, "from the snapshot's xmin");
        assert_eq!(snapshot.as_deref(), Some("100:105:101,103"));
        assert!(export_token("100:99:").is_err(), "xmax below xmin");
        assert!(
            export_token("100:105:120").is_err(),
            "an in-progress xid past xmax"
        );
        let other = attome_types::cursor::seal("42:");
        assert!(
            open(&other).is_err(),
            "a query/changes cursor is not a stream cursor"
        );
    }
}

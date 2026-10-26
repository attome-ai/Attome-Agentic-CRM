//! Mass operations (roadmap AA10-T3): one change over every record a filter
//! selects, sized first by [`crate::heavy_op::size_check_rows`].
//!
//! - `POST /api/v1/{entity}/mass/estimate` answers the size check and writes
//!   nothing.
//! - `POST /api/v1/{entity}/mass` starts one: an `update` (the same values on
//!   every record), a `delete`, a `reassign` (a new owner, administrators
//!   only, through `attome_security::admin::reassign_owner_for`) or a
//!   `restore` (of deleted records). Up to the inline threshold it runs in
//!   the request, each record through the normal single-record path (record
//!   access, validation, rules, audit), and answers `200` with every
//!   record's outcome. Past it the caller must send `confirm_estimate_rows`
//!   (at least the rows counted) and the operation is recorded `queued`
//!   with `202`; the chunked runner that works it is AA10-T4.
//! - `GET /api/v1/mass/{id}` is its progress; `pause`, `resume`, `cancel`
//!   and `undo` control it, each with the operation's `row_version` in
//!   `If-Match`. Only the person who started it, or an administrator, sees
//!   or controls it; anyone else gets `404`.
//!
//! **Concurrency.** Each record is written with the row version read just
//! before, so a record changed meanwhile is counted as a conflict, not
//! overwritten. A control locks the operation row and checks its version.
//! Undo claims the operation (`undone`) before it replays, so two undos
//! cannot both replay; it writes each record back only when the record is
//! still at the version the operation left, and is refused for an operation
//! larger than the inline threshold (background undo is AA10-T5).
//! A retried start is caught by the durable idempotency tier
//! (`POST /api/v1/{entity}/mass` is in `MANDATORY_TIER_OPERATIONS`).

use attome_audit::{
    Attribution, AuditCategory, AuditEvent, AuditOperation, AuditOutcome, AuditRequestContext,
    AuditSource, BusinessEvent, write_bulk_accepted, write_bulk_completed_once,
    write_business_event_in_tx,
};
use attome_core::{EngineState, quote_ident};
use attome_security::record_action::Bulk;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped, SelfService};
use attome_server::middleware::idempotency_durable;
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::entity_crud;
use crate::entity_mutation::{DeleteKind, DeleteOrigin};
use crate::heavy_op::{
    self, ROWS_PER_SECOND, Rows, SizeEstimate, inline_threshold, matching_ids, size_check_rows,
};
use crate::query_spec::Condition;

/// What a mass operation does to each record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MassKind {
    /// Sets `payload`'s values on every record.
    Update,
    /// Deletes every record (to the recycle bin).
    Delete,
    /// Gives every record a new owner: `payload` names `user_email` or
    /// `team_name`. Administrators only.
    Reassign,
    /// Restores every deleted record the filter selects.
    Restore,
}

impl MassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Reassign => "reassign",
            Self::Restore => "restore",
        }
    }

    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "reassign" => Some(Self::Reassign),
            "restore" => Some(Self::Restore),
            _ => None,
        }
    }

    /// The record privilege the operation needs (restore and reassign use
    /// the update grant, as their single-record routes do).
    pub fn action(self) -> RecordAction {
        match self {
            Self::Delete => RecordAction::Delete,
            Self::Update | Self::Reassign | Self::Restore => RecordAction::Update,
        }
    }

    pub fn rows(self) -> Rows {
        match self {
            Self::Restore => Rows::Deleted,
            _ => Rows::Live,
        }
    }
}

/// Checks `payload` for `kind`. Pure.
pub fn validate_payload(kind: MassKind, payload: &Value) -> Result<(), AppError> {
    match kind {
        MassKind::Update => match payload.as_object() {
            Some(values) if !values.is_empty() => Ok(()),
            _ => Err(AppError::Validation(
                "an update needs payload: an object of the values to set".into(),
            )),
        },
        MassKind::Reassign => {
            let email = payload.get("user_email").and_then(Value::as_str);
            let team = payload.get("team_name").and_then(Value::as_str);
            if email.is_some() == team.is_some() {
                return Err(AppError::Validation(
                    "a reassign needs exactly one of payload.user_email or payload.team_name"
                        .into(),
                ));
            }
            Ok(())
        }
        MassKind::Delete | MassKind::Restore => match payload {
            Value::Null => Ok(()),
            Value::Object(values) if values.is_empty() => Ok(()),
            _ => Err(AppError::Validation(format!(
                "a {} takes no payload",
                kind.as_str()
            ))),
        },
    }
}

/// A control on a running operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Pause,
    Resume,
    Cancel,
    Undo,
}

impl Control {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
            Self::Undo => "undo",
        }
    }
}

/// The status `control` moves an operation in `status` to, or `None` when
/// it does not apply. Pure.
pub fn next_status(status: &str, control: Control) -> Option<&'static str> {
    match (control, status) {
        (Control::Pause, "queued" | "running") => Some("paused"),
        (Control::Resume, "paused") => Some("queued"),
        (Control::Cancel, "queued" | "running" | "paused") => Some("cancelled"),
        (Control::Undo, "done" | "cancelled") => Some("undone"),
        _ => None,
    }
}

/// Seconds left at [`ROWS_PER_SECOND`] for a working operation. Pure.
pub fn seconds_left(status: &str, estimated_rows: Option<i64>, rows_done: i64) -> Option<i64> {
    if !matches!(status, "queued" | "running" | "paused") {
        return None;
    }
    let left = (estimated_rows? - rows_done).max(0);
    Some((left + ROWS_PER_SECOND - 1) / ROWS_PER_SECOND)
}

/// What to estimate.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct MassEstimateBody {
    /// The query engine's filter (`query/run`'s `where`); none selects every
    /// record.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub filter: Option<Condition>,
    pub kind: MassKind,
    /// The change: the values for `update`, `user_email` or `team_name` for
    /// `reassign`, nothing for `delete` and `restore`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub payload: Value,
}

/// What to start.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct MassStartBody {
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub filter: Option<Condition>,
    pub kind: MassKind,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub payload: Value,
    /// Why, kept on the operation and on deleted records.
    #[serde(default)]
    pub reason: Option<String>,
    /// The rows the caller saw in the estimate. Required when the operation
    /// runs in the background, and at least the rows counted.
    #[serde(default)]
    pub confirm_estimate_rows: Option<i64>,
}

/// A mass operation and its progress.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MassOperation {
    pub id: Uuid,
    pub kind: String,
    pub entity: String,
    /// `queued`, `running`, `paused`, `cancelled`, `failed`, `done` or
    /// `undone`.
    pub status: String,
    pub estimated_rows: Option<i64>,
    pub rows_done: i64,
    pub rows_skipped_permission: i64,
    pub rows_conflict: i64,
    pub reason: Option<String>,
    pub started_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    /// While working: the seconds left at the estimated speed.
    pub seconds_left: Option<i64>,
}

/// How one record went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MassItemStatus {
    Done,
    /// Changed by someone else since it was read; left alone.
    Conflict,
    /// The caller may not change it.
    Skipped,
    Failed,
}

/// One record's outcome.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MassItem {
    pub id: Uuid,
    pub status: MassItemStatus,
    /// Why it failed, when the reason is the caller's to fix.
    pub error: Option<String>,
}

/// An operation with what this request did.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MassRun {
    pub operation: MassOperation,
    /// The size check the start was decided on.
    pub estimate: Option<SizeEstimate>,
    /// Each record changed in this request (inline, or undo).
    pub items: Vec<MassItem>,
}

#[derive(sqlx::FromRow)]
struct OpRow {
    id: Uuid,
    kind: String,
    entity_logicalname: String,
    status: String,
    estimated_rows: Option<i64>,
    rows_done: i64,
    rows_skipped_permission: i64,
    rows_conflict: i64,
    reason: Option<String>,
    started_by: Uuid,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    row_version: i64,
}

const OP_COLUMNS: &str = "id, kind, entity_logicalname, status, estimated_rows, rows_done, \
     rows_skipped_permission, rows_conflict, reason, started_by, created_at, finished_at, \
     row_version";

impl From<OpRow> for MassOperation {
    fn from(r: OpRow) -> Self {
        Self {
            seconds_left: seconds_left(&r.status, r.estimated_rows, r.rows_done),
            id: r.id,
            kind: r.kind,
            entity: r.entity_logicalname,
            status: r.status,
            estimated_rows: r.estimated_rows,
            rows_done: r.rows_done,
            rows_skipped_permission: r.rows_skipped_permission,
            rows_conflict: r.rows_conflict,
            reason: r.reason,
            started_by: r.started_by,
            created_at: r.created_at,
            finished_at: r.finished_at,
            row_version: r.row_version,
        }
    }
}

/// The outcome an error means for one record, and the message to show.
fn outcome_of(error: &AppError) -> (MassItemStatus, Option<String>) {
    match error {
        AppError::VersionConflict | AppError::VersionConflictAt { .. } => {
            (MassItemStatus::Conflict, None)
        }
        AppError::Forbidden | AppError::NotFound => (MassItemStatus::Skipped, None),
        AppError::Validation(message) => (MassItemStatus::Failed, Some(message.clone())),
        other => {
            tracing::warn!(error = %other, "mass operation: a record failed");
            (
                MassItemStatus::Failed,
                Some("the record could not be changed".into()),
            )
        }
    }
}

/// The size check for `body` as `ctx`.
pub async fn estimate(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    filter: Option<&Condition>,
    kind: MassKind,
    payload: &Value,
) -> Result<SizeEstimate, AppError> {
    validate_payload(kind, payload)?;
    if kind == MassKind::Reassign && !ctx.is_admin {
        return Err(AppError::Forbidden);
    }
    size_check_rows(
        state,
        ctx,
        entity,
        filter,
        kind.action(),
        inline_threshold(state),
        kind.rows(),
    )
    .await
}

/// Starts a mass operation as `ctx` (see the module docs). The second value
/// is whether it ran inline.
pub async fn start(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    body: MassStartBody,
    idempotency: Option<idempotency_durable::DurableIdempotencyHandle>,
) -> Result<(MassRun, bool), AppError> {
    let (_, entity, _, is_append_only) = entity_crud::resolve_entity(state, entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    let size = estimate(
        state,
        ctx,
        &entity,
        body.filter.as_ref(),
        body.kind,
        &body.payload,
    )
    .await?;
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(500).collect::<String>());
    let background = size.path == heavy_op::Path::Background;
    if background
        && body
            .confirm_estimate_rows
            .is_none_or(|n| n < size.exact_upto)
    {
        return Err(AppError::Validation(format!(
            "this operation changes about {} records and runs in the background: \
             send confirm_estimate_rows of at least {}",
            size.estimated_rows, size.exact_upto
        )));
    }

    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO heavy_operation (id, kind, entity_logicalname, filter, payload, status, \
             estimated_rows, started_by, reason) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(body.kind.as_str())
    .bind(&entity)
    .bind(serde_json::to_value(&body.filter).map_err(AppError::internal)?)
    .bind(&body.payload)
    .bind(if background { "queued" } else { "running" })
    .bind(size.estimated_rows)
    .bind(ctx.user_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let audit = attome_audit::audit_service(state);
    write_bulk_accepted(
        &audit,
        &mut tx,
        mass_event(state, ctx.user_id, &entity, id, body.kind).await,
        Attribution::user(ctx.user_id),
        i32::try_from(size.estimated_rows).unwrap_or(i32::MAX),
    )
    .await?;

    if background {
        let run = MassRun {
            operation: read_op_in(&mut tx, id).await?.into(),
            estimate: Some(size),
            items: Vec::new(),
        };
        complete_idempotency(&mut tx, idempotency, id, StatusCode::ACCEPTED, &run).await?;
        attome_db::tx::commit(tx).await?;
        return Ok((run, false));
    }
    attome_db::tx::commit(tx).await?;

    // Inline: every record through its own single-record path.
    let ids = matching_ids(
        state,
        ctx,
        &entity,
        body.filter.as_ref(),
        body.kind.action(),
        body.kind.rows(),
        size.exact_upto,
    )
    .await?;
    let mut items = Vec::with_capacity(ids.len());
    let mut undo = Vec::new();
    for record in ids {
        let applied = apply_one(state, ctx, &entity, id, record, &body, reason.as_deref()).await;
        match applied {
            Ok(before) => {
                undo.push(before);
                items.push(MassItem {
                    id: record,
                    status: MassItemStatus::Done,
                    error: None,
                });
            }
            Err(error) => {
                let (status, message) = outcome_of(&error);
                items.push(MassItem {
                    id: record,
                    status,
                    error: message,
                });
            }
        }
    }
    let count = |s: MassItemStatus| items.iter().filter(|i| i.status == s).count() as i64;
    let (done, conflict, skipped, failed) = (
        count(MassItemStatus::Done),
        count(MassItemStatus::Conflict),
        count(MassItemStatus::Skipped),
        count(MassItemStatus::Failed),
    );

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO heavy_operation_chunk (operation_id, chunk_no, last_id, status, \
             before_values) VALUES ($1, 0, $2, 'done', $3)",
    )
    .bind(id)
    .bind(items.last().map(|i| i.id))
    .bind(json!({ "kind": body.kind.as_str(), "items": undo }))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE heavy_operation SET status = 'done', rows_done = $2, rows_conflict = $3, \
             rows_skipped_permission = $4, finished_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(done)
    .bind(conflict)
    .bind(skipped)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let outcome = if done == items.len() as i64 {
        AuditOutcome::Succeeded
    } else if done == 0 && !items.is_empty() {
        AuditOutcome::Failed
    } else {
        AuditOutcome::PartiallyFailed
    };
    write_bulk_completed_once(
        &audit,
        &mut tx,
        mass_event(state, ctx.user_id, &entity, id, body.kind).await,
        Attribution::user(ctx.user_id),
        outcome,
        i32::try_from(done).unwrap_or(i32::MAX),
        i32::try_from(conflict + skipped + failed).unwrap_or(i32::MAX),
    )
    .await?;
    let run = MassRun {
        operation: read_op_in(&mut tx, id).await?.into(),
        estimate: Some(size),
        items,
    };
    complete_idempotency(&mut tx, idempotency, id, StatusCode::OK, &run).await?;
    attome_db::tx::commit(tx).await?;
    Ok((run, true))
}

/// Changes one record and answers what undo writes back.
async fn apply_one(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    operation: Uuid,
    record: Uuid,
    body: &MassStartBody,
    reason: Option<&str>,
) -> Result<Value, AppError> {
    match body.kind {
        MassKind::Update => {
            let current = entity_crud::read_record(state, ctx, entity, record).await?;
            let values = body.payload.as_object().cloned().unwrap_or_default();
            let before: Map<String, Value> = values
                .keys()
                .map(|k| {
                    (
                        k.clone(),
                        current.data().get(k).cloned().unwrap_or(Value::Null),
                    )
                })
                .collect();
            let updated = entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                entity,
                record,
                current.row_version(),
                Value::Object(values),
            )
            .await?;
            Ok(
                json!({ "id": record, "before": before, "row_version_after": updated.row_version() }),
            )
        }
        MassKind::Delete => {
            let origin =
                DeleteOrigin::with_id(DeleteKind::Bulk, operation.to_string()).reason(reason);
            entity_crud::delete_record_for(state, ctx, ctx.user_id, entity, record, None, &origin)
                .await?;
            Ok(json!({ "id": record }))
        }
        MassKind::Restore => {
            entity_crud::restore_record_for(state, ctx, ctx.user_id, entity, record, None).await?;
            Ok(json!({ "id": record }))
        }
        MassKind::Reassign => {
            let previous = owner_of(state, entity, record).await?;
            attome_security::admin::reassign_owner_for(
                state,
                ctx.user_id,
                entity,
                record,
                body.payload.get("user_email").and_then(Value::as_str),
                body.payload.get("team_name").and_then(Value::as_str),
            )
            .await?;
            Ok(json!({
                "id": record,
                "user_email": previous.0,
                "team_name": previous.1,
            }))
        }
    }
}

/// The record's owner as `reassign_owner_for` names one: a user's email or
/// a team's name.
async fn owner_of(
    state: &EngineState,
    entity: &str,
    record: Uuid,
) -> Result<(Option<String>, Option<String>), AppError> {
    let sql = format!(
        "SELECT owner_ref, owner_type FROM {} WHERE id = $1",
        quote_ident(entity)
    );
    let (owner, owner_type): (Option<Uuid>, Option<i16>) =
        sqlx::query_as(&attome_db::tag_dynamic("mass.owner_of", &sql))
            .bind(record)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let Some(owner) = owner else {
        return Ok((None, None));
    };
    if owner_type == Some(1) {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM team WHERE id = $1")
            .bind(owner)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        Ok((None, name))
    } else {
        let email: Option<Option<String>> =
            sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
                .bind(owner)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        Ok((email.flatten(), None))
    }
}

/// The audit event a mass operation's bulk events start from.
async fn mass_event(
    state: &EngineState,
    user: Uuid,
    entity: &str,
    operation: Uuid,
    kind: MassKind,
) -> AuditEvent {
    let (user_context, org_ref) = attome_audit::fetch_audit_ctx(state, user).await;
    AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity.to_owned()),
        record_id: None,
        operation: AuditOperation::BulkAccepted,
        version_before: None,
        version_after: None,
        user_context,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(operation),
        event_name: None,
        event_comment: Some(format!("mass {}", kind.as_str())),
        changed_fields: Vec::new(),
        snapshot_json: None,
    }
}

async fn complete_idempotency(
    tx: &mut attome_db::Tx<'_>,
    handle: Option<idempotency_durable::DurableIdempotencyHandle>,
    operation: Uuid,
    status: StatusCode,
    run: &MassRun,
) -> Result<(), AppError> {
    let Some(handle) = handle else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(run).map_err(AppError::internal)?;
    idempotency_durable::complete_in_tx(
        tx,
        handle.record_id,
        Some(operation),
        status.as_u16(),
        &[("content-type".to_string(), "application/json".to_string())],
        &bytes,
    )
    .await
    .map_err(AppError::internal)
}

async fn read_op_in(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<OpRow, AppError> {
    sqlx::query_as::<_, OpRow>(&format!(
        "SELECT {OP_COLUMNS} FROM heavy_operation WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The operation, when `ctx` started it or is an administrator.
pub async fn get_operation(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<MassOperation, AppError> {
    let row = sqlx::query_as::<_, OpRow>(&format!(
        "SELECT {OP_COLUMNS} FROM heavy_operation WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .filter(|r| ctx.is_admin || r.started_by == ctx.user_id)
    .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

/// Applies `control` at `expected` row version (see the module docs).
pub async fn control(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    expected: i64,
    control: Control,
) -> Result<MassRun, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = sqlx::query_as::<_, OpRow>(&format!(
        "SELECT {OP_COLUMNS} FROM heavy_operation WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .filter(|r| ctx.is_admin || r.started_by == ctx.user_id)
    .ok_or(AppError::NotFound)?;
    if row.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    let next = next_status(&row.status, control).ok_or(AppError::Conflict(
        "the operation is not in a state this control applies to",
    ))?;
    if control == Control::Undo && row.rows_done > inline_threshold(state) {
        return Err(AppError::Conflict(
            "this operation is too large to undo in one request",
        ));
    }
    let terminal = matches!(next, "cancelled" | "undone");
    sqlx::query(
        "UPDATE heavy_operation SET status = $2, row_version = row_version + 1, \
             finished_at = CASE WHEN $3 THEN now() ELSE finished_at END \
          WHERE id = $1",
    )
    .bind(id)
    .bind(next)
    .bind(terminal)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let operation = match control {
        Control::Cancel => AuditOperation::Cancelled,
        _ => AuditOperation::Update,
    };
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            "heavy_operation",
            id,
            operation,
            format!("mass.{}", control.as_str()),
            ctx.user_id,
        )
        .versions(Some(row.row_version), Some(row.row_version + 1))
        .comment(format!("{} -> {next}", row.status)),
    )
    .await?;
    let entity = row.entity_logicalname.clone();
    let kind = MassKind::parse(&row.kind);
    let chunks: Vec<Value> = if control == Control::Undo {
        sqlx::query_scalar(
            "SELECT before_values FROM heavy_operation_chunk \
              WHERE operation_id = $1 AND before_values IS NOT NULL ORDER BY chunk_no DESC",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?
    } else {
        Vec::new()
    };
    attome_db::tx::commit(tx).await?;

    let mut items = Vec::new();
    if let (Control::Undo, Some(kind)) = (control, kind) {
        for chunk in &chunks {
            let entries = chunk["items"].as_array().cloned().unwrap_or_default();
            for entry in entries.iter().rev() {
                let Some(record) = entry["id"].as_str().and_then(|s| Uuid::parse_str(s).ok())
                else {
                    continue;
                };
                let item = match undo_one(state, ctx, &entity, id, kind, record, entry).await {
                    Ok(()) => MassItem {
                        id: record,
                        status: MassItemStatus::Done,
                        error: None,
                    },
                    Err(error) => {
                        let (status, message) = outcome_of(&error);
                        MassItem {
                            id: record,
                            status,
                            error: message,
                        }
                    }
                };
                items.push(item);
            }
        }
    }
    Ok(MassRun {
        operation: get_operation(state, ctx, id).await?,
        estimate: None,
        items,
    })
}

/// Writes one record back to what it was before the operation.
async fn undo_one(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    operation: Uuid,
    kind: MassKind,
    record: Uuid,
    entry: &Value,
) -> Result<(), AppError> {
    match kind {
        MassKind::Update => {
            ctx.require(entity, "update")?;
            let after = entry["row_version_after"]
                .as_i64()
                .ok_or(AppError::VersionConflict)?;
            entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                entity,
                record,
                after,
                entry["before"].clone(),
            )
            .await?;
        }
        MassKind::Delete => {
            ctx.require(entity, "update")?;
            entity_crud::restore_record_for(state, ctx, ctx.user_id, entity, record, None).await?;
        }
        MassKind::Restore => {
            ctx.require(entity, "delete")?;
            let origin = DeleteOrigin::with_id(DeleteKind::Bulk, operation.to_string());
            entity_crud::delete_record_for(state, ctx, ctx.user_id, entity, record, None, &origin)
                .await?;
        }
        MassKind::Reassign => {
            if !ctx.is_admin {
                return Err(AppError::Forbidden);
            }
            let email = entry["user_email"].as_str();
            let team = entry["team_name"].as_str();
            if email.is_none() && team.is_none() {
                // It had no owner the reassign route can name.
                return Err(AppError::Validation(
                    "the previous owner can no longer be named".into(),
                ));
            }
            attome_security::admin::reassign_owner_for(
                state,
                ctx.user_id,
                entity,
                record,
                email,
                team,
            )
            .await?;
        }
    }
    Ok(())
}

/// `If-Match`'s row version, required.
fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match is required".into()))?;
    raw.to_str()
        .ok()
        .map(|s| s.trim().trim_matches('"'))
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| AppError::Validation("If-Match must be the operation's row_version".into()))
}

/// Estimate a mass operation
///
/// Counts the records the filter selects that the caller may change, up to
/// the inline threshold, and says whether the operation would run in the
/// request or in the background, with the estimated rows and seconds.
/// Writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/mass/estimate",
    operation_id = "post_mass_estimate",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = MassEstimateBody,
    responses(
        (status = 200, description = "The size check", body = SizeEstimate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change this entity's records in bulk", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "An invalid filter, kind or payload", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "estimate only: counts the records a mass operation would change and writes nothing"
    )))),
)]
async fn post_mass_estimate(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    Path(entity_input): Path<String>,
    Json(body): Json<MassEstimateBody>,
) -> Result<Json<SizeEstimate>, AppError> {
    let (_, entity, _, _) = entity_crud::resolve_entity(&state, &entity_input).await?;
    Ok(Json(
        estimate(
            &state,
            &ctx,
            &entity,
            body.filter.as_ref(),
            body.kind,
            &body.payload,
        )
        .await?,
    ))
}

/// Start a mass operation
///
/// Updates, deletes, reassigns or restores every record the filter selects
/// that the caller may change. Up to the inline threshold it runs now and
/// answers 200 with each record's outcome; past it, with
/// `confirm_estimate_rows`, it is queued for the background and answers 202
/// with the operation to follow at `GET /api/v1/mass/{id}`.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/mass",
    operation_id = "post_mass_start",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = MassStartBody,
    responses(
        (status = 200, description = "Ran in the request", body = MassRun),
        (status = 202, description = "Queued for the background", body = MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not make this change in bulk", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "An invalid filter, kind or payload, or a background operation without confirm_estimate_rows", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::BulkAccepted),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::BulkCompleted),
    ])))),
)]
async fn post_mass_start(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    idempotency_handle: Option<Extension<idempotency_durable::DurableIdempotencyHandle>>,
    Path(entity_input): Path<String>,
    Json(body): Json<MassStartBody>,
) -> Result<(StatusCode, Json<MassRun>), AppError> {
    let (run, inline) = start(
        &state,
        &ctx,
        &entity_input,
        body,
        idempotency_handle.map(|Extension(handle)| handle),
    )
    .await?;
    let status = if inline {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(run)))
}

/// A mass operation's progress
///
/// The operation's status, the rows done, skipped and in conflict, and the
/// seconds left while it works. Only the person who started it or an
/// administrator sees it.
#[utoipa::path(
    get,
    path = "/api/v1/mass/{id}",
    operation_id = "get_mass_operation",
    tag = "entity",
    params(("id" = Uuid, Path, description = "The operation")),
    responses(
        (status = 200, description = "The operation", body = MassOperation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such operation the caller started", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_mass_operation(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<MassOperation>, AppError> {
    Ok(Json(get_operation(&state, &ctx, id).await?))
}

async fn controlled(
    state: EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    headers: &HeaderMap,
    which: Control,
) -> Result<Json<MassRun>, AppError> {
    let expected = if_match(headers)?;
    Ok(Json(control(&state, ctx, id, expected, which).await?))
}

/// Pause a mass operation
///
/// Stops a queued or running operation after its current chunk. Send the
/// operation's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/mass/{id}/pause",
    operation_id = "post_mass_pause",
    tag = "entity",
    params(
        ("id" = Uuid, Path, description = "The operation"),
        ("If-Match" = String, Header, description = "The operation's row_version"),
    ),
    responses(
        (status = 200, description = "Paused", body = MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such operation the caller started", body = ErrorResponse),
        (status = 409, description = "The operation changed, or cannot be paused now", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_mass_pause(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<MassRun>, AppError> {
    controlled(state, &ctx, id, &headers, Control::Pause).await
}

/// Resume a mass operation
///
/// Queues a paused operation again. Send the operation's `row_version` in
/// `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/mass/{id}/resume",
    operation_id = "post_mass_resume",
    tag = "entity",
    params(
        ("id" = Uuid, Path, description = "The operation"),
        ("If-Match" = String, Header, description = "The operation's row_version"),
    ),
    responses(
        (status = 200, description = "Queued again", body = MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such operation the caller started", body = ErrorResponse),
        (status = 409, description = "The operation changed, or is not paused", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_mass_resume(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<MassRun>, AppError> {
    controlled(state, &ctx, id, &headers, Control::Resume).await
}

/// Cancel a mass operation
///
/// Stops a queued, running or paused operation for good; what it changed so
/// far stays changed (undo reverses it). Send the operation's `row_version`
/// in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/mass/{id}/cancel",
    operation_id = "post_mass_cancel",
    tag = "entity",
    params(
        ("id" = Uuid, Path, description = "The operation"),
        ("If-Match" = String, Header, description = "The operation's row_version"),
    ),
    responses(
        (status = 200, description = "Cancelled", body = MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such operation the caller started", body = ErrorResponse),
        (status = 409, description = "The operation changed, or has already finished", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Cancelled)])))),
)]
async fn post_mass_cancel(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<MassRun>, AppError> {
    controlled(state, &ctx, id, &headers, Control::Cancel).await
}

/// Undo a mass operation
///
/// Writes back what a done or cancelled operation changed, newest first,
/// each record through its single-record path and only while it is still as
/// the operation left it (a record changed since is reported as a
/// conflict). Deleted records are restored, restored ones deleted again.
/// Send the operation's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/mass/{id}/undo",
    operation_id = "post_mass_undo",
    tag = "entity",
    params(
        ("id" = Uuid, Path, description = "The operation"),
        ("If-Match" = String, Header, description = "The operation's row_version"),
    ),
    responses(
        (status = 200, description = "Undone, with each record's outcome", body = MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such operation the caller started", body = ErrorResponse),
        (status = 409, description = "The operation changed, is not finished, or is too large to undo in one request", body = ErrorResponse),
        (status = 422, description = "A missing or malformed If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_mass_undo(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<MassRun>, AppError> {
    controlled(state, &ctx, id, &headers, Control::Undo).await
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/{entity}/mass/estimate", post(post_mass_estimate))
        .route("/api/v1/{entity}/mass", post(post_mass_start))
        .route("/api/v1/mass/{id}", get(get_mass_operation))
        .route("/api/v1/mass/{id}/pause", post(post_mass_pause))
        .route("/api/v1/mass/{id}/resume", post(post_mass_resume))
        .route("/api/v1/mass/{id}/cancel", post(post_mass_cancel))
        .route("/api/v1/mass/{id}/undo", post(post_mass_undo))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    post_mass_estimate,
    post_mass_start,
    get_mass_operation,
    post_mass_pause,
    post_mass_resume,
    post_mass_cancel,
    post_mass_undo
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_its_kind() {
        assert!(validate_payload(MassKind::Update, &json!({"title": "x"})).is_ok());
        assert!(validate_payload(MassKind::Update, &json!({})).is_err());
        assert!(validate_payload(MassKind::Update, &Value::Null).is_err());
        assert!(validate_payload(MassKind::Delete, &Value::Null).is_ok());
        assert!(validate_payload(MassKind::Delete, &json!({"x": 1})).is_err());
        assert!(validate_payload(MassKind::Reassign, &json!({"user_email": "a@b.c"})).is_ok());
        assert!(
            validate_payload(
                MassKind::Reassign,
                &json!({"user_email": "a@b.c", "team_name": "t"})
            )
            .is_err()
        );
        assert!(validate_payload(MassKind::Reassign, &json!({})).is_err());
        assert_eq!(MassKind::Restore.rows(), Rows::Deleted);
        assert_eq!(MassKind::Reassign.action(), RecordAction::Update);
    }

    #[test]
    fn controls_follow_the_status() {
        assert_eq!(next_status("running", Control::Pause), Some("paused"));
        assert_eq!(next_status("paused", Control::Resume), Some("queued"));
        assert_eq!(next_status("paused", Control::Cancel), Some("cancelled"));
        assert_eq!(next_status("done", Control::Undo), Some("undone"));
        assert_eq!(next_status("done", Control::Pause), None);
        assert_eq!(next_status("undone", Control::Undo), None);
        assert_eq!(next_status("running", Control::Undo), None);
        assert_eq!(next_status("cancelled", Control::Resume), None);
    }

    #[test]
    fn time_left_only_while_working() {
        assert_eq!(seconds_left("running", Some(4001), 1), Some(2));
        assert_eq!(seconds_left("queued", Some(10), 50), Some(0));
        assert_eq!(seconds_left("done", Some(10), 0), None);
        assert_eq!(seconds_left("running", None, 0), None);
    }
}

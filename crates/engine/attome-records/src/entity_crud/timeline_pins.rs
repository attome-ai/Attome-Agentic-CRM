//! B1-T2: pin and unpin a timeline entry on a record
//! (`PUT`/`DELETE /api/v1/{entity}/{id}/timeline/pins/{kind}/{source_id}`).
//!
//! A pin changes what everyone who opens the record sees first, so it needs
//! the record's update access (`{entity}.update` and the record-level
//! check). It names an entry by its kind and source row only; the timeline
//! reads a pinned entry through its own sources, so a pin never shows an
//! entry its reader may not see. At most [`MAX_PINS`] per record. Both are
//! idempotent and write a business event.

use attome_audit::AuditOperation;
use attome_security::record_action::Update;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use attome_core::EngineState;

use super::access::require_record_access;
use super::resolve::resolve_entity;
use super::timeline::{MAX_PINS, TimelineEntryKind, require_live_record};

/// The record the pin is on, checked for update access; its entity name.
async fn pinnable(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
) -> Result<String, AppError> {
    let (entity_id, entity_name, _, is_append_only) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity_name, "update")?;
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;
    require_live_record(state, &entity_name, is_append_only, record_id).await?;
    Ok(entity_name)
}

fn kind_of(raw: &str) -> Result<TimelineEntryKind, AppError> {
    TimelineEntryKind::parse(raw)
        .ok_or_else(|| AppError::Validation(format!("unknown timeline kind: {raw}")))
}

/// Pin a timeline entry
///
/// B1-T2: pins one timeline entry on the record, for everyone who opens it.
/// Needs the record's update access; at most 50 pins per record.
#[utoipa::path(
    put,
    path = "/api/v1/{entity}/{id}/timeline/pins/{kind}/{source_id}",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("kind" = String, Path, description = "The entry's kind"),
        ("source_id" = Uuid, Path, description = "The entry's source row"),
    ),
    responses(
        (status = 204, description = "Pinned"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the entity", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller may not update it", body = ErrorResponse),
        (status = 409, description = "The record already holds 50 pins", body = ErrorResponse),
        (status = 422, description = "Unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(super) async fn pin_entry(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, kind, source_id)): Path<(String, Uuid, String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let kind = kind_of(&kind)?;
    let entity_name = pinnable(&state, &ctx, &entity_input, record_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM timeline_pin WHERE entity_name = $1 AND record_id = $2",
    )
    .bind(&entity_name)
    .bind(record_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let inserted = sqlx::query(
        "INSERT INTO timeline_pin (entity_name, record_id, kind, source_id, pinned_by) \
         SELECT $1, $2, $3, $4, $5 WHERE $6 < $7 \
         ON CONFLICT (entity_name, record_id, kind, source_id) DO NOTHING",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(kind.as_str())
    .bind(source_id)
    .bind(ctx.user_id)
    .bind(count)
    .bind(MAX_PINS)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted == 0 {
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM timeline_pin WHERE entity_name = $1 AND record_id = $2 \
               AND kind = $3 AND source_id = $4)",
        )
        .bind(&entity_name)
        .bind(record_id)
        .bind(kind.as_str())
        .bind(source_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !already {
            return Err(AppError::Conflict("a record holds at most 50 pins"));
        }
        // Already pinned: nothing to do.
        return Ok(StatusCode::NO_CONTENT);
    }
    tx.commit().await.map_err(AppError::internal)?;
    attome_audit::write_business_event(
        &state,
        &entity_name,
        record_id,
        AuditOperation::Update,
        "timeline.pinned",
        ctx.user_id,
        None,
        None,
        format!("{} {source_id} pinned", kind.as_str()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Unpin a timeline entry
///
/// B1-T2: removes a pin from the record. Needs the record's update access.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/timeline/pins/{kind}/{source_id}",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("kind" = String, Path, description = "The entry's kind"),
        ("source_id" = Uuid, Path, description = "The entry's source row"),
    ),
    responses(
        (status = 204, description = "Not pinned (any more)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the entity", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller may not update it", body = ErrorResponse),
        (status = 422, description = "Unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(super) async fn unpin_entry(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, kind, source_id)): Path<(String, Uuid, String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let kind = kind_of(&kind)?;
    let entity_name = pinnable(&state, &ctx, &entity_input, record_id).await?;
    let removed = sqlx::query(
        "DELETE FROM timeline_pin WHERE entity_name = $1 AND record_id = $2 \
           AND kind = $3 AND source_id = $4",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(kind.as_str())
    .bind(source_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if removed > 0 {
        attome_audit::write_business_event(
            &state,
            &entity_name,
            record_id,
            AuditOperation::Update,
            "timeline.unpinned",
            ctx.user_id,
            None,
            None,
            format!("{} {source_id} unpinned", kind.as_str()),
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(pin_entry, unpin_entry))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

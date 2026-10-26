//! Solution 7 Phase 2 (D-788 rule 9; `SOLUTION-7-PHASE-2-DESIGN.md` §8.5) —
//! the 30-day recovery archive's admin routes.
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/api/v1/admin/metadata/recovery-archive` | list, values **not** included |
//! | GET | `/api/v1/admin/metadata/recovery-archive/{archive_id}` | one row with its decrypted value (audited) |
//! | POST | `/api/v1/admin/metadata/recovery-archive/{archive_id}/restore` | restore one value |
//! | POST | `/api/v1/admin/metadata/recovery-archive/restore` | restore every unexpired, unrestored value of a field |
//!
//! Admin only (`Authorized<Admin>`). The archive key ring is
//! `metadata.recovery_archive_key_encryption_key`; without it a value read or
//! restore is refused (`archive_key_missing`), never answered in clear from
//! anywhere else.
//!
//! **Restore** resolves the target field by the archived `attribute_id` (a
//! type change keeps it), else by `(entity, field name)` (a deleted field
//! re-added under its name). No live field: 409 `restore_target_missing`.
//! The archived JSON value is converted to the field's current type; one
//! that does not fit is `restore_not_convertible` (per item: 409; per field:
//! counted). **Only empty targets are filled**: a record whose field has a
//! value now is skipped and counted, never overwritten. Each value is written
//! through the generic engine's update path (`entity_mutation::update_one`,
//! the deciding admin's security context) so validation, business rules and
//! the record's audit apply like any edit; `restored_at`/`restored_by` are
//! set in the same transaction. Idempotent: a restored row is skipped.
//!
//! Deviation from the design (stated): the per-field restore runs in
//! bounded id-ordered batches within the request (at most
//! [`MAX_RESTORE_PER_REQUEST`] rows) and reports `remaining`; the caller
//! repeats the request. The `RestoreArchive` job and the CSV export of §8.5
//! are left for the report lane.
//!
//! Security review fixes:
//!
//! - **M1** — a value read makes the same decision as a read of the field
//!   (D-111, `attome_security::field_gate::field_readable`, interactive
//!   surface): when the field was sensitive at archive time (sealed with the
//!   value, so it cannot be flipped in the database, and known even after
//!   the field is deleted) or is sensitive now, the caller needs the field's
//!   read grant (`has_field_read_grant`), else 403 and nothing is returned.
//!   Note: `has_field_read_grant` admits `system.admin` today, for record
//!   reads too, so for this admin-only route the gate matches — it does not
//!   exceed — what the admin could read on the record itself.
//! - **L2** — each restored value writes its `Configuration` security event
//!   in the restore's own transaction (no after-commit summary that an
//!   early error could skip).
//! - **L4** — values are bound to their row (`recovery_archive::aad`); a
//!   moved ciphertext is refused (`archive_value_unreadable`).
//! - **L5** — an expired row (past `expires_at`, whether the purge has not
//!   reached it yet or a legal hold keeps it) is never read (404) or
//!   restored (409 `archive_expired`).

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::recovery_archive::{self, ARCHIVE_ROW_COLUMNS, ArchiveRow};
use attome_core::{EngineState, FieldType};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::audit_service;

/// Most values one per-field restore request writes.
pub const MAX_RESTORE_PER_REQUEST: i64 = 10_000;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct ArchiveFilter {
    /// Entity logical name.
    entity: Option<String>,
    /// Field logical name (as archived).
    field: Option<String>,
    /// `field_deleted | conversion_nulled`.
    reason: Option<String>,
    /// Include restored rows (default false).
    #[serde(default)]
    include_restored: bool,
}

/// One archive row with its decrypted value.
#[derive(Serialize, ToSchema)]
pub(super) struct ArchiveValue {
    #[serde(flatten)]
    row: ArchiveRow,
    /// The archived value (its JSON form: number, text, boolean, array).
    #[schema(value_type = Object)]
    value: Value,
}

/// `POST .../recovery-archive/restore`.
#[derive(Deserialize, ToSchema)]
pub(super) struct RestoreFieldBody {
    entity: String,
    /// The field name as archived.
    field: String,
    /// Only values archived at or after this time.
    #[serde(default)]
    archived_after: Option<chrono::DateTime<chrono::Utc>>,
}

/// What a restore did.
#[derive(Debug, Default, Serialize, ToSchema)]
pub(super) struct RestoreCounts {
    restored: u64,
    /// The record's field has a value now; never overwritten.
    skipped_filled: u64,
    /// The archived value does not fit the field's current type.
    skipped_not_convertible: u64,
    /// The record no longer exists.
    missing_records: u64,
    /// Unrestored rows left for another request (per-field only).
    remaining: i64,
}

fn ring(state: &EngineState) -> Result<&attome_config::KeyRing, AppError> {
    recovery_archive::ring(state.base.config.as_ref())
        .ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))
}

/// Stable refusal of a restore of an expired row (L5).
const ARCHIVE_EXPIRED: &str =
    "archive_expired: the value is past its 30 days and can no longer be restored";

/// Whether `ctx` may read the archived value (M1): the interactive field
/// gate, sensitive when the value was sealed sensitive or the live field is
/// sensitive now.
fn value_readable(
    ctx: &attome_server::security::SecurityContext,
    entity: &str,
    field: &str,
    sealed_sensitive: bool,
    live_sensitive: bool,
) -> bool {
    attome_security::field_gate::field_readable(
        ctx,
        entity,
        field,
        sealed_sensitive || live_sensitive,
        None,
        attome_security::field_gate::Surface::Interactive,
    )
}

/// List archived values
///
/// List archived values. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/recovery-archive",
    tag = "admin",
    params(ArchiveFilter, OnePageQuery),
    responses(
        (status = 200, description = "Archive rows (values not included), newest first", body = PaginatedResponse<ArchiveRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 422, description = "Unknown reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_archive(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(filter): Query<ArchiveFilter>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ArchiveRow>>, AppError> {
    if let Some(r) = filter.reason.as_deref()
        && recovery_archive::ArchiveReason::parse(r).is_none()
    {
        return Err(AppError::Validation(
            "reason: must be field_deleted or conversion_nulled".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let predicate = "($1::text IS NULL OR entity_logicalname = $1) \
         AND ($2::text IS NULL OR field_logicalname = $2) \
         AND ($3::text IS NULL OR reason = $3) \
         AND ($4 OR restored_at IS NULL)";
    let rows: Vec<ArchiveRow> = sqlx::query_as(&format!(
        "SELECT {ARCHIVE_ROW_COLUMNS} FROM recovery_archive WHERE {predicate} \
         ORDER BY archived_at DESC, id DESC LIMIT $5 OFFSET $6"
    ))
    .bind(&filter.entity)
    .bind(&filter.field)
    .bind(&filter.reason)
    .bind(filter.include_restored)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM recovery_archive WHERE {predicate}"
    ))
    .bind(&filter.entity)
    .bind(&filter.field)
    .bind(&filter.reason)
    .bind(filter.include_restored)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

/// One archived value
///
/// One archive row with its decrypted value. Reading a value is audited
/// (Security, `recovery_archive.read`, the row id — never the value).
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/recovery-archive/{archive_id}",
    tag = "admin",
    params(("archive_id" = Uuid, Path, description = "The archive row")),
    responses(
        (status = 200, description = "The row and its decrypted value", body = ArchiveValue),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin, or the field is sensitive and the caller holds no field-security read grant for it", body = ErrorResponse),
        (status = 404, description = "No such row (purged or expired)", body = ErrorResponse),
        (status = 409, description = "archive_key_missing or archive_value_unreadable", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_archive_value(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(archive_id): Path<Uuid>,
) -> Result<Json<ArchiveValue>, AppError> {
    let ring = ring(&state)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (row, value_enc) = recovery_archive::get_with_value(&mut tx, archive_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if recovery_archive::is_expired(&row, chrono::Utc::now()) {
        return Err(AppError::NotFound);
    }
    let opened = recovery_archive::open(ring, &row, &value_enc)?;
    let live = resolve_target(&mut tx, &row).await?;
    let (field, live_sensitive) = match &live {
        Some(t) => (t.name.as_str(), t.is_sensitive),
        None => (row.field_logicalname.as_str(), false),
    };
    if !value_readable(
        &ctx,
        &row.entity_logicalname,
        field,
        opened.sensitive,
        live_sensitive,
    ) {
        return Err(AppError::Forbidden);
    }
    let value = opened.value;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Export,
            ctx.user_id,
            "recovery_archive",
            Some(archive_id),
        )
        .named("recovery_archive.read")
        .comment(format!(
            "recovery-archive value read: {}.{} record {}",
            row.entity_logicalname, row.field_logicalname, row.record_id
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(ArchiveValue { row, value }))
}

/// The live target of an archive row.
struct LiveField {
    entity_id: Uuid,
    name: String,
    field_type: FieldType,
    options: Option<Value>,
    is_sensitive: bool,
}

/// The live target of an archive row: by its `attribute_id` (a type change
/// keeps it), else by `(entity, field name)` (a deleted field re-added).
async fn resolve_target(
    conn: &mut sqlx::PgConnection,
    row: &ArchiveRow,
) -> Result<Option<LiveField>, AppError> {
    let found: Option<(Uuid, String, i32, Option<Value>, bool)> = sqlx::query_as(
        r#"SELECT e.id, a.logicalname, COALESCE(a."type", 3), a.options,
                  COALESCE(a.is_sensitive, false)
           FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref
           WHERE (a.is_active IS NULL OR a.is_active = true)
             AND (e.is_active IS NULL OR e.is_active = true)
             AND a.logicalname IS NOT NULL
             AND (a.id = $1 OR (e.logicalname = $2 AND a.logicalname = $3))
           ORDER BY (a.id = $1) DESC LIMIT 1"#,
    )
    .bind(row.attribute_id)
    .bind(&row.entity_logicalname)
    .bind(&row.field_logicalname)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(
        found.map(|(entity_id, name, t, options, is_sensitive)| LiveField {
            entity_id,
            name,
            field_type: FieldType::from_int(t).unwrap_or(FieldType::Text),
            options,
            is_sensitive,
        }),
    )
}

/// The archived JSON value as the target type wants it, or `None`.
fn convert_for(value: &Value, target: FieldType, options: Option<&Value>) -> Option<Value> {
    let as_text = || match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    match target {
        FieldType::Text | FieldType::RichText | FieldType::Icon | FieldType::Color => {
            as_text().map(Value::String)
        }
        FieldType::Number | FieldType::Currency => match value {
            Value::Number(_) => Some(value.clone()),
            Value::String(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .and_then(|f| serde_json::Number::from_f64(f).map(Value::Number)),
            _ => None,
        },
        FieldType::Bool => match value {
            Value::Bool(_) => Some(value.clone()),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "t" | "yes" | "1" => Some(Value::Bool(true)),
                "false" | "f" | "no" | "0" => Some(Value::Bool(false)),
                _ => None,
            },
            _ => None,
        },
        // Y2-T1: a day column reads back as `YYYY-MM-DD`.
        FieldType::Date => match value {
            Value::String(s) => {
                let s = s.trim();
                (chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
                    || chrono::DateTime::parse_from_rfc3339(s).is_ok())
                .then(|| Value::String(s.to_owned()))
            }
            _ => None,
        },
        FieldType::Time => match value {
            Value::String(s) if attome_field::time_ok(s.trim()) => {
                Some(Value::String(s.trim().to_owned()))
            }
            _ => None,
        },
        FieldType::DateTime => match value {
            Value::String(s) => chrono::DateTime::parse_from_rfc3339(s.trim())
                .ok()
                .map(|_| Value::String(s.trim().to_owned())),
            _ => None,
        },
        FieldType::Choice => {
            let choices = attome_metadata::provision::field_change::choices_of(options);
            match value {
                Value::String(s) if choices.contains(s) => Some(value.clone()),
                Value::Array(items)
                    if items
                        .iter()
                        .all(|i| i.as_str().is_some_and(|s| choices.iter().any(|c| c == s))) =>
                {
                    Some(value.clone())
                }
                _ => None,
            }
        }
        _ => Some(value.clone()),
    }
}

pub(super) enum RestoreOne {
    Restored,
    Filled,
    NotConvertible,
    MissingRecord,
    Already,
    Expired,
}

/// Restores one archive row in its own transaction (see the module doc).
pub(super) async fn restore_row(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    actor: Uuid,
    archive_id: Uuid,
) -> Result<RestoreOne, AppError> {
    let ring = ring(state)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some((row, value_enc)) = recovery_archive::get_with_value(&mut tx, archive_id).await?
    else {
        return Err(AppError::NotFound);
    };
    if row.restored_at.is_some() {
        return Ok(RestoreOne::Already);
    }
    if recovery_archive::is_expired(&row, chrono::Utc::now()) {
        return Ok(RestoreOne::Expired);
    }
    let Some(LiveField {
        entity_id,
        name: field,
        field_type,
        options,
        ..
    }) = resolve_target(&mut tx, &row).await?
    else {
        return Err(AppError::Conflict(
            "restore_target_missing: the field no longer exists; re-add it first",
        ));
    };
    let value = recovery_archive::open(ring, &row, &value_enc)?.value;
    let Some(value) = convert_for(&value, field_type, options.as_ref()) else {
        return Ok(RestoreOne::NotConvertible);
    };
    let entity = row.entity_logicalname.clone();
    let current: Option<(i64, bool)> = sqlx::query_as(&format!(
        "SELECT row_version, {col} IS NULL FROM {table} WHERE id = $1 FOR UPDATE",
        col = attome_core::quote_ident(&field),
        table = attome_core::quote_ident(&entity)
    ))
    .bind(row.record_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((row_version, empty)) = current else {
        return Ok(RestoreOne::MissingRecord);
    };
    if !empty {
        return Ok(RestoreOne::Filled);
    }
    let attrs = state
        .entities
        .load()
        .get(&entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::Conflict(
            "restore_target_missing: the entity is not in the metadata registry",
        ))?;
    let mut obj = serde_json::Map::new();
    obj.insert(field.clone(), value);
    attome_records::entity_mutation::update_one(
        &mut tx,
        state,
        ctx,
        &entity,
        entity_id,
        row.record_id,
        &attrs,
        &obj,
        actor,
        row_version,
        attome_records::entity_mutation::MutationMode::Strict,
    )
    .await?;
    recovery_archive::mark_restored(&mut tx, archive_id, actor).await?;
    // The release-report item this value belongs to is `restored` once none
    // of its values is left (either Restore route).
    attome_core::release_report::on_archive_restored(&mut tx, row.report_item_ref, actor).await?;
    // L2: the restore's `Configuration` event, in the restore's own
    // transaction (the record's own `Update` event is written by
    // `update_one` above). Ids only, never the value.
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            actor,
            "recovery_archive",
            Some(archive_id),
        )
        .named("recovery_archive.restore")
        .comment(format!(
            "recovery-archive value restored into {entity}.{field} record {}",
            row.record_id
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(RestoreOne::Restored)
}

pub(super) fn tally(counts: &mut RestoreCounts, one: RestoreOne) {
    match one {
        RestoreOne::Restored => counts.restored += 1,
        RestoreOne::Filled => counts.skipped_filled += 1,
        RestoreOne::NotConvertible => counts.skipped_not_convertible += 1,
        RestoreOne::MissingRecord => counts.missing_records += 1,
        // Selected unexpired, expired before its turn: left for the purge.
        RestoreOne::Already | RestoreOne::Expired => {}
    }
}

/// Restore one archived value
///
/// Restores one archived value (fills an empty target only).
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/recovery-archive/{archive_id}/restore",
    tag = "admin",
    params(("archive_id" = Uuid, Path, description = "The archive row")),
    responses(
        (status = 200, description = "Restored, or skipped (counts say why)", body = RestoreCounts),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such row", body = ErrorResponse),
        (status = 409, description = "restore_target_missing, restore_not_convertible, archive_expired, archive_value_unreadable or archive_key_missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn restore_one(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(archive_id): Path<Uuid>,
) -> Result<Json<RestoreCounts>, AppError> {
    let one = restore_row(&state, &ctx, ctx.user_id, archive_id).await?;
    match one {
        RestoreOne::NotConvertible => {
            return Err(AppError::Conflict(
                "restore_not_convertible: the archived value does not fit the field's current type",
            ));
        }
        RestoreOne::Expired => return Err(AppError::Conflict(ARCHIVE_EXPIRED)),
        _ => {}
    }
    let mut counts = RestoreCounts::default();
    tally(&mut counts, one);
    Ok(Json(counts))
}

/// Restore a field's archived values
///
/// Restores every unexpired, unrestored value of a field (fills empty
/// targets only), up to [`MAX_RESTORE_PER_REQUEST`] per request.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/recovery-archive/restore",
    tag = "admin",
    request_body = RestoreFieldBody,
    responses(
        (status = 200, description = "Counts; `remaining > 0` means repeat the request", body = RestoreCounts),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 409, description = "restore_target_missing or archive_key_missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn restore_field(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<RestoreFieldBody>,
) -> Result<Json<RestoreCounts>, AppError> {
    ring(&state)?;
    let mut counts = RestoreCounts::default();
    let mut cursor: Option<Uuid> = None;
    let mut done: i64 = 0;
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM recovery_archive \
             WHERE entity_logicalname = $1 AND field_logicalname = $2 AND restored_at IS NULL \
               AND expires_at > now() AND ($3::timestamptz IS NULL OR archived_at >= $3) \
               AND ($4::uuid IS NULL OR id > $4) \
             ORDER BY id LIMIT 500",
        )
        .bind(&body.entity)
        .bind(&body.field)
        .bind(body.archived_after)
        .bind(cursor)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            let one = restore_row(&state, &ctx, ctx.user_id, *id).await?;
            tally(&mut counts, one);
            done += 1;
        }
        cursor = ids.last().copied();
        if done >= MAX_RESTORE_PER_REQUEST {
            break;
        }
    }
    counts.remaining = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_archive \
         WHERE entity_logicalname = $1 AND field_logicalname = $2 AND restored_at IS NULL \
           AND expires_at > now() AND ($3::timestamptz IS NULL OR archived_at >= $3) \
           AND ($4::uuid IS NULL OR id > $4)",
    )
    .bind(&body.entity)
    .bind(&body.field)
    .bind(body.archived_after)
    .bind(cursor)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    tracing::info!(
        entity = %body.entity, field = %body.field, restored = counts.restored,
        skipped_filled = counts.skipped_filled,
        skipped_not_convertible = counts.skipped_not_convertible,
        missing_records = counts.missing_records, remaining = counts.remaining,
        "recovery archive: per-field restore request done (each value audited in its own restore)"
    );
    Ok(Json(counts))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/metadata/recovery-archive", get(list_archive))
        .route(
            "/api/v1/admin/metadata/recovery-archive/restore",
            post(restore_field),
        )
        .route(
            "/api/v1/admin/metadata/recovery-archive/{archive_id}",
            get(get_archive_value),
        )
        .route(
            "/api/v1/admin/metadata/recovery-archive/{archive_id}/restore",
            post(restore_one),
        )
}

/// This file's slice of the OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_archive, get_archive_value, restore_one, restore_field))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with(is_admin: bool, grants: &[&str]) -> attome_server::security::SecurityContext {
        attome_server::security::SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: std::collections::HashSet::new(),
            field_grants: grants.iter().map(|s| s.to_string()).collect(),
            field_write_grants: std::collections::HashSet::new(),
            bulk_fields: attome_server::security::BulkFields::Legacy,
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: std::collections::HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    #[test]
    fn an_archived_value_is_gated_like_a_read_of_its_field() {
        // Security review M1: the same decision as a record read (D-111,
        // `field_gate`, interactive surface). A sensitive value (sealed
        // sensitive, or the live field sensitive now) needs the read grant;
        // `has_field_read_grant` admits `system.admin` exactly as a record
        // read does.
        let plain = ctx_with(false, &[]);
        assert!(!value_readable(&plain, "contact", "salary", true, false));
        assert!(!value_readable(&plain, "contact", "salary", false, true));
        assert!(value_readable(&plain, "contact", "phone", false, false));
        let granted = ctx_with(false, &["contact.salary"]);
        assert!(value_readable(&granted, "contact", "salary", true, false));
        assert!(!value_readable(&granted, "contact", "ssn", true, false));
        let admin = ctx_with(true, &[]);
        assert!(value_readable(&admin, "contact", "salary", true, true));
    }

    #[test]
    fn archived_values_convert_to_the_current_type_or_are_refused() {
        assert_eq!(
            convert_for(&json!(12.5), FieldType::Text, None),
            Some(json!("12.5"))
        );
        assert_eq!(
            convert_for(&json!("12.5"), FieldType::Number, None),
            Some(json!(12.5))
        );
        assert_eq!(convert_for(&json!("abc"), FieldType::Number, None), None);
        assert_eq!(
            convert_for(&json!("yes"), FieldType::Bool, None),
            Some(json!(true))
        );
        let options = json!({ "choices": ["gold", "silver"] });
        assert_eq!(
            convert_for(&json!("gold"), FieldType::Choice, Some(&options)),
            Some(json!("gold"))
        );
        assert_eq!(
            convert_for(&json!("bronze"), FieldType::Choice, Some(&options)),
            None
        );
        assert_eq!(
            convert_for(&json!("2026-09-30T10:00:00Z"), FieldType::Date, None),
            Some(json!("2026-09-30T10:00:00Z"))
        );
    }
}

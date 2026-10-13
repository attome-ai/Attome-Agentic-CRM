//! `/api/v1/admin/entities/{entity_id}/labels` — M05 Phase 1 (D-426).
//!
//! Per-locale overrides of an entity's own display name, its attributes'
//! display names, and (for a `choice` attribute) individual choice-option
//! labels — the Entity Manager label editor's backing API. Scoped to one
//! entity at a time (mirrors the checklist's `/admin/entities/{id}/labels`
//! shape): `object_kind='sidebar'/'dashboard'`/`'view'` labels are out of
//! this route's scope even though `metadata_label` itself carries
//! them (D-426) — nothing in this phase edits those object kinds yet.
//!
//! Same admin-metadata-object posture as `calendar_admin.rs`/`view_admin.rs`:
//! its own CRUD, not a generic XRM entity, bundle-exportable via
//! `bundle::export::export_labels` (export-only for now, mirroring
//! `SettingDef`/`COMPONENT_SETTING` — see that module's doc comment).

use attome_core::{
    EngineState, acquire_label_write_lock, append_label_change_log, is_valid_locale_tag,
    load_all_labels,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_core::changeset::{Layer, Op, RecordedOp, Recording, RecordingCtx};
use attome_records::query_admin::map_unique_violation;

/// The enumerated columns of a [`LabelDetail`] read.
const LABEL_COLUMNS: &str =
    "id, object_kind, object_ref, locale, display_name, description, row_version, owner_layer";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
struct LabelDetail {
    id: Uuid,
    object_kind: String,
    /// Full stored key — `"{entity_logicalname}"` for `entity`,
    /// `"{entity_logicalname}.{attribute_logicalname}"` for `attribute`,
    /// `"{entity_logicalname}.{attribute_logicalname}.{option_value}"` for
    /// `choice_option`.
    object_ref: String,
    locale: String,
    display_name: String,
    description: Option<String>,
    row_version: i64,
    /// Solution 7 (D-785): the layer that owns this label —
    /// `platform | product | project | customer`.
    owner_layer: String,
}

#[derive(Deserialize, ToSchema)]
struct LabelBody {
    /// `entity`, `attribute`, or `choice_option` — the only kinds this route
    /// accepts (see the module doc).
    object_kind: String,
    /// Required for `attribute`/`choice_option`; ignored for `entity` (the
    /// entity's own logicalname is always used).
    #[serde(default)]
    attribute_logicalname: Option<String>,
    /// Required for `choice_option` only.
    #[serde(default)]
    option_value: Option<String>,
    /// BCP-47 tag, e.g. `"ar-AE"` — validated with
    /// `attome_core::is_valid_locale_tag`.
    locale: String,
    display_name: String,
    #[serde(default)]
    description: Option<String>,
}

const ENTITY_SCOPED_KINDS: &[&str] = &["entity", "attribute", "choice_option"];

/// Resolves `body`'s target into the entity's own logicalname, the full
/// `object_ref` string, and validates the reference actually exists — never
/// trusts a client-supplied ref past that check.
async fn resolve_object_ref(
    db: &attome_db::DbPool,
    entity_id: Uuid,
    entity_logicalname: &str,
    body: &LabelBody,
) -> Result<String, AppError> {
    if !ENTITY_SCOPED_KINDS.contains(&body.object_kind.as_str()) {
        return Err(AppError::Validation(format!(
            "object_kind must be one of {ENTITY_SCOPED_KINDS:?} on this route"
        )));
    }
    match body.object_kind.as_str() {
        "entity" => Ok(entity_logicalname.to_owned()),
        "attribute" => {
            let attr = body.attribute_logicalname.as_deref().unwrap_or("");
            if attr.is_empty() {
                return Err(AppError::Validation(
                    "attribute_logicalname is required for object_kind = \"attribute\"".into(),
                ));
            }
            ensure_attribute_exists(db, entity_id, attr, None).await?;
            Ok(format!("{entity_logicalname}.{attr}"))
        }
        "choice_option" => {
            let attr = body.attribute_logicalname.as_deref().unwrap_or("");
            let option = body.option_value.as_deref().unwrap_or("");
            if attr.is_empty() || option.is_empty() {
                return Err(AppError::Validation(
                    "attribute_logicalname and option_value are required for \
                     object_kind = \"choice_option\""
                        .into(),
                ));
            }
            ensure_attribute_exists(db, entity_id, attr, Some(option)).await?;
            Ok(format!("{entity_logicalname}.{attr}.{option}"))
        }
        _ => unreachable!("checked by ENTITY_SCOPED_KINDS above"),
    }
}

/// Confirms `attribute_logicalname` is a live attribute of `entity_id`. When
/// `option_value` is given, also confirms the attribute is a `choice` field
/// (type 7/8, matching `schema.rs::int_to_type`) whose `options.choices`
/// array contains it — so a typo in a choice_option label's target never
/// silently creates an unreachable row.
async fn ensure_attribute_exists(
    db: &attome_db::DbPool,
    entity_id: Uuid,
    attribute_logicalname: &str,
    option_value: Option<&str>,
) -> Result<(), AppError> {
    let row: Option<(i32, Option<Value>)> = sqlx::query_as(
        "SELECT \"type\", options FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(attribute_logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((field_type, options)) = row else {
        return Err(AppError::Validation(format!(
            "'{attribute_logicalname}' is not a live attribute of this entity"
        )));
    };
    if let Some(option_value) = option_value {
        if !matches!(field_type, 7 | 8) {
            return Err(AppError::Validation(format!(
                "'{attribute_logicalname}' is not a choice field"
            )));
        }
        let known = options
            .as_ref()
            .and_then(|o| o.get("choices"))
            .and_then(|c| c.as_array())
            .is_none_or(|choices| choices.iter().any(|c| c.as_str() == Some(option_value)));
        if !known {
            return Err(AppError::Validation(format!(
                "'{option_value}' is not one of '{attribute_logicalname}''s declared choices"
            )));
        }
    }
    Ok(())
}

/// Resolves `entity_id` to its live logicalname, 404ing on an unknown or
/// retired entity — shared by every handler below.
async fn resolve_entity_logicalname(
    db: &attome_db::DbPool,
    entity_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT logicalname FROM entity_info \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?
    .filter(|s| !s.is_empty())
    .ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/labels",
    tag = "admin",
    params(("entity_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<LabelDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_labels(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<Vec<LabelDetail>>, AppError> {
    let logicalname = resolve_entity_logicalname(&state.base.db_migrator, entity_id).await?;
    let prefix = format!("{logicalname}.");
    let rows: Vec<LabelDetail> = sqlx::query_as(
        "SELECT id, object_kind, object_ref, locale, display_name, description, row_version, \
                owner_layer \
         FROM metadata_label \
         WHERE is_deleted = FALSE \
           AND ((object_kind = 'entity' AND object_ref = $1) \
             OR (object_kind IN ('attribute', 'choice_option') AND object_ref LIKE $2)) \
         ORDER BY object_kind, object_ref, locale",
    )
    .bind(&logicalname)
    .bind(format!("{prefix}%"))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(rows))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/labels",
    tag = "admin",
    params(("entity_id" = Uuid, Path)),
    request_body = LabelBody,
    responses(
        (status = 201, description = "Success", body = LabelDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown entity", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Create)])))),
)]
async fn create_label(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<LabelBody>,
) -> Result<(StatusCode, Json<LabelDetail>), AppError> {
    let logicalname = resolve_entity_logicalname(&state.base.db_migrator, entity_id).await?;
    validate_label_fields(&body)?;
    let object_ref =
        resolve_object_ref(&state.base.db_migrator, entity_id, &logicalname, &body).await?;

    let row = write_label(
        &state,
        &recording,
        &body.object_kind,
        &object_ref,
        &body,
        &logicalname,
        ctx.user_id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/entities/{entity_id}/labels/{label_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path), ("label_id" = Uuid, Path)),
    request_body = LabelBody,
    responses(
        (status = 200, description = "Success", body = LabelDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown entity or label", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
async fn update_label(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, label_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<LabelBody>,
) -> Result<Json<LabelDetail>, AppError> {
    let logicalname = resolve_entity_logicalname(&state.base.db_migrator, entity_id).await?;
    validate_label_fields(&body)?;
    let object_ref =
        resolve_object_ref(&state.base.db_migrator, entity_id, &logicalname, &body).await?;

    // The identity triple (object_kind, object_ref, locale) is immutable once
    // created — a PATCH that names a different one would silently retarget
    // the row rather than update it, so require it to match what `label_id`
    // already carries.
    let current: Option<(String, String, String)> = sqlx::query_as(
        "SELECT object_kind, object_ref, locale FROM metadata_label \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(label_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((current_kind, current_ref, current_locale)) = current else {
        return Err(AppError::NotFound);
    };
    if current_kind != body.object_kind
        || current_ref != object_ref
        || current_locale != body.locale
    {
        return Err(AppError::Validation(
            "a label's object_kind/target/locale cannot be changed after creation — \
             delete it and create a new one instead"
                .into(),
        ));
    }

    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    acquire_label_write_lock(&mut tx, &body.object_kind, &object_ref, &body.locale).await?;
    // Solution 7: only the owning layer may change a label (checked under
    // the label lock; the transaction rolls back on refusal).
    let owner_layer: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM metadata_label \
         WHERE id = $1 AND is_deleted = FALSE FOR UPDATE",
    )
    .bind(label_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(owner_layer) = owner_layer else {
        return Err(AppError::NotFound);
    };
    recording.check_owner(parse_layer(&owner_layer)?)?;
    let changed = sqlx::query(
        "UPDATE metadata_label \
         SET display_name = $2, description = $3, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(label_id)
    .bind(body.display_name.trim())
    .bind(body.description.as_deref().map(str::trim))
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    append_label_change_log(&mut tx, &body.object_kind, &object_ref, &body.locale, false).await?;
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(logicalname.clone()),
                record_id: Some(label_id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("metadata_label_updated".to_owned()),
                event_comment: Some(format!(
                    "{} label ({object_ref}, {})",
                    body.object_kind, body.locale
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    record_label_op(&mut tx, &recording, Op::SetLabel, label_id).await?;
    attome_db::tx::commit(tx).await?;

    refresh_local_labels(&state).await;

    let row: LabelDetail = sqlx::query_as(&format!(
        "SELECT {LABEL_COLUMNS} FROM metadata_label WHERE id = $1"
    ))
    .bind(label_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/entities/{entity_id}/labels/{label_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path), ("label_id" = Uuid, Path)),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown entity or label", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::SoftDelete)])))),
)]
async fn delete_label(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, label_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let logicalname = resolve_entity_logicalname(&state.base.db_migrator, entity_id).await?;
    let current: Option<(String, String, String)> = sqlx::query_as(
        "SELECT object_kind, object_ref, locale FROM metadata_label \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(label_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((object_kind, object_ref, locale)) = current else {
        return Err(AppError::NotFound);
    };

    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    acquire_label_write_lock(&mut tx, &object_kind, &object_ref, &locale).await?;
    let owner_layer: Option<String> = sqlx::query_scalar(
        "UPDATE metadata_label SET is_deleted = TRUE, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = FALSE \
         RETURNING owner_layer",
    )
    .bind(label_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(owner_layer) = owner_layer else {
        return Err(AppError::NotFound);
    };
    // Solution 7: checked under the label lock; the transaction rolls back
    // on refusal.
    recording.check_owner(parse_layer(&owner_layer)?)?;
    append_label_change_log(&mut tx, &object_kind, &object_ref, &locale, true).await?;
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(logicalname),
                record_id: Some(label_id),
                operation: AuditOperation::SoftDelete,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("metadata_label_deleted".to_owned()),
                event_comment: Some(format!("{object_kind} label ({object_ref}, {locale})")),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    record_label_op(&mut tx, &recording, Op::ClearLabel, label_id).await?;
    attome_db::tx::commit(tx).await?;

    refresh_local_labels(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_label_fields(body: &LabelBody) -> Result<(), AppError> {
    if body.display_name.trim().is_empty() {
        return Err(AppError::Validation("display_name is required".into()));
    }
    if !is_valid_locale_tag(&body.locale) {
        return Err(AppError::Validation(format!(
            "'{}' is not a valid BCP-47 locale tag (expected e.g. \"en\" or \"en-US\")",
            body.locale
        )));
    }
    Ok(())
}

/// Solution 7 Phase 1 (design §3, `set_label`'s executor) — the label write
/// itself, in the caller's transaction: label lock, owner check against a live
/// row for the same key, the upsert (a new row is stamped with `recording`'s
/// layer), and the label change-log row. The caller writes its audit event,
/// records the operation ([`record_label_op`]) and commits; the changeset
/// applier calls this with `Recording::Applying` (stamps, records nothing).
/// Returns the row id.
pub async fn write_label_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    object_kind: &str,
    object_ref: &str,
    locale: &str,
    display_name: &str,
    description: Option<&str>,
) -> Result<Uuid, AppError> {
    acquire_label_write_lock(tx, object_kind, object_ref, locale).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM metadata_label \
         WHERE object_kind = $1 AND object_ref = $2 AND locale = $3 AND is_deleted = FALSE \
         FOR UPDATE",
    )
    .bind(object_kind)
    .bind(object_ref)
    .bind(locale)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(owner_layer) = existing {
        recording.check_owner(parse_layer(&owner_layer)?)?;
    }
    let layer = recording.stamp()?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO metadata_label \
             (object_kind, object_ref, locale, display_name, description, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (object_kind, object_ref, locale) WHERE is_deleted = FALSE \
         DO UPDATE SET display_name = EXCLUDED.display_name, description = EXCLUDED.description, \
             updated_at = NOW(), row_version = metadata_label.row_version + 1 \
         RETURNING id",
    )
    .bind(object_kind)
    .bind(object_ref)
    .bind(locale)
    .bind(display_name)
    .bind(description)
    .bind(layer.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(map_unique_violation)?;

    append_label_change_log(tx, object_kind, object_ref, locale, false).await?;
    Ok(id)
}

/// Appends `set_label` / `clear_label` for the label row `id` (post-write
/// snapshot). MUST be the last statement before commit.
pub async fn record_label_op(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    op: Op,
    id: Uuid,
) -> Result<(), AppError> {
    if !matches!(recording, Recording::Request(_)) {
        return Ok(());
    }
    let snapshot: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
             'id', id, 'object_kind', object_kind, 'object_ref', object_ref, 'locale', locale, \
             'display_name', display_name, 'description', description, \
             'is_deleted', is_deleted, 'row_version', row_version, 'owner_layer', owner_layer) \
         FROM metadata_label WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let target = label_target(&snapshot)?;
    recording
        .record(
            tx,
            RecordedOp {
                op,
                object_kind: "label",
                object_ref: Some(id),
                target,
                snapshot,
                changed: vec!["display_name"],
            },
        )
        .await
}

/// A label's logical key (`object_kind`, `object_key`, `locale`, design §3):
/// the stored `object_ref` is already a logical key (`account`,
/// `account.name`, `account.status.open`), never a UUID.
fn label_target(snapshot: &Value) -> Result<Value, AppError> {
    let field = |name: &str| {
        snapshot
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AppError::internal(format!("label snapshot without {name}")))
    };
    Ok(serde_json::json!({
        "object_kind": field("object_kind")?,
        "object_key": field("object_ref")?,
        "locale": field("locale")?,
    }))
}

fn parse_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value)
        .ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?} on a label")))
}

/// Upserts one label row (create, or replace a soft-deleted row for the same
/// key) inside its own short transaction ([`write_label_in_tx`]), writes the
/// audit event, records `set_label`, and refreshes this node's cache
/// synchronously — same shape as `settings_admin::write_setting`.
async fn write_label(
    state: &EngineState,
    recording: &Recording,
    object_kind: &str,
    object_ref: &str,
    body: &LabelBody,
    entity_logicalname: &str,
    user_id: Uuid,
) -> Result<LabelDetail, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = write_label_in_tx(
        &mut tx,
        recording,
        object_kind,
        object_ref,
        &body.locale,
        body.display_name.trim(),
        body.description.as_deref().map(str::trim),
    )
    .await?;

    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(entity_logicalname.to_owned()),
                record_id: Some(id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("metadata_label_created".to_owned()),
                event_comment: Some(format!(
                    "{object_kind} label ({object_ref}, {})",
                    body.locale
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    record_label_op(&mut tx, recording, Op::SetLabel, id).await?;
    attome_db::tx::commit(tx).await?;

    refresh_local_labels(state).await;

    sqlx::query_as(&format!(
        "SELECT {LABEL_COLUMNS} FROM metadata_label WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Synchronous local cache refresh after a write — other nodes catch up via
/// the poll loop in `system.rs` (`label_store`'s module doc explains why
/// that's poll-only). Failure here is logged and otherwise ignored: the
/// commit already landed, so the worst case is this node self-healing on the
/// next poll tick rather than seeing its own write immediately.
async fn refresh_local_labels(state: &EngineState) {
    match load_all_labels(&state.base.db).await {
        Ok(snapshot) => state.labels.swap(snapshot),
        Err(e) => tracing::warn!(
            error = %e,
            "failed to refresh local metadata-label cache after write — will self-heal on next poll tick",
        ),
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/entities/{entity_id}/labels",
            get(list_labels).post(create_label),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/labels/{label_id}",
            axum::routing::patch(update_label).delete(delete_label),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged upward by `attome_api::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_labels, create_label, update_label, delete_label))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

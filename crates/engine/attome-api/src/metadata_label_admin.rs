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

/// An entity's labels
///
/// An entity's labels. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/labels",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity")),
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

/// Add a label
///
/// Add a label. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/labels",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity")),
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

/// Update a label
///
/// Update a label. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/entities/{entity_id}/labels/{label_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity"), ("label_id" = Uuid, Path, description = "The label")),
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

/// Delete a label
///
/// Delete a label. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/entities/{entity_id}/labels/{label_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity"), ("label_id" = Uuid, Path, description = "The label")),
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

    // A20-T1: the translation remembers the source it translated, so a later
    // change to the source shows it as stale; a person's write is reviewed.
    let source_hash = current_source(tx, object_kind, object_ref)
        .await?
        .map(|source| text_hash(&source));
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO metadata_label \
             (object_kind, object_ref, locale, display_name, description, owner_layer, \
              source_hash, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'reviewed') \
         ON CONFLICT (object_kind, object_ref, locale) WHERE is_deleted = FALSE \
         DO UPDATE SET display_name = EXCLUDED.display_name, description = EXCLUDED.description, \
             source_hash = EXCLUDED.source_hash, status = 'reviewed', \
             updated_at = NOW(), row_version = metadata_label.row_version + 1 \
         RETURNING id",
    )
    .bind(object_kind)
    .bind(object_ref)
    .bind(locale)
    .bind(display_name)
    .bind(description)
    .bind(layer.as_str())
    .bind(source_hash)
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

// ── XLIFF (A20-T4) ───────────────────────────────────────────────────────────

/// One translatable unit: `{object_kind}:{object_ref}`, the default text and
/// the translation, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XliffUnit {
    pub id: String,
    pub source: String,
    pub target: Option<String>,
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The `{name}` placeholders in a text, which a translation must keep.
fn placeholders(text: &str) -> std::collections::BTreeSet<&str> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let after = &rest[open..];
        let Some(close) = after.find('}') else { break };
        out.insert(&after[..=close]);
        rest = &after[close + 1..];
    }
    out
}

/// An XLIFF 2.0 document of `units` from `source_lang` to `target_lang`.
pub(crate) fn build_xliff(source_lang: &str, target_lang: &str, units: &[XliffUnit]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <xliff xmlns=\"urn:oasis:names:tc:xliff:document:2.0\" version=\"2.0\" \
         srcLang=\"{}\" trgLang=\"{}\">\n  <file id=\"attome-labels\">\n",
        xml_escape(source_lang),
        xml_escape(target_lang)
    );
    for unit in units {
        out.push_str(&format!(
            "    <unit id=\"{}\">\n      <segment>\n        <source>{}</source>\n",
            xml_escape(&unit.id),
            xml_escape(&unit.source)
        ));
        if let Some(target) = &unit.target {
            out.push_str(&format!(
                "        <target>{}</target>\n",
                xml_escape(target)
            ));
        }
        out.push_str("      </segment>\n    </unit>\n");
    }
    out.push_str("  </file>\n</xliff>\n");
    out
}

/// The text inside the first `<tag ...>...</tag>` in `xml`, unescaped.
fn element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after_name = &xml[start + open.len()..];
    // `<target>` or `<target state="final">`, never `<targetLanguage>`.
    if !after_name.starts_with(['>', ' ', '\t', '\n', '\r', '/']) {
        return None;
    }
    let body_start = after_name.find('>')?;
    if after_name[..body_start].ends_with('/') {
        return Some(String::new());
    }
    let body = &after_name[body_start + 1..];
    let end = body.find(&format!("</{tag}>"))?;
    Some(xml_unescape(&body[..end]))
}

/// The value of `name="..."` in an element's opening tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')?;
    Some(xml_unescape(&tag[start..start + end]))
}

/// The target language and units of an XLIFF 2.0 document; tolerant of the
/// attributes and whitespace translation tools add, strict about the shape.
pub(crate) fn parse_xliff(xml: &str) -> Result<(String, Vec<XliffUnit>), String> {
    let root_start = xml.find("<xliff").ok_or("not an XLIFF document")?;
    let root_end = xml[root_start..]
        .find('>')
        .ok_or("the xliff element is not closed")?;
    let root = &xml[root_start..root_start + root_end];
    if attribute(root, "version").as_deref() != Some("2.0") {
        return Err("only XLIFF 2.0 is read".into());
    }
    let target_lang = attribute(root, "trgLang").ok_or("trgLang is missing")?;
    let mut units = Vec::new();
    let mut rest = &xml[root_start..];
    while let Some(start) = rest.find("<unit") {
        let unit_xml = &rest[start..];
        let open_end = unit_xml.find('>').ok_or("a unit is not closed")?;
        let id = attribute(&unit_xml[..open_end], "id").ok_or("a unit has no id")?;
        let close = unit_xml.find("</unit>").ok_or("a unit is not closed")?;
        let body = &unit_xml[..close];
        let source =
            element_text(body, "source").ok_or_else(|| format!("unit {id} has no source"))?;
        let target = element_text(body, "target").filter(|t| !t.trim().is_empty());
        units.push(XliffUnit { id, source, target });
        rest = &unit_xml[close + "</unit>".len()..];
    }
    Ok((target_lang, units))
}

/// A20-T1: the hash a translation keeps of the source text it translated.
pub(crate) fn text_hash(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.trim().as_bytes()))
}

/// A20-T1: the text a label of `object_kind` / `object_ref` translates right
/// now: an entity's or attribute's name, or a choice's shown label. `None`
/// for a kind whose source this route does not track.
async fn current_source(
    tx: &mut attome_db::Tx<'_>,
    object_kind: &str,
    object_ref: &str,
) -> Result<Option<String>, AppError> {
    let mut parts = object_ref.splitn(3, '.');
    let (entity, attr, choice) = (parts.next(), parts.next(), parts.next());
    let source: Option<String> = match (object_kind, entity, attr, choice) {
        ("entity", Some(entity), None, None) => sqlx::query_scalar(
            "SELECT COALESCE(name::text, logicalname::text) FROM entity_info \
             WHERE logicalname = $1 AND is_active = true",
        )
        .bind(entity)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?,
        ("attribute", Some(entity), Some(attr), None) => sqlx::query_scalar(
            "SELECT COALESCE(a.name::text, a.logicalname::text) \
             FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname = $1 AND a.logicalname = $2 AND a.is_active = true",
        )
        .bind(entity)
        .bind(attr)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?,
        ("choice_option", Some(entity), Some(attr), Some(choice)) => sqlx::query_scalar(
            "SELECT COALESCE(a.options->'option_labels'->>$3, $3) \
             FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname = $1 AND a.logicalname = $2 AND a.is_active = true",
        )
        .bind(entity)
        .bind(attr)
        .bind(choice)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?,
        _ => None,
    };
    Ok(source)
}

/// A20-T1/T3: where one label-able text stands in a language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct WorkbenchRow {
    /// `<kind>:<object_ref>`, the XLIFF unit id.
    pub key: String,
    pub source: String,
    pub target: Option<String>,
    /// `untranslated`, `stale` (the source changed since it was translated),
    /// `draft` (not yet reviewed) or `reviewed`.
    pub status: &'static str,
}

/// A20-T1: a label's status from its source, translation, stored hash and
/// review state.
pub(crate) fn workbench_status(
    source: &str,
    target: Option<&str>,
    source_hash: Option<&str>,
    reviewed: bool,
) -> &'static str {
    match target {
        None => "untranslated",
        Some(_) if source_hash.is_some_and(|h| h != text_hash(source)) => "stale",
        Some(_) if !reviewed => "draft",
        Some(_) => "reviewed",
    }
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct WorkbenchQuery {
    /// The language, e.g. `ar-SA`.
    locale: String,
    /// `untranslated`, `stale`, `draft` or `reviewed`; all when absent.
    status: Option<String>,
}

/// Label translation workbench
///
/// A20-T3: every entity, attribute and choice label with its translation in
/// `locale` and where it stands (untranslated, stale, draft, reviewed),
/// optionally only one status.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/labels/workbench",
    tag = "admin",
    params(WorkbenchQuery),
    responses(
        (status = 200, description = "Every label with its translation and status", body = attome_types::PaginatedResponse<WorkbenchRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Invalid locale or status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn label_workbench(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Query(query): axum::extract::Query<WorkbenchQuery>,
) -> Result<Json<attome_types::PaginatedResponse<WorkbenchRow>>, AppError> {
    if !is_valid_locale_tag(&query.locale) {
        return Err(AppError::Validation(
            "locale must be a BCP-47 tag like ar-SA".into(),
        ));
    }
    let wanted = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if wanted.is_some_and(|s| !["untranslated", "stale", "draft", "reviewed"].contains(&s)) {
        return Err(AppError::Validation(
            "status is untranslated, stale, draft or reviewed".into(),
        ));
    }
    let items: Vec<WorkbenchRow> = workbench_rows(&state, &query.locale)
        .await?
        .into_iter()
        .map(|(row, _)| row)
        .filter(|row| wanted.is_none_or(|w| row.status == w))
        .collect();
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        total.max(1),
    )))
}

/// Every label-able text in `locale` with its status, and whether its stored
/// translation was reviewed by a person (A20-T2 redraws only unreviewed ones).
pub(crate) async fn workbench_rows(
    state: &EngineState,
    locale: &str,
) -> Result<Vec<(WorkbenchRow, bool)>, AppError> {
    let units = label_units(state, locale).await?;
    let stored: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT object_kind, object_ref, source_hash, status FROM metadata_label \
         WHERE locale = $1 AND is_deleted = false",
    )
    .bind(locale)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let meta: std::collections::HashMap<String, (Option<String>, bool)> = stored
        .into_iter()
        .map(|(kind, reference, hash, status)| {
            (format!("{kind}:{reference}"), (hash, status == "reviewed"))
        })
        .collect();
    Ok(units
        .into_iter()
        .map(|unit| {
            let (hash, reviewed) = meta.get(&unit.id).cloned().unwrap_or((None, true));
            let status = workbench_status(
                &unit.source,
                unit.target.as_deref(),
                hash.as_deref(),
                reviewed,
            );
            let row = WorkbenchRow {
                key: unit.id,
                source: unit.source,
                target: unit.target,
                status,
            };
            (row, reviewed)
        })
        .collect())
}

/// A20-T2: this node's label cache refreshed after drafts were written.
pub(crate) async fn refresh_labels(state: &EngineState) {
    refresh_local_labels(state).await;
}

/// Every label-able text with its default and the `locale` translation.
async fn label_units(state: &EngineState, locale: &str) -> Result<Vec<XliffUnit>, AppError> {
    let db = &state.base.db;
    let entities: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT logicalname::text, name::text FROM entity_info \
         WHERE is_active = true AND logicalname IS NOT NULL ORDER BY logicalname",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let attributes: Vec<(String, String, Option<String>, Option<Value>)> = sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text, a.name::text, a.options \
         FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE a.is_active = true AND e.is_active = true \
         ORDER BY e.logicalname, a.logicalname",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let labels: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT object_kind, object_ref, display_name FROM metadata_label \
         WHERE locale = $1 AND is_deleted = false",
    )
    .bind(locale)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let translated: std::collections::HashMap<String, String> = labels
        .into_iter()
        .map(|(kind, reference, name)| (format!("{kind}:{reference}"), name))
        .collect();
    let unit = |id: String, source: String| XliffUnit {
        target: translated.get(&id).cloned(),
        id,
        source,
    };
    let mut units = Vec::new();
    for (entity, name) in entities {
        units.push(unit(
            format!("entity:{entity}"),
            name.unwrap_or_else(|| entity.clone()),
        ));
    }
    for (entity, attr, name, options) in attributes {
        units.push(unit(
            format!("attribute:{entity}.{attr}"),
            name.unwrap_or_else(|| attr.clone()),
        ));
        let choices = options
            .as_ref()
            .and_then(|o| o.get("choices"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for choice in choices.iter().filter_map(Value::as_str) {
            let shown = options
                .as_ref()
                .and_then(|o| o.get("option_labels"))
                .and_then(|l| l.get(choice))
                .and_then(Value::as_str)
                .unwrap_or(choice);
            units.push(unit(
                format!("choice_option:{entity}.{attr}.{choice}"),
                shown.to_owned(),
            ));
        }
    }
    Ok(units)
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct XliffQuery {
    /// The language to translate into, e.g. `ar-SA`.
    locale: String,
}

/// `POST /api/v1/admin/entities/labels/xliff`: what an import did.
#[derive(Serialize, ToSchema)]
struct XliffImportResult {
    locale: String,
    /// Labels written.
    imported: usize,
    /// Units with no translation, left alone.
    skipped: usize,
    /// Units refused, with why; nothing is written when any unit is refused.
    errors: Vec<String>,
}

/// Export labels as XLIFF
///
/// A20-T4: every entity, attribute and choice label as an XLIFF 2.0 file to
/// translate into `locale`, with the translations already made.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/labels/xliff",
    tag = "admin",
    params(XliffQuery),
    responses(
        (status = 200, description = "The labels as XLIFF 2.0", body = String, content_type = "application/xliff+xml"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Invalid locale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_xliff(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Query(query): axum::extract::Query<XliffQuery>,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;
    if !is_valid_locale_tag(&query.locale) {
        return Err(AppError::Validation(
            "locale must be a BCP-47 tag like ar-SA".into(),
        ));
    }
    let units = label_units(&state, &query.locale).await?;
    let file = format!("attachment; filename=\"labels-{}.xlf\"", query.locale);
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/xliff+xml; charset=utf-8".to_owned(),
            ),
            (axum::http::header::CONTENT_DISPOSITION, file),
        ],
        build_xliff("en", &query.locale, &units),
    )
        .into_response())
}

/// Import translated XLIFF
///
/// A20-T4: reads a translated XLIFF 2.0 file and writes its translations as
/// labels for its `trgLang`. Every unit must name a label that exists and keep
/// its source's `{placeholders}`; if any unit is refused, nothing is written.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/labels/xliff",
    tag = "admin",
    request_body(content = String, content_type = "application/xliff+xml"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the import did", body = XliffImportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Not an XLIFF 2.0 file, or an invalid language", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn import_xliff(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    body: String,
) -> Result<Json<XliffImportResult>, AppError> {
    let (locale, units) = parse_xliff(&body).map_err(AppError::Validation)?;
    if !is_valid_locale_tag(&locale) {
        return Err(AppError::Validation(
            "trgLang must be a BCP-47 tag like ar-SA".into(),
        ));
    }
    let known: std::collections::HashMap<String, String> = label_units(&state, &locale)
        .await?
        .into_iter()
        .map(|u| (u.id, u.source))
        .collect();
    let mut errors = Vec::new();
    let mut writes = Vec::new();
    let mut skipped = 0;
    for unit in &units {
        let Some(target) = unit.target.as_deref().map(str::trim) else {
            skipped += 1;
            continue;
        };
        let Some(source) = known.get(&unit.id) else {
            errors.push(format!("{}: no such label", unit.id));
            continue;
        };
        if placeholders(source) != placeholders(target) {
            errors.push(format!(
                "{}: the translation must keep the placeholders of its source",
                unit.id
            ));
            continue;
        }
        if target.chars().count() > 200 {
            errors.push(format!("{}: a label is at most 200 characters", unit.id));
            continue;
        }
        let Some((kind, reference)) = unit.id.split_once(':') else {
            errors.push(format!("{}: not a label id", unit.id));
            continue;
        };
        writes.push((kind.to_owned(), reference.to_owned(), target.to_owned()));
    }
    if !errors.is_empty() {
        return Ok(Json(XliffImportResult {
            locale,
            imported: 0,
            skipped,
            errors,
        }));
    }
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for (kind, reference, target) in &writes {
        let id =
            write_label_in_tx(&mut tx, &recording, kind, reference, &locale, target, None).await?;
        record_label_op(&mut tx, &recording, Op::SetLabel, id).await?;
    }
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some("metadata_label".to_owned()),
                record_id: None,
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("metadata_labels_imported".to_owned()),
                event_comment: Some(format!("{} label(s) imported for {locale}", writes.len())),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    refresh_local_labels(&state).await;
    Ok(Json(XliffImportResult {
        locale,
        imported: writes.len(),
        skipped,
        errors,
    }))
}

/// B20-T3: whether `key` is a usable interface-text key: dotted words of
/// letters, digits and `_`, at most 200 characters.
pub(crate) fn valid_ui_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 200
        && key.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct UiTextQuery {
    /// The language, e.g. `ar` or `ar-SA`.
    locale: String,
}

/// This deployment's rewordings of built-in interface text in one language.
#[derive(Serialize, ToSchema)]
struct UiTextOverrides {
    locale: String,
    /// Catalogue key (`xrmForm.save`) to the text shown instead.
    #[schema(value_type = Object)]
    texts: std::collections::BTreeMap<String, String>,
}

/// Interface text overrides
///
/// B20-T3: the built-in interface text this deployment rewords, in `locale`,
/// for the app to lay over its own catalogue.
#[utoipa::path(
    get,
    path = "/api/v1/i18n/overrides",
    tag = "admin",
    params(UiTextQuery),
    responses(
        (status = 200, description = "Catalogue key to the deployment's wording", body = UiTextOverrides),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Invalid locale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn ui_text_overrides(
    State(state): State<EngineState>,
    _ctx: Authorized<attome_server::authz::SelfService>,
    axum::extract::Query(query): axum::extract::Query<UiTextQuery>,
) -> Result<Json<UiTextOverrides>, AppError> {
    if !is_valid_locale_tag(&query.locale) {
        return Err(AppError::Validation(
            "locale must be a BCP-47 tag like ar-SA".into(),
        ));
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT object_ref, display_name FROM metadata_label \
         WHERE object_kind = 'ui_text' AND locale = $1 AND is_deleted = false",
    )
    .bind(&query.locale)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(UiTextOverrides {
        locale: query.locale,
        texts: rows.into_iter().collect(),
    }))
}

/// `PUT /api/v1/admin/i18n/overrides`.
#[derive(Deserialize, ToSchema)]
struct UiTextOverride {
    locale: String,
    /// The built-in text's catalogue key, e.g. `xrmForm.save`.
    key: String,
    /// What to show instead, at most 500 characters.
    text: String,
}

/// Reword an interface text
///
/// B20-T3: rewords one built-in interface text in one language.
/// Administrators only.
#[utoipa::path(
    put,
    path = "/api/v1/admin/i18n/overrides",
    tag = "admin",
    request_body = UiTextOverride,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Invalid locale, key or text", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_ui_text_override(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<UiTextOverride>,
) -> Result<StatusCode, AppError> {
    let key = body.key.trim();
    let text = body.text.trim();
    if !is_valid_locale_tag(&body.locale) {
        return Err(AppError::Validation(
            "locale must be a BCP-47 tag like ar-SA".into(),
        ));
    }
    if !valid_ui_key(key) {
        return Err(AppError::Validation(
            "key is a catalogue key like xrmForm.save".into(),
        ));
    }
    if text.is_empty() || text.chars().count() > 500 {
        return Err(AppError::Validation("text is 1 to 500 characters".into()));
    }
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = write_label_in_tx(
        &mut tx,
        &recording,
        "ui_text",
        key,
        &body.locale,
        text,
        None,
    )
    .await?;
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some("metadata_label".to_owned()),
                record_id: Some(id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("ui_text_overridden".to_owned()),
                event_comment: Some(format!("{key} ({})", body.locale)),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    record_label_op(&mut tx, &recording, Op::SetLabel, id).await?;
    attome_db::tx::commit(tx).await?;
    refresh_local_labels(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct UiTextKeyQuery {
    /// The language, such as `ar` or `en`.
    locale: String,
    /// The text's key.
    key: String,
}

/// Restore an interface text
///
/// B20-T3: goes back to the built-in wording of one text in one language.
/// Administrators only.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/i18n/overrides",
    tag = "admin",
    params(UiTextKeyQuery),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "The built-in wording is back"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such override", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_ui_text_override(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    axum::extract::Query(query): axum::extract::Query<UiTextKeyQuery>,
) -> Result<StatusCode, AppError> {
    let key = query.key.trim();
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    acquire_label_write_lock(&mut tx, "ui_text", key, &query.locale).await?;
    let removed: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE metadata_label SET is_deleted = TRUE, updated_at = NOW() \
         WHERE object_kind = 'ui_text' AND object_ref = $1 AND locale = $2 AND is_deleted = FALSE \
         RETURNING id, owner_layer",
    )
    .bind(key)
    .bind(&query.locale)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((id, owner_layer)) = removed else {
        return Err(AppError::NotFound);
    };
    recording.check_owner(parse_layer(&owner_layer)?)?;
    append_label_change_log(&mut tx, "ui_text", key, &query.locale, true).await?;
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some("metadata_label".to_owned()),
                record_id: Some(id),
                operation: AuditOperation::SoftDelete,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: chrono::Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("ui_text_override_cleared".to_owned()),
                event_comment: Some(format!("{key} ({})", query.locale)),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    record_label_op(&mut tx, &recording, Op::ClearLabel, id).await?;
    attome_db::tx::commit(tx).await?;
    refresh_local_labels(&state).await;
    Ok(StatusCode::NO_CONTENT)
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
        .route(
            "/api/v1/admin/entities/labels/xliff",
            get(export_xliff).post(import_xliff),
        )
        .route(
            "/api/v1/admin/entities/labels/workbench",
            get(label_workbench),
        )
        .route("/api/v1/i18n/overrides", get(ui_text_overrides))
        .route(
            "/api/v1/admin/i18n/overrides",
            axum::routing::put(put_ui_text_override).delete(delete_ui_text_override),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged upward by `attome_api::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_labels,
    create_label,
    update_label,
    delete_label,
    export_xliff,
    import_xliff,
    label_workbench,
    ui_text_overrides,
    put_ui_text_override,
    delete_ui_text_override
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod xliff_tests {

    #[test]
    fn ui_text_override_keys_are_catalogue_keys() {
        assert!(super::valid_ui_key("xrmForm.save"));
        assert!(super::valid_ui_key("entityList.showingRange"));
        assert!(!super::valid_ui_key(""));
        assert!(!super::valid_ui_key("a..b"));
        assert!(!super::valid_ui_key("has space"));
        assert!(!super::valid_ui_key("x-y"));
    }

    #[test]
    fn a_label_is_stale_once_its_source_changes() {
        let hash = super::text_hash("Account");
        assert_eq!(
            super::workbench_status("Account", None, None, true),
            "untranslated"
        );
        assert_eq!(
            super::workbench_status("Account", Some("حساب"), Some(&hash), true),
            "reviewed"
        );
        assert_eq!(
            super::workbench_status("Customer", Some("حساب"), Some(&hash), true),
            "stale"
        );
        assert_eq!(
            super::workbench_status("Account", Some("حساب"), Some(&hash), false),
            "draft"
        );
        // A label written before hashes were kept is not called stale.
        assert_eq!(
            super::workbench_status("Account", Some("حساب"), None, true),
            "reviewed"
        );
    }

    use super::*;

    #[test]
    fn xliff_round_trips_and_checks_placeholders() {
        let units = vec![
            XliffUnit {
                id: "entity:account".into(),
                source: "Account".into(),
                target: Some("حساب".into()),
            },
            XliffUnit {
                id: "attribute:account.name".into(),
                source: "Name <of {who}>".into(),
                target: None,
            },
        ];
        let xml = build_xliff("en", "ar-SA", &units);
        assert!(xml.contains("trgLang=\"ar-SA\""));
        assert!(xml.contains("Name &lt;of {who}&gt;"));
        let (lang, back) = parse_xliff(&xml).unwrap();
        assert_eq!(lang, "ar-SA");
        assert_eq!(back, units);

        // What a translation tool sends back: attributes on the target.
        let edited = xml.replace(
            "<source>Name &lt;of {who}&gt;</source>",
            "<source>Name &lt;of {who}&gt;</source><target state=\"translated\">اسم {who}</target>",
        );
        let (_, edited) = parse_xliff(&edited).unwrap();
        assert_eq!(edited[1].target.as_deref(), Some("اسم {who}"));
        assert_eq!(placeholders("اسم {who}"), placeholders("Name <of {who}>"));
        assert_ne!(placeholders("اسم"), placeholders("Name {who}"));
        assert!(parse_xliff("<xliff version=\"1.2\">").is_err());
    }
}

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_core::changeset::{Op, Recording, RecordingCtx};
use attome_core::{EngineState, FieldType};
use attome_metadata::provision;
use attome_metadata::provision::{
    AttributeDesc, RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT, ReconcilePolicy, RecordAs,
    valid_identifier,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::{audit_service, notify_metadata_change, pin_write_best_effort, simple_field_change};
use attome_types::ErrorResponse;
use utoipa::ToSchema;

/// D-195/P-four-eyes-approval §5 step 9 — the `action_type` for both
/// creating a field and changing an existing one (`do_create_attribute`/
/// `do_update_attribute` below share this one action_type; the approval
/// payload's `"op"` discriminator tells `execute_approved` which to
/// dispatch to). Deliberately gates the mutation, not the `dry_run`
/// estimate — a dry run has no side effect regardless of approval config
/// (see `create_attribute`/`update_attribute`'s doc comments), so it is
/// never routed through this gate.
pub(crate) const ACTION_SCHEMA_CHANGE: &str = "schema.attribute_change";

/// Tables at or below this size finish quickly enough to retain the existing
/// synchronous admin experience. Larger tables use the durable apalis path.
const ATTRIBUTE_INDEX_INLINE_ROW_LIMIT: i64 = 10_000;
// P-online-schema-change §4(a): the size gate fed to
// `provision::classify_schema_change`, which decides whether
// `create_attribute`/`update_attribute` runs `evolve_attribute_schema`
// inline or queues an `ApplySchemaChangePlan` job (Steps 2-5 — see that
// plan's Status line for what's landed). C-20: `RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT`
// (imported above) used to be duplicated here as a second, separately
// defined `const SCHEMA_CHANGE_INLINE_ROW_LIMIT: i64 = 10_000` — same
// value, same untuned posture, but the copy in the wrong direction:
// `attome-api` can see `attome-metadata`'s constant, so it imports it instead of
// keeping its own. Deliberately still a separate constant from
// `ATTRIBUTE_INDEX_INLINE_ROW_LIMIT` above, even though both start at the
// same value — an index build and a `VALIDATE CONSTRAINT`/`SET NOT NULL`
// scan have different per-row cost profiles and may need to diverge once
// load-test evidence exists.

// ── Type mapping (attribute_info.type INTEGER → XRM field type string) ──
// (the string → INTEGER half lives in `attome_metadata::provision`, which owns the
// row write since the reconcile rewiring)
//
// C-16 (M01 §7): the map itself lives once on `attome_core::FieldType`;
// this is just the `&str` adapter this handler's read paths need.

fn int_to_type(t: i32) -> &'static str {
    FieldType::from_int(t).unwrap_or(FieldType::Text).as_str()
}

// ── DB row shapes ─────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AttrRow {
    id: Uuid,
    entity_ref: Option<Uuid>,
    logicalname: Option<String>,
    name: Option<String>,
    #[sqlx(rename = "type")]
    field_type_int: Option<i32>,
    required: Option<bool>,
    is_sensitive: Option<bool>,
    is_write_restricted: Option<bool>,
    is_sortable: Option<bool>,
    is_filterable: Option<bool>,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    lookup_entity_name: Option<String>,
    is_active: Option<bool>,
    on_target_delete: Option<String>,
    data_classification: Option<String>,
    purpose: Option<String>,
    options: Option<serde_json::Value>,
    owner_layer: String,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AttributeMeta {
    id: Uuid,
    entity_id: Uuid,
    logicalname: String,
    name: String,
    field_type: String,
    is_required: bool,
    is_sensitive: bool,
    /// D-507: writing this field's value needs a field-security `can_update`
    /// grant, but reading it does not (unlike `is_sensitive`, which gates
    /// both and masks audit values).
    is_write_restricted: bool,
    is_sortable: bool,
    is_filterable: bool,
    sort_order: i32,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    lookup_entity_name: Option<String>,
    is_active: bool,
    /// P-data-lifecycle item (c): `"restrict" | "orphan" | "cascade-deactivate"`
    /// — meaningless for a non-lookup field, always present regardless
    /// (matches the column's `NOT NULL DEFAULT 'orphan'`).
    on_target_delete: String,
    /// P-data-protection-governance §4: `"general" | "personal" |
    /// "sensitive_special_category"` — additive to `is_sensitive` above
    /// (which keeps its narrower audit-masking-only meaning). Always
    /// present, matching the column's `NOT NULL DEFAULT 'general'`.
    data_classification: String,
    /// Developer-facing note on why this field exists / what it's used for —
    /// locale-less, internal, distinct from `metadata_label`'s
    /// per-locale end-user-presentation `description` (D-426). `None` when
    /// never set.
    purpose: Option<String>,
    options: Option<serde_json::Value>,
    /// Solution 7 (D-785): the layer that owns this field —
    /// `platform | product | project | customer`. Only a changeset of this
    /// layer may change or retire it.
    owner_layer: String,
}

impl std::fmt::Debug for AttributeMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributeMeta").finish_non_exhaustive()
    }
}

/// The current state of the supporting sortable/filterable index. This is
/// intentionally a separately polled resource: `AttributeMeta` remains a
/// metadata contract, while queue and Postgres catalog state are transient.
#[derive(Serialize, ToSchema)]
pub(super) struct AttributeIndexStatus {
    /// `not_requested`, `queued`, `building`, `ready`, `invalid`, `failed`, or
    /// `missing`.
    status: &'static str,
}

/// P-online-schema-change §4(c). Deliberately no numeric row count: the
/// underlying probe (`provision::table_row_count_exceeds`) only ever learns
/// "is this table over the threshold", not an exact count — doing an exact
/// `COUNT(*)` on a large table would itself be the expensive scan this whole
/// plan exists to avoid, so this response doesn't fabricate a number it
/// can't honestly report.
#[derive(Serialize)]
struct SchemaChangeEstimate {
    /// `"cheap"` or `"expensive"`.
    classification: &'static str,
    exceeds_row_threshold: bool,
    will_require_backfill: bool,
}

fn schema_change_estimate(classification: provision::ChangeClassification) -> SchemaChangeEstimate {
    match classification {
        provision::ChangeClassification::Cheap => SchemaChangeEstimate {
            classification: "cheap",
            exceeds_row_threshold: false,
            will_require_backfill: false,
        },
        provision::ChangeClassification::Expensive { needs_backfill } => SchemaChangeEstimate {
            classification: "expensive",
            exceeds_row_threshold: true,
            will_require_backfill: needs_backfill,
        },
    }
}

/// P-online-schema-change §4(d) — separately polled resource, same reasoning
/// as `AttributeIndexStatus` above.
#[derive(Serialize, ToSchema)]
pub(super) struct SchemaChangeStatus {
    /// `not_requested | queued | claimed | backfilling | altering | succeeded | failed`.
    status: &'static str,
    error_message: Option<String>,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct CreateAttributeBody {
    logicalname: String,
    name: String,
    field_type: String,
    #[serde(default)]
    is_required: bool,
    #[serde(default)]
    is_sensitive: bool,
    /// D-507. Omitted → `false`.
    #[serde(default)]
    is_write_restricted: bool,
    #[serde(default)]
    is_sortable: bool,
    #[serde(default)]
    is_filterable: bool,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    /// P-data-lifecycle item (c). Omitted → the column's own default,
    /// `"orphan"` (today's behavior).
    on_target_delete: Option<String>,
    /// P-data-protection-governance §4. Omitted → the column's own default,
    /// `"general"`.
    data_classification: Option<String>,
    /// Developer-facing note on why this field exists / what it's used for.
    /// Omitted → `NULL`. Distinct from the label-store `description`
    /// (D-426) — see `AttributeMeta::purpose`'s doc comment.
    purpose: Option<String>,
    /// F004/F012: `ChoiceOptions`/`TextOptions` shape, validated against
    /// `field_type` via `attome_field::validate_options` before persisting.
    options: Option<serde_json::Value>,
    /// P-online-schema-change §4(c) — classification-only: no metadata
    /// write, no DDL, no job enqueue. Returns a `SchemaChangeEstimate`.
    #[serde(default)]
    dry_run: bool,
    /// P-online-schema-change §4(b) — value to backfill pre-existing `NULL`s
    /// with, ahead of the terminal `SET NOT NULL`, when this change is
    /// classified `Expensive`. Only consulted on that path; a JSON scalar
    /// only (`provision::validate_backfill_default`).
    default_value: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateAttributeBody {
    /// Solution 7 Phase 2 (D-788): a changed `logicalname` renames the field
    /// in place (`rename_field`, the same executor as `POST .../rename`):
    /// the column is renamed and every reference follows. Omitted = unchanged.
    #[serde(default)]
    logicalname: Option<String>,
    name: Option<String>,
    field_type: Option<String>,
    is_required: Option<bool>,
    /// P-environment-promotion §5 step 13: updatable at last (it was not
    /// before — neither here nor in the UPDATE). A downgrade (`true` ->
    /// `false`) loosens audit masking and field-security eligibility, so it
    /// is a protection downgrade: it goes through exactly the same
    /// `schema.attribute_change` approval gate every other field edit on
    /// this route does (`update_attribute` gates the whole non-dry-run PATCH
    /// behind `ACTION_SCHEMA_CHANGE` before the body is even parsed) — no new
    /// action type, and a deployment that requires two people for schema
    /// changes requires them for this too.
    is_sensitive: Option<bool>,
    /// D-507. Omitted → unchanged. Clearing it is a protection downgrade and
    /// rides the same `schema.attribute_change` gate as `is_sensitive` above.
    is_write_restricted: Option<bool>,
    is_sortable: Option<bool>,
    is_filterable: Option<bool>,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    on_target_delete: Option<String>,
    data_classification: Option<String>,
    /// Omitted → left unchanged (same "absent means no change" convention
    /// every other `Option<String>` field on this body uses).
    purpose: Option<String>,
    options: Option<serde_json::Value>,
    #[serde(default)]
    dry_run: bool,
    default_value: Option<serde_json::Value>,
}

// ── Validation ────────────────────────────────────────────────────────────────

/// U9 checklist item 3: the one field-type validator, shared with
/// `attome-metadata`'s reconcile (`provision::valid_field_type`, which reads
/// `FieldType::NAMES`) — this used to be a second hand-copied list.
use provision::valid_field_type;

/// B-R6 (D-604): a formula's value is computed, so it is never `required`
/// and has no `max_length`. Checked up front (reconcile re-checks) so an
/// `Expensive` contract change is never queued for one.
fn check_formula_contract(
    field_type: &str,
    is_required: bool,
    max_length: Option<i32>,
) -> Result<(), AppError> {
    if field_type != FieldType::Formula.as_str() {
        return Ok(());
    }
    if is_required {
        return Err(AppError::Validation(
            "a formula field cannot be required (its value is computed)".into(),
        ));
    }
    if max_length.is_some() {
        return Err(AppError::Validation(
            "max_length does not apply to a formula field".into(),
        ));
    }
    Ok(())
}

/// P-data-lifecycle item (c) — must match `attribute_info`'s `CHECK`
/// constraint (migration `0028_lookup_delete_semantics.sql`) exactly.
fn valid_on_target_delete(s: &str) -> bool {
    matches!(s, "restrict" | "orphan" | "cascade-deactivate")
}

/// P-data-protection-governance §4 — must match `attribute_info`'s
/// `CHECK` constraint (migration `0087_data_classification.sql`) exactly.
fn valid_data_classification(s: &str) -> bool {
    matches!(s, "general" | "personal" | "sensitive_special_category")
}

/// F004/F012: shape-checks a candidate `options` blob against `field_type`
/// BEFORE it's ever persisted (`attome_field::validate_options`) — a malformed
/// mask pattern or choice list is a 422 at attribute-create/update time, not
/// a surprise the first time a record write runs `attome_field::validate`
/// against it. No-op when `options` is absent.
fn validate_attribute_options(
    field_type: &str,
    options: &Option<serde_json::Value>,
) -> Result<(), AppError> {
    let Some(options) = options else {
        return Ok(());
    };
    let ft = FieldType::try_from(field_type)
        .map_err(|e| AppError::Validation(format!("invalid field_type: {e}")))?;
    attome_field::validate_options(&ft, options)
}

/// L7.2: whether a PATCH body sets any property besides `logicalname` (and
/// `dry_run`, which is not a change). A rename must travel alone — see
/// `do_update_attribute_recorded`.
fn update_body_changes_more_than_logicalname(body: &UpdateAttributeBody) -> bool {
    let UpdateAttributeBody {
        logicalname: _,
        name,
        field_type,
        is_required,
        is_sensitive,
        is_write_restricted,
        is_sortable,
        is_filterable,
        max_length,
        lookup_entity_ref,
        on_target_delete,
        data_classification,
        purpose,
        options,
        dry_run: _,
        default_value,
    } = body;
    name.is_some()
        || field_type.is_some()
        || is_required.is_some()
        || is_sensitive.is_some()
        || is_write_restricted.is_some()
        || is_sortable.is_some()
        || is_filterable.is_some()
        || max_length.is_some()
        || lookup_entity_ref.is_some()
        || on_target_delete.is_some()
        || data_classification.is_some()
        || purpose.is_some()
        || options.is_some()
        || default_value.is_some()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn attr_from_row(r: AttrRow, index: i32) -> AttributeMeta {
    AttributeMeta {
        id: r.id,
        entity_id: r.entity_ref.unwrap_or_default(),
        logicalname: r.logicalname.unwrap_or_default(),
        name: r.name.unwrap_or_default(),
        field_type: int_to_type(r.field_type_int.unwrap_or(3)).to_owned(),
        is_required: r.required.unwrap_or(false),
        is_sensitive: r.is_sensitive.unwrap_or(false),
        is_write_restricted: r.is_write_restricted.unwrap_or(false),
        is_sortable: r.is_sortable.unwrap_or(false),
        is_filterable: r.is_filterable.unwrap_or(false),
        sort_order: index,
        max_length: r.max_length,
        lookup_entity_ref: r.lookup_entity_ref,
        lookup_entity_name: r.lookup_entity_name,
        is_active: r.is_active.unwrap_or(true),
        on_target_delete: r.on_target_delete.unwrap_or_else(|| "orphan".to_owned()),
        data_classification: r
            .data_classification
            .unwrap_or_else(|| "general".to_owned()),
        purpose: r.purpose,
        options: r.options,
        owner_layer: r.owner_layer,
    }
}

pub(crate) async fn fetch_attributes(
    db: &attome_db::DbPool,
    entity_id: Uuid,
) -> Result<Vec<AttributeMeta>, AppError> {
    let rows: Vec<AttrRow> = sqlx::query_as(
        r#"SELECT a.id, a.entity_ref, a.logicalname, a.name,
                  a."type", a.required, a.is_sensitive, a.is_write_restricted,
                  a.is_sortable, a.is_filterable,
                  a.max_length,
                  a.lookup_entity_ref,
                  lei.name AS lookup_entity_name,
                  a.is_active,
                  a.on_target_delete,
                  a.data_classification,
                  a.purpose,
                  a.options,
                  a.owner_layer
           FROM attribute_info a
           LEFT JOIN entity_info lei ON lei.id = a.lookup_entity_ref
           WHERE a.entity_ref = $1 AND (a.is_active IS NULL OR a.is_active = true)
           ORDER BY a.sort_order ASC, a.created_at ASC NULLS LAST, a.logicalname"#,
    )
    .bind(entity_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| attr_from_row(r, i as i32))
        .collect())
}

// ── Attribute handlers ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SchemaChangePending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

/// D-195: gated behind `approval.required_actions` (empty/off by default,
/// same opt-in shape as every other wired action) — but only for an actual
/// mutation. `dry_run: true` never writes anything (see `CreateAttributeBody
/// ::dry_run`'s doc comment) and is answered directly, ungated, regardless
/// of approval config: gating a read-only estimate would block a
/// legitimate "what would this cost" preview for no security benefit. When
/// gated, submits an approval request carrying the raw body instead of
/// creating anything and returns `202` with `approval_pending: true` — the
/// attribute-limit/identifier/options validation and the actual
/// provisioning all only run once a different `system.admin` approves it
/// (`do_create_attribute` via `execute_approved`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields",
    tag = "admin",
    params(("entity_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Create)])))),
)]
pub(super) async fn create_attribute(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
    Json(raw_body): Json<Value>,
) -> Result<Response, AppError> {
    let is_dry_run = raw_body
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Solution 7 (D-785): a real write refuses (changeset_required, …)
    // before the approval gate and before any DDL; a dry run records nothing.
    if !is_dry_run {
        recording.preflight(&state.base.db_migrator).await?;
    }
    if !is_dry_run
        && let Some(request) = crate::approval_admin::gate(
            &state,
            ACTION_SCHEMA_CHANGE,
            serde_json::json!({ "op": "create", "entity_id": entity_id, "body": raw_body }),
            ctx.user_id,
        )
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(SchemaChangePending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let body: CreateAttributeBody = serde_json::from_value(raw_body)
        .map_err(|e| AppError::Validation(format!("invalid request body: {e}")))?;
    do_create_attribute_recorded(&state, entity_id, ctx.user_id, body, Some(&*recording)).await
}

/// `add_field` (design §1.1): recorded in the reconcile primitive's final
/// transaction, or — for a size-gated contract — when the contract change is
/// queued (the intent; the job records nothing).
pub(crate) async fn do_create_attribute_recorded(
    state: &EngineState,
    entity_id: Uuid,
    user_id: Uuid,
    body: CreateAttributeBody,
    recording: Option<&Recording>,
) -> Result<Response, AppError> {
    let entity_logicalname: Option<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let entity_logicalname = entity_logicalname.ok_or(AppError::NotFound)?;

    // P-provisioning-hardening item (e): deliberately no `is_active` filter —
    // a soft-deleted attribute's physical column still exists (D-005's
    // delete_attribute is metadata-only), so it still counts toward
    // Postgres's ~1,600 physical-column ceiling. Checked before any write.
    let attr_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?;
    if attr_count >= provision::MAX_ATTRIBUTES_PER_ENTITY {
        return Err(AppError::Validation(format!(
            "entity has reached the attribute limit ({}); deleted attributes count until their columns are purged",
            provision::MAX_ATTRIBUTES_PER_ENTITY
        )));
    }

    let logicalname = body.logicalname.trim().to_lowercase();
    if !valid_identifier(&logicalname) {
        return Err(AppError::Validation(format!(
            "logicalname must be lowercase letters, digits, or underscores, max {} chars",
            provision::MAX_IDENTIFIER_LEN
        )));
    }
    // P-provisioning-hardening item (a): checked BEFORE any metadata write
    // (the attribute_info INSERT happens inside ensure_attribute below,
    // outside this handler's own transaction — see the comment at the
    // ensure_attribute call site) so an oversized entity+field pair 422s with
    // no stranded metadata row.
    // A7-T3: a lookup is always indexed (the FK checks and related lists
    // read it), whatever its sort and filter flags say.
    let is_lookup = body.field_type.trim().eq_ignore_ascii_case("lookup");
    if body.is_sortable || body.is_filterable || is_lookup {
        provision::attribute_index_name(&entity_logicalname, &logicalname)?;
    }
    let display_name = body.name.trim().to_owned();
    if display_name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let field_type = body.field_type.trim().to_lowercase();
    if !valid_field_type(&field_type) {
        return Err(AppError::Validation(format!(
            "field_type must be one of: {}",
            FieldType::NAMES.join(", ")
        )));
    }
    validate_attribute_options(&field_type, &body.options)?;
    if field_type == FieldType::Formula.as_str() && body.options.is_none() {
        return Err(AppError::Validation(
            "a formula field requires options {\"expression\": ..., \"result_type\": ...}".into(),
        ));
    }
    check_formula_contract(&field_type, body.is_required, body.max_length)?;
    if field_type == "lookup" && body.lookup_entity_ref.is_none() {
        return Err(AppError::Validation(
            "lookup fields require lookup_entity_ref".into(),
        ));
    }
    if field_type != "lookup" && body.lookup_entity_ref.is_some() {
        return Err(AppError::Validation(
            "lookup_entity_ref only applies to lookup fields".into(),
        ));
    }

    let on_target_delete = body
        .on_target_delete
        .as_deref()
        .map(str::trim)
        .map(str::to_lowercase)
        .unwrap_or_else(|| "orphan".to_owned());
    if !valid_on_target_delete(&on_target_delete) {
        return Err(AppError::Validation(
            "on_target_delete must be one of: restrict, orphan, cascade-deactivate".into(),
        ));
    }

    let data_classification = body
        .data_classification
        .as_deref()
        .map(str::trim)
        .map(str::to_lowercase)
        .unwrap_or_else(|| "general".to_owned());
    if !valid_data_classification(&data_classification) {
        return Err(AppError::Validation(
            "data_classification must be one of: general, personal, sensitive_special_category"
                .into(),
        ));
    }

    let purpose = body
        .purpose
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // A live field under this logicalname is a 409 up front: the reconcile
    // primitive below is create-or-update by design and would otherwise
    // *update* the existing field to this body (the old `ensure_attribute`
    // path silently returned the existing id). A retired one is fine —
    // reconcile reactivates it (type-checked against its physical column,
    // D-055) rather than creating a second row for the same column.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(entity_id)
    .bind(&logicalname)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Err(AppError::Conflict(
            "a field with this logicalname already exists on this entity",
        ));
    }

    // `AttributeDesc.lookup_entity` is the target's logicalname (the bundle
    // carries logical keys, never ids); the display name feeds the response.
    let lookup_target =
        resolve_lookup_target(&state.base.db_migrator, body.lookup_entity_ref).await?;
    let lookup_entity_name = lookup_target.as_ref().map(|(_, name)| name.clone());

    // P-online-schema-change §4(a)/(c): classify before any write so
    // dry_run can answer with zero side effects, and so the actual write
    // below knows whether the physical contract lands inline (inside
    // `reconcile_attribute`) or through a queued `ApplySchemaChangePlan`.
    let classification = provision::classify_schema_change(
        &state.base.db_migrator,
        &entity_logicalname,
        RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
        body.is_required,
        body.max_length,
    )
    .await?;
    // C-22: a multi-valued (`choice`/`file`, D-078/D-362) column is
    // `TEXT[]`/`JSONB` — `max_length`'s `char_length` CHECK and a backfill
    // default's scalar cast are both meaningless against it, and used to
    // reach Postgres and surface as an opaque internal error instead of this
    // 422. `provision::queue_schema_change_plan_in_tx` re-checks this too
    // (defense in depth for the async path), but failing here lets a bad
    // `dry_run` request see the same rejection instead of a stale estimate.
    let is_multi = provision::is_multi_valued(&field_type, body.options.as_ref());
    if is_multi && body.max_length.is_some() {
        return Err(AppError::Validation(
            "max_length does not apply to multi-valued fields".into(),
        ));
    }
    if let Some(default_value) = &body.default_value {
        provision::validate_backfill_default(default_value, is_multi)?;
    }
    if body.dry_run {
        return Ok((StatusCode::OK, Json(schema_change_estimate(classification))).into_response());
    }
    let expensive = matches!(
        classification,
        provision::ChangeClassification::Expensive { .. }
    );

    let wants_index = body.is_sortable || body.is_filterable || is_lookup;
    let enqueue_index = wants_index
        && provision::attribute_index_requires_async(
            &state.base.db_migrator,
            &entity_logicalname,
            ATTRIBUTE_INDEX_INLINE_ROW_LIMIT,
        )
        .await?;

    // P-environment-promotion §5 step 13: one implementation of "make this
    // field match this description". `reconcile_attribute` (policy `Admin`)
    // registers the row with `is_customized = true` (step 5), provisions the
    // column, appends the change log, and — for a `Cheap` contract — installs
    // `required`/`max_length` inline, retiring the row itself if that DDL is
    // refused (mirrors what this handler used to do by hand). It can't share
    // a transaction with this handler (provisioning may need
    // `CREATE INDEX CONCURRENTLY`), so the audit event and the index job land
    // in a following commit — the same narrow window `create_entity`
    // documents. For an `Expensive` contract the primitive refuses rather
    // than scanning on the request thread, so the row is created with the
    // contract held at its defaults and the target is recorded + queued
    // right after, exactly as `do_update_attribute` does for its own
    // `Expensive` case.
    let desc = AttributeDesc {
        logicalname: logicalname.clone(),
        display_name: display_name.clone(),
        field_type: field_type.clone(),
        is_required: if expensive { false } else { body.is_required },
        is_sensitive: body.is_sensitive,
        is_write_restricted: Some(body.is_write_restricted),
        is_sortable: body.is_sortable,
        is_filterable: body.is_filterable,
        lookup_entity: lookup_target.map(|(logicalname, _)| logicalname),
        options: body.options.clone(),
        max_length: if expensive { None } else { body.max_length },
        on_target_delete: Some(on_target_delete.clone()),
        data_classification: Some(data_classification.clone()),
        purpose: purpose.clone(),
    };
    let (id, _outcome) = provision::reconcile_attribute_recorded(
        &state.base.db_migrator,
        entity_id,
        &desc,
        ReconcilePolicy::Admin,
        None,
        recording.map(|r| {
            if expensive {
                RecordAs::stamp_only(r)
            } else {
                RecordAs::op(r, Op::AddField)
            }
        }),
    )
    .await?;

    if expensive {
        // P-online-schema-change §4(b): record the target contract on the
        // metadata row and queue the durable plan in one short transaction
        // (the plan job reverts to `previous_*` on failure). Physical
        // enforcement lags asynchronously from here; every write path already
        // enforces `is_required`/`max_length` at the application layer via
        // `attome_field::validate` from this commit onward (the plan's documented
        // expand-phase window, §4). If the queue fails, retire the row
        // immediately so no node can observe a field whose contract was
        // neither installed nor scheduled (the nullable column stays for a
        // corrected retry — same recovery the inline path uses).
        if let Err(error) = provision::queue_contract_change_recorded(
            &state.base.db_migrator,
            provision::SchemaChangePlanRequest {
                entity_id,
                attribute_id: id,
                entity_logicalname: &entity_logicalname,
                field_logicalname: &logicalname,
                field_type: &field_type,
                target_required: body.is_required,
                target_max_length: body.max_length,
                previous_required: false,
                previous_max_length: None,
                backfill_default: body.default_value.clone(),
                is_multi,
                created_by: user_id,
            },
            recording.map(|r| RecordAs::op(r, Op::AddField)),
        )
        .await
        {
            // The row was created unrecorded (stamp only), so retiring it
            // unrecorded leaves the changeset describing the database.
            let _ =
                provision::retire_attribute(&state.base.db_migrator, entity_id, &logicalname).await;
            return Err(error);
        }
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribute_info
         WHERE entity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    let owner_layer: String =
        sqlx::query_scalar("SELECT owner_layer FROM attribute_info WHERE id = $1")
            .bind(id)
            .fetch_one(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?;

    // `ensure_default_query` (create_entity) can only ever seed `SELECT id
    // FROM ...` — no attribute exists yet at that point. Once the entity's
    // declared primary_name_attribute itself gets created, give the seeded
    // list view a real display column instead of leaving it id-only forever.
    let primary_name_attribute: Option<String> =
        sqlx::query_scalar("SELECT primary_name_attribute FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?;
    if primary_name_attribute.as_deref() == Some(logicalname.as_str()) {
        provision::set_default_query_display_column(
            &state.base.db_migrator,
            entity_id,
            &entity_logicalname,
            &logicalname,
        )
        .await?;
    }

    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    {
        let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
        if enqueue_index {
            // Used to be enqueued atomically with the metadata INSERT
            // (`ensure_attribute_with_index_job`); it now follows the
            // reconcile commit. A crash between the two leaves a field
            // whose flags ask for an index that was never queued —
            // `index-status` reports it as `missing`, and toggling the flag
            // off and on re-queues it.
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::BuildAttributeIndex {
                    entity_logicalname: entity_logicalname.clone(),
                    field_logicalname: logicalname.clone(),
                },
            )
            .await
            .map_err(AppError::internal)?;
        }
        audit_service(state)
            .write_in_tx(
                &mut tx,
                AuditEvent {
                    organization_ref: org_ref,
                    category: AuditCategory::Entity,
                    entity_name: Some(entity_logicalname.clone()),
                    record_id: Some(id),
                    operation: AuditOperation::Create,
                    version_before: None,
                    version_after: None,
                    user_context: user_ctx,
                    changed_on: Utc::now(),
                    source: AuditSource::Api,
                    request_context: AuditRequestContext::default(),
                    correlation_id: None,
                    batch_id: None,
                    event_name: Some("attribute_created".to_owned()),
                    event_comment: Some(format!(
                        "created field {logicalname} on {entity_logicalname}"
                    )),
                    changed_fields: vec![
                        simple_field_change("logicalname", None, Some(logicalname.clone())),
                        simple_field_change("name", None, Some(display_name.clone())),
                        simple_field_change("field_type", None, Some(field_type.clone())),
                        simple_field_change(
                            "is_required",
                            None,
                            Some(body.is_required.to_string()),
                        ),
                    ],
                    snapshot_json: None,
                },
            )
            .await?;
        attome_db::tx::commit(tx).await?;
    }

    if wants_index && !enqueue_index {
        provision::sync_attribute_index(
            state.base.config.as_ref(),
            &entity_logicalname,
            &logicalname,
            true,
        )
        .await?;
    }
    // A29-T1: an external id is unique among the entity's live records.
    if attome_field::is_unique(body.options.as_ref()) {
        provision::sync_external_id_index(
            state.base.config.as_ref(),
            &entity_logicalname,
            &logicalname,
        )
        .await?;
    }

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(state, user_id, "create attribute").await;

    Ok((
        StatusCode::CREATED,
        Json(AttributeMeta {
            id,
            entity_id,
            logicalname,
            name: display_name,
            field_type,
            is_required: body.is_required,
            is_sensitive: body.is_sensitive,
            is_write_restricted: body.is_write_restricted,
            is_sortable: body.is_sortable,
            is_filterable: body.is_filterable,
            sort_order: (count - 1) as i32,
            max_length: body.max_length,
            lookup_entity_ref: body.lookup_entity_ref,
            lookup_entity_name,
            is_active: true,
            on_target_delete,
            data_classification,
            purpose,
            options: body.options,
            owner_layer,
        }),
    )
        .into_response())
}

/// Resolves a client-supplied `lookup_entity_ref` to the live target's
/// `(logicalname, display name)` — the reconcile primitive takes the
/// logicalname (bundles carry logical keys), the response echoes the name.
/// `None` in, `None` out; an id that names no live entity is a 422.
async fn resolve_lookup_target(
    db: &attome_db::DbPool,
    lookup_entity_ref: Option<Uuid>,
) -> Result<Option<(String, String)>, AppError> {
    let Some(lref) = lookup_entity_ref else {
        return Ok(None);
    };
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT logicalname, name FROM entity_info \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(lref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match row {
        Some((Some(logicalname), name)) => Ok(Some((logicalname, name.unwrap_or_default()))),
        _ => Err(AppError::Validation(
            "lookup_entity_ref does not name a live entity".into(),
        )),
    }
}

/// D-195: same gating shape as `create_attribute` above — `dry_run` is
/// always answered directly, ungated; a real change goes through
/// `ACTION_SCHEMA_CHANGE`.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn update_attribute(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
    Json(raw_body): Json<Value>,
) -> Result<Response, AppError> {
    let is_dry_run = raw_body
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Solution 7 (D-785): as `create_attribute`.
    if !is_dry_run {
        recording.preflight(&state.base.db_migrator).await?;
    }
    if !is_dry_run
        && let Some(request) = crate::approval_admin::gate(
            &state,
            ACTION_SCHEMA_CHANGE,
            serde_json::json!({
                "op": "update", "entity_id": entity_id, "attr_id": attr_id, "body": raw_body
            }),
            ctx.user_id,
        )
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(SchemaChangePending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let body: UpdateAttributeBody = serde_json::from_value(raw_body)
        .map_err(|e| AppError::Validation(format!("invalid request body: {e}")))?;
    do_update_attribute_recorded(
        &state,
        entity_id,
        attr_id,
        ctx.user_id,
        body,
        Some(&*recording),
    )
    .await
}

/// `update_field` (design §1.1): recorded in the reconcile primitive's final
/// transaction, or — for a size-gated contract change — when the plan is
/// queued (the intent). A field owned by another layer is refused
/// (`layer_mismatch`) before any DDL.
pub(crate) async fn do_update_attribute_recorded(
    state: &EngineState,
    entity_id: Uuid,
    attr_id: Uuid,
    user_id: Uuid,
    body: UpdateAttributeBody,
    recording: Option<&Recording>,
) -> Result<Response, AppError> {
    // D-788: a changed logicalname is a rename in place through the shared
    // executor (`rename_field`), which commits its own transaction (column,
    // references, changeset op). The rest of a PATCH commits separately
    // (reconcile, possibly a queued contract change), so the two cannot be
    // one atomic write: a PATCH that renames must change nothing else
    // (L7.2) — otherwise a rename could commit and the rest then fail
    // validation, leaving a half-applied PATCH.
    if let Some(new_logicalname) = body.logicalname.as_deref() {
        let new_logicalname = new_logicalname.trim().to_lowercase();
        let current: Option<Option<String>> = sqlx::query_scalar(
            "SELECT logicalname FROM attribute_info WHERE id = $1 AND entity_ref = $2",
        )
        .bind(attr_id)
        .bind(entity_id)
        .fetch_optional(&state.base.db_migrator)
        .await
        .map_err(AppError::internal)?;
        let current = current.flatten().ok_or(AppError::NotFound)?;
        if current != new_logicalname {
            if update_body_changes_more_than_logicalname(&body) {
                return Err(AppError::Validation(
                    "a PATCH that changes logicalname (a rename) cannot change anything else: \
                     rename first (or POST .../rename), then PATCH the other properties"
                        .into(),
                ));
            }
            // Both callers (the route and the approval dispatcher) record;
            // a rename is never silently skipped for want of a changeset.
            let recording = recording.ok_or_else(|| {
                AppError::internal("attribute rename requires a changeset recording")
            })?;
            let ctx = crate::field_changes::ChangeCtx {
                recording,
                actor: user_id,
                op: None,
                source: "admin",
            };
            let result = crate::field_changes::rename_field(
                state,
                &ctx,
                entity_id,
                attr_id,
                &new_logicalname,
                body.dry_run,
            )
            .await?;
            if result.error.is_some() || body.dry_run {
                return Ok(structure_response(result));
            }
            audit_structure_change(state, user_id, &result, attr_id).await?;
        }
    }
    let cur: Option<AttrRow> = sqlx::query_as(
        r#"SELECT a.id, a.entity_ref, a.logicalname, a.name,
                  a."type", a.required, a.is_sensitive, a.is_write_restricted,
                  a.is_sortable, a.is_filterable,
                  a.max_length,
                  a.lookup_entity_ref,
                  lei.name AS lookup_entity_name,
                  a.is_active,
                  a.on_target_delete,
                  a.data_classification,
                  a.purpose,
                  a.options,
                  a.owner_layer
           FROM attribute_info a
           LEFT JOIN entity_info lei ON lei.id = a.lookup_entity_ref
           WHERE a.id = $1 AND a.entity_ref = $2
             AND (a.is_active IS NULL OR a.is_active = true)"#,
    )
    .bind(attr_id)
    .bind(entity_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let cur = cur.ok_or(AppError::NotFound)?;

    let entity_logicalname: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let entity_logicalname = entity_logicalname.ok_or(AppError::NotFound)?;

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| cur.name.clone().unwrap_or_default());

    let new_ft_str = body
        .field_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .unwrap_or_else(|| int_to_type(cur.field_type_int.unwrap_or(3)).to_owned());

    let current_ft = int_to_type(cur.field_type_int.unwrap_or(3));
    if new_ft_str != current_ft {
        // D-788: a type change is an in-place conversion with its own route
        // (values that do not convert are archived and reported).
        return Err(AppError::Conflict(
            "type_change_needs_route: change a field's type with POST \
             /api/v1/admin/entities/{entity_id}/fields/{field_id}/change-type",
        ));
    }

    if !valid_field_type(&new_ft_str) {
        return Err(AppError::Validation("invalid field_type".into()));
    }
    let new_options = body.options.clone().or_else(|| cur.options.clone());
    if let Some(options) = &new_options {
        let ft = FieldType::try_from(new_ft_str.as_str())
            .map_err(|e| AppError::Validation(format!("invalid field_type: {e}")))?;
        attome_field::validate_options(&ft, options)?;
    }
    // A29-T1: becoming an external id needs the live values to be unique
    // already; the unique index is built after the metadata commits.
    // A3-T6: an external id is unique too; either way the field's unique
    // index follows the change.
    let new_unique = attome_field::is_unique(new_options.as_ref());
    let unique_changed = attome_field::is_unique(cur.options.as_ref()) != new_unique;
    let new_req = body
        .is_required
        .unwrap_or_else(|| cur.required.unwrap_or(false));
    let new_sortable = body
        .is_sortable
        .unwrap_or_else(|| cur.is_sortable.unwrap_or(false));
    let new_filterable = body
        .is_filterable
        .unwrap_or_else(|| cur.is_filterable.unwrap_or(false));
    let new_max = body.max_length.or(cur.max_length);
    check_formula_contract(&new_ft_str, new_req, new_max)?;
    let new_lookup_ref = body.lookup_entity_ref.or(cur.lookup_entity_ref);
    if new_ft_str == "lookup" && new_lookup_ref.is_none() {
        return Err(AppError::Validation(
            "lookup fields require lookup_entity_ref".into(),
        ));
    }
    if new_ft_str != "lookup" && new_lookup_ref.is_some() {
        return Err(AppError::Validation(
            "lookup_entity_ref only applies to lookup fields".into(),
        ));
    }
    let new_on_target_delete = body
        .on_target_delete
        .as_deref()
        .map(str::trim)
        .map(str::to_lowercase)
        .unwrap_or_else(|| {
            cur.on_target_delete
                .clone()
                .unwrap_or_else(|| "orphan".to_owned())
        });
    if !valid_on_target_delete(&new_on_target_delete) {
        return Err(AppError::Validation(
            "on_target_delete must be one of: restrict, orphan, cascade-deactivate".into(),
        ));
    }
    let new_data_classification = body
        .data_classification
        .as_deref()
        .map(str::trim)
        .map(str::to_lowercase)
        .unwrap_or_else(|| {
            cur.data_classification
                .clone()
                .unwrap_or_else(|| "general".to_owned())
        });
    if !valid_data_classification(&new_data_classification) {
        return Err(AppError::Validation(
            "data_classification must be one of: general, personal, sensitive_special_category"
                .into(),
        ));
    }
    let new_purpose = body
        .purpose
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| cur.purpose.clone());
    let new_sensitive = body
        .is_sensitive
        .unwrap_or_else(|| cur.is_sensitive.unwrap_or(false));
    let cur_write_restricted = cur.is_write_restricted.unwrap_or(false);
    let new_write_restricted = body.is_write_restricted.unwrap_or(cur_write_restricted);
    let new_lookup = resolve_lookup_target(&state.base.db_migrator, new_lookup_ref).await?;
    let new_lookup_name: Option<String> = new_lookup.as_ref().map(|(_, name)| name.clone());
    let field_logicalname = cur.logicalname.clone().ok_or(AppError::NotFound)?;
    if unique_changed && new_unique {
        let duplicates = provision::count_duplicate_values(
            &state.base.db_migrator,
            &entity_logicalname,
            &field_logicalname,
        )
        .await?;
        if duplicates > 0 {
            return Err(AppError::Validation(format!(
                "{field_logicalname}: {duplicates} value(s) are shared by more than one live \
                 record, so it cannot be unique; fix the duplicates first"
            )));
        }
    }

    let classification = provision::classify_schema_change(
        &state.base.db_migrator,
        &entity_logicalname,
        RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
        new_req,
        new_max,
    )
    .await?;
    // C-22: see `create_attribute`'s identical guard above for why this must
    // run before the `dry_run` early return, not only inside the enqueue path.
    let is_multi = provision::is_multi_valued(&new_ft_str, new_options.as_ref());
    if is_multi && new_max.is_some() {
        return Err(AppError::Validation(
            "max_length does not apply to multi-valued fields".into(),
        ));
    }
    if let Some(default_value) = &body.default_value {
        provision::validate_backfill_default(default_value, is_multi)?;
    }
    if body.dry_run {
        return Ok((StatusCode::OK, Json(schema_change_estimate(classification))).into_response());
    }
    let expensive = matches!(
        classification,
        provision::ChangeClassification::Expensive { .. }
    );

    // A7-T3: a lookup keeps its index whatever its flags say.
    let wants_index = new_sortable || new_filterable || new_ft_str == "lookup";
    let had_index = cur.is_sortable.unwrap_or(false)
        || cur.is_filterable.unwrap_or(false)
        || current_ft == "lookup";
    let index_changed = wants_index != had_index;
    // P-provisioning-hardening item (a): same early check as create_attribute,
    // on the toggle-ON path (either flag going false->true) — before the
    // write below, so an oversized pair 422s with the row left unchanged.
    if index_changed && wants_index {
        provision::attribute_index_name(&entity_logicalname, &field_logicalname)?;
    }
    let enqueue_index = index_changed
        && provision::attribute_index_requires_async(
            &state.base.db_migrator,
            &entity_logicalname,
            ATTRIBUTE_INDEX_INLINE_ROW_LIMIT,
        )
        .await?;

    // P-environment-promotion §5 step 13: the current row + this patch is a
    // full description, and `reconcile_attribute` (policy `Admin`) is the one
    // implementation that makes the row match it — metadata lock, UPDATE with
    // `is_customized = true` (step 5), change log, and for a `Cheap` contract
    // change the inline `evolve_attribute_schema` before the metadata
    // transaction (a refused validation leaves the prior contract visible).
    // `Expensive` skips the contract here (held at the live values, so the
    // primitive classifies nothing) and lands everything else now; the
    // target contract is recorded and queued right after. Field type is
    // never rewritten (checked above, and the primitive refuses too).
    let cur_required = cur.required.unwrap_or(false);
    let desc = AttributeDesc {
        logicalname: field_logicalname.clone(),
        display_name: new_name.clone(),
        field_type: new_ft_str.clone(),
        is_required: if expensive { cur_required } else { new_req },
        is_sensitive: new_sensitive,
        is_write_restricted: Some(new_write_restricted),
        is_sortable: new_sortable,
        is_filterable: new_filterable,
        lookup_entity: new_lookup.map(|(logicalname, _)| logicalname),
        options: new_options.clone(),
        max_length: if expensive { cur.max_length } else { new_max },
        on_target_delete: Some(new_on_target_delete.clone()),
        data_classification: Some(new_data_classification.clone()),
        purpose: new_purpose.clone(),
    };
    let (reconciled_id, _outcome) = provision::reconcile_attribute_recorded(
        &state.base.db_migrator,
        entity_id,
        &desc,
        ReconcilePolicy::Admin,
        None,
        recording.map(|r| {
            if expensive {
                RecordAs::stamp_only(r)
            } else {
                RecordAs::op(r, Op::UpdateField)
            }
        }),
    )
    .await?;
    if reconciled_id != attr_id {
        // The live row for this logicalname is not the one the path named
        // (retired and re-created concurrently) — nothing was written to
        // `attr_id`, so report the loss rather than a success.
        return Err(AppError::Conflict(
            "field was replaced concurrently; reload and retry",
        ));
    }

    if expensive {
        // P-online-schema-change §4(b): the ledger row and the
        // `ApplySchemaChangePlan` job become visible at the same commit as
        // `is_required`/`max_length`'s new values (`queue_contract_change`),
        // so the plan job finds the row already carrying the target it
        // expects and reverts to `previous_*` on failure.
        //
        // Solution 7: the one `update_field` op is recorded here, with the
        // plan (design §4.5). Changes landed by the reconcile above in the
        // same request are part of that op's snapshot.
        provision::queue_contract_change_recorded(
            &state.base.db_migrator,
            provision::SchemaChangePlanRequest {
                entity_id,
                attribute_id: attr_id,
                entity_logicalname: &entity_logicalname,
                field_logicalname: &field_logicalname,
                field_type: &new_ft_str,
                target_required: new_req,
                target_max_length: new_max,
                previous_required: cur_required,
                previous_max_length: cur.max_length,
                backfill_default: body.default_value.clone(),
                is_multi,
                created_by: user_id,
            },
            recording.map(|r| RecordAs::op(r, Op::UpdateField)),
        )
        .await?;
    }

    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    let mut changed_fields = Vec::new();
    if cur.name.as_deref() != Some(new_name.as_str()) {
        changed_fields.push(simple_field_change(
            "name",
            cur.name.clone(),
            Some(new_name.clone()),
        ));
    }
    if cur_required != new_req {
        changed_fields.push(simple_field_change(
            "is_required",
            Some(cur_required.to_string()),
            Some(new_req.to_string()),
        ));
    }
    if cur.is_sensitive.unwrap_or(false) != new_sensitive {
        changed_fields.push(simple_field_change(
            "is_sensitive",
            Some(cur.is_sensitive.unwrap_or(false).to_string()),
            Some(new_sensitive.to_string()),
        ));
    }
    if cur_write_restricted != new_write_restricted {
        changed_fields.push(simple_field_change(
            "is_write_restricted",
            Some(cur_write_restricted.to_string()),
            Some(new_write_restricted.to_string()),
        ));
    }
    if cur.is_sortable.unwrap_or(false) != new_sortable {
        changed_fields.push(simple_field_change(
            "is_sortable",
            Some(cur.is_sortable.unwrap_or(false).to_string()),
            Some(new_sortable.to_string()),
        ));
    }
    if cur.is_filterable.unwrap_or(false) != new_filterable {
        changed_fields.push(simple_field_change(
            "is_filterable",
            Some(cur.is_filterable.unwrap_or(false).to_string()),
            Some(new_filterable.to_string()),
        ));
    }
    if cur.max_length != new_max {
        changed_fields.push(simple_field_change(
            "max_length",
            cur.max_length.map(|v| v.to_string()),
            new_max.map(|v| v.to_string()),
        ));
    }
    if cur.lookup_entity_ref != new_lookup_ref {
        changed_fields.push(simple_field_change(
            "lookup_entity_ref",
            cur.lookup_entity_ref.map(|v| v.to_string()),
            new_lookup_ref.map(|v| v.to_string()),
        ));
    }
    if cur.on_target_delete.as_deref().unwrap_or("orphan") != new_on_target_delete {
        changed_fields.push(simple_field_change(
            "on_target_delete",
            cur.on_target_delete.clone(),
            Some(new_on_target_delete.clone()),
        ));
    }
    if cur.data_classification.as_deref().unwrap_or("general") != new_data_classification {
        changed_fields.push(simple_field_change(
            "data_classification",
            cur.data_classification.clone(),
            Some(new_data_classification.clone()),
        ));
    }
    if cur.purpose != new_purpose {
        changed_fields.push(simple_field_change(
            "purpose",
            cur.purpose.clone(),
            new_purpose.clone(),
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    if enqueue_index {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::BuildAttributeIndex {
                entity_logicalname: entity_logicalname.clone(),
                field_logicalname: field_logicalname.clone(),
            },
        )
        .await
        .map_err(AppError::internal)?;
    }
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(entity_logicalname.clone()),
                record_id: Some(attr_id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: None,
                event_comment: None,
                changed_fields,
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;

    // P1.11(h): index sync runs after commit, outside the transaction, on the
    // pool directly — CREATE/DROP INDEX CONCURRENTLY cannot run inside a
    // transaction block. Only touches DDL when the flag pair actually
    // changed, so a no-op update never issues a CONCURRENTLY statement
    // against a live table.
    if index_changed && !enqueue_index {
        provision::sync_attribute_index(
            state.base.config.as_ref(),
            &entity_logicalname,
            &field_logicalname,
            wants_index,
        )
        .await?;
    }

    if unique_changed {
        provision::sync_external_id_index(
            state.base.config.as_ref(),
            &entity_logicalname,
            &field_logicalname,
        )
        .await?;
    }

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(state, user_id, "update attribute").await;

    Ok(Json(AttributeMeta {
        id: attr_id,
        entity_id,
        logicalname: field_logicalname,
        name: new_name,
        field_type: new_ft_str,
        is_required: new_req,
        is_sensitive: new_sensitive,
        is_write_restricted: new_write_restricted,
        is_sortable: new_sortable,
        is_filterable: new_filterable,
        sort_order: 0,
        max_length: new_max,
        lookup_entity_ref: new_lookup_ref,
        lookup_entity_name: new_lookup_name,
        is_active: true,
        on_target_delete: new_on_target_delete,
        data_classification: new_data_classification,
        purpose: new_purpose,
        options: new_options,
        owner_layer: cur.owner_layer,
    })
    .into_response())
}

/// Reports the durable-job and PostgreSQL-catalog state for an attribute's
/// supporting index. Admin-only because this exposes operational queue state.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/index-status",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success", body = AttributeIndexStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn attribute_index_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<AttributeIndexStatus>, AppError> {
    let attribute: Option<(String, String, bool)> = sqlx::query_as(
        r#"SELECT e.logicalname,
                  a.logicalname,
                  (COALESCE(a.is_sortable, false) OR COALESCE(a.is_filterable, false)
                   OR a."type" = 11)
             FROM attribute_info a
             JOIN entity_info e ON e.id = a.entity_ref
            WHERE a.id = $1 AND a.entity_ref = $2
              AND (a.is_active IS NULL OR a.is_active = true)
              AND (e.is_active IS NULL OR e.is_active = true)"#,
    )
    .bind(attr_id)
    .bind(entity_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    let (entity_logicalname, field_logicalname, wanted) = attribute.ok_or(AppError::NotFound)?;
    if !wanted {
        return Ok(Json(AttributeIndexStatus {
            status: "not_requested",
        }));
    }

    // A lookup is always indexed (A7-T3), and a long name is hashed to fit.
    let index_name = provision::attribute_index_name(&entity_logicalname, &field_logicalname)?;
    let building: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index p JOIN pg_class c ON c.oid = p.index_relid WHERE c.relname = $1)",
    )
    .bind(&index_name)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if building {
        return Ok(Json(AttributeIndexStatus { status: "building" }));
    }

    let valid: Option<bool> = sqlx::query_scalar(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid WHERE c.relname = $1 AND t.relname = $2",
    )
    .bind(&index_name)
    .bind(&entity_logicalname)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if valid == Some(true) {
        return Ok(Json(AttributeIndexStatus { status: "ready" }));
    }

    let job: Option<(String, i32, i32)> = sqlx::query_as(
        "SELECT status, attempts, max_attempts FROM apalis.jobs WHERE job_type = $1 AND job @> $2::jsonb ORDER BY run_at DESC LIMIT 1",
    )
    .bind("attome_job")
    .bind(serde_json::json!({
        "BuildAttributeIndex": {
            "entity_logicalname": entity_logicalname,
            "field_logicalname": field_logicalname,
        }
    }))
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let status = match (valid, job) {
        (_, Some((job_status, attempts, max_attempts)))
            if job_status == "Failed" && attempts >= max_attempts =>
        {
            "failed"
        }
        (Some(false), _) => "invalid",
        (_, Some(_)) => "queued",
        (None, None) => "missing",
        // `Some(true)` returned early above; retain an exhaustive fallback if
        // this function is rearranged later.
        (Some(true), None) => "ready",
    };
    Ok(Json(AttributeIndexStatus { status }))
}

/// P-online-schema-change §4(d). Deliberately reads its own dedicated
/// ledger row rather than deriving state the way `attribute_index_status`
/// derives from `pg_stat_progress_create_index`/`pg_index` above: there is
/// no Postgres system view analogous to that for a generic `ALTER TABLE`/
/// `VALIDATE CONSTRAINT`, and the backfill phase's per-batch progress
/// (`backfill_cursor`) has nowhere else to live. This is not a second copy
/// of catalog truth (the objection `index-status`'s own no-shadow-column
/// design correctly avoided, D-083) — it is the only place this information
/// exists at all.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/schema-change-status",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success", body = SchemaChangeStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn attribute_schema_change_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<SchemaChangeStatus>, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attribute_info WHERE id = $1 AND entity_ref = $2)",
    )
    .bind(attr_id)
    .bind(entity_id)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }

    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status, error_message FROM schema_change_operation \
         WHERE attribute_ref = $1 AND is_deleted = false \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(attr_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let Some((status, error_message)) = row else {
        return Ok(Json(SchemaChangeStatus {
            status: "not_requested",
            error_message: None,
        }));
    };

    let status = match status.as_str() {
        "claimed" => "claimed",
        "backfilling" => "backfilling",
        "altering" => "altering",
        "succeeded" => "succeeded",
        "failed" => "failed",
        // "queued", and a defensive fallback for any future/unrecognized
        // status value — never panic on operational data from the ledger.
        _ => "queued",
    };
    Ok(Json(SchemaChangeStatus {
        status,
        error_message,
    }))
}

/// Solution 7 Phase 2 (D-788 rules 4 and 9): a **real delete**. The
/// field's non-null values are copied to the encrypted 30-day recovery
/// archive, its references are removed (ours must already be gone — they
/// block, listed; customer objects are adjusted and reported), the column is
/// dropped and the attribute row deleted, in one transaction (above the
/// size gate the archive copy runs as a batched run: `202` with `run_id`).
/// `?dry_run=true` returns the archive count, the references and the
/// blockers without writing. Recorded as `delete_field`. Gated like every
/// schema change (`schema.attribute_change`).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
        DryRunQuery,
    ),
    responses(
        (status = 200, description = "Deleted (values archived), or the dry-run report", body = crate::field_changes::FieldChangeResult),
        (status = 202, description = "Large table: the archive copy runs as a batched run (`run_id`), or approval pending"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Blocked (`field_referenced`, `field_in_use`, `archive_key_missing`, listed in `blockers`), no changeset to record into, or the field is owned by another layer", body = crate::field_changes::FieldChangeResult),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::HardDelete)])))),
)]
pub(super) async fn delete_attribute(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
    axum::extract::Query(query): axum::extract::Query<DryRunQuery>,
) -> Result<Response, AppError> {
    let body = serde_json::json!({ "dry_run": query.dry_run });
    structure_route(
        &state,
        &ctx,
        &recording,
        entity_id,
        attr_id,
        StructureAction::Delete,
        body,
    )
    .await
}

// ── Solution 7 Phase 2: structure changes (D-788) ───────────────────────────

/// `?dry_run=`.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct DryRunQuery {
    /// Report what the change would do (counts, references, blockers)
    /// without writing.
    #[serde(default)]
    dry_run: bool,
}

/// `POST .../fields/{field_id}/rename`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct RenameFieldBody {
    /// The new logical and column name (`^[a-z][a-z0-9_]*$`).
    new_name: String,
    #[serde(default)]
    dry_run: bool,
}

/// The conversion of `POST .../fields/{field_id}/change-type`
/// (`args.conversion` of `change_field_type`).
#[derive(Deserialize, ToSchema)]
pub(crate) struct ConversionBody {
    /// The type the caller expects the field to have now; `type_drift` when
    /// it differs. Omitted = the live type.
    #[serde(default)]
    from_type: Option<String>,
    /// text <-> date: `iso8601 | dd/mm/yyyy | mm/dd/yyyy | dd.mm.yyyy`.
    #[serde(default)]
    format: Option<String>,
    /// text -> bool.
    #[serde(default)]
    true_values: Option<Vec<String>>,
    #[serde(default)]
    false_values: Option<Vec<String>>,
    /// text -> choice: source text -> choice value (the values become the
    /// field's choices).
    #[serde(default)]
    map: Option<std::collections::BTreeMap<String, String>>,
}

/// `POST .../fields/{field_id}/change-type`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct ChangeTypeBody {
    /// `text | number | currency | date | bool | choice | rich_text`.
    field_type: String,
    #[serde(default)]
    conversion: Option<ConversionBody>,
    #[serde(default)]
    dry_run: bool,
}

/// `POST .../fields/{field_id}/choices`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct AddChoiceBody {
    /// The stored value (1..100 chars). Re-adding a removed value is allowed.
    value: String,
    /// Display name (1..200 chars), written as the `choice_option` label
    /// when it differs from the value.
    label: String,
    /// Place after this value; omitted = at the end.
    #[serde(default)]
    after: Option<String>,
    /// `{color, icon}` into `options.choice_styles`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    style: Option<Value>,
    /// The label's locale; omitted = `en`.
    #[serde(default)]
    locale: Option<String>,
}

/// The five structure changes the Phase 2 routes run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructureAction {
    Rename,
    ChangeType,
    Delete,
    AddChoice,
    RemoveChoice,
}

/// The HTTP answer of a structure change: 409 with the result when it was
/// blocked (the `blockers` list why), 202 when a large table continues as a
/// run, 200 otherwise (including a dry run).
pub(crate) fn structure_response(result: crate::field_changes::FieldChangeResult) -> Response {
    let status = if result.error.is_some() {
        StatusCode::CONFLICT
    } else if result.run_id.is_some() && !result.dry_run {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    (status, Json(result)).into_response()
}

/// The shared front half of the Phase 2 routes: refuse before any work
/// (changeset preflight), then the `schema.attribute_change` approval gate
/// (a dry run is never gated), then the change.
async fn structure_route(
    state: &EngineState,
    ctx: &Authorized<Admin>,
    recording: &RecordingCtx,
    entity_id: Uuid,
    attr_id: Uuid,
    action: StructureAction,
    body: Value,
) -> Result<Response, AppError> {
    let is_dry_run = body
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !is_dry_run {
        recording.preflight(&state.base.db_migrator).await?;
        if let Some(request) = crate::approval_admin::gate(
            state,
            ACTION_SCHEMA_CHANGE,
            serde_json::json!({
                "op": "structure", "action": action, "entity_id": entity_id,
                "attr_id": attr_id, "body": body
            }),
            ctx.user_id,
        )
        .await?
        {
            return Ok((
                StatusCode::ACCEPTED,
                Json(SchemaChangePending {
                    approval_pending: true,
                    approval_request_id: request.id,
                }),
            )
                .into_response());
        }
    }
    do_structure_change(
        state,
        ctx.user_id,
        entity_id,
        attr_id,
        action,
        body,
        recording,
    )
    .await
}

fn parse_body<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, AppError> {
    serde_json::from_value(body)
        .map_err(|e| AppError::Validation(format!("invalid request body: {e}")))
}

/// Runs one structure change for the route: [`run_structure_change`]
/// shaped by [`structure_response`] (a blocked change is a 409 carrying the
/// result, so the caller sees the blockers).
async fn do_structure_change(
    state: &EngineState,
    user_id: Uuid,
    entity_id: Uuid,
    attr_id: Uuid,
    action: StructureAction,
    body: Value,
    recording: &Recording,
) -> Result<Response, AppError> {
    let result =
        run_structure_change(state, user_id, entity_id, attr_id, action, body, recording).await?;
    Ok(structure_response(result))
}

/// Runs one structure change (the route and an approved deferred request)
/// and returns its result. A blocked change comes back as `Ok` with
/// `result.error` set: the route answers it as a 409 body, while the
/// approval dispatcher must treat it as a failure (L7.3).
pub(crate) async fn run_structure_change(
    state: &EngineState,
    user_id: Uuid,
    entity_id: Uuid,
    attr_id: Uuid,
    action: StructureAction,
    body: Value,
    recording: &Recording,
) -> Result<crate::field_changes::FieldChangeResult, AppError> {
    use crate::field_changes as changes;
    let ctx = changes::ChangeCtx {
        recording,
        actor: user_id,
        op: None,
        source: "admin",
    };
    let result = match action {
        StructureAction::Rename => {
            let b: RenameFieldBody = parse_body(body)?;
            let new_name = b.new_name.trim().to_lowercase();
            changes::rename_field(state, &ctx, entity_id, attr_id, &new_name, b.dry_run).await?
        }
        StructureAction::ChangeType => {
            let b: ChangeTypeBody = parse_body(body)?;
            let c = b.conversion.unwrap_or(ConversionBody {
                from_type: None,
                format: None,
                true_values: None,
                false_values: None,
                map: None,
            });
            let conv = attome_metadata::provision::field_change::Conversion {
                from_type: c.from_type.unwrap_or_default(),
                to_type: b.field_type.trim().to_lowercase(),
                format: c.format,
                true_values: c.true_values,
                false_values: c.false_values,
                map: c.map,
            };
            changes::change_field_type(state, &ctx, entity_id, attr_id, conv, b.dry_run).await?
        }
        StructureAction::Delete => {
            let dry_run = body
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            changes::delete_field(state, &ctx, entity_id, attr_id, dry_run).await?
        }
        StructureAction::AddChoice => {
            let b: AddChoiceBody = parse_body(body)?;
            let locale = b
                .locale
                .as_deref()
                .unwrap_or(changes::DEFAULT_LABEL_LOCALE)
                .to_owned();
            changes::add_choice(
                state,
                &ctx,
                entity_id,
                attr_id,
                &b.value,
                b.label.trim(),
                b.after.as_deref(),
                b.style.as_ref(),
                &locale,
            )
            .await?
        }
        StructureAction::RemoveChoice => {
            let value = body
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("value is required".into()))?
                .to_owned();
            let dry_run = body
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            changes::remove_choice(state, &ctx, entity_id, attr_id, &value, dry_run).await?
        }
    };
    if result.applied && !result.dry_run {
        audit_structure_change(state, user_id, &result, attr_id).await?;
        pin_write_best_effort(state, user_id, result.op).await;
    }
    Ok(result)
}

/// The `Entity` audit event of a structure change (counts and names, never
/// values), after its commit — the same narrow window `create_attribute`
/// documents for its own post-DDL audit write.
async fn audit_structure_change(
    state: &EngineState,
    user_id: Uuid,
    result: &crate::field_changes::FieldChangeResult,
    attr_id: Uuid,
) -> Result<(), AppError> {
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    let operation = if result.op == "delete_field" {
        AuditOperation::HardDelete
    } else {
        AuditOperation::Update
    };
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(result.entity.clone()),
                record_id: Some(attr_id),
                operation,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some(result.op.to_owned()),
                event_comment: Some(format!(
                    "{} {}.{} (archived {}, nulled {}, run {:?})",
                    result.op,
                    result.entity,
                    result.field,
                    result.archived,
                    result.nulled,
                    result.run_id
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await
}

/// Solution 7 Phase 2 (D-788 rule 3): renames the field **in place** — the
/// column (`ALTER TABLE … RENAME COLUMN`, no data moved), its index and
/// CHECK names, the attribute row, and every reference through the hook
/// registry (views, stored queries, forms, labels, rules, state models,
/// workflows, field security, lineage; customer objects adjusted and
/// reported), in one transaction. No alias: API integrations using the old
/// name break (reported as a breaking change). A reference of ours that
/// cannot be rewritten safely blocks it (409 `rename_blocked_by_reference`,
/// listed). Recorded as `rename_field`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/rename",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    request_body = RenameFieldBody,
    responses(
        (status = 200, description = "Renamed, or the dry-run report", body = crate::field_changes::FieldChangeResult),
        (status = 202, description = "Approval pending"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Blocked by references (listed), the new name exists, the field is busy, or another open changeset touches the entity", body = crate::field_changes::FieldChangeResult),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn rename_attribute(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    structure_route(
        &state,
        &ctx,
        &recording,
        entity_id,
        attr_id,
        StructureAction::Rename,
        body,
    )
    .await
}

/// Solution 7 Phase 2 (D-788 rule 5): converts the field's type **in
/// place**, same name. Values that do not convert become empty (even for a
/// required field — required is application-level), are copied to the
/// encrypted 30-day recovery archive, and are reported. At or under the size
/// gate one transaction; above it a shadow column with a sync trigger is
/// backfilled in batches and swapped (`202` with `run_id`). Runs without
/// business rules or workflows. `dry_run` returns the `not_convertible`
/// count and sample record ids. Recorded as `change_field_type`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/change-type",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    request_body = ChangeTypeBody,
    responses(
        (status = 200, description = "Converted, or the dry-run report", body = crate::field_changes::FieldChangeResult),
        (status = 202, description = "Large table: continues as a batched run (`run_id`), or approval pending"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "`type_drift`, `archive_key_missing`, or the field is busy", body = crate::field_changes::FieldChangeResult),
        (status = 422, description = "`conversion_not_defined` or invalid body", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn change_attribute_type(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    structure_route(
        &state,
        &ctx,
        &recording,
        entity_id,
        attr_id,
        StructureAction::ChangeType,
        body,
    )
    .await
}

/// Solution 7 Phase 2 (D-788 rule 6): adds a choice value (re-adding a
/// removed value, with any label, is allowed and makes stored values show
/// again). Recorded as `add_choice_value`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choices",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
    ),
    request_body = AddChoiceBody,
    responses(
        (status = 200, description = "Added (or already present)", body = crate::field_changes::FieldChangeResult),
        (status = 202, description = "Approval pending"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No changeset to record into, or the field is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Not a choice field, or invalid body", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn add_attribute_choice(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<Value>,
) -> Result<Response, AppError> {
    structure_route(
        &state,
        &ctx,
        &recording,
        entity_id,
        attr_id,
        StructureAction::AddChoice,
        body,
    )
    .await
}

/// Solution 7 Phase 2 (D-788 rule 6): removes a choice value. Stored values
/// stay in place (shown empty; no data step); the result counts the records
/// that keep it (`records_with_value`). Recorded as `remove_choice_value`.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choices/{value}",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
        ("value" = String, Path),
        DryRunQuery,
    ),
    responses(
        (status = 200, description = "Removed (or already absent), or the dry-run count", body = crate::field_changes::FieldChangeResult),
        (status = 202, description = "Approval pending"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No changeset to record into, or the field is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Not a choice field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn remove_attribute_choice(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((entity_id, attr_id, value)): Path<(Uuid, Uuid, String)>,
    axum::extract::Query(query): axum::extract::Query<DryRunQuery>,
) -> Result<Response, AppError> {
    let body = serde_json::json!({ "value": value, "dry_run": query.dry_run });
    structure_route(
        &state,
        &ctx,
        &recording,
        entity_id,
        attr_id,
        StructureAction::RemoveChoice,
        body,
    )
    .await
}

/// One value of a choice field and the records holding it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ChoiceValueUsage {
    pub value: String,
    pub records: i64,
    /// The value is one of the field's current choices; `false` for a value
    /// still stored after it was removed.
    pub defined: bool,
}

/// `GET .../fields/{field_id}/choice-usage`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ChoiceUsage {
    pub field: String,
    /// `false` on a table too large to count inline; `values` then lists the
    /// choices with no counts.
    pub counted: bool,
    pub values: Vec<ChoiceValueUsage>,
}

/// A5-T3: how many records hold each value of a choice field, including
/// values no longer offered, so an administrator sees what removing or
/// merging one would touch. Reads only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choice-usage",
    tag = "admin",
    params(("entity_id" = Uuid, Path), ("field_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Records per value, most used first", body = ChoiceUsage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such field", body = ErrorResponse),
        (status = 422, description = "Not a choice field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn choice_usage(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((entity_id, attr_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ChoiceUsage>, AppError> {
    use attome_metadata::provision::field_change as fc;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
    if row.field_type != "choice" {
        return Err(AppError::Validation(format!(
            "{} is not a choice field",
            row.field
        )));
    }
    let defined: Vec<String> = row
        .options
        .as_ref()
        .and_then(|o| o.get("choices"))
        .and_then(Value::as_array)
        .map(|choices| {
            choices
                .iter()
                .filter_map(|c| {
                    c.as_str()
                        .or_else(|| c.get("value").and_then(Value::as_str))
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let large = fc::row_count_exceeds_in_tx(
        &mut tx,
        &row,
        crate::field_changes::FIELD_CHANGE_INLINE_ROW_LIMIT,
    )
    .await?;
    let stored = if large {
        Vec::new()
    } else {
        fc::choice_usage(&mut tx, &row).await?
    };
    // Read only: release the field lock without writing.
    tx.rollback().await.map_err(AppError::internal)?;
    let mut values: Vec<ChoiceValueUsage> = stored
        .into_iter()
        .map(|(value, records)| ChoiceValueUsage {
            defined: defined.contains(&value),
            value,
            records,
        })
        .collect();
    for value in &defined {
        if !values.iter().any(|v| &v.value == value) {
            values.push(ChoiceValueUsage {
                value: value.clone(),
                records: 0,
                defined: true,
            });
        }
    }
    Ok(Json(ChoiceUsage {
        field: row.field,
        counted: !large,
        values,
    }))
}

/// The answer of `POST .../fields/{field_id}/runs/{run_id}/abandon`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AbandonedFieldRun {
    pub run_id: Uuid,
    /// The run's kind (`retype`, `archive`, ...).
    pub kind: String,
    /// Always `abandoned`.
    pub status: &'static str,
    /// A retype's shadow column, sync trigger and trigger function were
    /// dropped.
    pub shadow_dropped: bool,
    /// Recovery-archive rows the run had written and that were removed
    /// (their values are still the records' live values).
    pub archive_rows_removed: u64,
    /// A retype whose swap had already committed (only the work after it,
    /// such as the index rebuild, failed): the conversion stands, nothing is
    /// undone, and the run's archive rows are kept.
    pub conversion_completed: bool,
    /// What the abandon did not undo, for the operator.
    pub labels: Vec<&'static str>,
}

/// Label: the change's changeset op stays recorded.
const LABEL_ABANDON_OP_STAYS: &str = "the change was recorded in its changeset when it started; \
     abandoning the run does not remove that op: abandon or edit the changeset if it must not \
     be promoted";
/// Label: a retype's customer rules stay off.
const LABEL_ABANDON_RULES_STAY_OFF: &str = "customer business rules turned off when the type \
     change started stay off; turn them back on";

/// Solution 7 Phase 2 (D-788): abandons a **failed** batched run of a field
/// change (a large type change, `retype`; a large delete's archive copy,
/// `archive`) so the field is no longer `field_busy`. One transaction: the
/// field and the run are locked; a retype's shadow column, sync trigger and
/// trigger function are dropped; the run's recovery-archive rows are removed
/// (nothing was destroyed: the column still holds every value); the run is
/// marked `abandoned` with its cursor cleared. A retype whose swap had
/// already committed is closed without undoing anything
/// (`conversion_completed`). A queued or running run is refused (409
/// `run_not_failed`). Not approval-gated: it only undoes the partial state of
/// a change that was gated when it started. The change's changeset op is not
/// removed (reported in `labels`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/runs/{run_id}/abandon",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        ("field_id" = Uuid, Path),
        ("run_id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Abandoned", body = AbandonedFieldRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run for this field", body = ErrorResponse),
        (status = 409, description = "`run_not_failed`, or the table is busy (`field_busy`, retry)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn abandon_field_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((entity_id, attr_id, run_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<AbandonedFieldRun>, AppError> {
    do_abandon_field_run(&state, ctx.user_id, entity_id, attr_id, run_id)
        .await
        .map(Json)
}

/// Whether a run's spec names this field (`entity_id` + `attribute_id`).
fn run_names_field(spec: &Value, entity_id: Uuid, attr_id: Uuid) -> bool {
    let id = |key: &str| {
        spec.get(key)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
    };
    id("entity_id") == Some(entity_id) && id("attribute_id") == Some(attr_id)
}

async fn do_abandon_field_run(
    state: &EngineState,
    user_id: Uuid,
    entity_id: Uuid,
    attr_id: Uuid,
    run_id: Uuid,
) -> Result<AbandonedFieldRun, AppError> {
    use attome_metadata::provision::field_change as fc;
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    // Field first, then the run: the order the run's own batches lock in.
    let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
    let run = fc::lock_run_in_tx(&mut tx, run_id)
        .await?
        .filter(|run| {
            run.entity_logicalname == row.entity && run_names_field(&run.spec, entity_id, attr_id)
        })
        .ok_or(AppError::NotFound)?;
    if run.status != "failed" {
        return Err(AppError::Conflict(
            "run_not_failed: only a failed run can be abandoned; a queued or running run is \
             still in progress, and a finished one is already terminal",
        ));
    }
    let mut out = AbandonedFieldRun {
        run_id,
        kind: run.kind.clone(),
        status: "abandoned",
        shadow_dropped: false,
        archive_rows_removed: 0,
        conversion_completed: false,
        labels: vec![LABEL_ABANDON_OP_STAYS],
    };
    let undo = match run.kind.as_str() {
        "retype" => {
            let suffix = run
                .spec
                .get("suffix")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::internal("retype run without a shadow suffix"))?
                .to_owned();
            // The swap renames the shadow column into place and commits with
            // the attribute's new type: without the shadow column the
            // conversion already stands, and its archive rows hold the values
            // it destroyed. Keep them, undo nothing.
            let shadow = fc::retype_shadow_column(&suffix);
            if fc::column_exists(&mut tx, &row.entity, &shadow).await? {
                fc::retype_cleanup_in_tx(&mut tx, &row, &suffix).await?;
                out.shadow_dropped = true;
                out.labels.push(LABEL_ABANDON_RULES_STAY_OFF);
                true
            } else {
                out.conversion_completed = true;
                false
            }
        }
        // A large delete drops the column only in its final transaction,
        // which also marks the run succeeded: a failed one dropped nothing.
        "archive" => true,
        // Kinds with no executor in this release wrote nothing.
        _ => false,
    };
    if undo {
        out.archive_rows_removed = fc::delete_run_archive_in_tx(&mut tx, run_id).await?;
    }
    if !fc::abandon_run_in_tx(&mut tx, run_id).await? {
        return Err(AppError::Conflict(
            "run_not_failed: the run changed concurrently; reload and retry",
        ));
    }
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(row.entity.clone()),
                record_id: Some(attr_id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("abandon_field_run".to_owned()),
                event_comment: Some(format!(
                    "abandoned {} run {run_id} of {}.{} (shadow dropped {}, archive rows \
                     removed {}, conversion completed {})",
                    out.kind,
                    row.entity,
                    row.field,
                    out.shadow_dropped,
                    out.archive_rows_removed,
                    out.conversion_completed
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        %run_id, kind = %out.kind, entity = %row.entity, field = %row.field,
        shadow_dropped = out.shadow_dropped, archive_rows_removed = out.archive_rows_removed,
        conversion_completed = out.conversion_completed,
        "field run abandoned"
    );
    pin_write_best_effort(state, user_id, "abandon field run").await;
    Ok(out)
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_attribute,
    update_attribute,
    attribute_index_status,
    attribute_schema_change_status,
    delete_attribute,
    rename_attribute,
    change_attribute_type,
    add_attribute_choice,
    remove_attribute_choice,
    choice_usage,
    abandon_field_run
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(v: Value) -> UpdateAttributeBody {
        serde_json::from_value(v).expect("valid UpdateAttributeBody")
    }

    #[test]
    fn a_run_names_its_field_by_entity_and_attribute_id() {
        let entity = Uuid::now_v7();
        let attr = Uuid::now_v7();
        let spec = serde_json::json!({
            "field": "amount", "entity_id": entity.to_string(),
            "attribute_id": attr.to_string(), "suffix": "abcd1234"
        });
        assert!(run_names_field(&spec, entity, attr));
        assert!(!run_names_field(&spec, entity, Uuid::now_v7()));
        assert!(!run_names_field(&spec, Uuid::now_v7(), attr));
        assert!(!run_names_field(&serde_json::json!({}), entity, attr));
    }

    #[test]
    fn rename_alone_is_not_mixed() {
        assert!(!update_body_changes_more_than_logicalname(&body(
            serde_json::json!({ "logicalname": "new_name" })
        )));
        assert!(!update_body_changes_more_than_logicalname(&body(
            serde_json::json!({ "logicalname": "new_name", "dry_run": true })
        )));
    }

    #[test]
    fn rename_with_another_property_is_mixed() {
        for extra in [
            serde_json::json!({ "name": "Label" }),
            serde_json::json!({ "is_required": true }),
            serde_json::json!({ "max_length": 10 }),
            serde_json::json!({ "options": {} }),
            serde_json::json!({ "default_value": "x" }),
            serde_json::json!({ "purpose": "why" }),
        ] {
            let mut v = serde_json::json!({ "logicalname": "new_name" });
            if let (Some(obj), Some(add)) = (v.as_object_mut(), extra.as_object()) {
                for (k, val) in add {
                    obj.insert(k.clone(), val.clone());
                }
            }
            assert!(
                update_body_changes_more_than_logicalname(&body(v)),
                "{extra} must count as another change"
            );
        }
    }
}

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_core::changeset::{Op, RecordedOp, Recording, RecordingCtx};
use attome_core::{ChangeKind, EngineState};
use attome_metadata::provision;
use attome_metadata::provision::{EntityDesc, ReconcilePolicy, RecordAs, valid_identifier};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::attribute::{AttributeMeta, fetch_attributes};
use super::{audit_service, notify_metadata_change, pin_write_best_effort, simple_field_change};
use attome_types::ErrorResponse;
use utoipa::{IntoParams, ToSchema};

// ── DB row shapes ─────────────────────────────────────────────────────────────

/// `entity_info` row: (logicalname, name, primary_name_attribute, is_active, is_append_only, category, owner_layer, business_key, is_reference_data).
type EntityInfoRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<bool>,
    Option<String>,
    String,
    Option<Vec<String>>,
    bool,
);

/// `entity_info` row without `is_active` — used by `update_entity`, which
/// reads live rows only (`is_active IS NULL OR is_active = true` is in the query):
/// (logicalname, name, primary_name_attribute, is_append_only, is_audited, category, owner_layer).
type EntityInfoCoreRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<bool>,
    Option<String>,
    String,
);

#[derive(sqlx::FromRow)]
struct EntityRow {
    id: Uuid,
    logicalname: Option<String>,
    name: Option<String>,
    primary_name_attribute: Option<String>,
    is_active: Option<bool>,
    is_append_only: Option<bool>,
    category: Option<String>,
    attribute_count: i64,
    owner_layer: String,
    business_key: Option<Vec<String>>,
    is_reference_data: bool,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct EntityMeta {
    id: Uuid,
    logicalname: String,
    name: String,
    primary_name_attribute: Option<String>,
    is_active: bool,
    is_append_only: bool,
    /// Admin-assigned grouping label (e.g. "Account Management"); `None` when uncategorized.
    category: Option<String>,
    attribute_count: i64,
    /// Solution 7 (D-785): the layer that owns this entity —
    /// `platform | product | project | customer`. Only a changeset of this
    /// layer may change or retire it.
    owner_layer: String,
    /// Solution 7 Phase 2 (D-787 rule 7): the declared business key — the
    /// 1–4 fields its records are matched by, in order; `null`: none.
    business_key: Option<Vec<String>>,
    /// A configuration-like entity whose records move between deployments
    /// in changesets (`upsert_record`); always has a business key.
    is_reference_data: bool,
    /// PATCH only, when the business key changed: how its unique index was
    /// brought in line — `inline`, `queued` (a background job; read its state
    /// on GET), or `failed` (the key is declared but not yet enforced; see
    /// the server log, and GET's `business_key_index_state`).
    #[serde(skip_serializing_if = "Option::is_none")]
    business_key_index_sync: Option<String>,
}

impl std::fmt::Debug for EntityMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityMeta").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct EntityDetail {
    id: Uuid,
    logicalname: String,
    name: String,
    primary_name_attribute: Option<String>,
    is_active: bool,
    is_append_only: bool,
    category: Option<String>,
    /// Solution 7 (D-785): the layer that owns this entity.
    owner_layer: String,
    /// Solution 7 Phase 2 (D-787 rule 7): the declared business key; `null`:
    /// none.
    business_key: Option<Vec<String>>,
    is_reference_data: bool,
    /// The unique index that enforces the key (`uxbk_<e40>_<h8>`); `null`
    /// without a key.
    business_key_index: Option<String>,
    /// `none` (no key), `missing`, `building`, `invalid` (a failed build;
    /// the next sync rebuilds it) or `valid`.
    business_key_index_state: String,
    /// L1-T1: whether the entity is master data, and its hub style.
    master_data: attome_compliance::governance_admin::MasterData,
    attributes: Vec<AttributeMeta>,
}

impl std::fmt::Debug for EntityDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityDetail").finish_non_exhaustive()
    }
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateEntityBody {
    logicalname: String,
    name: String,
    primary_name_attribute: Option<String>,
    #[serde(default)]
    is_append_only: bool,
}

#[derive(Deserialize, ToSchema)]
pub(super) struct UpdateEntityBody {
    logicalname: Option<String>,
    name: Option<String>,
    primary_name_attribute: Option<String>,
    /// Set to an empty string to clear the category back to uncategorized.
    category: Option<String>,
    /// Solution 7 Phase 2 (D-787 rule 7): declare the business key — 1 to 4
    /// field logical names, in order (text, number, date, bool or lookup;
    /// single-valued; a lookup's target must itself have a key). An empty
    /// list clears it; absent leaves it unchanged. Refused with 409
    /// `business_key_duplicates` while live records share a key value.
    business_key: Option<Vec<String>>,
    /// Mark the entity as reference data (requires a business key):
    /// generic writes to it are recorded as `upsert_record` when a changeset
    /// is in play. Absent leaves it unchanged.
    is_reference_data: Option<bool>,
    /// L1-T1: the entity's master-data settings, written as one
    /// `set_entity_master_data` changeset operation. `is_master: true`
    /// needs the entity to be in a data domain (422 naming `is_master`).
    /// Absent leaves them unchanged.
    master_data: Option<attome_compliance::governance_admin::MasterData>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A stored `owner_layer` (CHECK-constrained by migration 0520) as a
/// [`attome_core::changeset::Layer`]; anything else is a masked internal
/// error, never a client error.
pub(super) fn parse_owner_layer(value: &str) -> Result<attome_core::changeset::Layer, AppError> {
    attome_core::changeset::Layer::parse(value).ok_or_else(|| {
        AppError::internal(format!("unknown owner_layer {value:?} on a metadata row"))
    })
}

fn entity_meta_from_row(r: EntityRow) -> EntityMeta {
    EntityMeta {
        id: r.id,
        logicalname: r.logicalname.unwrap_or_default(),
        name: r.name.unwrap_or_default(),
        primary_name_attribute: r.primary_name_attribute,
        is_active: r.is_active.unwrap_or(true),
        is_append_only: r.is_append_only.unwrap_or(false),
        category: r.category,
        attribute_count: r.attribute_count,
        owner_layer: r.owner_layer,
        business_key: r.business_key,
        is_reference_data: r.is_reference_data,
        business_key_index_sync: None,
    }
}

// ── Entity handlers ───────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/entities",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<EntityMeta>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_entities(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<EntityMeta>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let rows: Vec<EntityRow> = sqlx::query_as(
        r#"SELECT e.id, e.logicalname, e.name, e.primary_name_attribute,
                  e.is_active, e.is_append_only, e.category, e.owner_layer,
                  e.business_key, e.is_reference_data,
                  COUNT(a.id) FILTER (WHERE a.is_active IS NULL OR a.is_active = true) AS attribute_count
           FROM entity_info e
           LEFT JOIN attribute_info a ON a.entity_ref = e.id
           WHERE e.is_active IS NULL OR e.is_active = true
           GROUP BY e.id
           ORDER BY e.name
           LIMIT $1 OFFSET $2"#,
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_info e WHERE e.is_active IS NULL OR e.is_active = true",
    )
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let items = rows.into_iter().map(entity_meta_from_row).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// S1-T7: logical names that clash with fixed `/api/v1/<name>` routes.
const RESERVED_ENTITY_NAMES: &[&str] =
    &["composite", "query", "search", "graph", "schema", "openapi"];

#[utoipa::path(
    post,
    path = "/api/v1/admin/entities",
    tag = "admin",
    request_body = CreateEntityBody,
    responses(
        (status = 201, description = "Success", body = EntityMeta),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Create)])))),
)]
pub(super) async fn create_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateEntityBody>,
) -> Result<(StatusCode, Json<EntityMeta>), AppError> {
    let logicalname = body.logicalname.trim().to_lowercase();
    if !valid_identifier(&logicalname) {
        return Err(AppError::Validation(format!(
            "logicalname must be lowercase letters, digits, or underscores, max {} chars",
            provision::MAX_IDENTIFIER_LEN
        )));
    }
    // S1-T7: names a fixed `/api/v1/<name>` route already answers would
    // make the entity's own record routes unreachable.
    if RESERVED_ENTITY_NAMES.contains(&logicalname.as_str()) {
        return Err(AppError::Validation("logicalname is reserved".into()));
    }
    let display_name = body.name.trim().to_owned();
    if display_name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let primary = body
        .primary_name_attribute
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // Solution 7 (D-785): refuse (changeset_required, …) before any write.
    recording.preflight(&state.base.db_migrator).await?;

    // A live entity under this logicalname is a 409 up front: the reconcile
    // primitive below would otherwise *update* it to this body (it is
    // create-or-update by design). A retired one is fine — reconcile
    // reactivates it and its existing physical table (D-055: never dropped)
    // rather than creating a second metadata row for the same table.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&logicalname)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Err(AppError::Conflict(
            "an entity with this logicalname already exists",
        ));
    }
    // Y11-T10: a platform name or a reserved prefix stays the platform's.
    attome_model::guard::refuse_reserved(
        &logicalname,
        &crate::changeset::layers::platform_keys().entities,
    )?;

    // P-environment-promotion §5 step 13: one implementation of "make this
    // entity match this description" — `reconcile_entity` with the `Admin`
    // policy writes the metadata row (with `is_customized = true`, step 5),
    // provisions the physical table, and appends the change log in its own
    // short transaction. It can't share the transaction below (provisioning
    // may issue `CREATE INDEX CONCURRENTLY`, refused inside a transaction
    // block), so the audit event lands in a separate commit; the change log
    // itself is now atomic with the metadata row, closing the crash window
    // the old `ensure_entity` + separate change-log write had.
    //
    // Solution 7 (design §4.4): `create_entity` is recorded in the
    // primitive's final lock + change-log transaction, after the table DDL.
    let (id, _outcome) = provision::reconcile_entity_recorded(
        &state.base.db_migrator,
        &EntityDesc {
            logicalname: logicalname.clone(),
            display_name: display_name.clone(),
            primary_name_attribute: primary.clone(),
            is_append_only: body.is_append_only,
            is_audited: false,
            category: None,
        },
        ReconcilePolicy::Admin,
        None,
        Some(RecordAs::op(&recording, Op::CreateEntity)),
    )
    .await?;
    let layer = recording.stamp()?;
    let owner_layer = layer.as_str().to_owned();

    // Two views, not one: "Active {name}" (the default the list page opens
    // on) and "Inactive {name}" for the soft-deleted rows. Both are ordinary
    // view rows, so the list page's view picker offers them
    // immediately and an admin can rename or re-column either afterwards.
    provision::ensure_entity_list_views(&state.base.db_migrator, id, &logicalname, &display_name)
        .await?;

    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    {
        let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
        audit_service(&state)
            .write_in_tx(
                &mut tx,
                AuditEvent {
                    organization_ref: org_ref,
                    category: AuditCategory::Entity,
                    entity_name: Some(logicalname.clone()),
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
                    event_name: Some("entity_created".to_owned()),
                    event_comment: None,
                    changed_fields: vec![
                        simple_field_change("name", None, Some(display_name.clone())),
                        simple_field_change("primary_name_attribute", None, primary.clone()),
                        simple_field_change(
                            "is_append_only",
                            None,
                            Some(body.is_append_only.to_string()),
                        ),
                    ],
                    snapshot_json: None,
                },
            )
            .await?;
        attome_db::tx::commit(tx).await?;
    }

    if let Err(e) = attome_security::entity_privileges::ensure_entity_privileges(
        &state.base.db_migrator,
        &logicalname,
        layer,
    )
    .await
    {
        tracing::warn!(error = %e, entity = %logicalname, "failed to seed per-entity privileges on create");
    }

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(&state, ctx.user_id, "create entity").await;

    Ok((
        StatusCode::CREATED,
        Json(EntityMeta {
            id,
            logicalname,
            name: display_name,
            primary_name_attribute: primary,
            is_active: true,
            is_append_only: body.is_append_only,
            category: None,
            attribute_count: 0,
            owner_layer,
            business_key: None,
            is_reference_data: false,
            business_key_index_sync: None,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = EntityDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_entity(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<EntityDetail>, AppError> {
    let row: Option<EntityInfoRow> = sqlx::query_as(
        "SELECT logicalname, name, primary_name_attribute, is_active, is_append_only, category,
                owner_layer, business_key, is_reference_data
             FROM entity_info WHERE id = $1",
    )
    .bind(entity_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let (
        logicalname,
        name,
        primary,
        is_active,
        is_append_only,
        category,
        owner_layer,
        business_key,
        is_reference_data,
    ) = row.ok_or(AppError::NotFound)?;
    let logicalname = logicalname.unwrap_or_default();
    let (is_master, hub_style): (bool, Option<String>) =
        sqlx::query_as("SELECT is_master, hub_style FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?;
    let attributes = fetch_attributes(&state.base.db_migrator, entity_id).await?;
    let (business_key_index, index_state) = provision::business_key_index_status(
        &state.base.db_migrator,
        &logicalname,
        business_key.as_deref(),
    )
    .await?;

    Ok(Json(EntityDetail {
        id: entity_id,
        logicalname,
        name: name.unwrap_or_default(),
        primary_name_attribute: primary,
        is_active: is_active.unwrap_or(true),
        is_append_only: is_append_only.unwrap_or(false),
        category,
        owner_layer,
        business_key,
        is_reference_data,
        business_key_index,
        business_key_index_state: index_state.as_str().to_owned(),
        master_data: attome_compliance::governance_admin::MasterData {
            is_master,
            hub_style,
        },
        attributes,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/entities/{entity_id}",
    tag = "admin",
    params(("entity_id" = Uuid, Path)),
    request_body = UpdateEntityBody,
    responses(
        (status = 200, description = "Success", body = EntityMeta),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "layer_mismatch, business_key_duplicates, or a concurrent change", body = ErrorResponse),
        (status = 422, description = "Request failed validation (business_key_invalid, business_key_missing)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
)]
pub(super) async fn update_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<UpdateEntityBody>,
) -> Result<Json<EntityMeta>, AppError> {
    let cur: Option<EntityInfoCoreRow> = sqlx::query_as(
        "SELECT logicalname, name, primary_name_attribute, is_append_only, is_audited, category,
                owner_layer
         FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;

    let (
        cur_logical,
        cur_name,
        cur_primary,
        cur_append_only,
        cur_audited,
        cur_category,
        owner_layer,
    ) = cur.ok_or(AppError::NotFound)?;
    let old_logical = cur_logical.unwrap_or_default();
    // Y11-T10: a locked or add-only entity keeps what it has.
    attome_model::guard::check_entity(
        &state.base.db_migrator,
        &old_logical,
        attome_model::guard::ChangeKind::Set,
    )
    .await?;

    // logicalname is immutable after creation (D-021): the physical table is
    // never renamed alongside entity_info, so a rename here would brick
    // the entity for every subsequent generic-CRUD call. Only display name /
    // primary-name-attribute stay mutable.
    if let Some(requested) = body
        .logicalname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        && requested != old_logical
    {
        return Err(AppError::Validation(
            "logicalname is immutable after creation".into(),
        ));
    }

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| cur_name.clone().unwrap_or_default());

    let new_primary = body
        .primary_name_attribute
        .as_deref()
        .map(str::trim)
        .map(str::to_owned)
        .or_else(|| cur_primary.clone());

    // Empty string clears the category back to uncategorized; absent field
    // leaves it unchanged — same "field not present in the request means
    // don't touch it" convention `name`/`primary_name_attribute` use above,
    // except category additionally supports explicit clearing since "" is
    // never a meaningful category value.
    let new_category = match body.category.as_deref().map(str::trim) {
        Some("") => None,
        Some(s) => Some(s.to_owned()),
        None => cur_category.clone(),
    };

    // Solution 7 Phase 2 (D-787 rule 7, design §1): declaring a business key
    // or the reference-data flag runs first, so a refused key (invalid
    // fields, live duplicates, another layer's entity) writes nothing at all.
    // It records its own `update_entity` with `changed: ["business_key", …]`;
    // the unique index follows after the audit commit below.
    let key_declaration = if body.business_key.is_some() || body.is_reference_data.is_some() {
        let current = provision::read_business_key(&state.base.db_migrator, &old_logical)
            .await?
            .ok_or(AppError::NotFound)?;
        let desired = provision::BusinessKey {
            fields: match body.business_key.as_deref() {
                Some([]) => None,
                Some(fields) => Some(fields.to_vec()),
                None => current.fields.clone(),
            },
            is_reference_data: body.is_reference_data.unwrap_or(current.is_reference_data),
        };
        Some(
            provision::declare_business_key_recorded(
                &state.base.db_migrator,
                entity_id,
                &desired,
                Some(RecordAs::op(&recording, Op::UpdateEntity)),
            )
            .await?,
        )
    } else {
        None
    };

    // P-environment-promotion §5 step 13: the current row + this patch is a
    // full description, and `reconcile_entity` (policy `Admin`) is the one
    // implementation that makes the row match it — metadata lock, UPDATE,
    // `is_customized = true` (step 5) and change log in its own short
    // transaction; `Unchanged` when nothing differs (no lock, no write).
    // `logicalname` is the key and is immutable (checked above);
    // `is_append_only`/`is_audited` are not patchable here and are carried
    // through unchanged.
    //
    // Solution 7: `update_entity` is recorded in that same transaction; a
    // row owned by another layer is refused (409 `layer_mismatch`).
    let (reconciled_id, _outcome) = provision::reconcile_entity_recorded(
        &state.base.db_migrator,
        &EntityDesc {
            logicalname: old_logical.clone(),
            display_name: new_name.clone(),
            primary_name_attribute: new_primary.clone(),
            is_append_only: cur_append_only.unwrap_or(false),
            is_audited: cur_audited.unwrap_or(false),
            category: new_category.clone(),
        },
        ReconcilePolicy::Admin,
        None,
        Some(RecordAs::op(&recording, Op::UpdateEntity)),
    )
    .await?;
    if reconciled_id != entity_id {
        // The live row for this logicalname is not the one the path named
        // (it was retired and re-created concurrently) — nothing here was
        // written to `entity_id`, so report the loss rather than a success.
        return Err(AppError::Conflict(
            "entity was replaced concurrently; reload and retry",
        ));
    }

    // L1-T1: the master-data settings are their own recorded operation.
    let master_changed = match &body.master_data {
        Some(settings) => {
            attome_compliance::governance_admin::set_entity_master_data(
                &state,
                &recording,
                &old_logical,
                settings,
                attome_audit::security::SecurityEvent::new(
                    attome_audit::security::MandatoryCategory::Configuration,
                    AuditOperation::Update,
                    ctx.user_id,
                    "entity_info",
                    Some(entity_id),
                )
                .named("entity.master_data_set"),
            )
            .await?
        }
        None => false,
    };

    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;

    let attribute_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribute_info
         WHERE entity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mut changed_fields = Vec::new();
    if cur_name.as_deref() != Some(new_name.as_str()) {
        changed_fields.push(simple_field_change(
            "name",
            cur_name.clone(),
            Some(new_name.clone()),
        ));
    }
    if cur_primary != new_primary {
        changed_fields.push(simple_field_change(
            "primary_name_attribute",
            cur_primary.clone(),
            new_primary.clone(),
        ));
    }
    if cur_category != new_category {
        changed_fields.push(simple_field_change(
            "category",
            cur_category.clone(),
            new_category.clone(),
        ));
    }
    if master_changed && let Some(settings) = &body.master_data {
        changed_fields.push(simple_field_change(
            "is_master",
            None,
            Some(settings.is_master.to_string()),
        ));
    }
    if let Some(declared) = &key_declaration {
        let shown = |key: &Option<Vec<String>>| key.as_ref().map(|k| k.join(","));
        if declared.before.fields != declared.after.fields {
            changed_fields.push(simple_field_change(
                "business_key",
                shown(&declared.before.fields),
                shown(&declared.after.fields),
            ));
        }
        if declared.before.is_reference_data != declared.after.is_reference_data {
            changed_fields.push(simple_field_change(
                "is_reference_data",
                Some(declared.before.is_reference_data.to_string()),
                Some(declared.after.is_reference_data.to_string()),
            ));
        }
    }
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(old_logical.clone()),
                record_id: Some(entity_id),
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

    // The unique index follows a changed key: inline under the size gate,
    // else the durable `BuildBusinessKeyIndex` job. The key is declared
    // already; a build that fails here (a duplicate inserted since the
    // pre-check) leaves it unenforced, which the response says and GET's
    // `business_key_index_state` keeps showing until a later sync succeeds.
    let mut business_key_index_sync = None;
    if let Some(declared) = &key_declaration
        && declared.key_changed()
    {
        business_key_index_sync = Some(
            match provision::ensure_business_key_index(
                &state.base.db_migrator,
                state.base.config.as_ref(),
                &old_logical,
            )
            .await
            {
                Ok(sync) => sync.as_str().to_owned(),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        entity = %old_logical,
                        "business key declared but its unique index did not build"
                    );
                    "failed".to_owned()
                }
            },
        );
    }

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(&state, ctx.user_id, "update entity").await;

    let (business_key, is_reference_data) = match key_declaration {
        Some(declared) => (declared.after.fields, declared.after.is_reference_data),
        None => provision::read_business_key(&state.base.db_migrator, &old_logical)
            .await?
            .map(|k| (k.fields, k.is_reference_data))
            .unwrap_or_default(),
    };

    Ok(Json(EntityMeta {
        id: entity_id,
        logicalname: old_logical,
        name: new_name,
        primary_name_attribute: new_primary,
        is_active: true,
        is_append_only: cur_append_only.unwrap_or(false),
        category: new_category,
        attribute_count,
        owner_layer,
        business_key,
        is_reference_data,
        business_key_index_sync,
    }))
}

#[derive(Deserialize, IntoParams)]
pub(super) struct DeleteEntityParams {
    #[serde(default)]
    hard: bool,
}

/// D-195/P-four-eyes-approval — `action_type` for the default *soft* entity
/// delete (`is_active = false` on the entity and its attributes).
///
/// The sibling `ACTION_SCHEMA_CHANGE` already gates attribute create/update,
/// which left entity deletion as the one schema mutation any single admin
/// could perform unilaterally. Kept as its own action rather than folded into
/// `ACTION_SCHEMA_CHANGE` so a deployment can require two people for removing
/// an entity without also gating every routine field edit.
///
/// Reversible (the rows and the physical table both survive), so this one
/// stays deployment-opt-in — the same posture `query.publish` and
/// `schema.attribute_change` get. See `ACTION_ENTITY_HARD_DELETE` for the half
/// that is not reversible.
pub(crate) const ACTION_ENTITY_DELETE: &str = "schema.entity_delete";

/// D-195/P-four-eyes-approval — `action_type` for `DELETE ...?hard=true`,
/// which issues a real `DROP TABLE` and deletes the metadata rows outright.
///
/// Split from `ACTION_ENTITY_DELETE` precisely so the two can carry different
/// policy: this one meets `PRODUCTION_MANDATORY_ACTIONS`' stated criterion
/// (execution that cannot be undone by any follow-up action — the customer's
/// table and every row in it are gone, exactly as gone as `security.erasure`
/// leaves a shredded key), while a soft delete is undone by flipping
/// `is_active` back. One shared action type would have forced a deployment to
/// choose between gating routine soft deletes and leaving `DROP TABLE`
/// ungated.
pub(crate) const ACTION_ENTITY_HARD_DELETE: &str = "schema.entity_hard_delete";

/// Solution 7 (design §1.1, §7; D-785 ruling 0.10 — no hard drop): a hard
/// delete drops the physical table, which no changeset operation can express
/// or replay, so an admin request (always recorded) refuses it.
pub(crate) const HARD_DELETE_NOT_RECORDABLE: &str = "hard_delete_not_recordable: a hard \
     delete drops the table and cannot be recorded in a changeset; retire the entity with a \
     soft delete instead";

#[derive(Serialize)]
struct EntityDeletePending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/entities/{entity_id}",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path),
        DeleteEntityParams,
    ),
    responses(
        (status = 204, description = "Success"),
        (status = 202, description = "Four-eyes approval required; request submitted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No changeset to record into, the entity is owned by another layer, or `hard=true` (a hard delete cannot be recorded)", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Entity, AuditOperation::SoftDelete)])))),
)]
pub(super) async fn delete_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
    Query(params): Query<DeleteEntityParams>,
) -> Result<Response, AppError> {
    // Solution 7: refused before the approval gate, so no approval request is
    // created for a write that could never be recorded.
    if params.hard {
        return Err(AppError::Conflict(HARD_DELETE_NOT_RECORDABLE));
    }
    attome_model::guard::check_entity_id(
        &state.base.db_migrator,
        entity_id,
        attome_model::guard::ChangeKind::Remove,
    )
    .await?;
    recording.preflight(&state.base.db_migrator).await?;

    // Gated behind `approval.required_actions` (empty/off by default, the same
    // opt-in shape every other wired action uses). When gated, the request is
    // recorded and nothing is deleted until a second admin decides it.
    let action = if params.hard {
        ACTION_ENTITY_HARD_DELETE
    } else {
        ACTION_ENTITY_DELETE
    };
    if let Some(request) = crate::approval_admin::gate(
        &state,
        action,
        serde_json::json!({ "entity_id": entity_id, "hard": params.hard }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(EntityDeletePending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    do_delete_entity_recorded(
        &state,
        entity_id,
        ctx.user_id,
        params.hard,
        Some(&*recording),
    )
    .await
    .map(IntoResponse::into_response)
}

/// The unrecorded delete, kept for the approval-deferred execution
/// (`approval_admin::execute_approved`; design §4.5 moves it onto a captured
/// changeset in lane L6).
pub(crate) async fn do_delete_entity(
    state: &EngineState,
    entity_id: Uuid,
    user_id: Uuid,
    hard: bool,
) -> Result<StatusCode, AppError> {
    do_delete_entity_recorded(state, entity_id, user_id, hard, None).await
}

/// Soft delete = `retire_entity`, recorded in the delete's own transaction
/// after the change-log append (design §1.1). With a recording, a hard delete
/// is refused (`hard_delete_not_recordable`) and a row owned by another layer
/// is refused (`layer_mismatch`).
pub(crate) async fn do_delete_entity_recorded(
    state: &EngineState,
    entity_id: Uuid,
    user_id: Uuid,
    hard: bool,
    recording: Option<&Recording>,
) -> Result<StatusCode, AppError> {
    if hard {
        if recording.is_some() {
            return Err(AppError::Conflict(HARD_DELETE_NOT_RECORDABLE));
        }
        return hard_delete_entity(state, entity_id, user_id).await;
    }
    if let Some(recording) = recording {
        recording.preflight(&state.base.db_migrator).await?;
    }

    let logicalname: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let logicalname = logicalname.ok_or(AppError::NotFound)?;
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;

    // `is_customized = true` on soft delete too (P-environment-promotion §5
    // step 5, "any admin write that touches the row"): a seeded entity an
    // admin deliberately retired must not be reactivated by the next boot's
    // reconciling seed, which skips customized rows retired or not.
    let owner_layer: Option<String> = sqlx::query_scalar(
        "UPDATE entity_info SET is_active = false, is_customized = true \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
         RETURNING owner_layer",
    )
    .bind(entity_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let Some(owner_layer) = owner_layer else {
        return Err(AppError::NotFound);
    };
    // Checked under the metadata lock; the transaction rolls back on refusal.
    if let Some(recording) = recording {
        recording.check_owner(parse_owner_layer(&owner_layer)?)?;
    }

    sqlx::query("UPDATE attribute_info SET is_active = false WHERE entity_ref = $1")
        .bind(entity_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    attome_core::append_change_log(&mut tx, entity_id, &logicalname, ChangeKind::Delete).await?;
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(logicalname.clone()),
                record_id: Some(entity_id),
                operation: AuditOperation::SoftDelete,
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
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    // Solution 7: `retire_entity`, the last statement before commit (§4.2).
    if let Some(recording) = recording {
        let snapshot = provision::changeset::snapshot(
            &mut tx,
            provision::changeset::ObjectKind::Entity,
            entity_id,
        )
        .await?;
        recording
            .record(
                &mut tx,
                RecordedOp {
                    op: Op::RetireEntity,
                    object_kind: "entity",
                    object_ref: Some(entity_id),
                    target: provision::changeset::entity_target(&logicalname),
                    snapshot,
                    changed: vec!["is_active"],
                },
            )
            .await?;
    }
    attome_db::tx::commit(tx).await?;

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(state, user_id, "delete entity").await;
    warn_if_field_security_stale_for_entity(state, &logicalname).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Permanently removes an entity: drops its physical table and deletes its
/// `entity_info`/`attribute_info` rows outright (no `is_active`
/// flag). Irreversible — unlike `delete_entity`'s default soft delete.
async fn hard_delete_entity(
    state: &EngineState,
    entity_id: Uuid,
    user_id: Uuid,
) -> Result<StatusCode, AppError> {
    let logicalname: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?
            .flatten();

    let logicalname = logicalname.ok_or(AppError::NotFound)?;
    let (user_ctx, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;

    sqlx::query("DELETE FROM attribute_info WHERE entity_ref = $1")
        .bind(entity_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // `create_entity` always seeds a default `view` row
    // (`provision::ensure_default_query`), and migration 0078 gave that
    // table a `REFERENCES entity_info(id)` FK — deleting the view
    // (and its backing `sql_query` row, no FK but orphaned
    // otherwise) before `entity_info` is required, not optional,
    // for every entity created since that migration.
    sqlx::query("DELETE FROM view WHERE entity_logical_name = $1")
        .bind(entity_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // Two more children sit between `view` and `sql_query`
    // that the pre-existing delete above never accounted for:
    //  - `sql_query_entity_mapping.query_version_id` (migration 0059)
    //    references `sql_query_version(id)`, no cascade, and
    //    `.entity_ref` separately references `entity_info(id)`, also
    //    no cascade — covers both "this entity's own query has mapping rows"
    //    and "this entity participates in someone else's multi-entity query".
    //  - `sql_query_version.query_id` (migration 0047) references
    //    `sql_query(id)`, no cascade — every publish left an
    //    immutable version row that outlives the query itself otherwise.
    // Without these, the `sql_query` delete below 500s on the first
    // FK it hits rather than dropping the entity (caught live: hard-deleting
    // any admin-API-created entity failed until this was added).
    sqlx::query(
        "DELETE FROM sql_query_entity_mapping \
         WHERE entity_ref = $1 \
            OR query_version_id IN ( \
                SELECT v.id FROM sql_query_version v \
                JOIN sql_query q ON q.id = v.query_id \
                WHERE q.entity_logical_name = $1 \
            )",
    )
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "DELETE FROM sql_query_version \
         WHERE query_id IN (SELECT id FROM sql_query WHERE entity_logical_name = $1)",
    )
    .bind(entity_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query("DELETE FROM sql_query WHERE entity_logical_name = $1")
        .bind(entity_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    sqlx::query("DELETE FROM entity_info WHERE id = $1")
        .bind(entity_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    attome_core::append_change_log(&mut tx, entity_id, &logicalname, ChangeKind::Delete).await?;
    // AuditOperation::HardDelete's one call site (D-001 gov-auditor trust —
    // this irreversible drop-table-and-metadata action is exactly the
    // operation that must never go unsigned).
    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some(logicalname.clone()),
                record_id: Some(entity_id),
                operation: AuditOperation::HardDelete,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: None,
                event_comment: Some(format!(
                    "permanently dropped entity {logicalname} and its physical table"
                )),
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_db::tx::commit(tx).await?;

    // Physical-DDL concern, deliberately outside the transaction above (D-003
    // provisioning-owns-entity-tables boundary) — the log only needs to agree
    // with entity_info/attribute_info, not with the table's
    // existence.
    provision::drop_table(&state.base.db_migrator, &logicalname).await?;

    if let Err(e) = attome_security::entity_privileges::deactivate_entity_privileges(
        &state.base.db_migrator,
        &logicalname,
    )
    .await
    {
        tracing::warn!(error = %e, entity = %logicalname, "failed to deactivate per-entity privileges on hard delete");
    }

    notify_metadata_change(&state.base.redis).await;
    pin_write_best_effort(state, user_id, "hard delete entity").await;
    warn_if_field_security_stale_for_entity(state, &logicalname).await;

    Ok(StatusCode::NO_CONTENT)
}

/// D-188 best-effort observability, entity-scoped sibling of
/// `attribute::warn_if_field_security_stale_for_field` — called when a whole
/// entity (and every one of its attributes) is deactivated at once, so it
/// checks by `entity_logicalname` alone rather than one field at a time.
async fn warn_if_field_security_stale_for_entity(state: &EngineState, entity_logicalname: &str) {
    match attome_security::revalidation::count_field_security_refs_for_entity(
        &state.base.db_migrator,
        entity_logicalname,
    )
    .await
    {
        Ok(count) if count > 0 => {
            tracing::warn!(
                entity_logicalname = %entity_logicalname,
                field_security_profile_count = count,
                "deactivated entity is still referenced by field-security profiles"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "field security staleness check: count query failed");
        }
    }
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_entities, create_entity, get_entity, update_entity, delete_entity))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

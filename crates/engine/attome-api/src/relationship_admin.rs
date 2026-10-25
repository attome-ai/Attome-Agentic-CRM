//! M01 Core P3 gap (D-455) — `relationship_info` admin CRUD:
//! `/api/v1/admin/relationships*`. `system.admin` only, mounted with
//! `strict_authz` — same posture as `duplicates_admin.rs`'s match-rule/
//! survivorship-rule surface, the closest existing analog (a small,
//! admin-authored metadata table with no separate license gate).
//!
//! Every write goes through `attome_metadata::provision::reconcile_relationship`
//! — the one INSERT/UPDATE implementation this admin surface shares with
//! the bundle engine's apply step (`bundle/apply.rs`), same "one
//! implementation, multiple callers" shape `reconcile_entity`/
//! `reconcile_attribute` already established. This file's job is strictly
//! transport: parse the request, resolve the two entities, call the
//! reconcile primitive, shape the response. Cache reload + the cross-node
//! invalidation doorbell are the reconcile primitive's own responsibility
//! (`attome_metadata::provision::relationship::invalidate`), not this file's —
//! same split `attome-state`'s admin surface already has with its own
//! `reconcile.rs`.

use attome_core::changeset::{Op, RecordingCtx};
use attome_core::{EngineState, RelationshipCascade};
use attome_metadata::provision::{
    ReconcileOutcome, ReconcilePolicy, RecordAs, RelationshipDesc, RelationshipDetail,
    reconcile_relationship_recorded, retire_relationship_recorded,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_records::entity_crud;

/// Wire representation of `RelationshipCascade` — a plain lowercase string
/// matching the column's own `CHECK` constraint vocabulary, so the API
/// contract and the stored value never need a second mapping table.
///
/// C-21 (M01 §7): the canonical spelling is hyphenated
/// (`"cascade-deactivate"`), matching `on_target_delete`'s existing D-088
/// vocabulary (`admin/attribute.rs::valid_on_target_delete`) — this
/// endpoint's own underscore spelling was the divergent one, an accident of
/// this surface being written separately from `attribute.rs`'s, not a
/// second deliberate vocabulary. The underscore spelling is still accepted
/// here for one release (an existing caller/script may already send it);
/// every value this handler subsequently writes is normalized to the
/// hyphenated form by `RelationshipCascade::as_db_str`.
fn cascade_from_wire(s: &str) -> Result<RelationshipCascade, AppError> {
    match s {
        "restrict" => Ok(RelationshipCascade::Restrict),
        "orphan" => Ok(RelationshipCascade::Orphan),
        "cascade-deactivate" | "cascade_deactivate" => Ok(RelationshipCascade::CascadeDeactivate),
        other => Err(AppError::Validation(format!(
            "cascade must be one of restrict|orphan|cascade-deactivate, got '{other}'"
        ))),
    }
}

#[derive(Serialize, ToSchema)]
struct RelationshipView {
    id: Uuid,
    name: String,
    entity_a: String,
    entity_b: String,
    role_a: String,
    role_b: String,
    join_table: String,
    cascade: String,
    is_customized: bool,
    is_active: bool,
    row_version: i64,
    /// Solution 7 (D-785): the layer that owns this relationship —
    /// `platform | product | project | customer`.
    owner_layer: String,
}

impl From<RelationshipDetail> for RelationshipView {
    fn from(d: RelationshipDetail) -> Self {
        Self {
            id: d.id,
            name: d.name,
            entity_a: d.entity_a,
            entity_b: d.entity_b,
            role_a: d.role_a,
            role_b: d.role_b,
            join_table: d.join_table,
            cascade: d.cascade.as_db_str().to_owned(),
            is_customized: d.is_customized,
            is_active: d.is_active,
            row_version: d.row_version,
            owner_layer: d.owner_layer,
        }
    }
}

// ── GET /api/v1/admin/relationships ─────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListRelationshipsQuery {
    /// Only this entity (its logical name).
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct RelationshipRow {
    id: Uuid,
    name: String,
    entity_a: String,
    entity_b: String,
    role_a: String,
    role_b: String,
    join_table: String,
    cascade: String,
    is_customized: bool,
    is_active: bool,
    row_version: i64,
    owner_layer: String,
}

impl From<RelationshipRow> for RelationshipView {
    fn from(r: RelationshipRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            entity_a: r.entity_a,
            entity_b: r.entity_b,
            role_a: r.role_a,
            role_b: r.role_b,
            join_table: r.join_table,
            cascade: r.cascade,
            is_customized: r.is_customized,
            is_active: r.is_active,
            row_version: r.row_version,
            owner_layer: r.owner_layer,
        }
    }
}

/// List relationships
///
/// `GET /api/v1/admin/relationships` — `system.admin` only. `?entity=`
/// narrows to relationships touching one entity on either side.
#[utoipa::path(
    get,
    path = "/api/v1/admin/relationships",
    tag = "admin",
    params(ListRelationshipsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RelationshipView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_relationships(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListRelationshipsQuery>,
) -> Result<Json<PaginatedResponse<RelationshipView>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let rows: Vec<RelationshipRow> = sqlx::query_as(
        "SELECT id, name, entity_a, entity_b, role_a, role_b, join_table, cascade, \
                is_customized, is_active, row_version, owner_layer \
         FROM relationship_info \
         WHERE NOT is_deleted AND ($1::text IS NULL OR entity_a = $1 OR entity_b = $1) \
         ORDER BY name ASC OFFSET $2 LIMIT $3",
    )
    .bind(&q.entity)
    .bind(offset)
    .bind(page_size)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM relationship_info \
         WHERE NOT is_deleted AND ($1::text IS NULL OR entity_a = $1 OR entity_b = $1)",
    )
    .bind(&q.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows.into_iter().map(RelationshipView::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One relationship
///
/// `GET /api/v1/admin/relationships/{id}` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/relationships/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The relationship")),
    responses(
        (status = 200, description = "Success", body = RelationshipView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Relationship not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_relationship(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<RelationshipView>, AppError> {
    let row: Option<RelationshipRow> = sqlx::query_as(
        "SELECT id, name, entity_a, entity_b, role_a, role_b, join_table, cascade, \
                is_customized, is_active, row_version, owner_layer \
         FROM relationship_info WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    Ok(Json(row.into()))
}

// ── POST /api/v1/admin/relationships ────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateRelationshipBody {
    name: String,
    entity_a: String,
    entity_b: String,
    role_a: String,
    role_b: String,
    #[serde(default = "default_cascade")]
    cascade: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

fn default_cascade() -> String {
    "orphan".to_owned()
}

fn default_true() -> bool {
    true
}

/// `POST /api/v1/admin/relationships` — `system.admin` only. Creates the
/// relationship definition AND provisions its physical join table
/// (`mm_{name}`) — see `reconcile_relationship`'s doc comment for the
/// create-before-insert ordering and its failure-mode reasoning.
///
/// **`name` is not renameable, and reusing a retired one after swapping
/// `entity_a`/`entity_b` is a `409` (C-21, M01 §7).** There is no
/// in-place rename endpoint: `join_table` is derived from `name` once, at
/// create time. Retiring one `name` and creating another under a different
/// `name` (the only way to get a differently-named relationship between the
/// same two entities) provisions a brand-new, empty `mm_{new name}`
/// table — it does not move data out of the old one, which stays exactly as
/// the retired relationship left it (`retire_relationship`'s doc comment).
/// Reusing the OLD `name` later is fine as long as `entity_a`/`entity_b`
/// match what it originally provisioned; if they don't, this endpoint
/// refuses with `409` rather than silently attaching the new relationship to
/// the old, wrongly-shaped physical table
/// (`attome_metadata::provision::relationship::verify_join_table_matches_or_absent`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/relationships",
    tag = "admin",
    request_body = CreateRelationshipBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = RelationshipView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A live relationship with this name already exists, or this name's join table was left behind by a retired relationship with different endpoints (C-21)", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_relationship(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateRelationshipBody>,
) -> Result<(StatusCode, Json<RelationshipView>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    let role_a = body.role_a.trim();
    let role_b = body.role_b.trim();
    if role_a.is_empty() || role_b.is_empty() {
        return Err(AppError::Validation(
            "role_a and role_b must not be empty".into(),
        ));
    }
    let cascade = cascade_from_wire(&body.cascade)?;

    // Resolves both endpoints against the DB-trusted metadata registry
    // (existence + license) before anything is written — same "resolve
    // first" discipline `create_match_rule` already applies to its single
    // `entity` field.
    let (_, entity_a, _, _) = entity_crud::resolve_entity(&state, &body.entity_a).await?;
    let (_, entity_b, _, _) = entity_crud::resolve_entity(&state, &body.entity_b).await?;
    if entity_a == entity_b {
        return Err(AppError::Validation(
            "entity_a and entity_b must be different entities (a self-referencing M:M \
             relationship is not supported by this generic mechanism yet)"
                .into(),
        ));
    }

    let desc = RelationshipDesc {
        name: name.to_owned(),
        entity_a,
        entity_b,
        role_a: role_a.to_owned(),
        role_b: role_b.to_owned(),
        cascade,
        is_active: body.is_active,
    };
    // Solution 7 (D-785): `upsert_relationship`, recorded in the metadata
    // transaction after the junction-table DDL (design §1.1, §4.4).
    let (detail, outcome) = reconcile_relationship_recorded(
        &state,
        &desc,
        ReconcilePolicy::Admin,
        Some(ctx.user_id),
        Some(RecordAs::op(&recording, Op::UpsertRelationship)),
    )
    .await?;
    audit_relationship_change(
        &state,
        ctx.user_id,
        detail.id,
        attome_audit::AuditOperation::Create,
        "relationship.create",
    )
    .await?;

    let status = match outcome {
        ReconcileOutcome::Created => StatusCode::CREATED,
        // A retried/duplicate create request against the same desired state
        // is not an error — same idempotent-retry posture the rest of this
        // platform's mutation contract already promises (guidelines §2).
        _ => StatusCode::OK,
    };
    Ok((status, Json(detail.into())))
}

// ── PATCH /api/v1/admin/relationships/{id} ──────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct UpdateRelationshipBody {
    role_a: Option<String>,
    role_b: Option<String>,
    cascade: Option<String>,
    is_active: Option<bool>,
}

/// Update a relationship
///
/// `PATCH /api/v1/admin/relationships/{id}` — `system.admin` only.
/// `entity_a`/`entity_b`/`name`/`join_table` are immutable (delete and
/// recreate under a new name to retarget) — same posture
/// `update_match_rule` takes for `entity`. See `create_relationship`'s doc
/// comment above for what that recreate actually does to the physical join
/// table (a new one, not a rename — C-21, M01 §7).
#[utoipa::path(
    patch,
    path = "/api/v1/admin/relationships/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The relationship")),
    request_body = UpdateRelationshipBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = RelationshipView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Relationship not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_relationship(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRelationshipBody>,
) -> Result<Json<RelationshipView>, AppError> {
    let existing: Option<RelationshipRow> = sqlx::query_as(
        "SELECT id, name, entity_a, entity_b, role_a, role_b, join_table, cascade, \
                is_customized, is_active, row_version, owner_layer \
         FROM relationship_info WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let existing = existing.ok_or(AppError::NotFound)?;

    let role_a = body.role_a.as_deref().unwrap_or(&existing.role_a).trim();
    let role_b = body.role_b.as_deref().unwrap_or(&existing.role_b).trim();
    if role_a.is_empty() || role_b.is_empty() {
        return Err(AppError::Validation(
            "role_a and role_b must not be empty".into(),
        ));
    }
    let cascade = match &body.cascade {
        Some(c) => cascade_from_wire(c)?,
        None => RelationshipCascade::from_db_str(&existing.cascade),
    };

    let desc = RelationshipDesc {
        name: existing.name.clone(),
        entity_a: existing.entity_a.clone(),
        entity_b: existing.entity_b.clone(),
        role_a: role_a.to_owned(),
        role_b: role_b.to_owned(),
        cascade,
        is_active: body.is_active.unwrap_or(existing.is_active),
    };
    // Solution 7: `upsert_relationship`; a row owned by another layer is a
    // 409 `layer_mismatch`.
    let (detail, _) = reconcile_relationship_recorded(
        &state,
        &desc,
        ReconcilePolicy::Admin,
        Some(ctx.user_id),
        Some(RecordAs::op(&recording, Op::UpsertRelationship)),
    )
    .await?;
    audit_relationship_change(
        &state,
        ctx.user_id,
        detail.id,
        attome_audit::AuditOperation::Update,
        "relationship.update",
    )
    .await?;
    Ok(Json(detail.into()))
}

// ── DELETE /api/v1/admin/relationships/{id} ─────────────────────────────────

/// Delete a relationship
///
/// `DELETE /api/v1/admin/relationships/{id}` — `system.admin` only.
/// Soft-retires the relationship DEFINITION (`is_deleted = true`); never
/// drops the physical join table or its data — see
/// `attome_metadata::provision::retire_relationship`'s doc comment. A retired
/// relationship's `/related/{relationship}` route immediately 404s (the
/// registry no longer resolves the name) even though the join rows survive
/// physically, in case the name is ever reused.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/relationships/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The relationship")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Relationship not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_relationship(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Solution 7: `retire_relationship`, owner-checked and recorded.
    let retired = retire_relationship_recorded(
        &state,
        id,
        Some(RecordAs::op(&recording, Op::RetireRelationship)),
    )
    .await?;
    if !retired {
        return Err(AppError::NotFound);
    }
    audit_relationship_change(
        &state,
        ctx.user_id,
        id,
        attome_audit::AuditOperation::SoftDelete,
        "relationship.delete",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Writes this route's mandatory `Configuration` audit event in its own
/// short transaction, immediately after `reconcile_relationship`/
/// `retire_relationship` committed. Not atomic with that DDL+metadata write
/// (`attome_audit` depends on `attome-metadata`, so `attome-metadata` cannot depend back
/// on it to join the same transaction without a cycle — guidelines §1); a
/// crash between the two would leave the schema change audited-less, the
/// same posture `write_business_event`'s pre-3.6 callers already accept
/// (see `attome_audit::business`'s module doc). Phase 3.7 coverage only; not a
/// claim of D-062 atomicity for this one schema-DDL surface.
async fn audit_relationship_change(
    state: &EngineState,
    actor_user_id: Uuid,
    relationship_id: Uuid,
    operation: attome_audit::AuditOperation,
    event_name: &'static str,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            operation,
            actor_user_id,
            "relationship_info",
            Some(relationship_id),
        )
        .named(event_name),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/relationships",
            get(list_relationships).post(create_relationship),
        )
        .route(
            "/api/v1/admin/relationships/{id}",
            get(get_relationship)
                .patch(update_relationship)
                .delete(delete_relationship),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_relationships,
    get_relationship,
    create_relationship,
    update_relationship,
    delete_relationship,
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

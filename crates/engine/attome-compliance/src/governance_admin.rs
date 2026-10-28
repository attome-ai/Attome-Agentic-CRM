//! M15 (Data Governance, D-413) — the accountability-register admin surface:
//! CRUD for `data_domain` (migration `0171_data_domain.sql`),
//! entity <-> domain assignment (`entity_info.domain_ref`), and the
//! plan's §3/§4 accountability report endpoint. A dedicated route (guidelines
//! §9: this isn't CRUD on a registered entity), gated on `system.admin` and
//! mounted with the `strict_authz` re-resolve layer at `system.rs`'s
//! composition point, matching `retention_admin.rs`/`dsr_admin.rs`/
//! `legal_hold_admin.rs`'s established pattern in this crate.
//!
//! **Scope note (M15 plan §4 checklist, adjusted for this pass):**
//! - "Standards rules (M45 `kind = standard`)" is skipped entirely — M45's
//!   own plan (`M45-rules-engine.md` §3.2) defines its rule `kind` enum as
//!   exactly `validation | calculation | visibility | requirement | default |
//!   policy | routing`; there is no `standard` kind to wire into, and M45 is
//!   owned by a different, concurrently-in-progress crate this session must
//!   not edit. A future session should extend M45's `kind` enum first.
//! - "Data policies... become M20 policy objects" is not attempted — M20
//!   does not exist yet. Nothing here needs an `applies_to` field, since no
//!   policy-object table is created by this change.
//! - Steward defaulting for M03 (access reviews)/M13 (duplicate queues)/M14
//!   (quality issues) is not wired anywhere — none of those engines exist
//!   yet. The reusable primitive
//!   (`attome_core::resolve_steward_for_domain`) is ready for them.
//!   M24 (DSR) genuinely exists today, but `dsr_request` carries no
//!   entity/domain association until fulfillment time (scopes are supplied
//!   only in the `fulfill-*` request bodies, never stored at request
//!   creation) — wiring a "default reviewer" onto DSR creation would mean
//!   changing that table's contract, out of scope for this pass and a real
//!   risk of colliding with a concurrent sibling change to `dsr_admin.rs`'s
//!   export/DSR-writer paths. `legal_hold_admin::place_hold` DOES have
//!   entity context at creation time, so that is where the hook is actually
//!   wired (see its own doc comment).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, RecordedOp, Recording, RecordingCtx};
use attome_metadata::provision::changeset::{
    ObjectKind, entity_target, snapshot as entity_snapshot,
};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{OnePageQuery, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

// ── Domain CRUD ──────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DataDomainSummary {
    id: Uuid,
    name: String,
    description: Option<String>,
    steward_ref: Option<Uuid>,
    deputy_ref: Option<Uuid>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    row_version: i64,
    /// Solution 7 (D-785): the layer that owns this domain —
    /// `platform | product | project | customer`.
    owner_layer: String,
}

/// The enumerated columns of a [`DataDomainSummary`].
const DOMAIN_COLUMNS: &str = "id, name, description, steward_ref, deputy_ref, created_by, \
     created_at, updated_at, row_version, owner_layer";

fn parse_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| {
        AppError::internal(format!("unknown owner_layer {value:?} on a governance row"))
    })
}

/// Appends `upsert_data_domain` for the domain row `id` (post-write
/// snapshot). MUST be the last statement before commit.
async fn record_domain(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    name: &str,
    changed: Vec<&'static str>,
) -> Result<(), AppError> {
    if !matches!(recording, Recording::Request(_)) {
        return Ok(());
    }
    let snapshot: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
             'id', id, 'name', name, 'description', description, \
             'steward_ref', steward_ref, 'deputy_ref', deputy_ref, \
             'row_version', row_version, 'owner_layer', owner_layer) \
         FROM data_domain WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    recording
        .record(
            tx,
            RecordedOp {
                op: Op::UpsertDataDomain,
                object_kind: "data_domain",
                object_ref: Some(id),
                target: serde_json::json!({ "domain": name }),
                snapshot,
                changed,
            },
        )
        .await
}

async fn fetch_domain(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<DataDomainSummary>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {DOMAIN_COLUMNS} FROM data_domain WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// List data domains
///
/// The data domains of the accountability register, with each one's steward and deputy, one-based
/// pages. Compliance administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/domains",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DataDomainSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_domains(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DataDomainSummary>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let items: Vec<DataDomainSummary> = sqlx::query_as(&format!(
        "SELECT {DOMAIN_COLUMNS} FROM data_domain \
          WHERE is_deleted = false \
          ORDER BY name \
          LIMIT $1 OFFSET $2"
    ))
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM data_domain WHERE is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct CreateDomainBody {
    name: String,
    description: Option<String>,
    steward_ref: Option<Uuid>,
    deputy_ref: Option<Uuid>,
}

/// Create a data domain
///
/// A named data domain with an optional description, steward and deputy (each an active user).
/// Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/governance/domains",
    tag = "admin",
    request_body = CreateDomainBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = DataDomainSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    recording: RecordingCtx,
    Json(body): Json<CreateDomainBody>,
) -> Result<(StatusCode, Json<DataDomainSummary>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Solution 7 (D-785): `upsert_data_domain`, stamped with the recording's
    // layer and recorded as the last statement before commit (after the
    // mandatory security event).
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;
    let new_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: DataDomainSummary = sqlx::query_as(&format!(
        "INSERT INTO data_domain \
             (id, name, description, steward_ref, deputy_ref, created_by, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {DOMAIN_COLUMNS}"
    ))
    .bind(new_id)
    .bind(name)
    .bind(description)
    .bind(body.steward_ref)
    .bind(body.deputy_ref)
    .bind(ctx.user_id)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "data_domain",
            Some(new_id),
        )
        .named("governance_domain.create"),
    )
    .await?;
    record_domain(&mut tx, &recording, row.id, &row.name, Vec::new()).await?;
    attome_db::tx::commit(tx).await?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// Get a data domain
///
/// One domain: its name, description, steward, deputy and `row_version`. Compliance administrators
/// only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/domains/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain")),
    responses(
        (status = 200, description = "Success", body = DataDomainSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_domain(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataDomainSummary>, AppError> {
    let domain = fetch_domain(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(domain))
}

#[derive(Deserialize, ToSchema)]
struct UpdateDomainBody {
    /// Absent = leave unchanged (same convention as
    /// `admin::entity::update_entity`'s `UpdateEntityBody`).
    name: Option<String>,
    /// Absent = leave unchanged; empty string clears the description back to
    /// `NULL` (same convention as that handler's `category` field).
    description: Option<String>,
    /// Absent = leave unchanged. There is deliberately no way to explicitly
    /// clear an already-set steward/deputy back to unassigned in this pass
    /// — reassign to a different systemuser, or delete and recreate the
    /// domain, until a real need for clearing is demonstrated.
    steward_ref: Option<Uuid>,
    deputy_ref: Option<Uuid>,
    /// Optimistic-concurrency guard (guidelines §2).
    row_version: i64,
}

/// Change a data domain
///
/// Changes the fields given (name, description, steward, deputy) when `row_version` is the stored
/// one; an empty description clears it, and a steward or deputy can be replaced but not cleared.
/// Compliance administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/governance/domains/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain")),
    request_body = UpdateDomainBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = DataDomainSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateDomainBody>,
) -> Result<Json<DataDomainSummary>, AppError> {
    let current = fetch_domain(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| current.name.clone());
    let new_description = match body.description.as_deref().map(str::trim) {
        Some("") => None,
        Some(s) => Some(s.to_owned()),
        None => current.description.clone(),
    };
    let new_steward = body.steward_ref.or(current.steward_ref);
    let new_deputy = body.deputy_ref.or(current.deputy_ref);
    let mut changed = Vec::new();
    for (name, differs) in [
        ("name", current.name != new_name),
        ("description", current.description != new_description),
        ("steward_ref", current.steward_ref != new_steward),
        ("deputy_ref", current.deputy_ref != new_deputy),
    ] {
        if differs {
            changed.push(name);
        }
    }

    // Solution 7: only the owning layer may change a domain.
    recording.preflight(&state.base.db).await?;
    recording.check_owner(parse_layer(&current.owner_layer)?)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<DataDomainSummary> = sqlx::query_as(&format!(
        "UPDATE data_domain \
            SET name = $2, description = $3, steward_ref = $4, deputy_ref = $5, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $6 AND is_deleted = false \
          RETURNING {DOMAIN_COLUMNS}"
    ))
    .bind(id)
    .bind(&new_name)
    .bind(&new_description)
    .bind(new_steward)
    .bind(new_deputy)
    .bind(body.row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let Some(row) = row else {
        return Err(AppError::Conflict(
            "row_version mismatch, or the domain no longer exists",
        ));
    };
    // The row_version guard above pins the row the owner check read.
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "data_domain",
            Some(id),
        )
        .named("governance_domain.update"),
    )
    .await?;
    // A PATCH that changes nothing records nothing ("one op per change").
    if !changed.is_empty() {
        record_domain(&mut tx, &recording, row.id, &row.name, changed).await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(Json(row))
}

// ── Entity <-> domain assignment ────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DomainEntitySummary {
    logicalname: Option<String>,
    name: Option<String>,
}

async fn domain_entities(
    db: &attome_db::DbPool,
    domain_id: Uuid,
) -> Result<Vec<DomainEntitySummary>, AppError> {
    sqlx::query_as(
        "SELECT logicalname, name FROM entity_info \
          WHERE domain_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY logicalname",
    )
    .bind(domain_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[derive(Deserialize, ToSchema)]
struct AssignEntitiesBody {
    entity_logicalnames: Vec<String>,
}

/// Assign entities to a data domain
///
/// Moves every named entity into this domain, out of any domain it was in (an entity has at most
/// one). Every name is checked against the live metadata first, and one unknown name refuses the
/// whole call. Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/governance/domains/{id}/entities",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain")),
    request_body = AssignEntitiesBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Grant)])))),
    responses(
        (status = 200, description = "Success", body = Vec<DomainEntitySummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn assign_entities(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<AssignEntitiesBody>,
) -> Result<Json<Vec<DomainEntitySummary>>, AppError> {
    if body.entity_logicalnames.is_empty() {
        return Err(AppError::Validation(
            "entity_logicalnames must not be empty".into(),
        ));
    }
    if fetch_domain(&state.base.db, id).await?.is_none() {
        return Err(AppError::NotFound);
    }

    let registry = state.entities.load();
    for logicalname in &body.entity_logicalnames {
        if registry.get(logicalname).is_none() {
            return Err(AppError::Validation(format!(
                "unknown entity: {logicalname}"
            )));
        }
    }

    set_entity_domain(
        &state,
        &recording,
        Some(id),
        &body.entity_logicalnames,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Grant,
            ctx.user_id,
            "data_domain",
            Some(id),
        )
        .named("governance_domain.entities_assign"),
    )
    .await?;

    Ok(Json(domain_entities(&state.base.db, id).await?))
}

/// Remove an entity from a data domain
///
/// Leaves the entity in no domain, but only if it is in this one; against another domain the call is
/// 404 and changes nothing. Compliance administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/governance/domains/{id}/entities/{entity_logicalname}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain"), ("entity_logicalname" = String, Path, description = "The entity's logical name")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Domain/entity assignment not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn unassign_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    recording: RecordingCtx,
    Path((id, entity_logicalname)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    let cleared = clear_entity_domain(
        &state,
        &recording,
        id,
        &entity_logicalname,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Revoke,
            ctx.user_id,
            "data_domain",
            Some(id),
        )
        .named("governance_domain.entities_unassign"),
    )
    .await?;
    if !cleared {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── set_entity_domain (Solution 7, design §1.1 / §3) ────────────────────

/// One live entity row as the domain writes read it, locked.
#[derive(sqlx::FromRow)]
struct EntityDomainRow {
    id: Uuid,
    logicalname: String,
    domain_ref: Option<Uuid>,
    owner_layer: String,
}

/// Sets `entity_info.domain_ref` on every named live entity to
/// `domain` (`None` clears it) — the `set_entity_domain` operation's one
/// implementation, shared by assign and the changeset applier.
///
/// `domain_ref` is entity metadata, so this runs like every other entity
/// write (the design finding: it used to skip both): the global metadata-write
/// lock first, the owner check per entity (409 `layer_mismatch`), the UPDATE,
/// one `metadata_change_log` row per entity whose domain actually
/// changed (other nodes' registries catch up), the security event, and one
/// recorded operation per changed entity as the last statements. An entity
/// already in `domain` changes nothing and records nothing.
pub async fn set_entity_domain(
    state: &EngineState,
    recording: &Recording,
    domain: Option<Uuid>,
    entity_logicalnames: &[String],
    event: SecurityEvent,
) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    recording.preflight(db).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let rows: Vec<EntityDomainRow> = sqlx::query_as(
        "SELECT id, logicalname, domain_ref, owner_layer FROM entity_info \
          WHERE logicalname = ANY($1) AND (is_active IS NULL OR is_active = true) \
          ORDER BY logicalname \
          FOR UPDATE",
    )
    .bind(entity_logicalnames)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let changing: Vec<&EntityDomainRow> = rows.iter().filter(|r| r.domain_ref != domain).collect();
    for row in &changing {
        recording.check_owner(parse_layer(&row.owner_layer)?)?;
    }
    write_entity_domains(&mut tx, recording, domain, &changing, event, state).await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Clears `entity_logicalname`'s domain when it currently belongs to exactly
/// `domain` (`set_entity_domain` with `domain: null`). `Ok(false)` when it
/// does not (a stale unassign is a 404, not a silent success).
pub async fn clear_entity_domain(
    state: &EngineState,
    recording: &Recording,
    domain: Uuid,
    entity_logicalname: &str,
    event: SecurityEvent,
) -> Result<bool, AppError> {
    let db = &state.base.db_migrator;
    recording.preflight(db).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let rows: Vec<EntityDomainRow> = sqlx::query_as(
        "SELECT id, logicalname, domain_ref, owner_layer FROM entity_info \
          WHERE logicalname = $1 AND domain_ref = $2 \
          FOR UPDATE",
    )
    .bind(entity_logicalname)
    .bind(domain)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if rows.is_empty() {
        return Ok(false);
    }
    let changing: Vec<&EntityDomainRow> = rows.iter().collect();
    for row in &changing {
        recording.check_owner(parse_layer(&row.owner_layer)?)?;
    }
    write_entity_domains(&mut tx, recording, None, &changing, event, state).await?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// The shared tail of [`set_entity_domain`] / [`clear_entity_domain`]: the
/// UPDATE, one change-log row per entity, the security event, then one
/// recorded `set_entity_domain` per entity. The caller holds the metadata
/// lock and commits.
async fn write_entity_domains(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    domain: Option<Uuid>,
    rows: &[&EntityDomainRow],
    event: SecurityEvent,
    state: &EngineState,
) -> Result<(), AppError> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    if !ids.is_empty() {
        sqlx::query("UPDATE entity_info SET domain_ref = $1 WHERE id = ANY($2)")
            .bind(domain)
            .bind(&ids)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        for row in rows {
            attome_core::append_change_log(
                tx,
                row.id,
                &row.logicalname,
                attome_core::ChangeKind::Upsert,
            )
            .await?;
        }
    }
    write_security_event(tx, &attome_audit::audit_service(state), event).await?;
    if matches!(recording, Recording::Request(_)) {
        for row in rows {
            let snapshot = entity_snapshot(tx, ObjectKind::Entity, row.id).await?;
            recording
                .record(
                    tx,
                    RecordedOp {
                        op: Op::SetEntityDomain,
                        object_kind: "entity",
                        object_ref: Some(row.id),
                        target: entity_target(&row.logicalname),
                        snapshot,
                        changed: vec!["domain"],
                    },
                )
                .await?;
        }
    }
    Ok(())
}

// ── set_entity_master_data (roadmap L1-T1) ─────────────────────────────

/// The master-data hub styles (L1).
pub const HUB_STYLES: [&str; 3] = ["registry", "consolidation", "coexistence"];

/// An entity's master-data settings (`entity_info.is_master`, `hub_style`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
pub struct MasterData {
    pub is_master: bool,
    /// `registry`, `consolidation` or `coexistence`; `null` when unset.
    pub hub_style: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EntityMasterRow {
    id: Uuid,
    domain_ref: Option<Uuid>,
    owner_layer: String,
    is_master: bool,
    hub_style: Option<String>,
}

/// Sets `entity_logicalname`'s master-data settings — the
/// `set_entity_master_data` operation's one implementation, shared by the
/// entity PATCH and the changeset applier. Like the domain write: the
/// metadata-write lock, the owner check (409 `layer_mismatch`), the UPDATE,
/// a change-log row (other nodes' registries catch up), the security event
/// and one recorded operation. A master entity needs a data domain (422
/// naming `is_master`), and `hub_style` is one of [`HUB_STYLES`]. Returns
/// whether anything changed; nothing changed records nothing.
pub async fn set_entity_master_data(
    state: &EngineState,
    recording: &Recording,
    entity_logicalname: &str,
    settings: &MasterData,
    event: SecurityEvent,
) -> Result<bool, AppError> {
    if let Some(style) = settings.hub_style.as_deref()
        && !HUB_STYLES.contains(&style)
    {
        return Err(AppError::Validation(
            "hub_style must be registry, consolidation or coexistence".into(),
        ));
    }
    let db = &state.base.db_migrator;
    recording.preflight(db).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let row: Option<EntityMasterRow> = sqlx::query_as(
        "SELECT id, domain_ref, owner_layer, is_master, hub_style FROM entity_info           WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)           FOR UPDATE",
    )
    .bind(entity_logicalname)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    if settings.is_master && row.domain_ref.is_none() {
        return Err(AppError::Validation(
            "is_master: a master entity needs a data domain; assign the entity to one first".into(),
        ));
    }
    if row.is_master == settings.is_master && row.hub_style == settings.hub_style {
        attome_db::tx::commit(tx).await?;
        // L1-T2: an entity already master still gets any side table it lacks.
        if settings.is_master {
            attome_metadata::provision::master::ensure_master_tables(db, entity_logicalname)
                .await?;
        }
        return Ok(false);
    }
    recording.check_owner(parse_layer(&row.owner_layer)?)?;
    sqlx::query("UPDATE entity_info SET is_master = $2, hub_style = $3 WHERE id = $1")
        .bind(row.id)
        .bind(settings.is_master)
        .bind(&settings.hub_style)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_core::append_change_log(
        &mut tx,
        row.id,
        entity_logicalname,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    write_security_event(&mut tx, &attome_audit::audit_service(state), event).await?;
    if matches!(recording, Recording::Request(_)) {
        let snapshot = entity_snapshot(&mut tx, ObjectKind::Entity, row.id).await?;
        recording
            .record(
                &mut tx,
                RecordedOp {
                    op: Op::SetEntityMasterData,
                    object_kind: "entity",
                    object_ref: Some(row.id),
                    target: entity_target(entity_logicalname),
                    snapshot,
                    changed: vec!["is_master", "hub_style"],
                },
            )
            .await?;
    }
    attome_db::tx::commit(tx).await?;
    // L1-T2: a master entity's contribution and provenance tables, after the
    // metadata commit (DDL runs under its own bounded lock timeout).
    if settings.is_master {
        attome_metadata::provision::master::ensure_master_tables(db, entity_logicalname).await?;
    }
    Ok(true)
}

// ── Accountability report (M15 plan §3/§4) ──────────────────────────────

#[derive(Serialize, Default, ToSchema)]
struct ClassificationBreakdown {
    general: i64,
    personal: i64,
    sensitive_special_category: i64,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DomainLegalHold {
    id: Uuid,
    entity_logicalname: String,
    record_id: Option<Uuid>,
    matter_reference: String,
    placed_at: DateTime<Utc>,
    released_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct DomainDsrRequest {
    id: Uuid,
    subject_reference: String,
    request_type: String,
    status: String,
    requested_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct DomainReport {
    domain_id: Uuid,
    domain_name: String,
    steward_ref: Option<Uuid>,
    deputy_ref: Option<Uuid>,
    entities: Vec<DomainEntitySummary>,
    classification_breakdown: ClassificationBreakdown,
    /// Always empty today — M13 (duplicate queues) and M14 (quality issues),
    /// the plan's named sources of "open issues", are not built yet. Kept as
    /// its own field (rather than omitted) so a future session wires a real
    /// source in without a breaking response-shape change.
    open_issues: Vec<serde_json::Value>,
    legal_holds: Vec<DomainLegalHold>,
    /// Best-effort: only a fulfilled/blocked request carries any entity
    /// association at all (via its `evidence_ref`'s scope list, written at
    /// fulfillment time) — `dsr_admin::create_request` is deliberately
    /// entity-agnostic (a bare subject reference), so a still-pending
    /// request cannot yet be attributed to a domain. See this file's header
    /// note.
    dsr_requests: Vec<DomainDsrRequest>,
    /// Best-effort proxy: this domain row's own `updated_at` (the last time
    /// its steward/deputy/membership assignment was edited through this
    /// admin surface), not a genuine review-cadence tracker — this platform
    /// has no M03 access-review workflow yet to record an actual review
    /// event against.
    last_review_date: Option<DateTime<Utc>>,
}

/// Raw row shape for the DSR-candidate scan below — factored into a type
/// alias only to satisfy `clippy::type_complexity`, not because it is reused
/// anywhere else.
type DsrCandidateRow = (
    Uuid,
    String,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    String,
);

/// Read a data domain's accountability report
///
/// The domain's steward and deputy, its entities and their data classification, the legal holds on
/// them and the data subject requests that touched them. Compliance administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/domains/{id}/report",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain")),
    responses(
        (status = 200, description = "Success", body = DomainReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Domain not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DomainReport>, AppError> {
    let domain = fetch_domain(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let entities = domain_entities(&state.base.db, id).await?;
    let entity_names: HashSet<&str> = entities
        .iter()
        .filter_map(|e| e.logicalname.as_deref())
        .collect();

    // Classification breakdown — reuses the existing 0087_data_classification
    // column on attribute_info verbatim, grouped across every
    // attribute of every entity currently in this domain.
    let class_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT a.data_classification, COUNT(*) \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
          WHERE e.domain_ref = $1 \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND (e.is_active IS NULL OR e.is_active = true) \
          GROUP BY a.data_classification",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut classification_breakdown = ClassificationBreakdown::default();
    for (classification, count) in class_rows {
        match classification.as_str() {
            "general" => classification_breakdown.general = count,
            "personal" => classification_breakdown.personal = count,
            "sensitive_special_category" => {
                classification_breakdown.sensitive_special_category = count
            }
            _ => {}
        }
    }

    // Legal holds touching this domain's entities — these exist today
    // (0088_data_protection_governance.sql), unlike M13/M14's open issues.
    let legal_holds: Vec<DomainLegalHold> = sqlx::query_as(
        "SELECT h.id, h.entity_logicalname, h.record_id, h.matter_reference, \
                h.placed_at, h.released_at \
           FROM legal_hold h \
           JOIN entity_info e ON e.logicalname = h.entity_logicalname \
          WHERE e.domain_ref = $1 AND h.is_deleted = false \
          ORDER BY h.placed_at DESC \
          LIMIT 200",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // DSR requests touching this domain — bounded, best-effort scan of the
    // recent fulfilled/blocked requests' evidence_ref (see DomainDsrRequest's
    // own doc comment on why a pending request can never match).
    let mut dsr_requests = Vec::new();
    if !entity_names.is_empty() {
        let candidates: Vec<DsrCandidateRow> = sqlx::query_as(
            "SELECT id, subject_reference, request_type, status, requested_at, \
                    fulfilled_at, evidence_ref \
               FROM dsr_request \
              WHERE is_deleted = false AND evidence_ref IS NOT NULL \
              ORDER BY requested_at DESC \
              LIMIT 500",
        )
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

        for (
            rid,
            subject_reference,
            request_type,
            status,
            requested_at,
            fulfilled_at,
            evidence_ref,
        ) in candidates
        {
            let Ok(scopes) = serde_json::from_str::<Vec<serde_json::Value>>(&evidence_ref) else {
                continue;
            };
            let touches_domain = scopes.iter().any(|scope| {
                scope
                    .get("entity_logicalname")
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| entity_names.contains(name))
            });
            if touches_domain {
                dsr_requests.push(DomainDsrRequest {
                    id: rid,
                    subject_reference,
                    request_type,
                    status,
                    requested_at,
                    fulfilled_at,
                });
            }
        }
    }

    Ok(Json(DomainReport {
        domain_id: domain.id,
        domain_name: domain.name,
        steward_ref: domain.steward_ref,
        deputy_ref: domain.deputy_ref,
        entities,
        classification_breakdown,
        open_issues: Vec::new(),
        legal_holds,
        dsr_requests,
        last_review_date: Some(domain.updated_at),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/governance/domains",
            get(list_domains).post(create_domain),
        )
        .route(
            "/api/v1/admin/governance/domains/{id}",
            get(get_domain).patch(update_domain),
        )
        .route(
            "/api/v1/admin/governance/domains/{id}/entities",
            post(assign_entities),
        )
        .route(
            "/api/v1/admin/governance/domains/{id}/entities/{entity_logicalname}",
            axum::routing::delete(unassign_entity),
        )
        .route(
            "/api/v1/admin/governance/domains/{id}/report",
            get(get_report),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers are
/// module-private — the crate's `openapi()` merges every fragment back into
/// one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_domains,
    create_domain,
    get_domain,
    update_domain,
    assign_entities,
    unassign_entity,
    get_report
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

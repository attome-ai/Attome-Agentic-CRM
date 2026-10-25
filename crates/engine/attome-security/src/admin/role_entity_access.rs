//! Role × entity access-level grants (supersedes D-133/D-134's role-wide
//! `access_level` column — see D-136 in DECISIONS.md for why a single scalar
//! per role, MAX-aggregated across every role a user held regardless of
//! entity, was a cross-entity privilege-escalation gap).
//!
//! Solution 7 Phase 1 (D-785): an upsert is recorded as
//! `set_role_entity_access` and a delete as `clear_role_entity_access`
//! (target `{ role, entity }`); the position-hierarchy toggle is a role
//! property, recorded as `upsert_role`. A new access row is stamped with the
//! changeset's layer; changing or clearing an existing one needs its layer,
//! and the toggle needs the role's.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{upsert_role_entity_access, users_holding_role};

use super::shared::{
    ROLE_SNAPSHOT, invalidate_sync_all, lock_live_role, mark_role_customized, parse_owner_layer,
    resolve_entity_ref, security_op, snapshot_row,
};

/// `role_mm_entity_access`'s snapshot, role and entity by logical
/// key.
const ENTITY_ACCESS_SNAPSHOT: &str = "SELECT ea.id, ea.role_ref, r.name AS role, \
     ea.entity_ref, ei.logicalname AS entity, ea.read_access_level, ea.write_access_level, \
     ea.delete_access_level, ea.read_owner_visible, ea.write_owner_visible, \
     ea.delete_owner_visible, ea.is_deleted, ea.row_version, ea.owner_layer \
     FROM role_mm_entity_access ea \
     JOIN role r ON r.id = ea.role_ref \
     JOIN entity_info ei ON ei.id = ea.entity_ref \
     WHERE ea.id = $1";

/// An access row's stored state: (is_deleted, owner_layer, read, write,
/// delete, read_owner_visible, write_owner_visible, delete_owner_visible).
type AccessState = (bool, String, i16, i16, i16, bool, bool, bool);
use attome_types::ErrorResponse;
use utoipa::ToSchema;

/// Validates one column's depth against the same range
/// `core_role_mm_entity_access_{read,write,delete}_range`'s CHECK
/// constraints enforce in Postgres — checked here too so a bad request 422s
/// with a clear message instead of surfacing as a raw constraint-violation
/// 500 from the INSERT/UPDATE.
fn validate_access_level(level: i16) -> Result<(), AppError> {
    if !(0..=3).contains(&level) {
        return Err(AppError::Validation(
            "access level must be 0 (None), 1 (Team), 2 (BusinessUnit), or 3 (Global)".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct RoleEntityAccessItem {
    id: Uuid,
    role_id: Uuid,
    role_name: Option<String>,
    entity: String,
    read_access_level: i16,
    write_access_level: i16,
    delete_access_level: i16,
    /// D-371 (amends D-357 ruling 2): orthogonal "I own this record"
    /// visibility per action, independent of the depth columns above.
    read_owner_visible: bool,
    write_owner_visible: bool,
    delete_owner_visible: bool,
    /// Solution 7 (D-785): the layer that owns this access row.
    owner_layer: String,
}

impl std::fmt::Debug for RoleEntityAccessItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleEntityAccessItem")
            .finish_non_exhaustive()
    }
}

/// (id, role_ref, role_name, entity logicalname, read, write, delete,
/// read_owner_visible, write_owner_visible, delete_owner_visible,
/// owner_layer) — the
/// projection `list_entity_access_grants`/`upsert_entity_access_grant` both
/// return, joined through `entity_info` for the logicalname since
/// `role_mm_entity_access.entity_ref` is a bare FK (D-133's convention),
/// never a denormalized name column.
type EntityAccessRow = (
    Uuid,
    Uuid,
    Option<String>,
    String,
    i16,
    i16,
    i16,
    bool,
    bool,
    bool,
    String,
);

/// List role entity access
///
/// Each role's access level per entity. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-entity-access",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RoleEntityAccessItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_entity_access_grants(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<RoleEntityAccessItem>>, AppError> {
    let window = query.window();

    let rows: Vec<EntityAccessRow> = sqlx::query_as(
        r#"
        SELECT ea.id, ea.role_ref, r.name, ei.logicalname,
               ea.read_access_level, ea.write_access_level, ea.delete_access_level,
               ea.read_owner_visible, ea.write_owner_visible, ea.delete_owner_visible,
               ea.owner_layer
        FROM role_mm_entity_access ea
        JOIN entity_info ei ON ei.id = ea.entity_ref
        LEFT JOIN role r ON r.id = ea.role_ref
        WHERE ea.is_deleted = false
        ORDER BY r.name, ei.logicalname
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM role_mm_entity_access WHERE is_deleted = false")
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(
            |(
                id,
                role_id,
                role_name,
                entity,
                read,
                write,
                delete,
                read_ow,
                write_ow,
                delete_ow,
                owner_layer,
            )| {
                RoleEntityAccessItem {
                    id,
                    role_id,
                    role_name,
                    entity,
                    read_access_level: read,
                    write_access_level: write,
                    delete_access_level: delete,
                    read_owner_visible: read_ow,
                    write_owner_visible: write_ow,
                    delete_owner_visible: delete_ow,
                    owner_layer,
                }
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct UpsertEntityAccessGrantBody {
    role_id: Uuid,
    /// Entity logicalname, resolved to `entity_info.id` server-side
    /// (`resolve_entity_ref`) — never a client-supplied UUID, same
    /// convention `shares::create_record_share`/`shares::create_entity_default_share`
    /// use.
    entity: String,
    /// Each defaults to `Global` (3) on a brand-new grant row — matching
    /// `role_mm_entity_access`'s own DB column default, so creating a
    /// grant that only narrows (say) `delete_access_level` doesn't silently
    /// narrow read/write too.
    #[serde(default = "default_access_level")]
    read_access_level: i16,
    #[serde(default = "default_access_level")]
    write_access_level: i16,
    #[serde(default = "default_access_level")]
    delete_access_level: i16,
    /// D-371: each defaults to `false` — matching the DB column default, so
    /// upserting a grant that only narrows a depth doesn't silently opt the
    /// role into owner-visibility too.
    #[serde(default)]
    read_owner_visible: bool,
    #[serde(default)]
    write_owner_visible: bool,
    #[serde(default)]
    delete_owner_visible: bool,
}

fn default_access_level() -> i16 {
    3
}

/// Set a role's entity access
///
/// Upserts one `(role, entity)` grant row — the mutation a deployment
/// actually uses to opt a role into narrowed record-level scoping for a
/// specific entity, since a role holding the underlying privilege but no row
/// here defaults to `Global` on every action (D-133's zero-behavior-change
/// guarantee, carried forward — see `resolve_entity_access_level`'s doc
/// comment). Every current holder of this role (direct + team-mediated) is
/// invalidated so the change takes effect on their next request rather than
/// waiting out the cache TTL.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/role-entity-access",
    tag = "admin-security",
    request_body = UpsertEntityAccessGrantBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = RoleEntityAccessItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the access row is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn upsert_entity_access_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<UpsertEntityAccessGrantBody>,
) -> Result<(StatusCode, Json<RoleEntityAccessItem>), AppError> {
    validate_access_level(body.read_access_level)?;
    validate_access_level(body.write_access_level)?;
    validate_access_level(body.delete_access_level)?;

    let role_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM role WHERE id = $1 AND is_deleted = false")
            .bind(body.role_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(role_name) = role_name else {
        return Err(AppError::Validation(
            "no active role found with this role_id".into(),
        ));
    };

    let entity_ref = resolve_entity_ref(&state.base.db, &body.entity).await?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    // C-19: the one atomic upsert, shared with `reconcile_role` — this call
    // site used to hand-roll the same `ON CONFLICT` statement without the
    // `row_version` bump `reconcile_role`'s copy had, so an admin edit and a
    // reconcile of the same grant disagreed about whether the column moved.
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "role_mm_entity_access",
        None,
    )
    .await?;
    // An existing row (live or cleared) is changed only by its own layer; a
    // live row already holding exactly these values changes nothing and
    // records nothing.
    let existing: Option<AccessState> = sqlx::query_as(
        "SELECT is_deleted, owner_layer, read_access_level, write_access_level, \
                delete_access_level, read_owner_visible, write_owner_visible, \
                delete_owner_visible \
         FROM role_mm_entity_access WHERE role_ref = $1 AND entity_ref = $2 \
         FOR UPDATE",
    )
    .bind(body.role_id)
    .bind(entity_ref)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let wanted = (
        body.read_access_level,
        body.write_access_level,
        body.delete_access_level,
        body.read_owner_visible,
        body.write_owner_visible,
        body.delete_owner_visible,
    );
    let changes = match &existing {
        None => true,
        Some((is_deleted, owner, r, w, d, ro, wo, dow)) => {
            let same = !is_deleted && (*r, *w, *d, *ro, *wo, *dow) == wanted;
            if !same {
                recording.check_owner(parse_owner_layer(owner)?)?;
            }
            !same
        }
    };
    let id = upsert_role_entity_access(
        &mut *tx,
        body.role_id,
        entity_ref,
        body.read_access_level,
        body.write_access_level,
        body.delete_access_level,
        body.read_owner_visible,
        body.write_owner_visible,
        body.delete_owner_visible,
        layer,
    )
    .await?;
    mark_role_customized(&mut *tx, body.role_id).await?;
    let snapshot = snapshot_row(&mut tx, ENTITY_ACCESS_SNAPSHOT, id).await?;
    let owner_layer = snapshot["owner_layer"]
        .as_str()
        .unwrap_or(layer.as_str())
        .to_owned();
    if changes {
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::SetRoleEntityAccess,
                    "role_entity_access",
                    id,
                    serde_json::json!({ "role": role_name, "entity": body.entity }),
                    snapshot,
                ),
            )
            .await?;
    }
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, body.role_id).await?,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleEntityAccessItem {
            id,
            role_id: body.role_id,
            role_name: Some(role_name),
            entity: body.entity,
            read_access_level: body.read_access_level,
            write_access_level: body.write_access_level,
            delete_access_level: body.delete_access_level,
            read_owner_visible: body.read_owner_visible,
            write_owner_visible: body.write_owner_visible,
            delete_owner_visible: body.delete_owner_visible,
            owner_layer,
        }),
    ))
}

/// Remove a role's entity access
///
/// Soft-deletes one `(role, entity)` grant row — after this, the role holds
/// no entity-access row for this entity at all, so `resolve_entity_access_level`
/// falls back to its default (`Global`) for every action on this entity,
/// same as a role that never had a row here in the first place.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/role-entity-access/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role entity access row")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the access row is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_entity_access_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(grant_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "role_mm_entity_access",
        Some(grant_id),
    )
    .await?;
    let live: Option<(String, String, String)> = sqlx::query_as(
        "SELECT ea.owner_layer, r.name, ei.logicalname \
         FROM role_mm_entity_access ea \
         JOIN role r ON r.id = ea.role_ref \
         JOIN entity_info ei ON ei.id = ea.entity_ref \
         WHERE ea.id = $1 AND ea.is_deleted = false FOR UPDATE OF ea",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (owner, role_name, entity) = live.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner)?)?;
    let role_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role_mm_entity_access SET is_deleted = true, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING role_ref",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let role_id = role_id.ok_or(AppError::NotFound)?;
    mark_role_customized(&mut *tx, role_id).await?;
    let snapshot = snapshot_row(&mut tx, ENTITY_ACCESS_SNAPSHOT, grant_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::ClearRoleEntityAccess,
                "role_entity_access",
                grant_id,
                serde_json::json!({ "role": role_name, "entity": entity }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, role_id).await?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub(super) struct UpdatePositionHierarchyEnabledBody {
    position_hierarchy_enabled: bool,
}

/// Turn position access on for a role
///
/// Toggles a role's F138 opt-in flag — the mutation a deployment actually
/// uses to turn position-hierarchy scoping on for a role after the fact,
/// mirroring `upsert_entity_access_grant`'s invalidation fan-out exactly
/// (same every-current-holder pattern via `users_holding_role`, covering
/// both direct and team-mediated holders).
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/roles/{id}/position-hierarchy",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The role")),
    request_body = UpdatePositionHierarchyEnabledBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the role is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn update_role_position_hierarchy(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(role_id): Path<Uuid>,
    Json(body): Json<UpdatePositionHierarchyEnabledBody>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "role",
        Some(role_id),
    )
    .await?;
    let (role_name, owner) = lock_live_role(&mut tx, role_id)
        .await?
        .ok_or(AppError::NotFound)?;
    recording.check_owner(owner)?;
    let updated: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role SET position_hierarchy_enabled = $1, is_customized = true, \
         updated_at = NOW() WHERE id = $2 AND is_deleted = false RETURNING id",
    )
    .bind(body.position_hierarchy_enabled)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    updated.ok_or(AppError::NotFound)?;
    let snapshot = snapshot_row(&mut tx, ROLE_SNAPSHOT, role_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::UpsertRole,
                "role",
                role_id,
                serde_json::json!({ "role": role_name }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, role_id).await?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/role-entity-access",
            get(list_entity_access_grants).post(upsert_entity_access_grant),
        )
        .route(
            "/api/v1/admin/security/role-entity-access/{id}",
            axum::routing::delete(delete_entity_access_grant),
        )
        .route(
            "/api/v1/admin/security/roles/{id}/position-hierarchy",
            axum::routing::put(update_role_position_hierarchy),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_entity_access_grants,
    upsert_entity_access_grant,
    delete_entity_access_grant,
    update_role_position_hierarchy
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

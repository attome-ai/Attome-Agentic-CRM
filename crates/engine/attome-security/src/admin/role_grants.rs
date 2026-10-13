//! Role-mediated privilege grants (role ↔ privilege, `role_mm_privilege`).
//!
//! Solution 7 Phase 1 (D-785): a grant is recorded as `grant_role_privilege`
//! (target `{ role, privilege }`, preceded by `ensure_privilege` when the
//! request minted the privilege) and a revoke as `revoke_role_privilege`. A
//! project changeset may grant on a platform role (a new grant row is stamped
//! with the changeset's layer); re-activating or revoking a grant row needs
//! the row's own layer.

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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{ensure_privilege_in_tx, upsert_role_privilege_grant, users_holding_role};

use super::shared::{
    access_tx, invalidate_sync_all, mark_role_customized, parse_owner_layer, security_op,
    snapshot_row,
};

/// `role_mm_privilege`'s snapshot, with the role and privilege by
/// logical key.
const GRANT_SNAPSHOT: &str = "SELECT rp.id, rp.role_ref, r.name AS role, rp.privilege_ref, \
     p.key AS privilege, rp.is_deleted, rp.row_version, rp.owner_layer \
     FROM role_mm_privilege rp \
     JOIN role r ON r.id = rp.role_ref \
     JOIN privilege p ON p.id = rp.privilege_ref \
     WHERE rp.id = $1";

/// `privilege`'s snapshot.
const PRIVILEGE_SNAPSHOT: &str = "SELECT id, key, name, description, is_active, owner_layer \
     FROM privilege WHERE id = $1";
use attome_types::ErrorResponse;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct RoleGrantItem {
    id: Uuid,
    role_id: Uuid,
    role_name: Option<String>,
    privilege_key: String,
    privilege_name: String,
    granted_on: Option<DateTime<Utc>>,
    /// D-369: live `role_privilege_condition` count for this grant —
    /// eager, not lazy-fetched per row, so the Role form's Privilege Grants
    /// matrix can show a "Conditional" badge without an extra request per
    /// grant (an N+1 a lazy per-row fetch would otherwise cause).
    condition_count: i64,
    /// Solution 7 (D-785): the layer that owns this grant row.
    owner_layer: String,
}

impl std::fmt::Debug for RoleGrantItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleGrantItem").finish_non_exhaustive()
    }
}

/// `list_role_grants`' own row shape — deliberately not the shared `GrantRow`
/// (also used by `grants::list_grants`, which has no conditions concept):
/// (id, role_ref, role_name, privilege_key, privilege_name, granted_on,
/// condition_count, owner_layer).
type RoleGrantRow = (
    Uuid,
    Uuid,
    Option<String>,
    String,
    String,
    Option<DateTime<Utc>>,
    i64,
    String,
);

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateRoleGrantBody {
    role_id: Uuid,
    privilege_key: String,
    #[serde(default)]
    privilege_name: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-grants",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<RoleGrantItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_role_grants(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<RoleGrantItem>>, AppError> {
    let window = query.window();

    let rows: Vec<RoleGrantRow> = sqlx::query_as(
        r#"
        SELECT rp.id, rp.role_ref, r.name, p.key, p.name, rp.created_at,
               COUNT(c.id) FILTER (WHERE c.is_deleted = false) AS condition_count,
               rp.owner_layer
        FROM role_mm_privilege rp
        JOIN privilege p ON p.id = rp.privilege_ref
        LEFT JOIN role r ON r.id = rp.role_ref
        LEFT JOIN role_privilege_condition c ON c.role_privilege_ref = rp.id
        WHERE rp.is_deleted = false
        GROUP BY rp.id, rp.role_ref, r.name, p.key, p.name, rp.created_at, rp.owner_layer
        ORDER BY rp.created_at DESC NULLS LAST
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM role_mm_privilege WHERE is_deleted = false")
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
                privilege_key,
                privilege_name,
                granted_on,
                condition_count,
                owner_layer,
            )| {
                RoleGrantItem {
                    id,
                    role_id,
                    role_name,
                    privilege_key,
                    privilege_name,
                    granted_on,
                    condition_count,
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

#[utoipa::path(
    post,
    path = "/api/v1/admin/security/role-grants",
    tag = "admin-security",
    request_body = CreateRoleGrantBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = RoleGrantItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or a revoked grant being restored is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_role_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CreateRoleGrantBody>,
) -> Result<(StatusCode, Json<RoleGrantItem>), AppError> {
    let key = body.privilege_key.trim();
    if key.is_empty() {
        return Err(AppError::Validation("privilege_key is required".into()));
    }

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
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let display_name = body.privilege_name.as_deref().unwrap_or(key);
    let mut tx = access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "role_mm_privilege",
        None,
    )
    .await?;
    // Minted in the grant's transaction (it used to commit on its own first),
    // so a refused grant leaves no orphan privilege and the recorded
    // `ensure_privilege` op commits with its grant.
    let (privilege_id, privilege_created) = ensure_privilege_in_tx(
        &mut tx,
        key,
        display_name,
        "Created via role-privileges admin page",
        layer,
    )
    .await?;
    // A live grant for the pair is re-granted as a no-op (nothing to record,
    // nothing of its layer changes); a revoked one is restored, which is a
    // change to that row and needs its layer.
    let existing: Option<(bool, String)> = sqlx::query_as(
        "SELECT is_deleted, owner_layer FROM role_mm_privilege \
         WHERE role_ref = $1 AND privilege_ref = $2 FOR UPDATE",
    )
    .bind(body.role_id)
    .bind(privilege_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let grant_changes = match &existing {
        Some((false, _)) => false,
        Some((true, owner)) => {
            recording.check_owner(parse_owner_layer(owner)?)?;
            true
        }
        None => true,
    };
    let grant_id = upsert_role_privilege_grant(&mut *tx, body.role_id, privilege_id, layer).await?;
    mark_role_customized(&mut *tx, body.role_id).await?;
    let row: (Uuid, Option<DateTime<Utc>>, String) =
        sqlx::query_as("SELECT id, created_at, owner_layer FROM role_mm_privilege WHERE id = $1")
            .bind(grant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if privilege_created {
        let snapshot = snapshot_row(&mut tx, PRIVILEGE_SNAPSHOT, privilege_id).await?;
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::EnsurePrivilege,
                    "privilege",
                    privilege_id,
                    serde_json::json!({ "privilege": key }),
                    snapshot,
                ),
            )
            .await?;
    }
    if grant_changes {
        let snapshot = snapshot_row(&mut tx, GRANT_SNAPSHOT, grant_id).await?;
        recording
            .record(
                tx.tx(),
                security_op(
                    Op::GrantRolePrivilege,
                    "role_privilege",
                    grant_id,
                    serde_json::json!({ "role": role_name, "privilege": key }),
                    snapshot,
                ),
            )
            .await?;
    }
    tx.event_mut().set_record_id(grant_id);
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, body.role_id).await?,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleGrantItem {
            id: row.0,
            role_id: body.role_id,
            role_name: Some(role_name),
            privilege_key: key.to_owned(),
            privilege_name: display_name.to_owned(),
            granted_on: row.1,
            condition_count: 0,
            owner_layer: row.2,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/role-grants/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the grant is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_role_grant(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(grant_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "role_mm_privilege",
        Some(grant_id),
    )
    .await?;
    let live: Option<(String, String, String)> = sqlx::query_as(
        "SELECT rp.owner_layer, r.name, p.key FROM role_mm_privilege rp \
         JOIN role r ON r.id = rp.role_ref \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.id = $1 AND rp.is_deleted = false FOR UPDATE OF rp",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (owner, role_name, privilege_key) = live.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner)?)?;
    let role_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role_mm_privilege SET is_deleted = true, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING role_ref",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let role_id = role_id.ok_or(AppError::NotFound)?;
    mark_role_customized(&mut *tx, role_id).await?;
    let snapshot = snapshot_row(&mut tx, GRANT_SNAPSHOT, grant_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::RevokeRolePrivilege,
                "role_privilege",
                grant_id,
                serde_json::json!({ "role": role_name, "privilege": privilege_key }),
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
            "/api/v1/admin/security/role-grants",
            get(list_role_grants).post(create_role_grant),
        )
        .route(
            "/api/v1/admin/security/role-grants/{id}",
            axum::routing::delete(delete_role_grant),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_role_grants, create_role_grant, delete_role_grant))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

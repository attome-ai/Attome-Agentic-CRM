//! Positions (F138 position hierarchy). A position is a pure hierarchy node
//! — no privileges of its own (same posture as `teams`): it exists only to
//! answer "who is a subordinate of whom" for `attome_security::rls_predicate`'s
//! position-tier OR-branch. A role opts into extending its existing
//! `access_level` down a holder's position subtree via the
//! `position_hierarchy_enabled` flag/endpoint (`role_entity_access`), not via
//! anything on the position itself. A user may hold more than one position at
//! once (dual-hatting, interim coverage) — `user_account_mm_position` is
//! M:M, same shape as `user_account_mm_team`.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
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

use super::shared::invalidate_sync_all;
use attome_types::ErrorResponse;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct PositionItem {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    parent_position_id: Option<Uuid>,
}

impl std::fmt::Debug for PositionItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PositionItem").finish_non_exhaustive()
    }
}

/// List positions
///
/// The position hierarchy used by position-based record access. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/positions",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PositionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_positions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PositionItem>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, String, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, name, description, parent_position_ref FROM position \
         WHERE is_deleted = false ORDER BY name LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM position WHERE is_deleted = false")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, name, description, parent_position_id)| PositionItem {
            id,
            name,
            description,
            parent_position_id,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreatePositionBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parent_position_id: Option<Uuid>,
}

async fn position_exists(db: &attome_db::DbPool, position_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM position WHERE id = $1 AND is_deleted = false)")
        .bind(position_id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Create a position
///
/// Adds a position to the hierarchy. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/positions",
    tag = "admin-security",
    request_body = CreatePositionBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = PositionItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_position(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreatePositionBody>,
) -> Result<(StatusCode, Json<PositionItem>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }

    if let Some(parent_id) = body.parent_position_id
        && !position_exists(&state.base.db, parent_id).await?
    {
        return Err(AppError::Validation(
            "no active position found with this parent_position_id".into(),
        ));
    }
    // A brand-new position has no children yet, so it cannot already be an
    // ancestor of its chosen parent — the cycle guard only matters when
    // reparenting an EXISTING position (see update_position_parent below).

    let id = Uuid::now_v7();
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "position",
        Some(id),
    )
    .await?;
    sqlx::query(
        "INSERT INTO position (id, name, description, parent_position_ref) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(body.description.as_deref())
    .bind(body.parent_position_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(PositionItem {
            id,
            name: name.to_owned(),
            description: body.description.clone(),
            parent_position_id: body.parent_position_id,
        }),
    ))
}

#[derive(Deserialize, ToSchema)]
pub(super) struct UpdatePositionParentBody {
    #[serde(default)]
    parent_position_id: Option<Uuid>,
}

/// Move a position
///
/// Reparents an existing position — the mutation `create_position` alone
/// can't cover. Guarded against creating a cycle via
/// `would_create_position_cycle` before writing;
/// `resolve_subordinate_user_ids`'s own recursive-CTE depth bound is defense
/// in depth on top of this, not the primary guard.
#[utoipa::path(
    put,
    path = "/api/v1/admin/security/positions/{id}/parent",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The position")),
    request_body = UpdatePositionParentBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn update_position_parent(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(position_id): Path<Uuid>,
    Json(body): Json<UpdatePositionParentBody>,
) -> Result<StatusCode, AppError> {
    if !position_exists(&state.base.db, position_id).await? {
        return Err(AppError::NotFound);
    }

    if let Some(parent_id) = body.parent_position_id {
        if !position_exists(&state.base.db, parent_id).await? {
            return Err(AppError::Validation(
                "no active position found with this parent_position_id".into(),
            ));
        }
        if crate::db::would_create_position_cycle(&state.base.db, position_id, parent_id).await? {
            return Err(AppError::Validation(
                "this parent would create a cycle in the position hierarchy".into(),
            ));
        }
    }

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Update,
        ctx.user_id,
        "position",
        Some(position_id),
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE position SET parent_position_ref = $1, updated_at = NOW(), \
         row_version = row_version + 1 WHERE id = $2 AND is_deleted = false",
    )
    .bind(body.parent_position_id)
    .bind(position_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    // `position_exists` above is a separate query, not a lock — a concurrent
    // delete of this position between that check and this UPDATE must not
    // silently no-op behind a 204.
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;

    // Every current holder of THIS position has a now-stale cached
    // subordinate_user_ids and is invalidated directly. Holders of an
    // ancestor position further up the (newly changed) chain are not fanned
    // out to here — same accepted, bounded-staleness posture
    // `organization`'s own un-invalidated hierarchy edits already have
    // in this codebase (no admin endpoint mutates that tree either); the
    // ordinary D-012 60s cache TTL covers the rest.
    let holder_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_position \
         WHERE position_ref = $1 AND is_deleted = false",
    )
    .bind(position_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    invalidate_sync_all(&state.base.security, holder_ids).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete a position
///
/// Deletes a position. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/positions/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The position")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_position(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(position_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let holder_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_position \
         WHERE position_ref = $1 AND is_deleted = false",
    )
    .bind(position_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::SoftDelete,
        ctx.user_id,
        "position",
        Some(position_id),
    )
    .await?;
    let deleted: Option<Uuid> = sqlx::query_scalar(
        "UPDATE position SET is_deleted = true, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING id",
    )
    .bind(position_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    deleted.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    invalidate_sync_all(&state.base.security, holder_ids).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub(super) struct AddPositionMemberBody {
    user_email: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PositionMemberItem {
    id: Uuid,
    user_id: Uuid,
    user_email: String,
}

/// Put a user in a position
///
/// Assigns a user to a position in the hierarchy. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/positions/{id}/members",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The position")),
    request_body = AddPositionMemberBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = PositionMemberItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn add_position_member(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(position_id): Path<Uuid>,
    Json(body): Json<AddPositionMemberBody>,
) -> Result<(StatusCode, Json<PositionMemberItem>), AppError> {
    let email = body.user_email.trim();
    if email.is_empty() {
        return Err(AppError::Validation("user_email is required".into()));
    }

    if !position_exists(&state.base.db, position_id).await? {
        return Err(AppError::Validation(
            "no active position found with this position_id".into(),
        ));
    }

    let user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let user_id = user_id
        .ok_or_else(|| AppError::Validation(format!("no user found with email '{email}'")))?;

    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Grant,
        ctx.user_id,
        "user_account_mm_position",
        None,
    )
    .await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_account_mm_position (id, user_ref, position_ref) VALUES ($1, $2, $3) \
         ON CONFLICT (user_ref, position_ref) DO UPDATE SET is_deleted = false, updated_at = NOW() \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(position_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    // The new holder's own cached SecurityContext changed directly and is
    // invalidated here. Existing holders of an ANCESTOR position (whose
    // subordinate set just gained a member) are not fanned out to — see
    // `update_position_parent`'s doc comment for why that's an accepted,
    // bounded staleness window rather than a gap unique to this endpoint.
    state.base.security.invalidate_sync(user_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(PositionMemberItem {
            id,
            user_id,
            user_email: email.to_owned(),
        }),
    ))
}

/// Take a user out of a position
///
/// Ends a user's place in a position. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/positions/{id}/members/{user_id}",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The position"),
        ("user_id" = Uuid, Path, description = "The user"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn remove_position_member(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((position_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = super::shared::access_tx(
        &state,
        AuditOperation::Revoke,
        ctx.user_id,
        "user_account_mm_position",
        None,
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account_mm_position SET is_deleted = true, updated_at = NOW() \
         WHERE position_ref = $1 AND user_ref = $2 AND is_deleted = false RETURNING user_ref",
    )
    .bind(position_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    removed.ok_or(AppError::NotFound)?;
    tx.commit().await?;

    state.base.security.invalidate_sync(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/positions",
            get(list_positions).post(create_position),
        )
        .route(
            "/api/v1/admin/security/positions/{id}/parent",
            axum::routing::put(update_position_parent),
        )
        .route(
            "/api/v1/admin/security/positions/{id}",
            axum::routing::delete(delete_position),
        )
        .route(
            "/api/v1/admin/security/positions/{id}/members",
            axum::routing::post(add_position_member),
        )
        .route(
            "/api/v1/admin/security/positions/{id}/members/{user_id}",
            axum::routing::delete(remove_position_member),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_positions,
    create_position,
    update_position_parent,
    delete_position,
    add_position_member,
    remove_position_member
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

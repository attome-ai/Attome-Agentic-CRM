//! Q1-T9: a sign-in provider's group mappings, under
//! `/api/v1/admin/security/oidc-providers/{id}/group-mappings`. Each maps one
//! value of the provider's groups claim to a team or a role; at each sign-in
//! through the provider the person gets what their groups map to
//! (`crate::oidc_mapping`). A mapping can never grant system administration:
//! a role carrying `system.admin`, or a team with such a role, is refused
//! with 422 `mapping_cannot_grant_admin`.
//!
//! `system.admin` only, like the providers. Each change is audited in its
//! own transaction.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const ENTITY: &str = "oidc_group_mapping";

/// One group mapping: a value of the groups claim and the team or the role
/// it gives.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct OidcGroupMappingItem {
    pub id: Uuid,
    pub provider_id: Uuid,
    /// The value of the provider's groups claim.
    pub claim_value: String,
    pub team_id: Option<Uuid>,
    pub role_id: Option<Uuid>,
}

/// What to map. Exactly one of `team_id` and `role_id`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOidcGroupMappingBody {
    /// The value of the provider's groups claim, such as a group id.
    pub claim_value: String,
    #[serde(default)]
    pub team_id: Option<Uuid>,
    #[serde(default)]
    pub role_id: Option<Uuid>,
}

const SELECT: &str = "SELECT id, provider_ref AS provider_id, claim_value, team_ref AS team_id, \
        role_ref AS role_id FROM oidc_group_mapping";

/// A provider added on screen, or 404.
async fn provider(db: &mut sqlx::PgConnection, id: Uuid) -> Result<(), AppError> {
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM oidc_provider WHERE id = $1 AND NOT is_deleted")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    found.map(|_| ()).ok_or(AppError::NotFound)
}

async fn config_tx(
    state: &EngineState,
    operation: AuditOperation,
    actor: Uuid,
    id: Uuid,
) -> Result<SecurityTx<'_>, AppError> {
    SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            ENTITY,
            Some(id),
        ),
    )
    .await
}

/// Sign-in provider group mappings
///
/// The provider's group mappings: each value of its groups claim and the team or role it gives at sign-in. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/oidc-providers/{id}/group-mappings",
    operation_id = "list_oidc_group_mappings",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The provider added on screen"), OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OidcGroupMappingItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider added on screen", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_mappings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OidcGroupMappingItem>>, AppError> {
    let window = query.window();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    provider(&mut conn, id).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_group_mapping WHERE provider_ref = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<OidcGroupMappingItem> = sqlx::query_as(&format!(
        "{SELECT} WHERE provider_ref = $1 ORDER BY claim_value, id LIMIT $2 OFFSET $3"
    ))
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a sign-in provider group mapping
///
/// Maps a value of the provider's groups claim to a team or a role, given at each sign-in through the provider. A role carrying system administration, or a team with such a role, is refused. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/oidc-providers/{id}/group-mappings",
    operation_id = "create_oidc_group_mapping",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The provider added on screen")),
    request_body = CreateOidcGroupMappingBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Mapped", body = OidcGroupMappingItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider added on screen", body = ErrorResponse),
        (status = 409, description = "The same mapping exists", body = ErrorResponse),
        (status = 422, description = "Not exactly one live team or role, an empty claim value, or one that would grant system administration (`mapping_cannot_grant_admin`)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateOidcGroupMappingBody>,
) -> Result<(StatusCode, Json<OidcGroupMappingItem>), AppError> {
    let claim_value = body.claim_value.trim();
    if claim_value.is_empty() || claim_value.chars().count() > 500 {
        return Err(AppError::Validation(
            "claim_value is 1 to 500 characters".into(),
        ));
    }
    if body.team_id.is_some() == body.role_id.is_some() {
        return Err(AppError::Validation(
            "give exactly one of team_id and role_id".into(),
        ));
    }
    let mapping_id = Uuid::now_v7();
    let mut tx = config_tx(&state, AuditOperation::Create, ctx.user_id, mapping_id).await?;
    provider(&mut tx, id).await?;
    let (live, admin) = match (body.team_id, body.role_id) {
        (Some(team), _) => {
            let live: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM team WHERE id = $1 AND NOT is_deleted)",
            )
            .bind(team)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (
                live,
                crate::oidc_mapping::team_grants_admin(&mut tx, team).await?,
            )
        }
        (None, Some(role)) => {
            let live: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM role WHERE id = $1 AND NOT is_deleted)",
            )
            .bind(role)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (
                live,
                crate::oidc_mapping::role_grants_admin(&mut tx, role).await?,
            )
        }
        (None, None) => (false, false),
    };
    if !live {
        return Err(AppError::Validation(
            "no live team or role with that id".into(),
        ));
    }
    if admin {
        return Err(AppError::Validation("mapping_cannot_grant_admin".into()));
    }
    // The unique constraint treats the empty side as distinct, so the same
    // mapping is looked for first.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oidc_group_mapping \
                         WHERE provider_ref = $1 AND claim_value = $2 \
                           AND team_ref IS NOT DISTINCT FROM $3 \
                           AND role_ref IS NOT DISTINCT FROM $4)",
    )
    .bind(id)
    .bind(claim_value)
    .bind(body.team_id)
    .bind(body.role_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Err(AppError::Conflict("the same mapping exists"));
    }
    let item: OidcGroupMappingItem = sqlx::query_as(
        "INSERT INTO oidc_group_mapping (id, provider_ref, claim_value, team_ref, role_ref) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, provider_ref AS provider_id, claim_value, team_ref AS team_id, \
                   role_ref AS role_id",
    )
    .bind(mapping_id)
    .bind(id)
    .bind(claim_value)
    .bind(body.team_id)
    .bind(body.role_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match attome_db::classify(e) {
        AppError::Conflict(_) => AppError::Conflict("the same mapping exists"),
        other => other,
    })?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(item)))
}

/// Remove a sign-in provider group mapping
///
/// The group no longer gives its team or role. People keep what it gave until their next sign-in through the provider, which removes it. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/oidc-providers/{id}/group-mappings/{mapping_id}",
    operation_id = "delete_oidc_group_mapping",
    tag = "admin-security",
    params(
        ("id" = Uuid, Path, description = "The provider added on screen"),
        ("mapping_id" = Uuid, Path, description = "The group mapping"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such group mapping on this provider", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((id, mapping_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = config_tx(&state, AuditOperation::HardDelete, ctx.user_id, mapping_id).await?;
    let n = sqlx::query("DELETE FROM oidc_group_mapping WHERE id = $1 AND provider_ref = $2")
        .bind(mapping_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_mappings, create_mapping, delete_mapping))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/oidc-providers/{id}/group-mappings",
            get(list_mappings).post(create_mapping),
        )
        .route(
            "/api/v1/admin/security/oidc-providers/{id}/group-mappings/{mapping_id}",
            axum::routing::delete(delete_mapping),
        )
}

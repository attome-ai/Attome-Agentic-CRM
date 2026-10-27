//! S11-T2: the administrator registers and removes the identity-provider
//! trusts of an S2S client ([`crate::federated`]).

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most trusts one client holds; the list answers them all.
const MAX_TRUSTS_PER_CLIENT: i64 = 50;

/// A trust to register.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTrustBody {
    /// The identity provider's exact `iss`, e.g.
    /// `https://login.microsoftonline.com/{tenant}/v2.0`.
    pub issuer: String,
    /// The audience its tokens must carry for this deployment.
    pub audience: String,
    /// The workload's exact `sub`.
    pub subject: String,
    /// The provider's JWKS URL (`https://`).
    pub jwks_uri: String,
}

/// A registered trust.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrustItem {
    pub id: Uuid,
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub jwks_uri: String,
    pub created_at: DateTime<Utc>,
}

fn required(field: &str, value: &str, max: usize) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max {
        return Err(AppError::Validation(format!(
            "{field} is required (at most {max} characters)"
        )));
    }
    Ok(value.to_owned())
}

/// The body, checked: every field present, the JWKS fetched over `https`.
fn checked(body: &CreateTrustBody) -> Result<CreateTrustBody, AppError> {
    let jwks_uri = required("jwks_uri", &body.jwks_uri, 2048)?;
    if !jwks_uri.starts_with("https://") {
        return Err(AppError::Validation(
            "jwks_uri must be an https:// URL".into(),
        ));
    }
    Ok(CreateTrustBody {
        issuer: required("issuer", &body.issuer, 2048)?,
        audience: required("audience", &body.audience, 2048)?,
        subject: required("subject", &body.subject, 1024)?,
        jwks_uri,
    })
}

async fn client_exists(state: &EngineState, client_db_id: Uuid) -> Result<(), AppError> {
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM s2s_client WHERE id = $1 AND is_deleted = FALSE")
            .bind(client_db_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    found.map(|_| ()).ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/trusts",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Every trust of the client", body = PaginatedResponse<TrustItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such client", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_trusts(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Security>>,
    Path(client_db_id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<TrustItem>>, AppError> {
    client_exists(&state, client_db_id).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, String, DateTime<Utc>)>(
        r#"
        SELECT id, issuer, audience, subject, jwks_uri, created_at
        FROM s2s_federated_trust
        WHERE client_ref = $1 AND is_deleted = FALSE
        ORDER BY created_at
        LIMIT $2
        "#,
    )
    .bind(client_db_id)
    .bind(MAX_TRUSTS_PER_CLIENT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<TrustItem> = rows
        .into_iter()
        .map(|r| TrustItem {
            id: r.0,
            issuer: r.1,
            audience: r.2,
            subject: r.3,
            jwks_uri: r.4,
            created_at: r.5,
        })
        .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_TRUSTS_PER_CLIENT,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/trusts",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    request_body = CreateTrustBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The trust", body = TrustItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such client", body = ErrorResponse),
        (status = 409, description = "That issuer, audience and subject is already trusted", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_trust(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path(client_db_id): Path<Uuid>,
    Json(body): Json<CreateTrustBody>,
) -> Result<(StatusCode, Json<TrustItem>), AppError> {
    let body = checked(&body)?;
    client_exists(&state, client_db_id).await?;
    crate::admin::require_existing_client_within_area(&state.base.db, &ctx, client_db_id).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "s2s_federated_trust",
            None,
        )
        .comment(format!(
            "issuer {} audience {} subject {}",
            body.issuer, body.audience, body.subject
        )),
    )
    .await?;
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM s2s_federated_trust WHERE client_ref = $1 AND is_deleted = FALSE",
    )
    .bind(client_db_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if held >= MAX_TRUSTS_PER_CLIENT {
        return Err(AppError::Validation(format!(
            "a client holds at most {MAX_TRUSTS_PER_CLIENT} trusts"
        )));
    }
    // The partial unique index refuses a second live trust for the same
    // issuer, audience and subject, so a retry or a race cannot add one.
    let row = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        r#"
        INSERT INTO s2s_federated_trust
            (client_ref, issuer, audience, subject, jwks_uri, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (issuer, audience, subject) WHERE NOT is_deleted DO NOTHING
        RETURNING id, created_at
        "#,
    )
    .bind(client_db_id)
    .bind(&body.issuer)
    .bind(&body.audience)
    .bind(&body.subject)
    .bind(&body.jwks_uri)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((id, created_at)) = row else {
        return Err(AppError::Conflict(
            "that issuer, audience and subject is already trusted",
        ));
    };
    tx.event_mut().set_record_id(id);
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(TrustItem {
            id,
            issuer: body.issuer,
            audience: body.audience,
            subject: body.subject,
            jwks_uri: body.jwks_uri,
            created_at,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/trusts/{trust_id}",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path), ("trust_id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "The trust is removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such trust on this client", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_trust(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path((client_db_id, trust_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "s2s_federated_trust",
            Some(trust_id),
        ),
    )
    .await?;
    let removed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE s2s_federated_trust SET is_deleted = TRUE
         WHERE id = $1 AND client_ref = $2 AND is_deleted = FALSE
         RETURNING id",
    )
    .bind(trust_id)
    .bind(client_db_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if removed.is_none() {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/trusts",
            get(list_trusts).post(create_trust),
        )
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/trusts/{trust_id}",
            delete(delete_trust),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_trusts, create_trust, delete_trust))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

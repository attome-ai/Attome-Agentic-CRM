//! K5-T2: who may read a page, and signed preview links.
//!
//! A page's `audience` is `public` (anyone, through `/api/v1/content/view`
//! and `/api/v1/content/delivery`) or `internal` (signed-in people, through
//! `/api/v1/content/internal`); the public routes answer an internal page
//! with the same 404 as a page that does not exist, so its existence leaks
//! nothing. A preview link lets someone without an account read a page's
//! current draft until the link expires: it is signed with the active
//! `auth.jwt_secret` under its own domain (`attome_auth::signed_link`), so it
//! needs no storage and opens nothing else.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The audiences a page may have.
pub const AUDIENCES: [&str; 2] = ["public", "internal"];
/// The domain preview links are signed under.
pub const PREVIEW_DOMAIN: &str = "attome-content-preview";
/// Longest a preview link lives, in minutes (seven days).
pub const MAX_PREVIEW_MINUTES: i64 = 7 * 24 * 60;

/// `PUT .../audience`.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AudienceBody {
    /// `public` or `internal`.
    pub audience: String,
}

/// `POST .../preview-link`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct PreviewLinkBody {
    /// How long the link works, 1 to 10,080 minutes; 60 when unset.
    #[serde(default)]
    pub minutes: Option<i64>,
}

/// A signed preview link.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewLink {
    /// The token for `GET /api/v1/content/preview?token=`.
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// The signing secret: the active token-signing key.
pub fn preview_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// The page a preview token names, if it is valid now. Pure but for the clock.
pub fn preview_page(secret: &str, token: &str, now: DateTime<Utc>) -> Option<Uuid> {
    attome_auth::signed_link::verify(secret, PREVIEW_DOMAIN, token, now.timestamp())
        .and_then(|subject| Uuid::parse_str(&subject).ok())
}

/// Sets who may read a page (K5-T2).
///
/// `public`: anyone, through the public view and delivery routes.
/// `internal`: signed-in people only; the public routes answer it with the
/// same 404 as a missing page.
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/pages/{id}/audience",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id")),
    request_body = AudienceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The audience was set", body = AudienceBody),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 422, description = "The audience is not public or internal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_audience(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<AudienceBody>,
) -> Result<Json<AudienceBody>, AppError> {
    if !AUDIENCES.contains(&body.audience.as_str()) {
        return Err(AppError::Validation(
            "audience is public or internal".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE content_page SET audience = $2, row_version = row_version + 1, \
             updated_at = NOW(), updated_by = $3 \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .bind(&body.audience)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.audience")
        .comment(format!("audience {}", body.audience)),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(body))
}

/// A signed link to a page's current draft (K5-T2).
///
/// Anyone with the link reads the draft until it expires (60 minutes unless
/// `minutes` says otherwise, at most seven days); it opens nothing else.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/preview-link",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id")),
    request_body = PreviewLinkBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The preview link", body = PreviewLink),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "Page not found", body = ErrorResponse),
        (status = 422, description = "minutes is out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_preview_link(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<PreviewLinkBody>,
) -> Result<Json<PreviewLink>, AppError> {
    let minutes = body.minutes.unwrap_or(60);
    if !(1..=MAX_PREVIEW_MINUTES).contains(&minutes) {
        return Err(AppError::Validation(format!(
            "minutes is 1 to {MAX_PREVIEW_MINUTES}"
        )));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM content_page WHERE id = $1 AND is_deleted = FALSE)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let expires_at = Utc::now() + chrono::Duration::minutes(minutes);
    let token = attome_auth::signed_link::sign(
        &preview_secret(&state)?,
        PREVIEW_DOMAIN,
        &id.to_string(),
        expires_at.timestamp(),
    )
    .ok_or_else(|| AppError::internal("the preview link could not be signed"))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.preview_link")
        .comment(format!("preview link for {minutes} minutes")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(PreviewLink { token, expires_at }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/pages/{id}/audience",
            put(set_audience),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/preview-link",
            post(create_preview_link),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(set_audience, create_preview_link))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_token_names_its_page_until_it_expires() {
        let page = Uuid::now_v7();
        let now = Utc::now();
        let token = attome_auth::signed_link::sign(
            "secret",
            PREVIEW_DOMAIN,
            &page.to_string(),
            (now + chrono::Duration::minutes(5)).timestamp(),
        )
        .unwrap_or_default();
        assert_eq!(preview_page("secret", &token, now), Some(page));
        assert_eq!(
            preview_page("secret", &token, now + chrono::Duration::minutes(6)),
            None
        );
        assert_eq!(preview_page("other", &token, now), None);
        let not_a_page = attome_auth::signed_link::sign(
            "secret",
            PREVIEW_DOMAIN,
            "x",
            (now + chrono::Duration::minutes(5)).timestamp(),
        )
        .unwrap_or_default();
        assert_eq!(preview_page("secret", &not_a_page, now), None);
    }
}

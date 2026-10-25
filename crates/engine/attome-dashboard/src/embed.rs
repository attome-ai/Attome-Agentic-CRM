//! P8-T1: embedding a dashboard in another site.
//!
//! An embed (`dashboard_embed`, migration 0250) names a dashboard, the
//! origins that may frame it and whose behalf it reads as (the
//! administrator who made it). The host site's server asks for a viewer
//! token (`POST /api/v1/admin/dashboard-embeds/{id}/tokens`, with an API
//! key) carrying the parameters that viewer is fixed to (`customer: …`);
//! the token is signed and short-lived ([`MAX_TOKEN_SECS`]), so the browser
//! can neither widen the parameters nor keep the token.
//!
//! The browser reads a page's data through the one public route,
//! `POST /api/v1/embed/dashboard/data` `{token, page_id}`: the token is
//! checked, the embed must still be live, the dashboard runs as the embed's
//! creator (their record security applies) with the token's parameters,
//! which a caller cannot override. The answer carries
//! `Content-Security-Policy: frame-ancestors <the embed's origins>` (and no
//! `X-Frame-Options`), so only those sites may frame what it serves.

use std::collections::BTreeMap;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event, x_audit};
use attome_audit::{AuditCategory, AuditOperation, audit_service};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The signing domain of embed tokens.
const TOKEN_DOMAIN: &str = "attome-dashboard/embed";
/// The longest a viewer token lives.
pub const MAX_TOKEN_SECS: i64 = 3600;
/// The most origins one embed allows.
pub const MAX_ORIGINS: usize = 20;

/// An origin a site frames from: `https://host[:port]`, nothing else.
/// Pure.
pub fn origin_ok(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 253
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        && !rest.starts_with(['.', '-', ':'])
}

/// The `frame-ancestors` policy for an embed's origins; `'none'` with
/// none. Pure.
pub fn frame_ancestors(origins: &[String]) -> String {
    let allowed: Vec<&str> = origins
        .iter()
        .map(String::as_str)
        .filter(|o| origin_ok(o))
        .collect();
    if allowed.is_empty() {
        "frame-ancestors 'none'".to_owned()
    } else {
        format!("frame-ancestors {}", allowed.join(" "))
    }
}

/// What a viewer token says: which embed, and the parameters it fixes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenClaims {
    #[serde(rename = "e")]
    pub embed: Uuid,
    #[serde(rename = "p", default)]
    pub parameters: BTreeMap<String, Value>,
}

/// The subject a token signs: the claims as compact JSON (a signed link
/// carries at most `attome_auth::signed_link::MAX_SUBJECT_CHARS`). Pure.
pub fn token_subject(claims: &TokenClaims) -> String {
    serde_json::to_string(claims).unwrap_or_default()
}

/// The claims of a verified subject. Pure.
pub fn claims_of(subject: &str) -> Option<TokenClaims> {
    serde_json::from_str(subject).ok()
}

/// The token lifetime a request may have: 1 to [`MAX_TOKEN_SECS`], 600 by
/// default. Pure.
pub fn token_secs(asked: Option<i64>) -> i64 {
    asked.unwrap_or(600).clamp(1, MAX_TOKEN_SECS)
}

fn signing_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// An embed.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct DashboardEmbed {
    pub id: Uuid,
    pub dashboard_id: Uuid,
    pub allowed_origins: Vec<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An embed to make.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewEmbed {
    /// `https://` origins that may frame the dashboard.
    pub allowed_origins: Vec<String>,
}

/// A viewer token to issue.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewToken {
    /// The dashboard parameters this viewer is fixed to.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub parameters: BTreeMap<String, Value>,
    /// Seconds the token lives: 1 to 3600, 600 by default.
    #[serde(default)]
    pub ttl_secs: Option<i64>,
}

/// An issued viewer token.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmbedToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// A page of an embedded dashboard to read.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbedRead {
    pub token: String,
    pub page_id: Uuid,
}

const EMBED_COLUMNS: &str = "id, dashboard_id, allowed_origins, created_by, created_at, revoked_at";

fn config_event(actor: Uuid, op: AuditOperation, id: Uuid, name: &str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        op,
        actor,
        "dashboard_embed",
        Some(id),
    )
    .named(name)
}

/// Embed a dashboard
///
/// P8-T1: lets the given sites frame the dashboard, reading as the caller.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dashboards/{id}/embeds",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The dashboard")),
    request_body = NewEmbed,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The embed", body = DashboardEmbed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 422, description = "No origins, too many, or one that is not an https origin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_embed(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(dashboard): Path<Uuid>,
    Json(body): Json<NewEmbed>,
) -> Result<(StatusCode, Json<DashboardEmbed>), AppError> {
    if body.allowed_origins.is_empty()
        || body.allowed_origins.len() > MAX_ORIGINS
        || !body.allowed_origins.iter().all(|o| origin_ok(o))
    {
        return Err(AppError::Validation(format!(
            "allowed_origins has 1 to {MAX_ORIGINS} https origins (https://host[:port])"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attome_dashboard WHERE id = $1 AND is_active)",
    )
    .bind(dashboard)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let embed: DashboardEmbed = sqlx::query_as(&format!(
        "INSERT INTO dashboard_embed (dashboard_id, allowed_origins, created_by) \
         VALUES ($1, $2, $3) RETURNING {EMBED_COLUMNS}"
    ))
    .bind(dashboard)
    .bind(&body.allowed_origins)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        config_event(
            ctx.user_id,
            AuditOperation::Create,
            embed.id,
            "dashboard_embed.create",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(embed)))
}

/// Stop an embed
///
/// P8-T1: tokens already issued for it stop working at once.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/dashboard-embeds/{id}",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The embed")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Stopped"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live embed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn revoke_embed(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let stopped = sqlx::query(
        "UPDATE dashboard_embed SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if stopped == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        config_event(
            ctx.user_id,
            AuditOperation::Update,
            id,
            "dashboard_embed.revoke",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Issue a viewer token for an embed
///
/// P8-T1: called by the host site's server, never its browser. The token
/// fixes the given dashboard parameters for one viewer and lives at most an
/// hour.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dashboard-embeds/{id}/tokens",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The embed")),
    request_body = NewToken,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "signs a short-lived viewer token; nothing is stored",
    )))),
    responses(
        (status = 200, description = "The token", body = EmbedToken),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such live embed", body = ErrorResponse),
        (status = 422, description = "The fixed parameters do not fit in a token", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn issue_token(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<NewToken>,
) -> Result<Json<EmbedToken>, AppError> {
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM dashboard_embed WHERE id = $1 AND revoked_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !live {
        return Err(AppError::NotFound);
    }
    let expires_at = Utc::now() + chrono::Duration::seconds(token_secs(body.ttl_secs));
    let subject = token_subject(&TokenClaims {
        embed: id,
        parameters: body.parameters,
    });
    let token = attome_auth::signed_link::sign(
        &signing_secret(&state)?,
        TOKEN_DOMAIN,
        &subject,
        expires_at.timestamp(),
    )
    .ok_or_else(|| {
        AppError::Validation(format!(
            "the fixed parameters are too long for a token (at most {} characters with the embed id)",
            attome_auth::signed_link::MAX_SUBJECT_CHARS
        ))
    })?;
    Ok(Json(EmbedToken { token, expires_at }))
}

/// Read a page of an embedded dashboard
///
/// P8-T1: public; the signed viewer token is the credential. Answers the
/// page's widgets as the embed's creator sees them, with the token's fixed
/// parameters, and only the embed's sites may frame it.
#[utoipa::path(
    post,
    path = "/api/v1/embed/dashboard/data",
    tag = "dashboard",
    request_body = EmbedRead,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads one embedded dashboard page; writes nothing",
    )))),
    responses(
        (status = 200, description = "The page's widgets", body = crate::widget_data::PageDataResponse),
        (status = 401, description = "A token that is malformed, forged or expired", body = ErrorResponse),
        (status = 404, description = "The embed was stopped, or no such page", body = ErrorResponse),
    ),
)]
async fn embed_data(
    State(state): State<EngineState>,
    Json(body): Json<EmbedRead>,
) -> Result<Response, AppError> {
    // A public route: an unlicensed module answers as if it were not there.
    if state
        .modules
        .load()
        .require(attome_modules::MODULE_DASHBOARD)
        .is_err()
    {
        return Err(AppError::NotFound);
    }
    let subject = attome_auth::signed_link::verify(
        &signing_secret(&state)?,
        TOKEN_DOMAIN,
        &body.token,
        Utc::now().timestamp(),
    )
    .ok_or(AppError::Unauthorized)?;
    let claims = claims_of(&subject).ok_or(AppError::Unauthorized)?;
    let embed: Option<(Uuid, Vec<String>, Uuid)> = sqlx::query_as(
        "SELECT dashboard_id, allowed_origins, created_by FROM dashboard_embed \
          WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(claims.embed)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (dashboard, origins, creator) = embed.ok_or(AppError::NotFound)?;
    let ctx = attome_security::resolve_uncached(&state.base.db, creator).await?;
    let inputs = crate::execution::WidgetInputs {
        parameters: claims.parameters,
        ..Default::default()
    };
    let page_data =
        crate::widget_data::run_page(&state, &ctx, dashboard, body.page_id, inputs).await?;
    let mut response = Json(page_data).into_response();
    let policy = HeaderValue::from_str(&frame_ancestors(&origins)).map_err(AppError::internal)?;
    response
        .extensions_mut()
        .insert(attome_server::middleware::security_headers::FrameAncestors(
            policy,
        ));
    Ok(response)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/dashboards/{id}/embeds", post(create_embed))
        .route("/api/v1/admin/dashboard-embeds/{id}", delete(revoke_embed))
        .route(
            "/api/v1/admin/dashboard-embeds/{id}/tokens",
            post(issue_token),
        )
        .route("/api/v1/embed/dashboard/data", post(embed_data))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(create_embed, revoke_embed, issue_token, embed_data))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn embed_token_round_trip_and_tamper() {
        let claims = TokenClaims {
            embed: Uuid::from_u128(7),
            parameters: BTreeMap::from([("customer".to_owned(), json!("C-42"))]),
        };
        let secret = "s".repeat(32);
        let subject = token_subject(&claims);
        let token =
            attome_auth::signed_link::sign(&secret, TOKEN_DOMAIN, &subject, 2_000_000_000).unwrap();
        let back = attome_auth::signed_link::verify(&secret, TOKEN_DOMAIN, &token, 1_900_000_000)
            .and_then(|s| claims_of(&s));
        assert_eq!(back, Some(claims.clone()));
        // Expired, signed for another use, or altered: refused.
        assert!(
            attome_auth::signed_link::verify(&secret, TOKEN_DOMAIN, &token, 2_000_000_001)
                .is_none()
        );
        assert!(
            attome_auth::signed_link::verify(&secret, "other/domain", &token, 1_900_000_000)
                .is_none()
        );
        let mut forged = token.clone();
        forged.insert(0, 'x');
        assert!(
            attome_auth::signed_link::verify(&secret, TOKEN_DOMAIN, &forged, 1_900_000_000)
                .is_none()
        );
        assert_eq!(claims_of("not base64 json"), None);
    }

    #[test]
    fn embed_token_lifetime_is_bounded() {
        assert_eq!(token_secs(None), 600);
        assert_eq!(token_secs(Some(99_999)), MAX_TOKEN_SECS);
        assert_eq!(token_secs(Some(-5)), 1);
    }

    #[test]
    fn embed_token_frame_ancestors_from_https_origins_only() {
        assert!(origin_ok("https://portal.example.sa"));
        assert!(origin_ok("https://intranet.example.com:8443"));
        assert!(!origin_ok("http://portal.example.sa"));
        assert!(!origin_ok("https://evil.example/path"));
        assert!(!origin_ok("https://a.example; script-src *"));
        assert_eq!(
            frame_ancestors(&["https://a.example".into(), "javascript:alert(1)".into()]),
            "frame-ancestors https://a.example"
        );
        assert_eq!(frame_ancestors(&[]), "frame-ancestors 'none'");
    }
}

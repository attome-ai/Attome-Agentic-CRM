//! G12-T3: a web portal on its own domain.
//!
//! - **Domain**: a portal may name one domain (`webportal_domain`, unique),
//!   kept as [`attome_types::text::normalise_domain`] keeps it. Set and
//!   cleared by a user administrator; audited.
//! - **Host routing**: `GET /api/v1/portal-host` answers the keyword of the
//!   live, enabled portal whose domain is the request's host. The web app
//!   asks it at `/` and opens `/p/{keyword}`; every portal call that follows
//!   is same-origin on that domain, so cookies and the same-origin check
//!   work unchanged.
//! - **Certificate**: with `app.tls.acme.enabled`, the server orders one
//!   certificate for the configured domains plus every portal domain it
//!   finds at boot ([`acme_domains`]); a new domain is covered after the
//!   next restart.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::text::normalise_domain;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, header},
    routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::provision;

/// A portal's own domain; `null` when it has none.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PortalDomain {
    /// The host name, e.g. `support.example.com`; `null` clears it.
    pub domain: Option<String>,
}

/// The portal served on the request's host.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalHost {
    pub keyword: String,
}

/// The domain stored for `portal_id`.
pub async fn domain_of(
    conn: &mut PgConnection,
    portal_id: Uuid,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT domain FROM webportal_domain WHERE webportal_id = $1")
        .bind(portal_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// Sets (or, with `None`, clears) `portal_id`'s domain. A domain another
/// portal holds is a conflict; one that is not a plain host name is refused.
pub async fn set_domain(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    domain: Option<&str>,
) -> Result<Option<String>, AppError> {
    provision::load_portal(conn, portal_id).await?;
    let Some(raw) = domain.map(str::trim).filter(|d| !d.is_empty()) else {
        sqlx::query("DELETE FROM webportal_domain WHERE webportal_id = $1")
            .bind(portal_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
        return Ok(None);
    };
    let domain = normalise_domain(raw).ok_or_else(|| {
        AppError::Validation("domain must be a host name such as support.example.com".into())
    })?;
    provision::lock(conn, format!("attome-portal/domain:{domain}")).await?;
    let holder: Option<Uuid> =
        sqlx::query_scalar("SELECT webportal_id FROM webportal_domain WHERE domain = $1")
            .bind(&domain)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    if holder.is_some_and(|h| h != portal_id) {
        return Err(AppError::Conflict("another web portal uses this domain"));
    }
    sqlx::query(
        "INSERT INTO webportal_domain (webportal_id, domain, created_by) VALUES ($1, $2, $3) \
         ON CONFLICT (webportal_id) DO UPDATE SET domain = EXCLUDED.domain, \
           created_by = EXCLUDED.created_by, created_at = now()",
    )
    .bind(portal_id)
    .bind(&domain)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(domain))
}

/// The keyword of the live, enabled portal whose domain is `host`.
pub async fn portal_for_host(db: &DbPool, host: &str) -> Result<Option<String>, AppError> {
    let Some(domain) = normalise_domain(host) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT w.keyword FROM webportal_domain d JOIN webportal w ON w.id = d.webportal_id \
          WHERE d.domain = $1 AND w.is_active IS NOT FALSE AND w.is_enabled IS TRUE",
    )
    .bind(domain)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Every live portal's domain, for the ACME certificate at boot. Before the
/// portal tables exist (a fresh database's first boot), none.
pub async fn acme_domains(db: &DbPool) -> Vec<String> {
    let found: Result<Vec<String>, sqlx::Error> = sqlx::query_scalar(
        "SELECT d.domain FROM webportal_domain d JOIN webportal w ON w.id = d.webportal_id \
          WHERE w.is_active IS NOT FALSE ORDER BY d.domain",
    )
    .fetch_all(db)
    .await;
    found.unwrap_or_else(|error| {
        tracing::warn!(%error, "tls: could not read the web portal domains; ACME covers the configured domains only");
        Vec::new()
    })
}

fn event(actor: Uuid, portal_id: Uuid) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        actor,
        "webportal",
        Some(portal_id),
    )
}

/// A web portal's domain
///
/// G12-T3: the domain the portal is served on, if any. User administrators only.
#[utoipa::path(
    get,
    operation_id = "portal_admin_get_domain",
    path = "/api/v1/admin/webportals/{id}/domain",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    responses(
        (status = 200, description = "The portal's domain", body = PortalDomain),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_domain(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PortalDomain>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    provision::load_portal(&mut conn, id).await?;
    Ok(Json(PortalDomain {
        domain: domain_of(&mut conn, id).await?,
    }))
}

/// Serve a web portal on its own domain
///
/// G12-T3: sets the domain the portal is served on (`null` clears it). Point the domain's DNS at
/// this server; with ACME on, its certificate is ordered at the next restart. User administrators
/// only. Audited.
#[utoipa::path(
    put,
    operation_id = "portal_admin_put_domain",
    path = "/api/v1/admin/webportals/{id}/domain",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "Web portal id")),
    request_body = PortalDomain,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The domain, as stored", body = PortalDomain),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Another portal uses this domain", body = ErrorResponse),
        (status = 422, description = "Not a host name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PortalDomain>,
) -> Result<Json<PortalDomain>, AppError> {
    let mut tx = SecurityTx::begin(&state, event(ctx.user_id, id)).await?;
    let domain = set_domain(&mut tx, ctx.user_id, id, body.domain.as_deref()).await?;
    tx.commit().await?;
    crate::cache::invalidate(&state).await;
    Ok(Json(PortalDomain { domain }))
}

/// The web portal on this host
///
/// G12-T3: the keyword of the enabled web portal served on the request's host, so the web app
/// opens it at `/`. No sign-in; 404 when no portal uses the host.
#[utoipa::path(
    get,
    operation_id = "portal_host",
    path = "/api/v1/portal-host",
    tag = "auth",
    responses(
        (status = 200, description = "The portal on this host", body = PortalHost),
        (status = 404, description = "No portal uses this host", body = ErrorResponse),
    ),
)]
async fn portal_host(
    State(state): State<EngineState>,
    headers: HeaderMap,
) -> Result<Json<PortalHost>, AppError> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    portal_for_host(&state.base.db, host)
        .await?
        .map(|keyword| Json(PortalHost { keyword }))
        .ok_or(AppError::NotFound)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/webportals/{id}/domain",
            get(get_domain).put(put_domain),
        )
        .route("/api/v1/portal-host", get(portal_host))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_domain, put_domain, portal_host),
    components(schemas(PortalDomain, PortalHost))
)]
pub(crate) struct DomainApiDoc;

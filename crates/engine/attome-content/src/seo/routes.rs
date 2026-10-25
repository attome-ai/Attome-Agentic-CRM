//! E13-T8: the SEO administration routes. Like every content admin route
//! they need `Authorized<Admin>` and sit behind the Content Management
//! licence gate (`admin::routes`). Handlers parse, call one function of
//! [`super::site`] and shape the answer.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::settings::PageSeo;
use super::site::{self, SeoFinding, SeoTopic, SeoTopicBody};

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match is required for every update".into()))?
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"')
        .to_owned();
    raw.parse().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {raw}"
        ))
    })
}

/// A page's search settings, as the SEO panel reads them.
#[derive(Debug, Serialize, ToSchema)]
pub struct PageSeoView {
    pub settings: PageSeo,
    /// Send back as `If-Match` on the next `PUT`.
    pub row_version: i64,
}

/// A page's search settings
///
/// E13-T8: the title, description, canonical URL, robots flags and Open
/// Graph card stored on the page, with its row version.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/seo",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page")),
    responses(
        (status = 200, description = "The page's search settings", body = PageSeoView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such page", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_page_seo(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PageSeoView>, AppError> {
    let (settings, row_version) = super::settings::get_page_seo(&state.base.db, id).await?;
    Ok(Json(PageSeoView {
        settings,
        row_version,
    }))
}

/// Change a page's search settings
///
/// E13-T8: replaces the settings at the `If-Match` row version. A change to
/// the canonical URL or the noindex flag is recorded as a configuration
/// event in the same transaction.
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/pages/{id}/seo",
    tag = "admin-content",
    params(
        ("id" = Uuid, Path, description = "The page"),
        ("If-Match" = String, Header, description = "The row_version last read"),
    ),
    request_body = PageSeo,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The saved settings and the new row version", body = PageSeoView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such page", body = ErrorResponse),
        (status = 409, description = "The page changed since that row version", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed, or a setting out of bounds", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_page_seo(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<PageSeo>,
) -> Result<Json<PageSeoView>, AppError> {
    let expected = if_match(&headers)?;
    let row_version = site::save_page_seo(&state, ctx.user_id, id, &body, expected).await?;
    let (settings, _) = super::settings::get_page_seo(&state.base.db, id).await?;
    Ok(Json(PageSeoView {
        settings,
        row_version,
    }))
}

/// A page's search findings
///
/// E13-T8: the findings of the page's last audit, errors first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/seo/findings",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page"), OnePageQuery),
    responses(
        (status = 200, description = "A page of findings", body = PaginatedResponse<SeoFinding>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such page", body = ErrorResponse),
        (status = 422, description = "Paging out of bounds", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn page_findings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SeoFinding>>, AppError> {
    super::settings::get_page_seo(&state.base.db, id).await?;
    let window = q.window();
    let (rows, total) = site::findings(&state.base.db, id, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// What an audit run found.
#[derive(Debug, Serialize, ToSchema)]
pub struct SeoAuditRun {
    /// 0 to 100.
    pub score: i16,
    pub audited_at: DateTime<Utc>,
}

/// Audit a page now
///
/// E13-T8: runs the page audit at once (whether or not audits run on save)
/// and replaces the stored findings and score.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/seo/audit",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "recomputes the page's derived search findings and score; changes no content or setting",
    )))),
    responses(
        (status = 200, description = "The new score", body = SeoAuditRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such page", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn audit_page_now(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<SeoAuditRun>, AppError> {
    let score = site::audit_now(&state.base.db, id).await?;
    Ok(Json(SeoAuditRun {
        score,
        audited_at: Utc::now(),
    }))
}

/// Topic clusters
///
/// E13-T8: every topic, by name.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/seo/topics",
    tag = "admin-content",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of topics", body = PaginatedResponse<SeoTopic>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Paging out of bounds", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_topics(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SeoTopic>>, AppError> {
    let window = q.window();
    let (rows, total) = site::list_topics(&state.base.db, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// Create a topic cluster
///
/// E13-T8: a topic with its language and, optionally, its pillar page.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/seo/topics",
    tag = "admin-content",
    request_body = SeoTopicBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The topic", body = SeoTopic),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "A name or language out of bounds, or no such pillar page", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_topic(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SeoTopicBody>,
) -> Result<(StatusCode, Json<SeoTopic>), AppError> {
    let topic = site::create_topic(&state, ctx.user_id, &body).await?;
    Ok((StatusCode::CREATED, Json(topic)))
}

/// Change a topic cluster
///
/// E13-T8: name, language and pillar page, at the `If-Match` row version.
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/seo/topics/{id}",
    tag = "admin-content",
    params(
        ("id" = Uuid, Path, description = "The topic"),
        ("If-Match" = String, Header, description = "The row_version last read"),
    ),
    request_body = SeoTopicBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The topic", body = SeoTopic),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such topic", body = ErrorResponse),
        (status = 409, description = "The topic changed since that row version", body = ErrorResponse),
        (status = 422, description = "If-Match missing, or a value out of bounds", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_topic(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SeoTopicBody>,
) -> Result<Json<SeoTopic>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        site::update_topic(&state, ctx.user_id, id, &body, expected).await?,
    ))
}

/// Delete a topic cluster
///
/// E13-T8: the topic and its page links; the pages stay.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/content/seo/topics/{id}",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The topic")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such topic", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_topic(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    site::delete_topic(&state, ctx.user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A topic's cluster pages.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SeoTopicPagesBody {
    pub page_ids: Vec<Uuid>,
}

/// Set a topic's cluster pages
///
/// E13-T8: replaces the pages of the cluster (at most 500).
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/seo/topics/{id}/pages",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The topic")),
    request_body = SeoTopicPagesBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such topic", body = ErrorResponse),
        (status = 422, description = "A page that does not exist, or too many", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_topic_pages(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<SeoTopicPagesBody>,
) -> Result<StatusCode, AppError> {
    site::set_topic_pages(&state, ctx.user_id, id, &body.page_ids).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A site's robots.txt as stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct SeoRobotsView {
    pub site_key: String,
    /// The stored body; `null` when the site has none (the default applies).
    pub body: Option<String>,
    /// What crawlers are served: the body (or the default) with the paths
    /// that are always closed appended.
    pub served: String,
    pub row_version: Option<i64>,
}

/// A robots body to store.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SeoRobotsBody {
    pub body: String,
}

/// A site's robots.txt
///
/// E13-T8: the stored body and what crawlers are served.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/sites/{site_key}/robots",
    tag = "admin-content",
    params(("site_key" = String, Path, description = "The site's host name")),
    responses(
        (status = 200, description = "The site's robots.txt", body = SeoRobotsView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Not a host name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_robots(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(site_key): Path<String>,
) -> Result<Json<SeoRobotsView>, AppError> {
    if !site::site_key_ok(&site_key) {
        return Err(AppError::Validation("site_key is a host name".into()));
    }
    let stored = site::robots(&state.base.db, &site_key).await?;
    Ok(Json(SeoRobotsView {
        served: site::served_robots(stored.as_ref().map(|(b, _)| b.as_str())),
        row_version: stored.as_ref().map(|(_, v)| *v),
        body: stored.map(|(b, _)| b),
        site_key,
    }))
}

/// Set a site's robots.txt
///
/// E13-T8: stores the body; portal-only and preview paths stay closed to
/// crawlers whatever it says. The change is a configuration event with the
/// body before and after.
#[utoipa::path(
    put,
    path = "/api/v1/admin/content/sites/{site_key}/robots",
    tag = "admin-content",
    params(("site_key" = String, Path, description = "The site's host name")),
    request_body = SeoRobotsBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The stored robots.txt", body = SeoRobotsView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Another change to this site's robots.txt is in progress", body = ErrorResponse),
        (status = 422, description = "Not a host name, or the body is too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_robots(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(site_key): Path<String>,
    Json(body): Json<SeoRobotsBody>,
) -> Result<Json<SeoRobotsView>, AppError> {
    let version = site::put_robots(&state, ctx.user_id, &site_key, &body.body).await?;
    Ok(Json(SeoRobotsView {
        served: site::served_robots(Some(&body.body)),
        row_version: Some(version),
        body: Some(body.body),
        site_key,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/pages/{id}/seo",
            get(get_page_seo).put(put_page_seo),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/seo/findings",
            get(page_findings),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/seo/audit",
            post(audit_page_now),
        )
        .route(
            "/api/v1/admin/content/seo/topics",
            get(list_topics).post(create_topic),
        )
        .route(
            "/api/v1/admin/content/seo/topics/{id}",
            put(update_topic).delete(delete_topic),
        )
        .route(
            "/api/v1/admin/content/seo/topics/{id}/pages",
            put(set_topic_pages),
        )
        .route(
            "/api/v1/admin/content/sites/{site_key}/robots",
            get(get_robots).put(put_robots),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    get_page_seo,
    put_page_seo,
    page_findings,
    audit_page_now,
    list_topics,
    create_topic,
    update_topic,
    delete_topic,
    set_topic_pages,
    get_robots,
    put_robots,
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

//! G12-T1: the pages a web portal shows (the `page` model kind, T2-T1, with
//! `audience` `portal` or `public`, T2-T4). The portal app renders them with
//! the page runtime; every component reads its data through this portal's
//! record routes under the portal user's own plan, so a page names what to
//! show and never widens what the user may see.
//!
//! A child of [`super`], so it shares the session, budget and consent path of
//! the record routes. A page the deployment publishes for staff only
//! (`internal`, or no audience) is the same 404 as a missing one.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::data_caller;

/// The most pages one index lists.
const MAX_PAGES: i64 = 100;

/// One page a portal may show, for its navigation.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalPageSummary {
    pub name: String,
    pub page_type: String,
    pub title_en: Option<String>,
    pub title_ar: Option<String>,
}

/// One page as the portal app renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalPage {
    pub id: Uuid,
    pub name: String,
    /// A record page's entity, by logical name.
    pub entity_name: Option<String>,
    /// The page document (the page kind's shape), with its `id` and `name`.
    #[schema(value_type = Object)]
    pub doc: Value,
}

/// The newest published portal or public pages, the customer's own first;
/// `name` narrows it to one.
async fn published(
    state: &EngineState,
    name: Option<&str>,
) -> Result<Vec<(Uuid, String, Value)>, AppError> {
    sqlx::query_as(
        "SELECT o.id, o.name, v.doc FROM metadata_object o \
           JOIN LATERAL ( \
               SELECT doc FROM metadata_object_version \
                WHERE object_id = o.id AND state = 'published' \
                ORDER BY version_no DESC LIMIT 1 \
           ) v ON true \
          WHERE o.kind = 'page' AND o.is_active \
            AND v.doc->>'audience' IN ('portal', 'public') \
            AND ($1::text IS NULL OR o.name = $1) \
          ORDER BY (o.app = 'customer') DESC, o.app, o.name \
          LIMIT $2",
    )
    .bind(name)
    .bind(MAX_PAGES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

fn text(doc: &Value, key: &str) -> Option<String> {
    doc.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// List a portal's pages
///
/// The published pages for portal users (audience `portal` or `public`), at most 100, the
/// deployment's own first, for the portal app's navigation. Needs a portal session and the
/// portal's current consent.
#[utoipa::path(
    get,
    operation_id = "portal_pages",
    path = "/{keyword}/api/v1/pages",
    tag = "entity",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The portal's pages", body = PaginatedResponse<PortalPageSummary>),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "Consent to the portal's current terms is missing", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn pages_index(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PaginatedResponse<PortalPageSummary>>, AppError> {
    data_caller(&state, &keyword, &headers, false).await?;
    let mut seen = std::collections::BTreeSet::new();
    let items: Vec<PortalPageSummary> = published(&state, None)
        .await?
        .into_iter()
        // The customer's own page of a name hides an app's of the same name.
        .filter(|(_, name, _)| seen.insert(name.clone()))
        .map(|(_, name, doc)| PortalPageSummary {
            page_type: text(&doc, "page_type").unwrap_or_default(),
            title_en: text(&doc, "title_en"),
            title_ar: text(&doc, "title_ar"),
            name,
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_PAGES,
        warnings: Vec::new(),
    }))
}

/// Get a portal page
///
/// A published page for portal users, by name, with a record page's entity by logical name. Needs a
/// portal session and the portal's current consent. A page for staff only is 404.
#[utoipa::path(
    get,
    operation_id = "portal_page",
    path = "/{keyword}/api/v1/pages/{name}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("name" = String, Path, description = "The page's name"),
    ),
    responses(
        (status = 200, description = "The page", body = PortalPage),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "Consent to the portal's current terms is missing", body = ErrorResponse),
        (status = 404, description = "No such portal, or no such portal page", body = ErrorResponse),
    ),
)]
async fn page(
    State(state): State<EngineState>,
    Path((keyword, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<PortalPage>, AppError> {
    data_caller(&state, &keyword, &headers, false).await?;
    let (id, name, mut doc) = published(&state, Some(&name))
        .await?
        .into_iter()
        .next()
        .ok_or(AppError::NotFound)?;
    let entity_name = match doc
        .get("entity")
        .and_then(Value::as_str)
        .and_then(|e| Uuid::parse_str(e).ok())
    {
        Some(entity_id) => state
            .entities
            .load()
            .get_by_id(entity_id)
            .map(|meta| meta.logicalname.clone()),
        None => None,
    };
    if let Some(object) = doc.as_object_mut() {
        object.insert("id".into(), Value::String(id.to_string()));
        object.insert("name".into(), Value::String(name.clone()));
    }
    Ok(Json(PortalPage {
        id,
        name,
        entity_name,
        doc,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/pages", get(pages_index))
        .route("/{keyword}/api/v1/pages/{name}", get(page))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pages_index, page),
    components(schemas(PortalPageSummary, PortalPage))
)]
pub(super) struct PagesApiDoc;

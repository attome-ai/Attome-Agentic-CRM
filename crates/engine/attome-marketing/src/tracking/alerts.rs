//! E14-T9: page-view alerts and the live visitor list.
//!
//! **Alerts.** A `marketing_watched_page` names a site's page by a URL
//! pattern and an audience. After a batch of page views is written (the
//! `marketing_web_event_batch` job), [`after_batch`] looks at the session:
//! when `marketing.tracking_alerts` is on and the visitor is known (a contact
//! or a lead, E14-T7), each enabled watched page of the site that one of the
//! session's page views matches emits the named change-feed event
//! [`PAGE_VIEWED_EVENT`] on the contact (else the lead). The workflow
//! engine's entity-trigger dispatch starts the flows whose trigger is
//! `web.page_viewed` on that entity (attome-workflow `trigger_index`). An
//! anonymous visitor starts nothing. A `target_account` page alerts only for
//! a contact with an account.
//!
//! Each session alerts once per watched page: a `marketing_watched_alert`
//! row (migration 0305) is claimed in the same transaction as the event, so
//! a rerun of the batch or a later view of the page adds nothing.
//!
//! **The cache.** Each site's enabled watched pages are kept in a moka cache
//! for 60 seconds, rebuilt from the table on a miss: the table is the source
//! of truth, and a changed watch list is seen within a minute on every node.
//!
//! **Live visitors.** [`live`] lists the site's sessions seen in the last
//! [`LIVE_MINUTES`] minutes (bots left out), newest first, with the page each
//! is on, for proactive chat (J3) to pick from.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, PAGE_VIEWED_EVENT};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::summary::path_of;

/// The flag that switches alerts on.
pub const FLAG: &str = "marketing.tracking_alerts";
/// Minutes since a session's last page view for it to count as live.
pub const LIVE_MINUTES: i32 = 5;
/// Watched pages read per site.
const MAX_WATCHED: i64 = 200;
/// A session's latest page views looked at per batch.
const RECENT_VIEWS: i64 = 50;

/// One enabled watched page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPage {
    pub id: Uuid,
    pub pattern: String,
    /// `known_contact` (any known visitor) or `target_account`.
    pub audience: Option<String>,
}

/// Whether `url`'s path matches `pattern`: `*` stands for any text; a
/// pattern without one matches the path itself and the paths under it. A
/// full URL pattern is reduced to its path; the query and fragment never
/// count. Pure.
pub fn pattern_matches(pattern: &str, url: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let pattern = if pattern.contains("://") || pattern.starts_with('/') {
        path_of(pattern)
    } else {
        format!("/{pattern}")
    };
    let path = path_of(url);
    if !pattern.contains('*') {
        let p = pattern.trim_end_matches('/');
        let path = path.trim_end_matches('/');
        return path == p || (!p.is_empty() && path.starts_with(&format!("{p}/")));
    }
    glob(&pattern, &path)
}

/// `*`-only glob over the whole text. Pure.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

fn watch_cache() -> &'static moka::future::Cache<String, Arc<Vec<WatchedPage>>> {
    static CACHE: OnceLock<moka::future::Cache<String, Arc<Vec<WatchedPage>>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(60))
            .build()
    })
}

/// The site's enabled watched pages, from the cache or the table.
async fn watched(state: &EngineState, site_key: &str) -> Result<Arc<Vec<WatchedPage>>, AppError> {
    if let Some(hit) = watch_cache().get(site_key).await {
        return Ok(hit);
    }
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT w.id, w.url_pattern, w.audience FROM marketing_watched_page w \
           JOIN marketing_tracked_site s ON s.id = w.site_ref AND s.is_active IS NOT FALSE \
          WHERE s.site_key = $1 AND w.is_active IS NOT FALSE AND COALESCE(w.enabled, true) \
          ORDER BY w.id LIMIT $2",
    )
    .bind(site_key)
    .bind(MAX_WATCHED)
    .fetch_all(&state.base.db_readonly)
    .await
    .map_err(AppError::internal)?;
    let pages = Arc::new(
        rows.into_iter()
            .filter_map(|(id, pattern, audience)| {
                pattern
                    .filter(|p| !p.trim().is_empty())
                    .map(|pattern| WatchedPage {
                        id,
                        pattern,
                        audience,
                    })
            })
            .collect::<Vec<_>>(),
    );
    watch_cache()
        .insert(site_key.to_owned(), pages.clone())
        .await;
    Ok(pages)
}

/// Emits the page-view alerts a written batch earned; returns how many.
pub async fn after_batch(
    state: &EngineState,
    site_key: &str,
    session: Uuid,
) -> Result<u64, AppError> {
    if !state.feature_flags().is_on_for_deployment(FLAG) {
        return Ok(0);
    }
    let db = &state.base.db;
    let known: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT contact_ref, lead_ref FROM marketing_web_session \
          WHERE id = $1 AND site_key = $2 AND NOT is_bot",
    )
    .bind(session)
    .bind(site_key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (entity, record) = match known {
        Some((Some(contact), _)) => ("contact", contact),
        Some((None, Some(lead))) => ("lead", lead),
        _ => return Ok(0),
    };
    let pages = watched(state, site_key).await?;
    if pages.is_empty() {
        return Ok(0);
    }
    let urls: Vec<String> = sqlx::query_scalar(
        "SELECT url FROM marketing_web_event \
          WHERE session_id = $1 AND kind = 'page_view' AND url IS NOT NULL \
          ORDER BY occurred_at DESC LIMIT $2",
    )
    .bind(session)
    .bind(RECENT_VIEWS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let hits: Vec<&WatchedPage> = pages
        .iter()
        .filter(|w| urls.iter().any(|u| pattern_matches(&w.pattern, u)))
        .collect();
    if hits.is_empty() {
        return Ok(0);
    }
    let with_account = if hits
        .iter()
        .any(|w| w.audience.as_deref() == Some("target_account"))
    {
        entity == "contact"
            && sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM contact WHERE id = $1 AND account_ref IS NOT NULL)",
            )
            .bind(record)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?
    } else {
        false
    };
    let mut tx = attome_db::tx::begin(db).await?;
    let mut alerted = 0u64;
    for page in hits {
        if page.audience.as_deref() == Some("target_account") && !with_account {
            continue;
        }
        let claimed = sqlx::query(
            "INSERT INTO marketing_watched_alert (session_id, watched_page_id, entity, record_id) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (session_id, watched_page_id) DO NOTHING",
        )
        .bind(session)
        .bind(page.id)
        .bind(entity)
        .bind(record)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if claimed == 0 {
            continue;
        }
        attome_core::change_feed::emit_named(
            &mut tx,
            entity,
            record,
            ChangeOperation::Update,
            PAGE_VIEWED_EVENT,
        )
        .await?;
        alerted += 1;
    }
    attome_db::tx::commit(tx).await?;
    Ok(alerted)
}

/// One live session.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct LiveVisitor {
    pub session_id: Uuid,
    pub visitor_id: Uuid,
    /// The known contact or lead, when the visitor is identified.
    pub contact_ref: Option<Uuid>,
    pub lead_ref: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub page_count: i32,
    /// The page the visitor last viewed.
    pub current_url: Option<String>,
    pub utm_source: Option<String>,
}

/// The site's live sessions, newest first, and their total.
pub async fn live(
    state: &EngineState,
    site_key: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LiveVisitor>, i64), AppError> {
    let db = &state.base.db_readonly;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_web_session \
          WHERE site_key = $1 AND NOT is_bot \
            AND last_seen_at >= now() - make_interval(mins => $2)",
    )
    .bind(site_key)
    .bind(LIVE_MINUTES)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<LiveVisitor> = sqlx::query_as(
        "SELECT s.id AS session_id, s.visitor_id, s.contact_ref, s.lead_ref, s.started_at, \
                s.last_seen_at, s.page_count, last_view.url AS current_url, s.utm_source \
           FROM marketing_web_session s \
           LEFT JOIN LATERAL (SELECT e.url FROM marketing_web_event e \
                               WHERE e.session_id = s.id AND e.kind = 'page_view' \
                                 AND e.occurred_at >= s.started_at \
                               ORDER BY e.occurred_at DESC LIMIT 1) last_view ON true \
          WHERE s.site_key = $1 AND NOT s.is_bot \
            AND s.last_seen_at >= now() - make_interval(mins => $2) \
          ORDER BY s.last_seen_at DESC, s.id LIMIT $3 OFFSET $4",
    )
    .bind(site_key)
    .bind(LIVE_MINUTES)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok((items, total))
}

/// `marketing_tracked_site.read`: who may see a site's live visitors.
#[derive(Debug)]
pub struct TrackedSiteRead;

impl PrivilegeKey for TrackedSiteRead {
    const KEY: &'static str = "marketing_tracked_site.read";
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LiveQuery {
    /// The site's key.
    pub site: String,
    /// One-based page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/tracking/live",
    operation_id = "list_live_visitors",
    tag = "marketing",
    params(LiveQuery),
    responses(
        (status = 200, description = "Sessions seen in the last five minutes, newest first", body = PaginatedResponse<LiveVisitor>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_tracked_site.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// List a site's live visitors.
///
/// The sessions seen in the last five minutes (bots left out), newest
/// first, each with the page it is on and the known contact or lead.
pub async fn get_live(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrackedSiteRead>>,
    Query(q): Query<LiveQuery>,
) -> Result<Json<PaginatedResponse<LiveVisitor>>, AppError> {
    let window = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let (items, total) = live(&state, q.site.trim(), window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/marketing/tracking/live", get(get_live))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_live), components(schemas(LiveVisitor)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_pattern_matches_path() {
        assert!(pattern_matches(
            "/pricing",
            "https://acme.sa/pricing?plan=pro"
        ));
        assert!(pattern_matches(
            "/pricing",
            "https://acme.sa/pricing/enterprise"
        ));
        assert!(!pattern_matches("/pricing", "https://acme.sa/pricing-old"));
        assert!(pattern_matches(
            "/blog/*/demo",
            "https://acme.sa/blog/2026/demo"
        ));
        assert!(!pattern_matches(
            "/blog/*/demo",
            "https://acme.sa/blog/2026/other"
        ));
        assert!(pattern_matches("*/careers*", "/en/careers/sales"));
        assert!(pattern_matches(
            "https://acme.sa/contact",
            "https://acme.sa/contact#form"
        ));
        assert!(pattern_matches("demo", "/demo"));
        assert!(!pattern_matches("", "/demo"));
        assert!(pattern_matches("/", "https://acme.sa/"));
    }
}

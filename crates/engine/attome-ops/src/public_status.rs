//! AB11-T2: the status page's component states, open incidents and
//! maintenance, for any signed-in user.
//!
//! - `GET /api/v1/ops/status`: each component (`ops_status_component`,
//!   migration 0314) with its state, from the capability its row names (the
//!   probes already running, never a probe per request) or, for `records`,
//!   from the database answering; an open incident listing a component makes
//!   it at least as bad as the incident's impact. Internal incidents,
//!   internal maintenance and non-public components reach only `ops.read`
//!   holders (and administrators).
//! - `GET /api/v1/ops/status/banner`: the one notice a signed-in user should
//!   see: the most severe open incident, else maintenance starting within
//!   24 hours, in the caller's language (`Accept-Language`); `204` when none.
//!
//! The snapshot is computed at most every 15 seconds per node and filtered
//! per caller from the cached copy.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_core::EngineState;
use attome_server::authz::{Authorized, PrivilegeKey, SelfService};
use attome_server::{CapabilityState, security::SecurityContext};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::ACCEPT_LANGUAGE},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::upgrades::OpsRead;

/// How long one computed snapshot is reused.
const CACHE_TTL: Duration = Duration::from_secs(15);

/// How far ahead the banner announces maintenance.
const MAINTENANCE_NOTICE_HOURS: i64 = 24;

static CACHE: LazyLock<Mutex<Option<(Instant, Snapshot)>>> = LazyLock::new(|| Mutex::new(None));

/// One component's state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComponentStatus {
    pub key: String,
    pub name_en: String,
    pub name_ar: String,
    /// `operational`, `degraded`, `down` or `unknown`.
    pub state: String,
    #[serde(skip)]
    public: bool,
}

/// An open incident.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct IncidentSummary {
    pub id: Uuid,
    pub title_en: String,
    pub title_ar: Option<String>,
    /// `internal` or `public`.
    pub audience: String,
    /// `investigating`, `identified` or `monitoring`.
    pub state: String,
    /// `degraded`, `partial` or `major`.
    pub impact: String,
    pub components: Vec<String>,
    pub started_at: DateTime<Utc>,
}

/// Maintenance not yet over.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct MaintenanceSummary {
    pub id: Uuid,
    pub title_en: String,
    pub title_ar: Option<String>,
    pub audience: String,
    pub components: Vec<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

/// What `GET /api/v1/ops/status` answers.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatusSnapshot {
    pub components: Vec<ComponentStatus>,
    pub incidents: Vec<IncidentSummary>,
    pub maintenance: Vec<MaintenanceSummary>,
    pub computed_at: DateTime<Utc>,
}

/// The one notice for a signed-in user.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatusBanner {
    /// `incident` or `maintenance`.
    pub kind: String,
    pub id: Uuid,
    /// The title in the caller's language (English when there is no Arabic).
    pub title: String,
    /// An incident's impact; absent for maintenance.
    pub impact: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: Option<DateTime<Utc>>,
}

/// The cached, unfiltered snapshot.
type Snapshot = StatusSnapshot;

#[derive(sqlx::FromRow)]
struct ComponentRow {
    key: String,
    name_en: String,
    name_ar: String,
    capability: Option<String>,
    public: bool,
}

/// A component's state from its capability's. Pure.
pub fn state_of_capability(state: Option<CapabilityState>) -> &'static str {
    match state {
        Some(CapabilityState::Available) => "operational",
        Some(CapabilityState::Unavailable) => "down",
        // A capability switched off, unprobed or unnamed tells nothing.
        Some(CapabilityState::Disabled | CapabilityState::Unknown) | None => "unknown",
    }
}

fn severity(state: &str) -> u8 {
    match state {
        "down" => 3,
        "degraded" => 2,
        "operational" => 1,
        _ => 0,
    }
}

fn impact_rank(impact: &str) -> u8 {
    match impact {
        "major" => 3,
        "partial" => 2,
        _ => 1,
    }
}

/// `state` made at least as bad as an incident of `impact`. Pure.
pub fn with_incident(state: &str, impact: &str) -> &'static str {
    let from_incident = if impact == "major" {
        "down"
    } else {
        "degraded"
    };
    if severity(from_incident) >= severity(state) {
        from_incident
    } else {
        match state {
            "down" => "down",
            "degraded" => "degraded",
            "operational" => "operational",
            _ => "unknown",
        }
    }
}

async fn compute(state: &EngineState) -> Result<Snapshot, AppError> {
    let rows: Vec<ComponentRow> = sqlx::query_as(
        "SELECT key, name_en, name_ar, capability, public FROM ops_status_component \
          ORDER BY sort, key",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let incidents: Vec<IncidentSummary> = sqlx::query_as(
        "SELECT id, title_en, title_ar, audience, state, impact, components, started_at \
           FROM ops_incident \
          WHERE resolved_at IS NULL AND state NOT IN ('draft', 'resolved') \
          ORDER BY started_at DESC",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let maintenance: Vec<MaintenanceSummary> = sqlx::query_as(
        "SELECT id, title_en, title_ar, audience, components, starts_at, ends_at \
           FROM ops_maintenance \
          WHERE cancelled_at IS NULL AND ends_at > now() \
          ORDER BY starts_at",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let reports = state.base.capabilities.snapshot();
    let components = rows
        .into_iter()
        .map(|row| {
            let base = match row.capability.as_deref() {
                // The queries above answered: the database is up.
                None if row.key == "records" => "operational",
                None => "unknown",
                Some(capability) => state_of_capability(
                    reports
                        .iter()
                        .find(|r| r.capability == capability)
                        .map(|r| r.state),
                ),
            };
            let state = incidents
                .iter()
                .filter(|i| i.components.iter().any(|c| c == &row.key))
                .fold(base, |s, i| with_incident(s, &i.impact));
            ComponentStatus {
                key: row.key,
                name_en: row.name_en,
                name_ar: row.name_ar,
                state: state.to_owned(),
                public: row.public,
            }
        })
        .collect();
    Ok(StatusSnapshot {
        components,
        incidents,
        maintenance,
        computed_at: Utc::now(),
    })
}

async fn snapshot(state: &EngineState) -> Result<Snapshot, AppError> {
    let cached = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|(at, _)| at.elapsed() < CACHE_TTL)
        .map(|(_, s)| s.clone());
    if let Some(s) = cached {
        return Ok(s);
    }
    let fresh = compute(state).await?;
    *CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((Instant::now(), fresh.clone()));
    Ok(fresh)
}

/// Whether `ctx` sees internal incidents, maintenance and components.
fn sees_internal(ctx: &SecurityContext) -> bool {
    ctx.is_admin || ctx.privileges.contains(OpsRead::KEY)
}

/// `snapshot` as a caller who does (or does not) see internal detail reads
/// it. Pure.
pub fn visible_to(mut snapshot: StatusSnapshot, internal: bool) -> StatusSnapshot {
    if !internal {
        snapshot.components.retain(|c| c.public);
        snapshot.incidents.retain(|i| i.audience == "public");
        snapshot.maintenance.retain(|m| m.audience == "public");
    }
    snapshot
}

/// The banner `snapshot` (already filtered for the caller) gives at `now`,
/// in Arabic when `arabic`. Pure.
pub fn banner_of(
    snapshot: &StatusSnapshot,
    now: DateTime<Utc>,
    arabic: bool,
) -> Option<StatusBanner> {
    let title = |en: &str, ar: &Option<String>| match (arabic, ar) {
        (true, Some(ar)) if !ar.trim().is_empty() => ar.clone(),
        _ => en.to_owned(),
    };
    if let Some(incident) = snapshot
        .incidents
        .iter()
        .max_by_key(|i| (impact_rank(&i.impact), i.started_at))
    {
        return Some(StatusBanner {
            kind: "incident".into(),
            id: incident.id,
            title: title(&incident.title_en, &incident.title_ar),
            impact: Some(incident.impact.clone()),
            starts_at: incident.started_at,
            ends_at: None,
        });
    }
    let horizon = now + chrono::Duration::hours(MAINTENANCE_NOTICE_HOURS);
    snapshot
        .maintenance
        .iter()
        .filter(|m| m.starts_at <= horizon && m.ends_at > now)
        .min_by_key(|m| m.starts_at)
        .map(|m| StatusBanner {
            kind: "maintenance".into(),
            id: m.id,
            title: title(&m.title_en, &m.title_ar),
            impact: None,
            starts_at: m.starts_at,
            ends_at: Some(m.ends_at),
        })
}

/// Whether the request's `Accept-Language` puts Arabic first.
fn prefers_arabic(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|first| first.trim().to_ascii_lowercase().starts_with("ar"))
}

/// The platform's status
///
/// AB11-T2: each component's state, open incidents and maintenance not yet
/// over. Any signed-in user; internal items need `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/status",
    tag = "ops",
    operation_id = "get_ops_status",
    responses(
        (status = 200, description = "Component states, incidents and maintenance", body = StatusSnapshot),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_status(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<StatusSnapshot>, AppError> {
    let snapshot = snapshot(&state).await?;
    Ok(Json(visible_to(snapshot, sees_internal(&ctx))))
}

/// The status notice for the signed-in user
///
/// AB11-T2: the most severe open incident, else maintenance starting within
/// 24 hours, titled in the `Accept-Language` language; `204` when there is
/// nothing to say.
#[utoipa::path(
    get,
    path = "/api/v1/ops/status/banner",
    tag = "ops",
    operation_id = "get_ops_status_banner",
    responses(
        (status = 200, description = "The notice to show", body = StatusBanner),
        (status = 204, description = "Nothing to show"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_banner(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let snapshot = visible_to(snapshot(&state).await?, sees_internal(&ctx));
    Ok(
        match banner_of(&snapshot, Utc::now(), prefers_arabic(&headers)) {
            Some(banner) => Json(banner).into_response(),
            None => StatusCode::NO_CONTENT.into_response(),
        },
    )
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/status", get(get_status))
        .route("/api/v1/ops/status/banner", get(get_banner))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_status, get_banner),
    components(schemas(
        StatusSnapshot,
        ComponentStatus,
        IncidentSummary,
        MaintenanceSummary,
        StatusBanner
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(key: &str, state: &str, public: bool) -> ComponentStatus {
        ComponentStatus {
            key: key.into(),
            name_en: key.into(),
            name_ar: key.into(),
            state: state.into(),
            public,
        }
    }

    fn incident(audience: &str, impact: &str, hours_ago: i64) -> IncidentSummary {
        IncidentSummary {
            id: Uuid::now_v7(),
            title_en: format!("{impact} outage"),
            title_ar: Some(format!("عطل {impact}")),
            audience: audience.into(),
            state: "investigating".into(),
            impact: impact.into(),
            components: vec!["search".into()],
            started_at: Utc::now() - chrono::Duration::hours(hours_ago),
        }
    }

    fn snapshot_with(
        incidents: Vec<IncidentSummary>,
        maintenance: Vec<MaintenanceSummary>,
    ) -> StatusSnapshot {
        StatusSnapshot {
            components: vec![
                component("records", "operational", true),
                component("ops_db", "operational", false),
            ],
            incidents,
            maintenance,
            computed_at: Utc::now(),
        }
    }

    #[test]
    fn components_follow_capability_state() {
        assert_eq!(
            state_of_capability(Some(CapabilityState::Available)),
            "operational"
        );
        assert_eq!(
            state_of_capability(Some(CapabilityState::Unavailable)),
            "down"
        );
        assert_eq!(
            state_of_capability(Some(CapabilityState::Disabled)),
            "unknown"
        );
        assert_eq!(state_of_capability(None), "unknown");
        // an open incident makes a component at least as bad as its impact
        assert_eq!(with_incident("operational", "partial"), "degraded");
        assert_eq!(with_incident("operational", "major"), "down");
        assert_eq!(with_incident("down", "degraded"), "down");
        assert_eq!(with_incident("unknown", "degraded"), "degraded");
    }

    #[test]
    fn internal_incident_hidden_from_normal_user() {
        let s = snapshot_with(
            vec![
                incident("internal", "major", 1),
                incident("public", "degraded", 2),
            ],
            Vec::new(),
        );
        let normal = visible_to(s.clone(), false);
        assert_eq!(normal.incidents.len(), 1);
        assert_eq!(normal.incidents[0].audience, "public");
        assert_eq!(
            normal.components.len(),
            1,
            "a non-public component is hidden too"
        );
        let ops = visible_to(s, true);
        assert_eq!(ops.incidents.len(), 2);
        assert_eq!(ops.components.len(), 2);
    }

    #[test]
    fn banner_is_204_when_quiet() {
        let now = Utc::now();
        assert!(banner_of(&snapshot_with(Vec::new(), Vec::new()), now, false).is_none());
        // maintenance further than 24 hours away is not announced yet
        let later = MaintenanceSummary {
            id: Uuid::now_v7(),
            title_en: "Upgrade".into(),
            title_ar: Some("ترقية".into()),
            audience: "public".into(),
            components: Vec::new(),
            starts_at: now + chrono::Duration::hours(30),
            ends_at: now + chrono::Duration::hours(31),
        };
        assert!(banner_of(&snapshot_with(Vec::new(), vec![later.clone()]), now, false).is_none());
        let soon = MaintenanceSummary {
            starts_at: now + chrono::Duration::hours(2),
            ends_at: now + chrono::Duration::hours(3),
            ..later
        };
        let banner = banner_of(&snapshot_with(Vec::new(), vec![soon]), now, true).unwrap();
        assert_eq!(
            (banner.kind.as_str(), banner.title.as_str()),
            ("maintenance", "ترقية")
        );
    }

    #[test]
    fn banner_shows_the_most_severe_incident() {
        let s = snapshot_with(
            vec![
                incident("public", "degraded", 1),
                incident("public", "major", 5),
            ],
            Vec::new(),
        );
        let banner = banner_of(&s, Utc::now(), false).unwrap();
        assert_eq!(banner.impact.as_deref(), Some("major"));
        assert_eq!(banner.title, "major outage");
    }
}

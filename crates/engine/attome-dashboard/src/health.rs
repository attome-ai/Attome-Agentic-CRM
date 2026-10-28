//! M26 Phase 2 backlog item: "no dashboard health check (validate all bound
//! queries still resolve) before publish." `dashboard_widget.query_id`
//! and `.view_id` are both free-text references (to `sql_query` and
//! `view` respectively) with no FK/lookup integrity — neither is a
//! registered entity, so neither can become a real `lookup` target (same
//! reasoning `access.rs`'s `dashboard_of_widget` doc comment gives for
//! `query_id`). A renamed or deleted query/view breaks a widget silently, and
//! nothing surfaces that until the widget fails to render. This is a
//! read-only diagnostic, not enforcement: it does not block publish (the
//! four-eyes gate already covers that transition, and a draft dashboard with
//! a dangling widget is not itself invalid — the widget may be mid-edit) —
//! it just answers "would this dashboard's widgets actually work right now."
//!
//! R-16 (`document/xrm/module/M26-dashboard/remediation.md`)
//! extended this from `query_id`-only to also check `view_id` — a widget
//! declaring either (or both) contributes one checked reference per
//! non-empty column, not one per widget, since `dashboard-widget-view`
//! prefers `view_id` over `query_id` when both are present (R-01/R-16's own
//! Angular spec) and either can independently go stale.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;
use crate::auth::DashboardRead;

#[derive(FromRow)]
struct WidgetRefRow {
    widget_id: Uuid,
    widget_name: Option<String>,
    page_name: String,
    section_type: String,
    query_id: Option<String>,
    view_id: Option<String>,
}

/// One non-empty reference off one widget row — `field` names which column
/// it came from, so `do_health_check` can dispatch each to the right
/// existence check (`sql_query` vs `view`) and the response
/// can tell a caller which binding is broken.
struct WidgetRef<'a> {
    row: &'a WidgetRefRow,
    field: &'static str,
    value: &'a str,
}

#[derive(Serialize, ToSchema)]
// `pub` fields — same reason `scenario.rs::ScenarioResultRow` gives: this
// crate's own `tests/health.rs` reads them straight off `do_health_check`'s
// result, the "call the `pub` `do_*` function, skip the HTTP layer"
// convention every suite in this crate already uses.
pub struct BrokenWidgetRef {
    pub widget_id: Uuid,
    pub widget_name: Option<String>,
    pub page_name: String,
    pub section_type: String,
    /// `"query_id"` or `"view_id"` — which column this broken reference came
    /// from.
    pub field: &'static str,
    /// The raw stored value that failed to resolve.
    pub value: String,
    /// `"invalid_format"` (not a UUID at all) or `"not_found"` (well-formed,
    /// but no active row of the referenced kind has that id).
    pub reason: &'static str,
}

impl std::fmt::Debug for BrokenWidgetRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokenWidgetRef").finish_non_exhaustive()
    }
}

impl BrokenWidgetRef {
    fn from_ref(r: &WidgetRef<'_>, reason: &'static str) -> Self {
        BrokenWidgetRef {
            widget_id: r.row.widget_id,
            widget_name: r.row.widget_name.clone(),
            page_name: r.row.page_name.clone(),
            section_type: r.row.section_type.clone(),
            field: r.field,
            value: r.value.to_string(),
            reason,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct HealthCheckResponse {
    /// Non-empty `query_id`/`view_id` references checked across this
    /// dashboard's widgets — a widget declaring both counts as two; a widget
    /// declaring neither (rich text, dividers, …) is not counted at all.
    pub checked: usize,
    pub broken: Vec<BrokenWidgetRef>,
    /// D-521 — the query versions the **live** version is pinned to, and
    /// whether each has been superseded. Empty when nothing is live or the
    /// live snapshot predates pinning (snapshot format 1).
    pub live_version_dependencies: Vec<PinnedDependencyStatus>,
    /// D-543 — the live snapshot's format. `None` when nothing is live.
    pub live_snapshot_format: Option<i64>,
    /// True when something is live but its snapshot predates format 3, so some
    /// of what viewers see is still resolved live (view semantics, column
    /// metadata, parameters, variables), or predates format 4 while it has
    /// governed KPI widgets (D-544). Cleared by republishing.
    pub partially_pinned: bool,
    /// Phase 3.5 — what refuses publish; empty from `do_health_check` alone,
    /// filled by the health route.
    pub blocking: Vec<crate::publish_gate::GateIssue>,
    /// Phase 3.5 — what is reported but never blocks.
    pub warnings: Vec<crate::publish_gate::GateIssue>,
    /// Whether publish would pass the gate now.
    pub publishable: bool,
}

impl std::fmt::Debug for HealthCheckResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthCheckResponse")
            .finish_non_exhaustive()
    }
}

/// D-521 — one widget's pinned query version in the live snapshot. A pinned
/// dashboard keeps running `pinned_version_id` until it is republished;
/// `newer_version_available` tells an editor that a republish would pick up a
/// changed query. `query_active` false means the pinned SQL will not run at
/// all (pinned SQL, live security).
#[derive(Serialize, ToSchema)]
pub struct PinnedDependencyStatus {
    pub widget_id: String,
    pub query_id: Uuid,
    pub pinned_version_id: Uuid,
    pub latest_version_id: Option<Uuid>,
    pub newer_version_available: bool,
    pub query_active: bool,
}

impl std::fmt::Debug for PinnedDependencyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedDependencyStatus")
            .finish_non_exhaustive()
    }
}

/// D-543 — the live snapshot's `snapshot_format` and whether it holds governed
/// KPI widgets, or `None` when nothing is live. Format 1 predates pinning;
/// format 2 pins query versions only; format 3 lacks captured metrics.
async fn live_snapshot_format(
    db: &DbPool,
    dashboard_id: Uuid,
) -> Result<Option<(i64, bool)>, AppError> {
    let snapshot: Option<String> = sqlx::query_scalar(
        "SELECT v.snapshot_json FROM attome_dashboard d \
         JOIN dashboard_version v ON v.id = d.published_version_id \
         WHERE d.id = $1",
    )
    .bind(dashboard_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(snapshot) = snapshot else {
        return Ok(None);
    };
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot)
        .map_err(|e| AppError::internal(format!("corrupt version snapshot: {e}")))?;
    let format = snapshot
        .get("snapshot_format")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1);
    let has_kpi = snapshot
        .get("pages")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|pages| {
            pages.iter().any(|page| {
                let mut widgets = Vec::new();
                crate::execution::collect_widgets(page, &mut widgets);
                widgets
                    .iter()
                    .any(|w| !crate::execution::kpi_metric_refs(w).is_empty())
            })
        });
    Ok(Some((format, has_kpi)))
}

async fn live_version_dependencies(
    db: &DbPool,
    dashboard_id: Uuid,
) -> Result<Vec<PinnedDependencyStatus>, AppError> {
    let snapshot: Option<String> = sqlx::query_scalar(
        "SELECT v.snapshot_json FROM attome_dashboard d \
         JOIN dashboard_version v ON v.id = d.published_version_id \
             AND (v.is_active IS NULL OR v.is_active = true) \
         WHERE d.id = $1",
    )
    .bind(dashboard_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(snapshot) = snapshot else {
        return Ok(Vec::new());
    };
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot)
        .map_err(|e| AppError::internal(format!("corrupt version snapshot: {e}")))?;
    let Some(dependencies) = snapshot
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(Vec::new());
    };

    let mut statuses = Vec::with_capacity(dependencies.len());
    for dep in dependencies {
        let uuid = |key: &str| {
            dep.get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
        };
        let (Some(query_id), Some(pinned_version_id)) =
            (uuid("query_id"), uuid("query_version_id"))
        else {
            continue;
        };
        let latest: Option<(Uuid, bool)> = sqlx::query_as(
            "SELECT v.id, (q.is_active IS NULL OR q.is_active = true) \
             FROM sql_query q \
             LEFT JOIN LATERAL ( \
                 SELECT id FROM sql_query_version \
                 WHERE query_id = q.id ORDER BY id DESC LIMIT 1 \
             ) v ON true \
             WHERE q.id = $1",
        )
        .bind(query_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let (latest_version_id, query_active) = match latest {
            Some((id, active)) => (Some(id), active),
            None => (None, false),
        };
        statuses.push(PinnedDependencyStatus {
            widget_id: dep
                .get("widget_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            query_id,
            pinned_version_id,
            newer_version_available: latest_version_id.is_some_and(|l| l != pinned_version_id),
            latest_version_id,
            query_active,
        });
    }
    Ok(statuses)
}

pub async fn do_health_check(
    db: &DbPool,
    dashboard_id: Uuid,
) -> Result<HealthCheckResponse, AppError> {
    let rows: Vec<WidgetRefRow> = sqlx::query_as(
        "SELECT w.id AS widget_id, w.name AS widget_name, p.name AS page_name, \
                s.section_type, w.query_id, w.view_id \
         FROM dashboard_widget w \
         JOIN dashboard_section s ON s.id = w.section_id \
             AND (s.is_active IS NULL OR s.is_active = true) \
         JOIN dashboard_page p ON p.id = s.page_id \
             AND (p.is_active IS NULL OR p.is_active = true) \
         WHERE p.dashboard_id = $1 \
           AND (w.is_active IS NULL OR w.is_active = true) \
           AND ((w.query_id IS NOT NULL AND w.query_id != '') \
                OR (w.view_id IS NOT NULL AND w.view_id != ''))",
    )
    .bind(dashboard_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut refs: Vec<WidgetRef<'_>> = Vec::new();
    for row in &rows {
        if let Some(v) = row.query_id.as_deref().filter(|v| !v.is_empty()) {
            refs.push(WidgetRef {
                row,
                field: "query_id",
                value: v,
            });
        }
        if let Some(v) = row.view_id.as_deref().filter(|v| !v.is_empty()) {
            refs.push(WidgetRef {
                row,
                field: "view_id",
                value: v,
            });
        }
    }

    let checked = refs.len();
    let mut valid_query_ids = Vec::new();
    let mut valid_view_ids = Vec::new();
    let mut broken = Vec::new();
    for r in &refs {
        match Uuid::parse_str(r.value) {
            Ok(id) if r.field == "query_id" => valid_query_ids.push(id),
            Ok(id) => valid_view_ids.push(id),
            Err(_) => broken.push(BrokenWidgetRef::from_ref(r, "invalid_format")),
        }
    }

    let existing_queries: Vec<Uuid> = if valid_query_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar(
            "SELECT id FROM sql_query \
             WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&valid_query_ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    };
    let existing_views: Vec<Uuid> = if valid_view_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar(
            "SELECT id FROM view \
             WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&valid_view_ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    };

    for r in &refs {
        let Ok(id) = Uuid::parse_str(r.value) else {
            continue; // already reported above
        };
        let exists = if r.field == "query_id" {
            existing_queries.contains(&id)
        } else {
            existing_views.contains(&id)
        };
        if !exists {
            broken.push(BrokenWidgetRef::from_ref(r, "not_found"));
        }
    }

    let live_version_dependencies = live_version_dependencies(db, dashboard_id).await?;
    let live = live_snapshot_format(db, dashboard_id).await?;
    Ok(HealthCheckResponse {
        checked,
        broken,
        live_version_dependencies,
        partially_pinned: live
            .is_some_and(|(format, has_kpi)| format < 3 || (format < 4 && has_kpi)),
        live_snapshot_format: live.map(|(format, _)| format),
        blocking: Vec::new(),
        warnings: Vec::new(),
        publishable: true,
    })
}

/// Check a dashboard's bound queries
///
/// Whether every query and view its widgets name still exists and resolves, so a renamed or deleted
/// one is found before publishing instead of when a widget fails to draw. Anyone who may read the
/// dashboard.
#[utoipa::path(
    get,
    path = "/api/v1/attome-dashboard/{id}/health-check",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The dashboard")),
    responses(
        (status = 200, description = "Success", body = HealthCheckResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn dashboard_health_check(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    axum::extract::Path(dashboard_id): axum::extract::Path<Uuid>,
) -> Result<Json<HealthCheckResponse>, AppError> {
    require_dashboard_access(&state, &ctx, dashboard_id, RecordAction::Read).await?;
    let mut result = do_health_check(&state.base.db, dashboard_id).await?;
    let gate = crate::publish_gate::do_publish_gate(&state, dashboard_id).await?;
    result.publishable = gate.publishable();
    result.blocking = gate.blocking;
    result.warnings = gate.warnings;
    Ok(Json(result))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/attome-dashboard/{id}/health-check",
        get(dashboard_health_check),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(dashboard_health_check))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

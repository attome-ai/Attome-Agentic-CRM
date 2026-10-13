//! F2 — release reports across customers (design §6.2): each customer's
//! reports and items read through its rollout credential, the fleet-wide
//! open-items view, and Accept / Use mine / Dismiss sent to the customer's
//! own item routes (owner answer Topic 17 Q2: the console may read and
//! decide conflict values; each read and decision is audited on the
//! customer server under the rollout user, joined by `x-correlation-id`).
//!
//! Reads are proxied as the customer answered them (its `PaginatedResponse`
//! envelopes), so the console never re-shapes or stores a record value.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_audit::{AuditOperation, AuditOutcome};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};

use super::{HumanSession, record};
use crate::client::{CustomerClient, RemoteError, is_safe_query_value, paths};
use crate::error::{ConsoleError, ConsoleResult};
use crate::runtime::FleetState;
use crate::store::{self, ActionWrite, DeploymentRow};

/// How many of a customer's newest reports the open-items view scans.
const OPEN_REPORTS_SCANNED: i64 = 10;
/// How many open items per report the open-items view reads.
const OPEN_ITEMS_PER_REPORT: i64 = 100;
/// How many customers the open-items view reads at once.
const OPEN_ITEMS_CONCURRENCY: usize = 4;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReportFilter {
    /// The customer's report status filter (`building`, `ready`).
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ItemFilter {
    /// `open`, `info`, `accepted`, `used_mine`, …
    pub status: Option<String>,
    /// `conflict`, `conversion_nulled`, `field_deleted`, …
    pub kind: Option<String>,
}

/// Accept or Dismiss: the item's `row_version` (sent as `If-Match`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DecideItemBody {
    pub row_version: i64,
}

/// Use mine: the item's `row_version` and the record's (design §10.4).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UseMineItemBody {
    pub row_version: i64,
    #[serde(default)]
    pub record_row_version: Option<i64>,
}

/// One open item somewhere in the fleet.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpenItemView {
    pub deployment_id: Uuid,
    pub deployment_label: String,
    pub project_code: String,
    pub report_id: Uuid,
    /// The customer's item (`ReportItemView`), conflict values included
    /// when it sent them.
    #[schema(value_type = Object)]
    pub item: Value,
}

fn filter_value(field: &str, value: Option<&str>) -> Result<Option<String>, AppError> {
    match value {
        None => Ok(None),
        Some(v) if is_safe_query_value(v) => Ok(Some(v.to_owned())),
        Some(_) => Err(AppError::Validation(format!("{field}: unknown value"))),
    }
}

fn page_query(page: i64, page_size: i64, filters: &[(&str, Option<String>)]) -> String {
    let mut query = format!("page={page}&page_size={page_size}");
    for (name, value) in filters {
        if let Some(value) = value {
            query.push('&');
            query.push_str(name);
            query.push('=');
            query.push_str(value);
        }
    }
    query
}

async fn customer(
    state: &FleetState,
    deployment_id: Uuid,
) -> Result<(DeploymentRow, CustomerClient), AppError> {
    let deployment = store::get_deployment(&state.xrm.base.db, deployment_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let client = state
        .runtime
        .customer(&state.xrm.base.db, &deployment)
        .await?;
    if !client.has_credential() {
        return Err(AppError::Validation(
            "no_credential: store this deployment's rollout credential first".into(),
        ));
    }
    Ok((deployment, client))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/deployments/{id}/release-reports",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id"), ReportFilter, OnePageQuery),
    responses(
        (status = 200, description = "The customer's release reports, newest first, as it answered them (PaginatedResponse<ReleaseReport>)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 422, description = "no_credential, or an unknown filter value", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_reports(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
    Query(filter): Query<ReportFilter>,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<Value>> {
    let status = filter_value("status", filter.status.as_deref())?;
    let PageWindow {
        page, page_size, ..
    } = paging.window();
    let (_, client) = customer(&state, id).await?;
    let query = page_query(page, page_size, &[("status", status)]);
    let body = client
        .get(&format!("{}?{query}", paths::REPORTS), Some(Uuid::now_v7()))
        .await?;
    Ok(Json(body))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/deployments/{id}/release-reports/{report_id}/items",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Deployment id"),
        ("report_id" = Uuid, Path, description = "The customer's report id"),
        ItemFilter,
        OnePageQuery
    ),
    responses(
        (status = 200, description = "The report's items as the customer answered them (PaginatedResponse<ReportItemView>), conflict values included", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 422, description = "no_credential, or an unknown filter value", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error (the customer's 404 for an unknown report included)", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_items(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Path((id, report_id)): Path<(Uuid, Uuid)>,
    Query(filter): Query<ItemFilter>,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<Value>> {
    let status = filter_value("status", filter.status.as_deref())?;
    let kind = filter_value("kind", filter.kind.as_deref())?;
    let PageWindow {
        page, page_size, ..
    } = paging.window();
    let (_, client) = customer(&state, id).await?;
    let query = page_query(page, page_size, &[("status", status), ("kind", kind)]);
    let body = client
        .get(
            &format!("{}/{report_id}/items?{query}", paths::REPORTS),
            Some(Uuid::now_v7()),
        )
        .await?;
    Ok(Json(body))
}

/// Sends one item decision to the customer and records it here.
async fn decide(
    state: &FleetState,
    user_id: Uuid,
    deployment_id: Uuid,
    item_id: Uuid,
    verb: &'static str,
    row_version: i64,
    body: Value,
) -> ConsoleResult<Json<Value>> {
    let (deployment, client) = customer(state, deployment_id).await?;
    let action_id = Uuid::now_v7();
    let path = format!("{}/{item_id}/{verb}", paths::REPORT_ITEMS);
    let result = client
        .post(&path, &body, Some(row_version), Some(action_id))
        .await;
    let name: &'static str = match verb {
        "accept" => "accept",
        "use-mine" => "use_mine",
        _ => "dismiss",
    };
    let (remote_status, outcome) = match &result {
        Ok(response) => (Some(response.status), "ok"),
        Err(RemoteError::AuthRefused { status }) => (Some(*status), "refused"),
        Err(e) => (e.status(), "failed"),
    };
    let action = ActionWrite {
        id: action_id,
        actor_ref: user_id,
        deployment_ref: Some(deployment.id),
        rollout_ref: None,
        action: name,
        remote_method: Some("POST"),
        remote_path: Some(path),
        remote_status,
        outcome,
        detail: json!({ "item_id": item_id }),
    };
    let mut event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        user_id,
        "release_report_item",
        Some(item_id),
    )
    .named(format!("fleet.report_item.{name}"))
    .comment(format!(
        "customer {} ({})",
        deployment.project_code, deployment.environment
    ));
    if result.is_err() {
        event = event.outcome(AuditOutcome::Failed);
    }
    record(state, event, &action).await?;
    match result {
        Ok(response) => Ok(Json(response.body)),
        Err(e) => Err(ConsoleError::Remote(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/accept",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Deployment id"),
        ("item_id" = Uuid, Path, description = "The customer's item id")
    ),
    request_body = DecideItemBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The customer's decided item (ReportItem)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 422, description = "no_credential", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the customer refused (version_conflict, report_item_decided, …) or failed", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn accept_item(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    _session: HumanSession,
    Path((id, item_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<DecideItemBody>,
) -> ConsoleResult<Json<Value>> {
    decide(
        &state,
        ctx.user_id,
        id,
        item_id,
        "accept",
        body.row_version,
        json!({}),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/use-mine",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Deployment id"),
        ("item_id" = Uuid, Path, description = "The customer's item id")
    ),
    request_body = UseMineItemBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Our value written on the customer; the item is used_mine (ReportItem)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 422, description = "no_credential", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the customer refused (version_conflict on the item or record, …) or failed", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn use_mine_item(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    _session: HumanSession,
    Path((id, item_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UseMineItemBody>,
) -> ConsoleResult<Json<Value>> {
    decide(
        &state,
        ctx.user_id,
        id,
        item_id,
        "use-mine",
        body.row_version,
        json!({ "record_row_version": body.record_row_version }),
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/dismiss",
    tag = "fleet",
    params(
        ("id" = Uuid, Path, description = "Deployment id"),
        ("item_id" = Uuid, Path, description = "The customer's item id")
    ),
    request_body = DecideItemBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The customer's dismissed item (ReportItem)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 422, description = "no_credential", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn dismiss_item(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    _session: HumanSession,
    Path((id, item_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<DecideItemBody>,
) -> ConsoleResult<Json<Value>> {
    decide(
        &state,
        ctx.user_id,
        id,
        item_id,
        "dismiss",
        body.row_version,
        json!({}),
    )
    .await
}

/// One customer's open items (newest reports first, bounded).
async fn open_items_of(
    state: &FleetState,
    deployment: &DeploymentRow,
) -> Result<Vec<OpenItemView>, RemoteError> {
    let client = state
        .runtime
        .customer(&state.xrm.base.db, deployment)
        .await
        .map_err(|e| {
            tracing::warn!(deployment_id = %deployment.id, error = %e, "fleet open items: the credential could not be loaded");
            RemoteError::NoCredential
        })?;
    if !client.has_credential() {
        return Ok(Vec::new());
    }
    let correlation = Some(Uuid::now_v7());
    let reports = client
        .get(
            &format!(
                "{}?{}",
                paths::REPORTS,
                page_query(1, OPEN_REPORTS_SCANNED, &[])
            ),
            correlation,
        )
        .await?;
    let mut out = Vec::new();
    for report in reports["items"].as_array().cloned().unwrap_or_default() {
        if report["items_open"].as_i64().unwrap_or(0) <= 0 {
            continue;
        }
        let Some(report_id) = report["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            continue;
        };
        let items = client
            .get(
                &format!(
                    "{}/{report_id}/items?{}",
                    paths::REPORTS,
                    page_query(
                        1,
                        OPEN_ITEMS_PER_REPORT,
                        &[("status", Some("open".to_owned()))]
                    )
                ),
                correlation,
            )
            .await?;
        for item in items["items"].as_array().cloned().unwrap_or_default() {
            out.push(OpenItemView {
                deployment_id: deployment.id,
                deployment_label: deployment.label.clone(),
                project_code: deployment.project_code.clone(),
                report_id,
                item,
            });
        }
    }
    Ok(out)
}

/// Oldest first, by the item's `created_at` (RFC 3339 strings compare in
/// time order when they share an offset, which the customers' UTC
/// timestamps do).
pub fn sort_oldest_first(items: &mut [OpenItemView]) {
    items.sort_by(|a, b| {
        a.item["created_at"]
            .as_str()
            .unwrap_or_default()
            .cmp(b.item["created_at"].as_str().unwrap_or_default())
    });
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/open-items",
    tag = "fleet",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Open release-report items across every customer, oldest first; a customer that could not be read is skipped (see its observation.error_code)", body = PaginatedResponse<OpenItemView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn fleet_open_items(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<PaginatedResponse<OpenItemView>>> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let deployments = store::active_deployments(&state.xrm.base.db).await?;
    let ids: Vec<Uuid> = deployments.iter().map(|d| d.id).collect();
    let observations = store::observations_for(&state.xrm.base.db, &ids).await?;
    // Owned rows: a stream of borrowed rows inside the handler future trips
    // the higher-ranked `FnOnce` bound axum's `Handler` needs.
    let with_open: Vec<DeploymentRow> = deployments
        .into_iter()
        .filter(|d| {
            observations
                .iter()
                .find(|o| o.deployment_ref == d.id)
                .and_then(|o| o.open_items)
                .unwrap_or(0)
                > 0
        })
        .collect();
    let state_ref = &state;
    let results: Vec<Result<Vec<OpenItemView>, RemoteError>> =
        futures_util::stream::iter(with_open)
            .map(|deployment| async move { open_items_of(state_ref, &deployment).await })
            .buffer_unordered(OPEN_ITEMS_CONCURRENCY)
            .collect()
            .await;
    let mut items: Vec<OpenItemView> = Vec::new();
    for result in results {
        match result {
            Ok(found) => items.extend(found),
            Err(e) => {
                tracing::info!(error = %e, "fleet open items: one customer could not be read")
            }
        }
    }
    sort_oldest_first(&mut items);
    let total = items.len() as i64;
    let page_items = items
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(0))
        .take(usize::try_from(page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        page_items, total, page, page_size,
    )))
}

pub fn routes() -> Router<FleetState> {
    Router::new()
        .route(
            "/api/v1/fleet/deployments/{id}/release-reports",
            get(list_reports),
        )
        .route(
            "/api/v1/fleet/deployments/{id}/release-reports/{report_id}/items",
            get(list_items),
        )
        .route(
            "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/accept",
            post(accept_item),
        )
        .route(
            "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/use-mine",
            post(use_mine_item),
        )
        .route(
            "/api/v1/fleet/deployments/{id}/release-report-items/{item_id}/dismiss",
            post(dismiss_item),
        )
        .route("/api/v1/fleet/open-items", get(fleet_open_items))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_reports,
    list_items,
    accept_item,
    use_mine_item,
    dismiss_item,
    fleet_open_items
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_queries_carry_only_set_filters() {
        assert_eq!(page_query(1, 20, &[]), "page=1&page_size=20");
        assert_eq!(
            page_query(2, 50, &[("status", Some("open".into())), ("kind", None)]),
            "page=2&page_size=50&status=open"
        );
        assert!(filter_value("status", Some("open")).is_ok());
        assert!(filter_value("status", Some("open&x=1")).is_err());
    }

    #[test]
    fn open_items_sort_oldest_first() {
        let item = |at: &str| OpenItemView {
            deployment_id: Uuid::nil(),
            deployment_label: String::new(),
            project_code: String::new(),
            report_id: Uuid::nil(),
            item: json!({ "created_at": at }),
        };
        let mut items = vec![
            item("2026-10-01T10:00:00Z"),
            item("2026-09-30T10:00:00Z"),
            item("2026-10-01T09:00:00Z"),
        ];
        sort_oldest_first(&mut items);
        assert_eq!(items[0].item["created_at"], "2026-09-30T10:00:00Z");
        assert_eq!(items[2].item["created_at"], "2026-10-01T10:00:00Z");
    }
}

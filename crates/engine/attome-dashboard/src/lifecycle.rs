//! The `attome_dashboard` lifecycle state machine: `Draft -> Review -> Approved
//! -> Published -> Archived`. Ordinary field CRUD on a dashboard goes
//! through the generic entity engine (`/api/v1/attome_dashboard/{id}`); these
//! are the business-action transitions the generic engine cannot express.
//!
//! Mounted under `/api/v1/attome-dashboard/{id}/...`, not the shorter
//! `/api/v1/dashboard/...` every other bespoke-route crate would use (e.g.
//! `attome-project`'s `/api/v1/project/{id}/summary`) — see `seed.rs`'s naming
//! note: `attome-report` already owns the bare `/api/v1/dashboard/{id}`
//! generic-CRUD path for its own, unrelated `dashboard` entity.
//!
//! **Chosen transition semantics** (the spec left one ambiguous): the
//! four-eyes gate sits on `Approved -> Published` — literally "the
//! transition *to* Published" — not on `Review -> Approved`. `Review ->
//! Approved` is an ordinary reviewer sign-off (any caller holding
//! `attome_dashboard.update`); the version snapshot and audit trail on the
//! gated transition are the record that a second person authorized the
//! record going live.
//!
//! **Archive, not delete.** `archive` sets `lifecycle_status = 'archived'`
//! AND `is_active = false` in the same update, so an archived dashboard also
//! drops out of the generic entity engine's active-record lists. The generic
//! `/api/v1/attome_dashboard/{id}/restore` endpoint flips `is_active` back but
//! does not touch `lifecycle_status` — a restored dashboard comes back
//! `archived`-but-active, and its owner moves it forward again explicitly
//! (`unpublish`/`submit-review`). Reworking `restore` itself to also reset
//! `lifecycle_status` is a reasonable follow-up, not attempted here to avoid
//! reaching into the generic engine's restore path for one entity's needs.
//!
//! **Clone and duplicate are the same operation for now.** The Phase 1
//! spec checklist lists both, but with no pages/sections/widgets yet
//! (Phase 2+) there is nothing that would make them behave differently — a
//! full-fidelity "clone" and a "quick duplicate" only diverge once there is
//! child content to decide whether to deep-copy. One `clone` endpoint here;
//! split it if/when Phase 2+ gives the two an actual difference to have.
//!
//! **What viewers see (D-521).** `lifecycle_status` describes the *working
//! copy* — the live page/section/widget rows editors change.
//! `attome_dashboard.published_version_id` alone decides what viewers see: it
//! points at an immutable `dashboard_version` snapshot. `publish` writes a
//! new version and moves the pointer; `start-revision` returns a published
//! working copy to `draft` without touching the pointer; `activate` rolls the
//! pointer back to an earlier version (four-eyes, like publish); `unpublish`
//! and `archive` clear it. `restore` writes a version's tree into the draft
//! only. Publishing also pins every widget's stored query to the exact
//! `sql_query_version` it was published with (`dependencies` in the
//! snapshot), so a published dashboard's SQL cannot change underneath it.
//!
//! Every `do_*` transition function is `pub` (not `pub(crate)`) for the same
//! reason `attome-service::convert`'s conversion functions are: this crate's
//! own `tests/dashboard_crud.rs` exercises the real transaction/lock/status
//! logic directly against a live database, without standing up a full
//! authenticated HTTP request. The thin HTTP handlers below own only the
//! privilege check, the gate, and the audit write.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;
use crate::auth::{DashboardRead, DashboardUpdate};

/// D-195 four-eyes action_type for the Approved -> Published transition —
/// wired into `attome-api`'s `approval_admin::{KNOWN_ACTION_TYPES,
/// execute_approved}` so a second admin's `POST /api/v1/admin/approvals/
/// {id}/decide` dispatches back into `do_publish_dashboard` below.
pub const ACTION_DASHBOARD_PUBLISH: &str = "dashboard.publish";

/// D-521 — the audit event name for rolling the live version back to an
/// earlier one (`activate`). Not an approval action type: activate changes
/// what viewers see exactly as publish does, so it rides the same
/// `ACTION_DASHBOARD_PUBLISH` gate — a deployment that requires four-eyes on
/// publish can never roll back without it. The approval payload carries
/// `version_id`, which is how `approval_admin::execute_approved` tells the two
/// apart.
pub const AUDIT_DASHBOARD_ACTIVATE_VERSION: &str = "dashboard.activate_version";

/// The dashboard lifecycle lock — shared by every transition here and by
/// `pages::do_create_page`, so a page can never be added while publish,
/// clone or restore is rewriting the same dashboard's tree.
pub(crate) async fn lock_dashboard(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
) -> Result<(), AppError> {
    // Advisory lock BEFORE reading — same "lock, then act" order as
    // `attome-service::convert::lock_and_load_work_request` — so two concurrent
    // transitions on the same dashboard can't both pass the status check
    // below.
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-dashboard/lifecycle:{dashboard_id}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another request is already changing this dashboard's lifecycle state",
        ));
    }
    Ok(())
}

/// `NULL` (no field-level default exists — see `seed.rs`'s module doc) reads
/// as `"draft"`.
async fn load_status_and_version(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
) -> Result<(String, i64), AppError> {
    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT lifecycle_status, row_version FROM attome_dashboard \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (status, row_version) = row.ok_or(AppError::NotFound)?;
    Ok((status.unwrap_or_else(|| "draft".to_string()), row_version))
}

/// Locks, verifies the current state is one of `allowed_from` and that
/// `expected_row_version` still matches, then applies the transition.
/// `wrong_state_msg` is this call site's own static conflict message (each
/// transition knows its own wording; `AppError::Conflict` takes `&'static
/// str`, not an owned `String`).
async fn apply_transition(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
    expected_row_version: i64,
    allowed_from: &[&str],
    to_status: &str,
    also_deactivate: bool,
    wrong_state_msg: &'static str,
) -> Result<i64, AppError> {
    lock_dashboard(tx, dashboard_id).await?;
    let (status, row_version) = load_status_and_version(tx, dashboard_id).await?;
    if !allowed_from.contains(&status.as_str()) {
        return Err(AppError::Conflict(wrong_state_msg));
    }
    if row_version != expected_row_version {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state — reload and retry",
        ));
    }

    let rows_affected = if also_deactivate {
        sqlx::query(
            "UPDATE attome_dashboard SET lifecycle_status = $3, modified_at = NOW(), \
             row_version = row_version + 1, is_active = false, published_version_id = NULL \
             WHERE id = $1 AND row_version = $2",
        )
        .bind(dashboard_id)
        .bind(expected_row_version)
        .bind(to_status)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE attome_dashboard SET lifecycle_status = $3, modified_at = NOW(), \
             row_version = row_version + 1 \
             WHERE id = $1 AND row_version = $2",
        )
        .bind(dashboard_id)
        .bind(expected_row_version)
        .bind(to_status)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
    };
    if rows_affected != 1 {
        return Err(AppError::Conflict(
            "dashboard row_version changed concurrently — reload and retry",
        ));
    }
    Ok(expected_row_version + 1)
}

/// The subset of `attome_dashboard`'s own columns that both `do_publish_dashboard`
/// (into `dashboard_version.snapshot_json`) and `do_clone` (into a new
/// row) copy verbatim — infra columns (`row_version`, `is_active`,
/// `created_at`/`modified_at`, `lifecycle_status`) are deliberately excluded,
/// since both callers set those themselves.
#[derive(sqlx::FromRow)]
struct DashboardFieldsRow {
    name: String,
    name_ar: Option<String>,
    description: Option<String>,
    description_ar: Option<String>,
    dashboard_type: String,
    owner_id: Option<Uuid>,
    organization_id: Option<Uuid>,
    visibility: Option<String>,
    thumbnail: Option<String>,
    settings: Option<String>,
    is_template: Option<bool>,
    template_category: Option<String>,
    template_version: Option<String>,
}

/// The `dashboard.submit_for_review` event is written in the same transaction
/// (D-062, audit plan 3.6) — found missing from the whole review lifecycle
/// (this, `do_approve`, `do_reject`, `do_unpublish`, `do_archive`,
/// `do_publish_dashboard_checked`) alongside the audit-coverage sweep that
/// mapped these routes; only `do_start_revision`/`do_activate_version` had it.
pub async fn do_submit_for_review(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let new_version = apply_transition(
        &mut tx,
        dashboard_id,
        expected_row_version,
        &["draft"],
        "review",
        false,
        "only a draft dashboard can be submitted for review",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Submitted,
            "dashboard.submit_review",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(new_version))
        .comment(format!("dashboard {dashboard_id} submitted for review")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_version)
}

/// The `dashboard.approve` event is written in the same transaction (D-062).
pub async fn do_approve(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let new_version = apply_transition(
        &mut tx,
        dashboard_id,
        expected_row_version,
        &["review"],
        "approved",
        false,
        "only a dashboard in review can be approved",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Approved,
            "dashboard.approve",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(new_version)),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_version)
}

/// The `dashboard.reject` event is written in the same transaction (D-062).
pub async fn do_reject(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let new_version = apply_transition(
        &mut tx,
        dashboard_id,
        expected_row_version,
        &["review"],
        "draft",
        false,
        "only a dashboard in review can be rejected",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Rejected,
            "dashboard.reject",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(new_version)),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_version)
}

/// D-521 — starts a new revision of a published dashboard: the working copy
/// returns to `draft` so it can be edited and reviewed again, while
/// `published_version_id` — what viewers see — is left exactly as it is.
///
/// The `dashboard.start_revision` event is written in the same transaction
/// (D-062, audit plan 3.6).
pub async fn do_start_revision(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let new_version = apply_transition(
        &mut tx,
        dashboard_id,
        expected_row_version,
        &["published"],
        "draft",
        false,
        "only a published dashboard can start a new revision",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Update,
            "dashboard.start_revision",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(new_version))
        .comment(format!(
            "dashboard {dashboard_id} started a new revision; the live version is unchanged"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_version)
}

/// D-521 — takes the dashboard offline by clearing `published_version_id`.
/// A `published` working copy returns to `draft`; a working copy already in
/// revision keeps its status. Returns the new `row_version` and
/// the resulting `lifecycle_status`.
/// The `dashboard.unpublish` event is written in the same transaction (D-062).
pub async fn do_unpublish(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<(i64, String), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_dashboard(&mut tx, dashboard_id).await?;
    let row: Option<(Option<String>, i64, Option<Uuid>)> = sqlx::query_as(
        "SELECT lifecycle_status, row_version, published_version_id FROM attome_dashboard \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (status, row_version, live_version) = row.ok_or(AppError::NotFound)?;
    let status = status.unwrap_or_else(|| "draft".to_string());
    if live_version.is_none() {
        return Err(AppError::Conflict(
            "this dashboard has no live version to unpublish",
        ));
    }
    if row_version != expected_row_version {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state — reload and retry",
        ));
    }
    let new_status = if status == "published" {
        "draft".to_string()
    } else {
        status
    };
    let rows_affected = sqlx::query(
        "UPDATE attome_dashboard SET published_version_id = NULL, lifecycle_status = $3, \
         modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2",
    )
    .bind(dashboard_id)
    .bind(expected_row_version)
    .bind(&new_status)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows_affected != 1 {
        return Err(AppError::Conflict(
            "dashboard row_version changed concurrently — reload and retry",
        ));
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Update,
            "dashboard.unpublish",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(expected_row_version + 1)),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((expected_row_version + 1, new_status))
}

/// The `dashboard.archive` event is written in the same transaction (D-062).
pub async fn do_archive(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let new_version = apply_transition(
        &mut tx,
        dashboard_id,
        expected_row_version,
        &["draft", "review", "approved", "published"],
        "archived",
        true,
        "this dashboard is already archived",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::SoftDelete,
            "dashboard.archive",
            actor_id,
        )
        .versions(Some(expected_row_version), Some(new_version)),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_version)
}

/// Collects every widget in a `pages_snapshot` tree that is bound to a stored
/// query or view, as `(widget_id, query_id, view_id)`.
fn collect_widget_refs(
    sections: &[serde_json::Value],
    out: &mut Vec<(String, Option<String>, Option<String>)>,
) {
    for section in sections {
        if let Some(widgets) = section.get("widgets").and_then(serde_json::Value::as_array) {
            for widget in widgets {
                let text = |key: &str| {
                    widget
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                };
                let (mut query_id, view_id) = (text("query_id"), text("view_id"));
                // A declarative widget names its query in `config.query_ref`
                // (`declarative_widget.rs`); it executes like a `query_id`, so
                // it is pinned like one (D-543 rule 3).
                if query_id.is_none()
                    && view_id.is_none()
                    && text("widget_type").as_deref() == Some("declarative_widget")
                {
                    query_id = crate::execution::widget_config(widget)
                        .get("query_ref")
                        .and_then(serde_json::Value::as_str)
                        .filter(|v| !v.is_empty())
                        .map(str::to_string);
                }
                if query_id.is_some() || view_id.is_some() {
                    out.push((text("id").unwrap_or_default(), query_id, view_id));
                }
            }
        }
        if let Some(children) = section
            .get("children")
            .and_then(serde_json::Value::as_array)
        {
            collect_widget_refs(children, out);
        }
    }
}

/// D-521 — resolves each bound widget to the exact query version it is
/// published with. The viewer renders a widget's view in preference to its
/// raw query (R-02), so a view-bound widget pins the view's query. A widget
/// whose view or query no longer resolves, or whose query has never been
/// published, cannot be pinned and refuses the publish with its id named.
async fn pin_dependencies(
    tx: &mut Transaction<'_, Postgres>,
    pages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut refs = Vec::new();
    for page in pages {
        if let Some(sections) = page.get("sections").and_then(serde_json::Value::as_array) {
            collect_widget_refs(sections, &mut refs);
        }
    }
    let mut dependencies = Vec::with_capacity(refs.len());
    for (widget_id, query_id, view_id) in refs {
        // D-543: a view is not versioned (D-521 rule 2), and execution reads
        // its `kind`/`view_metadata`/`table_definition` live, so publish
        // captures them by value rather than leaving them a reference.
        let (query_uuid, view_semantics): (Uuid, Option<serde_json::Value>) = match &view_id {
            Some(view) => {
                let view_uuid = Uuid::parse_str(view).map_err(|_| {
                    AppError::Validation(format!(
                        "widget {widget_id} cannot be published: its view_id is not a valid id"
                    ))
                })?;
                let row: Option<ViewSemanticsRow> = sqlx::query_as(
                    "SELECT sql_query_ref, kind, view_metadata, table_definition \
                     FROM view WHERE id = $1 AND is_active = true",
                )
                .bind(view_uuid)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?;
                let row = row.ok_or_else(|| {
                    AppError::Validation(format!(
                        "widget {widget_id} cannot be published: its view no longer exists"
                    ))
                })?;
                let semantics = serde_json::json!({
                    "view_id": view,
                    "kind": row.kind,
                    "view_metadata": row.view_metadata,
                    "table_definition": row.table_definition,
                });
                (row.sql_query_ref, Some(semantics))
            }
            None => (
                Uuid::parse_str(query_id.as_deref().unwrap_or_default()).map_err(|_| {
                    AppError::Validation(format!(
                        "widget {widget_id} cannot be published: its query_id is not a valid id"
                    ))
                })?,
                None,
            ),
        };
        let version_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT v.id FROM sql_query_version v \
             JOIN sql_query q ON q.id = v.query_id \
             WHERE v.query_id = $1 AND q.is_active = true \
             ORDER BY v.id DESC LIMIT 1",
        )
        .bind(query_uuid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        let version_id = version_id.ok_or_else(|| {
            AppError::Validation(format!(
                "widget {widget_id} cannot be published: its query is missing, inactive or \
                 has no published version"
            ))
        })?;
        // D-543: `sql_query_version` pins SQL, relations and cost
        // only, so the column metadata that decides projected columns and the
        // filter whitelist is captured here too — the view's when the widget is
        // view-bound (that is what execution reads), otherwise the query's.
        let column_definition = match &view_semantics {
            Some(view) => view.get("table_definition").cloned(),
            None => sqlx::query_scalar::<_, Option<String>>(
                "SELECT table_definition FROM sql_query WHERE id = $1",
            )
            .bind(query_uuid)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .flatten()
            .map(|raw| serde_json::from_str(&raw).unwrap_or(serde_json::Value::String(raw))),
        };
        dependencies.push(serde_json::json!({
            "widget_id": widget_id,
            "view_id": view_id,
            "query_id": query_uuid,
            "query_version_id": version_id,
            "column_definition": column_definition,
            "view": view_semantics,
        }));
    }
    Ok(dependencies)
}

/// D-543 rule 3 (E-02) — each governed KPI widget's metric definitions,
/// captured by value with the query version a query-backed metric resolves to
/// and the snapshot current at publish. A published KPI widget then renders
/// only snapshots computed from that definition (`widget_data.rs`): a later
/// edit to the metric shows as `definition_changed` instead of silently
/// changing what the number means. A KPI widget naming a missing metric
/// refuses the publish with its id named, like an unpinnable query.
async fn pin_metric_dependencies(
    tx: &mut Transaction<'_, Postgres>,
    pages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, AppError> {
    let mut widgets = Vec::new();
    for page in pages {
        crate::execution::collect_widgets(page, &mut widgets);
    }
    let mut dependencies = Vec::new();
    for widget in widgets {
        let widget_id = widget
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        for metric_id in crate::execution::kpi_metric_refs(widget) {
            let definition: Option<MetricDefinitionCapture> = sqlx::query_as(
                "SELECT source_kind, query_ref, formula, period, direction FROM dashboard_metric_definition WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(metric_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            let definition = definition.ok_or_else(|| {
                AppError::Validation(format!(
                    "widget {widget_id} cannot be published: metric {metric_id} is missing or inactive"
                ))
            })?;
            let query_version_id: Option<Uuid> = match (
                definition.source_kind.as_deref(),
                definition
                    .query_ref
                    .as_deref()
                    .and_then(|r| Uuid::parse_str(r).ok()),
            ) {
                (Some("query"), Some(query_id)) => sqlx::query_scalar(
                    "SELECT id FROM sql_query_version WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
                )
                .bind(query_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?,
                _ => None,
            };
            let snapshot_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM metric_snapshot WHERE metric_ref = $1 ORDER BY period_start DESC, computed_at DESC, id DESC LIMIT 1",
            )
            .bind(metric_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            dependencies.push(serde_json::json!({
                "widget_id": widget_id,
                "metric_id": metric_id,
                "definition": {
                    "source_kind": definition.source_kind,
                    "query_ref": definition.query_ref,
                    "formula": definition.formula,
                    "period": definition.period,
                    "direction": definition.direction,
                },
                "query_version_id": query_version_id,
                "snapshot_id_at_publish": snapshot_id,
            }));
        }
    }
    Ok(dependencies)
}

/// The definition-bearing columns of a metric (E-02), as captured at publish.
#[derive(sqlx::FromRow)]
pub(crate) struct MetricDefinitionCapture {
    pub(crate) source_kind: Option<String>,
    pub(crate) query_ref: Option<String>,
    pub(crate) formula: Option<String>,
    pub(crate) period: Option<String>,
    pub(crate) direction: Option<String>,
}

/// Dashboard 10/10 Phase 2.3 — the working copy as an unpinned snapshot, for
/// an editor's preview. Performs no authorization of its own.
pub async fn do_load_draft(db: &DbPool, dashboard_id: Uuid) -> Result<serde_json::Value, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let exists: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM attome_dashboard WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    exists.ok_or(AppError::NotFound)?;
    let snapshot = build_snapshot_json(&mut tx, dashboard_id, false).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(snapshot)
}

/// D-543 — the published execution definition of `dashboard_id`'s current
/// working copy (format 3): its scalar fields, its whole page tree, its
/// parameter and variable declarations, and — when `pin` is true — the
/// `dependencies` that pin each bound widget to a query version and capture
/// the view semantics and column metadata execution would otherwise read live.
/// Closed with a `publication_fingerprint` over the whole resolved definition.
///
/// The single source of truth for the snapshot shape; `DashboardSnapshotFields`
/// mirrors the subset restore reads back (restore still rewrites only the
/// scalars and the tree — rewriting parameters and variables from a snapshot is
/// a separate change, tracked with the Phase 1 exit criteria).
async fn build_snapshot_json(
    tx: &mut Transaction<'_, Postgres>,
    dashboard_id: Uuid,
    pin: bool,
) -> Result<serde_json::Value, AppError> {
    let snapshot_row: Option<DashboardFieldsRow> = sqlx::query_as(
        "SELECT name, name_ar, description, description_ar, dashboard_type, owner_id, \
                organization_id, visibility, thumbnail, settings, is_template, \
                template_category, template_version \
         FROM attome_dashboard WHERE id = $1",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let fields = snapshot_row.ok_or(AppError::NotFound)?;
    let pages = crate::layout::pages_snapshot(tx, dashboard_id).await?;
    let (dependencies, metric_dependencies) = if pin {
        (
            pin_dependencies(tx, &pages).await?,
            pin_metric_dependencies(tx, &pages).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let parameters = definition_rows(
        tx,
        "SELECT to_jsonb(r) FROM (SELECT id, page_id, name, name_ar, parameter_type, \
             lookup_entity_logicalname, default_value FROM dashboard_parameter \
             WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true)) r \
         ORDER BY (r.id)",
        dashboard_id,
    )
    .await?;
    let variables = definition_rows(
        tx,
        "SELECT to_jsonb(r) FROM (SELECT id, page_id, name, name_ar, variable_type, \
             default_value FROM dashboard_variable \
             WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true)) r \
         ORDER BY (r.id)",
        dashboard_id,
    )
    .await?;
    let mut snapshot = serde_json::json!({
        // Format 4 (dashboard 10/10 Phase 2) adds `metric_dependencies`.
        "snapshot_format": 4,
        "name": fields.name,
        "name_ar": fields.name_ar,
        "description": fields.description,
        "description_ar": fields.description_ar,
        "dashboard_type": fields.dashboard_type,
        "owner_id": fields.owner_id,
        "organization_id": fields.organization_id,
        "visibility": fields.visibility,
        "thumbnail": fields.thumbnail,
        "settings": fields.settings,
        "is_template": fields.is_template,
        "template_category": fields.template_category,
        "template_version": fields.template_version,
        "pages": pages,
        "parameters": parameters,
        "variables": variables,
        "dependencies": dependencies,
        "metric_dependencies": metric_dependencies,
    });
    let fingerprint = publication_fingerprint(&snapshot);
    if let Some(object) = snapshot.as_object_mut() {
        object.insert(
            "publication_fingerprint".to_string(),
            serde_json::Value::String(fingerprint),
        );
    }
    Ok(snapshot)
}

/// One definition-bearing child table as JSON rows, ordered by id so the
/// snapshot — and therefore its fingerprint — is stable across runs.
async fn definition_rows(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    dashboard_id: Uuid,
) -> Result<Vec<serde_json::Value>, AppError> {
    sqlx::query_scalar::<_, serde_json::Value>(sql)
        .bind(dashboard_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// D-543 — SHA-256 over the resolved definition. `serde_json::Map` is a
/// `BTreeMap` in this workspace (the `preserve_order` feature is not enabled),
/// so `to_string` emits keys in sorted order and the hash is canonical.
/// Computed before the fingerprint field itself is inserted.
///
/// D-544: `metric_dependencies[].snapshot_id_at_publish` is excluded — a new
/// snapshot computed from the same metric definition is data, not definition,
/// so it must not invalidate a four-eyes approval of unchanged content.
fn publication_fingerprint(snapshot: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical = snapshot.clone();
    if let Some(deps) = canonical
        .get_mut("metric_dependencies")
        .and_then(serde_json::Value::as_array_mut)
    {
        for dep in deps {
            if let Some(object) = dep.as_object_mut() {
                object.remove("snapshot_id_at_publish");
            }
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Dashboard 10/10 Phase 3.5 — the fingerprint publishing the working copy now
/// would produce (the whole resolved definition, pinned). 422 when the working
/// copy cannot be pinned. Writes nothing.
pub async fn do_publication_fingerprint(
    db: &DbPool,
    dashboard_id: Uuid,
) -> Result<String, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let snapshot = build_snapshot_json(&mut tx, dashboard_id, true).await?;
    tx.rollback().await.map_err(AppError::internal)?;
    snapshot
        .get("publication_fingerprint")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("snapshot without a publication fingerprint"))
}

/// The result of a publish bound to an expected fingerprint.
pub enum PublishOutcome {
    /// `(row_version, version_id, version_number)`.
    Published(i64, Uuid, i64),
    /// The resolved definition no longer matches what was reviewed; nothing was
    /// written.
    DefinitionChanged,
}

impl std::fmt::Debug for PublishOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishOutcome").finish_non_exhaustive()
    }
}

/// The mutable semantics a view contributes to execution (D-543): captured at
/// publish because `view` has no version to pin.
#[derive(sqlx::FromRow)]
struct ViewSemanticsRow {
    sql_query_ref: Uuid,
    kind: Option<String>,
    view_metadata: Option<serde_json::Value>,
    table_definition: Option<serde_json::Value>,
}

/// The gated transition. `pub` (not `pub(crate)`) so `attome-api`'s
/// `approval_admin::execute_approved` can dispatch back into it once a
/// second admin approves the pending request — same shape as
/// `attome_compliance::rewrap_admin::do_trigger_rewrap`/`attome_security::admin::
/// do_assign_user_role`. Also writes the immutable `dashboard_version`
/// snapshot in the same transaction as the status flip, so a published
/// dashboard and its version row can never observably disagree.
pub async fn do_publish_dashboard(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    published_by: Uuid,
) -> Result<(i64, Uuid, i64), AppError> {
    match do_publish_dashboard_checked(
        state,
        dashboard_id,
        expected_row_version,
        published_by,
        None,
    )
    .await?
    {
        PublishOutcome::Published(row_version, version_id, version_number) => {
            Ok((row_version, version_id, version_number))
        }
        PublishOutcome::DefinitionChanged => unreachable!("no fingerprint was expected"),
    }
}

/// [`do_publish_dashboard`] bound to the resolved definition a reviewer saw
/// (Phase 3.5, E-03): with `expected_fingerprint`, the version is written only
/// when the definition captured under the lock has exactly that fingerprint.
pub async fn do_publish_dashboard_checked(
    state: &EngineState,
    dashboard_id: Uuid,
    expected_row_version: i64,
    published_by: Uuid,
    expected_fingerprint: Option<&str>,
) -> Result<PublishOutcome, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_dashboard(&mut tx, dashboard_id).await?;
    let (status, row_version) = load_status_and_version(&mut tx, dashboard_id).await?;
    if status != "approved" {
        return Err(AppError::Conflict(
            "only an approved dashboard can be published",
        ));
    }
    if row_version != expected_row_version {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state — reload and retry",
        ));
    }

    let snapshot_json = build_snapshot_json(&mut tx, dashboard_id, true).await?;
    if let Some(expected) = expected_fingerprint
        && snapshot_json
            .get("publication_fingerprint")
            .and_then(serde_json::Value::as_str)
            != Some(expected)
    {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(PublishOutcome::DefinitionChanged);
    }

    // `version_number` is a `"number"`-typed attribute (NUMERIC column, per
    // `attome-metadata::provision::identifiers`), so it must be cast to a native
    // type before sqlx can decode it — this workspace has neither the
    // `bigdecimal` nor `rust_decimal` sqlx feature enabled, so a bare NUMERIC
    // column has no `Decode<Postgres>` target at all. Same
    // `::bigint`/`::double precision` cast convention `attome-project`'s
    // `work_plan.rs`/`summary.rs`/`portfolio_program.rs` use for every raw
    // read of a "number" field.
    let next_version_number: i64 = sqlx::query_scalar(
        "SELECT (COALESCE(MAX(version_number), 0) + 1)::bigint FROM dashboard_version \
         WHERE dashboard_id = $1",
    )
    .bind(dashboard_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let version_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_version \
         (id, dashboard_id, version_number, snapshot_json, published_by, published_at) \
         VALUES ($1, $2, $3, $4, $5, NOW())",
    )
    .bind(version_id)
    .bind(dashboard_id)
    .bind(next_version_number)
    .bind(snapshot_json.to_string())
    .bind(published_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let updated = sqlx::query(
        "UPDATE attome_dashboard SET lifecycle_status = 'published', published_version_id = $3, \
         modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2",
    )
    .bind(dashboard_id)
    .bind(expected_row_version)
    .bind(version_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "dashboard row_version changed concurrently — reload and retry",
        ));
    }

    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Activated,
            "dashboard.publish",
            published_by,
        )
        .versions(Some(expected_row_version), Some(expected_row_version + 1)),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(PublishOutcome::Published(
        expected_row_version + 1,
        version_id,
        next_version_number,
    ))
}

/// Deep-copies `dashboard_id`'s scalar fields **and its whole page/section/
/// breakpoint/widget tree** into a new `draft` dashboard — see `layout.rs`'s
/// module doc comment for why this used to leave the clone with zero pages
/// (found and fixed 2026-08-29, alongside `do_restore_version` below, which
/// shares `layout::apply_pages_snapshot` with this function).
///
/// R-07: takes `state` (not a bare `db: &DbPool`) — `layout::
/// apply_pages_snapshot` needs it to validate every copied node against the
/// live entity metadata. Also takes `lock_dashboard(source)` immediately
/// after `begin()` now, same as `do_restore_version` always did — this
/// function's own doc comment used to claim the two were symmetric here when
/// they weren't (fixed, not just documented): without the lock, a concurrent
/// `archive`/`publish` on the source could interleave with this read and
/// clone a torn snapshot of it.
pub async fn do_clone(
    state: &EngineState,
    dashboard_id: Uuid,
    cloned_by: Uuid,
) -> Result<Uuid, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_dashboard(&mut tx, dashboard_id).await?;

    // Reuses `DashboardFieldsRow` (the same shape `do_publish_dashboard`
    // snapshots) even though its own `owner_id` is discarded below — the
    // clone's owner is always the caller, not copied from the source.
    let row: Option<DashboardFieldsRow> = sqlx::query_as(
        "SELECT name, name_ar, description, description_ar, dashboard_type, owner_id, \
                organization_id, visibility, thumbnail, settings, is_template, \
                template_category, template_version \
         FROM attome_dashboard WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let fields = row.ok_or(AppError::NotFound)?;

    let new_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_dashboard \
         (id, name, name_ar, description, description_ar, dashboard_type, owner_id, \
          organization_id, lifecycle_status, visibility, thumbnail, settings, is_template, \
          template_category, template_version, created_by, modified_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'draft', $9, $10, $11, $12, $13, $14, $15, $15)",
    )
    .bind(new_id)
    .bind(format!("{} (Copy)", fields.name))
    .bind(&fields.name_ar)
    .bind(&fields.description)
    .bind(&fields.description_ar)
    .bind(&fields.dashboard_type)
    .bind(cloned_by)
    .bind(fields.organization_id)
    .bind(&fields.visibility)
    .bind(&fields.thumbnail)
    .bind(&fields.settings)
    .bind(fields.is_template)
    .bind(&fields.template_category)
    .bind(&fields.template_version)
    .bind(cloned_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let pages = crate::layout::pages_snapshot(&mut tx, dashboard_id).await?;
    let pages_json = serde_json::Value::Array(pages);
    crate::layout::apply_pages_snapshot(
        &mut tx,
        state,
        new_id,
        &pages_json,
        crate::layout::IdPolicy::GenerateNewIds,
        cloned_by,
    )
    .await?;

    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            new_id,
            AuditOperation::Clone,
            "dashboard.clone",
            cloned_by,
        )
        .comment(format!("dashboard {new_id} cloned from {dashboard_id}")),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(new_id)
}

/// The scalar half of a version snapshot — `do_publish_dashboard`'s own
/// `serde_json::json!({...})` call is the single source of truth for this
/// shape (`name`/`name_ar`/.../`pages`); this struct mirrors exactly the
/// subset `do_restore_version` reverts. `owner_id`/`organization_id` are
/// present in the JSON but deliberately have no field here — a content
/// restore should not silently reassign ownership — so serde just ignores
/// them (no `deny_unknown_fields`).
#[derive(Deserialize)]
struct DashboardSnapshotFields {
    name: String,
    name_ar: Option<String>,
    description: Option<String>,
    description_ar: Option<String>,
    dashboard_type: String,
    visibility: Option<String>,
    thumbnail: Option<String>,
    settings: Option<String>,
    is_template: Option<bool>,
    template_category: Option<String>,
    template_version: Option<String>,
    pages: serde_json::Value,
}

/// Restores `dashboard_id`'s scalar fields **and** its whole page/section/
/// breakpoint/widget tree from one of its own past published versions —
/// `dashboard_version` was write-only until this (M26 Phase 2 backlog:
/// "nothing restores from one"). Reuses every id the snapshot carries
/// (`IdPolicy::ReuseIds`), so restoring the same version twice in a row is a
/// no-op the second time.
///
/// Deliberately **not gated by lifecycle status** — a `published` dashboard
/// can be restored (the operator then republishes through the normal
/// four-eyes gate if they want the restored state live again) and so can a
/// `draft` one (undoing in-progress edits back to the last known-good
/// version is exactly what an operator reaches for this to do). Deliberately
/// **no caller-supplied `expected_row_version` guard** either, unlike every
/// other transition in this file — restore's whole point is to overwrite
/// whatever is currently there with a known target state, not to apply a
/// patch that assumes an unchanged baseline; the advisory lock below is the
/// actual concurrency story (it still refuses to race a concurrent
/// publish/clone/restore on the same dashboard). What *is* enforced: the
/// version must actually belong to this dashboard.
///
/// D-521: restore writes into the **working copy** only. It sets
/// `lifecycle_status` to `draft` (the restored content has not been reviewed
/// as the working copy) and never touches `published_version_id`, so viewers
/// keep seeing the live version. Making an earlier version live is
/// `do_activate_version`.
pub async fn do_restore_version(
    state: &EngineState,
    dashboard_id: Uuid,
    version_id: Uuid,
    restored_by: Uuid,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_dashboard(&mut tx, dashboard_id).await?;

    let snapshot_json: Option<String> = sqlx::query_scalar(
        "SELECT snapshot_json FROM dashboard_version \
         WHERE id = $1 AND dashboard_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(version_id)
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let snapshot_json = snapshot_json.ok_or(AppError::NotFound)?;
    let snapshot: DashboardSnapshotFields = serde_json::from_str(&snapshot_json)
        .map_err(|e| AppError::internal(format!("corrupt version snapshot: {e}")))?;

    sqlx::query(
        "UPDATE attome_dashboard SET \
             name = $2, name_ar = $3, description = $4, description_ar = $5, \
             dashboard_type = $6, visibility = $7, thumbnail = $8, settings = $9, \
             is_template = $10, template_category = $11, template_version = $12, \
             lifecycle_status = 'draft', \
             modified_at = NOW(), modified_by = $13, row_version = row_version + 1 \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .bind(&snapshot.name)
    .bind(&snapshot.name_ar)
    .bind(&snapshot.description)
    .bind(&snapshot.description_ar)
    .bind(&snapshot.dashboard_type)
    .bind(&snapshot.visibility)
    .bind(&snapshot.thumbnail)
    .bind(&snapshot.settings)
    .bind(snapshot.is_template)
    .bind(&snapshot.template_category)
    .bind(&snapshot.template_version)
    .bind(restored_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    crate::layout::apply_pages_snapshot(
        &mut tx,
        state,
        dashboard_id,
        &snapshot.pages,
        crate::layout::IdPolicy::ReuseIds,
        restored_by,
    )
    .await?;

    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Restore,
            "dashboard.restore_version",
            restored_by,
        )
        .comment(format!(
            "dashboard {dashboard_id} restored from version {version_id}"
        )),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// D-521 — rollback: makes one of this dashboard's earlier published versions
/// the live one again. The working copy is untouched; a `published` working
/// copy returns to `draft`, because it no longer matches what viewers see.
/// Returns the new `row_version` and the activated version's number.
///
/// The activation event is written in the same transaction (D-062, audit
/// plan 3.6), attributed to `actor_id` (the deciding admin under four-eyes).
pub async fn do_activate_version(
    state: &EngineState,
    dashboard_id: Uuid,
    version_id: Uuid,
    expected_row_version: i64,
    actor_id: Uuid,
) -> Result<(i64, i64), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_dashboard(&mut tx, dashboard_id).await?;
    let (status, row_version) = load_status_and_version(&mut tx, dashboard_id).await?;
    if row_version != expected_row_version {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state — reload and retry",
        ));
    }
    let version_number: i64 = sqlx::query_scalar(
        "SELECT version_number::bigint FROM dashboard_version \
         WHERE id = $1 AND dashboard_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(version_id)
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let new_status = if status == "published" {
        "draft".to_string()
    } else {
        status
    };
    let rows_affected = sqlx::query(
        "UPDATE attome_dashboard SET published_version_id = $3, lifecycle_status = $4, \
         modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2",
    )
    .bind(dashboard_id)
    .bind(expected_row_version)
    .bind(version_id)
    .bind(&new_status)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows_affected != 1 {
        return Err(AppError::Conflict(
            "dashboard row_version changed concurrently — reload and retry",
        ));
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            dashboard_id,
            AuditOperation::Activated,
            AUDIT_DASHBOARD_ACTIVATE_VERSION,
            actor_id,
        )
        .versions(Some(expected_row_version), Some(expected_row_version + 1))
        .comment(format!(
            "dashboard {dashboard_id} rolled back to version {version_number} ({version_id})"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((expected_row_version + 1, version_number))
}

/// D-521 — what a viewer of `dashboard_id` sees.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublishedDashboard {
    /// `published` (an immutable version is live) or `none`.
    pub state: String,
    pub version_id: Option<Uuid>,
    pub version_number: Option<i64>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
    pub published_by: Option<Uuid>,
    /// The version snapshot (`snapshot_format` 2 carries pinned
    /// `dependencies`); `null` for `none`.
    #[schema(value_type = Object)]
    pub snapshot: Option<serde_json::Value>,
}

impl PublishedDashboard {
    fn none() -> Self {
        Self {
            state: "none".to_string(),
            version_id: None,
            version_number: None,
            published_at: None,
            published_by: None,
            snapshot: None,
        }
    }
}

/// Loads what viewers of `dashboard_id` see. Performs no authorization of
/// its own.
pub async fn do_load_published(
    db: &DbPool,
    dashboard_id: Uuid,
) -> Result<PublishedDashboard, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT published_version_id FROM attome_dashboard \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (live_version,) = row.ok_or(AppError::NotFound)?;

    let published = if let Some(version_id) = live_version {
        type VersionRow = (
            i64,
            String,
            Option<Uuid>,
            Option<chrono::DateTime<chrono::Utc>>,
        );
        let version: Option<VersionRow> = sqlx::query_as(
            "SELECT version_number::bigint, snapshot_json, published_by, published_at \
             FROM dashboard_version \
             WHERE id = $1 AND dashboard_id = $2 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(version_id)
        .bind(dashboard_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        match version {
            Some((version_number, snapshot_json, published_by, published_at)) => {
                let snapshot = serde_json::from_str(&snapshot_json)
                    .map_err(|e| AppError::internal(format!("corrupt version snapshot: {e}")))?;
                PublishedDashboard {
                    state: "published".to_string(),
                    version_id: Some(version_id),
                    version_number: Some(version_number),
                    published_at,
                    published_by,
                    snapshot: Some(snapshot),
                }
            }
            None => {
                tracing::warn!(
                    dashboard_id = %dashboard_id,
                    version_id = %version_id,
                    "dashboard's live version pointer names a missing or inactive version"
                );
                PublishedDashboard::none()
            }
        }
    } else {
        PublishedDashboard::none()
    };
    tx.commit().await.map_err(AppError::internal)?;
    Ok(published)
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct TransitionBody {
    row_version: i64,
}

#[derive(Serialize, ToSchema)]
struct TransitionResponse {
    id: Uuid,
    lifecycle_status: String,
    row_version: i64,
}

#[derive(Serialize, ToSchema)]
struct PublishResponse {
    id: Uuid,
    lifecycle_status: String,
    row_version: i64,
    /// `true` when `dashboard.publish` is in `approval.required_actions` and
    /// this call only submitted a pending four-eyes request — the fields
    /// below are `None` in that case, and the dashboard is still `approved`,
    /// not `published`, until a second admin decides the request.
    approval_pending: bool,
    approval_request_id: Option<Uuid>,
    version_id: Option<Uuid>,
    version_number: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct CloneResponse {
    id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/submit-review",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Submitted)])))),
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not in draft, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn submit_for_review(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let row_version = do_submit_for_review(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status: "review".to_string(),
        row_version,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/approve",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Approved)])))),
    // Pre-existing collision fix (unrelated to M95/D-430, applied only
    // because it broke `ng build base` for every consumer of the committed
    // `api-types.ts`): utoipa auto-derives an operation id from the function
    // name, and `decision.rs` has its own unrelated `approve` handler —
    // disambiguate explicitly, same convention `attome-events::admin` already
    // uses for `list_event_deliveries`.
    operation_id = "approve_dashboard",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not in review, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn approve(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let row_version = do_approve(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status: "approved".to_string(),
        row_version,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/reject",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Rejected)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not in review, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn reject(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let row_version = do_reject(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status: "draft".to_string(),
        row_version,
    }))
}

/// D-195: gated behind `approval.required_actions` (empty/off by default,
/// same as every other wired action_type — see `attome_audit::approval::gate`).
/// When gated, this submits an approval request instead of publishing and
/// returns `202` with `approval_pending: true` — the dashboard stays
/// `approved` until a second, different `system.admin` decides the request
/// (`attome-api`'s `approval_admin::decide_approval`, wired to
/// `do_publish_dashboard` via `ACTION_DASHBOARD_PUBLISH`).
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/publish",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Activated)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = PublishResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = PublishResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not approved, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<(StatusCode, Json<PublishResponse>), AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    // Phase 3.5: health is a gate, and approval binds the resolved definition.
    let gate = crate::publish_gate::do_publish_gate(&state, id).await?;
    if !gate.publishable() {
        return Err(gate.refusal());
    }
    let fingerprint = do_publication_fingerprint(&state.base.db, id).await?;
    let payload = serde_json::json!({
        "dashboard_id": id,
        "row_version": body.row_version,
        "publication_fingerprint": fingerprint,
    });
    if let Some(request) =
        attome_audit::approval::gate(&state, ACTION_DASHBOARD_PUBLISH, payload, ctx.user_id).await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(PublishResponse {
                id,
                lifecycle_status: "approved".to_string(),
                row_version: body.row_version,
                approval_pending: true,
                approval_request_id: Some(request.id),
                version_id: None,
                version_number: None,
            }),
        ));
    }

    let (row_version, version_id, version_number) = match do_publish_dashboard_checked(
        &state,
        id,
        body.row_version,
        ctx.user_id,
        Some(&fingerprint),
    )
    .await?
    {
        PublishOutcome::Published(row_version, version_id, version_number) => {
            (row_version, version_id, version_number)
        }
        PublishOutcome::DefinitionChanged => {
            return Err(AppError::Conflict(
                "the dashboard changed while it was being published; review and publish again",
            ));
        }
    };
    Ok((
        StatusCode::OK,
        Json(PublishResponse {
            id,
            lifecycle_status: "published".to_string(),
            row_version,
            approval_pending: false,
            approval_request_id: None,
            version_id: Some(version_id),
            version_number: Some(version_number),
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/unpublish",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not published, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn unpublish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let (row_version, lifecycle_status) =
        do_unpublish(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status,
        row_version,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/start-revision",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Working copy returned to draft; the live version is unchanged", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not published, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_revision(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let row_version = do_start_revision(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status: "draft".to_string(),
        row_version,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/archive",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::SoftDelete)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "Success", body = TransitionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Already archived, or row_version is stale", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn archive(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransitionBody>,
) -> Result<Json<TransitionResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let row_version = do_archive(&state, id, body.row_version, ctx.user_id).await?;
    Ok(Json(TransitionResponse {
        id,
        lifecycle_status: "archived".to_string(),
        row_version,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/clone",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Clone)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    responses(
        (status = 201, description = "Success", body = CloneResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn clone_dashboard(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<CloneResponse>), AppError> {
    // The route's compile-time policy covers attome_dashboard.update (on the
    // source record); creating the copy needs attome_dashboard.create too,
    // checked manually — same reason attome-service::convert checks a second
    // privilege by hand (`Authorized<P>` only composes one policy).
    ctx.require_key("attome_dashboard.create")?;
    // R-04: the clone is owned by the caller once created, so only *reading*
    // the source dashboard needs a record-level check here — not Update.
    require_dashboard_access(&state, &ctx, id, RecordAction::Read).await?;

    let new_id = do_clone(&state, id, ctx.user_id).await?;
    Ok((StatusCode::CREATED, Json(CloneResponse { id: new_id })))
}

#[derive(Serialize, ToSchema)]
struct RestoreResponse {
    id: Uuid,
    restored_from_version: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/versions/{version_id}/restore",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Restore)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path), ("version_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = RestoreResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, or the version does not belong to it", body = ErrorResponse),
        (status = 409, description = "Another request is already changing this dashboard", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn restore_version(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path((id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RestoreResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    do_restore_version(&state, id, version_id, ctx.user_id).await?;
    Ok(Json(RestoreResponse {
        id,
        restored_from_version: version_id,
    }))
}

#[derive(Serialize, ToSchema)]
struct ActivateResponse {
    id: Uuid,
    row_version: i64,
    /// `true` when `dashboard.publish` is in
    /// `approval.required_actions` and this call only submitted a pending
    /// four-eyes request; the live version is unchanged until it is decided.
    approval_pending: bool,
    approval_request_id: Option<Uuid>,
    live_version_id: Option<Uuid>,
    live_version_number: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/versions/{version_id}/activate",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Activated)])))),
    params(("id" = Uuid, Path), ("version_id" = Uuid, Path)),
    request_body = TransitionBody,
    responses(
        (status = 200, description = "The version is now live", body = ActivateResponse),
        (status = 202, description = "Four-eyes approval required — request submitted", body = ActivateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard, or the version does not belong to it", body = ErrorResponse),
        (status = 409, description = "row_version is stale, or the dashboard is busy", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn activate_version(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path((id, version_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<TransitionBody>,
) -> Result<(StatusCode, Json<ActivateResponse>), AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    let gate = crate::publish_gate::do_activate_gate(&state, id, version_id).await?;
    if !gate.publishable() {
        return Err(gate.refusal());
    }
    let payload = serde_json::json!({
        "dashboard_id": id,
        "version_id": version_id,
        "row_version": body.row_version,
    });
    if let Some(request) =
        attome_audit::approval::gate(&state, ACTION_DASHBOARD_PUBLISH, payload, ctx.user_id).await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(ActivateResponse {
                id,
                row_version: body.row_version,
                approval_pending: true,
                approval_request_id: Some(request.id),
                live_version_id: None,
                live_version_number: None,
            }),
        ));
    }
    let (row_version, version_number) =
        do_activate_version(&state, id, version_id, body.row_version, ctx.user_id).await?;
    Ok((
        StatusCode::OK,
        Json(ActivateResponse {
            id,
            row_version,
            approval_pending: false,
            approval_request_id: None,
            live_version_id: Some(version_id),
            live_version_number: Some(version_number),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/attome-dashboard/{id}/published",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "What viewers of this dashboard see", body = PublishedDashboard),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn published(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishedDashboard>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Read).await?;
    Ok(Json(do_load_published(&state.base.db, id).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/attome-dashboard/{id}/submit-review",
            post(submit_for_review),
        )
        .route(
            "/api/v1/attome-dashboard/{id}/start-revision",
            post(start_revision),
        )
        .route(
            "/api/v1/attome-dashboard/{id}/versions/{version_id}/activate",
            post(activate_version),
        )
        .route("/api/v1/attome-dashboard/{id}/published", get(published))
        .route("/api/v1/attome-dashboard/{id}/approve", post(approve))
        .route("/api/v1/attome-dashboard/{id}/reject", post(reject))
        .route("/api/v1/attome-dashboard/{id}/publish", post(publish))
        .route("/api/v1/attome-dashboard/{id}/unpublish", post(unpublish))
        .route("/api/v1/attome-dashboard/{id}/archive", post(archive))
        .route("/api/v1/attome-dashboard/{id}/clone", post(clone_dashboard))
        .route(
            "/api/v1/attome-dashboard/{id}/versions/{version_id}/restore",
            post(restore_version),
        )
}

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document; merged in by `crate::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    submit_for_review,
    approve,
    reject,
    publish,
    unpublish,
    start_revision,
    archive,
    clone_dashboard,
    restore_version,
    activate_version,
    published
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

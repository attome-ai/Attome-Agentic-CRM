//! `GET /api/v1/admin/metadata/rollout/status` — the fleet console's one
//! call per customer per poll (D-792, `document/general/FLEET-CONSOLE-DESIGN.md`
//! §5.2): what `/version`, `/health/ready`, the release-report summary and
//! the changeset ledger would answer in four calls.
//!
//! `Authorized<Privilege<MetadataRollout>>`: `system.admin` or the rollout
//! credential (`metadata.rollout`). Read-only, no audit event (a read of
//! deployment state, no record or secret).
//!
//! **Never carries record values or secrets** — versions, a readiness bit,
//! counts, ids, sequence numbers and ledger statuses only; the shape is
//! pinned by `crates/engine/attome-api/tests/rollout_privilege.rs`. The ledger
//! head is bounded: one row per (layer, scope), at most [`MAX_HEADS`].

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_security::MetadataRollout;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Most (layer, scope) ledger heads one answer carries.
const MAX_HEADS: i64 = 500;

/// The release report's open work (the fleet's notification rule reads
/// `last_report_id` and `open_items`).
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloutReleaseReport {
    /// Open items across every report.
    pub open_items: i64,
    /// Open items by kind.
    pub by_kind: BTreeMap<String, i64>,
    /// The newest ready release report (an apply run, not a single change).
    pub last_report_id: Option<Uuid>,
    /// When that report became ready.
    pub last_release_at: Option<DateTime<Utc>>,
    /// Reports still building (an apply running or stopped mid-run).
    pub building: i64,
}

/// The newest ledger row of one (layer, scope).
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct LedgerHead {
    pub layer: String,
    pub scope: String,
    pub changeset_id: Uuid,
    #[serde(rename = "ref")]
    pub changeset_ref: String,
    pub seq: i32,
    /// `expand` or `contract`.
    pub phase: String,
    /// The row's ledger status (`planned` … `succeeded`, `failed`,
    /// `adopted`).
    pub status: String,
    /// The highest `seq` of this (layer, scope) whose effects are in place
    /// (`succeeded` or `adopted`); `null` when none is.
    pub last_applied_seq: Option<i32>,
}

/// `GET /api/v1/admin/metadata/rollout/status`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloutStatus {
    /// The running binary's release version (as `/version`).
    pub application_version: String,
    /// The highest applied SQL migration (as `/version`); `null` when the
    /// migration table cannot be read.
    pub schema_version: Option<i64>,
    /// The sha256 of this deployment's canonical metadata export (as
    /// `/version`).
    pub configuration_version: String,
    /// `/health/ready` answered 200.
    pub ready: bool,
    pub release_report: RolloutReleaseReport,
    /// One row per (layer, scope), newest `seq` first within it.
    pub ledger_head: Vec<LedgerHead>,
    /// Pending `metadata.changeset_apply` approval requests (an apply waiting
    /// for a human on this server).
    pub pending_approvals: i64,
}

async fn release_report(state: &EngineState) -> Result<RolloutReleaseReport, AppError> {
    let by_kind: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, COUNT(*) FROM release_report_item \
         WHERE status = 'open' GROUP BY kind ORDER BY kind",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let building: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM release_report \
         WHERE source <> 'change' AND status = 'building'",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let last: Option<(Uuid, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, ready_at FROM release_report \
         WHERE source <> 'change' AND ready_at IS NOT NULL \
         ORDER BY ready_at DESC, id DESC LIMIT 1",
    )
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(RolloutReleaseReport {
        open_items: by_kind.iter().map(|(_, n)| n).sum(),
        by_kind: by_kind.into_iter().collect(),
        last_report_id: last.map(|(id, _)| id),
        last_release_at: last.and_then(|(_, at)| at),
        building,
    })
}

async fn ledger_head(state: &EngineState) -> Result<Vec<LedgerHead>, AppError> {
    sqlx::query_as::<_, LedgerHead>(
        "SELECT DISTINCT ON (layer, scope) \
                layer, scope, changeset_id, ref AS changeset_ref, seq, phase, status, \
                MAX(seq) FILTER (WHERE status IN ('succeeded', 'adopted')) \
                    OVER (PARTITION BY layer, scope) AS last_applied_seq \
           FROM changeset_apply \
          ORDER BY layer, scope, seq DESC, created_at DESC, id DESC \
          LIMIT $1",
    )
    .bind(MAX_HEADS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn pending_approvals(state: &EngineState) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request \
         WHERE action_type = $1 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(super::ACTION_CHANGESET_APPLY)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/rollout/status",
    tag = "admin-changesets",
    responses(
        (status = 200, description = "Versions, readiness, open release-report work, the changeset ledger head and pending apply approvals; never record values or secrets", body = RolloutStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rollout_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
) -> Result<Json<RolloutStatus>, AppError> {
    // The same answers `/version` and `/health/ready` give, from the same
    // handlers, so the console never sees two versions of one fact.
    let Json(version) = attome_server::health::version(State(state.base.clone())).await;
    let (ready_status, _) = attome_server::health::health_ready(State(state.base.clone())).await;
    let application_version = version["application_version"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let configuration_version = version["configuration_version"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| application_version.clone());
    Ok(Json(RolloutStatus {
        schema_version: version["schema_version"].as_i64(),
        application_version,
        configuration_version,
        ready: ready_status == StatusCode::OK,
        release_report: release_report(&state).await?,
        ledger_head: ledger_head(&state).await?,
        pending_approvals: pending_approvals(&state).await?,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/metadata/rollout/status", get(rollout_status))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(rollout_status))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_is_documented_with_its_shape() {
        let value = serde_json::to_value(openapi_fragment()).expect("serializes");
        let op = &value["paths"]["/api/v1/admin/metadata/rollout/status"]["get"];
        assert!(op.is_object());
        assert!(op["x-audit"].is_null(), "a read declares no audit event");
    }

    #[test]
    fn the_status_serializes_only_its_documented_keys() {
        let status = RolloutStatus {
            application_version: "1.0.0".into(),
            schema_version: Some(543),
            configuration_version: "abc".into(),
            ready: true,
            release_report: RolloutReleaseReport {
                open_items: 2,
                by_kind: BTreeMap::from([("conflict".to_owned(), 2)]),
                last_report_id: Some(Uuid::now_v7()),
                last_release_at: Some(Utc::now()),
                building: 0,
            },
            ledger_head: vec![LedgerHead {
                layer: "project".into(),
                scope: "bmd".into(),
                changeset_id: Uuid::now_v7(),
                changeset_ref: "project/bmd/0001-x".into(),
                seq: 1,
                phase: "expand".into(),
                status: "succeeded".into(),
                last_applied_seq: Some(1),
            }],
            pending_approvals: 0,
        };
        let value = serde_json::to_value(&status).expect("serializes");
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "application_version",
                "configuration_version",
                "ledger_head",
                "pending_approvals",
                "ready",
                "release_report",
                "schema_version",
            ]
        );
        let mut head: Vec<&str> = value["ledger_head"][0]
            .as_object()
            .expect("head")
            .keys()
            .map(String::as_str)
            .collect();
        head.sort_unstable();
        assert_eq!(
            head,
            [
                "changeset_id",
                "last_applied_seq",
                "layer",
                "phase",
                "ref",
                "scope",
                "seq",
                "status",
            ]
        );
    }
}

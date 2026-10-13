//! F1 sync and F3 notifications (design §6.1, §6.3).
//!
//! One sync of one deployment is three calls — anonymous `GET /version` and
//! `GET /health/ready`, then the signed `GET …/rollout/status` (falling back
//! to the release-report summary and the newest report when a customer does
//! not have that route yet) — with no retries inside a sync: the next poll is
//! the retry. The I/O runs outside any transaction; then one short
//! transaction records the observation and, in the same transaction, sends
//! the developer at most one notification per new release report with open
//! items and one per readiness change, so each is sent once
//! (`notified_report_id`; the previous `ready`).
//!
//! `FleetPoll` (the job) syncs every active deployment with bounded
//! concurrency 4, then re-arms the step of every rollout target that waits
//! on a customer (an approval or an apply in flight) and re-evaluates live
//! rollouts.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde_json::Value;
use uuid::Uuid;

use attome_core::EngineState;
use attome_types::AppError;

use crate::client::{
    CustomerClient, RemoteError, RemoteReportSummary, RemoteRolloutStatus, is_safe_query_value,
    paths,
};
use crate::core::VersionProbe;
use crate::runtime::FleetRuntime;
use crate::store::{self, DeploymentRow, ObservationRow};

/// How many customers one poll talks to at once (design §6.1).
pub const SYNC_CONCURRENCY: usize = 4;
/// Upper bound on notification recipients.
const MAX_RECIPIENTS: i64 = 50;
/// The notification preference category of every console notification.
pub const NOTIFY_CATEGORY: &str = "fleet";

/// What one probe of one customer returned.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub version: Option<VersionProbe>,
    pub ready: Option<bool>,
    pub status: Option<RemoteRolloutStatus>,
    /// The first failure, if any (stored as `error_code`).
    pub error: Option<RemoteError>,
}

fn keep_first(slot: &mut Option<RemoteError>, error: RemoteError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

/// The three calls (module doc). Never fails: every failure is recorded.
pub async fn probe(client: &CustomerClient, correlation: Option<Uuid>) -> Probe {
    let mut error = None;
    let version = match client.version().await {
        Ok(version) => Some(version),
        Err(e) => {
            keep_first(&mut error, e);
            None
        }
    };
    let ready = match client.ready().await {
        Ok(ready) => Some(ready),
        Err(e) => {
            keep_first(&mut error, e);
            // Unreachable counts as not ready for the readiness notification.
            Some(false)
        }
    };
    let status = if client.has_credential() {
        match client.rollout_status(correlation).await {
            Ok(status) => Some(status),
            Err(RemoteError::NotFound) => match fallback_status(client, correlation).await {
                Ok(status) => Some(status),
                Err(e) => {
                    keep_first(&mut error, e);
                    None
                }
            },
            Err(e) => {
                keep_first(&mut error, e);
                None
            }
        }
    } else {
        None
    };
    Probe {
        version,
        ready,
        status,
        error,
    }
}

/// A customer without `/rollout/status`: the summary plus the newest report.
async fn fallback_status(
    client: &CustomerClient,
    correlation: Option<Uuid>,
) -> Result<RemoteRolloutStatus, RemoteError> {
    let summary = client.report_summary(correlation).await?;
    let newest = client
        .get(
            &format!("{}?page=1&page_size=1", paths::REPORTS),
            correlation,
        )
        .await?;
    let last_report_id = newest["items"][0]["id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok());
    Ok(RemoteRolloutStatus {
        release_report: RemoteReportSummary {
            last_report_id,
            ..summary
        },
        ..RemoteRolloutStatus::default()
    })
}

fn clamp_i32(value: i64) -> i32 {
    value.clamp(0, i64::from(i32::MAX)) as i32
}

/// The new observation: what the probe read, and the previous value of
/// anything it could not read (a stale value beats a blank one; the error
/// code and `observed_at` say how fresh it is).
pub fn observation(
    deployment_id: Uuid,
    probe: &Probe,
    previous: Option<&ObservationRow>,
    now: DateTime<Utc>,
) -> ObservationRow {
    let prev = previous.cloned().unwrap_or_default();
    let status = probe.status.clone().unwrap_or_default();
    let report = &status.release_report;
    let read = probe.status.is_some();
    let ledger_head = match &status.ledger_head {
        Value::Null => prev.ledger_head.clone(),
        head => Some(head.clone()),
    };
    let error_code = match (&probe.error, probe.ready) {
        (Some(e), _) => Some(e.code().to_owned()),
        (None, Some(false)) => Some("not_ready".to_owned()),
        (None, _) => None,
    };
    ObservationRow {
        deployment_ref: deployment_id,
        application_version: probe
            .version
            .as_ref()
            .map(|v| v.application_version.clone())
            .or(status.application_version.clone())
            .or(prev.application_version),
        git_revision: probe
            .version
            .as_ref()
            .map(|v| v.git_revision.clone())
            .or(prev.git_revision),
        schema_version: probe
            .version
            .as_ref()
            .and_then(|v| v.schema_version)
            .or(status.schema_version)
            .or(prev.schema_version),
        schema_dirty: probe
            .version
            .as_ref()
            .and_then(|v| v.schema_dirty)
            .or(prev.schema_dirty),
        configuration_version: probe
            .version
            .as_ref()
            .map(|v| v.configuration_version.clone())
            .or(status.configuration_version.clone())
            .or(prev.configuration_version),
        ready: probe.ready.or(status.ready).or(prev.ready),
        open_items: if read {
            report.open_items.map(clamp_i32)
        } else {
            prev.open_items
        },
        last_report_id: if read {
            report.last_report_id.or(prev.last_report_id)
        } else {
            prev.last_report_id
        },
        last_release_at: if read {
            report.last_release_at.or(prev.last_release_at)
        } else {
            prev.last_release_at
        },
        ledger_head,
        pending_approvals: if read {
            status.pending_approvals.map(clamp_i32)
        } else {
            prev.pending_approvals
        },
        error_code,
        observed_at: now,
        notified_report_id: prev.notified_report_id,
    }
}

/// F3 rule 1: notify once per new report that has open items.
pub fn report_to_notify(
    notified: Option<Uuid>,
    last_report_id: Option<Uuid>,
    open_items: Option<i32>,
) -> Option<Uuid> {
    let report = last_report_id?;
    (Some(report) != notified && open_items.unwrap_or(0) > 0).then_some(report)
}

/// F3 rule 2: a readiness change worth one notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessChange {
    WentDown,
    Recovered,
}

pub fn readiness_change(previous: Option<bool>, now: Option<bool>) -> Option<ReadinessChange> {
    match (previous, now) {
        (Some(true), Some(false)) => Some(ReadinessChange::WentDown),
        (Some(false), Some(true)) => Some(ReadinessChange::Recovered),
        _ => None,
    }
}

/// Who console notifications go to: `fleet.notify_user_refs`, or every
/// active `system.admin` holder of the developer's database.
async fn recipients(
    conn: &mut sqlx::PgConnection,
    state: &EngineState,
) -> Result<Vec<Uuid>, AppError> {
    let configured = &state.base.config.fleet.notify_user_refs;
    if !configured.is_empty() {
        return Ok(configured.clone());
    }
    sqlx::query_scalar(
        "SELECT u.id FROM user_account u \
         WHERE u.is_active = true AND ( \
             EXISTS (SELECT 1 FROM user_account_mm_privilege up \
                     JOIN privilege p ON p.id = up.privilege_ref \
                     WHERE up.user_ref = u.id AND up.is_active = true \
                       AND p.is_active = true AND p.key = $1) \
          OR EXISTS (SELECT 1 FROM user_account_mm_role ur \
                     JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
                     JOIN privilege p ON p.id = rp.privilege_ref \
                     WHERE ur.user_ref = u.id AND ur.is_deleted = false \
                       AND rp.is_deleted = false AND p.is_active = true AND p.key = $1)) \
         ORDER BY u.id LIMIT $2",
    )
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .bind(MAX_RECIPIENTS)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// One in-app notification per recipient, inside the caller's transaction.
async fn notify(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    deployment: &DeploymentRow,
    subject: String,
    body: String,
) -> Result<(), AppError> {
    for user in recipients(tx, state).await? {
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_string()]),
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(format!("/xrm/fleet/deployments/{}", deployment.id)),
            variables: HashMap::new(),
            priority: "normal".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            tx,
            &state.base.config.notification,
            request,
            Some(NOTIFY_CATEGORY),
        )
        .await?;
    }
    Ok(())
}

/// Records one probe: the observation and its notifications, one short
/// transaction. A second sync of the same deployment running at the same
/// moment loses the advisory lock and records nothing (the winner's
/// observation is as fresh).
pub async fn record(
    state: &EngineState,
    deployment: &DeploymentRow,
    probe: &Probe,
) -> Result<ObservationRow, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let key = format!("attome-fleet/sync:{}", deployment.id);
    if !crate::try_lock(&mut tx, &key).await? {
        let previous = store::observation_for_update(&mut tx, deployment.id).await?;
        attome_db::tx::commit(tx).await?;
        return Ok(previous.unwrap_or_else(|| observation(deployment.id, probe, None, Utc::now())));
    }
    let previous = store::observation_for_update(&mut tx, deployment.id).await?;
    let mut row = observation(deployment.id, probe, previous.as_ref(), Utc::now());
    if let Some(report) =
        report_to_notify(row.notified_report_id, row.last_report_id, row.open_items)
    {
        let open = row.open_items.unwrap_or(0);
        notify(
            &mut tx,
            state,
            deployment,
            format!(
                "{}: release report with {open} open item(s)",
                deployment.label
            ),
            format!(
                "{} ({} {}) has a new release report with {open} open item(s). Open the \
                 fleet console's release reports to decide them.",
                deployment.label, deployment.project_code, deployment.environment
            ),
        )
        .await?;
        row.notified_report_id = Some(report);
    }
    match readiness_change(previous.as_ref().and_then(|p| p.ready), row.ready) {
        Some(ReadinessChange::WentDown) => {
            notify(
                &mut tx,
                state,
                deployment,
                format!("{} is not ready", deployment.label),
                format!(
                    "{} ({} {}) stopped answering ready ({}).",
                    deployment.label,
                    deployment.project_code,
                    deployment.environment,
                    row.error_code.as_deref().unwrap_or("not_ready")
                ),
            )
            .await?
        }
        Some(ReadinessChange::Recovered) => {
            notify(
                &mut tx,
                state,
                deployment,
                format!("{} is ready again", deployment.label),
                format!(
                    "{} ({} {}) answers ready again.",
                    deployment.label, deployment.project_code, deployment.environment
                ),
            )
            .await?
        }
        None => {}
    }
    store::upsert_observation(&mut tx, &row).await?;
    attome_db::tx::commit(tx).await?;
    Ok(row)
}

/// Probe + record for one deployment.
pub async fn sync_one(
    state: &EngineState,
    runtime: &FleetRuntime,
    deployment: &DeploymentRow,
    correlation: Option<Uuid>,
) -> Result<(ObservationRow, Probe), AppError> {
    let client = runtime.customer(&state.base.db, deployment).await?;
    let probe = probe(&client, correlation).await;
    let row = record(state, deployment, &probe).await?;
    Ok((row, probe))
}

/// What one `FleetPoll` run did.
#[derive(Debug, Clone, Default)]
pub struct PollSummary {
    pub synced: usize,
    pub failed: usize,
    pub steps_rearmed: usize,
    pub rollouts_evaluated: usize,
}

/// One deployment's sync outcome in a poll.
type SyncResult = (Uuid, Result<(ObservationRow, Probe), AppError>);

/// The `FleetPoll` job body (gate re-checked: fails closed when off).
pub async fn run(state: &EngineState) -> Result<PollSummary, AppError> {
    crate::gate::require_open(&state.base.config)?;
    let runtime = FleetRuntime::from_config(&state.base.config)?;
    let deployments = store::active_deployments(&state.base.db).await?;
    let mut summary = PollSummary::default();

    let results: Vec<SyncResult> =
        // Owned rows: a stream of borrowed rows makes the job future fail the
        // higher-ranked `Send` bound the apalis worker needs.
        futures_util::stream::iter(deployments)
            .map(|deployment| {
                let runtime = &runtime;
                async move {
                    (
                        deployment.id,
                        sync_one(state, runtime, &deployment, None).await,
                    )
                }
            })
            .buffer_unordered(SYNC_CONCURRENCY)
            .collect()
            .await;
    for (deployment_id, result) in results {
        match result {
            Ok(_) => summary.synced += 1,
            Err(e) => {
                summary.failed += 1;
                tracing::warn!(%deployment_id, error = %e, "fleet poll: recording a sync failed");
            }
        }
    }

    for target_id in store::waiting_target_ids(&state.base.db).await? {
        if crate::publish::enqueue_step(&state.base.db, target_id).await? {
            summary.steps_rearmed += 1;
        }
    }
    for rollout_id in store::live_rollout_ids(&state.base.db).await? {
        crate::publish::evaluate(state, rollout_id).await?;
        summary.rollouts_evaluated += 1;
    }
    Ok(summary)
}

/// The query used to page a customer's release reports from the console.
pub fn reports_query(page: i64, page_size: i64, status: Option<&str>) -> Option<String> {
    let mut query = format!("{}?page={page}&page_size={page_size}", paths::REPORTS);
    if let Some(status) = status {
        if !is_safe_query_value(status) {
            return None;
        }
        query.push_str(&format!("&status={status}"));
    }
    Some(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn version(app: &str) -> VersionProbe {
        VersionProbe {
            application_version: app.into(),
            git_revision: "abc".into(),
            schema_version: Some(543),
            schema_dirty: Some(false),
            configuration_version: "sha256:cfg".into(),
            components: BTreeMap::new(),
        }
    }

    #[test]
    fn a_new_report_with_open_items_is_notified_once() {
        let report = Uuid::now_v7();
        assert_eq!(report_to_notify(None, Some(report), Some(2)), Some(report));
        assert_eq!(report_to_notify(Some(report), Some(report), Some(2)), None);
        assert_eq!(report_to_notify(None, Some(report), Some(0)), None);
        assert_eq!(report_to_notify(None, None, Some(5)), None);
        let newer = Uuid::now_v7();
        assert_eq!(
            report_to_notify(Some(report), Some(newer), Some(1)),
            Some(newer)
        );
    }

    #[test]
    fn only_a_readiness_flip_is_a_change() {
        assert_eq!(
            readiness_change(Some(true), Some(false)),
            Some(ReadinessChange::WentDown)
        );
        assert_eq!(
            readiness_change(Some(false), Some(true)),
            Some(ReadinessChange::Recovered)
        );
        assert_eq!(readiness_change(None, Some(false)), None);
        assert_eq!(readiness_change(Some(true), Some(true)), None);
    }

    #[test]
    fn a_full_probe_fills_the_observation() {
        let id = Uuid::now_v7();
        let report = Uuid::now_v7();
        let probe = Probe {
            version: Some(version("4.0.1")),
            ready: Some(true),
            status: Some(RemoteRolloutStatus {
                release_report: RemoteReportSummary {
                    open_items: Some(3),
                    last_report_id: Some(report),
                    last_release_at: None,
                },
                ledger_head: serde_json::json!([{"layer": "platform", "seq": 9}]),
                pending_approvals: Some(1),
                ..RemoteRolloutStatus::default()
            }),
            error: None,
        };
        let row = observation(id, &probe, None, Utc::now());
        assert_eq!(row.application_version.as_deref(), Some("4.0.1"));
        assert_eq!(row.schema_version, Some(543));
        assert_eq!(row.open_items, Some(3));
        assert_eq!(row.last_report_id, Some(report));
        assert_eq!(row.pending_approvals, Some(1));
        assert_eq!(row.error_code, None);
        assert_eq!(row.ready, Some(true));
    }

    #[test]
    fn a_failed_probe_keeps_the_last_known_values_and_names_the_failure() {
        let id = Uuid::now_v7();
        let previous = ObservationRow {
            deployment_ref: id,
            application_version: Some("4.0.0".into()),
            open_items: Some(2),
            last_report_id: Some(Uuid::now_v7()),
            notified_report_id: Some(Uuid::now_v7()),
            ready: Some(true),
            ..ObservationRow::default()
        };
        let probe = Probe {
            ready: Some(false),
            error: Some(RemoteError::Timeout),
            ..Probe::default()
        };
        let row = observation(id, &probe, Some(&previous), Utc::now());
        assert_eq!(row.application_version.as_deref(), Some("4.0.0"));
        assert_eq!(row.open_items, Some(2));
        assert_eq!(row.last_report_id, previous.last_report_id);
        assert_eq!(row.notified_report_id, previous.notified_report_id);
        assert_eq!(row.error_code.as_deref(), Some("timeout"));
        assert_eq!(row.ready, Some(false));
    }

    #[test]
    fn report_queries_take_only_plain_tokens() {
        assert_eq!(
            reports_query(2, 20, Some("ready")).as_deref(),
            Some("/api/v1/admin/metadata/release-reports?page=2&page_size=20&status=ready")
        );
        assert_eq!(reports_query(1, 20, Some("a&b")), None);
    }
}

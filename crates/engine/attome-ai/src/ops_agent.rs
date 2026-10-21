//! The operations agent (roadmap AK2-T1): one report of how the deployment
//! is running, the routine actions it calls for, and a weekly digest of both
//! to the administrators.
//!
//! - **`ops.report`** (Read, administrators): the nodes and the version each
//!   runs (the metrics store's `attome_node_up` samples, as
//!   `GET /api/v1/admin/ops/nodes` reads them); the services this node
//!   depends on (`system.status`'s reading); the backups (`backup.dir`: the
//!   newest `attome-YYYYMMDD-HHMM.dump` archive, how many and their size, and
//!   the last restore drill in `drills.jsonl`, the names the app's backup job
//!   writes); the database's and the backups' size; each SLO class's status;
//!   and the proposed actions ([`proposals`]). It changes nothing.
//! - **Proposals** are pure rules over the report: no backup in 26 hours,
//!   backups off, no passing restore drill in 35 days, a service down,
//!   writes paused, a node not seen for three minutes, nodes on different
//!   versions, an SLO class over its error budget. Each names the command or
//!   setting that fixes it; the agent proposes, a person runs it.
//! - **Weekly digest** ([`weekly`], job [`WEEKLY_JOB`], checked hourly): on
//!   Monday from 06:00 UTC, the report and its proposals go to every
//!   administrator as an in-app and email notification
//!   (`attome_notification::dispatch::alert_admins`), once a week: the
//!   marker `attome-ai:ops_digest:done:{iso week}` (kept 8 days) stops a
//!   second send, and a lost marker only sends the week's digest again.
//!
//! Certificates are not in the report: the server holds none it could read
//! the expiry of while TLS ends at the proxy. Free disk space is not either,
//! since reading it needs a native call per platform; the sizes are.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc, Weekday};
use serde::Serialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_REPORT: &str = "ops.report";
/// The registered job that sends the weekly digest.
pub const WEEKLY_JOB: &str = "ai_ops_weekly_digest";
/// The hour (UTC) on Monday from which the digest goes.
pub const DIGEST_HOUR: u32 = 6;
/// A backup older than this is reported.
pub const BACKUP_MAX_AGE_HOURS: i64 = 26;
/// A restore drill older than this is reported.
pub const DRILL_MAX_AGE_DAYS: i64 = 35;
/// Where the admin console shows the operations screens.
const OPS_ROUTE: &str = "/admin/ops";
/// The backup job's archive names (`attome::backup::archive_name`).
const ARCHIVE_PREFIX: &str = "attome-";
const ARCHIVE_SUFFIX: &str = ".dump";
/// The backup job's drill log (`attome::backup::DRILLS_FILE`).
const DRILLS_FILE: &str = "drills.jsonl";

/// One node as the metrics store last saw it.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
pub struct NodeRow {
    pub node: Option<String>,
    pub version: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub healthy: Option<bool>,
}

/// The backups in `backup.dir`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Backups {
    pub enabled: bool,
    pub archives: usize,
    pub bytes: u64,
    /// The newest archive's time, from its name.
    pub newest_at: Option<DateTime<Utc>>,
    pub last_drill_at: Option<DateTime<Utc>>,
    pub last_drill_passed: Option<bool>,
    /// Why the folder could not be read, if it could not.
    pub unreadable: Option<String>,
}

/// One SLO class.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SloRow {
    pub id: String,
    pub status: String,
}

/// Everything the report holds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpsReport {
    pub at: DateTime<Utc>,
    pub version: String,
    pub nodes: Vec<NodeRow>,
    /// `system.status`'s reading on this node.
    pub services: Value,
    pub backups: Backups,
    pub database_bytes: Option<i64>,
    pub slo: Vec<SloRow>,
}

/// One routine action the report calls for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    /// `high` or `normal`.
    pub severity: &'static str,
    pub text: String,
}

/// The archive's time from its name (`attome-YYYYMMDD-HHMM.dump`). Pure.
pub fn archive_time(name: &str) -> Option<DateTime<Utc>> {
    let stamp = name.strip_prefix(ARCHIVE_PREFIX)?.strip_suffix(ARCHIVE_SUFFIX)?;
    NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M")
        .ok()
        .map(|t| t.and_utc())
}

/// The last drill's time and result from the drill log's text. Pure.
pub fn last_drill(log: &str) -> Option<(DateTime<Utc>, bool)> {
    let line = log.lines().rev().find(|l| !l.trim().is_empty())?;
    let row: Value = serde_json::from_str(line).ok()?;
    let at = row["at"].as_str()?.parse::<DateTime<Utc>>().ok()?;
    Some((at, row["passed"].as_bool() == Some(true)))
}

/// Reads the backup folder. Blocking: call it on a blocking thread.
fn read_backups(dir: &std::path::Path, enabled: bool) -> Backups {
    let mut out = Backups {
        enabled,
        ..Backups::default()
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            out.unreadable = Some(error.kind().to_string());
            return out;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(at) = archive_time(&name) else {
            continue;
        };
        out.archives += 1;
        out.bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        if out.newest_at.is_none_or(|newest| at > newest) {
            out.newest_at = Some(at);
        }
    }
    if let Ok(log) = std::fs::read_to_string(dir.join(DRILLS_FILE))
        && let Some((at, passed)) = last_drill(&log)
    {
        out.last_drill_at = Some(at);
        out.last_drill_passed = Some(passed);
    }
    out
}

/// Builds the report from this node's readings.
pub async fn gather(state: &EngineState) -> Result<OpsReport, AppError> {
    let db = &state.base.db;
    let nodes: Vec<NodeRow> = sqlx::query_as(
        "SELECT labels->>'node' AS node, \
                (array_agg(labels->>'version' ORDER BY ts DESC))[1] AS version, \
                max(ts) AS last_seen, \
                max(ts) > now() - interval '3 minutes' AS healthy \
         FROM ops_metric_sample \
         WHERE name = $1 AND ts > now() - interval '1 day' AND labels ? 'node' \
         GROUP BY 1 ORDER BY 1",
    )
    .bind(attome_server::metrics_store::NODE_UP)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let database_bytes: Option<i64> =
        sqlx::query_scalar("SELECT pg_database_size(current_database())")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let backup = &state.base.config.backup;
    let (dir, enabled) = (backup.resolved_dir(), backup.enabled);
    let backups = tokio::task::spawn_blocking(move || read_backups(&dir, enabled))
        .await
        .map_err(AppError::internal)?;
    let mut slo = Vec::new();
    for class in &attome_server::slo::catalogue().classes {
        let budget = attome_server::slo::budget(db, class)
            .await
            .map_err(AppError::internal)?;
        slo.push(SloRow {
            id: class.id.clone(),
            status: budget
                .as_ref()
                .map_or("unmeasured", attome_server::slo::status)
                .to_owned(),
        });
    }
    let services = crate::actions::system_status::status_body(
        &state.base.capabilities,
        state
            .base
            .audit_ingest_backlog_exceeded
            .load(Ordering::Relaxed)
            || attome_server::read_only::current(&state.base.read_only).is_some(),
        state.base.metadata_lagging.load(Ordering::Relaxed),
    );
    Ok(OpsReport {
        at: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        nodes,
        services,
        backups,
        database_bytes,
        slo,
    })
}

fn proposal(severity: &'static str, text: String) -> Proposal {
    Proposal { severity, text }
}

/// The routine actions the report calls for, most urgent first. Pure.
pub fn proposals(report: &OpsReport) -> Vec<Proposal> {
    let now = report.at;
    let mut out = Vec::new();
    let b = &report.backups;
    if !b.enabled {
        out.push(proposal(
            "high",
            "The daily backup is off: set backup.enabled to true, or make sure another backup \
             covers this database."
                .into(),
        ));
    } else if let Some(reason) = &b.unreadable {
        out.push(proposal(
            "high",
            format!(
                "The backup folder cannot be read ({reason}): check backup.dir and its \
                 permissions."
            ),
        ));
    } else {
        match b.newest_at {
            None => out.push(proposal(
                "high",
                "There is no backup yet: run `attome backup now`.".into(),
            )),
            Some(at) if (now - at).num_hours() > BACKUP_MAX_AGE_HOURS => out.push(proposal(
                "high",
                format!(
                    "The newest backup is {} hours old: check the backup job's log and pg_dump, \
                     then run `attome backup now`.",
                    (now - at).num_hours()
                ),
            )),
            Some(_) => {}
        }
    }
    let services = report.services["services"].as_array();
    for service in services.into_iter().flatten() {
        if service["state"] == "down" {
            out.push(proposal(
                "high",
                format!(
                    "{} is down on this node: see /health/dependencies.",
                    service["service"].as_str().unwrap_or("A service")
                ),
            ));
        }
    }
    if report.services["writes_paused"] == true {
        out.push(proposal(
            "high",
            "Writes are paused (audit backlog or read-only mode): check the audit chainer and \
             the read-only switch."
                .into(),
        ));
    }
    for node in &report.nodes {
        if node.healthy != Some(true) {
            out.push(proposal(
                "high",
                format!(
                    "Node {} has not reported for over three minutes: check that it is running.",
                    node.node.as_deref().unwrap_or("(unnamed)")
                ),
            ));
        }
    }
    let mut versions: Vec<&str> = report
        .nodes
        .iter()
        .filter(|n| n.healthy == Some(true))
        .filter_map(|n| n.version.as_deref())
        .collect();
    versions.sort_unstable();
    versions.dedup();
    if versions.len() > 1 {
        out.push(proposal(
            "normal",
            format!(
                "Nodes run different versions ({}): finish the upgrade so every node runs \
                 the same one.",
                versions.join(", ")
            ),
        ));
    }
    for class in &report.slo {
        if class.status == "exhausted" {
            out.push(proposal(
                "normal",
                format!(
                    "SLO class {} is over its 30-day error budget: see the operations dashboards.",
                    class.id
                ),
            ));
        }
    }
    if b.enabled && b.unreadable.is_none() && b.newest_at.is_some() {
        let drilled = b
            .last_drill_at
            .filter(|_| b.last_drill_passed == Some(true))
            .is_some_and(|at| (now - at).num_days() <= DRILL_MAX_AGE_DAYS);
        if !drilled {
            out.push(proposal(
                "normal",
                "No restore drill has passed in the last 35 days: run `attome backup drill`."
                    .into(),
            ));
        }
    }
    out.sort_by_key(|p| p.severity != "high");
    out
}

fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_048_576.0)
}

/// The digest's subject and text. Pure.
pub fn digest(report: &OpsReport, proposed: &[Proposal]) -> (String, String) {
    let subject = if proposed.is_empty() {
        "Weekly operations digest: nothing needs doing".to_owned()
    } else {
        format!(
            "Weekly operations digest: {} thing{} to do",
            proposed.len(),
            if proposed.len() == 1 { "" } else { "s" }
        )
    };
    let mut body = String::new();
    if proposed.is_empty() {
        body.push_str("Nothing needs doing this week.\n");
    } else {
        body.push_str("Proposed actions:\n");
        for p in proposed {
            let mark = if p.severity == "high" { "[urgent] " } else { "" };
            body.push_str(&format!("- {mark}{}\n", p.text));
        }
    }
    body.push_str(&format!(
        "\nVersion {}; {} node(s) seen in the last day.\n",
        report.version,
        report.nodes.len()
    ));
    let b = &report.backups;
    match b.newest_at {
        Some(at) => body.push_str(&format!(
            "Backups: {} archive(s), {}, newest {}.\n",
            b.archives,
            megabytes(b.bytes),
            at.format("%Y-%m-%d %H:%M UTC")
        )),
        None => body.push_str("Backups: none found.\n"),
    }
    if let Some(at) = b.last_drill_at {
        body.push_str(&format!(
            "Last restore drill: {} ({}).\n",
            at.format("%Y-%m-%d"),
            if b.last_drill_passed == Some(true) {
                "passed"
            } else {
                "failed"
            }
        ));
    }
    if let Some(bytes) = report.database_bytes {
        body.push_str(&format!(
            "Database size: {}.\n",
            megabytes(u64::try_from(bytes).unwrap_or(0))
        ));
    }
    (subject, body)
}

/// Whether the digest is due at `now`: Monday from [`DIGEST_HOUR`] UTC.
/// Pure.
pub fn digest_due(now: DateTime<Utc>) -> bool {
    now.weekday() == Weekday::Mon && now.hour() >= DIGEST_HOUR
}

fn done_key(now: DateTime<Utc>) -> String {
    let week = now.iso_week();
    format!("attome-ai:ops_digest:done:{}-W{:02}", week.year(), week.week())
}

/// The weekly run (job [`WEEKLY_JOB`], hourly): sends the digest once a
/// week. `Some(proposals)` when it sent one.
pub async fn weekly(state: &EngineState, now: DateTime<Utc>) -> Result<Option<usize>, AppError> {
    if !digest_due(now) {
        return Ok(None);
    }
    let key = done_key(now);
    match state.base.redis.get(&key).await {
        Ok(Some(_)) => return Ok(None),
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "ops digest: marker unavailable; sending"),
    }
    let report = gather(state).await?;
    let proposed = proposals(&report);
    let (subject, body) = digest(&report, &proposed);
    attome_notification::dispatch::alert_admins(
        &state.base.db,
        &state.base.config.notification,
        subject,
        body,
        OPS_ROUTE,
    )
    .await;
    if let Err(error) = state
        .base
        .redis
        .set(&key, "1".to_owned(), Some(Duration::from_secs(8 * 24 * 3600)))
        .await
    {
        tracing::warn!(%error, "ops digest: marker not stored");
    }
    tracing::info!(proposals = proposed.len(), "ops digest sent");
    Ok(Some(proposed.len()))
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            OPS_REPORT,
            "Report how the deployment is running: nodes and their versions, the services \
             this node depends on, backups and the last restore drill, database and backup \
             sizes, SLO status, and the routine actions they call for.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &["system.admin"],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(OpsReportAction)]
}

struct OpsReportAction;

impl Action for OpsReportAction {
    fn id(&self) -> ActionId {
        ActionId(OPS_REPORT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let report = gather(state).await?;
            let proposed = proposals(&report);
            Ok(ActionResult::plain(json!({
                "report": report,
                "proposals": proposed,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn node(name: &str, version: &str, healthy: bool) -> NodeRow {
        NodeRow {
            node: Some(name.to_owned()),
            version: Some(version.to_owned()),
            last_seen: Some(at(19, 9)),
            healthy: Some(healthy),
        }
    }

    fn healthy_report() -> OpsReport {
        OpsReport {
            at: at(19, 9),
            version: "0.1.0".into(),
            nodes: vec![node("a", "0.1.0", true)],
            services: json!({
                "degraded": [],
                "services": [{ "service": "object_storage", "state": "up" }],
                "writes_paused": false,
                "metadata_lagging": false,
            }),
            backups: Backups {
                enabled: true,
                archives: 7,
                bytes: 7 * 1_048_576,
                newest_at: Some(at(19, 2)),
                last_drill_at: Some(at(5, 3)),
                last_drill_passed: Some(true),
                unreadable: None,
            },
            database_bytes: Some(50 * 1_048_576),
            slo: vec![SloRow {
                id: "S1".into(),
                status: "ok".into(),
            }],
        }
    }

    #[test]
    fn ops_agent_a_healthy_deployment_needs_nothing() {
        assert!(proposals(&healthy_report()).is_empty());
        let (subject, body) = digest(&healthy_report(), &[]);
        assert!(subject.contains("nothing needs doing"));
        assert!(body.contains("7 archive(s)"));
        assert!(body.contains("Last restore drill: 2026-10-05 (passed)"));
    }

    #[test]
    fn ops_agent_proposes_backup_fixes() {
        let mut report = healthy_report();
        report.backups.newest_at = Some(at(17, 2));
        let p = proposals(&report);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].severity, "high");
        assert!(p[0].text.contains("55 hours old"), "{}", p[0].text);

        report.backups.newest_at = None;
        assert!(proposals(&report)[0].text.contains("attome backup now"));

        report.backups.enabled = false;
        assert!(proposals(&report)[0].text.contains("backup.enabled"));
    }

    #[test]
    fn ops_agent_proposes_a_drill_when_none_passed_recently() {
        let mut report = healthy_report();
        report.backups.last_drill_passed = Some(false);
        let p = proposals(&report);
        assert!(p.iter().any(|p| p.text.contains("attome backup drill")));
        report.backups.last_drill_passed = Some(true);
        report.backups.last_drill_at = Some(at(1, 3) - chrono::Duration::days(30));
        let p = proposals(&report);
        assert!(p.iter().any(|p| p.text.contains("restore drill")));
    }

    #[test]
    fn ops_agent_reports_services_nodes_versions_and_slo() {
        let mut report = healthy_report();
        report.services["services"] = json!([{ "service": "email", "state": "down" }]);
        report.services["writes_paused"] = json!(true);
        report.nodes = vec![
            node("a", "0.1.0", true),
            node("b", "0.2.0", true),
            node("c", "0.2.0", false),
        ];
        report.slo[0].status = "exhausted".into();
        let p = proposals(&report);
        let text: Vec<&str> = p.iter().map(|p| p.text.as_str()).collect();
        assert!(text.iter().any(|t| t.starts_with("email is down")));
        assert!(text.iter().any(|t| t.starts_with("Writes are paused")));
        assert!(text.iter().any(|t| t.starts_with("Node c has not")));
        assert!(text.iter().any(|t| t.contains("(0.1.0, 0.2.0)")));
        assert!(text.iter().any(|t| t.contains("SLO class S1")));
        let first_normal = p
            .iter()
            .position(|p| p.severity == "normal")
            .unwrap_or(p.len());
        assert!(
            p[first_normal..].iter().all(|p| p.severity == "normal"),
            "urgent first"
        );
        let (subject, body) = digest(&report, &p);
        assert!(subject.contains(&format!("{} things to do", p.len())));
        assert!(body.contains("[urgent] email is down"));
    }

    #[test]
    fn ops_agent_reads_backup_names_and_the_drill_log() {
        assert_eq!(archive_time("attome-20261019-0200.dump"), Some(at(19, 2)));
        assert_eq!(archive_time("attome-20261019-0200.files.json"), None);
        assert_eq!(archive_time("other.dump"), None);
        let log = concat!(
            r#"{"at":"2026-10-01T03:00:00Z","archive":"a","seconds":4,"passed":false}"#,
            "\n",
            r#"{"at":"2026-10-05T03:00:00Z","archive":"b","seconds":4,"passed":true}"#,
            "\n",
        );
        assert_eq!(last_drill(log), Some((at(5, 3), true)));
        assert_eq!(last_drill(""), None);
    }

    #[test]
    fn ops_agent_digest_goes_on_monday_morning_once_a_week() {
        // 2026-10-19 is a Monday.
        assert!(!digest_due(at(19, 5)));
        assert!(digest_due(at(19, 6)));
        assert!(digest_due(at(19, 23)));
        assert!(!digest_due(at(20, 9)));
        assert_eq!(done_key(at(19, 6)), done_key(at(19, 23)));
        assert_ne!(done_key(at(19, 6)), done_key(at(26, 6)));
    }

    #[test]
    fn ops_agent_report_is_for_administrators_and_reads_only() {
        let d = &descriptors()[0];
        assert_eq!(d.required_privileges, &["system.admin"]);
        assert!(matches!(d.risk, RiskTier::Read));
        assert_eq!(d.effect, Effect::Read);
    }

    #[test]
    fn ops_agent_definition_reads_only() {
        let bundle: Value = serde_json::from_str(include_str!(
            "../../../../platform-bundles/attome-ai-ops-agent.json"
        ))
        .unwrap_or_default();
        let rows = |entity: &str| -> Vec<Value> {
            bundle["record_sets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|rs| rs["entity"] == entity)
                .flat_map(|rs| rs["rows"].as_array().cloned().unwrap_or_default())
                .collect()
        };
        let policy = rows("ai_agent_policy")
            .into_iter()
            .find(|p| p["name"] == "Operations")
            .unwrap_or_default();
        assert_eq!(policy["risk_ceiling"], "read");
        let allowed = policy["allowed_action_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(allowed.iter().any(|a| a == OPS_REPORT));
        let registry = crate::registry::ActionRegistry::new();
        for id in &allowed {
            let id = id.as_str().unwrap_or_default();
            let d = registry.resolve(id);
            assert!(
                d.is_some_and(|d| d.risk == RiskTier::Read),
                "{id} is not a read"
            );
        }
        let agent = rows("ai_agent")
            .into_iter()
            .find(|a| a["name"] == "ops_agent")
            .unwrap_or_default();
        assert_eq!(agent["policy_ref"]["key"]["name"], "Operations");
    }
}

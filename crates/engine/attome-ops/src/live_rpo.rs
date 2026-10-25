//! AB3-T2: the live recovery point: how much data a disaster now would
//! lose, measured every minute from three sources.
//!
//! - `wal_archive`: seconds since PostgreSQL last archived a WAL segment
//!   (`pg_stat_archiver`); `off` when `archive_mode` is off or nothing was
//!   ever archived.
//! - `standby`: seconds the read replica is behind
//!   (`pg_last_xact_replay_timestamp()` on the read pool); `off` when the read
//!   pool is the primary (a single server).
//! - `backup`: the age of the newest backup archive in `backup.dir` (v2 backs
//!   up with `pg_dump` into a folder, not to a bucket, so the folder is read,
//!   one directory listing, no file contents).
//!
//! Each is judged against this profile's recovery target (AB3-T1): the
//! `node_loss` RPO for the standby, the `corruption` RPO for the archive
//! and the backup. The latest values live in process memory (observational,
//! rebuilt every minute; each node measures its own) and in the gauge
//! `ops_live_rpo_seconds{source}`. `GET /api/v1/ops/rpo` (`ops.read`)
//! answers them. The `ops_live_rpo` job notifies `ops.read` holders when a
//! source turns `over`, once per transition, never every minute while it
//! stays over.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

use crate::upgrades::OpsRead;

/// The registered one-minute job.
pub const JOB: &str = "ops_live_rpo";

/// The gauge each source's value goes to.
pub const GAUGE: &str = "ops_live_rpo_seconds";

/// How old the remembered values may be before the route measures afresh.
const REUSE: Duration = Duration::from_secs(120);

static LATEST: LazyLock<Mutex<Option<(Instant, Vec<RpoSource>)>>> =
    LazyLock::new(|| Mutex::new(None));

static OVER: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// One source's live recovery point.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct RpoSource {
    /// `wal_archive`, `standby` or `backup`.
    pub source: String,
    pub value_seconds: Option<f64>,
    /// This profile's target for it.
    pub target_seconds: Option<i64>,
    /// `ok`, `over` or `off`.
    pub status: String,
}

/// A source's status. Pure.
pub fn status_of(value: Option<f64>, target: Option<i64>) -> &'static str {
    match (value, target) {
        (None, _) => "off",
        (Some(v), Some(t)) if v > t as f64 => "over",
        _ => "ok",
    }
}

/// The sources that newly turned over, given the ones over before;
/// updates `over_before`. Pure.
pub fn newly_over(sources: &[RpoSource], over_before: &mut HashSet<String>) -> Vec<String> {
    let now: HashSet<String> = sources
        .iter()
        .filter(|s| s.status == "over")
        .map(|s| s.source.clone())
        .collect();
    let mut fresh: Vec<String> = now.difference(over_before).cloned().collect();
    fresh.sort();
    *over_before = now;
    fresh
}

/// The newest backup archive's age in `dir` (names `attome-*.dump`).
fn newest_backup_age(dir: &Path) -> Option<f64> {
    let newest: SystemTime = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("attome-") && name.ends_with(".dump")
        })
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()?;
    SystemTime::now()
        .duration_since(newest)
        .ok()
        .map(|d| d.as_secs_f64())
}

/// Measures every source now.
pub async fn measure(state: &EngineState) -> Result<Vec<RpoSource>, AppError> {
    let db = &state.base.db;
    let archive_on: bool = sqlx::query_scalar("SELECT current_setting('archive_mode') <> 'off'")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let wal: Option<f64> = if archive_on {
        sqlx::query_scalar(
            "SELECT extract(epoch FROM now() - last_archived_time)::float8 FROM pg_stat_archiver",
        )
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?
    } else {
        None
    };
    let standby: Option<f64> = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - pg_last_xact_replay_timestamp())::float8",
    )
    .fetch_one(&state.base.db_readonly)
    .await
    .map_err(AppError::internal)?;
    let dir = state.base.config.backup.resolved_dir();
    let backup = tokio::task::spawn_blocking(move || newest_backup_age(&dir))
        .await
        .map_err(AppError::internal)?;

    let targets: HashMap<String, i64> = sqlx::query_as::<_, (String, i32)>(
        "SELECT scenario, rpo_seconds FROM ops_recovery_target \
          WHERE profile = $1 AND scenario IN ('node_loss', 'corruption')",
    )
    .bind(&state.base.config.ops.profile)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(scenario, rpo)| (scenario, i64::from(rpo)))
    .collect();
    let source = |name: &str, value: Option<f64>, scenario: &str| {
        let target = targets.get(scenario).copied();
        RpoSource {
            source: name.to_owned(),
            value_seconds: value,
            target_seconds: target,
            status: status_of(value, target).to_owned(),
        }
    };
    Ok(vec![
        source("wal_archive", wal, "corruption"),
        source("standby", standby, "node_loss"),
        source("backup", backup, "corruption"),
    ])
}

/// One minute's run: measure, record, and notify on a new `over`. Answers
/// how many sources newly turned over.
pub async fn run(state: &EngineState) -> Result<usize, AppError> {
    let sources = measure(state).await?;
    for s in &sources {
        if let Some(v) = s.value_seconds {
            metrics::gauge!(GAUGE, "source" => s.source.clone()).set(v);
        }
    }
    *LATEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((Instant::now(), sources.clone()));
    let fresh = {
        let mut over = OVER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        newly_over(&sources, &mut over)
    };
    for name in &fresh {
        let Some(s) = sources.iter().find(|s| &s.source == name) else {
            continue;
        };
        let subject = format!("Recovery point over target: {name}");
        let body = format!(
            "A disaster now would lose about {:.0} seconds of data from {name}; the target is {} \
             seconds. Check backups, WAL archiving and the replica.",
            s.value_seconds.unwrap_or_default(),
            s.target_seconds.unwrap_or_default()
        );
        tracing::warn!(source = %name, "live recovery point over its target");
        crate::freshness::notify_readers(state, &subject, &body).await?;
    }
    Ok(fresh.len())
}

/// The values the last minute's run measured, or a fresh measure when
/// they are older than two minutes (the route, and AB3-T11's `ops.live_rpo`
/// agent action).
pub async fn current(state: &EngineState) -> Result<Vec<RpoSource>, AppError> {
    let cached = LATEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|(at, _)| at.elapsed() < REUSE)
        .map(|(_, sources)| sources.clone());
    match cached {
        Some(items) => Ok(items),
        None => measure(state).await,
    }
}

/// Live recovery point
///
/// AB3-T2: each source's live recovery point in seconds, this profile's
/// target and `ok`, `over` or `off`. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/rpo",
    tag = "ops",
    operation_id = "get_ops_live_rpo",
    responses(
        (status = 200, description = "Every source", body = PaginatedResponse<RpoSource>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_rpo(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
) -> Result<Json<PaginatedResponse<RpoSource>>, AppError> {
    let items = current(&state).await?;
    let n = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, n, 1, n.max(1))))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ops/rpo", get(get_rpo))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_rpo), components(schemas(RpoSource)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str, value: Option<f64>, target: Option<i64>) -> RpoSource {
        RpoSource {
            source: name.into(),
            value_seconds: value,
            target_seconds: target,
            status: status_of(value, target).into(),
        }
    }

    #[test]
    fn archiver_off_reports_off() {
        assert_eq!(status_of(None, Some(300)), "off");
        assert_eq!(status_of(Some(10.0), Some(300)), "ok");
        assert_eq!(status_of(Some(301.0), Some(300)), "over");
        assert_eq!(status_of(Some(10_000.0), None), "ok");
    }

    #[test]
    fn over_target_notifies_once() {
        let mut over = HashSet::new();
        let over_run = [
            source("backup", Some(90_000.0), Some(300)),
            source("standby", None, Some(0)),
        ];
        assert_eq!(newly_over(&over_run, &mut over), ["backup"]);
        // Still over a minute later: nothing new to tell.
        assert!(newly_over(&over_run, &mut over).is_empty());
        // Back under, then over again: a new transition.
        let ok_run = [source("backup", Some(10.0), Some(300))];
        assert!(newly_over(&ok_run, &mut over).is_empty());
        assert_eq!(newly_over(&over_run, &mut over), ["backup"]);
    }

    #[test]
    fn the_newest_backup_archive_sets_the_age() {
        let dir = std::env::temp_dir().join(format!("attome-rpo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(newest_backup_age(&dir), None);
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        assert_eq!(newest_backup_age(&dir), None);
        std::fs::write(dir.join("attome-20261025-0200.dump"), b"x").unwrap();
        let age = newest_backup_age(&dir).unwrap();
        assert!((0.0..60.0).contains(&age), "{age}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

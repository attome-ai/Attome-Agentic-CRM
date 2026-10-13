//! Directly-follows-graph discovery, variant clustering, and cycle-time
//! computation over `process_event` — `document/module-master-plans/
//! M41-process-intelligence.md` §3/§4. [`compute_snapshot`] is called by
//! `extraction::run_sweep` after any tick that wrote new events for a case
//! def, and writes one `process_dfg_snapshot` row (never UPDATEd — a
//! recompute is a new row, same posture `metric_snapshot` already uses,
//! see migration `0298`'s header). `GET .../dfg` and `GET .../variants`
//! (routes below) just read the latest snapshot row — this module never
//! computes synchronously on a request thread.
//!
//! A snapshot always covers a fixed trailing window
//! ([`ROLLING_WINDOW_DAYS`]) ending "now", not an admin-selectable period —
//! Phase 1's checklist calls for DFG/variants/cycle-time, not a period picker
//! UI; period selection is left for a later phase alongside benchmarking
//! (module plan §4, "Process benchmarking", Phase 3).

use attome_db::DbPool;
use attome_types::{AppError, ErrorResponse};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};

use crate::model::{DfgSnapshotResponse, VariantsResponse};

const ROLLING_WINDOW_DAYS: i64 = 90;
/// Bounds one compute call regardless of how much history a case def has
/// accumulated (guidelines §9/§10) — a case def whose window holds more
/// events than this simply gets a snapshot computed over the most recent
/// `MAX_EVENTS_PER_COMPUTE` of them rather than the whole window.
const MAX_EVENTS_PER_COMPUTE: i64 = 50_000;

#[derive(sqlx::FromRow)]
struct EventRow {
    case_id: Uuid,
    activity: String,
    ts_start: DateTime<Utc>,
    ts_end: Option<DateTime<Utc>>,
}

/// FNV-1a — stable across process restarts and machines (unlike
/// `std::collections::hash_map::DefaultHasher`, whose docs make no
/// cross-version stability guarantee), which matters here because a variant
/// hash is persisted in `process_dfg_snapshot.variants_json` and compared
/// across snapshots over time.
fn fnv1a(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn duration_stats(mut samples: Vec<f64>) -> serde_json::Value {
    if samples.is_empty() {
        return serde_json::json!({ "count": 0 });
    }
    samples.sort_by(f64::total_cmp);
    serde_json::json!({
        "count": samples.len(),
        "p50_seconds": percentile(&samples, 0.50),
        "p90_seconds": percentile(&samples, 0.90),
        "max_seconds": samples.last().copied().unwrap_or(0.0),
    })
}

pub struct ComputeStats {
    pub case_count: i32,
    pub event_count: i32,
}

impl std::fmt::Debug for ComputeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeStats").finish_non_exhaustive()
    }
}

/// Computes and persists a new snapshot for `case_def_id` over the trailing
/// [`ROLLING_WINDOW_DAYS`]. Returns `Ok(None)` when there is nothing in the
/// window yet (no snapshot row is written — an empty snapshot would just be
/// noise for `GET .../dfg`'s "no snapshot yet" 404 to already communicate
/// correctly).
pub async fn compute_snapshot(
    db: &DbPool,
    case_def_id: Uuid,
) -> Result<Option<ComputeStats>, AppError> {
    let period_end = Utc::now();
    let period_start = period_end - ChronoDuration::days(ROLLING_WINDOW_DAYS);

    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT case_id, activity, ts_start, ts_end FROM process_event \
         WHERE case_def_ref = $1 AND ts_start >= $2 AND ts_start < $3 \
         ORDER BY case_id, ts_start LIMIT $4",
    )
    .bind(case_def_id)
    .bind(period_start)
    .bind(period_end)
    .bind(MAX_EVENTS_PER_COMPUTE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        return Ok(None);
    }

    // Group by case_id — rows are already ORDER BY case_id, ts_start.
    let mut cases: Vec<Vec<&EventRow>> = Vec::new();
    for row in &rows {
        match cases.last_mut() {
            Some(current) if current[0].case_id == row.case_id => current.push(row),
            _ => cases.push(vec![row]),
        }
    }

    let mut node_counts: HashMap<&str, i64> = HashMap::new();
    let mut edge_stats: HashMap<(&str, &str), Vec<f64>> = HashMap::new();
    let mut variants: HashMap<String, (Vec<String>, i64)> = HashMap::new();
    let mut per_case_durations: Vec<f64> = Vec::new();
    let mut per_step_durations: HashMap<&str, Vec<f64>> = HashMap::new();

    for case_events in &cases {
        let sequence: Vec<String> = case_events.iter().map(|e| e.activity.clone()).collect();
        let hash = fnv1a(&sequence.join("\u{1f}"));
        let entry = variants
            .entry(hash)
            .or_insert_with(|| (sequence.clone(), 0));
        entry.1 += 1;

        for event in case_events {
            *node_counts.entry(event.activity.as_str()).or_insert(0) += 1;
            if let Some(end) = event.ts_end {
                let secs = (end - event.ts_start).num_milliseconds() as f64 / 1000.0;
                if secs >= 0.0 {
                    per_step_durations
                        .entry(event.activity.as_str())
                        .or_default()
                        .push(secs);
                }
            }
        }
        for pair in case_events.windows(2) {
            let (prev, next) = (pair[0], pair[1]);
            let prev_end = prev.ts_end.unwrap_or(prev.ts_start);
            let secs = (next.ts_start - prev_end).num_milliseconds() as f64 / 1000.0;
            edge_stats
                .entry((prev.activity.as_str(), next.activity.as_str()))
                .or_default()
                .push(secs.max(0.0));
        }

        if let (Some(first), Some(last)) = (case_events.first(), case_events.last()) {
            let end = last.ts_end.unwrap_or(last.ts_start);
            let secs = (end - first.ts_start).num_milliseconds() as f64 / 1000.0;
            if secs >= 0.0 {
                per_case_durations.push(secs);
            }
        }
    }

    let nodes: Vec<serde_json::Value> = node_counts
        .iter()
        .map(|(activity, count)| serde_json::json!({ "activity": activity, "count": count }))
        .collect();
    let edges: Vec<serde_json::Value> = edge_stats
        .into_iter()
        .map(|((from, to), durations)| {
            let frequency = durations.len() as i64;
            let mut sorted = durations;
            sorted.sort_by(f64::total_cmp);
            let median = if sorted.is_empty() {
                0.0
            } else {
                percentile(&sorted, 0.5)
            };
            serde_json::json!({
                "from": from,
                "to": to,
                "frequency": frequency,
                "median_duration_seconds": median,
            })
        })
        .collect();
    let graph_json = serde_json::json!({ "nodes": nodes, "edges": edges });

    // Variants ordered by count DESC — the most common paths through the
    // process first, matching how a DFG viewer would want to highlight them.
    let mut variant_list: Vec<(Vec<String>, String, i64)> = variants
        .into_iter()
        .map(|(hash, (sequence, count))| (sequence, hash, count))
        .collect();
    variant_list.sort_by_key(|v| std::cmp::Reverse(v.2));
    let variants_json: Vec<serde_json::Value> = variant_list
        .iter()
        .map(|(sequence, hash, count)| {
            serde_json::json!({ "sequence": sequence, "hash": hash, "count": count })
        })
        .collect();

    let per_step_json: serde_json::Map<String, serde_json::Value> = per_step_durations
        .into_iter()
        .map(|(activity, durations)| (activity.to_string(), duration_stats(durations)))
        .collect();
    let cycle_time_json = serde_json::json!({
        "per_case": duration_stats(per_case_durations),
        "per_step": serde_json::Value::Object(per_step_json),
    });

    let case_count = cases.len() as i32;
    let event_count = rows.len() as i32;

    sqlx::query(
        "INSERT INTO process_dfg_snapshot \
             (case_def_ref, period_start, period_end, graph_json, variants_json, \
              cycle_time_json, case_count, event_count) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(case_def_id)
    .bind(period_start.date_naive())
    .bind(period_end.date_naive())
    .bind(&graph_json)
    .bind(serde_json::Value::Array(variants_json))
    .bind(&cycle_time_json)
    .bind(case_count)
    .bind(event_count)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(Some(ComputeStats {
        case_count,
        event_count,
    }))
}

#[derive(sqlx::FromRow)]
struct SnapshotRow {
    id: Uuid,
    case_def_ref: Uuid,
    period_start: chrono::NaiveDate,
    period_end: chrono::NaiveDate,
    computed_at: DateTime<Utc>,
    graph_json: serde_json::Value,
    variants_json: serde_json::Value,
    cycle_time_json: serde_json::Value,
    case_count: i32,
    event_count: i32,
}

async fn latest_snapshot(state: &EngineState, case_def_id: Uuid) -> Result<SnapshotRow, AppError> {
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM process_case_def WHERE id = $1 AND is_deleted = false")
            .bind(case_def_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }
    sqlx::query_as(
        "SELECT id, case_def_ref, period_start, period_end, computed_at, graph_json, \
                variants_json, cycle_time_json, case_count, event_count \
         FROM process_dfg_snapshot \
         WHERE case_def_ref = $1 ORDER BY computed_at DESC LIMIT 1",
    )
    .bind(case_def_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/dfg",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Success", body = DfgSnapshotResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Case def not found, or no snapshot computed yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_dfg(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DfgSnapshotResponse>, AppError> {
    let row = latest_snapshot(&state, id).await?;
    Ok(Json(DfgSnapshotResponse {
        id: row.id,
        case_def_ref: row.case_def_ref,
        period_start: row.period_start,
        period_end: row.period_end,
        computed_at: row.computed_at,
        graph: row.graph_json,
        case_count: row.case_count,
        event_count: row.event_count,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/variants",
    tag = "process",
    params(("id" = Uuid, Path, description = "Case definition id")),
    responses(
        (status = 200, description = "Success", body = VariantsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Case def not found, or no snapshot computed yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_variants(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<VariantsResponse>, AppError> {
    let row = latest_snapshot(&state, id).await?;
    Ok(Json(VariantsResponse {
        id: row.id,
        case_def_ref: row.case_def_ref,
        period_start: row.period_start,
        period_end: row.period_end,
        computed_at: row.computed_at,
        variants: row.variants_json,
        cycle_time: row.cycle_time_json,
        case_count: row.case_count,
        event_count: row.event_count,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/process/case-defs/{id}/dfg", get(get_dfg))
        .route("/api/v1/process/case-defs/{id}/variants", get(get_variants))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_dfg, get_variants))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_is_stable_and_order_sensitive() {
        assert_eq!(fnv1a("a\u{1f}b"), fnv1a("a\u{1f}b"));
        assert_ne!(fnv1a("a\u{1f}b"), fnv1a("b\u{1f}a"));
    }

    #[test]
    fn duration_stats_reports_count_zero_for_an_empty_sample() {
        assert_eq!(duration_stats(vec![])["count"], 0);
    }

    #[test]
    fn percentile_is_bounded_within_the_sample() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!(percentile(&sorted, 0.5) >= 1.0 && percentile(&sorted, 0.5) <= 5.0);
        assert_eq!(percentile(&sorted, 0.0), 1.0);
    }
}

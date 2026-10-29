//! P9-T10: a metric's past periods, filled by a durable job.
//!
//! `POST /api/v1/metrics/{id}/backfill` with `{from, to}` queues
//! [`BACKFILL_JOB`]. Each run ([`backfill`]) computes up to
//! [`PERIODS_PER_RUN`] periods, oldest first, and the job queues itself for
//! the rest. A period that already has a snapshot that did not fail
//! (scheduled, on demand, or backfilled before) is skipped, so a re-run or an
//! overlapping range never duplicates one; the check is repeated under the
//! snapshot's advisory lock. A new row is a plain INSERT marked
//! `is_backfill = true` (snapshots are append-only, D-407).
//!
//! What can be backfilled:
//!
//! - **A builder metric** (P9-T3): its spec over the period `[start, end)`,
//!   aggregated as the metric service principal (D-786) through the
//!   structured aggregate. Records are placed in periods by the spec's date
//!   field and filtered by their values now, so a filter on a field that
//!   changes over time (a status) counts records as they are today. A
//!   dimensioned metric's total is backfilled, not its members.
//! - **A formula metric**: evaluated from its inputs' snapshots for the same
//!   period, so its inputs are backfilled first. A period whose inputs have
//!   no snapshot is left empty.
//!
//! Any other query metric's stored SQL measures the current period only and
//! cannot be moved to a past one, and a manual metric has nothing to compute:
//! both are refused (422). Periods are on the metric's own calendar
//! ([`crate::metric::metric_calendar`], P9-T16), as the scheduled sweep's;
//! the current period and later are left to the sweep.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::MetricUpdate;
use crate::builder::MetricSpec;
use crate::metric::{MetricDefinitionRow, PeriodCalendar, SnapshotStatus};

/// The registered job type's name.
pub const BACKFILL_JOB: &str = "metric_backfill";
/// Periods computed per job run.
pub const PERIODS_PER_RUN: usize = 12;
/// The longest range one request may cover: ten years.
pub const MAX_RANGE_DAYS: i64 = 3_653;

/// One run's work: the periods starting in `[from, to)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillPayload {
    pub metric_id: Uuid,
    pub from: NaiveDate,
    pub to: NaiveDate,
}

/// The job that backfills `payload`'s periods.
pub fn backfill_job(payload: &BackfillPayload) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
        name: BACKFILL_JOB.to_owned(),
        version: 1,
        payload: serde_json::json!(payload),
        next: None,
    })
}

/// The queue's dedup key for a metric's first backfill run, so a second
/// request while one is queued is a no-op.
pub fn dedup_key(metric_id: Uuid) -> String {
    format!("metric-backfill:{metric_id}")
}

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackfillRun {
    /// Snapshots written.
    pub written: u32,
    /// Periods that already had a snapshot.
    pub skipped: u32,
    /// Periods with no value to record (no inputs, or no records for an
    /// aggregate other than count and sum).
    pub empty: u32,
    /// Where the next run starts, when periods remain.
    pub next: Option<NaiveDate>,
}

/// The periods of `period` starting in `[from, to)`, at most `limit` of
/// them, oldest first, beginning with the period that contains `from`, and
/// the first day of the next one when more remain. Pure.
pub fn periods(
    period: &str,
    calendar: PeriodCalendar,
    from: NaiveDate,
    to: NaiveDate,
    limit: usize,
) -> Result<(Vec<(NaiveDate, NaiveDate)>, Option<NaiveDate>), AppError> {
    let bounds = |day: NaiveDate| {
        crate::metric::period_bounds(
            period,
            calendar,
            day.and_time(chrono::NaiveTime::MIN).and_utc(),
        )
    };
    let mut out = Vec::new();
    let (mut start, _) = bounds(from)?;
    while start < to {
        if out.len() == limit {
            return Ok((out, Some(start)));
        }
        let (s, end) = bounds(start)?;
        out.push((s, end));
        start = end;
    }
    Ok((out, None))
}

/// How a metric's past value is computed.
enum Source {
    Builder(MetricSpec),
    Formula(String),
}

/// The metric's backfill source, or 422 when it has none.
async fn source(state: &EngineState, metric: &MetricDefinitionRow) -> Result<Source, AppError> {
    match metric.source_kind.as_str() {
        "formula" => metric
            .formula
            .clone()
            .map(Source::Formula)
            .ok_or_else(|| AppError::Validation("the formula metric has no formula".into())),
        "query" => crate::builder::current_spec(&state.base.db, metric.id)
            .await?
            .map(Source::Builder)
            .ok_or_else(|| {
                AppError::Validation(
                    "only a builder or formula metric can be backfilled: this metric's query \
                     measures the current period only"
                        .into(),
                )
            }),
        _ => Err(AppError::Validation(
            "a manual metric has no past values to compute; record them with /compute".into(),
        )),
    }
}

/// One backfill run: the periods in `[from, to)` (stopping before the
/// current period), at most [`PERIODS_PER_RUN`] of them. The job handler
/// queues the next run from [`BackfillRun::next`].
pub async fn backfill(
    state: &EngineState,
    metric_id: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<BackfillRun, AppError> {
    let db = &state.base.db;
    let metric = crate::metric::fetch_metric(db, metric_id).await?;
    let source = source(state, &metric).await?;
    let to = to.min(crate::metric::current_period_start(db, &metric, Utc::now()).await?);
    let calendar = crate::metric::metric_calendar(db, metric_id).await?;
    let (todo, next) = periods(&metric.period, calendar, from, to, PERIODS_PER_RUN)?;
    let principal = match &source {
        Source::Builder(_) => Some(
            crate::principal::resolve(state, crate::principal::Trigger::from_evaluated_by(None))
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?,
        ),
        Source::Formula(_) => None,
    };

    let mut run = BackfillRun {
        next,
        ..BackfillRun::default()
    };
    for (start, end) in todo {
        if let Some(existing) = crate::metric::latest_snapshot(db, metric_id, start).await?
            && existing.status != SnapshotStatus::Failed.as_str()
        {
            run.skipped += 1;
            continue;
        }
        let (value, source_version) = match (&source, &principal) {
            (Source::Builder(spec), Some(principal)) => {
                let definition = crate::builder::spec_definition(spec, start, end)?;
                let aggregate = attome_search::aggregate::run_structured_aggregate(
                    state,
                    principal,
                    &definition,
                    &[],
                    chrono_tz::UTC,
                )
                .await?;
                let value = aggregate
                    .buckets
                    .first()
                    .and_then(|b| b.values.first().copied().flatten());
                // A count or sum over no records is zero; any other aggregate
                // has no value.
                let value = match value {
                    Some(v) => Some(v),
                    None if matches!(spec.aggregate.as_str(), "count" | "sum") => Some(0.0),
                    None => None,
                };
                (value, "backfill")
            }
            (Source::Formula(formula), _) => {
                match crate::metric::evaluate_formula_metric(db, formula, start, None).await {
                    Ok(v) => (Some(v), "formula"),
                    Err(AppError::Validation(reason)) => {
                        tracing::info!(%metric_id, period_start = %start, %reason, "metric backfill: formula period left empty");
                        (None, "formula")
                    }
                    Err(e) => return Err(e),
                }
            }
            (Source::Builder(_), None) => {
                return Err(AppError::internal("metric backfill without a principal"));
            }
        };
        let Some(value) = value else {
            run.empty += 1;
            continue;
        };
        match crate::metric::record_backfill(db, &metric, start, value, source_version).await {
            Ok(_) => run.written += 1,
            // Someone recorded the period since the check above.
            Err(AppError::Conflict(_)) => run.skipped += 1,
            Err(e) => return Err(e),
        }
    }
    tracing::info!(
        %metric_id,
        written = run.written,
        skipped = run.skipped,
        empty = run.empty,
        more = run.next.is_some(),
        "metric backfill run"
    );
    Ok(run)
}

/// The range to backfill.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackfillMetricBody {
    /// The first day; the period containing it is the first filled.
    pub from: NaiveDate,
    /// The day after the last; periods starting from it are not filled. The
    /// current period and later are always left to the schedule.
    pub to: NaiveDate,
}

/// The backfill that was queued.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackfillMetricQueued {
    pub metric_id: Uuid,
    pub from: NaiveDate,
    /// `to`, moved back to the start of the current period when later.
    pub to: NaiveDate,
    /// `false` when a backfill of this metric was already queued.
    pub queued: bool,
}

/// Queues the computation of the metric's past periods in `[from, to)`. Each value is recorded as a
/// backfilled snapshot; a period that already has a snapshot is left alone. Only builder and
/// formula metrics can be backfilled. Needs update rights on metric definitions. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/backfill",
    operation_id = "backfill_metric",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The metric")),
    request_body = BackfillMetricBody,
    responses(
        (status = 202, description = "Queued", body = BackfillMetricQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
        (status = 422, description = "A range over ten years, empty or entirely in the current period, or a metric that cannot be backfilled", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
pub(crate) async fn post_backfill(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetricUpdate>>,
    Path(metric_id): Path<Uuid>,
    Json(body): Json<BackfillMetricBody>,
) -> Result<(StatusCode, Json<BackfillMetricQueued>), AppError> {
    if body.from >= body.to {
        return Err(AppError::Validation("from must be before to".into()));
    }
    if (body.to - body.from).num_days() > MAX_RANGE_DAYS {
        return Err(AppError::Validation(
            "a backfill covers at most ten years".into(),
        ));
    }
    let metric = crate::metric::fetch_metric(&state.base.db, metric_id).await?;
    source(&state, &metric).await?;
    let to = body
        .to
        .min(crate::metric::current_period_start(&state.base.db, &metric, Utc::now()).await?);
    if body.from >= to {
        return Err(AppError::Validation(
            "the range has no period before the current one".into(),
        ));
    }
    let payload = BackfillPayload {
        metric_id,
        from: body.from,
        to,
    };
    let queued = attome_jobs::enqueue_dedup(
        &state.base.db,
        backfill_job(&payload),
        &dedup_key(metric_id),
    )
    .await
    .map_err(AppError::internal)?;
    if queued {
        attome_audit::write_business_event(
            &state,
            "metric_definition",
            metric_id,
            attome_audit::AuditOperation::Execute,
            "metric.backfill",
            ctx.user_id,
            None,
            None,
            format!(
                "metric backfill queued for {} to {}",
                payload.from, payload.to
            ),
        )
        .await;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(BackfillMetricQueued {
            metric_id,
            from: payload.from,
            to,
            queued,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn periods_walk_months_from_the_one_containing_from() {
        let (got, next) = periods(
            "month",
            PeriodCalendar::default(),
            d(2026, 1, 15),
            d(2026, 4, 1),
            12,
        )
        .unwrap();
        assert_eq!(
            got,
            vec![
                (d(2026, 1, 1), d(2026, 2, 1)),
                (d(2026, 2, 1), d(2026, 3, 1)),
                (d(2026, 3, 1), d(2026, 4, 1)),
            ]
        );
        assert_eq!(next, None);
    }

    #[test]
    fn periods_stop_at_the_limit_and_say_where_to_resume() {
        let (got, next) = periods(
            "month",
            PeriodCalendar::default(),
            d(2024, 1, 1),
            d(2026, 1, 1),
            12,
        )
        .unwrap();
        assert_eq!(got.len(), 12);
        assert_eq!(got[11], (d(2024, 12, 1), d(2025, 1, 1)));
        assert_eq!(next, Some(d(2025, 1, 1)));
        let (rest, next) = periods(
            "month",
            PeriodCalendar::default(),
            d(2025, 1, 1),
            d(2026, 1, 1),
            12,
        )
        .unwrap();
        assert_eq!(rest.len(), 12);
        assert_eq!(next, None);
    }

    #[test]
    fn periods_of_quarters_and_an_empty_range() {
        let (got, _) = periods(
            "quarter",
            PeriodCalendar::default(),
            d(2025, 5, 10),
            d(2025, 10, 1),
            12,
        )
        .unwrap();
        assert_eq!(
            got,
            vec![
                (d(2025, 4, 1), d(2025, 7, 1)),
                (d(2025, 7, 1), d(2025, 10, 1))
            ]
        );
        let (none, next) = periods(
            "month",
            PeriodCalendar::default(),
            d(2025, 5, 1),
            d(2025, 5, 1),
            12,
        )
        .unwrap();
        assert!(none.is_empty());
        assert_eq!(next, None);
    }
}

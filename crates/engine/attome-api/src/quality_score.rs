//! M14 Phase 1 (Data Quality) — the scoring engine. Since L2-T3 an entity
//! is scored as its records change (`crate::quality::incremental`, which
//! calls [`score_entity`]); `EngineJob::DataQualityScoreSweep` writes the
//! daily snapshot and alerts ([`run_snapshot`]); [`run_sweep`] still scores
//! every entity at once on request.
//! Two dimensions, neither needing M45's not-yet-authorable `kind=quality`
//! custom-rule mechanism (see the module plan's scope note):
//!
//!   * **completeness** — `is_required` field metadata + null counts, the
//!     same `COUNT(*) FILTER (WHERE col IS NULL)` technique
//!     `data_profile_admin::profile_field` (M12) already uses. One "check"
//!     is one (row, required-field) pair; `sample_size` is `row_count *
//!     required_field_count`.
//!   * **uniqueness** — `duplicate_candidate` (M13), `status =
//!     'open'`, not a second dedup-detection pass. `fail_count` is the
//!     number of *distinct records* named by an open candidate pair (a
//!     record can appear in more than one pair; it is still one failing
//!     record), `sample_size` is the entity's row count.
//!
//! **Concurrency.** No advisory lock. Every write is an idempotent `ON
//! CONFLICT` upsert keyed by `(entity, period, dimension[, record, field])`
//! (see migrations `0386`/`0387`) and the sweep always re-derives its
//! numbers fresh rather than reading its own prior row — same "the upsert
//! key is the concurrency story" posture `DataMatchSweep`/
//! `ContentScheduledPublishSweep` already take with no lock of their own.
//!
//! **Bounding (coding-guidelines §9).** [`MAX_ISSUES_PER_RUN`] caps the
//! whole sweep's issue-row writes; [`MAX_ISSUES_PER_ENTITY`] caps one
//! entity's share of that budget so one badly-configured entity (e.g. a
//! required field left null on every row) cannot consume the whole run and
//! starve every other entity's issue detail. Scores are still written for
//! every entity regardless of the issue-row cap — the cap only bounds the
//! *detail* rows, never the aggregate score.
//!
//! **Alerting (M51).** A dimension score at or below [`SCORE_ALERT_THRESHOLD`]
//! raises a best-effort in-app notification to `system.admin` holders, same
//! shape as `attome_ai::quality_monitor::alert_significant_drop` (D-435):
//! a dispatch failure for one recipient (or the whole recipient resolution)
//! is logged and never fails the sweep. The threshold is a fixed Phase 1
//! constant, not a per-entity configuration surface — M45's rule-authoring
//! UI (not built yet) is where a customer-configurable threshold belongs;
//! see the module plan's scope note.

use std::collections::{HashMap, HashSet};

use attome_config::NotificationSection;
use attome_core::{AttrInfo, EngineState, EntityMeta, quote_ident};
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch};
use attome_types::AppError;
use chrono::Utc;
use uuid::Uuid;

/// Caps the whole sweep's issue-row writes.
pub const MAX_ISSUES_PER_RUN: i64 = 2_000;
/// Caps one entity's share of [`MAX_ISSUES_PER_RUN`].
pub const MAX_ISSUES_PER_ENTITY: i64 = 200;

/// A dimension score at or below this value raises an M51 alert.
const SCORE_ALERT_THRESHOLD: f64 = 70.0;

const COMPLETENESS: &str = "completeness";
const UNIQUENESS: &str = "uniqueness";
/// L2-T2: the weighted overall score's dimension row.
const OVERALL: &str = "overall";

pub struct QualitySweepStats {
    pub entities_scored: usize,
    pub scores_written: usize,
    pub issues_written: i64,
    pub alerts_sent: usize,
}

impl std::fmt::Debug for QualitySweepStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QualitySweepStats").finish_non_exhaustive()
    }
}

struct DimensionAlert {
    dimension: &'static str,
    score: f64,
    fail_count: i64,
    sample_size: i64,
}

pub(crate) struct EntityOutcome {
    scores_written: usize,
    pub(crate) issues_written: i64,
    alerts: Vec<DimensionAlert>,
}

/// Today's UTC calendar date as `YYYY-MM-DD` — the sweep's period key.
/// Matches the sweep's own once/day cadence, so a period always represents
/// one calendar day's answer; a re-run within the same day is the
/// idempotent-upsert case documented above, not a new period.
pub(crate) fn today_period() -> String {
    Utc::now().date_naive().format("%Y-%m-%d").to_string()
}

/// Pure — computes `(pass_count, score)` from a fail count and a sample
/// size. `score` is `100.0` for a zero sample size (nothing to fail),
/// clamped to `[0, 100]` so a caller can never round-trip a value outside
/// the column's expected range. Unit-tested directly without a database
/// (see `tests::*`) — the reason this is its own function rather than
/// inlined at each call site.
fn compute_score(fail_count: i64, sample_size: i64) -> (i64, f64) {
    if sample_size <= 0 {
        return (0, 100.0);
    }
    let pass_count = (sample_size - fail_count).max(0);
    let score = (pass_count as f64 / sample_size as f64 * 100.0).clamp(0.0, 100.0);
    (pass_count, score)
}

/// The job's entry point (`EngineJob::DataQualityScoreSweep`'s handler).
/// Failure isolation matches `run_scheduled_snapshot_sweep`/
/// `alert_significant_drop`'s posture: a failure scoring one entity is
/// logged and skipped, never fails the rest of the sweep.
pub async fn run_sweep(
    state: &EngineState,
    notification_cfg: &NotificationSection,
) -> Result<QualitySweepStats, AppError> {
    let period = today_period();
    // Cloned out of the arc-swap snapshot up front so the loop below never
    // holds the registry guard across an `.await` point (coding-guidelines
    // §10) — the registry is read-mostly and cheap to snapshot; a sweep
    // observing metadata as of the moment it started, rather than a
    // mid-sweep metadata change, is also the more predictable behavior.
    let entities: Vec<EntityMeta> = state.entities.load().iter().cloned().collect();

    let mut stats = QualitySweepStats {
        entities_scored: 0,
        scores_written: 0,
        issues_written: 0,
        alerts_sent: 0,
    };
    // L2-T3: the caps are settings (defaults the two constants).
    let caps = crate::quality::incremental::caps(state);
    let mut issue_budget = caps.per_run;

    for meta in &entities {
        let entity_budget = issue_budget.clamp(0, caps.per_entity);
        match score_entity(&state.base.db, meta, &period, entity_budget).await {
            Ok(outcome) => {
                stats.entities_scored += 1;
                stats.scores_written += outcome.scores_written;
                stats.issues_written += outcome.issues_written;
                issue_budget = (issue_budget - outcome.issues_written).max(0);

                for alert in outcome.alerts {
                    dispatch_score_alert(
                        &state.base.db,
                        notification_cfg,
                        &meta.logicalname,
                        &alert,
                    )
                    .await;
                    stats.alerts_sent += 1;
                }
            }
            Err(e) => {
                tracing::warn!(
                    entity = %meta.logicalname,
                    error = %e,
                    "data quality sweep: entity scoring failed, continuing with the rest of the sweep"
                );
            }
        }
    }

    Ok(stats)
}

/// L2-T3: what the daily job did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotStats {
    pub snapshot_rows: usize,
    pub timeliness_rescored: usize,
    pub alerts_sent: usize,
}

/// L2-T3: the daily job (`EngineJob::DataQualityScoreSweep`). Scoring runs
/// as records change (`crate::quality::incremental`); this rescores only
/// the entities with a timeliness target (their scores age with no change),
/// writes the day's `quality_snapshot` from every entity's latest scores,
/// and alerts the stewards of entities below target or dropping
/// (`crate::quality::alerts`, L2-T7).
pub async fn run_snapshot(
    state: &EngineState,
    notification_cfg: &NotificationSection,
) -> Result<SnapshotStats, AppError> {
    let db = &state.base.db;
    let mut stats = SnapshotStats::default();
    let period = today_period();
    let caps = crate::quality::incremental::caps(state);
    let timely: Vec<String> =
        sqlx::query_scalar("SELECT entity FROM quality_target WHERE timeliness_days IS NOT NULL")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    let mut budget = caps.per_run;
    for entity in timely {
        let Some(meta) = state.entities.load().get(&entity).cloned() else {
            continue;
        };
        match score_entity(db, &meta, &period, budget.clamp(0, caps.per_entity)).await {
            Ok(outcome) => {
                budget = (budget - outcome.issues_written).max(0);
                stats.timeliness_rescored += 1;
            }
            Err(e) => {
                tracing::warn!(%entity, error = %e, "quality snapshot: timeliness rescoring failed")
            }
        }
    }

    let latest: Vec<(String, String, f64, i64, i64)> = sqlx::query_as(
        "WITH latest AS ( \
             SELECT DISTINCT ON (entity_logicalname, dimension) \
                    entity_logicalname, dimension, score::float8 AS score, fail_count, sample_size \
               FROM quality_score \
              ORDER BY entity_logicalname, dimension, computed_at DESC \
         ), written AS ( \
             INSERT INTO quality_snapshot (entity, dimension, day, score) \
             SELECT entity_logicalname, dimension, CURRENT_DATE, score FROM latest \
             ON CONFLICT (entity, dimension, day) DO UPDATE SET score = EXCLUDED.score \
         ) \
         SELECT entity_logicalname, dimension, score, fail_count, sample_size FROM latest",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    stats.snapshot_rows = latest.len();
    // L2-T7: one alert per entity per day, to its stewards.
    stats.alerts_sent = crate::quality::alerts::after_snapshot(state, notification_cfg).await?;
    Ok(stats)
}

pub(crate) async fn score_entity(
    db: &DbPool,
    meta: &EntityMeta,
    period: &str,
    issue_budget: i64,
) -> Result<EntityOutcome, AppError> {
    let table = quote_ident(&meta.logicalname);
    let row_count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table}",
        table = quote_ident(&meta.logicalname)
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let mut outcome = EntityOutcome {
        scores_written: 0,
        issues_written: 0,
        alerts: Vec::new(),
    };
    let mut remaining_budget = issue_budget;

    if row_count > 0 {
        let required: Vec<&AttrInfo> = meta.attrs.iter().filter(|a| a.is_required).collect();
        if !required.is_empty() {
            let written = score_completeness(
                db,
                &table,
                &meta.logicalname,
                period,
                &required,
                row_count,
                remaining_budget,
                &mut outcome,
            )
            .await?;
            remaining_budget -= written;
        }

        score_uniqueness(
            db,
            &meta.logicalname,
            period,
            row_count,
            remaining_budget,
            &mut outcome,
        )
        .await?;
    }

    // L2-T4: new open issues go to the domain steward or the record owner.
    crate::quality::routing::assign_open(db, meta).await?;

    // L2-T2: validity, consistency and timeliness over a sample of recent
    // records, then the weighted overall score against the threshold.
    score_rules_and_overall(
        db,
        &table,
        &meta.logicalname,
        period,
        row_count,
        &mut outcome,
    )
    .await?;

    Ok(outcome)
}

/// Records sampled for the rule and timeliness dimensions, newest first.
const RULE_SAMPLE: i64 = 1_000;

/// L2-T2: the dimensions measured from rules and record age, and the
/// overall score (`crate::quality::dimensions`).
async fn score_rules_and_overall(
    db: &DbPool,
    table: &str,
    entity_name: &str,
    period: &str,
    row_count: i64,
    outcome: &mut EntityOutcome,
) -> Result<(), AppError> {
    use crate::quality::dimensions::{self, Dimension, Measure};

    let target: Option<(serde_json::Value, f64, Option<i32>)> = sqlx::query_as(
        "SELECT dimension_weights, threshold::float8, timeliness_days FROM quality_target \
          WHERE entity = $1",
    )
    .bind(entity_name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let rules: Vec<(String, String)> = sqlx::query_as(
        "SELECT dimension, expression FROM quality_rule \
          WHERE entity = $1 AND enabled AND dimension IN ('validity', 'consistency') \
          ORDER BY id",
    )
    .bind(entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let of = |dimension: &str| -> Vec<String> {
        rules
            .iter()
            .filter(|(d, _)| d == dimension)
            .map(|(_, e)| e.clone())
            .collect()
    };
    let (validity_rules, consistency_rules) = (of("validity"), of("consistency"));
    let max_age = target.as_ref().and_then(|t| t.2).map(f64::from);

    let mut measured: Vec<(Dimension, Measure)> = Vec::new();
    if row_count > 0 && (!rules.is_empty() || max_age.is_some()) {
        let records: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t)::jsonb FROM {table} t ORDER BY t.id DESC LIMIT {RULE_SAMPLE}"
        ))
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        // A soft-deleted record is not measured.
        let records: Vec<serde_json::Value> = records
            .into_iter()
            .filter(|r| r.get("is_active").and_then(serde_json::Value::as_bool) != Some(false))
            .collect();
        let now = Utc::now();
        let ages: Vec<f64> = records
            .iter()
            .filter_map(|r| {
                r.get("modified_at")
                    .or_else(|| r.get("created_at"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|at| (now - at.with_timezone(&Utc)).num_seconds() as f64 / 86_400.0)
            })
            .collect();
        measured.push((
            Dimension::Validity,
            dimensions::rule_pass_rate(&validity_rules, &records),
        ));
        measured.push((
            Dimension::Consistency,
            dimensions::rule_pass_rate(&consistency_rules, &records),
        ));
        measured.push((
            Dimension::Timeliness,
            dimensions::timeliness(&ages, max_age),
        ));
    }
    for (dimension, measure) in &measured {
        if let Measure::Measured {
            pass,
            fail,
            sample,
            score,
        } = *measure
        {
            upsert_score(
                db,
                entity_name,
                period,
                dimension.as_str(),
                pass,
                fail,
                sample,
                score,
            )
            .await?;
            outcome.scores_written += 1;
        }
    }
    // Accuracy has no verification source yet: not measured.

    // The overall score from every dimension measured today.
    let today: Vec<(String, f64)> = sqlx::query_as(
        "SELECT dimension, score::float8 FROM quality_score \
          WHERE entity_logicalname = $1 AND period = $2 AND dimension <> 'overall'",
    )
    .bind(entity_name)
    .bind(period)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let scores: Vec<(Dimension, Measure)> = today
        .into_iter()
        .filter_map(|(d, score)| {
            Dimension::parse(&d).map(|dim| {
                (
                    dim,
                    Measure::Measured {
                        pass: 0,
                        fail: 0,
                        sample: 0,
                        score,
                    },
                )
            })
        })
        .collect();
    let weights = target
        .as_ref()
        .map(|t| dimensions::weights_from(&t.0))
        .unwrap_or_default();
    let threshold = target
        .as_ref()
        .map_or(dimensions::DEFAULT_THRESHOLD, |t| t.1);
    if let Some(overall) = dimensions::combine(&scores, &weights) {
        let counted = i64::try_from(scores.len()).unwrap_or(0);
        upsert_score(
            db,
            entity_name,
            period,
            OVERALL,
            counted,
            0,
            counted,
            overall,
        )
        .await?;
        outcome.scores_written += 1;
        if overall < threshold {
            outcome.alerts.push(DimensionAlert {
                dimension: OVERALL,
                score: overall,
                fail_count: 0,
                sample_size: counted,
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn score_completeness(
    db: &DbPool,
    table: &str,
    entity_name: &str,
    period: &str,
    required: &[&AttrInfo],
    row_count: i64,
    mut remaining_budget: i64,
    outcome: &mut EntityOutcome,
) -> Result<i64, AppError> {
    let sample_size = row_count * required.len() as i64;
    let mut fail_total: i64 = 0;
    let mut issues_written: i64 = 0;

    for attr in required {
        let col = quote_ident(&attr.logicalname);
        let nulls: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FILTER (WHERE {col} IS NULL) FROM {table}"
        ))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        fail_total += nulls;

        if remaining_budget > 0 && nulls > 0 {
            let cap = remaining_budget.min(nulls);
            let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
                "SELECT id FROM {table} WHERE {col} IS NULL ORDER BY id LIMIT {cap}"
            ))
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;

            let written =
                upsert_completeness_issues(db, entity_name, period, &attr.logicalname, &ids)
                    .await?;
            issues_written += written;
            remaining_budget -= written;
        }
    }

    let (pass_count, score) = compute_score(fail_total, sample_size);
    upsert_score(
        db,
        entity_name,
        period,
        COMPLETENESS,
        pass_count,
        fail_total,
        sample_size,
        score,
    )
    .await?;
    outcome.scores_written += 1;
    outcome.issues_written += issues_written;
    if score <= SCORE_ALERT_THRESHOLD {
        outcome.alerts.push(DimensionAlert {
            dimension: COMPLETENESS,
            score,
            fail_count: fail_total,
            sample_size,
        });
    }

    Ok(issues_written)
}

async fn score_uniqueness(
    db: &DbPool,
    entity_name: &str,
    period: &str,
    row_count: i64,
    mut remaining_budget: i64,
    outcome: &mut EntityOutcome,
) -> Result<(), AppError> {
    let pairs: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT record_a, record_b FROM duplicate_candidate \
         WHERE entity_logicalname = $1 AND status = 'open' \
         ORDER BY detected_at, record_a, record_b",
    )
    .bind(entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // A record can appear in more than one open pair; it is still one
    // failing record, not one per pair — matches this dimension's issue
    // rows below, which are keyed one-per-record (field_logicalname = '').
    let mut flagged: HashSet<Uuid> = HashSet::new();
    let mut related_of: HashMap<Uuid, Uuid> = HashMap::new();
    for (a, b) in &pairs {
        flagged.insert(*a);
        flagged.insert(*b);
        related_of.entry(*a).or_insert(*b);
        related_of.entry(*b).or_insert(*a);
    }
    let fail_count = flagged.len() as i64;
    let sample_size = row_count;

    let mut flagged_sorted: Vec<Uuid> = flagged.into_iter().collect();
    flagged_sorted.sort();

    if remaining_budget > 0 && !flagged_sorted.is_empty() {
        let cap = remaining_budget.min(flagged_sorted.len() as i64) as usize;
        let batch: Vec<(Uuid, Uuid)> = flagged_sorted[..cap]
            .iter()
            .map(|id| (*id, related_of[id]))
            .collect();
        let written = upsert_uniqueness_issues(db, entity_name, period, &batch).await?;
        outcome.issues_written += written;
        remaining_budget -= written;
    }
    let _ = remaining_budget;

    let (pass_count, score) = compute_score(fail_count, sample_size);
    upsert_score(
        db,
        entity_name,
        period,
        UNIQUENESS,
        pass_count,
        fail_count,
        sample_size,
        score,
    )
    .await?;
    outcome.scores_written += 1;
    if score <= SCORE_ALERT_THRESHOLD {
        outcome.alerts.push(DimensionAlert {
            dimension: UNIQUENESS,
            score,
            fail_count,
            sample_size,
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upsert_score(
    db: &DbPool,
    entity_name: &str,
    period: &str,
    dimension: &str,
    pass_count: i64,
    fail_count: i64,
    sample_size: i64,
    score: f64,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO quality_score \
            (entity_logicalname, period, dimension, pass_count, fail_count, sample_size, score) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (entity_logicalname, period, dimension) \
         DO UPDATE SET pass_count = EXCLUDED.pass_count, fail_count = EXCLUDED.fail_count, \
             sample_size = EXCLUDED.sample_size, score = EXCLUDED.score, computed_at = NOW()",
    )
    .bind(entity_name)
    .bind(period)
    .bind(dimension)
    .bind(pass_count)
    .bind(fail_count)
    .bind(sample_size)
    .bind(score)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Returns the number of rows actually written (a re-run within the same
/// period re-discovers the same nulls and no-ops via `ON CONFLICT DO
/// NOTHING`, so `rows_affected` — not the input length — is the truthful
/// count against the sweep's issue budget).
async fn upsert_completeness_issues(
    db: &DbPool,
    entity_name: &str,
    period: &str,
    field_logicalname: &str,
    record_ids: &[Uuid],
) -> Result<i64, AppError> {
    let mut written = 0i64;
    for record_id in record_ids {
        let result = sqlx::query(
            "INSERT INTO quality_issue \
                (entity_logicalname, period, dimension, record_id, field_logicalname, detail) \
             VALUES ($1, $2, 'completeness', $3, $4, $5) \
             ON CONFLICT (entity_logicalname, period, dimension, record_id, field_logicalname) \
             DO NOTHING",
        )
        .bind(entity_name)
        .bind(period)
        .bind(record_id)
        .bind(field_logicalname)
        .bind(format!("required field '{field_logicalname}' is null"))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        written += result.rows_affected() as i64;
    }
    Ok(written)
}

async fn upsert_uniqueness_issues(
    db: &DbPool,
    entity_name: &str,
    period: &str,
    records: &[(Uuid, Uuid)],
) -> Result<i64, AppError> {
    let mut written = 0i64;
    for (record_id, related_record_id) in records {
        let result = sqlx::query(
            "INSERT INTO quality_issue \
                (entity_logicalname, period, dimension, record_id, related_record_id, detail) \
             VALUES ($1, $2, 'uniqueness', $3, $4, 'open duplicate candidate pending review') \
             ON CONFLICT (entity_logicalname, period, dimension, record_id, field_logicalname) \
             DO NOTHING",
        )
        .bind(entity_name)
        .bind(period)
        .bind(record_id)
        .bind(related_record_id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        written += result.rows_affected() as i64;
    }
    Ok(written)
}

/// Every active `system.admin` holder — same query shape
/// `attome_ai::quality_monitor::admin_recipients` (D-435) already uses.
pub(crate) async fn admin_recipients(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT su.id \
         FROM user_account su \
         WHERE (su.is_active IS NULL OR su.is_active = true) \
           AND ( \
             EXISTS ( \
               SELECT 1 FROM user_account_mm_privilege up \
               JOIN privilege p ON p.id = up.privilege_ref \
               WHERE up.user_ref = su.id AND up.is_active = true AND p.is_active = true \
                 AND p.key = 'system.admin' \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM user_account_mm_role ur \
               JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
               JOIN privilege p ON p.id = rp.privilege_ref \
               WHERE ur.user_ref = su.id AND ur.is_deleted = false AND rp.is_deleted = false \
                 AND p.is_active = true AND p.key = 'system.admin' \
             ) \
           )",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Best-effort: a dispatch failure for one admin (or the whole recipient
/// resolution) is logged and never fails the sweep, same posture
/// `attome_ai::quality_monitor::alert_significant_drop` documents.
async fn dispatch_score_alert(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    entity_name: &str,
    alert: &DimensionAlert,
) {
    // L2-T7: the entity's stewards, not every full administrator.
    let recipients = match crate::quality::alerts::recipients(db, entity_name).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %e,
                "data quality sweep: failed to resolve the stewards for a threshold alert"
            );
            return;
        }
    };

    let subject = format!(
        "Data quality: {} {} score dropped to {:.0}%",
        entity_name, alert.dimension, alert.score
    );
    let body = format!(
        "The {} dimension for entity '{}' scored {:.0}% ({} failing of {} sampled), at or below \
         the {:.0}% alert threshold. Review at /admin/data/quality.",
        alert.dimension,
        entity_name,
        alert.score,
        alert.fail_count,
        alert.sample_size,
        SCORE_ALERT_THRESHOLD,
    );

    for user_id in recipients {
        let req = DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some("/admin/data/quality".to_string()),
            variables: HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) = create_dispatch(db, notification_cfg, req).await {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "data quality sweep: threshold alert dispatch failed for one recipient"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sample_size_scores_perfect_with_no_pass_count() {
        assert_eq!(compute_score(0, 0), (0, 100.0));
        assert_eq!(compute_score(5, 0), (0, 100.0));
    }

    #[test]
    fn all_passing_scores_100() {
        assert_eq!(compute_score(0, 40), (40, 100.0));
    }

    #[test]
    fn all_failing_scores_0() {
        assert_eq!(compute_score(40, 40), (0, 0.0));
    }

    #[test]
    fn partial_failure_scores_proportionally() {
        // 10 failing of 40 sampled -> 30 pass -> 75%.
        assert_eq!(compute_score(10, 40), (30, 75.0));
    }

    #[test]
    fn a_fail_count_exceeding_sample_size_never_produces_a_negative_pass_count() {
        // Defensive: fail_count should never exceed sample_size in practice,
        // but the arithmetic must not underflow/produce a negative score if
        // it somehow did (e.g. a race between the row-count read and the
        // null-count read letting a row disappear mid-scan).
        let (pass, score) = compute_score(50, 40);
        assert_eq!(pass, 0);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn compute_score_is_deterministic_across_repeated_calls() {
        // Pure function — same inputs always produce the same outputs, the
        // property the sweep's "same input data produces the same score
        // every run" requirement rests on for the aggregate math (the SQL
        // side is order-independent COUNT/COUNT-DISTINCT-style aggregation,
        // never an unordered LIMIT-without-ORDER-BY scan feeding the score
        // itself — only the *issue-row sampling* uses a bounded, explicitly
        // ORDER BY'd LIMIT, see `score_completeness`/`score_uniqueness`).
        for _ in 0..25 {
            assert_eq!(compute_score(17, 63), compute_score(17, 63));
        }
    }

    #[test]
    fn max_issues_per_entity_never_exceeds_the_whole_run_budget() {
        const { assert!(MAX_ISSUES_PER_ENTITY <= MAX_ISSUES_PER_RUN) };
    }

    #[test]
    fn per_entity_budget_clamp_never_exceeds_the_per_entity_cap_or_goes_negative() {
        // Mirrors `run_sweep`'s `issue_budget.clamp(0, MAX_ISSUES_PER_ENTITY)`
        // — the budget handed to one entity is never more than
        // MAX_ISSUES_PER_ENTITY and never negative, however much run-wide
        // budget remains, including a budget already exhausted to 0 by
        // earlier entities.
        for remaining in [
            0,
            1,
            MAX_ISSUES_PER_ENTITY,
            MAX_ISSUES_PER_ENTITY + 1,
            MAX_ISSUES_PER_RUN,
        ] {
            let entity_budget = remaining.clamp(0, MAX_ISSUES_PER_ENTITY);
            assert!(entity_budget >= 0);
            assert!(entity_budget <= MAX_ISSUES_PER_ENTITY);
            assert!(entity_budget <= remaining.max(0));
        }
    }

    #[test]
    fn a_sequence_of_entities_each_consuming_their_full_budget_never_exceeds_the_run_cap() {
        // Simulates `run_sweep`'s running-budget arithmetic across enough
        // entities to exceed MAX_ISSUES_PER_RUN if the per-entity clamp/
        // decrement (coding-guidelines §9's bounding requirement) were wrong
        // — worst case, every entity has enough failing rows to consume its
        // entire allotted per-entity budget.
        let entity_count = (MAX_ISSUES_PER_RUN / MAX_ISSUES_PER_ENTITY) + 5;
        let mut issue_budget = MAX_ISSUES_PER_RUN;
        let mut total_written = 0i64;
        for _ in 0..entity_count {
            let entity_budget = issue_budget.clamp(0, MAX_ISSUES_PER_ENTITY);
            let written = entity_budget;
            total_written += written;
            issue_budget = (issue_budget - written).max(0);
        }
        assert_eq!(total_written, MAX_ISSUES_PER_RUN);
        assert_eq!(issue_budget, 0);
    }
}

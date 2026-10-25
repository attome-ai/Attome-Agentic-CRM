//! A3-T8: how often each check refuses a write, and how valid each entity's
//! stored records are.
//!
//! The record write path logs every refusal, off the request path, into
//! `validation_rejection` (`attome_records::rejection_log`); overrides are
//! security events (A3-T4). `EngineJob::ValidationScoreSweep` runs nightly
//! and writes each entity's validity score into `validation_score`: the share
//! of its live records that pass every active check, judged as the A3-T5
//! simulation judges one record. `GET /api/v1/admin/validation/stats` serves
//! both.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::business_rule_admin::RuleTestRequest;
use crate::rule_admin::{self as store, BusinessRule, RuleRow};
use crate::validation_simulation::{BATCH, Verdict, batch, verdict};

/// The default and longest rejection window, in days.
pub const DEFAULT_DAYS: u32 = 30;
pub const MAX_DAYS: u32 = 365;
/// Most rejection rows the stats return (largest counts first).
pub const MAX_REJECTION_ROWS: i64 = 1_000;

/// Refusals of one rule on one attribute through one channel.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct RuleRejections {
    pub rule_id: Uuid,
    /// The rule's display name; `None` once the rule is deleted.
    pub rule_name: Option<String>,
    pub entity: String,
    pub attribute: Option<String>,
    /// `staff`, `service`, `portal` or `system`.
    pub channel: String,
    pub rejections: i64,
    pub last_rejected_at: DateTime<Utc>,
}

/// One entity's validity score, as the last nightly sweep computed it.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct EntityValidity {
    pub entity: String,
    /// Live records checked.
    pub checked: i64,
    /// Records that pass every active check.
    pub passing: i64,
    /// Records some check could not decide (left out of the score).
    pub unknown: i64,
    /// `passing / (checked - unknown)`; `None` when nothing was decided.
    pub score: Option<f64>,
    pub computed_at: DateTime<Utc>,
}

/// `GET /api/v1/admin/validation/stats`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationStats {
    /// The start of the rejection window.
    pub since: DateTime<Utc>,
    pub rejections: Vec<RuleRejections>,
    pub entities: Vec<EntityValidity>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct StatsQuery {
    /// Days of rejections to count (default 30, at most 365).
    pub days: Option<u32>,
}

/// Validation statistics
///
/// Validation statistics. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/validation/stats",
    description = "Rejections per rule, attribute and channel over the window, and each entity's validity score from the last nightly sweep (A3-T8).",
    tag = "admin",
    params(StatsQuery),
    responses(
        (status = 200, description = "Rejections and validity scores", body = ValidationStats),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "`days` is out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn validation_stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<StatsQuery>,
) -> Result<Json<ValidationStats>, AppError> {
    stats(&state, q.days.unwrap_or(DEFAULT_DAYS))
        .await
        .map(Json)
}

/// The stats over the last `days` days.
pub async fn stats(state: &EngineState, days: u32) -> Result<ValidationStats, AppError> {
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(AppError::Validation(format!(
            "days must be between 1 and {MAX_DAYS}"
        )));
    }
    let since = Utc::now() - Duration::days(i64::from(days));
    let rejections: Vec<RuleRejections> = sqlx::query_as(
        "SELECT v.rule_ref AS rule_id, COALESCE(r.display_name, r.name) AS rule_name, \
                v.entity, v.attribute, v.channel, count(*) AS rejections, \
                max(v.rejected_at) AS last_rejected_at \
         FROM validation_rejection v \
         LEFT JOIN rule r ON r.id = v.rule_ref AND r.is_deleted = false \
         WHERE v.rejected_at >= $1 \
         GROUP BY v.rule_ref, r.display_name, r.name, v.entity, v.attribute, v.channel \
         ORDER BY rejections DESC, v.entity, v.rule_ref \
         LIMIT $2",
    )
    .bind(since)
    .bind(MAX_REJECTION_ROWS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let entities: Vec<EntityValidity> = sqlx::query_as(
        "SELECT entity, checked, passing, unknown, score, computed_at \
         FROM validation_score ORDER BY entity",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(ValidationStats {
        since,
        rejections,
        entities,
    })
}

/// One entity's counts while the sweep scans it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub checked: i64,
    pub passing: i64,
    pub unknown: i64,
}

impl Tally {
    /// Counts one record from each active check's verdict on it: any refusal
    /// fails it; otherwise any undecided check leaves it unknown.
    pub(crate) fn record(&mut self, verdicts: impl IntoIterator<Item = Verdict>) {
        self.checked += 1;
        let mut unknown = false;
        for v in verdicts {
            match v {
                Verdict::Fails(_) => return,
                Verdict::Unknown => unknown = true,
                Verdict::Passes => {}
            }
        }
        if unknown {
            self.unknown += 1;
        } else {
            self.passing += 1;
        }
    }

    /// `passing / (checked - unknown)`, `None` when nothing was decided.
    pub fn score(&self) -> Option<f64> {
        let decided = self.checked - self.unknown;
        #[allow(
            clippy::cast_precision_loss,
            reason = "record counts far below 2^52; the score is a ratio"
        )]
        (decided > 0).then(|| self.passing as f64 / decided as f64)
    }
}

/// The active rules, by entity.
async fn active_rules(
    state: &EngineState,
) -> Result<BTreeMap<String, Vec<BusinessRule>>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let rows: Vec<RuleRow> = sqlx::query_as(&format!(
        "SELECT {} FROM rule WHERE is_deleted = false AND is_active = true \
         ORDER BY entity_logicalname, display_order, id",
        store::RULE_COLUMNS
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let mut by_entity: BTreeMap<String, Vec<BusinessRule>> = BTreeMap::new();
    for rule in store::assemble_rules(&mut conn, rows).await? {
        by_entity
            .entry(rule.entity_logicalname.clone())
            .or_default()
            .push(rule);
    }
    Ok(by_entity)
}

/// Scores one entity: every live record against every rule.
async fn score_entity(
    state: &EngineState,
    entity: &str,
    rules: &[BusinessRule],
) -> Result<Option<Tally>, AppError> {
    let Some(attrs) = store::attrs_for_entity(state, entity) else {
        return Ok(None);
    };
    let now = Utc::now();
    let mut tally = Tally::default();
    let mut after = Uuid::nil();
    loop {
        let records = batch(state, entity, after).await?;
        let Some(last) = records.last() else {
            break;
        };
        after = last.id;
        let full = i64::try_from(records.len()).unwrap_or(i64::MAX) == BATCH;
        for stored in &records {
            let request = RuleTestRequest {
                record: stored.data.clone(),
                audience: None,
            };
            tally.record(rules.iter().map(|rule| {
                match crate::business_rule_admin::evaluate(rule, &attrs, &request, now) {
                    Ok(outcome) => verdict(&outcome),
                    Err(_) => Verdict::Unknown,
                }
            }));
        }
        if !full {
            break;
        }
    }
    Ok(Some(tally))
}

/// `EngineJob::ValidationScoreSweep`'s handler: rewrites every entity's
/// score from a full scan, and drops the score of an entity left with no
/// active check. Safe to retry: each run replaces the scores it computes.
/// Returns the entities scored.
pub async fn run_score_sweep(state: &EngineState) -> Result<usize, AppError> {
    let rules = active_rules(state).await?;
    let mut scored: Vec<String> = Vec::new();
    for (entity, rules) in &rules {
        let tally = match score_entity(state, entity, rules).await {
            Ok(Some(tally)) => tally,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(entity, error = %e, "validation score sweep: one entity failed, continuing");
                continue;
            }
        };
        sqlx::query(
            "INSERT INTO validation_score (entity, checked, passing, unknown, score, computed_at) \
             VALUES ($1, $2, $3, $4, $5, now()) \
             ON CONFLICT (entity) DO UPDATE SET checked = EXCLUDED.checked, \
               passing = EXCLUDED.passing, unknown = EXCLUDED.unknown, \
               score = EXCLUDED.score, computed_at = EXCLUDED.computed_at",
        )
        .bind(entity)
        .bind(tally.checked)
        .bind(tally.passing)
        .bind(tally.unknown)
        .bind(tally.score())
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        scored.push(entity.clone());
    }
    sqlx::query("DELETE FROM validation_score WHERE entity <> ALL($1)")
        .bind(rules.keys().cloned().collect::<Vec<String>>())
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    tracing::info!(entities = scored.len(), "validation scores rewritten");
    Ok(scored.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_score_counts_a_refusal_as_failing_and_undecided_apart() {
        let mut t = Tally::default();
        t.record([Verdict::Passes, Verdict::Passes]);
        t.record([Verdict::Passes, Verdict::Fails("no".into())]);
        t.record([Verdict::Unknown, Verdict::Passes]);
        t.record([Verdict::Unknown, Verdict::Fails("no".into())]);
        t.record([]);
        assert_eq!(
            t,
            Tally {
                checked: 5,
                passing: 2,
                unknown: 1
            }
        );
        assert_eq!(t.score(), Some(0.5));
        assert_eq!(Tally::default().score(), None);
    }
}

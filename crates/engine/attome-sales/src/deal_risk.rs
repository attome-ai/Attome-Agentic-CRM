//! Deal risk (roadmap D19-T1): every night each open opportunity gets a
//! risk score from 0 to 100 and the reasons behind it, stored on the deal
//! (`risk_score`, `risk_reasons`, `risk_evaluated_at`, sales pack 0014).
//!
//! Rule signals, each adding its weight when it fires:
//!
//! | Signal | Fires when | Weight |
//! |---|---|---|
//! | `no_recent_activity` | no activity about the deal for 14 days (30: double) | 20 / 30 |
//! | `close_date_pushed` | the close date moved 2 or more times | 15, +5 per push after 2, at most 30 |
//! | `missing_buyer` | no decision maker or economic buyer among the contact roles | 20 |
//! | `stalled_stage` | in its stage longer than 1.5 times the median for that stage | 20 |
//! | `overdue_close` | the close date has passed | 15 |
//!
//! The total is capped at 100. A learned risk model (O1) may later blend
//! in; the rule signals stay as the explanation.

use std::collections::HashMap;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Deals per batch.
pub const BATCH: i64 = 500;

/// What is known about one deal.
#[derive(Debug, Clone, PartialEq)]
pub struct DealFacts {
    pub last_activity: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub push_count: u32,
    pub has_buyer_role: bool,
    pub days_in_stage: Option<f64>,
    /// The median days open deals spend in this stage.
    pub stage_median_days: Option<f64>,
    pub close_date: Option<NaiveDate>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Signal {
    pub code: &'static str,
    pub weight: u32,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Risk {
    pub score: u32,
    pub signals: Vec<Signal>,
}

/// Scores one deal at `now`.
pub fn evaluate(f: &DealFacts, now: DateTime<Utc>) -> Risk {
    let mut signals = Vec::new();
    let quiet_days = (now - f.last_activity.unwrap_or(f.created_at)).num_days();
    if quiet_days >= 14 {
        signals.push(Signal {
            code: "no_recent_activity",
            weight: if quiet_days >= 30 { 30 } else { 20 },
            detail: format!("no activity for {quiet_days} days"),
        });
    }
    if f.push_count >= 2 {
        signals.push(Signal {
            code: "close_date_pushed",
            weight: (15 + 5 * (f.push_count - 2)).min(30),
            detail: format!("close date moved {} times", f.push_count),
        });
    }
    if !f.has_buyer_role {
        signals.push(Signal {
            code: "missing_buyer",
            weight: 20,
            detail: "no decision maker or economic buyer named".into(),
        });
    }
    if let (Some(days), Some(median)) = (f.days_in_stage, f.stage_median_days)
        && median > 0.0
        && days > median * 1.5
    {
        signals.push(Signal {
            code: "stalled_stage",
            weight: 20,
            detail: format!("{days:.0} days in stage against a median of {median:.0}"),
        });
    }
    if let Some(close) = f.close_date
        && close < now.date_naive()
    {
        signals.push(Signal {
            code: "overdue_close",
            weight: 15,
            detail: format!("close date {close} has passed"),
        });
    }
    let score = signals.iter().map(|s| s.weight).sum::<u32>().min(100);
    Risk { score, signals }
}

type OppRow = (
    Uuid,
    String,
    DateTime<Utc>,
    Option<f64>,
    Option<DateTime<Utc>>,
    Option<NaiveDate>,
);

/// Evaluates and stores the risk of every open deal; the number scored.
pub async fn run(db: &DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'opportunity' AND column_name = 'risk_score' \
           AND table_schema = ANY (current_schemas(false)))",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let medians: HashMap<String, f64> = sqlx::query_as::<_, (String, Option<f64>)>(
        "SELECT stage, percentile_cont(0.5) WITHIN GROUP \
             (ORDER BY EXTRACT(EPOCH FROM ($1 - stage_entered_at)) / 86400.0) \
         FROM opportunity WHERE (is_active IS NULL OR is_active = true) \
           AND stage NOT IN ('closed_won', 'closed_lost') AND stage_entered_at IS NOT NULL \
         GROUP BY stage",
    )
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .filter_map(|(stage, m)| m.map(|m| (stage, m)))
    .collect();
    let mut scored = 0;
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<OppRow> = sqlx::query_as(
            "SELECT id, COALESCE(stage, ''), created_at, close_date_push_count::float8, \
                    stage_entered_at, close_date::date \
             FROM opportunity WHERE (is_active IS NULL OR is_active = true) \
               AND COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost') AND id > $1 \
             ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else { break };
        after = last.0;
        let full = rows.len() as i64 == BATCH;
        let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
        let id_text: Vec<String> = ids.iter().map(Uuid::to_string).collect();
        let activity: HashMap<String, DateTime<Utc>> =
            sqlx::query_as::<_, (String, DateTime<Utc>)>(
                "SELECT record_id, max(COALESCE(completed_at, created_at)) FROM activity \
             WHERE entity_name = 'opportunity' AND record_id = ANY($1) \
               AND (is_active IS NULL OR is_active = true) GROUP BY record_id",
            )
            .bind(&id_text)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
        let buyers: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT opportunity_ref FROM opportunity_contact_role \
             WHERE opportunity_ref = ANY($1) AND role IN ('decision_maker', 'economic_buyer') \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (id, stage, created_at, pushes, entered, close_date) in rows {
            let facts = DealFacts {
                last_activity: activity.get(&id.to_string()).copied(),
                created_at,
                push_count: pushes.map(|p| p.max(0.0) as u32).unwrap_or(0),
                has_buyer_role: buyers.contains(&id),
                days_in_stage: entered.map(|e| (now - e).num_seconds() as f64 / 86_400.0),
                stage_median_days: medians.get(&stage).copied(),
                close_date,
            };
            let risk = evaluate(&facts, now);
            let reasons = serde_json::to_string(&risk.signals).map_err(AppError::internal)?;
            sqlx::query(
                "UPDATE opportunity SET risk_score = $2, risk_reasons = $3, risk_evaluated_at = $4 \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(f64::from(risk.score))
            .bind(reasons)
            .bind(now)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            scored += 1;
        }
        if !full {
            break;
        }
    }
    Ok(scored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn healthy() -> DealFacts {
        DealFacts {
            last_activity: Some(now() - chrono::Duration::days(2)),
            created_at: now() - chrono::Duration::days(60),
            push_count: 0,
            has_buyer_role: true,
            days_in_stage: Some(10.0),
            stage_median_days: Some(12.0),
            close_date: NaiveDate::from_ymd_opt(2026, 12, 1),
        }
    }

    #[test]
    fn a_healthy_deal_has_no_risk() {
        assert_eq!(
            evaluate(&healthy(), now()),
            Risk {
                score: 0,
                signals: vec![]
            }
        );
    }

    #[test]
    fn each_signal_adds_its_weight() {
        let quiet = DealFacts {
            last_activity: Some(now() - chrono::Duration::days(20)),
            push_count: 3,
            ..healthy()
        };
        let r = evaluate(&quiet, now());
        let codes: Vec<_> = r.signals.iter().map(|s| s.code).collect();
        assert_eq!(codes, ["no_recent_activity", "close_date_pushed"]);
        assert_eq!(r.score, 20 + 20);

        let bad = DealFacts {
            last_activity: None,
            push_count: 9,
            has_buyer_role: false,
            days_in_stage: Some(40.0),
            close_date: NaiveDate::from_ymd_opt(2026, 10, 1),
            ..healthy()
        };
        let r = evaluate(&bad, now());
        assert_eq!(r.signals.len(), 5);
        assert_eq!(r.score, 100, "capped");
    }
}

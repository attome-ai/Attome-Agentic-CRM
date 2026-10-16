//! Win/loss reviews on big closes (roadmap D25-T3). [`sweep_closes`] reads
//! deal changes off the change feed (its own cursor,
//! `attome-sales/deal-close`). When a deal's stage moved to `closed_won` or
//! `closed_lost` and its amount is at least the stage's
//! `review_amount_threshold`, it creates, as the deal's owner and through
//! the generic record writes, a draft `win_loss_review` with the outcome and
//! a snapshot of the deal's competitors, and a task for the owner due in
//! seven days. It never blocks or slows the close itself.
//!
//! Idempotent: one review per deal and outcome (reopening a deal keeps its
//! review and snapshot), and the task carries the review's id, so a retried
//! sweep adds neither twice.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use serde_json::json;
use uuid::Uuid;

/// The change-feed consumer.
pub const DEAL_CLOSE_CONSUMER: &str = "attome-sales/deal-close";

const SWEEP_BATCH: i64 = 200;

/// Days the owner has for the review.
pub const REVIEW_DUE_DAYS: i64 = 7;

/// The review outcome of a closing stage.
pub fn outcome_of(stage: &str) -> Option<&'static str> {
    match stage {
        "closed_won" => Some("won"),
        "closed_lost" => Some("lost"),
        _ => None,
    }
}

/// Whether a close is big enough to review: no threshold means no review.
pub fn needs_review(amount: Option<Decimal>, threshold: Option<Decimal>) -> bool {
    match (amount, threshold) {
        (Some(amount), Some(threshold)) => amount >= threshold,
        _ => false,
    }
}

fn task_marker(review: Uuid) -> String {
    format!("[win/loss review {review}]")
}

type DealRow = (Option<String>, Option<String>, Option<String>, Option<Uuid>);

/// Reviews one deal's close if it needs one; whether a review was created.
pub async fn review_close(state: &EngineState, deal: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let row: Option<DealRow> = sqlx::query_as(
        "SELECT stage, pipeline, amount::text, owner_ref FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(stage), pipeline, amount, Some(owner))) = row else {
        return Ok(false);
    };
    let Some(outcome) = outcome_of(&stage) else {
        return Ok(false);
    };
    let threshold: Option<Option<String>> = sqlx::query_scalar(
        "SELECT review_amount_threshold::text FROM opportunity_stage \
         WHERE stage = $1 AND ($2::text IS NULL OR pipeline IS NULL OR pipeline = $2) \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY (pipeline = $2) DESC NULLS LAST LIMIT 1",
    )
    .bind(&stage)
    .bind(&pipeline)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let parse = |v: Option<String>| v.and_then(|s| s.parse::<Decimal>().ok());
    if !needs_review(parse(amount), threshold.and_then(parse)) {
        return Ok(false);
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM win_loss_review WHERE opportunity_ref = $1 AND outcome = $2 \
           AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(deal)
    .bind(outcome)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let ctx = state.base.security.resolve_strict(owner).await?;
    let (review, created) = match existing {
        Some(id) => (id, false),
        None => {
            let snapshot: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT COALESCE(jsonb_agg(jsonb_build_object( \
                     'competitor_ref', competitor_ref, 'status', status, \
                     'threat_level', threat_level) ORDER BY id), '[]'::jsonb) \
                 FROM opportunity_competitor WHERE opportunity_ref = $1 \
                   AND (is_active IS NULL OR is_active = true)",
            )
            .bind(deal)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            let (id, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                owner,
                "win_loss_review",
                json!({
                    "opportunity_ref": deal.to_string(),
                    "outcome": outcome,
                    "competitors_snapshot": snapshot.unwrap_or_else(|| json!([])).to_string(),
                }),
            )
            .await?;
            (id, true)
        }
    };
    let marker = task_marker(review);
    let has_task: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM activity WHERE description LIKE '%' || $1 || '%')",
    )
    .bind(&marker)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !has_task {
        attome_records::entity_crud::create_record_for(
            state,
            &ctx,
            owner,
            "activity",
            json!({
                "activity_type": "task",
                "subject": format!("Win/loss review: deal {outcome}"),
                "description": format!("Fill in the review of this {outcome} deal. {marker}"),
                "entity_name": "opportunity",
                "record_id": deal.to_string(),
                "status": "open",
                "due_at": (Utc::now() + Duration::days(REVIEW_DUE_DAYS)).date_naive().to_string(),
            }),
        )
        .await?;
    }
    Ok(created)
}

/// Reviews the big closes since the cursor; reviews created.
pub async fn sweep_closes(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, DEAL_CLOSE_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('win_loss_review') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let mut created = 0;
    if installed {
        let mut deals: Vec<Uuid> = events
            .iter()
            .filter(|e| {
                e.entity_logicalname == "opportunity"
                    && e.operation() == Some(attome_core::change_feed::ChangeOperation::Update)
                    && (e.changed_attributes.is_empty()
                        || e.changed_attributes.iter().any(|a| a == "stage"))
            })
            .map(|e| e.record_id)
            .collect();
        deals.sort_unstable();
        deals.dedup();
        for deal in deals {
            if review_close(state, deal).await? {
                created += 1;
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, DEAL_CLOSE_CONSUMER, &last).await?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_closes_at_or_above_the_threshold_are_reviewed() {
        assert_eq!(outcome_of("closed_won"), Some("won"));
        assert_eq!(outcome_of("closed_lost"), Some("lost"));
        assert_eq!(outcome_of("negotiation"), None);
        let t = Some(Decimal::from(100_000));
        assert!(needs_review(Some(Decimal::from(100_000)), t));
        assert!(!needs_review(Some(Decimal::from(99_999)), t));
        assert!(!needs_review(Some(Decimal::from(500_000)), None));
        assert!(!needs_review(None, t));
    }
}

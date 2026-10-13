//! Suggestion-outcome logging (TODO-054, migration `0118`).
//!
//! **Why this is not a nice-to-have.** Every AI field suggestion is accepted,
//! edited, or rejected by a human looking at real customer data. That outcome
//! is the only per-customer ground truth for generation quality that will ever
//! exist — it cannot be reconstructed later and it cannot be bought. It is
//! free to capture from day one and impossible to capture retroactively, which
//! is the entire argument for building it alongside the first AI surface
//! rather than after it.
//!
//! **What it deliberately does not store.** No prompt text and no generated
//! text. An edit is recorded as a *distance*, not as a before/after pair. The
//! signal is "the human changed four characters"; storing the texts would make
//! this table a second copy of customer business data, inheriting the same
//! erasure obligation as the record it came from (D-358) for no additional
//! analytical value.

use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::outcome::{self, OutcomeProposal};

/// M97 Phase 1 (D-461): the `outcome.kind` every row this module
/// writes is dual-written under. Hardcoded, not threaded through
/// `SuggestionRecord` — this whole module is, by construction, the AI
/// suggestion domain (`0118`/`ai_suggestion_outcome`), so every row it
/// produces is that kind; a future non-AI-suggestion producer writes
/// `outcome` directly (see `outcome.rs`'s module doc) rather than
/// through this module.
const OUTCOME_KIND: &str = "ai_suggestion";

/// What a human did with a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionOutcome {
    Accepted,
    /// Used, after the human changed it. Always accompanied by an edit
    /// distance — an edit with no distance and a distance with no edit are
    /// both rejected by `0118`'s CHECK, because either means the writer and
    /// the reader disagree about what the row says.
    Edited {
        distance: i32,
    },
    Rejected,
}

impl SuggestionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            SuggestionOutcome::Accepted => "accepted",
            SuggestionOutcome::Edited { .. } => "edited",
            SuggestionOutcome::Rejected => "rejected",
        }
    }

    fn distance(self) -> Option<i32> {
        match self {
            SuggestionOutcome::Edited { distance } => Some(distance),
            _ => None,
        }
    }
}

/// Everything known when a suggestion is offered.
pub struct SuggestionRecord<'a> {
    pub action_id: &'a str,
    pub model_id: &'a str,
    pub prompt_version: &'a str,
    pub entity_logicalname: &'a str,
    pub field_ref: Option<&'a str>,
    pub record_id: Option<Uuid>,
    pub user_ref: Option<Uuid>,
    pub organization_ref: Option<Uuid>,
    /// The agent session this generation ran under, when there was one
    /// (D-511). A model-backed read is not in the invocation ledger (D-502),
    /// so this is what ties the generation back to the session that caused it.
    pub agent_session_ref: Option<Uuid>,
    pub latency_ms: Option<i32>,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
}

impl std::fmt::Debug for SuggestionRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuggestionRecord").finish_non_exhaustive()
    }
}

/// Records a suggestion as `pending` and returns its handle.
///
/// A row starts pending so an *abandoned* suggestion stays distinguishable
/// from a *rejected* one. Conflating them would systematically overstate
/// rejection and make every quality trend read worse than reality — a
/// measurement error that would then drive a model swap.
///
/// **Never on the request path.** The caller spawns this: a suggestion that
/// was generated but not logged is a lost data point, while a suggestion the
/// user waits an extra round trip for is a worse product. If this write fails,
/// it is logged and dropped, because failing a user's suggestion because
/// telemetry is down inverts the priority.
pub async fn record_suggestion(
    db: &PgPool,
    suggestion: &SuggestionRecord<'_>,
) -> Result<Uuid, AppError> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO ai_suggestion_outcome \
            (action_id, model_id, prompt_version, entity_logicalname, field_ref, \
             record_id, user_ref, organization_ref, latency_ms, prompt_tokens, \
             completion_tokens, agent_session_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         RETURNING id",
    )
    .bind(suggestion.action_id)
    .bind(suggestion.model_id)
    .bind(suggestion.prompt_version)
    .bind(suggestion.entity_logicalname)
    .bind(suggestion.field_ref)
    .bind(suggestion.record_id)
    .bind(suggestion.user_ref)
    .bind(suggestion.organization_ref)
    .bind(suggestion.latency_ms)
    .bind(suggestion.prompt_tokens)
    .bind(suggestion.completion_tokens)
    .bind(suggestion.agent_session_ref)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    // M97 Phase 1 (D-461) dual-write: the same row, generalized, into
    // `outcome` — sharing this row's own `id` as `regarding_id` is
    // what makes "which suggestion produced this outcome" a join instead of
    // a guess. Non-fatal on failure, same posture as the primary insert
    // above and as `read.rs`'s own caller: a missing generalized-ledger
    // entry is a worse report, not a worse product, and the primary
    // `ai_suggestion_outcome` row (the unbackfillable one) already
    // landed regardless.
    if let Err(e) = outcome::record_proposed(
        db,
        id,
        suggestion.action_id,
        &OutcomeProposal {
            kind: OUTCOME_KIND,
            entity_logicalname: Some(suggestion.entity_logicalname),
            regarding_entity: Some("ai_suggestion_outcome"),
            regarding_id: Some(id),
            model_id: Some(suggestion.model_id),
            prompt_version: Some(suggestion.prompt_version),
            rule_ref: None,
            proposed_by: suggestion.user_ref,
            organization_ref: suggestion.organization_ref,
            expected_value: None,
        },
    )
    .await
    {
        tracing::error!(
            suggestion_id = %id,
            error = %e,
            "failed to dual-write outcome for a suggestion"
        );
    }

    Ok(id)
}

/// Records what the human did.
///
/// `WHERE outcome = 'pending'` makes this idempotent-ish in the way that
/// matters: a double-submit from the UI cannot overwrite an accept with a
/// reject. The first decision wins, and `rows_affected` tells the caller
/// whether theirs was it (guidelines §4 — check `rows_affected` where zero
/// rows is meaningful).
///
/// **Only the human the suggestion was offered to may decide it**
/// (`user_ref = decided_by`). These rows are the ground truth every quality
/// comparison and model-swap decision reads, so an outcome written by anyone
/// else is poisoned evaluation data, not noise. A row with no `user_ref` is
/// decidable by nobody: `NULL = $4` is never true, and there is deliberately
/// no `OR user_ref IS NULL` fallback — an unowned suggestion's outcome is
/// unknowable, and recording a guess would be worse than recording nothing.
/// Someone else's suggestion reports `false`, exactly like an already-decided
/// one, so a caller cannot probe which suggestion ids exist.
pub async fn record_outcome(
    db: &PgPool,
    suggestion_id: Uuid,
    decided_by: Uuid,
    outcome: SuggestionOutcome,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE ai_suggestion_outcome \
            SET outcome = $2, edit_distance = $3, decided_at = NOW() \
          WHERE id = $1 AND outcome = 'pending' AND user_ref = $4",
    )
    .bind(suggestion_id)
    .bind(outcome.as_str())
    .bind(outcome.distance())
    .bind(decided_by)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if affected == 1 {
        // M97 Phase 1 (D-461) dual-write: the measurement half. `effectiveness`
        // is a coarse Phase 1 mapping — accepted used verbatim (1.0), edited
        // used after a human change (0.5, partial credit), rejected discarded
        // (0.0) — refined once a real learning consumer (M34/M96) needs a
        // finer signal than "was it usable at all".
        let effectiveness = match outcome {
            SuggestionOutcome::Accepted => 1.0,
            SuggestionOutcome::Edited { .. } => 0.5,
            SuggestionOutcome::Rejected => 0.0,
        };
        let actual_value = serde_json::json!({
            "outcome": outcome.as_str(),
            "edit_distance": outcome.distance(),
        });
        if let Err(e) =
            outcome::record_measured(db, suggestion_id, Some(actual_value), Some(effectiveness))
                .await
        {
            tracing::error!(
                suggestion_id = %suggestion_id,
                error = %e,
                "failed to dual-write outcome measurement for a suggestion"
            );
        }
    }

    Ok(affected == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `0118`'s CHECK ties `outcome = 'edited'` to a non-NULL
    /// `edit_distance`, in both directions. The Rust type has to satisfy that
    /// on both sides or every edit — or every non-edit — fails at runtime
    /// with a 23514.
    #[test]
    fn only_an_edit_carries_a_distance() {
        assert_eq!(SuggestionOutcome::Accepted.distance(), None);
        assert_eq!(SuggestionOutcome::Rejected.distance(), None);
        assert_eq!(
            SuggestionOutcome::Edited { distance: 4 }.distance(),
            Some(4)
        );
    }

    #[test]
    fn outcome_wire_values_match_the_check_constraint() {
        let migration = include_str!("../../../apps/attome/migrations/0008_modules.sql");
        for outcome in [
            SuggestionOutcome::Accepted,
            SuggestionOutcome::Edited { distance: 1 },
            SuggestionOutcome::Rejected,
        ] {
            assert!(
                migration.contains(&format!("'{}'", outcome.as_str())),
                "{} is missing from 0118's CHECK constraint",
                outcome.as_str()
            );
        }
        assert!(
            migration.contains("'pending'"),
            "the pending state must exist — without it an abandoned \
             suggestion is indistinguishable from a rejected one"
        );
    }

    /// There is no `SuggestionOutcome::Pending`. A caller cannot "decide"
    /// something back into pending, which is what keeps the abandoned/rejected
    /// distinction meaningful.
    #[test]
    fn a_decision_can_never_move_a_row_back_to_pending() {
        for outcome in [
            SuggestionOutcome::Accepted,
            SuggestionOutcome::Edited { distance: 0 },
            SuggestionOutcome::Rejected,
        ] {
            assert_ne!(outcome.as_str(), "pending");
        }
    }
}

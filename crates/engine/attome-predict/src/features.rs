//! Ticket feature extraction for `target = 'sla_breach'` — one function,
//! [`extract`], used identically by [`crate::train`] (building the labeled
//! training set from closed tickets) and [`crate::score`] (scoring open
//! tickets), so the model always sees the same feature vector shape it was
//! trained on (train/serve consistency — the one correctness property this
//! module exists to protect).
//!
//! **Every feature is a pure function of the ticket's state *at creation
//! time*, never of how it has aged since.** This is a deliberate scope cut,
//! not an oversight: an "age so far" feature would need a *point-in-time*
//! snapshot to compute correctly for a closed historical ticket (its
//! resolution age is almost tautologically correlated with whether it
//! breached — using it would make the model learn the label back from
//! itself rather than a real leading indicator), and this platform has no
//! historical point-in-time ticket-state reconstruction to compute it
//! honestly for training rows. Restricting to creation-time-fixed features
//! means a given ticket's score never changes after it is first computed,
//! which is also why `score::run_scoring_sweep` only ever scores a ticket
//! once per model version (see that module's doc comment) rather than
//! rescoring it on a schedule.
//!
//! Module plan §3's "age, count of related, M27 metric values" becomes,
//! concretely: `requester_prior_ticket_count` is the "count of related"
//! feature (a point-in-time-safe proxy: no historical state needed, since
//! "how many tickets did this requester have before this one" is a fact
//! fixed forever once the ticket exists). "Age" and live M27 metric values
//! are left out for the reason above and for the plan's own "don't
//! over-engineer feature richness for a first cut" instruction,
//! respectively — a real gap, not a hidden one; see this crate's D-473 entry.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Datelike, Timelike, Utc};
use uuid::Uuid;

/// Fixed order every feature vector this crate produces or trains against
/// uses. `model::ModelArtifact::feature_order` is stamped from this at
/// training time and checked against it at scoring time — see
/// [`fixed_feature_order`].
pub const FEATURE_KEYS: &[&str] = &[
    "priority_ord",
    "severity_ord",
    "is_incident",
    "resolution_target_hours",
    "requester_prior_ticket_count",
    "hour_of_day_created",
    "day_of_week_created",
];

pub fn fixed_feature_order() -> Vec<String> {
    FEATURE_KEYS.iter().map(|s| s.to_string()).collect()
}

fn priority_ord(priority: &str) -> f64 {
    match priority {
        "low" => 0.0,
        "medium" => 1.0,
        "high" => 2.0,
        "critical" => 3.0,
        _ => 0.0,
    }
}

fn severity_ord(severity: Option<&str>) -> f64 {
    match severity {
        Some("low") => 1.0,
        Some("medium") => 2.0,
        Some("high") => 3.0,
        Some("critical") => 4.0,
        _ => 0.0,
    }
}

/// One ticket's raw inputs, as read off `service_ticket`/`service_sla_policy` plus
/// the point-in-time-safe `requester_prior_ticket_count` subquery. `label`
/// is only meaningful (and only selected) for the training path — see
/// [`training_rows`].
#[derive(Debug, sqlx::FromRow)]
struct TicketFeatureRow {
    id: Uuid,
    priority: String,
    severity: Option<String>,
    ticket_type: Option<String>,
    resolution_target_minutes: Option<f64>,
    created_at: DateTime<Utc>,
    prior_count: i64,
    /// `resolution_due_at` if an SLA policy was ever applied — used as the
    /// prediction's `horizon_at` by `score::run_scoring_sweep`, never as a
    /// feature (it is a function of the *outcome* window, not of anything
    /// knowable independent of whether/when the ticket resolves).
    resolution_due_at: Option<DateTime<Utc>>,
    /// Training-only: `service_ticket.sla_breached`. Always `NULL` on the
    /// scoring path's query (selected as a literal `NULL::boolean` there,
    /// since an open ticket's outcome isn't known yet).
    sla_breached: Option<bool>,
}

impl TicketFeatureRow {
    fn to_vector(&self) -> Vec<f64> {
        vec![
            priority_ord(&self.priority),
            severity_ord(self.severity.as_deref()),
            if self.ticket_type.as_deref() == Some("incident") {
                1.0
            } else {
                0.0
            },
            self.resolution_target_minutes.unwrap_or(0.0) / 60.0,
            self.prior_count as f64,
            self.created_at.hour() as f64,
            self.created_at.weekday().num_days_from_monday() as f64,
        ]
    }
}

/// One labeled training example: features (in [`FEATURE_KEYS`] order) plus
/// `label` (`1` if the ticket breached its SLA, `0` otherwise — smartcore's
/// `LogisticRegression::fit` wants `Vec<i32>` class labels).
pub struct TrainingRow {
    pub features: Vec<f64>,
    pub label: i32,
}

impl std::fmt::Debug for TrainingRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrainingRow").finish_non_exhaustive()
    }
}

/// Bounded per `db-and-migrations`/guidelines §9 ("bounded batch sizes") —
/// a training run reads at most this many closed tickets. Ample for a first
/// cut; revisit only with evidence a real deployment's history exceeds it.
pub const MAX_TRAINING_ROWS: i64 = 20_000;

/// Builds the labeled training set for `target = 'sla_breach'`: every
/// resolved/closed ticket (the only tickets whose SLA outcome is actually
/// known), newest first, capped at [`MAX_TRAINING_ROWS`].
///
/// The correlated `prior_count` subquery is O(n²) in the worst case over a
/// deployment's whole ticket history; acceptable for a first cut bounded by
/// `MAX_TRAINING_ROWS`, and identical to the query [`score::open_tickets`]
/// runs per-batch — see this crate's D-473 entry for the tradeoff.
pub async fn training_rows(db: &DbPool) -> Result<Vec<TrainingRow>, AppError> {
    let rows: Vec<TicketFeatureRow> = sqlx::query_as(
        "SELECT t.id, t.priority, t.severity, t.ticket_type, \
                sp.resolution_target_minutes::double precision AS resolution_target_minutes, \
                t.created_at, t.resolution_due_at, t.sla_breached, \
                (SELECT COUNT(*) FROM service_ticket t2 \
                  WHERE t2.requester_id = t.requester_id AND t2.created_at < t.created_at) \
                  AS prior_count \
         FROM service_ticket t \
         LEFT JOIN service_sla_policy sp ON sp.id = t.sla_policy_id \
         WHERE t.status IN ('resolved', 'closed') AND t.sla_breached IS NOT NULL \
           AND (t.is_active IS NULL OR t.is_active = true) \
         ORDER BY t.created_at DESC \
         LIMIT $1",
    )
    .bind(MAX_TRAINING_ROWS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| TrainingRow {
            label: i32::from(r.sla_breached.unwrap_or(false)),
            features: r.to_vector(),
        })
        .collect())
}

/// One open ticket, ready to score: its feature vector plus the horizon
/// (`resolution_due_at`, falling back to 72h from creation when no SLA
/// policy was ever applied — same "never block on unconfigured SLA" posture
/// `sla.rs::apply_policy` itself takes for `Ok(None)`).
pub struct ScoringCandidate {
    pub ticket_id: Uuid,
    pub features: Vec<f64>,
    pub horizon_at: DateTime<Utc>,
}

impl std::fmt::Debug for ScoringCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScoringCandidate").finish_non_exhaustive()
    }
}

/// Bounded per tick, same convention as `sla::SWEEP_BATCH_SIZE`.
pub const SCORING_BATCH_SIZE: i64 = 500;

/// Open tickets (`status NOT IN ('resolved', 'closed')`) that have never
/// been scored by `model_ref`'s current row — i.e. no `prediction` row
/// exists yet for this `(model_ref, ticket)` pair. Since every feature here
/// is fixed at ticket-creation time (this module's own doc comment), a
/// ticket only ever needs one prediction per model version: a fresh
/// `model_ref` (a retrain) naturally makes every ticket eligible again.
pub async fn open_tickets(db: &DbPool, model_ref: Uuid) -> Result<Vec<ScoringCandidate>, AppError> {
    let rows: Vec<TicketFeatureRow> = sqlx::query_as(
        "SELECT t.id, t.priority, t.severity, t.ticket_type, \
                sp.resolution_target_minutes::double precision AS resolution_target_minutes, \
                t.created_at, t.resolution_due_at, NULL::boolean AS sla_breached, \
                (SELECT COUNT(*) FROM service_ticket t2 \
                  WHERE t2.requester_id = t.requester_id AND t2.created_at < t.created_at) \
                  AS prior_count \
         FROM service_ticket t \
         LEFT JOIN service_sla_policy sp ON sp.id = t.sla_policy_id \
         WHERE t.status NOT IN ('resolved', 'closed') \
           AND (t.is_active IS NULL OR t.is_active = true) \
           AND NOT EXISTS ( \
               SELECT 1 FROM prediction p \
               WHERE p.regarding_entity = 'service_ticket' AND p.regarding_id = t.id \
                 AND p.model_ref = $1 AND p.is_deleted = false \
           ) \
         ORDER BY t.created_at ASC \
         LIMIT $2",
    )
    .bind(model_ref)
    .bind(SCORING_BATCH_SIZE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| ScoringCandidate {
            ticket_id: r.id,
            horizon_at: r
                .resolution_due_at
                .unwrap_or_else(|| r.created_at + chrono::Duration::hours(72)),
            features: r.to_vector(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ordinal_is_monotonic() {
        assert!(priority_ord("low") < priority_ord("medium"));
        assert!(priority_ord("medium") < priority_ord("high"));
        assert!(priority_ord("high") < priority_ord("critical"));
    }

    #[test]
    fn severity_none_is_the_floor() {
        assert_eq!(severity_ord(None), 0.0);
        assert!(severity_ord(None) < severity_ord(Some("low")));
    }

    #[test]
    fn feature_order_matches_the_vector_this_module_builds() {
        // Pins FEATURE_KEYS' length against to_vector()'s own arity so the
        // two can't silently drift apart.
        let row = TicketFeatureRow {
            id: Uuid::now_v7(),
            priority: "high".into(),
            severity: None,
            ticket_type: Some("incident".into()),
            resolution_target_minutes: Some(120.0),
            created_at: Utc::now(),
            prior_count: 3,
            resolution_due_at: None,
            sla_breached: None,
        };
        assert_eq!(row.to_vector().len(), FEATURE_KEYS.len());
    }
}

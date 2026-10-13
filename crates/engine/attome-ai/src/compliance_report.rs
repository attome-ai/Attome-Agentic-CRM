//! D-435, simplified by D-491 — the AI compliance report bundle: models in
//! use, their approval status, token spend, acceptance rates, and outcomes
//! recorded WITHOUT provenance (which must always be zero).
//!
//! **Why "models in use" and "models with a catalog row" are two independent
//! sets, merged.** A model can appear in `ai_suggestion_outcome` (it was
//! actually invoked) without ever appearing in `ai_model` (nobody
//! registered a catalog row for it) — that mismatch is exactly the finding
//! this report exists to surface, so [`build_report`] outer-joins the two
//! rather than only listing whichever set is more convenient. A model that is
//! `in_use` and NOT `approved` is a live governance gap, not a display quirk.
//!
//! **D-491 removed the separate `ai_model_approval` entity** — approval
//! is now `ai_model.approval_status` (`pending`/`approved`/`blocked`)
//! directly on the catalog row a model was registered with. This report lost
//! `approved_for` (per-action scoping), `data_residency`, `approved_by`, and
//! `approved_at` along with it — see `document/decisions/runtime/D-491.md`
//! for what that trade-off gave up.
//!
//! **Why `outcomes_without_provenance` should always read zero.** Migration
//! `0118` makes `model_id`/`prompt_version`/`action_id` `NOT NULL`, and the
//! only writer, `telemetry::record_suggestion`, always supplies real values —
//! so this can only be non-zero via a bypass of the application (a hand-run
//! `INSERT`, `NOT NULL` notwithstanding an empty string, or a future
//! bulk-import path that doesn't go through `record_suggestion`). Checking it
//! **as data**, not as an assumption, is the point: a schema constraint that
//! is never independently verified is a claim, not a guarantee — see
//! `tests/compliance_report.rs`, which proves this reads zero on a healthy
//! fixture and non-zero once a bad row is injected directly (the one
//! sanctioned way to prove a detector fires, per `/xrm-api-first`'s "tests
//! against a throwaway database" exemption).

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComplianceModelRow {
    pub model_id: String,
    /// `true` when this model has at least one row in
    /// `ai_suggestion_outcome` — it was actually invoked.
    pub in_use: bool,
    /// `true` when a live `ai_model` catalog row names this model with
    /// `approval_status = 'approved'`.
    /// **`in_use && !approved` is the finding this report exists to catch.**
    pub approved: bool,
    pub approval_status: Option<String>,
    pub total_suggestions: i64,
    pub accepted: i64,
    pub edited: i64,
    pub rejected: i64,
    pub pending: i64,
    /// `(accepted + edited) / (accepted + edited + rejected)`. `None` when
    /// there are zero decided outcomes for this model — a rate of "0%" would
    /// misreport "everyone rejected it" when really nobody has decided yet.
    pub acceptance_rate: Option<f64>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComplianceReport {
    pub generated_at: DateTime<Utc>,
    pub models: Vec<ComplianceModelRow>,
    /// Governance-sensitive count of `ai_suggestion_outcome` rows missing
    /// model_id/prompt_version/action_id — see this module's doc comment for
    /// why this should always read zero and how it is nonetheless checked as
    /// data rather than assumed from the schema.
    pub outcomes_without_provenance: i64,
}

#[derive(sqlx::FromRow)]
struct UsageRow {
    model_id: String,
    total: i64,
    accepted: i64,
    edited: i64,
    rejected: i64,
    pending: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
}

async fn fetch_usage(db: &PgPool) -> Result<Vec<UsageRow>, AppError> {
    sqlx::query_as::<_, UsageRow>(
        "SELECT model_id, COUNT(*) AS total, COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted, COUNT(*) FILTER (WHERE outcome = 'edited') AS edited, COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected, COUNT(*) FILTER (WHERE outcome = 'pending') AS pending, COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens FROM ai_suggestion_outcome GROUP BY model_id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
struct CatalogRow {
    model_id: String,
    approval_status: String,
}

/// Every live `ai_model` catalog row, keyed by its wire identifier — a
/// `blocked`/`pending` row is still governance evidence ("this model WAS
/// registered and reviewed"), and a soft-deleted row is excluded the same way
/// every other generic-entity read excludes one (guidelines §4's
/// live/deleted predicate).
async fn fetch_catalog(db: &PgPool) -> Result<Vec<CatalogRow>, AppError> {
    sqlx::query_as::<_, CatalogRow>(
        "SELECT provider_model_id AS model_id, approval_status FROM ai_model WHERE (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Provenance is missing when any of the three `NOT NULL` columns holds an
/// empty (post-trim) string rather than a real value — the schema constraint
/// blocks `NULL`, not an empty string, so this is genuine defense in depth,
/// not a redundant re-check.
async fn count_outcomes_without_provenance(db: &PgPool) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_suggestion_outcome WHERE btrim(model_id) = '' OR btrim(prompt_version) = '' OR btrim(action_id) = ''",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Builds the whole bundle. Two independent queries plus one count, merged
/// in Rust (a `FULL OUTER JOIN` between an infra table and a provisioned
/// entity table works fine in SQL too, but merging in Rust keeps each query
/// simple enough to read on its own and keeps this function testable without
/// standing up a join).
pub async fn build_report(db: &PgPool) -> Result<ComplianceReport, AppError> {
    let usage = fetch_usage(db).await?;
    let catalog = fetch_catalog(db).await?;
    let outcomes_without_provenance = count_outcomes_without_provenance(db).await?;

    let mut by_model: std::collections::BTreeMap<String, ComplianceModelRow> = usage
        .into_iter()
        .map(|u| {
            let total_decided = u.accepted + u.edited + u.rejected;
            let acceptance_rate = if total_decided == 0 {
                None
            } else {
                Some((u.accepted + u.edited) as f64 / total_decided as f64)
            };
            (
                u.model_id.clone(),
                ComplianceModelRow {
                    model_id: u.model_id,
                    in_use: true,
                    approved: false,
                    approval_status: None,
                    total_suggestions: u.total,
                    accepted: u.accepted,
                    edited: u.edited,
                    rejected: u.rejected,
                    pending: u.pending,
                    acceptance_rate,
                    prompt_tokens: u.prompt_tokens,
                    completion_tokens: u.completion_tokens,
                },
            )
        })
        .collect();

    for c in catalog {
        let approved = c.approval_status == "approved";
        by_model
            .entry(c.model_id.clone())
            .and_modify(|row| {
                row.approved = approved;
                row.approval_status = Some(c.approval_status.clone());
            })
            .or_insert(ComplianceModelRow {
                model_id: c.model_id,
                in_use: false,
                approved,
                approval_status: Some(c.approval_status),
                total_suggestions: 0,
                accepted: 0,
                edited: 0,
                rejected: 0,
                pending: 0,
                acceptance_rate: None,
                prompt_tokens: 0,
                completion_tokens: 0,
            });
    }

    Ok(ComplianceReport {
        generated_at: Utc::now(),
        models: by_model.into_values().collect(),
        outcomes_without_provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure structural check: `in_use && !approved` must be representable —
    /// if a future refactor collapsed the two booleans into one, this
    /// governance finding would become inexpressible.
    #[test]
    fn a_model_can_be_in_use_and_unapproved_at_once() {
        let row = ComplianceModelRow {
            model_id: "shadow-model".into(),
            in_use: true,
            approved: false,
            approval_status: None,
            total_suggestions: 5,
            accepted: 3,
            edited: 0,
            rejected: 2,
            pending: 0,
            acceptance_rate: Some(0.6),
            prompt_tokens: 100,
            completion_tokens: 50,
        };
        assert!(row.in_use && !row.approved);
    }
}

//! M97 Phase 1 (D-461) — the generalized outcome ledger, `outcome`
//! (migration `0291`): what was proposed, what happened, and how far apart
//! they were, for every proposing capability the platform ships.
//!
//! **Why this crate owns it.** `attome-ai` already owns the one existing
//! producer (`ai_suggestion_outcome`, `0118`, `telemetry.rs`) and the
//! established "read reports over an outcome-shaped table"
//! precedent (`quality_monitor.rs`, `comparison_report.rs`). A future
//! producer in a different engine (M28 Phase 2's `dashboard_decision`, in
//! `attome-dashboard`) writes into this table directly by bound SQL — the same
//! "reach a table you don't own the seed of" shape `attome-dashboard::metric.rs`
//! already uses for `sql_query`, and `attome_ai::decision`'s own
//! module doc documents for the reverse direction — not by depending on this
//! crate, so no new dependency edge is needed for this table to be
//! genuinely shared.
//!
//! **Dual-write, not a view — see migration `0291`'s header for the reason.**
//! [`record_proposed`]/[`record_measured`] are called from
//! `telemetry::record_suggestion`/`record_outcome`, sharing the same row
//! `id` as the `ai_suggestion_outcome` row they accompany.
//!
//! **The CI-guard half of "if it proposes, it records an outcome row"
//! (plan §3).** [`ActionDescriptor::outcome_kind`] is the declaration;
//! [`record_proposed`] refuses to write a row whose `kind` does not match
//! what the calling action's own descriptor declares (`require_declared_kind`
//! below) — fail-closed, checked on every call, not a lint that can go stale.
//! `tests::` pins this against the live registry without a database.
//!
//! **The read surface — "proposals and their fates" (plan §3).** [`routes`]
//! is mounted as its own `EngineModel` ([`OutcomeModel`]), `MODULE_CORE`
//! rather than `MODULE_AI` — deliberately not the same gate
//! `ActionModel` uses for `/ai/suggestions/{id}/outcome` and this crate's
//! other AI-specific reports. The ledger this reads is meant to hold rows
//! from non-AI producers too (a decision proposed by a human, a rule-driven
//! classification), so a deployment without an AI license must still be able
//! to see what its core-licensed engines proposed and how it went — the same
//! "core platform machinery" gate `attome_security::model::SecurityModel` and
//! `attome_compliance::model::ComplianceModel` already use for cross-cutting
//! surfaces that must not be locked behind a paid module.

use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CORE, ModuleId};
use attome_server::authz::{Admin, Authorized};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Which engine wrote a row. `attome-ai` is the only writer so far — the
/// column exists so a future writer in another engine (`attome-dashboard` for
/// M28 Phase 2) has somewhere to say so, without this crate having to know
/// its name.
pub const SOURCE_MODULE: &str = "attome-ai";

// ── Writing ──────────────────────────────────────────────────────────────

/// Everything known when a proposal is offered, before it has been judged.
pub struct OutcomeProposal<'a> {
    /// Must match the calling action's `ActionDescriptor::outcome_kind`
    /// exactly — see `require_declared_kind`.
    pub kind: &'static str,
    pub entity_logicalname: Option<&'a str>,
    /// The producing record's own entity/table name and id — e.g.
    /// `("ai_suggestion_outcome", <same id as this row>)`. See migration
    /// `0291`'s header for why this is a different pointer from a future
    /// `dashboard_decision.regarding_entity`/`regarding_id`.
    pub regarding_entity: Option<&'a str>,
    pub regarding_id: Option<Uuid>,
    pub model_id: Option<&'a str>,
    pub prompt_version: Option<&'a str>,
    pub rule_ref: Option<&'a str>,
    pub proposed_by: Option<Uuid>,
    pub organization_ref: Option<Uuid>,
    pub expected_value: Option<Value>,
}

impl std::fmt::Debug for OutcomeProposal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutcomeProposal").finish_non_exhaustive()
    }
}

/// Looks up `action_id` in the closed, in-memory registry (`crate::
/// actions::all()` — no DB access) and confirms its descriptor declares
/// `kind`. This is the runtime enforcement half of "an action declaring
/// `outcome_kind` gets checked somewhere": a suggestion-producing action
/// that forgets to declare it, or declares a different kind than it
/// actually writes, fails the very first write instead of silently missing
/// the "proposals and their fates" report.
///
/// Takes `&str` rather than `ActionId` deliberately: `ActionId` wraps
/// `&'static str` (I-9 — the registry is closed, never assembled from a
/// borrowed/runtime string), but this function's caller
/// (`telemetry::record_suggestion`) only has `SuggestionRecord<'a>
/// .action_id: &'a str` to hand it, and every real value behind that
/// field is in fact one of the `&'static str` id constants
/// (`RECORD_SUMMARIZE` etc.) — just not provably so at this generic
/// lifetime. Comparing content (`d.id.as_str() == action_id`) needs no
/// `'static` bound and is exactly the pattern `read.rs`'s own tests
/// already use for the same comparison.
fn require_declared_kind(action_id: &str, kind: &str) -> Result<(), AppError> {
    let descriptor = crate::actions::all()
        .into_iter()
        .find(|d| d.id.as_str() == action_id)
        .ok_or_else(|| {
            AppError::internal(format!(
                "outcome::record_proposed: {action_id} is not a registered action"
            ))
        })?;
    match descriptor.outcome_kind {
        Some(declared) if declared == kind => Ok(()),
        Some(declared) => Err(AppError::internal(format!(
            "outcome::record_proposed: {action_id} declares outcome_kind \
             {declared:?}, called with {kind:?}"
        ))),
        None => Err(AppError::internal(format!(
            "outcome::record_proposed: {action_id} does not declare an \
             outcome_kind — see ActionDescriptor::outcome_kind's doc comment"
        ))),
    }
}

/// Writes the proposal half of an outcome row under the given `id` — the
/// caller generates it (`Uuid::now_v7()`, the workspace's established
/// app-side-id convention) so it can share it with a kind-specific ledger
/// row, e.g. `ai_suggestion_outcome.id`.
///
/// Same "never on the request path, log and continue" posture as
/// `telemetry::record_suggestion`'s own doc comment: this is written by
/// callers that treat a failure here as non-fatal to the user's request.
pub async fn record_proposed(
    db: &PgPool,
    id: Uuid,
    action_id: &str,
    proposal: &OutcomeProposal<'_>,
) -> Result<(), AppError> {
    require_declared_kind(action_id, proposal.kind)?;
    sqlx::query(
        "INSERT INTO outcome \
            (id, kind, source_module, entity_logicalname, regarding_entity, \
             regarding_id, model_id, prompt_version, rule_ref, proposed_by, \
             organization_ref, expected_value) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(proposal.kind)
    .bind(SOURCE_MODULE)
    .bind(proposal.entity_logicalname)
    .bind(proposal.regarding_entity)
    .bind(proposal.regarding_id)
    .bind(proposal.model_id)
    .bind(proposal.prompt_version)
    .bind(proposal.rule_ref)
    .bind(proposal.proposed_by)
    .bind(proposal.organization_ref)
    .bind(proposal.expected_value.clone())
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Writes the measurement half. `WHERE measured_at IS NULL` gives the same
/// "first decision wins" idempotency `telemetry::record_outcome`'s own
/// `WHERE outcome = 'pending'` guard does (guidelines §2 — check
/// `rows_affected` where zero rows is meaningful): a double-submit cannot
/// overwrite an already-measured row, and the caller learns whether theirs
/// was the one that landed.
pub async fn record_measured(
    db: &PgPool,
    id: Uuid,
    actual_value: Option<Value>,
    effectiveness: Option<f64>,
) -> Result<bool, AppError> {
    let affected = sqlx::query(
        "UPDATE outcome \
            SET actual_value = $2, effectiveness = $3, measured_at = NOW() \
          WHERE id = $1 AND measured_at IS NULL",
    )
    .bind(id)
    .bind(actual_value)
    .bind(effectiveness)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(affected == 1)
}

// ── Reading — "proposals and their fates" ───────────────────────────────

#[derive(sqlx::FromRow)]
struct OutcomeDbRow {
    id: Uuid,
    kind: String,
    source_module: String,
    entity_logicalname: Option<String>,
    regarding_entity: Option<String>,
    regarding_id: Option<Uuid>,
    model_id: Option<String>,
    prompt_version: Option<String>,
    rule_ref: Option<String>,
    proposed_by: Option<Uuid>,
    proposed_at: DateTime<Utc>,
    expected_value: Option<Value>,
    actual_value: Option<Value>,
    measured_at: Option<DateTime<Utc>>,
    effectiveness: Option<f64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutcomeSummaryRow {
    pub id: Uuid,
    pub kind: String,
    pub source_module: String,
    pub entity_logicalname: Option<String>,
    pub regarding_entity: Option<String>,
    pub regarding_id: Option<Uuid>,
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    pub rule_ref: Option<String>,
    pub proposed_by: Option<Uuid>,
    pub proposed_at: DateTime<Utc>,
    pub expected_value: Option<Value>,
    pub actual_value: Option<Value>,
    pub measured_at: Option<DateTime<Utc>>,
    pub effectiveness: Option<f64>,
}

impl From<OutcomeDbRow> for OutcomeSummaryRow {
    fn from(r: OutcomeDbRow) -> Self {
        Self {
            id: r.id,
            kind: r.kind,
            source_module: r.source_module,
            entity_logicalname: r.entity_logicalname,
            regarding_entity: r.regarding_entity,
            regarding_id: r.regarding_id,
            model_id: r.model_id,
            prompt_version: r.prompt_version,
            rule_ref: r.rule_ref,
            proposed_by: r.proposed_by,
            proposed_at: r.proposed_at,
            expected_value: r.expected_value,
            actual_value: r.actual_value,
            measured_at: r.measured_at,
            effectiveness: r.effectiveness,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
struct OutcomeListQuery {
    /// Restrict to one `kind` (`ai_suggestion`, …). Unfiltered by default.
    kind: Option<String>,
    source_module: Option<String>,
    regarding_entity: Option<String>,
    /// `true` — only rows still awaiting measurement; `false` — only
    /// already-measured rows; omitted — both.
    measured: Option<bool>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/outcomes` — the "proposals and their fates" list.
#[utoipa::path(
    get,
    path = "/api/v1/admin/outcomes",
    tag = "action",
    params(OutcomeListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OutcomeSummaryRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_outcomes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<OutcomeListQuery>,
) -> Result<Json<PaginatedResponse<OutcomeSummaryRow>>, AppError> {
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outcome \
          WHERE ($1::text IS NULL OR kind = $1) \
            AND ($2::text IS NULL OR source_module = $2) \
            AND ($3::text IS NULL OR regarding_entity = $3) \
            AND ($4::bool IS NULL OR (measured_at IS NULL) = $4)",
    )
    .bind(q.kind.as_deref())
    .bind(q.source_module.as_deref())
    .bind(q.regarding_entity.as_deref())
    .bind(q.measured.map(|m| !m))
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let rows: Vec<OutcomeDbRow> = sqlx::query_as(
        "SELECT id, kind, source_module, entity_logicalname, regarding_entity, \
                regarding_id, model_id, prompt_version, rule_ref, proposed_by, \
                proposed_at, expected_value, actual_value, measured_at, effectiveness \
         FROM outcome \
         WHERE ($1::text IS NULL OR kind = $1) \
           AND ($2::text IS NULL OR source_module = $2) \
           AND ($3::text IS NULL OR regarding_entity = $3) \
           AND ($4::bool IS NULL OR (measured_at IS NULL) = $4) \
         ORDER BY proposed_at DESC LIMIT $5 OFFSET $6",
    )
    .bind(q.kind.as_deref())
    .bind(q.source_module.as_deref())
    .bind(q.regarding_entity.as_deref())
    .bind(q.measured.map(|m| !m))
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items: Vec<OutcomeSummaryRow> = rows.into_iter().map(Into::into).collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(sqlx::FromRow)]
struct KindSourceCounts {
    kind: String,
    source_module: String,
    total: i64,
    measured: i64,
    avg_effectiveness: Option<f64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutcomeKindSummary {
    pub kind: String,
    pub source_module: String,
    pub total: i64,
    pub measured: i64,
    /// `total - measured` — still awaiting a verdict.
    pub pending: i64,
    pub avg_effectiveness: Option<f64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutcomeSummaryReport {
    pub generated_at: DateTime<Utc>,
    pub groups: Vec<OutcomeKindSummary>,
}

/// `GET /api/v1/admin/outcomes/summary` — "by kind, by source, acceptance
/// and effectiveness trends" (plan §3), the aggregate half of the dashboard
/// bundle. Deliberately unfiltered (unlike `list_outcomes`): the whole point
/// is one call showing every kind/source pair at once.
#[utoipa::path(
    get,
    path = "/api/v1/admin/outcomes/summary",
    tag = "action",
    responses(
        (status = 200, description = "Success", body = OutcomeSummaryReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_outcome_summary(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<OutcomeSummaryReport>, AppError> {
    let rows: Vec<KindSourceCounts> = sqlx::query_as(
        "SELECT kind, source_module, \
                COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE measured_at IS NOT NULL) AS measured, \
                AVG(effectiveness) FILTER (WHERE effectiveness IS NOT NULL) AS avg_effectiveness \
         FROM outcome \
         GROUP BY kind, source_module \
         ORDER BY kind, source_module",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let groups = rows
        .into_iter()
        .map(|r| OutcomeKindSummary {
            pending: r.total - r.measured,
            kind: r.kind,
            source_module: r.source_module,
            total: r.total,
            measured: r.measured,
            avg_effectiveness: r.avg_effectiveness,
        })
        .collect();

    Ok(Json(OutcomeSummaryReport {
        generated_at: Utc::now(),
        groups,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/outcomes", get(list_outcomes))
        .route("/api/v1/admin/outcomes/summary", get(get_outcome_summary))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_outcomes, get_outcome_summary))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// Registered via `EngineSystem::builder(state).register(OutcomeModel)` — a
/// separate `EngineModel` from `ActionModel`, same shape as
/// `DecisionExecutionModel` (`crate::decision`'s own doc comment), because
/// this surface needs `MODULE_CORE`, not `MODULE_AI`. Owns no entities:
/// `outcome` is a migration-owned infrastructure table (`0291`),
/// never reachable through generic entity CRUD, same as
/// `ai_suggestion_outcome` itself.
#[derive(Debug)]
pub struct OutcomeModel;

impl EngineModel for OutcomeModel {
    fn name(&self) -> &'static str {
        "attome-ai-outcome"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CORE
    }

    fn routes(&self) -> Router<EngineState> {
        routes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::read::RECORD_SUMMARIZE;
    use crate::descriptor::{Effect, RetryClass, RiskTier};

    /// The CI-guard invariant, pinned without a database: the one action
    /// wired to `record_proposed` today (`record.summarize`) declares
    /// exactly the `outcome_kind` its call site passes. If `read.rs` ever
    /// stops calling `.outcome_kind("ai_suggestion")` on this descriptor, or
    /// `telemetry.rs` starts passing a different kind, this fails.
    #[test]
    fn record_summarize_declares_the_kind_it_writes() {
        require_declared_kind(RECORD_SUMMARIZE, "ai_suggestion")
            .expect("record.summarize must declare outcome_kind = \"ai_suggestion\"");
    }

    /// An action with no `outcome_kind` at all — `record.get` never
    /// produces a suggestion — is refused, not silently accepted.
    #[test]
    fn an_action_with_no_declared_kind_is_refused() {
        let err = require_declared_kind(crate::actions::read::RECORD_GET, "ai_suggestion");
        assert!(err.is_err());
    }

    /// A kind mismatch is refused too — declaring one kind and writing
    /// another is exactly as much a drift bug as declaring none.
    #[test]
    fn a_mismatched_kind_is_refused() {
        let err = require_declared_kind(RECORD_SUMMARIZE, "decision");
        assert!(err.is_err());
    }

    /// An action id the registry does not know at all — defensive, should
    /// never happen from a real call site, but must still fail closed.
    #[test]
    fn an_unregistered_action_id_is_refused() {
        let err = require_declared_kind("not.a.real.action", "ai_suggestion");
        assert!(err.is_err());
    }

    /// Sanity check that every currently-registered `outcome_kind` (if any
    /// action declares one beyond `record.summarize`) is one of the values
    /// migration `0291`'s CHECK constraint allows — a descriptor declaring a
    /// kind the table would reject would fail every write with a 23514 the
    /// first time it ran, not at review time.
    #[test]
    fn every_declared_outcome_kind_is_a_value_0291_allows() {
        let migration = include_str!("../../../apps/attome/migrations/0006_engine.sql");
        for d in crate::actions::all() {
            if let Some(kind) = d.outcome_kind {
                assert!(
                    migration.contains(&format!("'{kind}'")),
                    "{}'s outcome_kind {kind:?} is missing from 0291's kind CHECK",
                    d.id
                );
            }
        }
    }

    /// `outcome_kind` does not silently loosen any other invariant this
    /// crate already enforces — `RiskTier`/`Effect` continue to mean what
    /// they meant before this field existed.
    #[test]
    fn outcome_kind_is_independent_of_risk_and_effect() {
        let d = crate::descriptor::ActionDescriptor::new(
            "test.independent",
            "d",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            attome_modules::MODULE_AI,
            &[],
        )
        .outcome_kind("ai_suggestion");
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
    }
}

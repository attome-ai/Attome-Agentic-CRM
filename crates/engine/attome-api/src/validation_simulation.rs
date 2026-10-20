//! A3-T5: what a new or tightened check does to the records already stored.
//!
//! `POST /api/v1/admin/business-rules/{id}/simulate` runs the rule over the
//! entity's live records in batches of [`BATCH`], exactly as
//! `.../{id}/test` evaluates one record, and answers how many it checked, how
//! many would be refused and the first [`FIRST_FAILING`] of those, before the
//! rule is published. A preview stops at [`PREVIEW_LIMIT`] records and says
//! so (`truncated`).
//!
//! Publishing enqueues `EngineJob::ValidationCleanupScan`, which scans every
//! live record and rewrites the rule's rows in `validation_cleanup`
//! (migration 0182): each failing record with its message and its owner, so
//! owners see their own records to fix
//! (`GET /api/v1/admin/business-rules/{id}/cleanup`). The scan is a durable
//! job, never the publish request: a full scan of a large table does not
//! belong on the request thread.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::business_rule_admin::{RuleTestRequest, RuleTestResponse};
use crate::rule_admin::{self as store, BusinessRule};

/// Records read per batch.
pub const BATCH: i64 = 500;
/// Most records a preview checks.
pub const PREVIEW_LIMIT: u64 = 10_000;
/// How many failing record ids a preview lists.
pub const FIRST_FAILING: usize = 50;

/// What a check would do to the stored records.
#[derive(Debug, Default, Clone, PartialEq, Serialize, ToSchema)]
pub struct Simulation {
    pub rule_id: Uuid,
    /// Live records checked.
    pub checked: u64,
    /// Records the check would refuse.
    pub failing: u64,
    /// Records whose condition could not be decided (an evaluation error).
    pub unknown: u64,
    /// The first failing records, in id order.
    pub failing_ids: Vec<Uuid>,
    /// The preview stopped at its limit before the end of the table.
    pub truncated: bool,
}

/// One record's verdict: refused (with the first refusing message), passing,
/// or undecided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Fails(String),
    Passes,
    Unknown,
}

/// The verdict a rule test outcome gives: any `error`-severity error
/// refuses; a warning does not.
pub(crate) fn verdict(outcome: &RuleTestResponse) -> Verdict {
    if let Some(error) = outcome.errors.iter().find(|e| e.severity == "error") {
        return Verdict::Fails(error.message.clone().unwrap_or_default());
    }
    if outcome.error.is_some() {
        return Verdict::Unknown;
    }
    Verdict::Passes
}

impl Simulation {
    /// Counts one record.
    pub(crate) fn record(&mut self, id: Uuid, verdict: &Verdict) {
        self.checked += 1;
        match verdict {
            Verdict::Fails(_) => {
                self.failing += 1;
                if self.failing_ids.len() < FIRST_FAILING {
                    self.failing_ids.push(id);
                }
            }
            Verdict::Unknown => self.unknown += 1,
            Verdict::Passes => {}
        }
    }
}

/// One live record as the scan reads it.
struct Stored {
    id: Uuid,
    owner: Option<Uuid>,
    data: Map<String, Value>,
}

/// The next batch of the entity's live records after `after`, by id.
async fn batch(state: &EngineState, entity: &str, after: Uuid) -> Result<Vec<Stored>, AppError> {
    let sql = format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id > $1 AND is_active IS NOT FALSE \
         ORDER BY id LIMIT $2",
        attome_core::quote_ident(entity)
    );
    let rows: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(after)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let data = row.as_object()?.clone();
            let id = data
                .get("id")?
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())?;
            let owner = data
                .get("owner_ref")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok());
            Some(Stored { id, owner, data })
        })
        .collect())
}

/// Runs `rule` over the stored records, calling `on_fail` for each refused
/// one, up to `limit` records (`None`: all).
async fn scan(
    state: &EngineState,
    rule: &BusinessRule,
    limit: Option<u64>,
    mut on_fail: impl FnMut(&Stored, &str),
) -> Result<Simulation, AppError> {
    let attrs = store::attrs_for_entity(state, &rule.entity_logicalname).ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{}'",
            rule.entity_logicalname
        ))
    })?;
    let now = Utc::now();
    let mut sim = Simulation {
        rule_id: rule.id,
        ..Simulation::default()
    };
    let mut after = Uuid::nil();
    loop {
        let records = batch(state, &rule.entity_logicalname, after).await?;
        let Some(last) = records.last() else {
            break;
        };
        after = last.id;
        let full = i64::try_from(records.len()).unwrap_or(i64::MAX) == BATCH;
        for stored in &records {
            if limit.is_some_and(|l| sim.checked >= l) {
                sim.truncated = true;
                return Ok(sim);
            }
            let request = RuleTestRequest {
                record: stored.data.clone(),
                audience: None,
            };
            let verdict = match crate::business_rule_admin::evaluate(rule, &attrs, &request, now) {
                Ok(outcome) => verdict(&outcome),
                Err(_) => Verdict::Unknown,
            };
            if let Verdict::Fails(message) = &verdict {
                on_fail(stored, message);
            }
            sim.record(stored.id, &verdict);
        }
        if !full {
            break;
        }
    }
    Ok(sim)
}

async fn read_rule(state: &EngineState, id: Uuid) -> Result<BusinessRule, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    store::read_rule(&mut conn, id)
        .await?
        .ok_or(AppError::NotFound)
}

/// The preview: the rule over at most [`PREVIEW_LIMIT`] stored records.
pub async fn simulate(state: &EngineState, rule_id: Uuid) -> Result<Simulation, AppError> {
    let rule = read_rule(state, rule_id).await?;
    scan(state, &rule, Some(PREVIEW_LIMIT), |_, _| {}).await
}

/// `EngineJob::ValidationCleanupScan`'s handler: scans every live record and
/// replaces the rule's clean-up rows with the records it refuses. A rule
/// deleted or deactivated since publish clears its rows. Safe to retry: each
/// run rewrites the whole set.
pub async fn run_cleanup_scan(state: &EngineState, rule_id: Uuid) -> Result<Simulation, AppError> {
    let rule = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        store::read_rule(&mut conn, rule_id).await?
    };
    let Some(rule) = rule.filter(|r| r.is_active) else {
        sqlx::query("DELETE FROM validation_cleanup WHERE rule_ref = $1")
            .bind(rule_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        return Ok(Simulation {
            rule_id,
            ..Simulation::default()
        });
    };
    let mut failing: Vec<(Uuid, Option<Uuid>, String)> = Vec::new();
    let sim = scan(state, &rule, None, |stored, message| {
        failing.push((stored.id, stored.owner, message.to_owned()));
    })
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM validation_cleanup WHERE rule_ref = $1")
        .bind(rule_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for chunk in failing.chunks(usize::try_from(BATCH).unwrap_or(500)) {
        let ids: Vec<Uuid> = chunk.iter().map(|f| f.0).collect();
        let owners: Vec<Option<Uuid>> = chunk.iter().map(|f| f.1).collect();
        let messages: Vec<String> = chunk.iter().map(|f| f.2.clone()).collect();
        sqlx::query(
            "INSERT INTO validation_cleanup (rule_ref, entity, record_id, owner_ref, message) \
             SELECT $1, $2, r.id, r.owner, r.message \
             FROM UNNEST($3::uuid[], $4::uuid[], $5::text[]) AS r(id, owner, message) \
             ON CONFLICT (rule_ref, record_id) DO NOTHING",
        )
        .bind(rule_id)
        .bind(&rule.entity_logicalname)
        .bind(&ids)
        .bind(&owners)
        .bind(&messages)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        rule_id = %rule_id,
        checked = sim.checked,
        failing = sim.failing,
        "validation clean-up queue rewritten"
    );
    Ok(sim)
}

/// One record in a rule's clean-up queue.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct CleanupItem {
    pub record_id: Uuid,
    pub entity: String,
    pub message: String,
    /// The record's owner, who is asked to fix it.
    pub owner_ref: Option<Uuid>,
    pub found_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/{id}/simulate",
    description = "Runs the rule over the entity's stored records (at most 10,000) and returns how many it would refuse and the first 50 of them, without saving anything (A3-T5).",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "evaluates the stored rule over stored records in memory only; writes nothing")))),
    responses(
        (status = 200, description = "What the rule would do to the stored records", body = Simulation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 422, description = "The rule's entity is not registered", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn simulate_rule(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Simulation>, AppError> {
    simulate(&state, id).await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules/{id}/cleanup",
    description = "The stored records the published rule refuses, as its last scan found them, newest first (A3-T5).",
    tag = "admin",
    params(("id" = Uuid, Path), OnePageQuery),
    responses(
        (status = 200, description = "The rule's clean-up queue", body = PaginatedResponse<CleanupItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn cleanup_queue(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CleanupItem>>, AppError> {
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validation_cleanup WHERE rule_ref = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<CleanupItem> = sqlx::query_as(
        "SELECT record_id, entity, message, owner_ref, found_at FROM validation_cleanup \
         WHERE rule_ref = $1 ORDER BY found_at DESC, record_id LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_simulation_counts_three_failing_of_a_hundred() {
        let mut sim = Simulation::default();
        let ids: Vec<Uuid> = (0..100u128).map(Uuid::from_u128).collect();
        for (i, id) in ids.iter().enumerate() {
            let v = if [7, 42, 99].contains(&i) {
                Verdict::Fails("amount must not be negative".into())
            } else {
                Verdict::Passes
            };
            sim.record(*id, &v);
        }
        assert_eq!(sim.checked, 100);
        assert_eq!(sim.failing, 3);
        assert_eq!(sim.failing_ids, vec![ids[7], ids[42], ids[99]]);
        assert_eq!(sim.unknown, 0);
    }

    #[test]
    fn validation_simulation_lists_at_most_fifty_failing_ids() {
        let mut sim = Simulation::default();
        for i in 0..120u128 {
            sim.record(Uuid::from_u128(i), &Verdict::Fails(String::new()));
        }
        assert_eq!(sim.failing, 120);
        assert_eq!(sim.failing_ids.len(), FIRST_FAILING);
        sim.record(Uuid::from_u128(500), &Verdict::Unknown);
        assert_eq!(sim.unknown, 1);
    }
}

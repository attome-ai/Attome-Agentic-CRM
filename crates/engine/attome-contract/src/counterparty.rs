//! Counterparty matching (roadmap W1-T3): contracts that name their
//! counterparty only as free text get a proposed account for a person to
//! confirm. The match folds both names the same way (Arabic normalised,
//! case, punctuation and runs of space folded) and takes an equal name
//! (score 1.0), else an account whose name starts the counterparty text or
//! the other way round (score 0.8, at least four characters). Two accounts
//! that match equally well are no proposal: a person picks by hand.
//!
//! The job ([`run_match`]) goes through contracts with counterparty text, no
//! `counterparty_account_ref` and no proposal yet, in batches of [`BATCH`];
//! a second run proposes nothing new. Confirming sets the contract's
//! account lookup in the same transaction as the proposal's status.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_rules::arabic::normalize_ar;
use attome_server::authz::{Admin, Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Contracts per batch.
pub const BATCH: i64 = 500;

/// The score of an exact (folded) name match.
pub const EXACT: f64 = 1.0;
/// The score of a prefix match.
pub const PREFIX: f64 = 0.8;
/// The fewest folded characters a prefix match needs.
pub const MIN_PREFIX_CHARS: usize = 4;

/// `contract.counterparty_confirm`: may confirm or dismiss a proposal.
#[derive(Debug)]
pub struct CounterpartyConfirm;

impl PrivilegeKey for CounterpartyConfirm {
    const KEY: &'static str = "contract.counterparty_confirm";
}

/// Folds a name for comparison.
pub fn fold(name: &str) -> String {
    normalize_ar(name)
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// One proposal: the account and its score.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Proposal {
    pub account: Uuid,
    pub score: f64,
}

/// The account `counterparty` names among `(id, folded name)` accounts.
pub fn propose(counterparty: &str, accounts: &[(Uuid, String)]) -> Option<Proposal> {
    let text = fold(counterparty);
    if text.is_empty() {
        return None;
    }
    let pick = |hits: Vec<Uuid>, score: f64| match hits.as_slice() {
        [account] => Some(Some(Proposal {
            account: *account,
            score,
        })),
        [] => None,
        _ => Some(None),
    };
    let exact = accounts
        .iter()
        .filter(|(_, name)| *name == text)
        .map(|(id, _)| *id)
        .collect();
    if let Some(found) = pick(exact, EXACT) {
        return found;
    }
    let prefix = accounts
        .iter()
        .filter(|(_, name)| {
            let (short, long) = if name.len() <= text.len() {
                (name.as_str(), text.as_str())
            } else {
                (text.as_str(), name.as_str())
            };
            short.chars().count() >= MIN_PREFIX_CHARS
                && long.starts_with(short)
                && long[short.len()..].starts_with(' ')
        })
        .map(|(id, _)| *id)
        .collect();
    pick(prefix, PREFIX).flatten()
}

/// What one run proposed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct MatchRun {
    pub contracts_seen: u64,
    pub proposals: u64,
}

/// Proposes accounts for unmatched counterparties. Does nothing where the
/// contract-management and CRM packs are not installed.
pub async fn run_match(db: &DbPool) -> Result<MatchRun, AppError> {
    let mut out = MatchRun::default();
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('contract') IS NOT NULL AND to_regclass('account') IS NOT NULL \
            AND to_regclass('counterparty_match_proposal') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(out);
    }
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM account          WHERE (is_active IS NULL OR is_active = true) AND name IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let accounts: Vec<(Uuid, String)> = rows
        .iter()
        .map(|(id, name)| (*id, fold(name)))
        .filter(|(_, name)| !name.is_empty())
        .collect();
    let names: std::collections::HashMap<Uuid, String> = rows.into_iter().collect();
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT c.id, c.counterparty FROM contract c \
             WHERE (c.is_active IS NULL OR c.is_active = true) \
               AND c.counterparty IS NOT NULL AND btrim(c.counterparty) <> '' \
               AND c.counterparty_account_ref IS NULL AND c.id > $1 \
               AND NOT EXISTS (SELECT 1 FROM counterparty_match_proposal p \
                               WHERE p.contract_id = c.id::text \
                                 AND (p.is_active IS NULL OR p.is_active = true)) \
             ORDER BY c.id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else { break };
        after = last.0;
        let full = rows.len() as i64 == BATCH;
        for (contract, text) in rows {
            out.contracts_seen += 1;
            let Some(p) = propose(&text, &accounts) else {
                continue;
            };
            sqlx::query(
                "INSERT INTO counterparty_match_proposal \
                   (counterparty_text, contract_id, account_id, account_name, score, status) \
                 VALUES ($1, $2, $3, $4, $5::float8::numeric, 'proposed')",
            )
            .bind(&text)
            .bind(contract.to_string())
            .bind(p.account.to_string())
            .bind(names.get(&p.account))
            .bind(p.score)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            out.proposals += 1;
        }
        if !full {
            break;
        }
    }
    Ok(out)
}

/// A proposal's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Confirm,
    Dismiss,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DecisionResult {
    pub proposal_id: Uuid,
    pub contract_id: Uuid,
    pub status: String,
}

/// Confirms a proposal (setting the contract's account) or dismisses it.
/// A proposal already decided is a conflict.
pub async fn decide(
    state: &EngineState,
    actor: Uuid,
    proposal: Uuid,
    decision: Decision,
) -> Result<DecisionResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT contract_id, account_id, status FROM counterparty_match_proposal \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(proposal)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((contract_id, account_id, status)) = row else {
        return Err(AppError::NotFound);
    };
    if status != "proposed" {
        return Err(AppError::Conflict("this proposal is already decided"));
    }
    let contract = Uuid::parse_str(&contract_id).map_err(AppError::internal)?;
    let account = Uuid::parse_str(&account_id).map_err(AppError::internal)?;
    let new_status = match decision {
        Decision::Confirm => {
            let updated = sqlx::query(
                "UPDATE contract SET counterparty_account_ref = $2, modified_at = now(), \
                 modified_by = $3, row_version = row_version + 1 \
                 WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(contract)
            .bind(account)
            .bind(actor)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if updated.rows_affected() != 1 {
                return Err(AppError::NotFound);
            }
            "confirmed"
        }
        Decision::Dismiss => "dismissed",
    };
    sqlx::query(
        "UPDATE counterparty_match_proposal SET status = $2, modified_at = now(), \
         modified_by = $3, row_version = row_version + 1 WHERE id = $1",
    )
    .bind(proposal)
    .bind(new_status)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contract",
            contract,
            AuditOperation::Update,
            "contract.counterparty_decided",
            actor,
        )
        .comment(format!(
            "counterparty match {new_status}: account {account}"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(DecisionResult {
        proposal_id: proposal,
        contract_id: contract,
        status: new_status.to_owned(),
    })
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecideBody {
    pub decision: Decision,
}

#[utoipa::path(
    post,
    path = "/api/v1/contract/counterparty-proposals/{id}/decide",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The proposal")),
    request_body = DecideBody,
    responses(
        (status = 200, description = "The proposal was confirmed (the contract's account is set) or dismissed", body = DecisionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contract.counterparty_confirm", body = ErrorResponse),
        (status = 404, description = "No such proposal or contract", body = ErrorResponse),
        (status = 409, description = "The proposal was already decided", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_decide(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CounterpartyConfirm>>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecideBody>,
) -> Result<Json<DecisionResult>, AppError> {
    Ok(Json(decide(&state, ctx.user_id, id, body.decision).await?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct RunQueued {
    /// False when a run was already queued.
    pub queued: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/contract/counterparty-match/run",
    tag = "contract",
    responses(
        (status = 202, description = "The matching job is queued", body = RunQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_run(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<(axum::http::StatusCode, Json<RunQueued>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let queued = attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::ContractCounterpartyMatch,
        "contract-counterparty-match",
    )
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "counterparty_match_proposal",
            None,
        )
        .named("contract.counterparty_match_run"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((axum::http::StatusCode::ACCEPTED, Json(RunQueued { queued })))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_decide, post_run),
    components(schemas(Decision, DecideBody, DecisionResult, RunQueued))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn accounts(names: &[&str]) -> Vec<(Uuid, String)> {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| (Uuid::from_u128(i as u128 + 1), fold(n)))
            .collect()
    }

    #[test]
    fn arabic_variant_matches_account() {
        let list = accounts(&["شركة الأمل للتجارة", "Acme Trading LLC"]);
        // Hamza dropped and taa marbuta written as ha.
        let p = propose("شركه الامل للتجاره", &list);
        assert_eq!(
            p,
            Some(Proposal {
                account: Uuid::from_u128(1),
                score: EXACT
            })
        );
        let p = propose("ACME trading", &list);
        assert_eq!(p.map(|p| p.score), Some(PREFIX));
    }

    #[test]
    fn ties_and_short_prefixes_propose_nothing() {
        let list = accounts(&["Acme Gulf", "Acme Gulf"]);
        assert_eq!(propose("acme gulf", &list), None);
        let list = accounts(&["Abc", "Acme Holdings"]);
        assert_eq!(
            propose("Abc Holdings", &list),
            None,
            "three letters is too short"
        );
        assert_eq!(propose("Acmeholdings", &list), None, "whole words only");
        assert_eq!(propose("  ", &list), None);
    }
}

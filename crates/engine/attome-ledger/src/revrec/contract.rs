//! F11-T3: revenue contracts from confirmed orders and active subscriptions.
//!
//! With the setting `revrec.contracts` on, [`sweep`] reads the change feed
//! (its own cursor, [`CONSUMER`]) after the writes committed and queues
//! `EngineJob::RevrecContractFromSource` for each order that is now
//! `confirmed` and each subscription that is now `active`. [`build_from_source`]
//! (the job) writes one `revenue_contract` per source, keyed by
//! (source_kind, source_id), and per source line its performance
//! obligations, keyed by (contract, source line, kind): from the line
//! product's revenue rule (`product.revenue_rule_ref`), one obligation with
//! the rule's pattern, or one per kind of the rule's split template with its
//! weight's share of the line; with no rule, one `point_in_time` obligation.
//! A retried job finds what it wrote and writes nothing.
//!
//! [`combine`] (`POST /api/v1/ledger/revrec/contracts/combine`) merges
//! contracts of one customer into the first: their obligations move to it and
//! the others close as `modified`. It is refused once any of their schedule
//! lines is locked.

use std::str::FromStr;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

/// The setting that turns contract creation on.
pub const CONTRACTS_SETTING: &str = "revrec.contracts";
/// The change-feed consumer.
pub const CONSUMER: &str = "attome-ledger/revrec-contracts";
/// Change events read per sweep.
const BATCH: i64 = 500;
/// The most contracts one combine merges.
const MAX_COMBINE: usize = 50;

/// The kinds and relative weights of a rule's split template:
/// `license:60, support:30, training:10`. A malformed or empty template is
/// no split. Pure.
pub fn split_template(template: Option<&str>) -> Vec<(String, Decimal)> {
    let Some(template) = template.map(str::trim).filter(|t| !t.is_empty()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for part in template.split([',', '\n', ';']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((kind, weight)) = part.split_once(':') else {
            return Vec::new();
        };
        let kind = kind.trim();
        let Ok(weight) = Decimal::from_str(weight.trim()) else {
            return Vec::new();
        };
        if kind.is_empty() || weight <= Decimal::ZERO || out.iter().any(|(k, _)| k == kind) {
            return Vec::new();
        }
        out.push((kind.to_owned(), weight));
    }
    out
}

/// `amount` shared by `weights`, each rounded to the cent, the remainder on
/// the last. Pure.
pub fn shares(amount: Decimal, weights: &[Decimal]) -> Vec<Decimal> {
    let total: Decimal = weights.iter().copied().sum();
    if weights.is_empty() || total <= Decimal::ZERO {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(weights.len());
    let mut assigned = Decimal::ZERO;
    for (i, w) in weights.iter().enumerate() {
        let share = if i + 1 == weights.len() {
            amount - assigned
        } else {
            (amount * *w / total).round_dp(2)
        };
        assigned += share;
        out.push(share);
    }
    out
}

/// Whether contract creation is on.
pub fn enabled(state: &EngineState) -> bool {
    attome_core::setting_registry()
        .get(CONTRACTS_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Queues a contract build for each order now confirmed and each
/// subscription now active since the last sweep; how many were queued.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut queued = 0;
    if enabled(state) {
        let mut seen = std::collections::HashSet::new();
        for e in &events {
            let wanted = match e.entity_logicalname.as_str() {
                "order" => "confirmed",
                "subscription" => "active",
                _ => continue,
            };
            if !matches!(
                e.operation(),
                Some(ChangeOperation::Create | ChangeOperation::Update)
            ) || !seen.insert((e.entity_logicalname.clone(), e.record_id))
            {
                continue;
            }
            let table = attome_core::quote_ident(&e.entity_logicalname);
            let status: Option<Option<String>> = sqlx::query_scalar(&format!(
                "SELECT status::text FROM {table} \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
            ))
            .bind(e.record_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if status.flatten().as_deref() != Some(wanted) {
                continue;
            }
            let job = attome_core::jobs::EngineJob::RevrecContractFromSource {
                source_kind: e.entity_logicalname.clone(),
                source_id: e.record_id,
            };
            let key = format!("revrec-contract:{}:{}", e.entity_logicalname, e.record_id);
            if attome_jobs::enqueue_dedup(&state.base.db, job, &key).await? {
                queued += 1;
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(queued)
}

/// One source line.
struct SourceLine {
    id: Uuid,
    product: Option<Uuid>,
    amount: Decimal,
}

fn decimal(text: Option<String>) -> Decimal {
    text.as_deref()
        .and_then(|t| Decimal::from_str(t).ok())
        .unwrap_or(Decimal::ZERO)
}

/// What a build wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub contract: Uuid,
    /// Obligations written now (0 on a retry).
    pub obligations_written: usize,
}

/// Builds the revenue contract of one order or subscription (the job).
pub async fn build_from_source(
    state: &EngineState,
    source_kind: &str,
    source_id: Uuid,
) -> Result<Built, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let built = build_in(&mut tx, source_kind, source_id).await?;
    attome_db::tx::commit(tx).await?;
    Ok(built)
}

async fn build_in(
    tx: &mut Transaction<'_, Postgres>,
    source_kind: &str,
    source_id: Uuid,
) -> Result<Built, AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-ledger/revrec-source:{source_kind}:{source_id}"
        ))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this source's contract is being built"));
    }
    type Header = (Option<Uuid>, Option<String>, Option<Uuid>);
    let (header, lines): (Option<Header>, Vec<SourceLine>) = match source_kind {
        "order" => {
            let header: Option<Header> = sqlx::query_as(
                "SELECT account_ref, currency, owner_ref FROM \"order\" \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            let rows: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
                "SELECT id, product_ref, line_total::text FROM order_line \
                  WHERE order_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
            )
            .bind(source_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (
                header,
                rows.into_iter()
                    .map(|(id, product, total)| SourceLine {
                        id,
                        product,
                        amount: decimal(total),
                    })
                    .collect(),
            )
        }
        "subscription" => {
            let header: Option<Header> = sqlx::query_as(
                "SELECT account_ref, currency, owner_ref FROM subscription \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            let rows: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
                "SELECT id, product_ref, \
                        (COALESCE(quantity, 1) * COALESCE(unit_price, 0))::text \
                   FROM subscription_line \
                  WHERE subscription_ref = $1 AND (is_active IS NULL OR is_active = true) \
                  ORDER BY id",
            )
            .bind(source_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (
                header,
                rows.into_iter()
                    .map(|(id, product, total)| SourceLine {
                        id,
                        product,
                        amount: decimal(total),
                    })
                    .collect(),
            )
        }
        other => {
            return Err(AppError::Validation(format!(
                "a revenue contract comes from an order or a subscription, not {other}"
            )));
        }
    };
    let Some((account, currency, owner)) = header else {
        return Err(AppError::NotFound);
    };
    let total: Decimal = lines.iter().map(|l| l.amount).sum();
    let source = source_id.to_string();
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM revenue_contract WHERE source_kind = $1 AND source_id = $2 \
           AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(source_kind)
    .bind(&source)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let contract = match existing {
        Some(id) => id,
        None => sqlx::query_scalar(&format!(
            "INSERT INTO revenue_contract (id, source_kind, source_id, customer_account_ref, \
                 currency, total_price, status, created_by, owner_ref) \
             VALUES ($1, '{source_kind}', $2, $3, $4, $5::numeric, 'open', $6, $6) RETURNING id"
        ))
        .bind(Uuid::now_v7())
        .bind(&source)
        .bind(account)
        .bind(&currency)
        .bind(total.to_string())
        .bind(owner)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?,
    };

    let mut written = 0;
    for line in &lines {
        let rule: Option<(Option<String>, Option<String>)> = match line.product {
            Some(product) => sqlx::query_as(
                "SELECT r.pattern::text, r.split_template FROM product p \
                   JOIN revenue_rule r ON r.id = p.revenue_rule_ref \
                  WHERE p.id = $1 AND (r.is_active IS NULL OR r.is_active = true)",
            )
            .bind(product)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?,
            None => None,
        };
        let pattern = rule
            .as_ref()
            .and_then(|r| r.0.clone())
            .filter(|p| PATTERNS.contains(&p.as_str()))
            .unwrap_or_else(|| "point_in_time".to_owned());
        let split = split_template(rule.as_ref().and_then(|r| r.1.as_deref()));
        let parts: Vec<(String, Decimal)> = if split.is_empty() {
            vec![("line".to_owned(), line.amount)]
        } else {
            let weights: Vec<Decimal> = split.iter().map(|(_, w)| *w).collect();
            split
                .iter()
                .map(|(k, _)| k.clone())
                .zip(shares(line.amount, &weights))
                .collect()
        };
        for (kind, amount) in parts {
            let inserted = sqlx::query(&format!(
                "INSERT INTO performance_obligation (id, revenue_contract_ref, source_line_id, \
                     product_ref, kind, pattern, allocated_amount, status, created_by, owner_ref) \
                 SELECT $1, $2, $3, $4, $5, '{pattern}', $6::numeric, 'open', $7, $7 \
                  WHERE NOT EXISTS (SELECT 1 FROM performance_obligation \
                                     WHERE revenue_contract_ref = $2 AND source_line_id = $3 \
                                       AND kind = $5 \
                                       AND (is_active IS NULL OR is_active = true))"
            ))
            .bind(Uuid::now_v7())
            .bind(contract)
            .bind(line.id.to_string())
            .bind(line.product)
            .bind(&kind)
            .bind(amount.to_string())
            .bind(owner)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            written += usize::try_from(inserted).unwrap_or(0);
        }
    }
    Ok(Built {
        contract,
        obligations_written: written,
    })
}

/// The recognition patterns a rule names.
const PATTERNS: &[&str] = &[
    "point_in_time",
    "ratable",
    "milestone",
    "usage",
    "percent_complete",
];

/// `revenue_contract.update`: who combines contracts (the revenue accountant).
pub struct RevenueContractUpdate;

impl PrivilegeKey for RevenueContractUpdate {
    const KEY: &'static str = "revenue_contract.update";
}

/// Contracts to merge.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CombineContractsBody {
    /// Two or more contracts of one customer; the first is kept.
    pub contract_ids: Vec<Uuid>,
}

/// The merged contract.
#[derive(Debug, Serialize, ToSchema)]
pub struct CombinedContract {
    pub contract_id: Uuid,
    pub merged: usize,
    pub obligations_moved: u64,
}

/// Checks a combine request. Pure.
pub fn check_combine(ids: &[Uuid]) -> Result<(), String> {
    if ids.len() < 2 {
        return Err("name at least two contracts to combine".into());
    }
    if ids.len() > MAX_COMBINE {
        return Err(format!("at most {MAX_COMBINE} contracts combine at once"));
    }
    let mut seen = std::collections::HashSet::new();
    if !ids.iter().all(|id| seen.insert(*id)) {
        return Err("a contract is named twice".into());
    }
    Ok(())
}

/// Merges contracts of one customer into the first.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/contracts/combine",
    operation_id = "revrec_contracts_combine",
    tag = "ledger",
    request_body = CombineContractsBody,
    responses(
        (status = 200, description = "The contracts are one", body = CombinedContract),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revenue_contract.update", body = ErrorResponse),
        (status = 404, description = "A contract does not exist", body = ErrorResponse),
        (status = 409, description = "A contract has a locked schedule line, or is being changed", body = ErrorResponse),
        (status = 422, description = "Fewer than two contracts, or of different customers", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn combine(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RevenueContractUpdate>>,
    Json(body): Json<CombineContractsBody>,
) -> Result<Json<CombinedContract>, AppError> {
    check_combine(&body.contract_ids).map_err(AppError::Validation)?;
    let keep = body.contract_ids[0];
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-ledger/revrec-combine:{keep}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("these contracts are being combined"));
    }
    let rows: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT id, customer_account_ref, total_price::text FROM revenue_contract \
          WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(&body.contract_ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if rows.len() != body.contract_ids.len() {
        return Err(AppError::NotFound);
    }
    let customer = rows[0].1;
    if rows.iter().any(|(_, c, _)| *c != customer) {
        return Err(AppError::Validation(
            "only contracts of one customer combine".into(),
        ));
    }
    let any_locked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM revenue_schedule_line s \
                          JOIN performance_obligation o ON o.id = s.obligation_ref \
                         WHERE o.revenue_contract_ref = ANY($1) AND s.status::text = 'locked' \
                           AND (s.is_active IS NULL OR s.is_active = true))",
    )
    .bind(&body.contract_ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if any_locked {
        return Err(AppError::Conflict(
            "a contract has a locked schedule line and can no longer be combined",
        ));
    }
    let others: Vec<Uuid> = body.contract_ids[1..].to_vec();
    let moved = sqlx::query(
        "UPDATE performance_obligation SET revenue_contract_ref = $1, modified_at = now() \
          WHERE revenue_contract_ref = ANY($2)",
    )
    .bind(keep)
    .bind(&others)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    let total: Decimal = rows.iter().map(|(_, _, t)| decimal(t.clone())).sum();
    sqlx::query(
        "UPDATE revenue_contract SET total_price = $2::numeric, modified_at = now(), \
                row_version = row_version + 1 WHERE id = $1",
    )
    .bind(keep)
    .bind(total.to_string())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE revenue_contract SET status = 'modified', is_active = false, modified_at = now(), \
                row_version = row_version + 1 WHERE id = ANY($1)",
    )
    .bind(&others)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "revenue_contract",
            keep,
            AuditOperation::Update,
            "revrec.contracts_combined",
            ctx.user_id,
        )
        .comment(format!(
            "combined {} contract(s) into {keep}: {}",
            others.len(),
            others
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(CombinedContract {
        contract_id: keep,
        merged: others.len(),
        obligations_moved: moved,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ledger/revrec/contracts/combine", post(combine))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(combine))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn revrec_split_template_reads_kinds_and_weights() {
        assert_eq!(
            split_template(Some("license:60, support:30\ntraining:10")),
            vec![
                ("license".to_owned(), dec("60")),
                ("support".to_owned(), dec("30")),
                ("training".to_owned(), dec("10")),
            ]
        );
        for bad in ["license", "license:x", "license:0", "a:1, a:2", ":5"] {
            assert!(split_template(Some(bad)).is_empty(), "{bad}");
        }
        assert!(split_template(None).is_empty());
    }

    #[test]
    fn revrec_shares_sum_exactly() {
        let parts = shares(dec("100.00"), &[dec("1"), dec("1"), dec("1")]);
        assert_eq!(parts, vec![dec("33.33"), dec("33.33"), dec("33.34")]);
        assert!(shares(dec("10"), &[]).is_empty());
        assert!(check_combine(&[Uuid::nil()]).is_err());
        let a = Uuid::now_v7();
        assert!(check_combine(&[a, a]).is_err());
        assert!(check_combine(&[a, Uuid::now_v7()]).is_ok());
    }
}

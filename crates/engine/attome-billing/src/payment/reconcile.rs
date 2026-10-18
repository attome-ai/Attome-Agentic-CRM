//! Settlement reconciliation (roadmap F5-T11).
//!
//! [`reconcile_day`] asks a gateway for the payouts it made on a day
//! (outside any transaction) and, per payout, in one transaction:
//!
//! - upserts its `gateway_payout` by gateway system and payout reference;
//! - matches the payments it settles to `customer_payment` rows by gateway
//!   reference (500 references a query): `matched` when every reference is
//!   known and the gross, fees and net agree with those payments' amounts
//!   and fees, otherwise `difference`, with the unmatched references and the
//!   expected totals in `differences`;
//! - puts the payout's fees on the change feed (`billing.gateway_fee`, with
//!   the amount, currency and day) for the ledger (W5) to post; no ledger
//!   rows are written here. A payout seen again only reports its fees again
//!   when they changed.
//!
//! The daily `BillingReconcile` job reconciles yesterday for each active
//! payment gateway; the stored query "Billing: Payouts with differences"
//! lists what needs a person.

use std::str::FromStr;

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, ChangePayload, emit_named, emit_with};
use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use super::recurring::AdapterSource;
use crate::gateway::Payout;

/// References matched per query.
const MATCH_BATCH: usize = 500;

/// What one day's reconciliation found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReconcileOutcome {
    pub payouts: usize,
    pub matched: usize,
    pub differences: usize,
}

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// Reconciles one gateway's payouts for `day`.
pub async fn reconcile_day(
    state: &EngineState,
    system_id: Uuid,
    day: NaiveDate,
    adapters: &dyn AdapterSource,
) -> Result<ReconcileOutcome, AppError> {
    let system = crate::gateway::system(state, system_id).await?;
    let gateway = adapters.adapter(&system)?;
    let credential = crate::gateway::credential(state, &system).await?;
    let payouts = gateway
        .list_payouts(&credential, day)
        .await
        .map_err(AppError::from)?;
    let actor = system.service_principal.unwrap_or_else(Uuid::nil);
    let mut outcome = ReconcileOutcome::default();
    for payout in &payouts {
        let matched = reconcile_payout(state, system_id, payout, actor).await?;
        outcome.payouts += 1;
        if matched {
            outcome.matched += 1;
        } else {
            outcome.differences += 1;
        }
    }
    Ok(outcome)
}

type KnownRow = (Option<String>, Option<String>, Option<String>);

/// One payout: upserted, matched and its fees reported; `true` when it
/// matched.
async fn reconcile_payout(
    state: &EngineState,
    system_id: Uuid,
    payout: &Payout,
    actor: Uuid,
) -> Result<bool, AppError> {
    let system_ref = system_id.to_string();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // What the payments it names add up to.
    let mut known: Vec<KnownRow> = Vec::new();
    for chunk in payout.payments.chunks(MATCH_BATCH) {
        let rows: Vec<KnownRow> = sqlx::query_as(
            "SELECT gateway_reference, amount::text, fee::text FROM customer_payment \
             WHERE gateway_system_ref = $1 AND gateway_reference = ANY($2) \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&system_ref)
        .bind(chunk.to_vec())
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        known.extend(rows);
    }
    let found: std::collections::BTreeSet<&str> =
        known.iter().filter_map(|(r, _, _)| r.as_deref()).collect();
    let unmatched: Vec<&String> = payout
        .payments
        .iter()
        .filter(|r| !found.contains(r.as_str()))
        .collect();
    let gross: Decimal = known.iter().map(|(_, a, _)| decimal(a.as_deref())).sum();
    let fees: Decimal = known.iter().map(|(_, _, f)| decimal(f.as_deref())).sum();
    let matched = unmatched.is_empty()
        && gross == payout.gross
        && fees == payout.fees
        && payout.net == payout.gross - payout.fees;
    let differences = (!matched).then(|| {
        json!({
            "unmatched_references": unmatched,
            "expected_gross": gross.to_string(),
            "expected_fees": fees.to_string(),
            "reported_gross": payout.gross.to_string(),
            "reported_fees": payout.fees.to_string(),
            "reported_net": payout.net.to_string(),
        })
        .to_string()
    });
    let status = if matched { "matched" } else { "difference" };
    let existing: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, fees::text FROM gateway_payout \
         WHERE gateway_system_ref = $1 AND payout_reference = $2 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY id LIMIT 1 FOR UPDATE",
    )
    .bind(&system_ref)
    .bind(&payout.payout_reference)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let day = payout.day.and_hms_opt(0, 0, 0).map(|d| d.and_utc());
    let (id, fees_changed) = match existing {
        Some((id, old_fees)) => {
            sqlx::query(
                "UPDATE gateway_payout SET payout_date = $2, gross = $3::numeric, \
                     fees = $4::numeric, net = $5::numeric, currency = $6, status = $7, \
                     differences = $8, payment_count = $9, modified_at = now(), \
                     row_version = row_version + 1 \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(day)
            .bind(payout.gross.to_string())
            .bind(payout.fees.to_string())
            .bind(payout.net.to_string())
            .bind(&payout.currency)
            .bind(status)
            .bind(differences.as_deref())
            .bind(i64::try_from(payout.payments.len()).unwrap_or(i64::MAX))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            emit_named(
                &mut tx,
                "gateway_payout",
                id,
                ChangeOperation::Update,
                "billing.payout.reconciled",
            )
            .await?;
            (id, decimal(old_fees.as_deref()) != payout.fees)
        }
        None => {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO gateway_payout (id, gateway_system_ref, payout_reference, \
                     payout_date, gross, fees, net, currency, status, differences, payment_count, \
                     created_by, owner_ref, owner_type, is_active, row_version) \
                 VALUES ($1, $2, $3, $4, $5::numeric, $6::numeric, $7::numeric, $8, $9, $10, \
                     $11, $12, $12, 0, true, 0)",
            )
            .bind(id)
            .bind(&system_ref)
            .bind(&payout.payout_reference)
            .bind(day)
            .bind(payout.gross.to_string())
            .bind(payout.fees.to_string())
            .bind(payout.net.to_string())
            .bind(&payout.currency)
            .bind(status)
            .bind(differences.as_deref())
            .bind(i64::try_from(payout.payments.len()).unwrap_or(i64::MAX))
            .bind(actor)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            emit_named(
                &mut tx,
                "gateway_payout",
                id,
                ChangeOperation::Create,
                "billing.payout.reconciled",
            )
            .await?;
            (id, true)
        }
    };
    if fees_changed && payout.fees > Decimal::ZERO {
        emit_with(
            &mut tx,
            "gateway_payout",
            id,
            ChangeOperation::Update,
            Some("billing.gateway_fee"),
            &ChangePayload {
                changed_attributes: vec!["fees".into()],
                before: None,
                after: Some(json!({
                    "payout_id": id,
                    "amount": payout.fees.to_string(),
                    "currency": payout.currency,
                    "day": payout.day,
                })),
            },
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    if !matched {
        tracing::warn!(payout = %payout.payout_reference, %system_id, "billing: a gateway payout does not match its payments");
    }
    Ok(matched)
}

/// Reconciles yesterday for every active payment gateway (the daily
/// `BillingReconcile` job); a gateway that fails is logged and the rest
/// still run.
pub async fn reconcile_yesterday(
    state: &EngineState,
    adapters: &dyn AdapterSource,
) -> Result<ReconcileOutcome, AppError> {
    let day = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    let systems: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
         WHERE kind = 'payment_gateway' AND COALESCE(status, 'active') = 'active' \
           AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut total = ReconcileOutcome::default();
    for system in systems {
        match reconcile_day(state, system, day, adapters).await {
            Ok(one) => {
                total.payouts += one.payouts;
                total.matched += one.matched;
                total.differences += one.differences;
            }
            Err(e) => {
                tracing::warn!(%system, error = %e, "billing: a gateway's payouts could not be reconciled");
            }
        }
    }
    Ok(total)
}

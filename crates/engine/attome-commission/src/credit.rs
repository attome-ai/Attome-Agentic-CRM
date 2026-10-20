//! Commission credits (roadmap F10-T3): from won deals, confirmed orders,
//! issued invoices and received payments, and clawbacks from credit notes
//! and refunds.
//!
//! [`sweep_won_deals`] reads opportunity changes off the change feed (its
//! own cursor, `attome-commission/credits`). For a deal at `closed_won` it
//! writes one `comp_credit` per revenue split, to the split member's
//! participation in a published plan with a `split_amount` component, for
//! the split's stored amount (D7-T4; never recomputed here). A deal with no
//! splits credits its owner with the deal amount. Credits are keyed by
//! source (`split`, the split id), so a replayed event writes nothing twice.
//!
//! The credit is dated on the deal's close date (today when it has none)
//! and lands in the period containing that date; when that period is
//! approved or locked it lands in the next open one, with a zero
//! `comp_adjustment` naming the locked period it belonged to (F10-T7).
//! Amounts stay in the deal's currency: no exchange rates exist yet.
//!
//! The same sweep credits the other sources, each to the participation
//! whose plan measures it: a `confirmed` order its owner (`order_amount`,
//! the grand total); an issued invoice (`invoice_amount`, the net total) and
//! a `succeeded` customer payment (`payment_amount`) the owner of the
//! account they belong to. An issued credit note, and a `succeeded` refund,
//! reverses each credit of the invoice or payment it corrects with a
//! negative credit (`reverses_credit_ref`), when the original credit is no
//! older than `commission.clawback_days` (default 180); an older one stands.
//! Every credit is keyed by its source, so a replay writes nothing twice.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{NaiveDate, Utc};
use uuid::Uuid;

/// The change-feed consumer that writes credits.
pub const CREDIT_CONSUMER: &str = "attome-commission/credits";

const SWEEP_BATCH: i64 = 200;

/// One credit to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSource {
    pub user: Uuid,
    /// `split` (or `order`, `invoice`, `payment` as those sources land).
    pub kind: &'static str,
    pub source_id: String,
    /// Decimal text.
    pub amount: String,
    pub currency: Option<String>,
    pub credited_on: NaiveDate,
    /// The credit a clawback reverses.
    pub reverses: Option<Uuid>,
}

/// The credits a won deal gives: one per revenue split with a member user,
/// or the owner's whole amount when it has no splits.
pub fn won_deal_credits(
    deal: Uuid,
    owner: Option<Uuid>,
    deal_amount: Option<String>,
    currency: Option<String>,
    credited_on: NaiveDate,
    splits: &[(Uuid, Option<Uuid>, Option<String>)],
) -> Vec<CreditSource> {
    if splits.is_empty() {
        return match (owner, deal_amount) {
            (Some(user), Some(amount)) => vec![CreditSource {
                user,
                kind: "split",
                source_id: format!("{deal}:owner"),
                amount,
                currency,
                credited_on,
                reverses: None,
            }],
            _ => Vec::new(),
        };
    }
    splits
        .iter()
        .filter_map(|(split, user, amount)| {
            Some(CreditSource {
                user: (*user)?,
                kind: "split",
                source_id: split.to_string(),
                amount: amount.clone()?,
                currency: currency.clone(),
                credited_on,
                reverses: None,
            })
        })
        .collect()
}

/// The participation a credit goes to: the user's in the latest published
/// plan version that measures `measure` and covers the date.
async fn participant_for(
    db: &attome_db::DbPool,
    user: Uuid,
    measure: &str,
    on: NaiveDate,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT p.id FROM plan_participant p \
         JOIN comp_plan_version v ON v.id = p.plan_version_ref \
         WHERE p.user_ref = $1 AND v.published_at IS NOT NULL \
           AND (p.is_active IS NULL OR p.is_active = true) \
           AND (v.is_active IS NULL OR v.is_active = true) \
           AND (p.starts_on IS NULL OR p.starts_on::date <= $3) \
           AND (p.ends_on IS NULL OR p.ends_on::date >= $3) \
           AND EXISTS (SELECT 1 FROM comp_component c WHERE c.plan_version_ref = v.id \
               AND c.measure = $2 AND (c.is_active IS NULL OR c.is_active = true)) \
         ORDER BY v.published_at DESC, p.id LIMIT 1",
    )
    .bind(user)
    .bind(measure)
    .bind(on)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Writes one credit unless the participant already has one for the same
/// source; whether a row was written.
pub async fn credit_from_source(
    state: &EngineState,
    participant: Uuid,
    source: &CreditSource,
) -> Result<bool, AppError> {
    let Some((period, locked_original)) =
        crate::close::late_credit_target(&state.base.db, source.credited_on).await?
    else {
        tracing::warn!(
            %participant,
            source = %source.source_id,
            on = %source.credited_on,
            "commission credit: no open period for the credit's date; not written"
        );
        return Ok(false);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-commission/credit:{participant}:{}:{}",
            source.kind, source.source_id
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this credit is being written by another worker",
        ));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM comp_credit WHERE participant_ref = $1 \
             AND source_kind = $2 AND source_id = $3 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(participant)
    .bind(source.kind)
    .bind(&source.source_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO comp_credit \
           (participant_ref, period_ref, source_kind, source_id, amount, currency, credited_on, \
            owner_ref, reverses_credit_ref) \
         VALUES ($1, $2, $3, $4, $5::numeric, $6, $7, $8, $9)",
    )
    .bind(participant)
    .bind(period)
    .bind(source.kind)
    .bind(&source.source_id)
    .bind(&source.amount)
    .bind(&source.currency)
    .bind(source.credited_on)
    .bind(source.user)
    .bind(source.reverses)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(original) = locked_original {
        sqlx::query(
            "INSERT INTO comp_adjustment (participant_ref, period_ref, amount, reason, owner_ref) \
             VALUES ($1, $2, 0, $3, $4)",
        )
        .bind(participant)
        .bind(period)
        .bind(format!(
            "late credit {} {} dated {} belongs to closed period {original}",
            source.kind, source.source_id, source.credited_on
        ))
        .bind(source.user)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    // F10-T9: the period's preview catches up with the new credit.
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::CommissionRecalcPreview { period_id: period },
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

type DealRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
);

/// Credits one deal if it is won; credits written.
pub async fn credit_won_deal(state: &EngineState, deal: Uuid) -> Result<u64, AppError> {
    let db = &state.base.db;
    let row: Option<DealRow> = sqlx::query_as(
        "SELECT stage, owner_ref, amount::text, currency, close_date::date FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((stage, owner, amount, currency, close_date)) = row else {
        return Ok(0);
    };
    if stage.as_deref() != Some("closed_won") {
        return Ok(0);
    }
    let splits: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT s.id, m.user_ref, s.amount::text FROM opportunity_split s \
         JOIN opportunity_team_member m ON m.id = s.member_ref \
         LEFT JOIN sales_split_type t ON t.id = s.split_type_ref \
         WHERE s.opportunity_ref = $1 AND COALESCE(t.counts_as_revenue, true) \
           AND (s.is_active IS NULL OR s.is_active = true) ORDER BY s.id",
    )
    .bind(deal)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let on = close_date.unwrap_or_else(|| Utc::now().date_naive());
    let mut written = 0;
    for source in won_deal_credits(deal, owner, amount, currency, on, &splits) {
        let Some(participant) = participant_for(db, source.user, "split_amount", on).await? else {
            continue;
        };
        if credit_from_source(state, participant, &source).await? {
            written += 1;
        }
    }
    Ok(written)
}

/// Credits every deal that changed and is won; credits written.
pub async fn sweep_won_deals(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, CREDIT_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    // Without the packs that define these tables there is nothing to do;
    // the cursor still moves past the batch.
    let installed: bool = sqlx::query_scalar(
        "SELECT bool_and(to_regclass(t) IS NOT NULL) FROM unnest($1::text[]) AS t",
    )
    .bind(&["comp_credit", "opportunity_split"][..])
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CREDIT_CONSUMER, &last).await?;
        return Ok(0);
    }
    let mut changed: Vec<(String, Uuid)> = events
        .iter()
        .filter(|e| {
            matches!(
                e.entity_logicalname.as_str(),
                "opportunity" | "order" | "invoice" | "customer_payment" | "payment_refund"
            )
        })
        .map(|e| (e.entity_logicalname.clone(), e.record_id))
        .collect();
    changed.sort_unstable();
    changed.dedup();
    let mut written = 0;
    for (entity, id) in changed {
        written += if entity == "opportunity" {
            credit_won_deal(state, id).await?
        } else {
            credit_business_source(state, &entity, id).await?
        };
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, CREDIT_CONSUMER, &last).await?;
    Ok(written)
}

/// Whether a reversal on `on` still claws back a credit dated `original`,
/// with a window of `days`. Pure.
pub fn in_clawback_window(original: NaiveDate, on: NaiveDate, days: i64) -> bool {
    on >= original && (on - original).num_days() <= days
}

/// The clawback window, `commission.clawback_days`.
fn clawback_days(state: &EngineState) -> i64 {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("commission.clawback_days")
        .and_then(|d| store.resolve(d, None, None).0.as_i64())
        .unwrap_or(180)
}

/// Whether the deployment has `table` (its pack is installed).
async fn has_table(db: &attome_db::DbPool, table: &str) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// The owner of an account, who takes credit for its invoices and payments.
async fn account_owner(
    db: &attome_db::DbPool,
    account: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let Some(account) = account else {
        return Ok(None);
    };
    let owner: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT owner_ref FROM account WHERE id = $1")
            .bind(account)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(owner.flatten())
}

/// Writes `source` to the user's participation measuring `measure`.
async fn credit_measure(
    state: &EngineState,
    measure: &str,
    source: &CreditSource,
) -> Result<u64, AppError> {
    let Some(participant) =
        participant_for(&state.base.db, source.user, measure, source.credited_on).await?
    else {
        return Ok(0);
    };
    Ok(u64::from(
        credit_from_source(state, participant, source).await?,
    ))
}

type CreditRow = (Uuid, Uuid, Uuid, NaiveDate, Option<String>);

/// Reverses each credit of `original_kind`/`original_id` still inside the
/// window, with `amount` (positive text) taken off.
async fn claw_back(
    state: &EngineState,
    kind: &'static str,
    source_id: Uuid,
    original_kind: &str,
    original_id: Uuid,
    amount: &str,
    on: NaiveDate,
) -> Result<u64, AppError> {
    let credits: Vec<CreditRow> = sqlx::query_as(
        "SELECT id, participant_ref, owner_ref, credited_on, currency FROM comp_credit \
          WHERE source_kind = $1 AND source_id = $2 AND reverses_credit_ref IS NULL \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(original_kind)
    .bind(original_id.to_string())
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let window = clawback_days(state);
    let mut written = 0;
    for (credit, participant, user, credited_on, currency) in credits {
        if !in_clawback_window(credited_on, on, window) {
            continue;
        }
        let source = CreditSource {
            user,
            kind,
            source_id: source_id.to_string(),
            amount: format!("-{}", amount.trim_start_matches('-')),
            currency,
            credited_on: on,
            reverses: Some(credit),
        };
        if credit_from_source(state, participant, &source).await? {
            written += 1;
        }
    }
    Ok(written)
}

type OrderRow = (Option<String>, Option<Uuid>, Option<String>, Option<String>);
type InvoiceRow = (
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
);
type PaymentRow = (
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
);
type RefundRow = (Option<String>, Option<Uuid>, Option<String>);

/// Credits (or claws back) one changed order, invoice, payment or refund;
/// credits written.
pub async fn credit_business_source(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<u64, AppError> {
    let db = &state.base.db;
    let table = if entity == "order" { "order" } else { entity };
    if !has_table(db, table).await? {
        return Ok(0);
    }
    let today = Utc::now().date_naive();
    match entity {
        "order" => {
            let row: Option<OrderRow> = sqlx::query_as(
                "SELECT status, owner_ref, grand_total::text, currency FROM \"order\" \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            let Some((Some(status), Some(user), Some(amount), currency)) = row else {
                return Ok(0);
            };
            if status != "confirmed" {
                return Ok(0);
            }
            let source = CreditSource {
                user,
                kind: "order",
                source_id: id.to_string(),
                amount,
                currency,
                credited_on: today,
                reverses: None,
            };
            credit_measure(state, "order_amount", &source).await
        }
        "invoice" => {
            let row: Option<InvoiceRow> = sqlx::query_as(
                "SELECT kind, status, account_ref, original_invoice_ref, net_total::text, \
                        currency, issued_date FROM invoice \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            let Some((kind, Some(status), account, original, Some(amount), currency, issued)) = row
            else {
                return Ok(0);
            };
            if !matches!(status.as_str(), "issued" | "sent" | "paid" | "overdue") {
                return Ok(0);
            }
            let on = issued.unwrap_or(today);
            match kind.as_deref() {
                Some("credit_note") => match original {
                    Some(original) => {
                        claw_back(state, "credit_note", id, "invoice", original, &amount, on).await
                    }
                    None => Ok(0),
                },
                Some("invoice") | None => {
                    let Some(user) = account_owner(db, account).await? else {
                        return Ok(0);
                    };
                    let source = CreditSource {
                        user,
                        kind: "invoice",
                        source_id: id.to_string(),
                        amount,
                        currency,
                        credited_on: on,
                        reverses: None,
                    };
                    credit_measure(state, "invoice_amount", &source).await
                }
                _ => Ok(0),
            }
        }
        "customer_payment" => {
            let row: Option<PaymentRow> = sqlx::query_as(
                "SELECT status, payer_account_ref, amount::text, currency, received_on \
                   FROM customer_payment WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            let Some((Some(status), account, Some(amount), currency, received)) = row else {
                return Ok(0);
            };
            if status != "succeeded" {
                return Ok(0);
            }
            let Some(user) = account_owner(db, account).await? else {
                return Ok(0);
            };
            let source = CreditSource {
                user,
                kind: "payment",
                source_id: id.to_string(),
                amount,
                currency,
                credited_on: received.unwrap_or(today),
                reverses: None,
            };
            credit_measure(state, "payment_amount", &source).await
        }
        "payment_refund" => {
            let row: Option<RefundRow> = sqlx::query_as(
                "SELECT status, payment_ref, amount::text FROM payment_refund \
                  WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            let Some((Some(status), Some(payment), Some(amount))) = row else {
                return Ok(0);
            };
            if status != "succeeded" {
                return Ok(0);
            }
            claw_back(state, "refund", id, "payment", payment, &amount, today).await
        }
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 1).unwrap_or_default()
    }

    #[test]
    fn split_amounts_credit_each_participant() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let (s1, s2) = (Uuid::from_u128(11), Uuid::from_u128(12));
        let credits = won_deal_credits(
            Uuid::from_u128(9),
            Some(a),
            Some("1000".into()),
            Some("SAR".into()),
            day(),
            &[
                (s1, Some(a), Some("600.00".into())),
                (s2, Some(b), Some("400.00".into())),
            ],
        );
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].user, a);
        assert_eq!(credits[0].amount, "600.00");
        assert_eq!(credits[1].source_id, s2.to_string());
    }

    #[test]
    fn a_deal_without_splits_credits_its_owner_once() {
        let owner = Uuid::from_u128(1);
        let deal = Uuid::from_u128(9);
        let credits = won_deal_credits(deal, Some(owner), Some("500".into()), None, day(), &[]);
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].source_id, format!("{deal}:owner"));
        assert!(won_deal_credits(deal, None, Some("500".into()), None, day(), &[]).is_empty());
    }

    #[test]
    fn clawback_outside_window_is_ignored() {
        let credited = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap_or_default();
        let inside = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap_or_default();
        let outside = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap_or_default();
        assert!(in_clawback_window(credited, inside, 180));
        assert!(!in_clawback_window(credited, outside, 180));
        assert!(
            !in_clawback_window(inside, credited, 180),
            "a reversal never predates its credit"
        );
    }

    #[test]
    fn a_split_without_a_member_user_or_amount_credits_nobody() {
        let credits = won_deal_credits(
            Uuid::from_u128(9),
            None,
            None,
            None,
            day(),
            &[
                (Uuid::from_u128(11), None, Some("1".into())),
                (Uuid::from_u128(12), Some(Uuid::from_u128(1)), None),
            ],
        );
        assert!(credits.is_empty());
    }
}

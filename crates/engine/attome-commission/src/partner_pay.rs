//! Partner pay (roadmap F10-T12): a partner takes part in a plan like a
//! seller, through the same credits, run and statement lines, with
//! `plan_participant.partner_account_ref` in place of `user_ref`.
//!
//! A won deal that names a partner (`opportunity.partner_account_ref`, F9)
//! credits that partner's participation in a published plan with a
//! `partner_referral`, `partner_margin` or `rebate` component measuring
//! `split_amount`. The credit has no owner, so no seller's record rules
//! reach it. A partner reads only its own statement: [`partner_statement`]
//! takes the account the portal session resolved, never one the caller names.

use attome_core::EngineState;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use chrono::NaiveDate;
use uuid::Uuid;

use crate::credit::{CreditSource, write_credit};
use crate::statement::{CommissionStatementRow, row_from_note, sources_union};

/// The component kinds that pay a partner.
const PARTNER_KINDS: [&str; 3] = ["partner_referral", "partner_margin", "rebate"];

/// Whether a participation names exactly one payee. Pure.
pub fn one_payee(user: Option<Uuid>, partner: Option<Uuid>) -> bool {
    user.is_some() != partner.is_some()
}

/// The first participant of `version` naming no payee or two, for the
/// publish step's refusal.
pub async fn invalid_participant(
    db: &attome_db::DbPool,
    version: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM plan_participant \
         WHERE plan_version_ref = $1 AND (user_ref IS NULL) = (partner_account_ref IS NULL) \
           AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT 1",
    )
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// The partner's participation that a deal on `on` credits.
async fn participant_for_partner(
    db: &attome_db::DbPool,
    partner: Uuid,
    on: NaiveDate,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT p.id FROM plan_participant p \
         JOIN comp_plan_version v ON v.id = p.plan_version_ref \
         WHERE p.partner_account_ref = $1 AND v.published_at IS NOT NULL \
           AND (p.is_active IS NULL OR p.is_active = true) \
           AND (v.is_active IS NULL OR v.is_active = true) \
           AND (p.starts_on IS NULL OR p.starts_on::date <= $2) \
           AND (p.ends_on IS NULL OR p.ends_on::date >= $2) \
           AND EXISTS (SELECT 1 FROM comp_component c WHERE c.plan_version_ref = v.id \
               AND c.measure = 'split_amount' AND c.kind = ANY($3) \
               AND (c.is_active IS NULL OR c.is_active = true)) \
         ORDER BY v.published_at DESC, p.id LIMIT 1",
    )
    .bind(partner)
    .bind(on)
    .bind(&PARTNER_KINDS[..])
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Credits the partner a won deal names, when the partner pack is installed
/// and the partner has a plan; credits written.
pub async fn credit_partner_deal(
    state: &EngineState,
    deal: Uuid,
    amount: Option<String>,
    currency: Option<String>,
    on: NaiveDate,
) -> Result<u64, AppError> {
    let db = &state.base.db;
    let Some(amount) = amount else {
        return Ok(0);
    };
    let named: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'opportunity' \
            AND column_name = 'partner_account_ref')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !named {
        return Ok(0);
    }
    let partner: Option<Uuid> =
        sqlx::query_scalar("SELECT partner_account_ref FROM opportunity WHERE id = $1")
            .bind(deal)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let Some(partner) = partner else {
        return Ok(0);
    };
    let Some(participant) = participant_for_partner(db, partner, on).await? else {
        return Ok(0);
    };
    let source = CreditSource {
        user: Uuid::nil(),
        kind: "partner_deal",
        source_id: deal.to_string(),
        amount,
        currency,
        credited_on: on,
        reverses: None,
    };
    Ok(u64::from(
        write_credit(state, participant, &source, None).await?,
    ))
}

/// One period's statement for a partner account, every row of its own
/// participations. `NotFound` when it has none in the period, so another
/// partner's period reads like one that does not exist.
pub async fn partner_statement(
    state: &EngineState,
    partner: Uuid,
    period: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<CommissionStatementRow>, AppError> {
    let window = page.window();
    let db = &state.base.db;
    let union = sources_union();
    let scoped = format!(
        "({union}) u WHERE u.participant_ref IN \
         (SELECT id FROM plan_participant WHERE partner_account_ref = $2 \
            AND (is_active IS NULL OR is_active = true))"
    );
    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {scoped}"))
        .bind(period)
        .bind(partner)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if total == 0 {
        return Err(AppError::NotFound);
    }
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(u) FROM {scoped} ORDER BY u.created_at DESC, u.id LIMIT $3 OFFSET $4"
    ))
    .bind(period)
    .bind(partner)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let items = rows.iter().filter_map(row_from_note).collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_participation_names_one_payee() {
        let id = Some(Uuid::nil());
        assert!(one_payee(id, None));
        assert!(one_payee(None, id));
        assert!(!one_payee(None, None));
        assert!(!one_payee(id, id));
    }
}

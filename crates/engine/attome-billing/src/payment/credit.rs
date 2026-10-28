//! Credit limits and credit hold (roadmap F5-T12).
//!
//! An account's `credit_limit` and `credit_hold` (billing pack `0002`)
//! decide whether more may be sold to it on credit. [`credit_check`] is what
//! order confirmation (D10) calls: it reads the limit and the hold from the
//! account and the open balance from the stored `open_total` of the
//! account's issued, sent and overdue invoices, and applies [`decide`]:
//!
//! - an account on hold is refused;
//! - with a limit, the open balance plus the new amount must stay within it;
//! - with `billing.credit.block_overdue` on, an account with an overdue
//!   invoice is refused.
//!
//! The open balance is per currency. With a limit and open invoices in more
//! than one currency the check refuses, since the limit cannot be compared
//! with them; an account without a limit is never refused for that.
//!
//! **Credit hold by rule.** With `billing.credit.auto_hold` on, the nightly
//! sweep ([`hold_overdue`]) sets `credit_hold` on every account with an
//! invoice overdue by more than `billing.credit.hold_after_days` (default
//! 30), through the record engine as the account's owner, so audit and
//! record rules apply. Clearing a hold is a person's update of the account.
//!
//! `GET /api/v1/billing/accounts/{id}/credit` (`payment.read`, and read
//! access to the account) shows the check for no new amount.

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Most accounts one nightly sweep puts on hold.
const HOLD_BATCH: i64 = 500;

/// The credit settings as the deployment has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditSettings {
    pub block_overdue: bool,
    pub auto_hold: bool,
    pub hold_after_days: i64,
}

impl Default for CreditSettings {
    fn default() -> Self {
        Self {
            block_overdue: false,
            auto_hold: false,
            hold_after_days: 30,
        }
    }
}

/// Reads `billing.credit.*`.
pub fn settings(state: &EngineState) -> CreditSettings {
    let store = state.settings.load();
    let registry = attome_core::setting_registry();
    let value = |key: &str| registry.get(key).map(|d| store.resolve(d, None, None).0);
    let defaults = CreditSettings::default();
    CreditSettings {
        block_overdue: value("billing.credit.block_overdue")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.block_overdue),
        auto_hold: value("billing.credit.auto_hold")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.auto_hold),
        hold_after_days: value("billing.credit.hold_after_days")
            .and_then(|v| v.as_i64())
            .unwrap_or(defaults.hold_after_days),
    }
}

/// Why a check refuses.
pub const REASON_HOLD: &str = "the account is on credit hold";
pub const REASON_LIMIT: &str = "the open balance and this amount exceed the credit limit";
pub const REASON_OVERDUE: &str = "the account has an overdue invoice";
pub const REASON_CURRENCIES: &str =
    "the account has open invoices in several currencies, so the credit limit cannot be compared";

/// Whether more may be sold on credit, and why not. Pure.
pub fn decide(
    limit: Option<Decimal>,
    open: Decimal,
    extra: Decimal,
    hold: bool,
    overdue: bool,
    block_overdue: bool,
) -> (bool, Option<&'static str>) {
    if hold {
        return (false, Some(REASON_HOLD));
    }
    if let Some(limit) = limit
        && open + extra > limit
    {
        return (false, Some(REASON_LIMIT));
    }
    if overdue && block_overdue {
        return (false, Some(REASON_OVERDUE));
    }
    (true, None)
}

/// One credit check.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct CreditCheck {
    pub account_id: Uuid,
    /// The account's limit; none means no limit.
    pub limit: Option<String>,
    /// What the account owes on its open invoices.
    pub open_balance: String,
    /// The open invoices' currency; none when there are none.
    pub currency: Option<String>,
    pub overdue: bool,
    pub credit_hold: bool,
    pub allowed: bool,
    pub reason: Option<String>,
}

fn decimal(text: Option<&str>) -> Option<Decimal> {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
}

/// The credit check for selling `extra` more to `account`. The caller
/// decides who may ask; this reads the account and its invoices directly.
pub async fn credit_check(
    state: &EngineState,
    account: Uuid,
    extra: Decimal,
) -> Result<CreditCheck, AppError> {
    let db = &state.base.db;
    let row: Option<(Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT credit_limit::text, credit_hold FROM account \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(account)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (limit, hold) = row.ok_or(AppError::NotFound)?;
    let open: Vec<(Option<String>, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT currency, sum(open_total)::text, bool_or(due_date::date < current_date) \
           FROM invoice \
          WHERE account_ref = $1 AND status::text IN ('issued', 'sent', 'overdue') \
            AND open_total > 0 AND (is_active IS NULL OR is_active = true) \
          GROUP BY currency ORDER BY currency",
    )
    .bind(account)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let limit_value = decimal(limit.as_deref());
    let hold = hold == Some(true);
    let overdue = open.iter().any(|(_, _, o)| *o == Some(true));
    let balance = open
        .first()
        .and_then(|(_, sum, _)| decimal(sum.as_deref()))
        .unwrap_or(Decimal::ZERO);
    let currency = open.first().and_then(|(c, _, _)| c.clone());
    let block_overdue = settings(state).block_overdue;
    let (allowed, reason) = if open.len() > 1 && limit_value.is_some() && !hold {
        (false, Some(REASON_CURRENCIES))
    } else {
        decide(limit_value, balance, extra, hold, overdue, block_overdue)
    };
    Ok(CreditCheck {
        account_id: account,
        limit,
        open_balance: balance.to_string(),
        currency,
        overdue,
        credit_hold: hold,
        allowed,
        reason: reason.map(str::to_owned),
    })
}

/// The day before which an invoice must have fallen due to put its account
/// on hold. Pure.
pub fn hold_cutoff(today: NaiveDate, hold_after_days: i64) -> NaiveDate {
    today - Duration::days(hold_after_days.max(0))
}

/// The nightly sweep: with `billing.credit.auto_hold` on, puts on hold every
/// account with an invoice overdue by more than `hold_after_days`. Returns
/// how many accounts it put on hold.
pub async fn hold_overdue(state: &EngineState, today: NaiveDate) -> Result<u64, AppError> {
    let s = settings(state);
    if !s.auto_hold {
        return Ok(0);
    }
    let accounts: Vec<(Uuid, Option<Uuid>, i64)> = sqlx::query_as(
        "SELECT a.id, a.owner_ref, a.row_version::bigint FROM account a \
          WHERE a.credit_hold IS NOT TRUE AND (a.is_active IS NULL OR a.is_active = true) \
            AND EXISTS (SELECT 1 FROM invoice i \
                         WHERE i.account_ref = a.id \
                           AND i.status::text IN ('issued', 'sent', 'overdue') \
                           AND i.open_total > 0 AND i.due_date::date < $1 \
                           AND (i.is_active IS NULL OR i.is_active = true)) \
          ORDER BY a.id LIMIT $2",
    )
    .bind(hold_cutoff(today, s.hold_after_days))
    .bind(HOLD_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut held = 0;
    for (id, owner, version) in accounts {
        let actor = owner.unwrap_or(Uuid::nil());
        let ctx = attome_records::entity_crud::admin_security_context(actor);
        match attome_records::entity_crud::update_record_for(
            state,
            &ctx,
            actor,
            "account",
            id,
            version,
            serde_json::json!({ "credit_hold": true }),
        )
        .await
        {
            Ok(_) => held += 1,
            Err(error) => tracing::warn!(account = %id, %error, "credit hold: account not held"),
        }
    }
    if held > 0 {
        tracing::info!(held, "credit hold: overdue accounts put on hold");
    }
    Ok(held)
}

/// `payment.read`: may read payments and credit.
#[derive(Debug)]
pub struct PaymentRead;

impl attome_server::authz::PrivilegeKey for PaymentRead {
    const KEY: &'static str = "payment.read";
}

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CreditQuery {
    /// An amount about to be sold on credit, to check with the open
    /// balance (default 0).
    pub amount: Option<String>,
}

/// Whether the caller may read the account (`404` otherwise).
async fn readable(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<(), AppError> {
    let scope = crate::scope::read_scope(state, ctx, "account", "a", 2).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT a.id FROM account a WHERE a.id = $1 \
           AND (a.is_active IS NULL OR a.is_active = true) {rls}"
    );
    let found: Option<(Uuid,)> =
        crate::scope::bind_scope(sqlx::query_as(&sql).bind(account), &scope)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    found.map(|_| ()).ok_or(AppError::NotFound)
}

/// Read an account's credit position
///
/// The account's credit limit, whether it is on credit hold, its open balance, and whether an amount
/// would still fit, as order confirmation checks it.
#[utoipa::path(
    get,
    path = "/api/v1/billing/accounts/{id}/credit",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The account"), CreditQuery),
    responses(
        (status = 200, description = "The credit limit, open balance, hold and whether the amount may be sold on credit", body = CreditCheck),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read payments or accounts", body = attome_types::ErrorResponse),
        (status = 404, description = "No such account, or not one the caller can read", body = attome_types::ErrorResponse),
        (status = 422, description = "amount is not a non-negative number", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_credit(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentRead>>,
    axum::extract::Path(account): axum::extract::Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<CreditQuery>,
) -> Result<axum::Json<CreditCheck>, AppError> {
    let extra = match q.amount.as_deref() {
        None => Decimal::ZERO,
        Some(text) => decimal(Some(text))
            .filter(|d| !d.is_sign_negative())
            .ok_or_else(|| AppError::Validation("amount must be a non-negative number".into()))?,
    };
    readable(&state, &ctx, account).await?;
    Ok(axum::Json(credit_check(&state, account, extra).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_credit), components(schemas(CreditCheck)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: i64) -> Decimal {
        Decimal::from(n)
    }

    #[test]
    fn credit_over_limit_blocks() {
        assert_eq!(
            decide(Some(d(1000)), d(800), d(300), false, false, false),
            (false, Some(REASON_LIMIT))
        );
        assert_eq!(
            decide(Some(d(1000)), d(800), d(200), false, false, false),
            (true, None),
            "exactly the limit is allowed"
        );
        assert_eq!(
            decide(None, d(1_000_000), d(1), false, false, false),
            (true, None),
            "no limit, no ceiling"
        );
    }

    #[test]
    fn credit_hold_blocks() {
        assert_eq!(
            decide(None, d(0), d(0), true, false, false),
            (false, Some(REASON_HOLD))
        );
        assert_eq!(
            decide(Some(d(1000)), d(2000), d(0), true, true, true),
            (false, Some(REASON_HOLD)),
            "the hold is the reason given first"
        );
    }

    #[test]
    fn credit_overdue_blocks_only_when_set() {
        assert_eq!(
            decide(None, d(10), d(0), false, true, true),
            (false, Some(REASON_OVERDUE))
        );
        assert_eq!(decide(None, d(10), d(0), false, true, false), (true, None));
    }

    #[test]
    fn credit_hold_cutoff_counts_back_from_today() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 21).unwrap_or_default();
        assert_eq!(
            hold_cutoff(today, 30),
            NaiveDate::from_ymd_opt(2026, 9, 21).unwrap_or_default()
        );
        assert_eq!(hold_cutoff(today, -5), today);
    }

    #[test]
    fn credit_settings_default_to_off() {
        let s = CreditSettings::default();
        assert!(!s.block_overdue && !s.auto_hold);
        assert_eq!(s.hold_after_days, 30);
    }
}

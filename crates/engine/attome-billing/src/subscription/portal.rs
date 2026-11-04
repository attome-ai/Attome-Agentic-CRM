//! F3-T13: an account's subscriptions as its customers see and change them
//! on the portal: each subscription's term and status, the lines in force
//! today and the charges still to come.
//!
//! The portal routes (`attome-portal`, `/{keyword}/api/v1/billing/
//! subscriptions...`) answer only while [`PORTAL_SETTING`] is on, and only
//! for the portal user's own account, taken from their contact.
//!
//! Changes (V2-D1588 (1)) run through the subscription service as the
//! portal's service user, the audit event naming the portal user:
//! [`change_quantity`] from today, prorated, only within the line's
//! `portal_min_quantity`..`portal_max_quantity` (billing pack changeset
//! 0025; a line without them cannot be changed on the portal), at the price
//! in force; [`cancel_at_term_end`] only at the end of the term, never at
//! once, and never a price change.

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The setting that opens the portal route (off by default).
pub const PORTAL_SETTING: &str = "billing.portal.subscriptions";
/// Subscriptions answered per account.
const MAX_SUBSCRIPTIONS: i64 = 100;
/// Coming charges answered per subscription.
const MAX_CHARGES: i64 = 12;

/// A line in force today.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PortalLine {
    pub line_id: Uuid,
    pub product: Option<String>,
    /// As stored, a decimal in text.
    pub quantity: Option<String>,
    pub unit_price: Option<String>,
}

/// A charge still to come.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PortalCharge {
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    /// As stored, a decimal in text.
    pub amount: Option<String>,
    pub kind: Option<String>,
}

/// One subscription as the customer sees it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PortalSubscription {
    pub id: Uuid,
    pub name: Option<String>,
    pub status: Option<String>,
    pub currency: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub billing_frequency: Option<String>,
    pub renewal_mode: Option<String>,
    /// When a cancellation takes effect, if one was made.
    pub cancel_effective: Option<DateTime<Utc>>,
    pub lines: Vec<PortalLine>,
    pub coming_charges: Vec<PortalCharge>,
}

/// Whether the portal route is open.
pub fn portal_on(state: &EngineState) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(PORTAL_SETTING) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

type SubscriptionRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
);

type LineRow = (Uuid, Option<String>, Option<String>, Option<String>);

type ChargeRow = (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<String>,
);

/// `account`'s subscriptions, newest first, with today's lines and the
/// coming charges.
pub async fn for_account(
    state: &EngineState,
    account: Uuid,
) -> Result<Vec<PortalSubscription>, AppError> {
    let db = &state.base.db;
    let rows: Vec<SubscriptionRow> = sqlx::query_as(
        "SELECT id, name, status::text, currency, start_date::timestamptz, \
                end_date::timestamptz, billing_frequency::text, renewal_mode::text, \
                cancel_effective::timestamptz \
           FROM subscription \
          WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY start_date DESC NULLS LAST, id LIMIT $2",
    )
    .bind(account)
    .bind(MAX_SUBSCRIPTIONS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, status, currency, start, end, frequency, renewal, cancel) in rows {
        let lines: Vec<LineRow> = sqlx::query_as(
            "SELECT l.id, to_jsonb(p) ->> 'name', l.quantity::text, l.unit_price::text \
               FROM subscription_line l \
               LEFT JOIN product p ON p.id = l.product_ref \
              WHERE l.subscription_ref = $1 AND (l.is_active IS NULL OR l.is_active = true) \
                AND (l.start_date IS NULL OR l.start_date <= now()) \
                AND (l.end_date IS NULL OR l.end_date > now()) \
              ORDER BY l.created_at, l.id",
        )
        .bind(id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let charges: Vec<ChargeRow> = sqlx::query_as(
            "SELECT period_start::timestamptz, period_end::timestamptz, amount::text, kind::text \
               FROM subscription_charge \
              WHERE subscription_ref = $1 AND status::text = 'planned' \
                AND (is_active IS NULL OR is_active = true) \
                AND (period_end IS NULL OR period_end > now()) \
              ORDER BY period_start NULLS LAST, id LIMIT $2",
        )
        .bind(id)
        .bind(MAX_CHARGES)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        out.push(PortalSubscription {
            id,
            name,
            status,
            currency,
            start_date: start,
            end_date: end,
            billing_frequency: frequency,
            renewal_mode: renewal,
            cancel_effective: cancel,
            lines: lines
                .into_iter()
                .map(|(line_id, product, quantity, unit_price)| PortalLine {
                    line_id,
                    product,
                    quantity,
                    unit_price,
                })
                .collect(),
            coming_charges: charges
                .into_iter()
                .map(|(period_start, period_end, amount, kind)| PortalCharge {
                    period_start,
                    period_end,
                    amount,
                    kind,
                })
                .collect(),
        });
    }
    Ok(out)
}

/// A quantity the portal may set, given the line's bounds; the reason when
/// not. A line with neither bound is not changeable on the portal. Pure.
pub fn quantity_allowed(
    min: Option<Decimal>,
    max: Option<Decimal>,
    quantity: Decimal,
) -> Result<(), String> {
    if min.is_none() && max.is_none() {
        return Err("this line cannot be changed on the portal".into());
    }
    if quantity <= Decimal::ZERO {
        return Err("quantity: above zero".into());
    }
    if let Some(min) = min
        && quantity < min
    {
        return Err(format!("quantity: at least {min}"));
    }
    if let Some(max) = max
        && quantity > max
    {
        return Err(format!("quantity: at most {max}"));
    }
    Ok(())
}

/// A quantity sent as text, as a decimal.
pub fn parse_quantity(text: &str) -> Result<Decimal, AppError> {
    text.trim()
        .parse::<Decimal>()
        .map_err(|_| AppError::Validation("quantity: a number".into()))
}

/// The subscription's status when it belongs to `account`; `None` for
/// anyone else's, so the caller answers 404.
async fn owned(
    state: &EngineState,
    account: Uuid,
    subscription: Uuid,
) -> Result<Option<Option<String>>, AppError> {
    sqlx::query_scalar(
        "SELECT status::text FROM subscription \
          WHERE id = $1 AND account_ref = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(subscription)
    .bind(account)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

type BoundsRow = (Option<String>, Option<String>, Option<String>);

/// Sets `line`'s quantity from today for the portal user `behalf`, as the
/// portal's service user `ctx`.
pub async fn change_quantity(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    account: Uuid,
    subscription: Uuid,
    line: Uuid,
    quantity: Decimal,
) -> Result<super::service::AmendmentResult, AppError> {
    owned(state, account, subscription)
        .await?
        .ok_or(AppError::NotFound)?;
    let today = Utc::now().date_naive();
    let row: Option<BoundsRow> = sqlx::query_as(
        "SELECT to_jsonb(l) ->> 'portal_min_quantity', to_jsonb(l) ->> 'portal_max_quantity', \
                (SELECT s.unit_price::text FROM subscription_segment s \
                  WHERE s.line_ref = l.id AND s.valid_from::date <= $3 \
                    AND (s.valid_to IS NULL OR s.valid_to::date > $3) \
                    AND (s.is_active IS NULL OR s.is_active = true) \
                  ORDER BY s.valid_from DESC LIMIT 1) \
           FROM subscription_line l \
          WHERE l.id = $1 AND l.subscription_ref = $2 \
            AND (l.is_active IS NULL OR l.is_active = true)",
    )
    .bind(line)
    .bind(subscription)
    .bind(today)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (min, max, price) = row.ok_or(AppError::NotFound)?;
    let parse = |v: Option<String>| v.and_then(|t| t.trim().parse::<Decimal>().ok());
    quantity_allowed(parse(min), parse(max), quantity).map_err(AppError::Validation)?;
    let unit_price = parse(price)
        .ok_or_else(|| AppError::Validation("the line has no price in force today".into()))?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT quantity::text FROM subscription_line WHERE id = $1")
            .bind(line)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let kind = if parse(current).is_some_and(|c| quantity < c) {
        super::segments::ChangeKind::Downgrade
    } else {
        super::segments::ChangeKind::Upgrade
    };
    super::service::amend_on_behalf(
        state,
        ctx,
        subscription,
        super::service::Amendment {
            effective: today,
            changes: vec![super::service::LineChange {
                line_id: line,
                quantity,
                unit_price,
                kind,
            }],
        },
        Some(behalf),
    )
    .await
}

/// The cancellation reasons a customer may give.
pub const CANCEL_REASONS: [&str; 5] =
    ["price", "product_fit", "budget", "switched_vendor", "other"];

/// Cancels at the end of the term for the portal user `behalf`, as the
/// portal's service user `ctx`; the date it ends.
pub async fn cancel_at_term_end(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    account: Uuid,
    subscription: Uuid,
    reason: &str,
) -> Result<chrono::NaiveDate, AppError> {
    if !CANCEL_REASONS.contains(&reason) {
        return Err(AppError::Validation(format!(
            "reason: one of {}",
            CANCEL_REASONS.join(", ")
        )));
    }
    let status = owned(state, account, subscription)
        .await?
        .ok_or(AppError::NotFound)?;
    if matches!(status.as_deref(), Some("cancelled" | "ended")) {
        return Err(AppError::Validation(
            "the subscription is already cancelled or ended".into(),
        ));
    }
    super::service::cancel_on_behalf(
        state,
        ctx,
        subscription,
        true,
        Utc::now().date_naive(),
        reason,
        Some(behalf),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantity_needs_bounds_and_stays_inside() {
        let d = |v: i64| Decimal::from(v);
        assert!(quantity_allowed(None, None, d(3)).is_err());
        assert!(quantity_allowed(Some(d(1)), Some(d(10)), d(5)).is_ok());
        assert!(quantity_allowed(Some(d(2)), None, d(1)).is_err());
        assert!(quantity_allowed(None, Some(d(10)), d(11)).is_err());
        assert!(quantity_allowed(None, Some(d(10)), d(0)).is_err());
    }
}

//! F3-T13, read part: an account's subscriptions as its customers see them
//! on the portal: each subscription's term and status, the lines in force
//! today and the charges still to come.
//!
//! The portal route (`attome-portal`, `GET /{keyword}/api/v1/billing/
//! subscriptions`) answers only while [`PORTAL_SETTING`] is on, and only for
//! the portal user's own account, taken from their contact. Changing a
//! quantity or cancelling from the portal is not here: the subscription
//! service writes as a staff user, and how a portal user acts through it is
//! still open.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
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
        "SELECT id, name, status::text, currency, start_date, end_date, \
                billing_frequency::text, renewal_mode::text, cancel_effective \
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
            "SELECT period_start, period_end, amount::text, kind::text \
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

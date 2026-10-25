//! F11-T4: standalone selling prices and the allocation of a contract's
//! price across its performance obligations.
//!
//! An obligation's standalone selling price (SSP) is, in order
//! ([`choose`]):
//!
//! 1. `entered`: the product's `ssp_entry` valid on the date, the highest
//!    version first;
//! 2. `median_standalone`: the median price of the product sold on its own
//!    (an order with that one line) over the last year, taken over the sales
//!    within [`BAND_PERCENT`] of the overall median and only with at least
//!    [`MIN_OBSERVATIONS`] of them;
//! 3. `list_less_discount`: the list price, less
//!    `revrec.ssp_list_discount_percent`;
//! 4. `cost_plus`: the cost, plus `revrec.ssp_cost_margin_percent`.
//!
//! [`allocate`] splits the contract's price over the obligations in
//! proportion to their SSPs, so a discount falls on each in proportion;
//! rounding to the cent leaves a remainder, which goes to the obligation
//! with the largest SSP. An obligation with no SSP by any method keeps its
//! own line amount as its weight. [`allocate_contract`] stores
//! `ssp_amount`, `allocated_amount`, the method and the SSP version on each
//! obligation, after the contract's obligations are built (F11-T3), unless a
//! schedule line of the contract is already locked.
//!
//! `PUT /api/v1/ledger/revrec/ssp` (holders of `ssp_entry.create`, the
//! revenue controller) adds a product's next SSP version; earlier versions
//! stay, so a past allocation can say which it used.

use std::str::FromStr;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::put};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

/// F11-T11: the flag that turns allocation by SSP on.
pub const ALLOCATION_FLAG: &str = "revrec.ssp_allocation";

/// The setting: percent taken off the list price for an SSP.
pub const LIST_DISCOUNT_SETTING: &str = "revrec.ssp_list_discount_percent";
/// The setting: percent added to cost for an SSP.
pub const COST_MARGIN_SETTING: &str = "revrec.ssp_cost_margin_percent";
/// Standalone sales needed for an observed SSP.
pub const MIN_OBSERVATIONS: usize = 3;
/// How far from the median, in percent, a standalone sale may be and count.
pub const BAND_PERCENT: u32 = 15;
/// How far back standalone sales are looked for.
pub const OBSERVATION_DAYS: i64 = 365;

/// How an SSP was found; the names are `ssp_entry.method`'s choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SspMethod {
    Entered,
    MedianStandalone,
    ListLessDiscount,
    CostPlus,
}

impl SspMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::MedianStandalone => "median_standalone",
            Self::ListLessDiscount => "list_less_discount",
            Self::CostPlus => "cost_plus",
        }
    }
}

/// An SSP and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssp {
    pub amount: Decimal,
    pub method: SspMethod,
    /// The `ssp_entry` version, for an entered SSP.
    pub version: Option<i64>,
}

/// The fallback percentages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fallback {
    pub list_discount_percent: Decimal,
    pub cost_margin_percent: Decimal,
}

impl Default for Fallback {
    fn default() -> Self {
        Fallback {
            list_discount_percent: Decimal::ZERO,
            cost_margin_percent: Decimal::ZERO,
        }
    }
}

/// The median of `values`; `None` for none. Pure.
pub fn median(values: &[Decimal]) -> Option<Decimal> {
    let mut sorted = values.to_vec();
    sorted.sort();
    let n = sorted.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(sorted[n / 2]),
        _ => Some((sorted[n / 2 - 1] + sorted[n / 2]) / Decimal::TWO),
    }
}

/// The observed standalone price: the median of the sales within the band
/// around the overall median, when there are enough of them. Pure.
pub fn observed(sales: &[Decimal]) -> Option<Decimal> {
    let center = median(sales)?;
    let band = center * Decimal::from(BAND_PERCENT) / Decimal::ONE_HUNDRED;
    let within: Vec<Decimal> = sales
        .iter()
        .copied()
        .filter(|s| (*s - center).abs() <= band)
        .collect();
    (within.len() >= MIN_OBSERVATIONS)
        .then(|| median(&within))
        .flatten()
        .map(|m| m.round_dp(2))
}

/// The SSP by the fallback order. Pure.
pub fn choose(
    entered: Option<(Decimal, i64)>,
    standalone_sales: &[Decimal],
    list_price: Option<Decimal>,
    cost: Option<Decimal>,
    fallback: &Fallback,
) -> Option<Ssp> {
    if let Some((amount, version)) = entered.filter(|(a, _)| *a > Decimal::ZERO) {
        return Some(Ssp {
            amount,
            method: SspMethod::Entered,
            version: Some(version),
        });
    }
    if let Some(amount) = observed(standalone_sales).filter(|a| *a > Decimal::ZERO) {
        return Some(Ssp {
            amount,
            method: SspMethod::MedianStandalone,
            version: None,
        });
    }
    if let Some(list) = list_price.filter(|l| *l > Decimal::ZERO) {
        let off = list * fallback.list_discount_percent / Decimal::ONE_HUNDRED;
        return Some(Ssp {
            amount: (list - off).round_dp(2),
            method: SspMethod::ListLessDiscount,
            version: None,
        });
    }
    cost.filter(|c| *c > Decimal::ZERO).map(|c| Ssp {
        amount: (c + c * fallback.cost_margin_percent / Decimal::ONE_HUNDRED).round_dp(2),
        method: SspMethod::CostPlus,
        version: None,
    })
}

/// `total` split over obligations in proportion to `ssps`, to the cent, the
/// rounding remainder on the largest SSP (the first, on a tie); equal parts
/// when every SSP is zero. Pure.
pub fn allocate(total: Decimal, ssps: &[Decimal]) -> Vec<Decimal> {
    if ssps.is_empty() {
        return Vec::new();
    }
    let weights: Vec<Decimal> = if ssps.iter().all(|s| *s <= Decimal::ZERO) {
        vec![Decimal::ONE; ssps.len()]
    } else {
        ssps.iter().map(|s| (*s).max(Decimal::ZERO)).collect()
    };
    let sum: Decimal = weights.iter().copied().sum();
    let mut out: Vec<Decimal> = weights
        .iter()
        .map(|w| (total * *w / sum).round_dp(2))
        .collect();
    let largest = weights
        .iter()
        .enumerate()
        .fold(0, |best, (i, w)| if *w > weights[best] { i } else { best });
    let assigned: Decimal = out.iter().copied().sum();
    out[largest] += total - assigned;
    out
}

fn dec(text: Option<String>) -> Option<Decimal> {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
}

/// A query against another pack's table: a missing table or column (the
/// sales pack not installed) is no answer, not an error.
fn optional<T>(result: Result<T, sqlx::Error>) -> Result<Option<T>, AppError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(sqlx::Error::Database(e)) if matches!(e.code().as_deref(), Some("42P01" | "42703")) => {
            Ok(None)
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// The fallback percentages the deployment set.
pub fn fallback(state: &EngineState) -> Fallback {
    let read = |key: &str| {
        attome_core::setting_registry()
            .get(key)
            .map(|d| state.settings.load().resolve(d, None, None).0)
            .and_then(|v| v.as_f64())
            .and_then(Decimal::from_f64_retain)
            .map(|d| d.round_dp(4))
            .unwrap_or(Decimal::ZERO)
    };
    Fallback {
        list_discount_percent: read(LIST_DISCOUNT_SETTING),
        cost_margin_percent: read(COST_MARGIN_SETTING),
    }
}

/// The SSP of `product` on `on`.
pub async fn ssp_for(
    conn: &mut PgConnection,
    product: Uuid,
    on: NaiveDate,
    fallback: &Fallback,
) -> Result<Option<Ssp>, AppError> {
    let entered: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT amount::text, version::bigint FROM ssp_entry \
          WHERE product_ref = $1 AND (is_active IS NULL OR is_active = true) \
            AND (period_start IS NULL OR period_start <= $2) \
            AND (period_end IS NULL OR period_end >= $2) \
          ORDER BY version DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(product)
    .bind(on)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let entered = entered.and_then(|(a, v)| Some((dec(a)?, v.unwrap_or(1))));
    let sales: Vec<Option<String>> = optional(
        sqlx::query_scalar(
            "SELECT (l.line_total / NULLIF(l.quantity, 0))::text FROM order_line l \
              WHERE l.product_ref = $1 AND (l.is_active IS NULL OR l.is_active = true) \
                AND l.created_at >= ($2::date - $3::int) \
                AND (SELECT count(*) FROM order_line x \
                      WHERE x.order_ref = l.order_ref \
                        AND (x.is_active IS NULL OR x.is_active = true)) = 1 \
              LIMIT 1000",
        )
        .bind(product)
        .bind(on)
        .bind(i32::try_from(OBSERVATION_DAYS).unwrap_or(365))
        .fetch_all(&mut *conn)
        .await,
    )?
    .unwrap_or_default();
    let sales: Vec<Decimal> = sales.into_iter().filter_map(dec).collect();
    let priced: Option<(Option<String>, Option<String>)> = optional(
        sqlx::query_as(
            "SELECT COALESCE(i.list_price, i.price)::text, i.cost::text \
               FROM price_list_item i JOIN price_list p ON p.id = i.price_list_ref \
              WHERE i.product_ref = $1 AND (i.is_active IS NULL OR i.is_active = true) \
                AND (p.is_active IS NULL OR p.is_active = true) \
                AND (p.valid_from IS NULL OR p.valid_from <= $2) \
                AND (p.valid_to IS NULL OR p.valid_to >= $2) \
              ORDER BY p.is_active_list DESC NULLS LAST, p.valid_from DESC NULLS LAST LIMIT 1",
        )
        .bind(product)
        .bind(on)
        .fetch_optional(&mut *conn)
        .await,
    )?
    .flatten();
    let (list, cost) = match priced {
        Some((list, cost)) => (dec(list), dec(cost)),
        None => (None, None),
    };
    Ok(choose(entered, &sales, list, cost, fallback))
}

/// Stores each obligation's SSP and allocation for `contract`; returns how
/// many obligations were updated (none once a schedule line is locked).
pub async fn allocate_contract(
    tx: &mut Transaction<'_, Postgres>,
    contract: Uuid,
    on: NaiveDate,
    fallback: &Fallback,
) -> Result<usize, AppError> {
    let locked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM revenue_schedule_line s \
                          JOIN performance_obligation o ON o.id = s.obligation_ref \
                         WHERE o.revenue_contract_ref = $1 AND s.status::text = 'locked' \
                           AND (s.is_active IS NULL OR s.is_active = true))",
    )
    .bind(contract)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if locked {
        return Ok(0);
    }
    let obligations: Vec<(Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT id, product_ref, allocated_amount::text FROM performance_obligation \
          WHERE revenue_contract_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id",
    )
    .bind(contract)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if obligations.is_empty() {
        return Ok(0);
    }
    let line_amounts: Vec<Decimal> = obligations
        .iter()
        .map(|(_, _, a)| dec(a.clone()).unwrap_or(Decimal::ZERO))
        .collect();
    let total: Option<String> =
        sqlx::query_scalar("SELECT total_price::text FROM revenue_contract WHERE id = $1")
            .bind(contract)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let total = dec(total).unwrap_or_else(|| line_amounts.iter().copied().sum());
    let mut ssps = Vec::with_capacity(obligations.len());
    for ((_, product, _), line) in obligations.iter().zip(&line_amounts) {
        let found = match product {
            Some(product) => ssp_for(&mut **tx, *product, on, fallback).await?,
            None => None,
        };
        ssps.push(found.ok_or(*line));
    }
    let weights: Vec<Decimal> = ssps
        .iter()
        .map(|s| match s {
            Ok(ssp) => ssp.amount,
            Err(line) => *line,
        })
        .collect();
    let allocated = allocate(total, &weights);
    for (((id, _, _), ssp), amount) in obligations.iter().zip(&ssps).zip(&allocated) {
        let (ssp_amount, method, version) = match ssp {
            Ok(s) => (Some(s.amount), Some(s.method.as_str()), s.version),
            Err(_) => (None, None, None),
        };
        sqlx::query(
            "UPDATE performance_obligation \
                SET ssp_amount = $2::numeric, allocated_amount = $3::numeric, \
                    ssp_method = $4, ssp_version = $5, modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE id = $1",
        )
        .bind(id)
        .bind(ssp_amount.map(|a| a.to_string()))
        .bind(amount.to_string())
        .bind(method)
        .bind(version)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        change_feed::emit_tx(tx, "performance_obligation", *id, ChangeOperation::Update).await?;
    }
    Ok(obligations.len())
}

/// `ssp_entry.create`: who sets standalone selling prices (the revenue
/// controller).
#[derive(Debug)]
pub struct SspEntryCreate;

impl PrivilegeKey for SspEntryCreate {
    const KEY: &'static str = "ssp_entry.create";
}

/// A product's next SSP version.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewSsp {
    pub product_id: Uuid,
    /// The SSP, above zero.
    #[schema(value_type = String)]
    pub amount: Decimal,
    /// The ISO 4217 currency, three letters.
    pub currency: String,
    /// The first day it applies; open when absent.
    #[serde(default)]
    pub period_start: Option<NaiveDate>,
    /// The last day it applies; open when absent.
    #[serde(default)]
    pub period_end: Option<NaiveDate>,
}

/// The SSP version written.
#[derive(Debug, Serialize, ToSchema)]
pub struct SspVersion {
    pub id: Uuid,
    pub product_id: Uuid,
    pub version: i64,
}

/// Checks a new SSP. Pure.
pub fn check_new_ssp(body: &NewSsp) -> Result<(), String> {
    if body.amount <= Decimal::ZERO {
        return Err("amount is above zero".into());
    }
    if body.currency.len() != 3 || !body.currency.chars().all(|c| c.is_ascii_uppercase()) {
        return Err("currency is three capital letters (ISO 4217)".into());
    }
    if let (Some(start), Some(end)) = (body.period_start, body.period_end)
        && end < start
    {
        return Err("period_end is on or after period_start".into());
    }
    Ok(())
}

/// Set a product's standalone selling price
///
/// F11-T4: adds the product's next `ssp_entry` version, method `entered`;
/// earlier versions stay, so a past allocation can name the one it used.
#[utoipa::path(
    put,
    path = "/api/v1/ledger/revrec/ssp",
    operation_id = "revrec_ssp_set",
    tag = "ledger",
    request_body = NewSsp,
    responses(
        (status = 200, description = "The version written", body = SspVersion),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ssp_entry.create", body = ErrorResponse),
        (status = 409, description = "Another SSP for this product is being written", body = ErrorResponse),
        (status = 422, description = "A zero amount, a malformed currency or an inverted period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn set_ssp(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SspEntryCreate>>,
    Json(body): Json<NewSsp>,
) -> Result<Json<SspVersion>, AppError> {
    // F11-T11: off, revenue recognition is not there.
    if !state
        .feature_flags()
        .is_on(crate::revrec::contract::BASIC_FLAG, &ctx)
        .await
    {
        return Err(AppError::NotFound);
    }
    check_new_ssp(&body).map_err(AppError::Validation)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-ledger/revrec-ssp:{}", body.product_id))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another SSP for this product is being written",
        ));
    }
    let version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(version), 0)::bigint + 1 FROM ssp_entry WHERE product_ref = $1",
    )
    .bind(body.product_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ssp_entry (id, name, product_ref, period_start, period_end, amount, \
             currency, method, version, created_by, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, 'entered', $8, $9, $9)",
    )
    .bind(id)
    .bind(format!("SSP v{version}"))
    .bind(body.product_id)
    .bind(body.period_start)
    .bind(body.period_end)
    .bind(body.amount.to_string())
    .bind(&body.currency)
    .bind(version)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    change_feed::emit_tx(&mut tx, "ssp_entry", id, ChangeOperation::Create).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "ssp_entry",
            id,
            AuditOperation::Create,
            "revrec.ssp_set",
            ctx.user_id,
        )
        .comment(format!(
            "SSP v{version} for product {}: {} {}",
            body.product_id, body.amount, body.currency
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SspVersion {
        id,
        product_id: body.product_id,
        version,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ledger/revrec/ssp", put(set_ssp))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(set_ssp))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn allocates_discount_proportionally() {
        // SSPs of 600, 300 and 100 sold together for 900: a 10% discount,
        // carried by each in proportion.
        let out = allocate(d("900"), &[d("600"), d("300"), d("100")]);
        assert_eq!(out, vec![d("540"), d("270"), d("90")]);
        assert_eq!(out.iter().copied().sum::<Decimal>(), d("900"));
    }

    #[test]
    fn remainder_goes_to_largest() {
        // 100 by 3:3:7 rounds to 23.08 + 23.08 + 53.85 = 100.01; the cent
        // comes off the largest.
        let out = allocate(d("100"), &[d("3"), d("3"), d("7")]);
        assert_eq!(out, vec![d("23.08"), d("23.08"), d("53.84")]);
        assert_eq!(out.iter().copied().sum::<Decimal>(), d("100"));
        // No SSPs at all: equal parts, the remainder on the first.
        assert_eq!(
            allocate(d("100"), &[Decimal::ZERO; 3]),
            vec![d("33.34"), d("33.33"), d("33.33")]
        );
    }

    #[test]
    fn fallback_uses_list_less_discount() {
        let fallback = Fallback {
            list_discount_percent: d("20"),
            cost_margin_percent: d("30"),
        };
        // Two standalone sales are too few to observe a price.
        let ssp = choose(
            None,
            &[d("950"), d("990")],
            Some(d("1000")),
            Some(d("500")),
            &fallback,
        )
        .unwrap();
        assert_eq!(ssp.method, SspMethod::ListLessDiscount);
        assert_eq!(ssp.amount, d("800"));
        // An entered SSP wins; with nothing but cost, cost plus margin.
        assert_eq!(
            choose(Some((d("700"), 3)), &[], Some(d("1000")), None, &fallback),
            Some(Ssp {
                amount: d("700"),
                method: SspMethod::Entered,
                version: Some(3)
            })
        );
        assert_eq!(
            choose(None, &[], None, Some(d("500")), &fallback).map(|s| (s.method, s.amount)),
            Some((SspMethod::CostPlus, d("650")))
        );
        assert_eq!(choose(None, &[], None, None, &fallback), None);
    }

    #[test]
    fn observed_price_ignores_sales_outside_the_band() {
        // 2000 is far from the others and is left out.
        let sales = [d("990"), d("1000"), d("1010"), d("2000")];
        assert_eq!(observed(&sales), Some(d("1000")));
        assert_eq!(observed(&[d("1000"), d("1000")]), None);
        assert_eq!(median(&[d("1"), d("3")]), Some(d("2")));
    }
}

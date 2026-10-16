//! Tax determination and line math (roadmap F4-T4), pure. The caller passes
//! the tax-rate rows (the region pack's `region_tax_rate` records, by
//! country, category and effective dates), read through [`TaxRateCache`].
//!
//! Rules: a sale inside one country takes that country's rate for the
//! category on the invoice date; a cross-border sale to a VAT-registered
//! business is reverse charge at 0; zero-rated, exempt and out-of-scope lines
//! carry 0 and their reason. Each line rounds once, half away from zero, to
//! the currency's minor units (3 for KWD, BHD, OMR and JOD, else 2), and the
//! invoice totals are sums of rounded lines, so a printed invoice adds up.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveDate;
use rust_decimal::{Decimal, RoundingStrategy};

/// The VAT category of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VatCategory {
    Standard,
    Reduced,
    ZeroRated,
    Exempt,
    OutOfScope,
}

/// One tax-rate row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxRateRow {
    pub country: String,
    pub category: VatCategory,
    pub rate_pct: Decimal,
    pub effective_from: NaiveDate,
    /// Exclusive; `None` is open-ended.
    pub effective_to: Option<NaiveDate>,
}

/// Who sells to whom, when, and what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxContext {
    pub seller_country: String,
    pub buyer_country: String,
    pub buyer_vat_registered: bool,
    pub category: VatCategory,
    pub on_date: NaiveDate,
}

/// Why a line carries no tax, in both languages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExemptionReason {
    pub code: &'static str,
    pub en: &'static str,
    pub ar: &'static str,
}

/// The tax applied to a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxDecision {
    pub rate_pct: Decimal,
    pub category: VatCategory,
    pub reverse_charge: bool,
    pub reason: Option<ExemptionReason>,
}

/// Why a line's tax cannot be decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaxError {
    /// No rate row for the seller's country, category and date.
    NoRate { country: String, on_date: NaiveDate },
}

const REVERSE_CHARGE: ExemptionReason = ExemptionReason {
    code: "reverse_charge",
    en: "Reverse charge: the buyer accounts for VAT",
    ar: "احتساب عكسي: يحتسب المشتري ضريبة القيمة المضافة",
};
const ZERO_RATED: ExemptionReason = ExemptionReason {
    code: "zero_rated",
    en: "Zero-rated supply",
    ar: "توريد خاضع لنسبة الصفر",
};
const EXEMPT: ExemptionReason = ExemptionReason {
    code: "exempt",
    en: "Exempt supply",
    ar: "توريد معفى",
};
const OUT_OF_SCOPE: ExemptionReason = ExemptionReason {
    code: "out_of_scope",
    en: "Outside the scope of VAT",
    ar: "خارج نطاق ضريبة القيمة المضافة",
};

/// Decides the tax of a line.
pub fn determine(ctx: &TaxContext, rates: &[TaxRateRow]) -> Result<TaxDecision, TaxError> {
    let zero = |reason: ExemptionReason, reverse_charge: bool| TaxDecision {
        rate_pct: Decimal::ZERO,
        category: ctx.category,
        reverse_charge,
        reason: Some(reason),
    };
    match ctx.category {
        VatCategory::Exempt => return Ok(zero(EXEMPT, false)),
        VatCategory::OutOfScope => return Ok(zero(OUT_OF_SCOPE, false)),
        VatCategory::ZeroRated => return Ok(zero(ZERO_RATED, false)),
        VatCategory::Standard | VatCategory::Reduced => {}
    }
    if !ctx.seller_country.eq_ignore_ascii_case(&ctx.buyer_country) && ctx.buyer_vat_registered {
        return Ok(zero(REVERSE_CHARGE, true));
    }
    let row = rates
        .iter()
        .filter(|r| {
            r.country.eq_ignore_ascii_case(&ctx.seller_country)
                && r.category == ctx.category
                && r.effective_from <= ctx.on_date
                && r.effective_to.is_none_or(|to| ctx.on_date < to)
        })
        .max_by_key(|r| r.effective_from)
        .ok_or_else(|| TaxError::NoRate {
            country: ctx.seller_country.clone(),
            on_date: ctx.on_date,
        })?;
    Ok(TaxDecision {
        rate_pct: row.rate_pct,
        category: ctx.category,
        reverse_charge: false,
        reason: None,
    })
}

/// The minor units of an ISO 4217 currency.
pub fn minor_units(currency: &str) -> u32 {
    match currency.to_ascii_uppercase().as_str() {
        "KWD" | "BHD" | "OMR" | "JOD" | "IQD" | "LYD" | "TND" => 3,
        "JPY" | "KRW" => 0,
        _ => 2,
    }
}

/// One line's amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineAmounts {
    pub net: Decimal,
    pub vat: Decimal,
    pub total: Decimal,
}

fn round(value: Decimal, minor_units: u32) -> Decimal {
    value.round_dp_with_strategy(minor_units, RoundingStrategy::MidpointAwayFromZero)
}

/// Net, VAT and total of a line, each rounded once.
pub fn line_amounts(
    quantity: Decimal,
    unit_price: Decimal,
    discount: Decimal,
    rate_pct: Decimal,
    minor_units: u32,
) -> LineAmounts {
    let net = round(quantity * unit_price - discount, minor_units);
    let vat = round(net * rate_pct / Decimal::ONE_HUNDRED, minor_units);
    LineAmounts {
        net,
        vat,
        total: net + vat,
    }
}

/// The invoice totals: sums of the rounded lines.
pub fn invoice_totals(lines: &[LineAmounts]) -> LineAmounts {
    lines.iter().fold(
        LineAmounts {
            net: Decimal::ZERO,
            vat: Decimal::ZERO,
            total: Decimal::ZERO,
        },
        |acc, l| LineAmounts {
            net: acc.net + l.net,
            vat: acc.vat + l.vat,
            total: acc.total + l.total,
        },
    )
}

/// The tax-rate cache's one key.
pub const TAX_RATES_KEY: &str = "attome-billing:tax_rates";

/// How long a loaded rate set is used before it is read again.
pub const TAX_RATES_TTL: Duration = Duration::from_secs(300);

/// The process-local cache of every tax-rate row.
///
/// - Source of truth: the `region_tax_rate` records in PostgreSQL.
/// - Key: [`TAX_RATES_KEY`], one entry holding the whole set (a few hundred
///   rows at most).
/// - TTL: [`TAX_RATES_TTL`]; a rate edited on one node is used everywhere
///   within five minutes. A rate change takes effect on a date, and rates
///   are entered ahead of it, so the delay never prices a line wrongly.
/// - Invalidation: [`TaxRateCache::invalidate`] after a rate write on this
///   node; other nodes wait for the TTL.
/// - Failure: a failed load is returned to the caller and not cached, so the
///   next call reads again; nothing falls back to stale or built-in rates.
/// - Cold start: the first call loads.
#[derive(Clone)]
pub struct TaxRateCache {
    inner: moka::future::Cache<&'static str, Arc<Vec<TaxRateRow>>>,
}

impl std::fmt::Debug for TaxRateCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaxRateCache").finish_non_exhaustive()
    }
}

impl Default for TaxRateCache {
    fn default() -> Self {
        Self::with_ttl(TAX_RATES_TTL)
    }
}

impl TaxRateCache {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: moka::future::Cache::builder()
                .max_capacity(1)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// The cached rows, or the rows `load` reads when none are cached.
    /// Concurrent callers on a cold cache share one load.
    pub async fn get_or_load<F, Fut, E>(&self, load: F) -> Result<Arc<Vec<TaxRateRow>>, Arc<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<TaxRateRow>, E>>,
        E: Send + Sync + 'static,
    {
        self.inner
            .try_get_with(TAX_RATES_KEY, async move { load().await.map(Arc::new) })
            .await
    }

    /// Drops the cached rows; the next call loads.
    pub async fn invalidate(&self) {
        self.inner.invalidate(TAX_RATES_KEY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn sa_rates() -> Vec<TaxRateRow> {
        vec![
            TaxRateRow {
                country: "SA".into(),
                category: VatCategory::Standard,
                rate_pct: dec("5"),
                effective_from: day("2018-01-01"),
                effective_to: Some(day("2020-07-01")),
            },
            TaxRateRow {
                country: "SA".into(),
                category: VatCategory::Standard,
                rate_pct: dec("15"),
                effective_from: day("2020-07-01"),
                effective_to: None,
            },
        ]
    }

    fn ctx(buyer: &str, registered: bool, on: &str) -> TaxContext {
        TaxContext {
            seller_country: "SA".into(),
            buyer_country: buyer.into(),
            buyer_vat_registered: registered,
            category: VatCategory::Standard,
            on_date: day(on),
        }
    }

    #[test]
    fn saudi_standard_rate_is_15() {
        let d = determine(&ctx("SA", false, "2026-10-16"), &sa_rates()).unwrap();
        assert_eq!(d.rate_pct, dec("15"));
        assert!(d.reason.is_none());
    }

    #[test]
    fn rate_change_uses_issue_date() {
        let d = determine(&ctx("SA", true, "2020-06-30"), &sa_rates()).unwrap();
        assert_eq!(d.rate_pct, dec("5"));
    }

    #[test]
    fn cross_border_b2b_is_reverse_charge() {
        let d = determine(&ctx("AE", true, "2026-10-16"), &sa_rates()).unwrap();
        assert!(d.reverse_charge);
        assert_eq!(d.rate_pct, Decimal::ZERO);
        assert_eq!(d.reason.unwrap().code, "reverse_charge");
        // A consumer abroad is charged the seller's rate.
        assert_eq!(
            determine(&ctx("AE", false, "2026-10-16"), &sa_rates())
                .unwrap()
                .rate_pct,
            dec("15")
        );
    }

    #[test]
    fn kwd_rounds_to_three_decimals() {
        let l = line_amounts(
            dec("3"),
            dec("1.3335"),
            Decimal::ZERO,
            dec("5"),
            minor_units("KWD"),
        );
        assert_eq!(l.net, dec("4.001"));
        assert_eq!(l.vat, dec("0.200"));
        assert_eq!(minor_units("sar"), 2);
    }

    #[test]
    fn totals_are_sum_of_rounded_lines() {
        let lines = [
            line_amounts(dec("1"), dec("0.105"), Decimal::ZERO, dec("15"), 2),
            line_amounts(dec("1"), dec("0.105"), Decimal::ZERO, dec("15"), 2),
        ];
        let t = invoice_totals(&lines);
        assert_eq!(lines[0].net, dec("0.11"));
        assert_eq!(t.net, dec("0.22"));
        assert_eq!(t.vat, dec("0.04"));
        assert_eq!(t.total, dec("0.26"));
    }

    #[test]
    fn exempt_and_missing_rates() {
        let mut c = ctx("SA", false, "2026-10-16");
        c.category = VatCategory::Exempt;
        assert_eq!(determine(&c, &[]).unwrap().reason.unwrap().code, "exempt");
        assert!(matches!(
            determine(&ctx("SA", false, "2017-01-01"), &sa_rates()),
            Err(TaxError::NoRate { .. })
        ));
    }

    #[tokio::test]
    async fn rates_load_once_until_invalidated() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = TaxRateCache::default();
        let loads = AtomicUsize::new(0);
        let load = || async {
            loads.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(sa_rates())
        };
        let first = cache.get_or_load(load).await.map(|r| r.len());
        let again = cache.get_or_load(load).await.map(|r| r.len());
        assert_eq!(first.ok(), again.ok());
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        cache.invalidate().await;
        let _ = cache.get_or_load(load).await;
        assert_eq!(loads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_load_is_not_cached() {
        let cache = TaxRateCache::default();
        let failed = cache
            .get_or_load(|| async { Err::<Vec<TaxRateRow>, _>("database down") })
            .await;
        assert!(failed.is_err());
        let ok = cache
            .get_or_load(|| async { Ok::<_, &str>(sa_rates()) })
            .await;
        assert!(ok.is_ok());
    }
}

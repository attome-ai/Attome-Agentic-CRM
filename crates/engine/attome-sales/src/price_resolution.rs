//! Price resolution (roadmap D8-T2): the price of one product for one
//! account, in a unit, quantity and currency, on a date — the one function
//! deal lines (D6), quotes (D9), orders (D10) and configured products (F1)
//! use. The first source that has a valid price wins:
//!
//! 1. an account price for the product in the currency, valid on the date;
//! 2. a contracted price (W1) for the account and product, valid on the date;
//! 3. the price list: the account's own list when it has one, otherwise the
//!    active list in the currency valid on the date, with the quantity breaks
//!    of the product's item.
//!
//! Prices are per unit of the item; a request in another unit of the same
//! unit group converts through the units' conversion factors (base units per
//! unit). Breaks are measured in the item's unit. [`resolve`] is pure: the
//! caller loads the candidate rows for the account and product.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

/// A validity window; either end may be open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Validity {
    pub from: Option<NaiveDate>,
    pub to: Option<NaiveDate>,
}

impl Validity {
    pub fn contains(&self, date: NaiveDate) -> bool {
        self.from.is_none_or(|f| f <= date) && self.to.is_none_or(|t| date <= t)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPrice {
    pub id: Uuid,
    pub currency: String,
    pub price: Decimal,
    pub valid: Validity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractPrice {
    pub id: Uuid,
    pub contract: Uuid,
    pub currency: String,
    pub price: Decimal,
    pub valid: Validity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceBreak {
    pub id: Uuid,
    /// From this quantity (in the item's unit) up.
    pub min_quantity: Decimal,
    pub price: Option<Decimal>,
    pub discount_percent: Option<Decimal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub id: Uuid,
    pub list_price: Decimal,
    /// The unit the price is for; `None` is the product's default unit.
    pub unit: Option<Uuid>,
    pub breaks: Vec<PriceBreak>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceList {
    pub id: Uuid,
    pub currency: String,
    pub active: bool,
    pub valid: Validity,
    /// This product's item on the list, when it has one.
    pub item: Option<ListItem>,
}

/// Base units per unit, by unit id.
pub type UnitFactors = std::collections::HashMap<Uuid, Decimal>;

/// What is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceRequest {
    pub currency: String,
    pub date: NaiveDate,
    pub quantity: Decimal,
    /// The unit the caller sells in; `None` is the product's default unit.
    pub unit: Option<Uuid>,
    /// The product's default unit, for items or requests without one.
    pub default_unit: Option<Uuid>,
    /// The account's own price list, when it has one.
    pub account_price_list: Option<Uuid>,
}

/// Where a price came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PriceSource {
    AccountPrice {
        id: Uuid,
    },
    Contract {
        contract: Uuid,
        id: Uuid,
    },
    PriceList {
        list: Uuid,
        item: Uuid,
        price_break: Option<Uuid>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPrice {
    /// The price of one requested unit.
    pub price: Decimal,
    pub source: PriceSource,
}

/// Requested units per item unit (1 when either unit is unknown or the same).
fn unit_ratio(req: &PriceRequest, item_unit: Option<Uuid>, factors: &UnitFactors) -> Decimal {
    let requested = req.unit.or(req.default_unit);
    let priced = item_unit.or(req.default_unit);
    match (requested, priced) {
        (Some(r), Some(p)) if r != p => match (factors.get(&r), factors.get(&p)) {
            (Some(fr), Some(fp)) if !fp.is_zero() => *fr / *fp,
            _ => Decimal::ONE,
        },
        _ => Decimal::ONE,
    }
}

fn same_currency(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Resolves the price from the loaded candidates; `None` when no source has
/// a valid price for the request.
pub fn resolve(
    req: &PriceRequest,
    account_prices: &[AccountPrice],
    contract_prices: &[ContractPrice],
    lists: &[PriceList],
    factors: &UnitFactors,
) -> Option<ResolvedPrice> {
    if let Some(p) = account_prices
        .iter()
        .filter(|p| same_currency(&p.currency, &req.currency) && p.valid.contains(req.date))
        .max_by_key(|p| p.valid.from)
    {
        return Some(ResolvedPrice {
            price: p.price,
            source: PriceSource::AccountPrice { id: p.id },
        });
    }
    if let Some(p) = contract_prices
        .iter()
        .filter(|p| same_currency(&p.currency, &req.currency) && p.valid.contains(req.date))
        .max_by_key(|p| p.valid.from)
    {
        return Some(ResolvedPrice {
            price: p.price,
            source: PriceSource::Contract {
                contract: p.contract,
                id: p.id,
            },
        });
    }
    let usable = |l: &&PriceList| {
        l.active
            && same_currency(&l.currency, &req.currency)
            && l.valid.contains(req.date)
            && l.item.is_some()
    };
    let list = req
        .account_price_list
        .and_then(|id| lists.iter().filter(usable).find(|l| l.id == id))
        .or_else(|| lists.iter().filter(usable).max_by_key(|l| l.valid.from))?;
    let item = list.item.as_ref()?;
    let ratio = unit_ratio(req, item.unit, factors);
    let quantity_in_item_unit = req.quantity * ratio;
    let price_break = item
        .breaks
        .iter()
        .filter(|b| b.min_quantity <= quantity_in_item_unit)
        .max_by_key(|b| b.min_quantity);
    let item_price = match price_break {
        Some(b) => match (b.price, b.discount_percent) {
            (Some(price), _) => price,
            (None, Some(pct)) => {
                item.list_price * (Decimal::ONE_HUNDRED - pct) / Decimal::ONE_HUNDRED
            }
            (None, None) => item.list_price,
        },
        None => item.list_price,
    };
    Some(ResolvedPrice {
        price: item_price * ratio,
        source: PriceSource::PriceList {
            list: list.id,
            item: item.id,
            price_break: price_break.map(|b| b.id),
        },
    })
}

#[cfg(test)]
mod resolve_price {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap_or_default()
    }

    fn day(m: u32, dd: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, dd).unwrap_or_default()
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn request(quantity: &str) -> PriceRequest {
        PriceRequest {
            currency: "SAR".into(),
            date: day(6, 1),
            quantity: d(quantity),
            unit: None,
            default_unit: Some(u(100)),
            account_price_list: None,
        }
    }

    fn list(id: u128, currency: &str, breaks: Vec<PriceBreak>) -> PriceList {
        PriceList {
            id: u(id),
            currency: currency.into(),
            active: true,
            valid: Validity {
                from: Some(day(1, 1)),
                to: None,
            },
            item: Some(ListItem {
                id: u(id + 1000),
                list_price: d("100"),
                unit: Some(u(100)),
                breaks,
            }),
        }
    }

    #[test]
    fn account_price_beats_contract_and_list() {
        let account = [AccountPrice {
            id: u(1),
            currency: "sar".into(),
            price: d("80"),
            valid: Validity::default(),
        }];
        let contract = [ContractPrice {
            id: u(2),
            contract: u(3),
            currency: "SAR".into(),
            price: d("85"),
            valid: Validity::default(),
        }];
        let lists = [list(10, "SAR", vec![])];
        let r = resolve(
            &request("1"),
            &account,
            &contract,
            &lists,
            &UnitFactors::new(),
        );
        assert_eq!(
            r.map(|r| r.source),
            Some(PriceSource::AccountPrice { id: u(1) })
        );
        let r = resolve(&request("1"), &[], &contract, &lists, &UnitFactors::new());
        assert_eq!(
            r.map(|r| r.price),
            Some(d("85")),
            "the contracted price comes before the list"
        );
    }

    #[test]
    fn expired_rows_and_other_currencies_are_skipped() {
        let account = [AccountPrice {
            id: u(1),
            currency: "SAR".into(),
            price: d("80"),
            valid: Validity {
                from: None,
                to: Some(day(5, 31)),
            },
        }];
        let lists = [list(10, "USD", vec![]), list(20, "SAR", vec![])];
        let r = resolve(&request("1"), &account, &[], &lists, &UnitFactors::new())
            .unwrap_or_else(|| panic!("a price list price"));
        assert_eq!(
            r.source,
            PriceSource::PriceList {
                list: u(20),
                item: u(1020),
                price_break: None
            }
        );
        assert_eq!(r.price, d("100"));
    }

    #[test]
    fn breaks_apply_by_quantity_with_price_or_discount() {
        let breaks = vec![
            PriceBreak {
                id: u(50),
                min_quantity: d("10"),
                price: Some(d("90")),
                discount_percent: None,
            },
            PriceBreak {
                id: u(51),
                min_quantity: d("100"),
                price: None,
                discount_percent: Some(d("25")),
            },
        ];
        let lists = [list(10, "SAR", breaks)];
        let price =
            |q| resolve(&request(q), &[], &[], &lists, &UnitFactors::new()).map(|r| r.price);
        assert_eq!(price("9"), Some(d("100")));
        assert_eq!(price("10"), Some(d("90")));
        assert_eq!(price("150"), Some(d("75")));
    }

    #[test]
    fn units_convert_through_their_factors() {
        // The item is priced per piece (factor 1); a box holds 12 pieces.
        let lists = [list(
            10,
            "SAR",
            vec![PriceBreak {
                id: u(50),
                min_quantity: d("24"),
                price: Some(d("90")),
                discount_percent: None,
            }],
        )];
        let factors: UnitFactors = [(u(100), d("1")), (u(200), d("12"))].into_iter().collect();
        let mut req = request("2");
        req.unit = Some(u(200));
        // Two boxes are 24 pieces, so the break applies: 12 x 90 per box.
        let r = resolve(&req, &[], &[], &lists, &factors);
        assert_eq!(r.map(|r| r.price), Some(d("1080")));
    }

    #[test]
    fn the_accounts_own_list_wins_over_the_newest() {
        let mut own = list(10, "SAR", vec![]);
        if let Some(item) = own.item.as_mut() {
            item.list_price = d("70");
        }
        let mut newer = list(20, "SAR", vec![]);
        newer.valid.from = Some(day(5, 1));
        let mut req = request("1");
        req.account_price_list = Some(u(10));
        let r = resolve(
            &req,
            &[],
            &[],
            &[own.clone(), newer.clone()],
            &UnitFactors::new(),
        );
        assert_eq!(r.map(|r| r.price), Some(d("70")));
        req.account_price_list = None;
        let r = resolve(&req, &[], &[], &[own, newer], &UnitFactors::new());
        assert_eq!(
            r.map(|r| r.price),
            Some(d("100")),
            "else the newest valid list"
        );
    }
}

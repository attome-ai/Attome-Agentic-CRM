//! F8-T7 (part): what shipping a cart costs to an address.
//!
//! A shipping zone (`shipping_zone`, sales pack changeset 0030) covers the
//! countries in `countries` (ISO codes, comma separated; empty: every
//! country) and, when `cities` is set, only those cities. Each of its rates
//! (`shipping_rate`) is one way to ship:
//!
//! - `flat`: `amount`;
//! - `by_weight`: `amount` when the cart's weight is inside
//!   `min_weight`..`max_weight` (an empty bound is open);
//! - `free_over`: nothing once the cart's total reaches `free_over_amount`,
//!   else `amount`;
//! - `carrier_live`: a carrier's live price; none is offered until an S12
//!   carrier connector quotes one.
//!
//! Cash on delivery adds the rate's `cod_fee`. [`quote_shipping`] lists the
//! options, cheapest first; checkout recomputes the chosen one, never taking
//! a price from the client.

use std::str::FromStr;

use attome_core::EngineState;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Where a cart ships to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShipTo {
    /// ISO 3166-1 alpha-2.
    pub country: String,
    pub city: Option<String>,
}

/// A zone's rate, as pricing reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rate {
    pub id: Uuid,
    pub zone: String,
    pub method: String,
    pub amount: Decimal,
    pub min_weight: Option<Decimal>,
    pub max_weight: Option<Decimal>,
    pub free_over: Option<Decimal>,
    pub cod_fee: Decimal,
}

/// One way to ship a cart.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ShippingOption {
    pub rate_id: Uuid,
    pub zone: String,
    pub method: String,
    /// Decimals in text.
    pub amount: String,
    /// What cash on delivery adds.
    pub cod_fee: String,
}

fn listed(list: Option<&str>, value: &str) -> bool {
    match list.map(str::trim).filter(|l| !l.is_empty()) {
        None => true,
        Some(list) => list
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(value.trim())),
    }
}

/// Whether a zone with `countries` and `cities` covers `to`. Pure.
pub fn zone_covers(countries: Option<&str>, cities: Option<&str>, to: &ShipTo) -> bool {
    listed(countries, &to.country)
        && match cities.map(str::trim).filter(|c| !c.is_empty()) {
            None => true,
            Some(_) => to.city.as_deref().is_some_and(|city| listed(cities, city)),
        }
}

/// What `rate` charges for a cart of `weight` and `total`, cash on
/// delivery adding its fee; `None` when it does not ship this cart. Pure.
pub fn rate_amount(rate: &Rate, weight: Decimal, total: Decimal, cod: bool) -> Option<Decimal> {
    let base = match rate.method.as_str() {
        "flat" => rate.amount,
        "by_weight" => {
            let above = rate.min_weight.is_none_or(|min| weight >= min);
            let below = rate.max_weight.is_none_or(|max| weight <= max);
            if !(above && below) {
                return None;
            }
            rate.amount
        }
        "free_over" => match rate.free_over {
            Some(threshold) if total >= threshold => Decimal::ZERO,
            _ => rate.amount,
        },
        // No live carrier quote yet (S12).
        _ => return None,
    };
    Some(if cod { base + rate.cod_fee } else { base })
}

fn dec(text: Option<String>) -> Option<Decimal> {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
}

type RateRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The live rates of the zones covering `to`.
pub async fn rates_for(state: &EngineState, to: &ShipTo) -> Result<Vec<Rate>, AppError> {
    let rows: Vec<RateRow> = sqlx::query_as(
        "SELECT r.id, z.name, z.countries, z.cities, r.method::text, r.amount::text, \
                r.min_weight::text, r.max_weight::text, r.free_over_amount::text, r.cod_fee::text \
           FROM shipping_rate r JOIN shipping_zone z ON z.id = r.shipping_zone_ref \
          WHERE (r.is_active IS NULL OR r.is_active = true) \
            AND (z.is_active IS NULL OR z.is_active = true) \
          ORDER BY z.name, r.id LIMIT 500",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter(|row| zone_covers(row.2.as_deref(), row.3.as_deref(), to))
        .map(
            |(id, zone, _, _, method, amount, min, max, free_over, cod_fee)| Rate {
                id,
                zone: zone.unwrap_or_default(),
                method,
                amount: dec(amount).unwrap_or(Decimal::ZERO),
                min_weight: dec(min),
                max_weight: dec(max),
                free_over: dec(free_over),
                cod_fee: dec(cod_fee).unwrap_or(Decimal::ZERO),
            },
        )
        .collect())
}

/// The ways to ship a cart of `weight` and `total` to `to`, cheapest first.
pub async fn quote_shipping(
    state: &EngineState,
    to: &ShipTo,
    weight: Decimal,
    total: Decimal,
) -> Result<Vec<ShippingOption>, AppError> {
    let mut options: Vec<(Decimal, ShippingOption)> = rates_for(state, to)
        .await?
        .into_iter()
        .filter_map(|rate| {
            let amount = rate_amount(&rate, weight, total, false)?;
            Some((
                amount,
                ShippingOption {
                    rate_id: rate.id,
                    zone: rate.zone,
                    method: rate.method,
                    amount: amount.to_string(),
                    cod_fee: rate.cod_fee.to_string(),
                },
            ))
        })
        .collect();
    options.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(options.into_iter().map(|(_, option)| option).collect())
}

/// [`quote_shipping`] for a weightless order of `total` (a decimal in
/// text) to `country` and `city`, as the shop's routes take them.
pub async fn quote_for_address(
    state: &EngineState,
    country: &str,
    city: Option<&str>,
    total: Option<&str>,
) -> Result<Vec<ShippingOption>, AppError> {
    let total = total
        .and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO);
    let to = ShipTo {
        country: country.trim().to_ascii_uppercase(),
        city: city.map(str::to_owned),
    };
    quote_shipping(state, &to, Decimal::ZERO, total).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn rate(method: &str) -> Rate {
        Rate {
            id: Uuid::nil(),
            zone: "KSA".into(),
            method: method.into(),
            amount: d("25"),
            min_weight: None,
            max_weight: None,
            free_over: None,
            cod_fee: d("10"),
        }
    }

    #[test]
    fn free_over_threshold_is_zero() {
        let mut r = rate("free_over");
        r.free_over = Some(d("300"));
        assert_eq!(
            rate_amount(&r, d("1"), d("300"), false),
            Some(Decimal::ZERO)
        );
        assert_eq!(rate_amount(&r, d("1"), d("299.99"), false), Some(d("25")));
        assert_eq!(
            rate_amount(&rate("carrier_live"), d("1"), d("1"), false),
            None
        );
    }

    #[test]
    fn weight_band_selected() {
        let mut light = rate("by_weight");
        light.max_weight = Some(d("5"));
        let mut heavy = rate("by_weight");
        heavy.min_weight = Some(d("5.001"));
        heavy.amount = d("60");
        assert_eq!(rate_amount(&light, d("4"), d("0"), false), Some(d("25")));
        assert_eq!(rate_amount(&heavy, d("4"), d("0"), false), None);
        assert_eq!(rate_amount(&light, d("9"), d("0"), false), None);
        assert_eq!(rate_amount(&heavy, d("9"), d("0"), false), Some(d("60")));
        let riyadh = ShipTo {
            country: "SA".into(),
            city: Some("Riyadh".into()),
        };
        assert!(zone_covers(Some("sa, ae"), None, &riyadh));
        assert!(zone_covers(Some("SA"), Some("Riyadh,Jeddah"), &riyadh));
        assert!(!zone_covers(Some("SA"), Some("Dammam"), &riyadh));
        assert!(!zone_covers(Some("AE"), None, &riyadh));
    }

    #[test]
    fn cod_fee_added() {
        assert_eq!(
            rate_amount(&rate("flat"), d("1"), d("1"), true),
            Some(d("35"))
        );
        let mut free = rate("free_over");
        free.free_over = Some(d("100"));
        assert_eq!(rate_amount(&free, d("1"), d("500"), true), Some(d("10")));
    }
}

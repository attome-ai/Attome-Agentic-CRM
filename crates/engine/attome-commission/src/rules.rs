//! Commission plan evaluation (roadmap F10-T4), pure: a component's rate
//! table, gate, margin floor and caps applied to a participant's credits for
//! a period, each computed line carrying the steps that produced it.
//!
//! Order, as the plan design fixes it: gate (nothing below the attainment
//! gate), floor (a credit whose margin is under the floor earns nothing),
//! rate by band (retroactive: the whole period at the band reached;
//! marginal: each slice of attainment at its own band), cap per deal, cap per
//! period. Bands are on attainment percent and may not overlap; publishing a
//! plan compiles it and refuses a table that overlaps. Explanation steps are
//! message keys with their values, so the UI renders them in English or
//! Arabic.

use rust_decimal::{Decimal, RoundingStrategy};
use uuid::Uuid;

/// One row of a rate table: from `from_pct` (inclusive) to `to_pct`
/// (exclusive; `None` is open-ended), pay `rate_pct` of the credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Band {
    pub from_pct: Decimal,
    pub to_pct: Option<Decimal>,
    pub rate_pct: Decimal,
}

/// How bands apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierMode {
    /// Every credit in the period at the rate of the band attainment reached.
    Retroactive,
    /// Each credit at the band its slice of attainment falls in.
    Marginal,
}

/// A compiled component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub id: Uuid,
    pub bands: Vec<Band>,
    pub mode: TierMode,
    /// Attainment percent below which the component pays nothing.
    pub gate_pct: Option<Decimal>,
    /// Margin percent below which a credit earns nothing.
    pub margin_floor_pct: Option<Decimal>,
    pub cap_per_deal: Option<Decimal>,
    pub cap_per_period: Option<Decimal>,
    pub minor_units: u32,
}

/// A credit to pay on (the `comp_credit` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    pub id: Uuid,
    pub deal: Uuid,
    pub amount: Decimal,
    pub margin_pct: Option<Decimal>,
}

/// One explanation step: a message key and its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub key: &'static str,
    pub values: Vec<(&'static str, String)>,
}

/// The payout of one credit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedLine {
    pub credit: Uuid,
    pub payout: Decimal,
    pub steps: Vec<Step>,
}

/// Why a plan does not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    NoBands,
    /// The two band rows (0-based) overlap.
    OverlappingBands(usize, usize),
    EmptyBand(usize),
}

/// Checks a component's table at publish.
pub fn compile(component: &Component) -> Result<(), PlanError> {
    if component.bands.is_empty() {
        return Err(PlanError::NoBands);
    }
    for (i, band) in component.bands.iter().enumerate() {
        if band.to_pct.is_some_and(|to| to <= band.from_pct) {
            return Err(PlanError::EmptyBand(i));
        }
    }
    for i in 0..component.bands.len() {
        for j in (i + 1)..component.bands.len() {
            let (a, b) = (&component.bands[i], &component.bands[j]);
            let a_end = a.to_pct.unwrap_or(Decimal::MAX);
            let b_end = b.to_pct.unwrap_or(Decimal::MAX);
            if a.from_pct < b_end && b.from_pct < a_end {
                return Err(PlanError::OverlappingBands(i, j));
            }
        }
    }
    Ok(())
}

fn band_for(component: &Component, attainment_pct: Decimal) -> Option<&Band> {
    component
        .bands
        .iter()
        .find(|b| attainment_pct >= b.from_pct && b.to_pct.is_none_or(|to| attainment_pct < to))
}

fn step(key: &'static str, values: Vec<(&'static str, String)>) -> Step {
    Step { key, values }
}

/// Pays `credits` (in credit order) for a period whose quota is `quota`.
/// `attainment_pct` before each credit is computed from the running total.
pub fn evaluate(component: &Component, credits: &[Credit], quota: Decimal) -> Vec<ComputedLine> {
    let round = |v: Decimal| {
        v.round_dp_with_strategy(
            component.minor_units,
            RoundingStrategy::MidpointAwayFromZero,
        )
    };
    let pct_of = |v: Decimal| {
        if quota.is_zero() {
            Decimal::ZERO
        } else {
            v / quota * Decimal::ONE_HUNDRED
        }
    };
    let period_total: Decimal = credits.iter().map(|c| c.amount).sum();
    let final_attainment = pct_of(period_total);

    let gated = component
        .gate_pct
        .is_some_and(|gate| final_attainment < gate);
    let retro_band = band_for(component, final_attainment);
    let mut running = Decimal::ZERO;
    let mut paid_in_period = Decimal::ZERO;
    let mut paid_per_deal: std::collections::BTreeMap<Uuid, Decimal> =
        std::collections::BTreeMap::new();
    let mut out = Vec::with_capacity(credits.len());

    for credit in credits {
        let mut steps = Vec::new();
        let before = running;
        running += credit.amount;
        let mut payout = Decimal::ZERO;

        if gated {
            steps.push(step(
                "commission.gate_not_met",
                vec![
                    ("attainment", final_attainment.round_dp(2).to_string()),
                    ("gate", component.gate_pct.unwrap_or_default().to_string()),
                ],
            ));
        } else if let Some(floor) = component.margin_floor_pct
            && credit.margin_pct.is_some_and(|m| m < floor)
        {
            steps.push(step(
                "commission.below_margin_floor",
                vec![
                    ("margin", credit.margin_pct.unwrap_or_default().to_string()),
                    ("floor", floor.to_string()),
                ],
            ));
        } else {
            match component.mode {
                TierMode::Retroactive => {
                    let rate = retro_band.map_or(Decimal::ZERO, |b| b.rate_pct);
                    payout = credit.amount * rate / Decimal::ONE_HUNDRED;
                    steps.push(step(
                        "commission.retroactive_rate",
                        vec![
                            ("attainment", final_attainment.round_dp(2).to_string()),
                            ("rate", rate.to_string()),
                        ],
                    ));
                }
                TierMode::Marginal => {
                    // Walk the credit's slice of attainment band by band.
                    let mut from = before;
                    while from < running {
                        let at_pct = pct_of(from);
                        let Some(band) = band_for(component, at_pct) else {
                            break;
                        };
                        let band_end_amount = band.to_pct.map_or(running, |to| {
                            if quota.is_zero() {
                                running
                            } else {
                                to * quota / Decimal::ONE_HUNDRED
                            }
                        });
                        let to = band_end_amount.min(running).max(from);
                        if to == from {
                            break;
                        }
                        let slice = to - from;
                        payout += slice * band.rate_pct / Decimal::ONE_HUNDRED;
                        steps.push(step(
                            "commission.marginal_slice",
                            vec![
                                ("slice", slice.to_string()),
                                ("rate", band.rate_pct.to_string()),
                            ],
                        ));
                        from = to;
                    }
                }
            }
        }

        if let Some(cap) = component.cap_per_deal {
            let so_far = paid_per_deal.get(&credit.deal).copied().unwrap_or_default();
            let room = (cap - so_far).max(Decimal::ZERO);
            if payout > room {
                steps.push(step(
                    "commission.capped_per_deal",
                    vec![("cap", cap.to_string())],
                ));
                payout = room;
            }
        }
        if let Some(cap) = component.cap_per_period {
            let room = (cap - paid_in_period).max(Decimal::ZERO);
            if payout > room {
                steps.push(step(
                    "commission.capped_per_period",
                    vec![("cap", cap.to_string())],
                ));
                payout = room;
            }
        }
        let payout = round(payout);
        paid_in_period += payout;
        *paid_per_deal.entry(credit.deal).or_default() += payout;
        out.push(ComputedLine {
            credit: credit.id,
            payout,
            steps,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn band(from: &str, to: Option<&str>, rate: &str) -> Band {
        Band {
            from_pct: dec(from),
            to_pct: to.map(dec),
            rate_pct: dec(rate),
        }
    }

    fn component(bands: Vec<Band>, mode: TierMode) -> Component {
        Component {
            id: Uuid::nil(),
            bands,
            mode,
            gate_pct: None,
            margin_floor_pct: None,
            cap_per_deal: None,
            cap_per_period: None,
            minor_units: 2,
        }
    }

    fn credit(n: u128, amount: &str) -> Credit {
        Credit {
            id: Uuid::from_u128(n),
            deal: Uuid::from_u128(100 + n),
            amount: dec(amount),
            margin_pct: None,
        }
    }

    fn total(lines: &[ComputedLine]) -> Decimal {
        lines.iter().map(|l| l.payout).sum()
    }

    fn tiers() -> Vec<Band> {
        vec![band("0", Some("100"), "5"), band("100", None, "10")]
    }

    #[test]
    fn flat_rate() {
        let c = component(vec![band("0", None, "8")], TierMode::Retroactive);
        let lines = evaluate(&c, &[credit(1, "1000"), credit(2, "500")], dec("10000"));
        assert_eq!(total(&lines), dec("120.00"));
    }

    #[test]
    fn retroactive_tier_pays_whole_period_at_top_band() {
        let c = component(tiers(), TierMode::Retroactive);
        let lines = evaluate(&c, &[credit(1, "800"), credit(2, "400")], dec("1000"));
        assert_eq!(total(&lines), dec("120.00"));
    }

    #[test]
    fn marginal_tier_pays_each_slice() {
        let c = component(tiers(), TierMode::Marginal);
        let lines = evaluate(&c, &[credit(1, "800"), credit(2, "400")], dec("1000"));
        // 1,000 at 5% and 200 at 10%.
        assert_eq!(total(&lines), dec("70.00"));
        assert_eq!(lines[1].payout, dec("30.00"));
    }

    #[test]
    fn gate_zeroes_below_threshold() {
        let mut c = component(tiers(), TierMode::Retroactive);
        c.gate_pct = Some(dec("50"));
        let lines = evaluate(&c, &[credit(1, "400")], dec("1000"));
        assert_eq!(total(&lines), Decimal::ZERO);
        assert_eq!(lines[0].steps[0].key, "commission.gate_not_met");
    }

    #[test]
    fn cap_per_period_limits_total() {
        let mut c = component(vec![band("0", None, "10")], TierMode::Retroactive);
        c.cap_per_period = Some(dec("150"));
        let lines = evaluate(&c, &[credit(1, "1000"), credit(2, "1000")], dec("1000"));
        assert_eq!(total(&lines), dec("150.00"));
        assert_eq!(lines[1].payout, dec("50.00"));
    }

    #[test]
    fn overlapping_bands_rejected() {
        let c = component(
            vec![band("0", Some("110"), "5"), band("100", None, "10")],
            TierMode::Retroactive,
        );
        assert_eq!(compile(&c), Err(PlanError::OverlappingBands(0, 1)));
        assert_eq!(compile(&component(tiers(), TierMode::Marginal)), Ok(()));
    }

    #[test]
    fn margin_floor_skips_thin_deals_and_deal_cap_applies() {
        let mut c = component(vec![band("0", None, "10")], TierMode::Retroactive);
        c.margin_floor_pct = Some(dec("20"));
        c.cap_per_deal = Some(dec("60"));
        let mut thin = credit(1, "1000");
        thin.margin_pct = Some(dec("12"));
        let lines = evaluate(&c, &[thin, credit(2, "1000")], dec("1000"));
        assert_eq!(lines[0].payout, Decimal::ZERO);
        assert_eq!(lines[1].payout, dec("60.00"));
    }
}

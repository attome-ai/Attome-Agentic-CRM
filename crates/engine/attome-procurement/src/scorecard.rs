//! Vendor scorecards (roadmap W2-T2), pure: one score per vendor per month
//! from its goods receipts (delivered on time, and accepted rather than
//! rejected) and its supplier SLA clocks (met or breached). Each part is a
//! share from 0 to 100; the score is their weighted mean over the parts that
//! had anything to measure that month.

use std::collections::BTreeMap;

use chrono::{Datelike, NaiveDate};
use uuid::Uuid;

/// One goods receipt line as the scorecard sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptFact {
    pub vendor: Uuid,
    pub expected_on: Option<NaiveDate>,
    pub received_on: NaiveDate,
    pub quantity: f64,
    pub rejected_quantity: f64,
}

/// One supplier SLA clock that closed in the month.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlaFact {
    pub vendor: Uuid,
    pub closed_on: NaiveDate,
    pub met: bool,
}

/// How much each part counts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Weights {
    pub on_time: f64,
    pub quality: f64,
    pub sla: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            on_time: 0.4,
            quality: 0.4,
            sla: 0.2,
        }
    }
}

/// A vendor's month.
#[derive(Debug, Clone, PartialEq)]
pub struct Scorecard {
    pub vendor: Uuid,
    /// The first day of the month.
    pub month: NaiveDate,
    /// Receipts that arrived on or before the expected date, in percent.
    pub on_time_pct: Option<f64>,
    /// Accepted quantity out of received quantity, in percent.
    pub quality_pct: Option<f64>,
    /// SLA clocks met, in percent.
    pub sla_pct: Option<f64>,
    /// The weighted score from 0 to 100; `None` with nothing to measure.
    pub score: Option<f64>,
    pub receipts: usize,
}

#[derive(Default)]
struct Tally {
    dated: u32,
    on_time: u32,
    received: f64,
    rejected: f64,
    clocks: u32,
    met: u32,
    receipts: usize,
}

fn month_of(d: NaiveDate) -> NaiveDate {
    d.with_day(1).unwrap_or(d)
}

fn pct(part: f64, whole: f64) -> Option<f64> {
    (whole > 0.0).then(|| (part / whole * 100.0).clamp(0.0, 100.0))
}

/// The scorecards for every vendor and month the facts touch, ordered by
/// vendor then month.
pub fn monthly(receipts: &[ReceiptFact], clocks: &[SlaFact], weights: Weights) -> Vec<Scorecard> {
    let mut tallies: BTreeMap<(Uuid, NaiveDate), Tally> = BTreeMap::new();
    for r in receipts {
        let t = tallies
            .entry((r.vendor, month_of(r.received_on)))
            .or_default();
        t.receipts += 1;
        if let Some(expected) = r.expected_on {
            t.dated += 1;
            if r.received_on <= expected {
                t.on_time += 1;
            }
        }
        t.received += r.quantity.max(0.0);
        t.rejected += r.rejected_quantity.max(0.0);
    }
    for c in clocks {
        let t = tallies
            .entry((c.vendor, month_of(c.closed_on)))
            .or_default();
        t.clocks += 1;
        if c.met {
            t.met += 1;
        }
    }
    tallies
        .into_iter()
        .map(|((vendor, month), t)| {
            let on_time_pct = pct(f64::from(t.on_time), f64::from(t.dated));
            let quality_pct = pct(t.received - t.rejected, t.received);
            let sla_pct = pct(f64::from(t.met), f64::from(t.clocks));
            let parts = [
                (on_time_pct, weights.on_time),
                (quality_pct, weights.quality),
                (sla_pct, weights.sla),
            ];
            let weight: f64 = parts
                .iter()
                .filter(|(v, _)| v.is_some())
                .map(|(_, w)| w)
                .sum();
            let score = (weight > 0.0).then(|| {
                parts
                    .iter()
                    .filter_map(|(v, w)| v.map(|v| v * w))
                    .sum::<f64>()
                    / weight
            });
            Scorecard {
                vendor,
                month,
                on_time_pct,
                quality_pct,
                sla_pct,
                score,
                receipts: t.receipts,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, d).unwrap_or_default()
    }

    fn receipt(
        vendor: u128,
        expected: Option<NaiveDate>,
        received: NaiveDate,
        q: f64,
        rejected: f64,
    ) -> ReceiptFact {
        ReceiptFact {
            vendor: Uuid::from_u128(vendor),
            expected_on: expected,
            received_on: received,
            quantity: q,
            rejected_quantity: rejected,
        }
    }

    #[test]
    fn on_time_quality_and_sla_make_the_score() {
        let receipts = [
            receipt(1, Some(day(3, 10)), day(3, 9), 100.0, 0.0),
            receipt(1, Some(day(3, 10)), day(3, 12), 100.0, 20.0),
        ];
        let clocks = [
            SlaFact {
                vendor: Uuid::from_u128(1),
                closed_on: day(3, 20),
                met: true,
            },
            SlaFact {
                vendor: Uuid::from_u128(1),
                closed_on: day(3, 21),
                met: true,
            },
        ];
        let cards = monthly(&receipts, &clocks, Weights::default());
        assert_eq!(cards.len(), 1);
        let c = &cards[0];
        assert_eq!(c.month, day(3, 1));
        assert_eq!(c.on_time_pct, Some(50.0));
        assert_eq!(c.quality_pct, Some(90.0));
        assert_eq!(c.sla_pct, Some(100.0));
        // 0.4 * 50 + 0.4 * 90 + 0.2 * 100 = 76
        assert!((c.score.unwrap_or_default() - 76.0).abs() < 1e-9);
    }

    #[test]
    fn missing_parts_are_left_out_of_the_weighting() {
        let receipts = [receipt(2, None, day(4, 2), 10.0, 5.0)];
        let cards = monthly(&receipts, &[], Weights::default());
        assert_eq!(cards[0].on_time_pct, None);
        assert_eq!(cards[0].sla_pct, None);
        assert_eq!(cards[0].score, Some(50.0), "quality alone");
    }

    #[test]
    fn vendors_and_months_are_kept_apart() {
        let receipts = [
            receipt(1, Some(day(5, 1)), day(5, 1), 1.0, 0.0),
            receipt(1, Some(day(6, 1)), day(6, 2), 1.0, 0.0),
            receipt(3, Some(day(5, 1)), day(5, 1), 1.0, 1.0),
        ];
        let cards = monthly(&receipts, &[], Weights::default());
        assert_eq!(cards.len(), 3);
        assert_eq!(cards[0].month, day(5, 1));
        assert_eq!(cards[1].month, day(6, 1));
        assert_eq!(cards[1].on_time_pct, Some(0.0));
        assert_eq!(cards[2].quality_pct, Some(0.0));
    }
}

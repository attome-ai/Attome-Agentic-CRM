//! F6-T5: available-to-promise. A line's promised date is today plus the
//! handling days when the location's free stock covers it, the day of the
//! first incoming receipt that covers the shortfall (plus handling) when one
//! does, and today plus the lead time when stock is not tracked or nothing
//! incoming covers it. The fulfilment order is promised for its latest line.
//!
//! Stock comes through `attome_core::stock_seam::StockSource`; with none
//! registered (no inventory engine) every line is `NotTracked`.

use attome_core::stock_seam::Availability;
use chrono::{Days, NaiveDate};
use rust_decimal::Decimal;

/// Days to pick and pack once stock is there.
pub const HANDLING_DAYS: u64 = 1;
/// Days to promise when stock is not tracked or nothing covers it.
pub const DEFAULT_LEAD_DAYS: u64 = 7;

/// When a line can ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Promise {
    /// From stock on hand.
    Available(NaiveDate),
    /// Once an incoming receipt arrives.
    Incoming(NaiveDate),
    /// Stock is not tracked, or nothing incoming covers it.
    NotTracked(NaiveDate),
}

impl Promise {
    pub fn date(self) -> NaiveDate {
        match self {
            Self::Available(d) | Self::Incoming(d) | Self::NotTracked(d) => d,
        }
    }

    /// Whether the line is short of stock (its expected date is worth
    /// recording).
    pub fn is_short(self) -> bool {
        !matches!(self, Self::Available(_))
    }
}

fn plus(day: NaiveDate, days: u64) -> NaiveDate {
    day.checked_add_days(Days::new(days)).unwrap_or(day)
}

/// The promise for `qty` of a product at a location. Pure.
pub fn promised_date(
    qty: Decimal,
    avail: Option<&Availability>,
    today: NaiveDate,
    lead_days: u64,
) -> Promise {
    let Some(avail) = avail else {
        return Promise::NotTracked(plus(today, lead_days));
    };
    let mut have = avail.free();
    if have >= qty {
        return Promise::Available(plus(today, HANDLING_DAYS));
    }
    let mut incoming = avail.incoming.clone();
    incoming.sort_by_key(|(day, _)| *day);
    for (day, amount) in incoming {
        have += amount.max(Decimal::ZERO);
        if have >= qty {
            return Promise::Incoming(plus(day.max(today), HANDLING_DAYS));
        }
    }
    Promise::NotTracked(plus(today, lead_days))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn atp_available_now() {
        let avail = Availability {
            on_hand: Decimal::from(10),
            reserved: Decimal::from(4),
            incoming: Vec::new(),
        };
        assert_eq!(
            promised_date(Decimal::from(6), Some(&avail), day("2026-10-25"), 7),
            Promise::Available(day("2026-10-26"))
        );
    }

    #[test]
    fn atp_waits_for_incoming() {
        let avail = Availability {
            on_hand: Decimal::from(2),
            reserved: Decimal::ZERO,
            incoming: vec![
                (day("2026-11-10"), Decimal::from(5)),
                (day("2026-11-01"), Decimal::from(1)),
            ],
        };
        // 2 free + 1 on the 1st is not enough; the 10th's 5 covers it.
        let promise = promised_date(Decimal::from(4), Some(&avail), day("2026-10-25"), 7);
        assert_eq!(promise, Promise::Incoming(day("2026-11-11")));
        assert!(promise.is_short());
        // Nothing covers 20: the lead time.
        assert_eq!(
            promised_date(Decimal::from(20), Some(&avail), day("2026-10-25"), 7),
            Promise::NotTracked(day("2026-11-01"))
        );
    }

    #[test]
    fn atp_not_tracked_uses_lead_time() {
        assert_eq!(
            promised_date(Decimal::ONE, None, day("2026-10-25"), DEFAULT_LEAD_DAYS),
            Promise::NotTracked(day("2026-11-01"))
        );
    }
}

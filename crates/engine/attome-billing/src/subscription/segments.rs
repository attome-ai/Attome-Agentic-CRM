//! Dated segments (roadmap F3-T2): a subscription line's quantity and price
//! over time. A change never edits a segment; it closes the one in force at
//! the effective date and opens the next, so the line can be read as it was
//! on any date.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Why a segment changed, the `subscription_segment.change_kind` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    New,
    Add,
    Remove,
    Upgrade,
    Downgrade,
    PriceChange,
    Renewal,
    Cancel,
    Pause,
    Resume,
}

/// One period of a line at one quantity and price. `valid_to` is exclusive;
/// `None` runs to the end of the subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub line_id: Uuid,
    pub valid_from: NaiveDate,
    pub valid_to: Option<NaiveDate>,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub change_kind: ChangeKind,
}

impl Segment {
    /// Whether the segment is in force on `date`.
    pub fn covers(&self, date: NaiveDate) -> bool {
        self.valid_from <= date && self.valid_to.is_none_or(|to| date < to)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentError {
    #[error("a change must take effect after the segment it changes starts")]
    BeforeStart,
    #[error("a change must take effect before the segment it changes ends")]
    AfterEnd,
    #[error("two segments of line {line_id} overlap on {on}")]
    Overlap { line_id: Uuid, on: NaiveDate },
}

/// The segment in force on `date` for each line, at most one per line, in
/// the order the lines first appear.
pub fn as_of(segments: &[Segment], date: NaiveDate) -> Vec<&Segment> {
    let mut out: Vec<&Segment> = Vec::new();
    for segment in segments.iter().filter(|s| s.covers(date)) {
        if !out.iter().any(|s| s.line_id == segment.line_id) {
            out.push(segment);
        }
    }
    out
}

/// Closes `current` at `effective` and opens the next segment from there
/// with the new quantity and price. The second segment keeps the first's
/// end, so a change inside a closed range stays inside it.
pub fn split_at(
    current: &Segment,
    effective: NaiveDate,
    new_quantity: Decimal,
    new_price: Decimal,
    kind: ChangeKind,
) -> Result<(Segment, Segment), SegmentError> {
    if effective <= current.valid_from {
        return Err(SegmentError::BeforeStart);
    }
    if current.valid_to.is_some_and(|to| effective >= to) {
        return Err(SegmentError::AfterEnd);
    }
    let closed = Segment {
        valid_to: Some(effective),
        ..current.clone()
    };
    let opened = Segment {
        line_id: current.line_id,
        valid_from: effective,
        valid_to: current.valid_to,
        quantity: new_quantity,
        unit_price: new_price,
        change_kind: kind,
    };
    Ok((closed, opened))
}

/// Refuses two segments of one line whose ranges overlap.
pub fn validate_no_overlap(segments: &[Segment]) -> Result<(), SegmentError> {
    for (i, a) in segments.iter().enumerate() {
        for b in &segments[i + 1..] {
            if a.line_id != b.line_id {
                continue;
            }
            // [a.from, a.to) and [b.from, b.to) overlap when each starts
            // before the other ends.
            let a_before_b_ends = b.valid_to.is_none_or(|to| a.valid_from < to);
            let b_before_a_ends = a.valid_to.is_none_or(|to| b.valid_from < to);
            if a_before_b_ends && b_before_a_ends {
                return Err(SegmentError::Overlap {
                    line_id: a.line_id,
                    on: a.valid_from.max(b.valid_from),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    fn seg(line: Uuid, from: NaiveDate, to: Option<NaiveDate>, qty: i64) -> Segment {
        Segment {
            line_id: line,
            valid_from: from,
            valid_to: to,
            quantity: Decimal::from(qty),
            unit_price: Decimal::from(10),
            change_kind: ChangeKind::New,
        }
    }

    #[test]
    fn as_of_returns_segment_in_force() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let segments = vec![
            seg(a, d(2026, 1, 1), Some(d(2026, 4, 1)), 5),
            seg(a, d(2026, 4, 1), None, 8),
            seg(b, d(2026, 2, 1), None, 1),
        ];
        let jan = as_of(&segments, d(2026, 1, 15));
        assert_eq!(jan.len(), 1, "line b has not started");
        assert_eq!(jan[0].quantity, Decimal::from(5));
        let april = as_of(&segments, d(2026, 4, 1));
        assert_eq!(april.len(), 2, "one segment per line");
        assert_eq!(
            april[0].quantity,
            Decimal::from(8),
            "the end date is exclusive"
        );
        assert!(as_of(&segments, d(2025, 12, 31)).is_empty());
    }

    #[test]
    fn split_closes_and_opens() {
        let line = Uuid::now_v7();
        let current = seg(line, d(2026, 1, 1), Some(d(2027, 1, 1)), 5);
        let (closed, opened) = split_at(
            &current,
            d(2026, 7, 1),
            Decimal::from(7),
            Decimal::from(12),
            ChangeKind::Add,
        )
        .expect("split");
        assert_eq!(closed.valid_to, Some(d(2026, 7, 1)));
        assert_eq!(closed.quantity, Decimal::from(5));
        assert_eq!(opened.valid_from, d(2026, 7, 1));
        assert_eq!(opened.valid_to, Some(d(2027, 1, 1)));
        assert_eq!(opened.quantity, Decimal::from(7));
        assert_eq!(opened.change_kind, ChangeKind::Add);
        validate_no_overlap(&[closed, opened]).expect("the halves do not overlap");
        assert_eq!(
            split_at(
                &current,
                d(2026, 1, 1),
                Decimal::ONE,
                Decimal::ONE,
                ChangeKind::Add
            ),
            Err(SegmentError::BeforeStart)
        );
        assert_eq!(
            split_at(
                &current,
                d(2027, 1, 1),
                Decimal::ONE,
                Decimal::ONE,
                ChangeKind::Add
            ),
            Err(SegmentError::AfterEnd)
        );
    }

    #[test]
    fn overlap_is_rejected() {
        let line = Uuid::now_v7();
        let other = Uuid::now_v7();
        let segments = vec![
            seg(line, d(2026, 1, 1), Some(d(2026, 6, 1)), 1),
            seg(line, d(2026, 5, 1), None, 2),
            seg(other, d(2026, 1, 1), None, 3),
        ];
        assert!(matches!(
            validate_no_overlap(&segments),
            Err(SegmentError::Overlap { .. })
        ));
        let touching = vec![
            seg(line, d(2026, 1, 1), Some(d(2026, 6, 1)), 1),
            seg(line, d(2026, 6, 1), None, 2),
        ];
        assert_eq!(validate_no_overlap(&touching), Ok(()));
    }
}

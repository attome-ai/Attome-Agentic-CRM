//! Change calendar checks (roadmap H3-T2), pure: before a change goes to
//! the change advisory board, its planned window is checked against the
//! other scheduled changes and the blackout windows.
//!
//! - Two changes conflict when they touch a shared configuration item and
//!   their windows overlap (a window is start-inclusive, end-exclusive, so
//!   back-to-back changes do not conflict). A conflict is a warning the
//!   board decides on.
//! - A blackout window refuses scheduling outright when it overlaps the
//!   change and applies to it: a blackout with no configuration items
//!   covers everything, otherwise only changes touching one of its items.
//!   An emergency change may go ahead in a blackout that allows emergencies.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// A planned window, start inclusive, end exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Window {
    pub fn overlaps(&self, other: &Window) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A change to schedule, or one already on the calendar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub id: Uuid,
    pub window: Window,
    pub configuration_items: Vec<Uuid>,
    pub emergency: bool,
}

/// A period when changes are not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blackout {
    pub id: Uuid,
    pub name: String,
    pub window: Window,
    /// Empty: every change.
    pub configuration_items: Vec<Uuid>,
    pub allows_emergency: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    pub change: Uuid,
    /// The configuration items both changes touch.
    pub shared_items: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct CalendarCheck {
    /// Overlapping changes on the same items: warnings for the board.
    pub conflicts: Vec<Conflict>,
    /// Blackouts the change falls in: scheduling is refused.
    pub blackouts: Vec<Uuid>,
}

impl CalendarCheck {
    /// Whether the change may be scheduled at all.
    pub fn schedulable(&self) -> bool {
        self.blackouts.is_empty()
    }
}

/// Checks `change` against the calendar (`others` may include the change
/// itself; it is skipped).
pub fn check(
    change: &PlannedChange,
    others: &[PlannedChange],
    blackouts: &[Blackout],
) -> CalendarCheck {
    let conflicts = others
        .iter()
        .filter(|o| o.id != change.id && o.window.overlaps(&change.window))
        .filter_map(|o| {
            let shared: Vec<Uuid> = o
                .configuration_items
                .iter()
                .filter(|ci| change.configuration_items.contains(ci))
                .copied()
                .collect();
            (!shared.is_empty()).then_some(Conflict {
                change: o.id,
                shared_items: shared,
            })
        })
        .collect();
    let blackouts = blackouts
        .iter()
        .filter(|b| b.window.overlaps(&change.window))
        .filter(|b| {
            b.configuration_items.is_empty()
                || b.configuration_items
                    .iter()
                    .any(|ci| change.configuration_items.contains(ci))
        })
        .filter(|b| !(change.emergency && b.allows_emergency))
        .map(|b| b.id)
        .collect();
    CalendarCheck {
        conflicts,
        blackouts,
    }
}

#[cfg(test)]
mod change_conflicts {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn window(day: u32, from: u32, to: u32) -> Window {
        let start = at(day, from);
        Window {
            start,
            end: start + chrono::Duration::hours(i64::from(to - from)),
        }
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn change(id: u128, w: Window, cis: &[u128]) -> PlannedChange {
        PlannedChange {
            id: u(id),
            window: w,
            configuration_items: cis.iter().map(|c| u(*c)).collect(),
            emergency: false,
        }
    }

    #[test]
    fn overlapping_changes_on_the_same_item_conflict() {
        let mine = change(1, window(3, 20, 23), &[100, 101]);
        let others = [
            change(2, window(3, 22, 23), &[101]),
            change(3, window(3, 22, 23), &[999]),
            change(4, window(3, 23, 24), &[100]),
            mine.clone(),
        ];
        let c = check(&mine, &others, &[]);
        assert_eq!(
            c.conflicts,
            vec![Conflict {
                change: u(2),
                shared_items: vec![u(101)]
            }],
            "another item, or a back-to-back window, is no conflict"
        );
        assert!(c.schedulable());
    }

    #[test]
    fn blackouts_refuse_scheduling() {
        let year_end = Blackout {
            id: u(50),
            name: "Year-end freeze".into(),
            window: Window {
                start: at(1, 0),
                end: at(5, 0),
            },
            configuration_items: vec![],
            allows_emergency: true,
        };
        let billing_only = Blackout {
            id: u(51),
            name: "Billing run".into(),
            window: window(3, 0, 6),
            configuration_items: vec![u(200)],
            allows_emergency: false,
        };
        let mine = change(1, window(3, 2, 4), &[100]);
        let c = check(&mine, &[], &[year_end.clone(), billing_only.clone()]);
        assert_eq!(
            c.blackouts,
            vec![u(50)],
            "the billing blackout is for another item"
        );
        assert!(!c.schedulable());

        let mut emergency = change(2, window(3, 2, 4), &[200]);
        emergency.emergency = true;
        let c = check(&emergency, &[], &[year_end, billing_only]);
        assert_eq!(
            c.blackouts,
            vec![u(51)],
            "an emergency passes the freeze that allows it, not the one that does not"
        );
    }
}

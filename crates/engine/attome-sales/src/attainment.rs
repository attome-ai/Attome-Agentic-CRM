//! Quota attainment (roadmap D12-T2), pure: how much of each quota is met,
//! under the crediting rule of its measure, rolled up a team tree.
//!
//! A credit event is a deal that closed won, an invoice that was issued, or
//! revenue that was recognised, with its date, amount and the people it is
//! credited to (the deal's splits). A quota counts the events of its own
//! rule inside its period. A manager's attainment is their own credits plus
//! those of everyone under them in the position tree.

use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use chrono::NaiveDate;

/// What counts toward a quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CreditRule {
    ClosedWon,
    Invoiced,
    Recognised,
}

/// One creditable event for one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    pub rule: CreditRule,
    pub user: Uuid,
    pub on: NaiveDate,
    pub amount: Decimal,
}

/// A quota for one person and period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    pub id: Uuid,
    pub user: Uuid,
    pub rule: CreditRule,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub target: Decimal,
}

/// A quota's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attainment {
    pub quota: Uuid,
    pub achieved: Decimal,
    /// `achieved / target * 100`, two decimals; `None` for a zero target.
    pub percent: Option<Decimal>,
}

/// The people at or under `root` in a reports-to map (`user -> manager`).
pub fn team_of(root: Uuid, manager_of: &BTreeMap<Uuid, Uuid>) -> BTreeSet<Uuid> {
    let mut team = BTreeSet::from([root]);
    // Walk until nothing new joins; a cycle cannot loop because a member is
    // only added once.
    loop {
        let before = team.len();
        for (user, manager) in manager_of {
            if team.contains(manager) {
                team.insert(*user);
            }
        }
        if team.len() == before {
            return team;
        }
    }
}

/// Attainment of each quota. With `roll_up`, a quota counts the credits of
/// its holder's whole team.
pub fn attainment(
    quotas: &[Quota],
    credits: &[Credit],
    manager_of: &BTreeMap<Uuid, Uuid>,
    roll_up: bool,
) -> Vec<Attainment> {
    quotas
        .iter()
        .map(|q| {
            let people = if roll_up {
                team_of(q.user, manager_of)
            } else {
                BTreeSet::from([q.user])
            };
            let achieved: Decimal = credits
                .iter()
                .filter(|c| {
                    c.rule == q.rule && people.contains(&c.user) && c.on >= q.from && c.on <= q.to
                })
                .map(|c| c.amount)
                .sum();
            let percent = if q.target.is_zero() {
                None
            } else {
                Some((achieved / q.target * Decimal::ONE_HUNDRED).round_dp(2))
            };
            Attainment {
                quota: q.id,
                achieved,
                percent,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn quota(user: u128, rule: CreditRule, target: &str) -> Quota {
        Quota {
            id: u(1000 + user),
            user: u(user),
            rule,
            from: d("2026-10-01"),
            to: d("2026-12-31"),
            target: dec(target),
        }
    }

    fn credit(user: u128, rule: CreditRule, on: &str, amount: &str) -> Credit {
        Credit {
            rule,
            user: u(user),
            on: d(on),
            amount: dec(amount),
        }
    }

    #[test]
    fn only_the_quota_rule_and_period_count() {
        let credits = [
            credit(1, CreditRule::ClosedWon, "2026-10-05", "100"),
            credit(1, CreditRule::Invoiced, "2026-10-06", "999"),
            credit(1, CreditRule::ClosedWon, "2027-01-02", "999"),
        ];
        let got = attainment(
            &[quota(1, CreditRule::ClosedWon, "400")],
            &credits,
            &BTreeMap::new(),
            false,
        );
        assert_eq!(got[0].achieved, dec("100"));
        assert_eq!(got[0].percent, Some(dec("25.00")));
    }

    #[test]
    fn managers_roll_up_their_team() {
        // 3 reports to 2, 2 reports to 1.
        let tree = BTreeMap::from([(u(2), u(1)), (u(3), u(2))]);
        let credits = [
            credit(2, CreditRule::Recognised, "2026-11-01", "50"),
            credit(3, CreditRule::Recognised, "2026-11-02", "70"),
            credit(4, CreditRule::Recognised, "2026-11-03", "1000"),
        ];
        let got = attainment(
            &[quota(1, CreditRule::Recognised, "240")],
            &credits,
            &tree,
            true,
        );
        assert_eq!(got[0].achieved, dec("120"));
        assert_eq!(got[0].percent, Some(dec("50.00")));
    }

    #[test]
    fn a_zero_target_has_no_percent() {
        let got = attainment(
            &[quota(1, CreditRule::ClosedWon, "0")],
            &[],
            &BTreeMap::new(),
            false,
        );
        assert_eq!(got[0].percent, None);
    }

    #[test]
    fn a_reporting_cycle_terminates() {
        let tree = BTreeMap::from([(u(1), u(2)), (u(2), u(1))]);
        assert_eq!(team_of(u(1), &tree), BTreeSet::from([u(1), u(2)]));
    }
}

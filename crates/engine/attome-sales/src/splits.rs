//! Deal splits (roadmap D7-T4), pure: the rules a set of splits must keep
//! and the amounts they come to. The route that replaces an opportunity's
//! splits under its lock, and the recalculation inside the line and amount
//! transactions, call these.
//!
//! A split type with `must_total_100` (Revenue) must add up to exactly 100%
//! per opportunity, or per line for line-level splits. Overlay types may add
//! up to anything. Amounts take the type's basis (total, one-time or
//! recurring), are rounded once to the currency's minor units, half away
//! from zero, and the rounding remainder of a type goes to the owner's split.

use rust_decimal::{Decimal, RoundingStrategy};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Which amount a split type divides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountBasis {
    Total,
    OneTime,
    Recurring,
}

/// A split type (the `sales_split_type` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitType {
    pub id: Uuid,
    pub name: String,
    pub must_total_100: bool,
    pub basis: AmountBasis,
}

/// One split (the `opportunity_split` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    pub id: Uuid,
    pub split_type: Uuid,
    pub member_user: Option<Uuid>,
    /// Set for a split of one line rather than the whole deal.
    pub line: Option<Uuid>,
    pub percent: Decimal,
}

/// The amounts a deal's splits divide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DealAmounts {
    pub total: Decimal,
    pub one_time: Decimal,
    pub recurring: Decimal,
    /// Line totals by line id, for line-level splits.
    pub lines: BTreeMap<Uuid, Decimal>,
}

/// A rule a set of splits breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError {
    UnknownType(Uuid),
    UnknownLine(Uuid),
    NegativePercent(Uuid),
    MustTotal100 {
        split_type: Uuid,
        line: Option<Uuid>,
        total: Decimal,
    },
}

/// Checks every rule; returns every break, not just the first.
pub fn validate_splits(
    types: &[SplitType],
    splits: &[Split],
    lines: &[Uuid],
) -> Result<(), Vec<SplitError>> {
    let mut errors = Vec::new();
    let mut sums: BTreeMap<(Uuid, Option<Uuid>), Decimal> = BTreeMap::new();
    for split in splits {
        if !types.iter().any(|t| t.id == split.split_type) {
            errors.push(SplitError::UnknownType(split.split_type));
            continue;
        }
        if let Some(line) = split.line
            && !lines.contains(&line)
        {
            errors.push(SplitError::UnknownLine(line));
        }
        if split.percent.is_sign_negative() {
            errors.push(SplitError::NegativePercent(split.id));
        }
        *sums.entry((split.split_type, split.line)).or_default() += split.percent;
    }
    for ((split_type, line), total) in sums {
        let strict = types.iter().any(|t| t.id == split_type && t.must_total_100);
        if strict && total != Decimal::ONE_HUNDRED {
            errors.push(SplitError::MustTotal100 {
                split_type,
                line,
                total,
            });
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Each split's amount, by split id. The rounding remainder of each
/// (type, line) group goes to the owner's split in that group, or to its
/// first split when the owner has none.
pub fn split_amounts(
    types: &[SplitType],
    splits: &[Split],
    amounts: &DealAmounts,
    owner: Uuid,
    minor_units: u32,
) -> BTreeMap<Uuid, Decimal> {
    let mut out = BTreeMap::new();
    let mut groups: BTreeMap<(Uuid, Option<Uuid>), Vec<&Split>> = BTreeMap::new();
    for split in splits {
        groups
            .entry((split.split_type, split.line))
            .or_default()
            .push(split);
    }
    for ((type_id, line), members) in groups {
        let Some(split_type) = types.iter().find(|t| t.id == type_id) else {
            continue;
        };
        let base = match line {
            Some(line) => amounts.lines.get(&line).copied().unwrap_or_default(),
            None => match split_type.basis {
                AmountBasis::Total => amounts.total,
                AmountBasis::OneTime => amounts.one_time,
                AmountBasis::Recurring => amounts.recurring,
            },
        };
        let mut rounded_sum = Decimal::ZERO;
        let mut exact_sum = Decimal::ZERO;
        for split in &members {
            let exact = base * split.percent / Decimal::ONE_HUNDRED;
            let rounded =
                exact.round_dp_with_strategy(minor_units, RoundingStrategy::MidpointAwayFromZero);
            exact_sum += exact;
            rounded_sum += rounded;
            out.insert(split.id, rounded);
        }
        let target =
            exact_sum.round_dp_with_strategy(minor_units, RoundingStrategy::MidpointAwayFromZero);
        let remainder = target - rounded_sum;
        if !remainder.is_zero() {
            let receiver = members
                .iter()
                .find(|s| s.member_user == Some(owner))
                .or_else(|| members.first());
            if let Some(receiver) = receiver
                && let Some(amount) = out.get_mut(&receiver.id)
            {
                *amount += remainder;
            }
        }
    }
    out
}

/// The splits a deal has when nobody set any: the owner gets 100% revenue.
pub fn default_owner_split(revenue_type: Uuid, owner: Uuid) -> Split {
    Split {
        id: Uuid::nil(),
        split_type: revenue_type,
        member_user: Some(owner),
        line: None,
        percent: Decimal::ONE_HUNDRED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).expect("decimal")
    }

    fn revenue() -> SplitType {
        SplitType {
            id: Uuid::from_u128(1),
            name: "Revenue".into(),
            must_total_100: true,
            basis: AmountBasis::Total,
        }
    }

    fn overlay() -> SplitType {
        SplitType {
            id: Uuid::from_u128(2),
            name: "Overlay".into(),
            must_total_100: false,
            basis: AmountBasis::Total,
        }
    }

    fn split(id: u128, t: &SplitType, user: u128, percent: &str) -> Split {
        Split {
            id: Uuid::from_u128(id),
            split_type: t.id,
            member_user: Some(Uuid::from_u128(user)),
            line: None,
            percent: dec(percent),
        }
    }

    #[test]
    fn revenue_must_total_100() {
        let types = [revenue()];
        let ok = [
            split(10, &revenue(), 100, "60"),
            split(11, &revenue(), 101, "40"),
        ];
        assert_eq!(validate_splits(&types, &ok, &[]), Ok(()));
        let short = [
            split(10, &revenue(), 100, "60"),
            split(11, &revenue(), 101, "39.99"),
        ];
        let errs = validate_splits(&types, &short, &[]).unwrap_err();
        assert!(
            matches!(errs[0], SplitError::MustTotal100 { ref total, .. } if *total == dec("99.99"))
        );
    }

    #[test]
    fn overlay_may_exceed() {
        let types = [revenue(), overlay()];
        let splits = [
            split(10, &revenue(), 100, "100"),
            split(11, &overlay(), 101, "100"),
            split(12, &overlay(), 102, "50"),
        ];
        assert_eq!(validate_splits(&types, &splits, &[]), Ok(()));
    }

    #[test]
    fn remainder_goes_to_owner() {
        let types = [revenue()];
        let owner = 100;
        let splits = [
            split(10, &revenue(), 101, "33.3333"),
            split(11, &revenue(), owner, "33.3333"),
            split(12, &revenue(), 102, "33.3334"),
        ];
        let amounts = DealAmounts {
            total: dec("100.00"),
            one_time: Decimal::ZERO,
            recurring: Decimal::ZERO,
            lines: BTreeMap::new(),
        };
        let got = split_amounts(&types, &splits, &amounts, Uuid::from_u128(owner), 2);
        let sum: Decimal = got.values().copied().sum();
        assert_eq!(sum, dec("100.00"));
        assert_eq!(got[&Uuid::from_u128(10)], dec("33.33"));
        assert_eq!(got[&Uuid::from_u128(11)], dec("33.34"));
        assert_eq!(got[&Uuid::from_u128(12)], dec("33.33"));
    }

    #[test]
    fn per_line_split_uses_line_total() {
        let line = Uuid::from_u128(500);
        let types = [revenue()];
        let mut s = split(10, &revenue(), 100, "100");
        s.line = Some(line);
        let amounts = DealAmounts {
            total: dec("1000"),
            one_time: Decimal::ZERO,
            recurring: Decimal::ZERO,
            lines: BTreeMap::from([(line, dec("250.50"))]),
        };
        assert_eq!(
            validate_splits(&types, std::slice::from_ref(&s), &[line]),
            Ok(())
        );
        let got = split_amounts(&types, &[s], &amounts, Uuid::from_u128(100), 2);
        assert_eq!(got[&Uuid::from_u128(10)], dec("250.50"));
    }

    #[test]
    fn an_unknown_line_or_type_is_reported() {
        let mut s = split(10, &revenue(), 100, "100");
        s.line = Some(Uuid::from_u128(9));
        let errs = validate_splits(&[revenue()], &[s], &[]).unwrap_err();
        assert!(errs.contains(&SplitError::UnknownLine(Uuid::from_u128(9))));
        let errs = validate_splits(&[], &[split(1, &overlay(), 1, "5")], &[]).unwrap_err();
        assert_eq!(errs, vec![SplitError::UnknownType(Uuid::from_u128(2))]);
    }
}

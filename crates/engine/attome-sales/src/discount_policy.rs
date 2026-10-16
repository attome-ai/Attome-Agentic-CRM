//! Discount policy (roadmap F2-T1), pure: a quote's largest line discount
//! and its total discount, checked against thresholds by product family, the
//! submitter's role and the deal size, choose the approval process the quote
//! needs on submit (none, or the strictest one any threshold calls for). An
//! agent-drafted quote is checked the same way, as its submitter.

use rust_decimal::Decimal;
use uuid::Uuid;

/// One threshold row of the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threshold {
    /// Applies to lines of this family; `None` for every family.
    pub family: Option<Uuid>,
    /// Applies to this role; `None` for every role.
    pub role: Option<String>,
    /// Applies from this deal total up.
    pub min_deal_total: Decimal,
    /// The largest line discount percent allowed without this approval.
    pub max_line_discount_pct: Decimal,
    /// The largest total discount percent allowed without this approval.
    pub max_total_discount_pct: Decimal,
    /// The approval process to run when exceeded.
    pub approval_process: String,
    /// Higher is stricter; the strictest exceeded threshold wins.
    pub level: u32,
}

/// A quote line as the policy sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteLine {
    pub family: Option<Uuid>,
    pub list_total: Decimal,
    pub net_total: Decimal,
}

/// The policy's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub max_line_discount_pct: Decimal,
    pub total_discount_pct: Decimal,
    /// `None`: the quote may be submitted without approval.
    pub approval_process: Option<String>,
    /// While an approval runs, the quote is locked.
    pub lock_quote: bool,
}

fn discount_pct(list: Decimal, net: Decimal) -> Decimal {
    if list.is_zero() {
        Decimal::ZERO
    } else {
        ((list - net) / list * Decimal::ONE_HUNDRED).round_dp(2)
    }
}

/// Evaluates `lines` for a submitter with `role`.
pub fn evaluate(thresholds: &[Threshold], lines: &[QuoteLine], role: &str) -> PolicyResult {
    let list: Decimal = lines.iter().map(|l| l.list_total).sum();
    let net: Decimal = lines.iter().map(|l| l.net_total).sum();
    let total_pct = discount_pct(list, net);
    let line_pct = |l: &QuoteLine| discount_pct(l.list_total, l.net_total);
    let max_line = lines.iter().map(line_pct).max().unwrap_or_default();

    let applies =
        |t: &&Threshold| t.role.as_deref().is_none_or(|r| r == role) && net >= t.min_deal_total;
    let exceeded = thresholds.iter().filter(applies).filter(|t| {
        let line_over = lines
            .iter()
            .filter(|l| t.family.is_none() || l.family == t.family)
            .any(|l| line_pct(l) > t.max_line_discount_pct);
        line_over || total_pct > t.max_total_discount_pct
    });
    let strictest = exceeded.max_by_key(|t| t.level);
    PolicyResult {
        max_line_discount_pct: max_line,
        total_discount_pct: total_pct,
        approval_process: strictest.map(|t| t.approval_process.clone()),
        lock_quote: strictest.is_some(),
    }
}

#[cfg(test)]
mod discount_policy {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn threshold(
        family: Option<u128>,
        role: Option<&str>,
        min_total: &str,
        line: &str,
        total: &str,
        process: &str,
        level: u32,
    ) -> Threshold {
        Threshold {
            family: family.map(Uuid::from_u128),
            role: role.map(str::to_owned),
            min_deal_total: dec(min_total),
            max_line_discount_pct: dec(line),
            max_total_discount_pct: dec(total),
            approval_process: process.into(),
            level,
        }
    }

    fn line(family: u128, list: &str, net: &str) -> QuoteLine {
        QuoteLine {
            family: Some(Uuid::from_u128(family)),
            list_total: dec(list),
            net_total: dec(net),
        }
    }

    fn policy() -> Vec<Threshold> {
        vec![
            threshold(None, None, "0", "10", "10", "manager_approval", 1),
            threshold(None, None, "0", "25", "20", "director_approval", 2),
            threshold(
                Some(7),
                None,
                "0",
                "5",
                "100",
                "hardware_margin_approval",
                3,
            ),
        ]
    }

    #[test]
    fn within_limits_needs_no_approval() {
        let r = evaluate(&policy(), &[line(1, "1000", "950")], "sales_rep");
        assert_eq!(r.approval_process, None);
        assert!(!r.lock_quote);
        assert_eq!(r.max_line_discount_pct, dec("5"));
    }

    #[test]
    fn the_strictest_exceeded_threshold_wins() {
        let r = evaluate(&policy(), &[line(1, "1000", "700")], "sales_rep");
        assert_eq!(r.approval_process.as_deref(), Some("director_approval"));
        assert!(r.lock_quote);
    }

    #[test]
    fn family_thresholds_apply_only_to_their_family() {
        let r = evaluate(
            &policy(),
            &[line(7, "1000", "920"), line(1, "1000", "1000")],
            "sales_rep",
        );
        assert_eq!(
            r.approval_process.as_deref(),
            Some("hardware_margin_approval")
        );
    }

    #[test]
    fn role_and_size_scope_a_threshold() {
        let mut p = policy();
        p.push(threshold(
            None,
            Some("partner"),
            "50000",
            "0",
            "0",
            "partner_desk",
            9,
        ));
        let small = evaluate(&p, &[line(1, "1000", "990")], "partner");
        assert_eq!(small.approval_process, None);
        let big = evaluate(&p, &[line(1, "60000", "59000")], "partner");
        assert_eq!(big.approval_process.as_deref(), Some("partner_desk"));
    }
}

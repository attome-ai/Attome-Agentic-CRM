//! The budget check (roadmap W4-T2), pure: what is still available on a
//! budget line is its amount less what is committed (approved requisitions
//! and open purchase orders) and what is already spent, and a new spend
//! that would go over it warns or is blocked, as the deployment's setting
//! says. Requisitions (W3), project costs (V1) and campaign spend (E29) all
//! call it before they commit money.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// What happens when a spend would go over the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverspendPolicy {
    /// Allowed, with a warning the person sees.
    Warn,
    /// Refused until the budget is raised or the spend is approved.
    Block,
}

/// A budget line's figures, all in the budget's currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLine {
    pub amount: Decimal,
    /// Approved requisitions and open purchase orders not yet billed.
    pub commitments: Decimal,
    /// Spend already booked.
    pub actuals: Decimal,
}

impl BudgetLine {
    /// What is left: amount less commitments and actuals (negative when the
    /// line is already over).
    pub fn available(&self) -> Decimal {
        self.amount - self.commitments - self.actuals
    }
}

/// The answer to "may this spend go ahead?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum BudgetCheck {
    /// Fits within what is available.
    Within { available_after: Decimal },
    /// Goes over by `over_by`, allowed with a warning.
    Warn { over_by: Decimal },
    /// Goes over by `over_by` and the policy refuses it.
    Blocked { over_by: Decimal },
}

impl BudgetCheck {
    /// Whether the spend may be committed.
    pub fn allowed(&self) -> bool {
        !matches!(self, Self::Blocked { .. })
    }
}

/// Checks a new spend of `amount` against `line`.
pub fn check(line: &BudgetLine, amount: Decimal, policy: OverspendPolicy) -> BudgetCheck {
    let available_after = line.available() - amount;
    if available_after >= Decimal::ZERO {
        return BudgetCheck::Within { available_after };
    }
    let over_by = -available_after;
    match policy {
        OverspendPolicy::Warn => BudgetCheck::Warn { over_by },
        OverspendPolicy::Block => BudgetCheck::Blocked { over_by },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap_or_default()
    }

    fn line() -> BudgetLine {
        BudgetLine {
            amount: d("10000"),
            commitments: d("2500.50"),
            actuals: d("4000"),
        }
    }

    #[test]
    fn available_is_amount_less_commitments_and_actuals() {
        assert_eq!(line().available(), d("3499.50"));
    }

    #[test]
    fn a_spend_within_budget_passes() {
        assert_eq!(
            check(&line(), d("3499.50"), OverspendPolicy::Block),
            BudgetCheck::Within {
                available_after: d("0")
            }
        );
    }

    #[test]
    fn overspend_warns_or_blocks_per_policy() {
        let warn = check(&line(), d("4000"), OverspendPolicy::Warn);
        assert_eq!(
            warn,
            BudgetCheck::Warn {
                over_by: d("500.50")
            }
        );
        assert!(warn.allowed());
        let block = check(&line(), d("4000"), OverspendPolicy::Block);
        assert_eq!(
            block,
            BudgetCheck::Blocked {
                over_by: d("500.50")
            }
        );
        assert!(!block.allowed());
    }
}

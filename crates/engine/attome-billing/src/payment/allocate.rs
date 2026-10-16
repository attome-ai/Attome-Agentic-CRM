//! Payment allocation (roadmap F5-T2), pure: a payment pays open invoices
//! oldest first, or as the payer says; a part payment leaves the rest open;
//! what is left over becomes customer credit.

use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenInvoice {
    pub id: Uuid,
    pub due_date: NaiveDate,
    pub issued: NaiveDate,
    /// What is still owed on it.
    pub open: Decimal,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    /// `(invoice id, amount)`, in the order they were paid.
    pub lines: Vec<(Uuid, Decimal)>,
    /// What the payment leaves over, as customer credit.
    pub credit: Decimal,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocError {
    #[error("the payment amount must be more than zero")]
    NotPositive,
    #[error("invoice {0} is in another currency than the payment")]
    Currency(Uuid),
    #[error("the amount for invoice {0} is more than it has open")]
    Exceeds(Uuid),
    #[error("invoice {0} is not one of the payer's open invoices")]
    Unknown(Uuid),
    #[error("the amounts given add up to more than the payment")]
    MoreThanPaid,
}

/// Allocates `amount` in `currency` over `invoices`. With `explicit`, the
/// payer's `(invoice, amount)` pairs are used as given; otherwise invoices
/// are paid in order of due date, then issue date.
pub fn allocate(
    amount: Decimal,
    currency: &str,
    invoices: &[OpenInvoice],
    explicit: Option<&[(Uuid, Decimal)]>,
) -> Result<Allocation, AllocError> {
    if amount <= Decimal::ZERO {
        return Err(AllocError::NotPositive);
    }
    let mut lines = Vec::new();
    let mut left = amount;
    match explicit {
        Some(pairs) => {
            for (id, part) in pairs {
                let invoice = invoices
                    .iter()
                    .find(|i| i.id == *id)
                    .ok_or(AllocError::Unknown(*id))?;
                if invoice.currency != currency {
                    return Err(AllocError::Currency(*id));
                }
                if *part > invoice.open {
                    return Err(AllocError::Exceeds(*id));
                }
                if *part > left {
                    return Err(AllocError::MoreThanPaid);
                }
                if part.is_zero() {
                    continue;
                }
                left -= *part;
                lines.push((*id, *part));
            }
        }
        None => {
            let mut ordered: Vec<&OpenInvoice> =
                invoices.iter().filter(|i| i.open > Decimal::ZERO).collect();
            if let Some(other) = ordered.iter().find(|i| i.currency != currency) {
                return Err(AllocError::Currency(other.id));
            }
            ordered.sort_by(|a, b| a.due_date.cmp(&b.due_date).then(a.issued.cmp(&b.issued)));
            for invoice in ordered {
                if left.is_zero() {
                    break;
                }
                let part = invoice.open.min(left);
                left -= part;
                lines.push((invoice.id, part));
            }
        }
    }
    Ok(Allocation {
        lines,
        credit: left,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, day).expect("valid date")
    }

    fn inv(due: NaiveDate, open: i64) -> OpenInvoice {
        OpenInvoice {
            id: Uuid::now_v7(),
            due_date: due,
            issued: due,
            open: Decimal::from(open),
            currency: "SAR".into(),
        }
    }

    #[test]
    fn allocate_oldest_first() {
        let newer = inv(d(3, 1), 100);
        let older = inv(d(1, 1), 50);
        let a = allocate(
            Decimal::from(120),
            "SAR",
            &[newer.clone(), older.clone()],
            None,
        )
        .expect("allocate");
        assert_eq!(
            a.lines,
            vec![(older.id, Decimal::from(50)), (newer.id, Decimal::from(70))]
        );
        assert_eq!(a.credit, Decimal::ZERO);
    }

    #[test]
    fn allocate_partial_leaves_open() {
        let only = inv(d(1, 1), 100);
        let a = allocate(Decimal::from(40), "SAR", &[only.clone()], None).expect("allocate");
        assert_eq!(a.lines, vec![(only.id, Decimal::from(40))]);
        assert_eq!(a.credit, Decimal::ZERO);
    }

    #[test]
    fn allocate_overpay_is_credit() {
        let only = inv(d(1, 1), 100);
        let a = allocate(Decimal::from(130), "SAR", &[only.clone()], None).expect("allocate");
        assert_eq!(a.lines, vec![(only.id, Decimal::from(100))]);
        assert_eq!(a.credit, Decimal::from(30));
    }

    #[test]
    fn allocate_explicit_exceeding_rejected() {
        let first = inv(d(1, 1), 100);
        let second = inv(d(2, 1), 100);
        let invoices = vec![first.clone(), second.clone()];
        assert_eq!(
            allocate(
                Decimal::from(200),
                "SAR",
                &invoices,
                Some(&[(second.id, Decimal::from(150))])
            ),
            Err(AllocError::Exceeds(second.id))
        );
        let ok = allocate(
            Decimal::from(100),
            "SAR",
            &invoices,
            Some(&[(second.id, Decimal::from(60))]),
        )
        .expect("explicit");
        assert_eq!(ok.lines, vec![(second.id, Decimal::from(60))]);
        assert_eq!(ok.credit, Decimal::from(40));
        let mut usd = inv(d(1, 1), 10);
        usd.currency = "USD".into();
        assert_eq!(
            allocate(Decimal::from(5), "SAR", &[usd.clone()], None),
            Err(AllocError::Currency(usd.id))
        );
    }
}

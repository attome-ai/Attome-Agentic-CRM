//! Amendments (roadmap W1-T11), pure: a contract's current terms are its
//! base terms with every amendment that is effective by `today` folded over
//! them, in effective-date order (ties by approval order). Amendments keep
//! their own record, so the history is the list itself; only the current
//! terms are recomputed. A term set to JSON `null` by an amendment is
//! removed.

use chrono::NaiveDate;
use serde_json::{Map, Value};

/// An approved amendment.
#[derive(Debug, Clone, PartialEq)]
pub struct Amendment {
    pub effective_date: NaiveDate,
    /// Order among amendments effective the same day.
    pub sequence: u32,
    /// Term name to new value (`changed_terms`).
    pub changed_terms: Map<String, Value>,
}

/// The terms in force on `today`.
pub fn current_terms(
    base: &Map<String, Value>,
    amendments: &[Amendment],
    today: NaiveDate,
) -> Map<String, Value> {
    let mut effective: Vec<&Amendment> = amendments
        .iter()
        .filter(|a| a.effective_date <= today)
        .collect();
    effective.sort_by_key(|a| (a.effective_date, a.sequence));
    let mut terms = base.clone();
    for amendment in effective {
        for (term, value) in &amendment.changed_terms {
            if value.is_null() {
                terms.remove(term);
            } else {
                terms.insert(term.clone(), value.clone());
            }
        }
    }
    terms
}

/// The contract end date in force: an `end_date` term (`YYYY-MM-DD`) wins
/// over the stored one.
pub fn current_end_date(
    terms: &Map<String, Value>,
    stored: Option<NaiveDate>,
) -> Option<NaiveDate> {
    terms
        .get("end_date")
        .and_then(Value::as_str)
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .or(stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn terms(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn amendment(on: &str, sequence: u32, v: Value) -> Amendment {
        Amendment {
            effective_date: day(on),
            sequence,
            changed_terms: terms(v),
        }
    }

    #[test]
    fn later_amendment_overrides_earlier() {
        let base = terms(json!({"price": 100, "payment_days": 30}));
        let got = current_terms(
            &base,
            &[
                amendment("2026-06-01", 1, json!({"price": 120})),
                amendment("2026-03-01", 1, json!({"price": 110, "payment_days": 45})),
            ],
            day("2026-10-16"),
        );
        assert_eq!(
            Value::Object(got),
            json!({"price": 120, "payment_days": 45})
        );
    }

    #[test]
    fn future_amendment_not_applied() {
        let base = terms(json!({"price": 100}));
        let got = current_terms(
            &base,
            &[amendment("2027-01-01", 1, json!({"price": 200}))],
            day("2026-10-16"),
        );
        assert_eq!(Value::Object(got), json!({"price": 100}));
    }

    #[test]
    fn null_removes_a_term_and_end_date_follows_the_terms() {
        let base = terms(json!({"sla": "gold", "end_date": "2026-12-31"}));
        let got = current_terms(
            &base,
            &[amendment(
                "2026-05-01",
                1,
                json!({"sla": null, "end_date": "2027-12-31"}),
            )],
            day("2026-10-16"),
        );
        assert!(!got.contains_key("sla"));
        assert_eq!(
            current_end_date(&got, Some(day("2026-12-31"))),
            Some(day("2027-12-31"))
        );
        assert_eq!(
            current_end_date(&Map::new(), Some(day("2026-12-31"))),
            Some(day("2026-12-31"))
        );
    }
}

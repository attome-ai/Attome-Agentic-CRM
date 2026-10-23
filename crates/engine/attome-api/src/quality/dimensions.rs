//! L2-T2: the six data-quality dimensions, pure.
//!
//! Each dimension is a pass rate over checks, 0 to 100:
//!
//! - **completeness**: one check per (record, required attribute); a null
//!   fails;
//! - **uniqueness**: one check per record; a record named by an open
//!   duplicate pair (A15) fails;
//! - **validity**: one check per (record, validity rule); the rule's
//!   condition must hold;
//! - **consistency**: the same for consistency rules, which compare a
//!   record's attributes with each other (`end_date >= start_date`);
//! - **timeliness**: one check per record; one changed longer ago than the
//!   entity's `timeliness_days` fails;
//! - **accuracy**: verified values against all checked, when a verification
//!   source exists; otherwise not measured.
//!
//! Rules are V2 rule text, evaluated by the one shared evaluator
//! (`attome_workflow::condition::expression_holds`, D-399): there is no
//! second one here. A quality rule only measures; it never refuses a save
//! (blocking checks are A3's).
//!
//! [`combine`] weighs the measured dimensions by the entity's
//! `quality_target.dimension_weights` (1 each when unset); a dimension not
//! measured does not count. The overall score is compared with the
//! entity's threshold (`quality_target.threshold`, default 70).

use std::collections::HashMap;

use serde_json::Value;

/// The default overall threshold.
pub const DEFAULT_THRESHOLD: f64 = 70.0;

/// A quality dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dimension {
    Completeness,
    Uniqueness,
    Validity,
    Consistency,
    Timeliness,
    Accuracy,
}

impl Dimension {
    pub const ALL: [Dimension; 6] = [
        Dimension::Completeness,
        Dimension::Uniqueness,
        Dimension::Validity,
        Dimension::Consistency,
        Dimension::Timeliness,
        Dimension::Accuracy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Completeness => "completeness",
            Dimension::Uniqueness => "uniqueness",
            Dimension::Validity => "validity",
            Dimension::Consistency => "consistency",
            Dimension::Timeliness => "timeliness",
            Dimension::Accuracy => "accuracy",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == raw)
    }
}

/// One dimension's result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Measure {
    Measured {
        pass: i64,
        fail: i64,
        sample: i64,
        score: f64,
    },
    /// No source to measure it from (accuracy without verification).
    NotMeasured,
}

impl Measure {
    /// `fail` failing checks out of `sample`; no checks scores 100.
    pub fn of(fail: i64, sample: i64) -> Self {
        let sample = sample.max(0);
        let fail = fail.clamp(0, sample);
        let score = if sample == 0 {
            100.0
        } else {
            ((sample - fail) as f64 * 100.0 / sample as f64 * 100.0).round() / 100.0
        };
        Measure::Measured {
            pass: sample - fail,
            fail,
            sample,
            score,
        }
    }

    pub fn score(self) -> Option<f64> {
        match self {
            Measure::Measured { score, .. } => Some(score),
            Measure::NotMeasured => None,
        }
    }
}

/// Completeness: `nulls` null (record, required attribute) pairs over
/// `rows` records with `required` required attributes.
pub fn completeness(nulls: i64, rows: i64, required: usize) -> Measure {
    Measure::of(
        nulls,
        rows * i64::try_from(required).unwrap_or(i64::MAX / 2),
    )
}

/// Uniqueness: `duplicates` records in open duplicate pairs over `rows`.
pub fn uniqueness(duplicates: i64, rows: i64) -> Measure {
    Measure::of(duplicates, rows)
}

/// Whether a rule's condition holds for a record (the shared evaluator).
pub fn rule_holds(expression: &str, record: &Value) -> bool {
    attome_workflow::condition::expression_holds(expression, record)
}

/// Validity or consistency: every (record, rule) pair is a check.
pub fn rule_pass_rate(rules: &[String], records: &[Value]) -> Measure {
    if rules.is_empty() {
        return Measure::NotMeasured;
    }
    let mut fail = 0;
    for record in records {
        for rule in rules {
            if !rule_holds(rule, record) {
                fail += 1;
            }
        }
    }
    Measure::of(fail, (records.len() * rules.len()) as i64)
}

/// Timeliness: records changed more than `max_age_days` ago fail.
pub fn timeliness(ages_days: &[f64], max_age_days: Option<f64>) -> Measure {
    let Some(max) = max_age_days.filter(|m| *m > 0.0) else {
        return Measure::NotMeasured;
    };
    let fail = ages_days.iter().filter(|age| **age > max).count();
    Measure::of(fail as i64, ages_days.len() as i64)
}

/// Accuracy: `(verified, checked)` when a verification source exists.
pub fn accuracy(verified: Option<(i64, i64)>) -> Measure {
    match verified {
        Some((ok, checked)) => Measure::of(checked - ok, checked),
        None => Measure::NotMeasured,
    }
}

/// The overall score: the measured dimensions weighted by `weights` (by
/// dimension name; 1 when absent, a negative weight counts as 0). `None`
/// when nothing is measured or every weight is 0.
pub fn combine(scores: &[(Dimension, Measure)], weights: &HashMap<String, f64>) -> Option<f64> {
    let mut total = 0.0;
    let mut weight_sum = 0.0;
    for (dimension, measure) in scores {
        let Some(score) = measure.score() else {
            continue;
        };
        let weight = weights
            .get(dimension.as_str())
            .copied()
            .unwrap_or(1.0)
            .max(0.0);
        total += score * weight;
        weight_sum += weight;
    }
    (weight_sum > 0.0).then(|| (total / weight_sum * 100.0).round() / 100.0)
}

/// The weights in a `quality_target.dimension_weights` value.
pub fn weights_from(value: &Value) -> HashMap<String, f64> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| Dimension::parse(k).is_some())
        .filter_map(|(k, v)| v.as_f64().map(|w| (k.clone(), w)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn completeness_counts_required() {
        // 10 records, 2 required attributes, 4 nulls: 16 of 20 checks pass.
        assert_eq!(completeness(4, 10, 2).score(), Some(80.0));
        assert_eq!(completeness(0, 0, 2).score(), Some(100.0), "no records");
    }

    #[test]
    fn uniqueness_uses_pairs() {
        // Two records named by open pairs out of eight.
        assert_eq!(uniqueness(2, 8).score(), Some(75.0));
    }

    #[test]
    fn validity_pass_rate() {
        let rules = vec!["email != null".to_owned()];
        let records = vec![
            json!({ "email": "a@b.sa" }),
            json!({ "email": null }),
            json!({ "email": "c@d.sa" }),
            json!({ "email": "e@f.sa" }),
        ];
        assert_eq!(rule_pass_rate(&rules, &records).score(), Some(75.0));
        assert_eq!(rule_pass_rate(&[], &records), Measure::NotMeasured);
    }

    #[test]
    fn consistency_rule_lowers_score() {
        let rules = vec!["end_day >= start_day".to_owned()];
        let good = vec![
            json!({ "start_day": 1, "end_day": 5 }),
            json!({ "start_day": 2, "end_day": 2 }),
        ];
        assert_eq!(rule_pass_rate(&rules, &good).score(), Some(100.0));
        let mut bad = good.clone();
        bad.push(json!({ "start_day": 9, "end_day": 3 }));
        let score = rule_pass_rate(&rules, &bad).score().unwrap();
        assert!(score < 100.0, "{score}");
    }

    #[test]
    fn timeliness_age() {
        let ages = [1.0, 10.0, 400.0, 30.0];
        assert_eq!(timeliness(&ages, Some(365.0)).score(), Some(75.0));
        assert_eq!(timeliness(&ages, None), Measure::NotMeasured);
    }

    #[test]
    fn accuracy_not_measured_without_source() {
        assert_eq!(accuracy(None), Measure::NotMeasured);
        assert_eq!(accuracy(Some((9, 10))).score(), Some(90.0));
    }

    #[test]
    fn weights_combine() {
        let scores = [
            (Dimension::Completeness, Measure::of(0, 10)),
            (Dimension::Uniqueness, Measure::of(5, 10)),
            (Dimension::Accuracy, Measure::NotMeasured),
        ];
        assert_eq!(
            combine(&scores, &HashMap::new()),
            Some(75.0),
            "equal weights"
        );
        let weights = weights_from(&json!({ "completeness": 3, "uniqueness": 1, "bogus": 9 }));
        assert_eq!(weights.len(), 2);
        assert_eq!(combine(&scores, &weights), Some(87.5));
        let none = weights_from(&json!({ "completeness": 0, "uniqueness": 0 }));
        assert_eq!(combine(&scores, &none), None);
    }
}

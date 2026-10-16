//! Points scoring (roadmap D18-T1), pure: a model's rules add points for
//! what a lead or contact has (fit) and what they did (behaviour), behaviour
//! points fade with a half-life, and the score keeps its reasons so a user
//! sees why. The caller evaluates the rule conditions (Z11 expressions over
//! the record) and stores the score and reasons, on change and nightly so
//! decay moves scores without new activity.

use chrono::{DateTime, Utc};

/// One rule of a points model.
#[derive(Debug, Clone, PartialEq)]
pub struct PointsRule {
    pub key: String,
    pub label: String,
    pub points: f64,
    /// Behaviour rules fade; fit rules do not.
    pub decays: bool,
    /// Most times the rule may count (`None`: no limit).
    pub max_hits: Option<u32>,
}

/// One time a rule matched: a fit rule once, a behaviour rule per event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule_key: String,
    pub at: DateTime<Utc>,
}

/// A rule's contribution to the score.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    pub rule_key: String,
    pub label: String,
    pub hits: u32,
    pub points: f64,
}

/// A computed score.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    /// Rounded to a whole number, never below zero.
    pub score: i64,
    /// Largest contribution first.
    pub reasons: Vec<Reason>,
}

/// Scores `hits` under `rules` at `now`. Behaviour points halve every
/// `half_life_days`; `max_hits` keeps the most recent hits of a rule.
pub fn points_score(
    rules: &[PointsRule],
    hits: &[Hit],
    now: DateTime<Utc>,
    half_life_days: f64,
) -> Score {
    let mut reasons = Vec::new();
    let mut total = 0.0;
    for rule in rules {
        let mut times: Vec<DateTime<Utc>> = hits
            .iter()
            .filter(|h| h.rule_key == rule.key)
            .map(|h| h.at)
            .collect();
        times.sort_unstable_by(|a, b| b.cmp(a));
        if let Some(max) = rule.max_hits {
            times.truncate(max as usize);
        }
        if times.is_empty() {
            continue;
        }
        let points: f64 = times
            .iter()
            .map(|at| {
                if rule.decays && half_life_days > 0.0 {
                    let days = (now - *at).num_seconds().max(0) as f64 / 86_400.0;
                    rule.points * 0.5f64.powf(days / half_life_days)
                } else {
                    rule.points
                }
            })
            .sum();
        total += points;
        reasons.push(Reason {
            rule_key: rule.key.clone(),
            label: rule.label.clone(),
            hits: times.len() as u32,
            points: (points * 10.0).round() / 10.0,
        });
    }
    reasons.sort_by(|a, b| b.points.abs().total_cmp(&a.points.abs()));
    Score {
        score: total.round().max(0.0) as i64,
        reasons,
    }
}

#[cfg(test)]
mod points_scoring {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn rule(key: &str, points: f64, decays: bool, max_hits: Option<u32>) -> PointsRule {
        PointsRule {
            key: key.into(),
            label: key.replace('_', " "),
            points,
            decays,
            max_hits,
        }
    }

    fn hit(key: &str, when: &str) -> Hit {
        Hit {
            rule_key: key.into(),
            at: at(when),
        }
    }

    #[test]
    fn fit_points_do_not_decay() {
        let s = points_score(
            &[rule("job_title_director", 20.0, false, None)],
            &[hit("job_title_director", "2025-01-01T00:00:00Z")],
            at("2026-10-01T00:00:00Z"),
            30.0,
        );
        assert_eq!(s.score, 20);
    }

    #[test]
    fn behaviour_points_halve_each_half_life() {
        let s = points_score(
            &[rule("visited_pricing", 10.0, true, None)],
            &[hit("visited_pricing", "2026-09-01T00:00:00Z")],
            at("2026-10-01T00:00:00Z"),
            30.0,
        );
        assert_eq!(s.score, 5);
    }

    #[test]
    fn max_hits_keeps_the_most_recent() {
        let s = points_score(
            &[rule("opened_email", 2.0, false, Some(2))],
            &[
                hit("opened_email", "2026-09-01T00:00:00Z"),
                hit("opened_email", "2026-09-02T00:00:00Z"),
                hit("opened_email", "2026-09-03T00:00:00Z"),
            ],
            at("2026-10-01T00:00:00Z"),
            30.0,
        );
        assert_eq!(s.score, 4);
        assert_eq!(s.reasons[0].hits, 2);
    }

    #[test]
    fn negative_rules_lower_the_score_but_not_below_zero() {
        let rules = [
            rule("competitor_domain", -50.0, false, None),
            rule("webinar", 15.0, false, None),
        ];
        let s = points_score(
            &rules,
            &[
                hit("competitor_domain", "2026-09-01T00:00:00Z"),
                hit("webinar", "2026-09-01T00:00:00Z"),
            ],
            at("2026-10-01T00:00:00Z"),
            30.0,
        );
        assert_eq!(s.score, 0);
        assert_eq!(
            s.reasons[0].rule_key, "competitor_domain",
            "largest contribution first"
        );
    }
}

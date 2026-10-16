//! Marketing attribution (roadmap E15-T1): how much of a won opportunity
//! each touchpoint earns, under the standard models. Pure: the caller loads
//! the opportunity's touchpoints (events and form submits of its contacts
//! before the close) and stores the credit per opportunity, nightly.
//!
//! Credits are shares that sum to one; multiplying by the won amount is the
//! caller's. Touchpoints are ordered by time, ties by id, so the result does
//! not depend on load order.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One marketing touch on the way to a deal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Touchpoint {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub campaign: Option<Uuid>,
    pub channel: String,
}

/// The attribution model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Model {
    FirstTouch,
    LastTouch,
    Linear,
    /// 40% first, 40% last, 20% spread over the middle.
    UShaped,
    /// Each touch weighs half as much per `half_life_days` before the close.
    TimeDecay {
        half_life_days: f64,
    },
}

/// One touchpoint's share of the deal.
#[derive(Debug, Clone, PartialEq)]
pub struct Credit {
    pub touchpoint: Uuid,
    pub share: f64,
}

/// The shares of `touchpoints` under `model` for a deal closed at `closed_at`.
/// Touchpoints after the close earn nothing and are left out.
pub fn attribute(
    touchpoints: &[Touchpoint],
    closed_at: DateTime<Utc>,
    model: Model,
) -> Vec<Credit> {
    let mut ordered: Vec<&Touchpoint> = touchpoints.iter().filter(|t| t.at <= closed_at).collect();
    ordered.sort_by_key(|t| (t.at, t.id));
    let n = ordered.len();
    if n == 0 {
        return Vec::new();
    }
    let weights: Vec<f64> = match model {
        Model::FirstTouch => (0..n).map(|i| if i == 0 { 1.0 } else { 0.0 }).collect(),
        Model::LastTouch => (0..n).map(|i| if i == n - 1 { 1.0 } else { 0.0 }).collect(),
        Model::Linear => vec![1.0; n],
        Model::UShaped => match n {
            1 => vec![1.0],
            2 => vec![0.5, 0.5],
            _ => {
                let middle = 0.2 / (n - 2) as f64;
                (0..n)
                    .map(|i| if i == 0 || i == n - 1 { 0.4 } else { middle })
                    .collect()
            }
        },
        Model::TimeDecay { half_life_days } => ordered
            .iter()
            .map(|t| {
                let days = (closed_at - t.at).num_seconds().max(0) as f64 / 86_400.0;
                if half_life_days > 0.0 {
                    0.5f64.powf(days / half_life_days)
                } else {
                    1.0
                }
            })
            .collect(),
    };
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return Vec::new();
    }
    ordered
        .iter()
        .zip(weights)
        .map(|(t, w)| Credit {
            touchpoint: t.id,
            share: w / total,
        })
        .collect()
}

/// Sums shares per campaign (touches without a campaign are left out).
pub fn by_campaign(touchpoints: &[Touchpoint], credits: &[Credit]) -> Vec<(Uuid, f64)> {
    let mut totals: std::collections::BTreeMap<Uuid, f64> = std::collections::BTreeMap::new();
    for credit in credits {
        if let Some(campaign) = touchpoints
            .iter()
            .find(|t| t.id == credit.touchpoint)
            .and_then(|t| t.campaign)
        {
            *totals.entry(campaign).or_default() += credit.share;
        }
    }
    totals.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(day: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-09-{day:02}T12:00:00Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    fn touches(days: &[u32]) -> Vec<Touchpoint> {
        days.iter()
            .enumerate()
            .map(|(i, d)| Touchpoint {
                id: Uuid::from_u128(i as u128 + 1),
                at: at(*d),
                campaign: Some(Uuid::from_u128(100 + (i as u128 % 2))),
                channel: "email".into(),
            })
            .collect()
    }

    fn shares(credits: &[Credit]) -> Vec<f64> {
        credits
            .iter()
            .map(|c| (c.share * 1000.0).round() / 1000.0)
            .collect()
    }

    #[test]
    fn first_and_last_touch_take_everything() {
        let t = touches(&[3, 1, 2]);
        assert_eq!(
            shares(&attribute(&t, at(30), Model::FirstTouch)),
            vec![1.0, 0.0, 0.0]
        );
        let last = attribute(&t, at(30), Model::LastTouch);
        assert_eq!(
            last[2].touchpoint,
            Uuid::from_u128(1),
            "ordered by time, not by load order"
        );
        assert_eq!(last[2].share, 1.0);
    }

    #[test]
    fn linear_and_u_shaped_sum_to_one() {
        let t = touches(&[1, 2, 3, 4, 5]);
        for model in [
            Model::Linear,
            Model::UShaped,
            Model::TimeDecay {
                half_life_days: 7.0,
            },
        ] {
            let total: f64 = attribute(&t, at(30), model).iter().map(|c| c.share).sum();
            assert!((total - 1.0).abs() < 1e-9, "{model:?}");
        }
        assert_eq!(
            shares(&attribute(&t, at(30), Model::UShaped)),
            vec![0.4, 0.067, 0.067, 0.067, 0.4]
        );
    }

    #[test]
    fn time_decay_favours_recent_touches() {
        let c = attribute(
            &touches(&[1, 29]),
            at(30),
            Model::TimeDecay {
                half_life_days: 7.0,
            },
        );
        assert!(c[1].share > c[0].share * 10.0);
    }

    #[test]
    fn touches_after_the_close_earn_nothing() {
        let c = attribute(&touches(&[1, 20]), at(10), Model::Linear);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].share, 1.0);
    }

    #[test]
    fn credit_sums_per_campaign() {
        let t = touches(&[1, 2, 3, 4]);
        let c = attribute(&t, at(30), Model::Linear);
        let per = by_campaign(&t, &c);
        assert_eq!(per.len(), 2);
        assert!(per.iter().all(|(_, s)| (s - 0.5).abs() < 1e-9));
    }
}

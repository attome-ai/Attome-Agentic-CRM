//! Risk scales and key risk indicators (roadmap R8-T1), pure.
//!
//! An organisation sets its own scale: how many probability and impact
//! levels it rates on (3 to 10 each) and the score bands that name a
//! rating (`low`, `medium`, `high`, `critical`), a score being probability
//! times impact. A key risk indicator (KRI) ties a risk to a governed
//! metric with a threshold; while a KRI is breached the risk's rating is
//! raised one band, and while two or more are, to the top band, so a risk
//! whose indicators turn red cannot keep its quiet rating.

use serde::{Deserialize, Serialize};

/// A rating, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rating {
    Low,
    Medium,
    High,
    Critical,
}

impl Rating {
    fn up(self, steps: usize) -> Self {
        const ALL: [Rating; 4] = [Rating::Low, Rating::Medium, Rating::High, Rating::Critical];
        let at = ALL.iter().position(|r| *r == self).unwrap_or(0);
        ALL[(at + steps).min(ALL.len() - 1)]
    }
}

/// An organisation's scale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScale {
    pub probability_levels: u32,
    pub impact_levels: u32,
    /// The lowest score of `medium`, `high` and `critical`, ascending.
    pub band_floors: [u32; 3],
}

impl Default for RiskScale {
    /// The common 5 x 5 matrix: 1-4 low, 5-9 medium, 10-16 high, 17-25
    /// critical.
    fn default() -> Self {
        Self {
            probability_levels: 5,
            impact_levels: 5,
            band_floors: [5, 10, 17],
        }
    }
}

impl RiskScale {
    /// Refuses a scale that cannot rate anything sensibly.
    pub fn validate(&self) -> Result<(), String> {
        for (name, levels) in [
            ("probability", self.probability_levels),
            ("impact", self.impact_levels),
        ] {
            if !(3..=10).contains(&levels) {
                return Err(format!("{name} needs 3 to 10 levels, not {levels}"));
            }
        }
        let max = self.probability_levels * self.impact_levels;
        let [m, h, c] = self.band_floors;
        if m <= 1 || h <= m || c <= h || c > max {
            return Err(format!(
                "band floors must rise between 2 and {max}: got {m}, {h}, {c}"
            ));
        }
        Ok(())
    }

    /// The score of a probability and impact, each clamped to the scale.
    pub fn score(&self, probability: u32, impact: u32) -> u32 {
        probability.clamp(1, self.probability_levels) * impact.clamp(1, self.impact_levels)
    }

    pub fn rating(&self, score: u32) -> Rating {
        let [m, h, c] = self.band_floors;
        if score >= c {
            Rating::Critical
        } else if score >= h {
            Rating::High
        } else if score >= m {
            Rating::Medium
        } else {
            Rating::Low
        }
    }
}

/// Which side of the threshold is bad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Breach {
    Above,
    Below,
}

/// A key risk indicator with the metric's latest value.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Kri {
    pub threshold: f64,
    pub breach: Breach,
    /// `None` until the metric has a value.
    pub latest: Option<f64>,
}

impl Kri {
    pub fn breached(&self) -> bool {
        match (self.latest, self.breach) {
            (Some(v), Breach::Above) => v > self.threshold,
            (Some(v), Breach::Below) => v < self.threshold,
            (None, _) => false,
        }
    }
}

/// The rating a risk carries: its scored rating, raised by breached KRIs.
pub fn effective_rating(scale: &RiskScale, probability: u32, impact: u32, kris: &[Kri]) -> Rating {
    let base = scale.rating(scale.score(probability, impact));
    match kris.iter().filter(|k| k.breached()).count() {
        0 => base,
        1 => base.up(1),
        _ => Rating::Critical,
    }
}

#[cfg(test)]
mod risk_scales {
    use super::*;

    #[test]
    fn the_default_scale_rates_a_five_by_five_matrix() {
        let scale = RiskScale::default();
        assert!(scale.validate().is_ok());
        assert_eq!(scale.rating(scale.score(1, 4)), Rating::Low);
        assert_eq!(scale.rating(scale.score(3, 3)), Rating::Medium);
        assert_eq!(scale.rating(scale.score(4, 4)), Rating::High);
        assert_eq!(
            scale.rating(scale.score(9, 9)),
            Rating::Critical,
            "clamped to 5 x 5"
        );
    }

    #[test]
    fn an_organisation_scale_is_checked() {
        let three = RiskScale {
            probability_levels: 3,
            impact_levels: 3,
            band_floors: [3, 5, 8],
        };
        assert!(three.validate().is_ok());
        assert_eq!(three.rating(three.score(2, 2)), Rating::Medium);
        let bad = RiskScale {
            band_floors: [5, 5, 30],
            ..RiskScale::default()
        };
        assert!(bad.validate().is_err());
        let tiny = RiskScale {
            probability_levels: 2,
            ..RiskScale::default()
        };
        assert!(tiny.validate().is_err());
    }

    #[test]
    fn breached_kris_raise_the_rating() {
        let scale = RiskScale::default();
        let ok = Kri {
            threshold: 5.0,
            breach: Breach::Above,
            latest: Some(3.0),
        };
        let red = Kri {
            latest: Some(7.0),
            ..ok
        };
        let low_stock = Kri {
            threshold: 10.0,
            breach: Breach::Below,
            latest: Some(4.0),
        };
        let unknown = Kri { latest: None, ..ok };
        assert_eq!(effective_rating(&scale, 2, 2, &[ok, unknown]), Rating::Low);
        assert_eq!(effective_rating(&scale, 2, 2, &[ok, red]), Rating::Medium);
        assert_eq!(effective_rating(&scale, 4, 4, &[red]), Rating::Critical);
        assert_eq!(
            effective_rating(&scale, 1, 1, &[red, low_stock]),
            Rating::Critical
        );
    }
}

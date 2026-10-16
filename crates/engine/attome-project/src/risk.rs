//! Risk scoring (roadmap V6-T1), pure: a risk's score is its likelihood
//! times its impact on the organisation's scale, its rating is the band the
//! score falls in, and a portfolio rolls its projects' risks up into the
//! top risks and a count per rating.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One rating band: scores at or above `min_score` (and below the next
/// band's) carry this rating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBand {
    pub rating: String,
    pub min_score: u32,
}

/// The organisation's risk scale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScale {
    /// The highest likelihood value (e.g. 5 on a 5x5 matrix).
    pub likelihood_levels: u32,
    pub impact_levels: u32,
    /// Bands from lowest to highest.
    pub bands: Vec<RiskBand>,
}

impl Default for RiskScale {
    /// The common 5x5 matrix: low 1-4, medium 5-9, high 10-15, critical 16-25.
    fn default() -> Self {
        let band = |rating: &str, min_score| RiskBand {
            rating: rating.to_owned(),
            min_score,
        };
        Self {
            likelihood_levels: 5,
            impact_levels: 5,
            bands: vec![
                band("low", 1),
                band("medium", 5),
                band("high", 10),
                band("critical", 16),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RiskError {
    #[error("likelihood {0} is outside the scale")]
    Likelihood(u32),
    #[error("impact {0} is outside the scale")]
    Impact(u32),
    #[error("the scale's bands must start at 1 and rise")]
    Bands,
}

impl RiskScale {
    pub fn validate(&self) -> Result<(), RiskError> {
        let rising = self
            .bands
            .windows(2)
            .all(|w| w[0].min_score < w[1].min_score);
        if self.bands.first().is_none_or(|b| b.min_score != 1) || !rising {
            return Err(RiskError::Bands);
        }
        Ok(())
    }

    /// Likelihood times impact, each checked against the scale.
    pub fn score(&self, likelihood: u32, impact: u32) -> Result<u32, RiskError> {
        if likelihood == 0 || likelihood > self.likelihood_levels {
            return Err(RiskError::Likelihood(likelihood));
        }
        if impact == 0 || impact > self.impact_levels {
            return Err(RiskError::Impact(impact));
        }
        Ok(likelihood * impact)
    }

    /// The rating of a score.
    pub fn rating(&self, score: u32) -> &str {
        self.bands
            .iter()
            .rev()
            .find(|b| score >= b.min_score)
            .map_or("", |b| b.rating.as_str())
    }
}

/// One risk of one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRisk {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub likelihood: u32,
    pub impact: u32,
    /// A closed risk does not count.
    pub open: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoredRisk {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub score: u32,
    pub rating: String,
}

/// A portfolio's risks: the highest `top` open ones and how many open risks
/// carry each rating. A risk off the scale is left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rollup {
    pub top: Vec<ScoredRisk>,
    pub by_rating: Vec<(String, usize)>,
}

pub fn roll_up(risks: &[ProjectRisk], scale: &RiskScale, top: usize) -> Rollup {
    let mut scored: Vec<ScoredRisk> = risks
        .iter()
        .filter(|r| r.open)
        .filter_map(|r| {
            let score = scale.score(r.likelihood, r.impact).ok()?;
            Some(ScoredRisk {
                id: r.id,
                project_id: r.project_id,
                title: r.title.clone(),
                score,
                rating: scale.rating(score).to_owned(),
            })
        })
        .collect();
    scored.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.title.cmp(&b.title)));
    let by_rating = scale
        .bands
        .iter()
        .rev()
        .map(|b| {
            let n = scored.iter().filter(|s| s.rating == b.rating).count();
            (b.rating.clone(), n)
        })
        .collect();
    scored.truncate(top);
    Rollup {
        top: scored,
        by_rating,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(title: &str, likelihood: u32, impact: u32, open: bool) -> ProjectRisk {
        ProjectRisk {
            id: Uuid::now_v7(),
            project_id: Uuid::now_v7(),
            title: title.to_owned(),
            likelihood,
            impact,
            open,
        }
    }

    #[test]
    fn score_and_rating_follow_the_scale() {
        let scale = RiskScale::default();
        scale.validate().expect("default scale is valid");
        assert_eq!(scale.score(4, 5), Ok(20));
        assert_eq!(scale.rating(20), "critical");
        assert_eq!(scale.rating(9), "medium");
        assert_eq!(scale.rating(1), "low");
        assert_eq!(scale.score(6, 1), Err(RiskError::Likelihood(6)));
        assert_eq!(scale.score(1, 0), Err(RiskError::Impact(0)));
        let three = RiskScale {
            likelihood_levels: 3,
            impact_levels: 3,
            bands: vec![
                RiskBand {
                    rating: "low".into(),
                    min_score: 1,
                },
                RiskBand {
                    rating: "high".into(),
                    min_score: 6,
                },
            ],
        };
        assert_eq!(three.rating(three.score(2, 3).expect("in scale")), "high");
        let bad = RiskScale {
            bands: vec![RiskBand {
                rating: "x".into(),
                min_score: 3,
            }],
            ..RiskScale::default()
        };
        assert_eq!(bad.validate(), Err(RiskError::Bands));
    }

    #[test]
    fn portfolio_rolls_up_top_open_risks() {
        let risks = vec![
            risk("vendor delay", 4, 4, true),
            risk("budget cut", 5, 5, true),
            risk("closed one", 5, 5, false),
            risk("minor", 1, 2, true),
            risk("off scale", 9, 9, true),
        ];
        let rollup = roll_up(&risks, &RiskScale::default(), 2);
        let titles: Vec<&str> = rollup.top.iter().map(|r| r.title.as_str()).collect();
        assert_eq!(titles, vec!["budget cut", "vendor delay"]);
        assert_eq!(
            rollup.by_rating,
            vec![
                ("critical".to_owned(), 2),
                ("high".to_owned(), 0),
                ("medium".to_owned(), 0),
                ("low".to_owned(), 1)
            ]
        );
    }
}

//! Did it work? (roadmap O12-T1), pure: two ways to estimate the effect of
//! a change (a new process, a campaign, a rule) on a metric, each with a 95%
//! confidence interval and the assumptions the estimate rests on, stated in
//! the result so nobody reads it as more than it is.
//!
//! - [`diff_in_diff`]: units that got the change and units that did not,
//!   each measured before and after; the effect is how much more the
//!   treated units moved than the others.
//! - [`propensity_matched`]: units described by covariates; each treated
//!   unit is paired with the untreated unit most alike in its estimated
//!   chance of being treated, and the effect is the mean outcome gap.
//!
//! Both refuse groups smaller than [`MIN_GROUP`].

use serde::Serialize;

/// The fewest units a group may have.
pub const MIN_GROUP: usize = 5;

const Z_95: f64 = 1.959_964;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Estimate {
    pub method: &'static str,
    pub effect: f64,
    pub ci_low: f64,
    pub ci_high: f64,
    pub treated: usize,
    pub control: usize,
    pub assumptions: Vec<&'static str>,
}

impl Estimate {
    /// Whether the interval excludes zero.
    pub fn significant(&self) -> bool {
        self.ci_low > 0.0 || self.ci_high < 0.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CausalError {
    TooFewTreated(usize),
    TooFewControl(usize),
    NoMatches,
}

impl std::fmt::Display for CausalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewTreated(n) => {
                write!(f, "{n} treated units; at least {MIN_GROUP} are needed")
            }
            Self::TooFewControl(n) => {
                write!(f, "{n} comparison units; at least {MIN_GROUP} are needed")
            }
            Self::NoMatches => {
                f.write_str("no comparison unit is alike enough to any treated unit")
            }
        }
    }
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn variance(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = mean(v);
    v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() - 1) as f64
}

/// A unit's metric before and after the change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeforeAfter {
    pub before: f64,
    pub after: f64,
}

/// Difference in differences over per-unit changes.
pub fn diff_in_diff(
    treated: &[BeforeAfter],
    control: &[BeforeAfter],
) -> Result<Estimate, CausalError> {
    if treated.len() < MIN_GROUP {
        return Err(CausalError::TooFewTreated(treated.len()));
    }
    if control.len() < MIN_GROUP {
        return Err(CausalError::TooFewControl(control.len()));
    }
    let dt: Vec<f64> = treated.iter().map(|u| u.after - u.before).collect();
    let dc: Vec<f64> = control.iter().map(|u| u.after - u.before).collect();
    let effect = mean(&dt) - mean(&dc);
    let se = (variance(&dt) / dt.len() as f64 + variance(&dc) / dc.len() as f64).sqrt();
    Ok(Estimate {
        method: "difference_in_differences",
        effect,
        ci_low: effect - Z_95 * se,
        ci_high: effect + Z_95 * se,
        treated: treated.len(),
        control: control.len(),
        assumptions: vec![
            "Without the change, both groups would have moved the same way (parallel trends).",
            "The change did not reach the comparison group.",
            "The units in each group stayed the same before and after.",
        ],
    })
}

/// A unit with its covariates, whether it got the change, and its outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub covariates: Vec<f64>,
    pub treated: bool,
    pub outcome: f64,
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Fits a logistic regression of treatment on standardised covariates by
/// gradient descent and returns each unit's propensity (deterministic).
fn propensities(units: &[Unit]) -> Vec<f64> {
    let k = units.first().map_or(0, |u| u.covariates.len());
    let n = units.len() as f64;
    let means: Vec<f64> = (0..k)
        .map(|j| {
            units
                .iter()
                .map(|u| u.covariates.get(j).copied().unwrap_or(0.0))
                .sum::<f64>()
                / n
        })
        .collect();
    let sds: Vec<f64> = (0..k)
        .map(|j| {
            let v = units
                .iter()
                .map(|u| (u.covariates.get(j).copied().unwrap_or(0.0) - means[j]).powi(2))
                .sum::<f64>()
                / n;
            if v > 0.0 { v.sqrt() } else { 1.0 }
        })
        .collect();
    let x: Vec<Vec<f64>> = units
        .iter()
        .map(|u| {
            (0..k)
                .map(|j| (u.covariates.get(j).copied().unwrap_or(0.0) - means[j]) / sds[j])
                .collect()
        })
        .collect();
    let mut w = vec![0.0; k + 1];
    for _ in 0..2000 {
        let mut grad = vec![0.0; k + 1];
        for (row, unit) in x.iter().zip(units) {
            let z = w[0] + row.iter().zip(&w[1..]).map(|(a, b)| a * b).sum::<f64>();
            let err = sigmoid(z) - if unit.treated { 1.0 } else { 0.0 };
            grad[0] += err;
            for (g, v) in grad[1..].iter_mut().zip(row) {
                *g += err * v;
            }
        }
        for (wi, g) in w.iter_mut().zip(&grad) {
            *wi -= 0.5 * g / n;
        }
    }
    x.iter()
        .map(|row| sigmoid(w[0] + row.iter().zip(&w[1..]).map(|(a, b)| a * b).sum::<f64>()))
        .collect()
}

/// Nearest-neighbour matching on the logit of the propensity, with
/// replacement, within a caliper of 0.2 standard deviations; the effect on
/// the treated.
pub fn propensity_matched(units: &[Unit]) -> Result<Estimate, CausalError> {
    let treated = units.iter().filter(|u| u.treated).count();
    let control = units.len() - treated;
    if treated < MIN_GROUP {
        return Err(CausalError::TooFewTreated(treated));
    }
    if control < MIN_GROUP {
        return Err(CausalError::TooFewControl(control));
    }
    let scores: Vec<f64> = propensities(units)
        .into_iter()
        .map(|p| {
            let p = p.clamp(1e-6, 1.0 - 1e-6);
            (p / (1.0 - p)).ln()
        })
        .collect();
    let caliper = 0.2 * variance(&scores).sqrt();
    let controls: Vec<usize> = (0..units.len()).filter(|i| !units[*i].treated).collect();
    let mut gaps = Vec::new();
    for (i, unit) in units.iter().enumerate().filter(|(_, u)| u.treated) {
        let best = controls
            .iter()
            .map(|c| (*c, (scores[*c] - scores[i]).abs()))
            .min_by(|a, b| a.1.total_cmp(&b.1));
        if let Some((c, distance)) = best
            && (caliper == 0.0 || distance <= caliper)
        {
            gaps.push(unit.outcome - units[c].outcome);
        }
    }
    if gaps.len() < MIN_GROUP {
        return Err(CausalError::NoMatches);
    }
    let effect = mean(&gaps);
    let se = (variance(&gaps) / gaps.len() as f64).sqrt();
    Ok(Estimate {
        method: "propensity_matched",
        effect,
        ci_low: effect - Z_95 * se,
        ci_high: effect + Z_95 * se,
        treated: gaps.len(),
        control,
        assumptions: vec![
            "Every difference that drove both treatment and outcome is among the covariates.",
            "Treated units had comparable untreated units (overlap); unmatched ones were left out.",
            "The interval ignores the uncertainty of the propensity model itself.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic noise source.
    fn noise(i: usize) -> f64 {
        ((i * 7919 % 101) as f64 / 101.0) - 0.5
    }

    #[test]
    fn diff_in_diff_recovers_a_known_effect() {
        // Everyone grows by 10; the treated grow by 5 more.
        let control: Vec<BeforeAfter> = (0..30)
            .map(|i| BeforeAfter {
                before: 100.0 + noise(i) * 10.0,
                after: 110.0 + noise(i + 50) * 10.0,
            })
            .collect();
        let treated: Vec<BeforeAfter> = (0..30)
            .map(|i| BeforeAfter {
                before: 120.0 + noise(i + 100) * 10.0,
                after: 135.0 + noise(i + 150) * 10.0,
            })
            .collect();
        let e = diff_in_diff(&treated, &control).unwrap_or_else(|e| panic!("{e}"));
        assert!((e.effect - 5.0).abs() < 2.5, "{}", e.effect);
        assert!(e.ci_low < e.effect && e.effect < e.ci_high);
        assert!(e.significant());
        assert_eq!(e.assumptions.len(), 3);
    }

    #[test]
    fn small_groups_are_refused() {
        let few = vec![
            BeforeAfter {
                before: 1.0,
                after: 2.0
            };
            3
        ];
        let enough = vec![
            BeforeAfter {
                before: 1.0,
                after: 2.0
            };
            10
        ];
        assert_eq!(
            diff_in_diff(&few, &enough),
            Err(CausalError::TooFewTreated(3))
        );
        assert_eq!(
            diff_in_diff(&enough, &few),
            Err(CausalError::TooFewControl(3))
        );
    }

    #[test]
    fn matching_removes_a_confounder() {
        // Bigger accounts are likelier to be treated and spend more anyway;
        // the true effect of treatment is +20.
        let units: Vec<Unit> = (0..200)
            .map(|i| {
                let size = (i % 50) as f64;
                let treated = (i * 31 % 100) < (size as usize * 2);
                let outcome =
                    100.0 + 3.0 * size + if treated { 20.0 } else { 0.0 } + noise(i) * 4.0;
                Unit {
                    covariates: vec![size],
                    treated,
                    outcome,
                }
            })
            .collect();
        let naive = {
            let t: Vec<f64> = units
                .iter()
                .filter(|u| u.treated)
                .map(|u| u.outcome)
                .collect();
            let c: Vec<f64> = units
                .iter()
                .filter(|u| !u.treated)
                .map(|u| u.outcome)
                .collect();
            mean(&t) - mean(&c)
        };
        let e = propensity_matched(&units).unwrap_or_else(|e| panic!("{e}"));
        assert!(naive > 35.0, "the raw gap is inflated: {naive}");
        assert!((e.effect - 20.0).abs() < 8.0, "{}", e.effect);
    }
}

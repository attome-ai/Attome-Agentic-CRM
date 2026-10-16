//! A/B tests (roadmap E4-T1): variants share a test audience, a winner is
//! chosen by a metric once the window has passed and every variant has
//! enough samples, and the rest of the audience gets the winner. This module
//! is the decision; the counters live in Postgres and are read by the caller.
//!
//! Significance is a two-sided two-proportion z-test of the leader against
//! the runner-up. Without significance the test reports a leader but no
//! winner, and the campaign's fallback (send the first variant, or stop)
//! applies.

use chrono::{DateTime, Duration, Utc};

/// What the test optimises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    Opens,
    Clicks,
    Conversions,
}

/// The defaults by channel: samples per variant and the wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub min_samples_per_variant: u64,
    pub window: Duration,
}

impl Thresholds {
    /// Email: 1,000 recipients per variant and four hours.
    pub fn email() -> Self {
        Self {
            min_samples_per_variant: 1_000,
            window: Duration::hours(4),
        }
    }

    /// Pages: 100 conversions per variant and seven days.
    pub fn page() -> Self {
        Self {
            min_samples_per_variant: 100,
            window: Duration::days(7),
        }
    }
}

/// One variant's counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantStats {
    pub name: String,
    /// Recipients (email) or visitors (page).
    pub exposures: u64,
    pub successes: u64,
}

impl VariantStats {
    pub fn rate(&self) -> f64 {
        if self.exposures == 0 {
            0.0
        } else {
            self.successes as f64 / self.exposures as f64
        }
    }
}

/// The decision at one moment.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Too early or too few samples.
    Waiting { reason: &'static str },
    /// A significant winner.
    Winner {
        variant: String,
        z: f64,
        p_value: f64,
    },
    /// The leader is not significantly better.
    NoClearWinner {
        leader: String,
        z: f64,
        p_value: f64,
    },
}

/// Splits `audience` into one share per variant plus the remainder that later
/// gets the winner. `test_share` is the share of the audience in the test.
pub fn split_sizes(audience: u64, variants: usize, test_share: f64) -> (Vec<u64>, u64) {
    if variants == 0 {
        return (Vec::new(), audience);
    }
    let share = test_share.clamp(0.0, 1.0);
    let in_test = ((audience as f64) * share).floor() as u64;
    let per = in_test / variants as u64;
    let mut sizes = vec![per; variants];
    // The rounding leftover of the test share goes to the first variants.
    let leftover = in_test - per * variants as u64;
    for size in sizes.iter_mut().take(leftover as usize) {
        *size += 1;
    }
    (sizes, audience - in_test)
}

/// Two-sided p-value of a two-proportion z-test.
pub fn two_proportion_z(a: &VariantStats, b: &VariantStats) -> (f64, f64) {
    let (n1, n2) = (a.exposures as f64, b.exposures as f64);
    if n1 == 0.0 || n2 == 0.0 {
        return (0.0, 1.0);
    }
    let pooled = (a.successes + b.successes) as f64 / (n1 + n2);
    let se = (pooled * (1.0 - pooled) * (1.0 / n1 + 1.0 / n2)).sqrt();
    if se == 0.0 {
        return (0.0, 1.0);
    }
    let z = (a.rate() - b.rate()) / se;
    (z, 2.0 * (1.0 - standard_normal_cdf(z.abs())))
}

/// The standard normal CDF (Abramowitz and Stegun 7.1.26 for erf).
fn standard_normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-x * x).exp();
    sign * y
}

/// Decides the test at `now`. `alpha` is the significance level (0.05).
pub fn decide(
    started_at: DateTime<Utc>,
    now: DateTime<Utc>,
    thresholds: Thresholds,
    metric: Metric,
    variants: &[VariantStats],
    alpha: f64,
) -> Decision {
    if variants.len() < 2 {
        return Decision::Waiting {
            reason: "an A/B test needs at least two variants",
        };
    }
    if now < started_at + thresholds.window {
        return Decision::Waiting {
            reason: "the test window has not passed",
        };
    }
    let enough = variants.iter().all(|v| match metric {
        Metric::Conversions => v.successes >= thresholds.min_samples_per_variant,
        Metric::Opens | Metric::Clicks => v.exposures >= thresholds.min_samples_per_variant,
    });
    if !enough {
        return Decision::Waiting {
            reason: "a variant has too few samples",
        };
    }
    let mut ranked: Vec<&VariantStats> = variants.iter().collect();
    ranked.sort_by(|a, b| b.rate().total_cmp(&a.rate()));
    let (leader, runner_up) = (ranked[0], ranked[1]);
    let (z, p_value) = two_proportion_z(leader, runner_up);
    if p_value < alpha {
        Decision::Winner {
            variant: leader.name.clone(),
            z,
            p_value,
        }
    } else {
        Decision::NoClearWinner {
            leader: leader.name.clone(),
            z,
            p_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(name: &str, exposures: u64, successes: u64) -> VariantStats {
        VariantStats {
            name: name.into(),
            exposures,
            successes,
        }
    }

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-01T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn split_gives_each_variant_its_share_and_keeps_the_rest() {
        let (sizes, rest) = split_sizes(10_001, 2, 0.2);
        assert_eq!(sizes, vec![1_000, 1_000]);
        assert_eq!(rest, 8_001);
        let (sizes, rest) = split_sizes(1_003, 3, 1.0);
        assert_eq!(sizes, vec![335, 334, 334]);
        assert_eq!(rest, 0);
    }

    #[test]
    fn waits_for_the_window_and_the_samples() {
        let stats = [v("A", 1_000, 200), v("B", 1_000, 300)];
        let early = decide(
            t0(),
            t0() + Duration::hours(1),
            Thresholds::email(),
            Metric::Opens,
            &stats,
            0.05,
        );
        assert!(matches!(early, Decision::Waiting { .. }));
        let thin = [v("A", 500, 100), v("B", 1_000, 300)];
        let late = decide(
            t0(),
            t0() + Duration::hours(5),
            Thresholds::email(),
            Metric::Opens,
            &thin,
            0.05,
        );
        assert!(matches!(late, Decision::Waiting { .. }));
    }

    #[test]
    fn a_clear_difference_picks_a_winner() {
        let stats = [v("A", 1_000, 200), v("B", 1_000, 300)];
        let got = decide(
            t0(),
            t0() + Duration::hours(5),
            Thresholds::email(),
            Metric::Opens,
            &stats,
            0.05,
        );
        match got {
            Decision::Winner {
                variant,
                z,
                p_value,
            } => {
                assert_eq!(variant, "B");
                assert!(z > 5.0, "{z}");
                assert!(p_value < 0.001, "{p_value}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_small_difference_is_not_a_winner() {
        let stats = [v("A", 1_000, 200), v("B", 1_000, 210)];
        let got = decide(
            t0(),
            t0() + Duration::hours(5),
            Thresholds::email(),
            Metric::Clicks,
            &stats,
            0.05,
        );
        assert!(
            matches!(got, Decision::NoClearWinner { ref leader, .. } if leader == "B"),
            "{got:?}"
        );
    }

    #[test]
    fn page_tests_count_conversions() {
        let stats = [v("A", 5_000, 99), v("B", 5_000, 180)];
        let got = decide(
            t0(),
            t0() + Duration::days(8),
            Thresholds::page(),
            Metric::Conversions,
            &stats,
            0.05,
        );
        assert!(matches!(got, Decision::Waiting { .. }));
    }

    #[test]
    fn the_normal_cdf_is_accurate() {
        assert!((standard_normal_cdf(1.96) - 0.975).abs() < 1e-3);
        assert!((standard_normal_cdf(0.0) - 0.5).abs() < 1e-9);
    }
}

//! Error budgets per SLO class from the built-in metrics store (roadmap
//! AA13-T7), so a deployment with no Prometheus still knows how much of its
//! monthly budget each class has left.
//!
//! **Source of truth.** `observability/slo-catalogue.json` (compiled in) for
//! the classes, and `ops_metric_sample` (the U4 store) for what happened:
//! the rises of `axum_http_requests_total` over the last 30 days for the
//! class's method and endpoint, 5xx counted as bad. The store keeps no
//! histogram buckets, so this is the error budget (`error_objective`); the
//! latency targets are judged by the release gate's load tests (AA13-T5)
//! and by Prometheus where it runs. Only `http` classes have an error
//! budget here.
//!
//! **Cache.** Results are kept in process for [`CACHE_TTL`] per class
//! (`slo:budget:<class>`); a cold start, or an expired entry, recomputes
//! from the store. Nothing here is durable state.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_db::DbPool;
use serde::{Deserialize, Serialize};

/// The SLO catalogue, compiled in.
const CATALOGUE_JSON: &str = include_str!("../../../../observability/slo-catalogue.json");

/// How long a computed budget is reused.
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// The budget period.
pub const PERIOD_DAYS: i32 = 30;

#[derive(Debug, Clone, Deserialize)]
pub struct SloCatalogue {
    pub classes: Vec<SloClass>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SloClass {
    pub id: String,
    pub name_en: String,
    pub name_ar: String,
    pub kind: String,
    #[serde(default, rename = "match")]
    pub matcher: serde_json::Value,
    #[serde(default)]
    pub error_objective: Option<f64>,
    /// Reference latency targets per deployment profile (`solo`, `team`,
    /// `ha`, `scale`).
    #[serde(default)]
    pub targets: Option<HashMap<String, Targets>>,
}

impl SloClass {
    /// The reference targets for `profile`, when the class has latency
    /// targets.
    pub fn targets_for(&self, profile: &str) -> Option<Targets> {
        self.targets.as_ref()?.get(profile).copied()
    }
}

/// One profile's latency targets for a class (absent where the catalogue
/// sets none).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
pub struct Targets {
    #[serde(default)]
    pub p50_ms: Option<f64>,
    #[serde(default)]
    pub p95_ms: Option<f64>,
    #[serde(default)]
    pub p99_ms: Option<f64>,
}

impl SloClass {
    /// The `(method, endpoint)` an `http` class measures.
    pub fn http_route(&self) -> Option<(&str, &str)> {
        if self.kind != "http" {
            return None;
        }
        Some((
            self.matcher.get("method")?.as_str()?,
            self.matcher.get("endpoint")?.as_str()?,
        ))
    }
}

/// The compiled-in catalogue; empty (with an error logged) when it does not
/// parse, which the unit tests rule out.
pub fn catalogue() -> &'static SloCatalogue {
    static CATALOGUE: LazyLock<SloCatalogue> = LazyLock::new(|| {
        serde_json::from_str(CATALOGUE_JSON).unwrap_or_else(|error| {
            tracing::error!(%error, "slo-catalogue.json does not parse; no SLO budgets");
            SloCatalogue {
                classes: Vec::new(),
            }
        })
    });
    &CATALOGUE
}

/// One class's error budget over the last [`PERIOD_DAYS`] days.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Budget {
    /// Requests that did not fail with a 5xx.
    pub good: f64,
    /// Requests that failed with a 5xx.
    pub bad: f64,
    /// The allowed share of bad requests.
    pub objective: f64,
    /// The share of the budget left: 1 with no failures, 0 when the bad
    /// share equals the objective, below 0 past it.
    pub remaining_ratio: f64,
}

/// `ok` with more than a quarter of the budget left, `at_risk` with some
/// left, `exhausted` with none.
pub fn status(budget: &Budget) -> &'static str {
    if budget.remaining_ratio > 0.25 {
        "ok"
    } else if budget.remaining_ratio > 0.0 {
        "at_risk"
    } else {
        "exhausted"
    }
}

/// The budget from good and bad counts. No traffic leaves the whole budget.
pub fn budget_of(good: f64, bad: f64, objective: f64) -> Budget {
    let total = good + bad;
    let remaining_ratio = if total <= 0.0 || objective <= 0.0 {
        1.0
    } else {
        1.0 - (bad / total) / objective
    };
    Budget {
        good,
        bad,
        objective,
        remaining_ratio,
    }
}

static CACHE: LazyLock<Mutex<HashMap<String, (Instant, Budget)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The 30-day error budget of an `http` class from the store, or `None` for
/// a class without one. Counter rises are summed per series (a reset counts
/// from zero), so restarts and several nodes add up correctly.
pub async fn budget(db: &DbPool, class: &SloClass) -> Result<Option<Budget>, sqlx::Error> {
    let (Some((method, endpoint)), Some(objective)) = (class.http_route(), class.error_objective)
    else {
        return Ok(None);
    };
    let key = format!("slo:budget:{}", class.id);
    if let Some((at, cached)) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
        && at.elapsed() < CACHE_TTL
    {
        return Ok(Some(cached));
    }
    let (bad, total): (f64, f64) = sqlx::query_as(
        "WITH s AS ( \
             SELECT labels, value, \
                    lag(value) OVER (PARTITION BY labels ORDER BY ts) AS prev \
               FROM ops_metric_sample \
              WHERE name = 'axum_http_requests_total' \
                AND ts > now() - make_interval(days => $3) \
                AND labels->>'method' = $1 AND labels->>'endpoint' = $2), \
         d AS ( \
             SELECT labels, CASE WHEN prev IS NULL THEN 0 \
                                 WHEN value >= prev THEN value - prev ELSE value END AS rise \
               FROM s) \
         SELECT COALESCE(SUM(rise) FILTER (WHERE labels->>'status' LIKE '5%'), 0)::float8, \
                COALESCE(SUM(rise), 0)::float8 \
           FROM d",
    )
    .bind(method)
    .bind(endpoint)
    .bind(PERIOD_DAYS)
    .fetch_one(db)
    .await?;
    let computed = budget_of(total - bad, bad, objective);
    CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, (Instant::now(), computed));
    Ok(Some(computed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_parses_and_http_classes_name_a_route() {
        let classes = &catalogue().classes;
        assert!(classes.len() >= 9, "{}", classes.len());
        let http: Vec<_> = classes.iter().filter(|c| c.kind == "http").collect();
        assert!(!http.is_empty());
        for class in http {
            assert!(class.http_route().is_some(), "{}", class.id);
            assert!(class.error_objective.is_some(), "{}", class.id);
        }
    }

    #[test]
    fn budget_full_when_no_bad_requests() {
        let b = budget_of(10_000.0, 0.0, 0.001);
        assert!((b.remaining_ratio - 1.0).abs() < 1e-12);
        assert_eq!(status(&b), "ok");
        assert_eq!(status(&budget_of(0.0, 0.0, 0.001)), "ok");
    }

    #[test]
    fn budget_burns_with_bad_requests() {
        // Half the allowed share spent.
        let half = budget_of(9_995.0, 5.0, 0.001);
        assert!((half.remaining_ratio - 0.5).abs() < 1e-9);
        assert_eq!(status(&half), "ok");
        assert_eq!(status(&budget_of(9_992.0, 8.0, 0.001)), "at_risk");
        let gone = budget_of(9_980.0, 20.0, 0.001);
        assert!(gone.remaining_ratio < 0.0);
        assert_eq!(status(&gone), "exhausted");
    }
}

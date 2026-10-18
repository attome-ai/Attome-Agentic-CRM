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
//! **Latency regressions (AA14-T8).** The store keeps the request-duration
//! buckets of the routes the `http` classes measure
//! ([`crate::metrics_store::SLO_LATENCY_BUCKETS`]), so the daily
//! [`perf_regression_check`] compares each class's p95 in the week after the
//! last upgrade with the week before it and raises a built-in alert
//! (`PerfRegression:<class>`) on a clear regression.
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
    let to = chrono::Utc::now();
    let from = to - chrono::Duration::days(i64::from(PERIOD_DAYS));
    let (bad, total) = counts_between(db, method, endpoint, from, to).await?;
    let computed = budget_of(total - bad, bad, objective);
    CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, (Instant::now(), computed));
    Ok(Some(computed))
}

/// The 5xx and all responses of one route in `[from, to)`, from the rises
/// of `axum_http_requests_total`, summed per series (a reset counts from
/// zero).
pub async fn counts_between(
    db: &DbPool,
    method: &str,
    endpoint: &str,
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
) -> Result<(f64, f64), sqlx::Error> {
    sqlx::query_as(
        "WITH s AS ( \
             SELECT labels, value, \
                    lag(value) OVER (PARTITION BY labels ORDER BY ts) AS prev \
               FROM ops_metric_sample \
              WHERE name = 'axum_http_requests_total' \
                AND ts >= $3 AND ts < $4 \
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
    .bind(from)
    .bind(to)
    .fetch_one(db)
    .await
}

/// The fast-burn factor of `observability/alerts.yml` (Google SRE workbook
/// ch. 5): a class burns when its bad ratio over both the last hour and the
/// last five minutes is above this many times its objective.
pub const FAST_BURN_FACTOR: f64 = 14.4;

/// Below this many requests in five minutes a ratio is noise, not a burn
/// (the same floor as the built-in `HighHttpErrorRate` rule).
pub const MIN_BURN_REQUESTS: f64 = 20.0;

/// Whether `(bad, total)` over one hour and over five minutes is a fast burn
/// of `objective`.
pub fn is_fast_burn(hour: (f64, f64), five_minutes: (f64, f64), objective: f64) -> bool {
    let ratio = |(bad, total): (f64, f64)| if total > 0.0 { bad / total } else { 0.0 };
    let limit = FAST_BURN_FACTOR * objective;
    objective > 0.0
        && five_minutes.1 >= MIN_BURN_REQUESTS
        && ratio(hour) > limit
        && ratio(five_minutes) > limit
}

// ── Latency regressions after an upgrade (AA14-T8) ──────────────────────────

/// A class regressed when its p95 rose by more than this factor (20%).
pub const REGRESSION_FACTOR: f64 = 1.2;

/// Below this many requests in either window a p95 is noise, not evidence.
pub const REGRESSION_MIN_REQUESTS: u64 = 1_000;

/// The length of each compared window, and how long after an upgrade the
/// check keeps comparing.
pub const REGRESSION_WINDOW_DAYS: i64 = 7;

/// A moment, in UTC.
pub type At = chrono::DateTime<chrono::Utc>;

/// A `[from, to)` time range.
pub type Range = (At, At);

/// One window's request count and p95, in seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyWindow {
    pub requests: u64,
    pub p95_seconds: f64,
}

impl LatencyWindow {
    /// The window of a cumulative histogram (`(upper bound, count)` sorted,
    /// `+Inf` last).
    pub fn of(buckets: &[(f64, u64)]) -> Self {
        Self {
            requests: buckets.last().map_or(0, |b| b.1),
            p95_seconds: crate::metrics::quantile(buckets, 0.95),
        }
    }
}

/// Whether `after`'s p95 rose more than 20% over `before`'s, with at least
/// [`REGRESSION_MIN_REQUESTS`] in each window.
pub fn is_p95_regression(before: LatencyWindow, after: LatencyWindow) -> bool {
    before.requests >= REGRESSION_MIN_REQUESTS
        && after.requests >= REGRESSION_MIN_REQUESTS
        && before.p95_seconds > 0.0
        && after.p95_seconds > before.p95_seconds * REGRESSION_FACTOR
}

/// The `(before, after)` windows to compare for an upgrade at `upgraded_at`:
/// the week before it, and the last week cut at the upgrade, so no traffic
/// of the old version counts as after. `None` once the upgrade is more than
/// a week old (the next upgrade starts a new comparison).
pub fn regression_windows(upgraded_at: At, now: At) -> Option<(Range, Range)> {
    let week = chrono::Duration::days(REGRESSION_WINDOW_DAYS);
    if upgraded_at > now || now - upgraded_at > week {
        return None;
    }
    Some((
        (upgraded_at - week, upgraded_at),
        ((now - week).max(upgraded_at), now),
    ))
}

/// When this deployment last changed version: the first start of the
/// version that started last, after the last start of any other version.
/// `None` when every recorded start ran one version.
pub async fn last_upgrade(db: &DbPool) -> Result<Option<At>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH cur AS ( \
             SELECT version FROM deploy_event WHERE kind = 'start' \
              ORDER BY started_at DESC, id DESC LIMIT 1), \
         prev AS ( \
             SELECT max(e.started_at) AS at FROM deploy_event e, cur \
              WHERE e.kind = 'start' AND e.version <> cur.version) \
         SELECT min(e.started_at) FROM deploy_event e, cur, prev \
          WHERE e.kind = 'start' AND e.version = cur.version \
            AND prev.at IS NOT NULL AND e.started_at > prev.at",
    )
    .fetch_one(db)
    .await
}

/// One route's cumulative latency histogram over `[from, to)`, from the
/// rises of the stored buckets (a reset counts from zero), `+Inf` last.
pub async fn latency_buckets_between(
    db: &DbPool,
    method: &str,
    endpoint: &str,
    (from, to): Range,
) -> Result<Vec<(f64, u64)>, sqlx::Error> {
    let rows: Vec<(String, f64)> = sqlx::query_as(
        "WITH s AS ( \
             SELECT labels, value, \
                    lag(value) OVER (PARTITION BY labels ORDER BY ts) AS prev \
               FROM ops_metric_sample \
              WHERE name = $5 \
                AND ts >= $3 AND ts < $4 \
                AND labels->>'method' = $1 AND labels->>'endpoint' = $2) \
         SELECT labels->>'le', \
                COALESCE(SUM(CASE WHEN prev IS NULL THEN 0 \
                                  WHEN value >= prev THEN value - prev ELSE value END), 0)::float8 \
           FROM s GROUP BY labels->>'le'",
    )
    .bind(method)
    .bind(endpoint)
    .bind(from)
    .bind(to)
    .bind(crate::metrics_store::SLO_LATENCY_BUCKETS)
    .fetch_all(db)
    .await?;
    Ok(cumulative_buckets(rows))
}

/// `(le, count)` rows as a sorted cumulative histogram; an `le` that is
/// neither a number nor `+Inf` is dropped.
fn cumulative_buckets(rows: Vec<(String, f64)>) -> Vec<(f64, u64)> {
    let mut buckets: Vec<(f64, u64)> = rows
        .into_iter()
        .filter_map(|(le, count)| {
            let bound = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse().ok()?
            };
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a sum of non-negative counter rises, well inside u64"
            )]
            let count = count.max(0.0).round() as u64;
            Some((bound, count))
        })
        .collect();
    buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
    buckets
}

/// One class's comparison.
#[derive(Debug, Clone, Serialize)]
pub struct RegressionFinding {
    pub class: String,
    pub before_p95_ms: f64,
    pub after_p95_ms: f64,
    pub before_requests: u64,
    pub after_requests: u64,
    pub regressed: bool,
}

/// The built-in alert a class's regression raises.
pub fn regression_alert_name(class_id: &str) -> String {
    format!("PerfRegression:{class_id}")
}

/// AA14-T8, the daily job's body: when the last upgrade is under a week
/// old, compares each `http` class's p95 in the week before it with the
/// time since (at most a week), raises `PerfRegression:<class>` through the
/// built-in alerts on a clear regression and clears it otherwise. With no
/// recent upgrade every such alert is cleared. Returns each class compared.
pub async fn perf_regression_check(
    db: &DbPool,
    now: At,
) -> Result<Vec<RegressionFinding>, sqlx::Error> {
    let windows = last_upgrade(db)
        .await?
        .and_then(|at| regression_windows(at, now));
    let mut findings = Vec::new();
    for class in &catalogue().classes {
        let Some((method, endpoint)) = class.http_route() else {
            continue;
        };
        let name = regression_alert_name(&class.id);
        let Some((before_range, after_range)) = windows else {
            crate::alerts::set_job_alert(db, &name, "warning", "", None, false).await?;
            continue;
        };
        let before =
            LatencyWindow::of(&latency_buckets_between(db, method, endpoint, before_range).await?);
        let after =
            LatencyWindow::of(&latency_buckets_between(db, method, endpoint, after_range).await?);
        let regressed = is_p95_regression(before, after);
        let finding = RegressionFinding {
            class: class.id.clone(),
            before_p95_ms: before.p95_seconds * 1000.0,
            after_p95_ms: after.p95_seconds * 1000.0,
            before_requests: before.requests,
            after_requests: after.requests,
            regressed,
        };
        let summary = format!(
            "{} ({method} {endpoint}): p95 {:.0} ms since the upgrade against {:.0} ms \
             the week before ({} and {} requests)",
            class.name_en,
            finding.after_p95_ms,
            finding.before_p95_ms,
            finding.after_requests,
            finding.before_requests
        );
        let ratio = (before.p95_seconds > 0.0).then(|| after.p95_seconds / before.p95_seconds);
        crate::alerts::set_job_alert(db, &name, "warning", &summary, ratio, regressed).await?;
        findings.push(finding);
    }
    Ok(findings)
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

    /// A histogram of `n` requests, `slow` of them in the 0.1-0.12 s bucket
    /// and the rest under 0.03 s.
    fn histogram(n: u64, slow: u64) -> Vec<(f64, u64)> {
        let fast = n - slow;
        vec![
            (0.03, fast),
            (0.1, fast),
            (0.12, n),
            (0.3, n),
            (f64::INFINITY, n),
        ]
    }

    #[test]
    fn perf_regression_raises_on_a_clear_p95_rise() {
        // Before: 2% slow, so p95 sits in the fast bucket. After: 10% slow,
        // so p95 lands in the 0.1-0.12 s bucket, several times higher.
        let before = LatencyWindow::of(&histogram(5_000, 100));
        let after = LatencyWindow::of(&histogram(5_000, 500));
        assert!(before.p95_seconds < 0.03, "{before:?}");
        assert!(after.p95_seconds > 0.1, "{after:?}");
        assert!(is_p95_regression(before, after));
    }

    #[test]
    fn perf_regression_ignores_noise() {
        // A few more slow requests after (4% to 4.6%): p95 rises under 20%.
        let before = LatencyWindow::of(&histogram(5_000, 200));
        let after = LatencyWindow::of(&histogram(5_000, 230));
        assert!(
            after.p95_seconds > before.p95_seconds,
            "{before:?} {after:?}"
        );
        assert!(!is_p95_regression(before, after), "{before:?} {after:?}");
        // A large rise on too few requests is noise too.
        let thin_before = LatencyWindow::of(&histogram(900, 18));
        let thin_after = LatencyWindow::of(&histogram(900, 90));
        assert!(!is_p95_regression(thin_before, thin_after));
        // No traffic before: nothing to compare.
        assert!(!is_p95_regression(
            LatencyWindow::of(&[]),
            LatencyWindow::of(&histogram(5_000, 500))
        ));
    }

    #[test]
    fn perf_regression_windows_follow_the_upgrade() {
        let at = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let upgraded = at("2026-10-10T12:00:00Z");
        let ((b0, b1), (a0, a1)) =
            regression_windows(upgraded, at("2026-10-12T12:00:00Z")).unwrap();
        assert_eq!((b0, b1), (at("2026-10-03T12:00:00Z"), upgraded));
        // Two days after the upgrade the after window starts at the upgrade,
        // not a week back, so no old-version traffic counts.
        assert_eq!((a0, a1), (upgraded, at("2026-10-12T12:00:00Z")));
        assert!(regression_windows(upgraded, at("2026-10-17T12:00:01Z")).is_none());
        assert!(regression_windows(upgraded, at("2026-10-09T12:00:00Z")).is_none());
    }

    #[test]
    fn perf_regression_reads_stored_buckets_in_order() {
        let rows = vec![
            ("+Inf".to_owned(), 10.0),
            ("0.1".to_owned(), 7.0),
            ("bogus".to_owned(), 1.0),
            ("0.03".to_owned(), 4.0),
        ];
        assert_eq!(
            cumulative_buckets(rows),
            [(0.03, 4), (0.1, 7), (f64::INFINITY, 10)]
        );
        assert_eq!(
            crate::metrics_store::SLO_LATENCY_BUCKETS,
            format!(
                "{}_bucket",
                axum_prometheus::AXUM_HTTP_REQUESTS_DURATION_SECONDS
            )
        );
    }

    #[test]
    fn a_fast_burn_needs_both_windows_and_enough_traffic() {
        // 0.1% objective: the limit is a 1.44% bad ratio.
        assert!(is_fast_burn((30.0, 1_000.0), (5.0, 100.0), 0.001));
        assert!(
            !is_fast_burn((10.0, 1_000.0), (5.0, 100.0), 0.001),
            "hour below"
        );
        assert!(
            !is_fast_burn((30.0, 1_000.0), (1.0, 100.0), 0.001),
            "5m below"
        );
        assert!(
            !is_fast_burn((30.0, 1_000.0), (5.0, 10.0), 0.001),
            "too few requests"
        );
        assert!(!is_fast_burn((30.0, 1_000.0), (5.0, 100.0), 0.0));
    }
}

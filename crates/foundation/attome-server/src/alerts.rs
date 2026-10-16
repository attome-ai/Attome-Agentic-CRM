//! Built-in alerting (roadmap AB10-T1): the rules in
//! `observability/builtin-alerts.json`, evaluated every minute on the
//! built-in metrics store ([`crate::metrics_store`]), so a Solo deployment is
//! told when something is wrong with no Prometheus or Alertmanager to run.
//!
//! **Rules.** Four kinds, enough for the signals this process records:
//! `threshold` (the latest minute, aggregated over the matching series),
//! `increase` (a counter's rise over a window, a reset counted from zero),
//! `ratio` (one increase over another, quiet below a minimum denominator) and
//! `stale` (a series, grouped by a label, that stopped reporting). A rule
//! must hold for `for_minutes` before it fires.
//!
//! **State.** `ops_alert` holds each rule's state (`inactive`, `pending`,
//! `firing`); every change to firing and back appends an `ops_alert_event`,
//! which the notifier (AB10-T2) sends. A one-row lease (`ops_alert_lease`)
//! lets one node evaluate each minute when several run. Evaluation reads
//! the store only; a failed minute is logged and the next one runs.

use std::collections::BTreeMap;
use std::time::Duration;

use attome_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};

/// The rule file, compiled in so every node evaluates the same rules.
const RULES_JSON: &str = include_str!("../../../../observability/builtin-alerts.json");

/// How often the rules are evaluated (the store samples once a minute).
pub const EVALUATE_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Threshold,
    Increase,
    Ratio,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Aggregate {
    #[default]
    Sum,
    Max,
    Min,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeriesRef {
    pub metric: String,
    #[serde(default, rename = "match")]
    pub matchers: BTreeMap<String, String>,
}

/// One rule of `observability/builtin-alerts.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub severity: String,
    pub summary: String,
    #[serde(default)]
    pub runbook: Option<String>,
    pub kind: RuleKind,
    pub metric: String,
    #[serde(default, rename = "match")]
    pub matchers: BTreeMap<String, String>,
    #[serde(default)]
    pub denominator: Option<SeriesRef>,
    #[serde(default)]
    pub min_denominator: f64,
    #[serde(default)]
    pub aggregate: Aggregate,
    #[serde(default = "default_window")]
    pub window_minutes: i64,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default = "default_stale_after")]
    pub stale_after_minutes: i64,
    pub op: String,
    pub value: f64,
    #[serde(default)]
    pub for_minutes: i64,
}

fn default_window() -> i64 {
    5
}

fn default_stale_after() -> i64 {
    3
}

#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<AlertRule>,
}

/// The built-in rules. The file is part of the binary, so a parse failure is
/// a build defect the unit tests catch; at run time it logs and yields none.
pub fn builtin_rules() -> Vec<AlertRule> {
    match serde_json::from_str::<RuleFile>(RULES_JSON) {
        Ok(file) => file.rules,
        Err(error) => {
            tracing::error!(%error, "builtin-alerts.json does not parse; no built-in alerts");
            Vec::new()
        }
    }
}

/// One stored sample, as the evaluator reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub at: DateTime<Utc>,
    pub labels: Map<String, Value>,
    pub value: f64,
}

fn label<'a>(labels: &'a Map<String, Value>, key: &str) -> &'a str {
    labels.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Whether `labels` satisfy every matcher (`x*` is a prefix).
pub fn matches(labels: &Map<String, Value>, matchers: &BTreeMap<String, String>) -> bool {
    matchers.iter().all(|(key, wanted)| {
        let got = label(labels, key);
        match wanted.strip_suffix('*') {
            Some(prefix) => got.starts_with(prefix),
            None => got == wanted,
        }
    })
}

/// A series' identity: its labels in key order.
fn series_key(labels: &Map<String, Value>) -> String {
    let mut pairs: Vec<(&String, &Value)> = labels.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    serde_json::to_string(&pairs).unwrap_or_default()
}

/// The rise of the matching counters over the points given (they span the
/// window), summed over series. A counter that went down was reset: its
/// rise is counted from zero.
pub fn increase(points: &[Point], matchers: &BTreeMap<String, String>) -> f64 {
    let mut by_series: BTreeMap<String, Vec<&Point>> = BTreeMap::new();
    for point in points.iter().filter(|p| matches(&p.labels, matchers)) {
        by_series
            .entry(series_key(&point.labels))
            .or_default()
            .push(point);
    }
    let mut total = 0.0;
    for (_, mut series) in by_series {
        series.sort_by_key(|p| p.at);
        for pair in series.windows(2) {
            let (before, after) = (pair[0].value, pair[1].value);
            total += if after >= before {
                after - before
            } else {
                after
            };
        }
    }
    total
}

/// The latest minute's value of the matching series, aggregated.
pub fn latest(
    points: &[Point],
    matchers: &BTreeMap<String, String>,
    aggregate: Aggregate,
) -> Option<f64> {
    let newest = points
        .iter()
        .filter(|p| matches(&p.labels, matchers))
        .map(|p| p.at)
        .max()?;
    let values = points
        .iter()
        .filter(|p| p.at == newest && matches(&p.labels, matchers))
        .map(|p| p.value);
    Some(match aggregate {
        Aggregate::Sum => values.sum(),
        Aggregate::Max => values.fold(f64::MIN, f64::max),
        Aggregate::Min => values.fold(f64::MAX, f64::min),
    })
}

/// How many groups (`group_by` values) reported within the window but not
/// for the last `stale_after` minutes, and their names.
pub fn stale_groups(
    points: &[Point],
    group_by: &str,
    stale_after: i64,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut last_seen: BTreeMap<&str, DateTime<Utc>> = BTreeMap::new();
    for point in points {
        let group = label(&point.labels, group_by);
        if group.is_empty() {
            continue;
        }
        let seen = last_seen.entry(group).or_insert(point.at);
        if point.at > *seen {
            *seen = point.at;
        }
    }
    let cutoff = now - chrono::Duration::minutes(stale_after);
    last_seen
        .into_iter()
        .filter(|(_, seen)| *seen < cutoff)
        .map(|(group, _)| group.to_owned())
        .collect()
}

/// The value a rule compares, from the points of its window (`denominator`
/// points for a ratio), or `None` when there is nothing to judge.
pub fn rule_value(
    rule: &AlertRule,
    points: &[Point],
    denominator: &[Point],
    now: DateTime<Utc>,
) -> Option<f64> {
    match rule.kind {
        RuleKind::Threshold => latest(points, &rule.matchers, rule.aggregate),
        RuleKind::Increase => {
            if points.is_empty() {
                None
            } else {
                Some(increase(points, &rule.matchers))
            }
        }
        RuleKind::Ratio => {
            let den_matchers = rule
                .denominator
                .as_ref()
                .map(|d| d.matchers.clone())
                .unwrap_or_default();
            let den = increase(denominator, &den_matchers);
            if den <= 0.0 || den < rule.min_denominator {
                return None;
            }
            Some(increase(points, &rule.matchers) / den)
        }
        RuleKind::Stale => {
            let group = rule.group_by.as_deref().unwrap_or("node");
            Some(stale_groups(points, group, rule.stale_after_minutes, now).len() as f64)
        }
    }
}

/// Whether `value op threshold` holds.
pub fn breaches(op: &str, value: f64, threshold: f64) -> bool {
    match op {
        ">" => value > threshold,
        ">=" => value >= threshold,
        "<" => value < threshold,
        "<=" => value <= threshold,
        "==" => (value - threshold).abs() < f64::EPSILON,
        "!=" => (value - threshold).abs() >= f64::EPSILON,
        _ => false,
    }
}

/// A rule's state between evaluations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    Inactive,
    Pending { since: DateTime<Utc> },
    Firing { since: DateTime<Utc> },
}

/// What one evaluation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    None,
    Fired,
    Resolved,
}

/// The next state of a rule that does (`breaching`) or does not hold at
/// `now`, and whether that fires or resolves it.
pub fn step(
    state: AlertState,
    breaching: bool,
    for_minutes: i64,
    now: DateTime<Utc>,
) -> (AlertState, Transition) {
    let hold = chrono::Duration::minutes(for_minutes.max(0));
    match (state, breaching) {
        (AlertState::Firing { .. }, false) => (AlertState::Inactive, Transition::Resolved),
        (AlertState::Pending { .. } | AlertState::Inactive, false) => {
            (AlertState::Inactive, Transition::None)
        }
        (AlertState::Firing { since }, true) => (AlertState::Firing { since }, Transition::None),
        (AlertState::Inactive, true) if hold.is_zero() => {
            (AlertState::Firing { since: now }, Transition::Fired)
        }
        (AlertState::Inactive, true) => (AlertState::Pending { since: now }, Transition::None),
        (AlertState::Pending { since }, true) if now - since >= hold => {
            (AlertState::Firing { since: now }, Transition::Fired)
        }
        (AlertState::Pending { since }, true) => (AlertState::Pending { since }, Transition::None),
    }
}

async fn read_points(db: &DbPool, metric: &str, minutes: i64) -> Result<Vec<Point>, sqlx::Error> {
    let rows: Vec<(DateTime<Utc>, Value, f64)> = sqlx::query_as(
        "SELECT ts, labels, value FROM ops_metric_sample \
          WHERE name = $1 AND ts > now() - make_interval(mins => $2::int) \
          ORDER BY ts",
    )
    .bind(metric)
    .bind(i32::try_from(minutes.clamp(1, 24 * 60)).unwrap_or(60))
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(at, labels, value)| Point {
            at,
            labels: labels.as_object().cloned().unwrap_or_default(),
            value,
        })
        .collect())
}

async fn stored_state(db: &DbPool, name: &str) -> Result<AlertState, sqlx::Error> {
    let row: Option<(String, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT state, pending_since, firing_since FROM ops_alert WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?;
    Ok(match row {
        Some((state, _, Some(since))) if state == "firing" => AlertState::Firing { since },
        Some((state, Some(since), _)) if state == "pending" => AlertState::Pending { since },
        _ => AlertState::Inactive,
    })
}

async fn save(
    db: &DbPool,
    rule: &AlertRule,
    state: AlertState,
    transition: Transition,
    value: Option<f64>,
) -> Result<(), sqlx::Error> {
    let (label, pending, firing) = match state {
        AlertState::Inactive => ("inactive", None, None),
        AlertState::Pending { since } => ("pending", Some(since), None),
        AlertState::Firing { since } => ("firing", None, Some(since)),
    };
    let mut tx = attome_db::tx::begin(db)
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    sqlx::query(
        "INSERT INTO ops_alert (name, state, severity, summary, value, pending_since, firing_since, \
                               resolved_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $8 THEN now() END, now()) \
         ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state, severity = EXCLUDED.severity, \
             summary = EXCLUDED.summary, value = EXCLUDED.value, \
             pending_since = EXCLUDED.pending_since, firing_since = EXCLUDED.firing_since, \
             resolved_at = COALESCE(EXCLUDED.resolved_at, ops_alert.resolved_at), \
             updated_at = now()",
    )
    .bind(&rule.name)
    .bind(label)
    .bind(&rule.severity)
    .bind(&rule.summary)
    .bind(value)
    .bind(pending)
    .bind(firing)
    .bind(transition == Transition::Resolved)
    .execute(&mut *tx)
    .await?;
    let event = match transition {
        Transition::Fired => Some("firing"),
        Transition::Resolved => Some("resolved"),
        Transition::None => None,
    };
    if let Some(event) = event {
        sqlx::query(
            "INSERT INTO ops_alert_event (name, event, severity, summary, value) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&rule.name)
        .bind(event)
        .bind(&rule.severity)
        .bind(&rule.summary)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Takes this minute's evaluation for this node, or `false` when another
/// node already did it.
async fn take_lease(db: &DbPool) -> Result<bool, sqlx::Error> {
    let taken = sqlx::query(
        "UPDATE ops_alert_lease SET evaluated_at = now() \
          WHERE id = 1 AND evaluated_at < now() - interval '50 seconds'",
    )
    .execute(db)
    .await?
    .rows_affected();
    Ok(taken == 1)
}

/// One evaluation of every rule.
pub async fn evaluate_once(db: &DbPool, rules: &[AlertRule]) -> Result<usize, sqlx::Error> {
    if !take_lease(db).await? {
        return Ok(0);
    }
    let now = Utc::now();
    let mut changed = 0;
    for rule in rules {
        let window = match rule.kind {
            RuleKind::Threshold => 3,
            _ => rule.window_minutes.max(1),
        };
        let points = read_points(db, &rule.metric, window).await?;
        let denominator = match (&rule.kind, &rule.denominator) {
            (RuleKind::Ratio, Some(den)) => read_points(db, &den.metric, window).await?,
            _ => Vec::new(),
        };
        let value = rule_value(rule, &points, &denominator, now);
        let breaching = value.is_some_and(|v| breaches(&rule.op, v, rule.value));
        let before = stored_state(db, &rule.name).await?;
        let (after, transition) = step(before, breaching, rule.for_minutes, now);
        match transition {
            Transition::Fired => tracing::warn!(
                alert = %rule.name, severity = %rule.severity, value = ?value,
                runbook = rule.runbook.as_deref().unwrap_or(""),
                "alert firing: {}", rule.summary
            ),
            Transition::Resolved => tracing::info!(alert = %rule.name, "alert resolved"),
            Transition::None => {}
        }
        if after != before || transition != Transition::None || value.is_some() {
            save(db, rule, after, transition, value).await?;
        }
        if transition != Transition::None {
            changed += 1;
        }
    }
    Ok(changed)
}

/// Starts the once-a-minute evaluation. Process-lifetime supervision: a
/// failed minute is logged and the next one runs.
pub fn spawn(db: DbPool) {
    let rules = builtin_rules();
    if rules.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(EVALUATE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = evaluate_once(&db, &rules).await {
                tracing::warn!(%error, "built-in alerts: this minute was not evaluated");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(minute: i64, labels: &[(&str, &str)], value: f64) -> Point {
        let at = DateTime::<Utc>::from_timestamp(1_800_000_000 + minute * 60, 0).unwrap();
        Point {
            at,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
                .collect(),
            value,
        }
    }

    fn at(minute: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + minute * 60, 0).unwrap()
    }

    #[test]
    fn the_shipped_rules_parse_and_use_known_kinds() {
        let rules = builtin_rules();
        assert!(rules.len() >= 8, "{}", rules.len());
        for rule in &rules {
            assert!(
                matches!(rule.op.as_str(), ">" | ">=" | "<" | "<=" | "==" | "!="),
                "{}: op {}",
                rule.name,
                rule.op
            );
            assert!(
                matches!(rule.severity.as_str(), "info" | "warning" | "critical"),
                "{}",
                rule.name
            );
            if rule.kind == RuleKind::Ratio {
                assert!(
                    rule.denominator.is_some(),
                    "{} needs a denominator",
                    rule.name
                );
            }
        }
    }

    #[test]
    fn increase_sums_series_and_counts_a_reset_from_zero() {
        let points = vec![
            point(0, &[("status", "500")], 10.0),
            point(1, &[("status", "500")], 14.0),
            point(2, &[("status", "500")], 3.0),
            point(0, &[("status", "503")], 1.0),
            point(2, &[("status", "503")], 2.0),
            point(0, &[("status", "200")], 100.0),
            point(2, &[("status", "200")], 200.0),
        ];
        let five = BTreeMap::from([("status".to_owned(), "5*".to_owned())]);
        // 500: +4, then reset to 3 (+3); 503: +1.
        assert!((increase(&points, &five) - 8.0).abs() < 1e-9);
        assert!((increase(&points, &BTreeMap::new()) - 108.0).abs() < 1e-9);
    }

    #[test]
    fn a_ratio_rule_is_quiet_below_its_minimum_traffic() {
        let mut rule: AlertRule = builtin_rules()
            .into_iter()
            .find(|r| r.kind == RuleKind::Ratio)
            .expect("a ratio rule ships");
        rule.min_denominator = 20.0;
        let errors = vec![
            point(0, &[("status", "500")], 0.0),
            point(5, &[("status", "500")], 5.0),
        ];
        let all_small = vec![point(0, &[], 0.0), point(5, &[], 10.0)];
        let all_big = vec![point(0, &[], 0.0), point(5, &[], 100.0)];
        assert_eq!(rule_value(&rule, &errors, &all_small, at(5)), None);
        let value = rule_value(&rule, &errors, &all_big, at(5)).expect("judged");
        assert!((value - 0.05).abs() < 1e-9);
        assert!(breaches(&rule.op, value, rule.value));
    }

    #[test]
    fn latest_aggregates_only_the_newest_minute() {
        let points = vec![
            point(0, &[("q", "a")], 9.0),
            point(1, &[("q", "a")], 2.0),
            point(1, &[("q", "b")], 5.0),
        ];
        assert_eq!(latest(&points, &BTreeMap::new(), Aggregate::Max), Some(5.0));
        assert_eq!(latest(&points, &BTreeMap::new(), Aggregate::Sum), Some(7.0));
        assert_eq!(latest(&points, &BTreeMap::new(), Aggregate::Min), Some(2.0));
        assert_eq!(latest(&[], &BTreeMap::new(), Aggregate::Max), None);
    }

    #[test]
    fn a_node_that_stopped_reporting_is_stale() {
        let points = vec![
            point(0, &[("node", "web-1")], 1.0),
            point(10, &[("node", "web-1")], 1.0),
            point(0, &[("node", "web-2")], 1.0),
            point(4, &[("node", "web-2")], 1.0),
        ];
        assert_eq!(
            stale_groups(&points, "node", 3, at(10)),
            vec!["web-2".to_owned()]
        );
    }

    #[test]
    fn a_rule_fires_after_holding_for_its_duration_and_resolves() {
        let (s, t) = step(AlertState::Inactive, true, 5, at(0));
        assert_eq!(
            (s, t),
            (AlertState::Pending { since: at(0) }, Transition::None)
        );
        let (s, t) = step(s, true, 5, at(4));
        assert_eq!(t, Transition::None);
        let (s, t) = step(s, true, 5, at(5));
        assert_eq!(
            (s, t),
            (AlertState::Firing { since: at(5) }, Transition::Fired)
        );
        let (s, t) = step(s, true, 5, at(6));
        assert_eq!(t, Transition::None);
        let (s, t) = step(s, false, 5, at(7));
        assert_eq!((s, t), (AlertState::Inactive, Transition::Resolved));
        // A breach that clears before its duration never fires.
        let (s, _) = step(AlertState::Inactive, true, 5, at(0));
        assert_eq!(
            step(s, false, 5, at(2)),
            (AlertState::Inactive, Transition::None)
        );
        // No duration: fires at once.
        assert_eq!(
            step(AlertState::Inactive, true, 0, at(0)),
            (AlertState::Firing { since: at(0) }, Transition::Fired)
        );
    }
}

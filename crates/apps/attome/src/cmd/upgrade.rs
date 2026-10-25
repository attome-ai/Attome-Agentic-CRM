//! `attome upgrade --plan <nodes.json>` (roadmap U8-T1): a rolling upgrade
//! with a canary that stops by itself when things get worse.
//!
//! The plan lists the nodes in order, each with where its metrics are read
//! (`/metrics`, Prometheus text) and the commands that upgrade it and roll
//! it back (run on this machine, so `ssh node attome service …` works the
//! same as a local command):
//!
//! ```json
//! { "watch_secs": 300, "max_error_rate_increase": 0.02, "max_latency_ratio": 1.5,
//!   "nodes": [ { "name": "app-1", "metrics_url": "http://app-1:9100/metrics",
//!                "upgrade": ["ssh", "app-1", "attome service upgrade 1.4.0"],
//!                "rollback": ["ssh", "app-1", "attome service upgrade 1.3.2"] } ] }
//! ```
//!
//! **How it decides** ([`run_plan`]): it first measures the fleet's error
//! rate (share of answers with a 5xx status) and mean latency over one
//! sampling period. Then, node by node, it upgrades the node and watches it
//! for `watch_secs` (the first node, the canary, and every node after it):
//! a node whose error rate rises more than `max_error_rate_increase` above
//! the baseline, or whose mean latency passes `max_latency_ratio` times the
//! baseline, is rolled back and the upgrade stops there, leaving the nodes
//! not yet reached on the old version. A node whose metrics cannot be read
//! counts as failing.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use serde::Deserialize;

const USAGE: &str = "usage: attome upgrade --plan <nodes.json>";
/// How long one sample of a node's counters spans.
pub const SAMPLE: Duration = Duration::from_secs(30);

/// One node of the plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Node {
    pub name: String,
    pub metrics_url: String,
    pub upgrade: Vec<String>,
    pub rollback: Vec<String>,
}

/// The plan file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Plan {
    #[serde(default = "default_watch_secs")]
    pub watch_secs: u64,
    #[serde(default = "default_error_increase")]
    pub max_error_rate_increase: f64,
    #[serde(default = "default_latency_ratio")]
    pub max_latency_ratio: f64,
    pub nodes: Vec<Node>,
}

fn default_watch_secs() -> u64 {
    300
}

fn default_error_increase() -> f64 {
    0.02
}

fn default_latency_ratio() -> f64 {
    1.5
}

/// A node's request counters at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counters {
    pub requests: f64,
    pub errors: f64,
    pub duration_sum: f64,
    pub duration_count: f64,
}

/// Error rate and mean latency over a period.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Health {
    pub error_rate: f64,
    pub mean_latency: f64,
    pub requests: f64,
}

fn label<'a>(labels: &'a str, name: &str) -> Option<&'a str> {
    labels.split(',').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim().trim_matches('"'))
    })
}

/// Sums the HTTP request counters of a Prometheus text exposition: any
/// `*http_requests_total` (5xx `status` as errors) and
/// `*http_requests_duration_seconds_sum`/`_count`. Pure.
pub fn counters(text: &str) -> Counters {
    let mut c = Counters::default();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(value) = value.trim().parse::<f64>() else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let (name, labels) = match series.split_once('{') {
            Some((n, rest)) => (n, rest.trim_end_matches('}')),
            None => (series, ""),
        };
        if name.ends_with("http_requests_total") {
            c.requests += value;
            if label(labels, "status").is_some_and(|s| s.starts_with('5')) {
                c.errors += value;
            }
        } else if name.ends_with("http_requests_duration_seconds_sum") {
            c.duration_sum += value;
        } else if name.ends_with("http_requests_duration_seconds_count") {
            c.duration_count += value;
        }
    }
    c
}

/// Health between two readings of the same node's counters (a restart in
/// between resets them: the later reading alone is then the period). Pure.
pub fn health(before: Counters, after: Counters) -> Health {
    let d = |a: f64, b: f64| if a >= b { a - b } else { a };
    let requests = d(after.requests, before.requests);
    let errors = d(after.errors, before.errors);
    let sum = d(after.duration_sum, before.duration_sum);
    let count = d(after.duration_count, before.duration_count);
    Health {
        error_rate: if requests > 0.0 {
            errors / requests
        } else {
            0.0
        },
        mean_latency: if count > 0.0 { sum / count } else { 0.0 },
        requests,
    }
}

/// The fleet's health over one period: totals of every node.
pub fn combine(parts: &[Health]) -> Health {
    let requests: f64 = parts.iter().map(|h| h.requests).sum();
    let errors: f64 = parts.iter().map(|h| h.error_rate * h.requests).sum();
    let weighted: f64 = parts.iter().map(|h| h.mean_latency * h.requests).sum();
    Health {
        error_rate: if requests > 0.0 {
            errors / requests
        } else {
            0.0
        },
        mean_latency: if requests > 0.0 {
            weighted / requests
        } else {
            0.0
        },
        requests,
    }
}

/// Whether a node watched after its upgrade is worse than the baseline
/// allows. Pure.
pub fn regressed(baseline: Health, observed: Health, plan: &Plan) -> Option<String> {
    if observed.error_rate > baseline.error_rate + plan.max_error_rate_increase {
        return Some(format!(
            "error rate {:.2}% against {:.2}% before",
            observed.error_rate * 100.0,
            baseline.error_rate * 100.0
        ));
    }
    if baseline.mean_latency > 0.0
        && observed.mean_latency > baseline.mean_latency * plan.max_latency_ratio
    {
        return Some(format!(
            "mean latency {:.0} ms against {:.0} ms before",
            observed.mean_latency * 1000.0,
            baseline.mean_latency * 1000.0
        ));
    }
    None
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the upgrade does to the outside world, so tests can fake it.
pub trait Fleet: Send + Sync {
    /// Reads a node's counters; `None` when they cannot be read.
    fn scrape<'a>(&'a self, node: &'a Node) -> Fut<'a, Option<Counters>>;
    /// Runs a command; `true` when it succeeded.
    fn run<'a>(&'a self, command: &'a [String]) -> Fut<'a, bool>;
    /// Waits (a real sleep, or nothing in a test).
    fn wait(&self, d: Duration) -> Fut<'_, ()>;
}

/// How a rolling upgrade ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Every node upgraded and stayed healthy.
    Done { upgraded: Vec<String> },
    /// A node got worse (or its upgrade command failed) and was rolled back.
    Stopped {
        upgraded: Vec<String>,
        rolled_back: String,
        reason: String,
    },
}

async fn period(fleet: &dyn Fleet, node: &Node) -> Option<Health> {
    let before = fleet.scrape(node).await?;
    fleet.wait(SAMPLE).await;
    let after = fleet.scrape(node).await?;
    Some(health(before, after))
}

/// Runs a plan against `fleet`.
pub async fn run_plan(plan: &Plan, fleet: &dyn Fleet) -> Outcome {
    let mut parts = Vec::new();
    for node in &plan.nodes {
        if let Some(h) = period(fleet, node).await {
            parts.push(h);
        }
    }
    let baseline = combine(&parts);
    let periods = (plan.watch_secs / SAMPLE.as_secs()).max(1);
    let mut upgraded = Vec::new();
    for node in &plan.nodes {
        let stop = |reason: String, upgraded: Vec<String>| Outcome::Stopped {
            upgraded,
            rolled_back: node.name.clone(),
            reason,
        };
        if !fleet.run(&node.upgrade).await {
            fleet.run(&node.rollback).await;
            return stop(
                format!("{}: the upgrade command failed", node.name),
                upgraded,
            );
        }
        let mut watched = Vec::new();
        for _ in 0..periods {
            match period(fleet, node).await {
                Some(h) => watched.push(h),
                None => {
                    fleet.run(&node.rollback).await;
                    return stop(
                        format!("{}: metrics could not be read", node.name),
                        upgraded,
                    );
                }
            }
            if let Some(reason) = regressed(baseline, combine(&watched), plan) {
                fleet.run(&node.rollback).await;
                return stop(format!("{}: {reason}", node.name), upgraded);
            }
        }
        upgraded.push(node.name.clone());
    }
    Outcome::Done { upgraded }
}

/// The real fleet: HTTP for metrics, local processes for commands.
struct Real {
    client: reqwest::Client,
}

impl Fleet for Real {
    fn scrape<'a>(&'a self, node: &'a Node) -> Fut<'a, Option<Counters>> {
        Box::pin(async move {
            let response = self.client.get(&node.metrics_url).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            Some(counters(&response.text().await.ok()?))
        })
    }

    fn run<'a>(&'a self, command: &'a [String]) -> Fut<'a, bool> {
        Box::pin(async move {
            let Some((program, args)) = command.split_first() else {
                return false;
            };
            println!("running: {}", command.join(" "));
            let mut child = tokio::process::Command::new(program);
            child.args(args);
            matches!(child.status().await, Ok(status) if status.success())
        })
    }

    fn wait(&self, d: Duration) -> Fut<'_, ()> {
        Box::pin(tokio::time::sleep(d))
    }
}

fn plan_from(args: &[String]) -> Result<Plan, String> {
    let path = match args {
        [flag, path] if flag == "--plan" => path,
        _ => return Err(USAGE.to_owned()),
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let plan: Plan = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    if plan.nodes.is_empty() {
        return Err("the plan lists no nodes".into());
    }
    if plan
        .nodes
        .iter()
        .any(|n| n.upgrade.is_empty() || n.rollback.is_empty())
    {
        return Err("every node needs an upgrade and a rollback command".into());
    }
    Ok(plan)
}

/// `attome upgrade`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let plan = match plan_from(args) {
        Ok(plan) => plan,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(2);
        }
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    match run_plan(&plan, &Real { client }).await {
        Outcome::Done { upgraded } => {
            println!("upgraded: {}", upgraded.join(", "));
            ExitCode::SUCCESS
        }
        Outcome::Stopped {
            upgraded,
            rolled_back,
            reason,
        } => {
            println!(
                "stopped: {reason}; rolled back {rolled_back}; upgraded before it: {}",
                if upgraded.is_empty() {
                    "none".to_owned()
                } else {
                    upgraded.join(", ")
                }
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Nodes that serve 100 requests per scrape, with a given error count and
    /// latency once upgraded.
    struct Fake {
        totals: Mutex<HashMap<String, Counters>>,
        upgraded: Mutex<Vec<String>>,
        log: Mutex<Vec<String>>,
        bad_after_upgrade: Option<String>,
    }

    impl Fake {
        fn new(nodes: &[&str], bad: Option<&str>) -> Self {
            Fake {
                totals: Mutex::new(
                    nodes
                        .iter()
                        .map(|n| ((*n).to_owned(), Counters::default()))
                        .collect(),
                ),
                upgraded: Mutex::new(Vec::new()),
                log: Mutex::new(Vec::new()),
                bad_after_upgrade: bad.map(str::to_owned),
            }
        }
    }

    impl Fleet for Fake {
        fn scrape<'a>(&'a self, node: &'a Node) -> Fut<'a, Option<Counters>> {
            Box::pin(async move {
                let bad = self.bad_after_upgrade.as_deref() == Some(node.name.as_str())
                    && self.upgraded.lock().unwrap().contains(&node.name);
                let mut totals = self.totals.lock().unwrap();
                let c = totals.get_mut(&node.name)?;
                c.requests += 100.0;
                c.errors += if bad { 20.0 } else { 1.0 };
                c.duration_count += 100.0;
                c.duration_sum += if bad { 30.0 } else { 10.0 };
                Some(*c)
            })
        }

        fn run<'a>(&'a self, command: &'a [String]) -> Fut<'a, bool> {
            Box::pin(async move {
                let line = command.join(" ");
                self.log.lock().unwrap().push(line.clone());
                if let Some(name) = line.strip_prefix("upgrade ") {
                    self.upgraded.lock().unwrap().push(name.to_owned());
                }
                if let Some(name) = line.strip_prefix("rollback ") {
                    self.upgraded.lock().unwrap().retain(|n| n != name);
                }
                true
            })
        }

        fn wait(&self, _d: Duration) -> Fut<'_, ()> {
            Box::pin(async {})
        }
    }

    fn plan(names: &[&str]) -> Plan {
        Plan {
            watch_secs: 90,
            max_error_rate_increase: 0.02,
            max_latency_ratio: 1.5,
            nodes: names
                .iter()
                .map(|n| Node {
                    name: (*n).to_owned(),
                    metrics_url: format!("http://{n}/metrics"),
                    upgrade: vec!["upgrade".into(), (*n).to_owned()],
                    rollback: vec!["rollback".into(), (*n).to_owned()],
                })
                .collect(),
        }
    }

    fn run<T>(f: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn rolling_upgrade_healthy_fleet_upgrades_every_node() {
        let fake = Fake::new(&["a", "b", "c"], None);
        let outcome = run(run_plan(&plan(&["a", "b", "c"]), &fake));
        assert_eq!(
            outcome,
            Outcome::Done {
                upgraded: vec!["a".into(), "b".into(), "c".into()]
            }
        );
        assert!(
            !fake
                .log
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("rollback"))
        );
    }

    #[test]
    fn rolling_upgrade_bad_canary_rolls_back_and_stops() {
        let fake = Fake::new(&["a", "b", "c"], Some("a"));
        let outcome = run(run_plan(&plan(&["a", "b", "c"]), &fake));
        let Outcome::Stopped {
            upgraded,
            rolled_back,
            reason,
        } = outcome
        else {
            panic!("the canary should have stopped the upgrade");
        };
        assert!(upgraded.is_empty());
        assert_eq!(rolled_back, "a");
        assert!(reason.contains("error rate"), "{reason}");
        let log = fake.log.lock().unwrap();
        assert_eq!(*log, vec!["upgrade a".to_owned(), "rollback a".to_owned()]);
    }

    #[test]
    fn rolling_upgrade_counters_and_health() {
        let text = "# TYPE axum_http_requests_total counter\n\
            axum_http_requests_total{method=\"GET\",endpoint=\"/x\",status=\"200\"} 90\n\
            axum_http_requests_total{method=\"GET\",endpoint=\"/x\",status=\"503\"} 10\n\
            axum_http_requests_duration_seconds_sum{method=\"GET\"} 5\n\
            axum_http_requests_duration_seconds_count{method=\"GET\"} 100\n";
        let c = counters(text);
        assert_eq!(c.requests, 100.0);
        assert_eq!(c.errors, 10.0);
        let h = health(Counters::default(), c);
        assert!((h.error_rate - 0.1).abs() < 1e-9);
        assert!((h.mean_latency - 0.05).abs() < 1e-9);
        // A restart resets the counters: the later reading is the period.
        let reset = health(
            Counters {
                requests: 500.0,
                ..Counters::default()
            },
            c,
        );
        assert_eq!(reset.requests, 100.0);
    }
}

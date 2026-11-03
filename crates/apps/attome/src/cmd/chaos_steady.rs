//! `attome drill chaos run ... --steady-url <url> --api-key <public:secret>`
//! (roadmap AB9-T3): the steady state around a fault.
//!
//! - **Load.** [`WORKERS`] workers read a list page of `--steady-entity`
//!   (`account` by default) over and over, through the API, as the key's
//!   holder; each request's status and time is kept per [`WINDOW`].
//! - **Before, during, after.** The run measures [`PHASE`] before the fault,
//!   the fault itself, and [`PHASE`] after it is undone: requests, error
//!   rate and p95 for each.
//! - **Automatic stop.** During the fault, a window whose error rate passes
//!   `--max-error-rate` (0.05) or whose p95 passes `--max-p95-ms` (2000)
//!   is a breach; three in a row ([`RollingWindows`]) stop the fault early,
//!   and the run reports `auto_stopped`.
//! - **Fail closed.** Every [`PROBE_EVERY`] during the fault, two creates
//!   with the same `Idempotency-Key` and different bodies are sent; the
//!   second must be refused (not 2xx), or idempotency failed open.
//! - **Audit chain.** With `--database-url`, the audit chain of every
//!   organisation in it is verified after the fault.
//!
//! The deployment under test is a rig, never production (the chaos command
//! refuses a production profile before anything starts).

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Concurrent load workers.
pub const WORKERS: usize = 10;
/// The length of one measuring window.
pub const WINDOW: Duration = Duration::from_secs(10);
/// How long the before and after phases measure.
pub const PHASE: Duration = Duration::from_secs(10);
/// How often the fail-closed probe runs during the fault.
pub const PROBE_EVERY: Duration = Duration::from_secs(5);
/// Consecutive breached windows that stop the fault.
pub const BREACHES_TO_STOP: u32 = 3;

/// The steady-state arguments, taken from the chaos command's.
#[derive(Debug, Clone, PartialEq)]
pub struct SteadyArgs {
    pub url: String,
    pub auth: String,
    pub entity: String,
    pub max_error_rate: f64,
    pub max_p95_ms: u64,
    pub database_url: Option<String>,
}

/// The steady-state arguments among `args`, when `--steady-url` is there;
/// the arguments it took out. Pure.
pub fn take_args(args: &[String]) -> Result<(Option<SteadyArgs>, Vec<String>), String> {
    let mut rest = Vec::new();
    let (mut url, mut key, mut entity) = (None, None, "account".to_owned());
    let (mut max_error_rate, mut max_p95_ms, mut database_url) = (0.05, 2000_u64, None);
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let takes = matches!(
            flag.as_str(),
            "--steady-url" | "--api-key" | "--steady-entity" | "--max-error-rate" | "--max-p95-ms"
        );
        if !takes {
            if flag == "--database-url" {
                database_url = iter.clone().next().cloned();
            }
            rest.push(flag.clone());
            continue;
        }
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--steady-url" => url = Some(value.trim_end_matches('/').to_owned()),
            "--api-key" => key = Some(value.clone()),
            "--steady-entity" => {
                if !value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    return Err("--steady-entity is an entity's logical name".into());
                }
                entity = value.clone();
            }
            "--max-error-rate" => {
                max_error_rate = value
                    .parse::<f64>()
                    .ok()
                    .filter(|r| (0.0..=1.0).contains(r))
                    .ok_or("--max-error-rate is 0 to 1")?;
            }
            _ => {
                max_p95_ms = value
                    .parse::<u64>()
                    .ok()
                    .filter(|ms| *ms > 0)
                    .ok_or("--max-p95-ms is a positive number of milliseconds")?;
            }
        }
    }
    let steady = match (url, key) {
        (Some(url), Some(key)) => Some(SteadyArgs {
            url,
            auth: format!("ApiKey {key}"),
            entity,
            max_error_rate,
            max_p95_ms,
            database_url,
        }),
        (None, None) => None,
        _ => return Err("--steady-url and --api-key go together".into()),
    };
    Ok((steady, rest))
}

/// One window's or phase's numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Stats {
    pub requests: usize,
    pub errors: usize,
    pub p95_ms: u64,
}

impl Stats {
    /// From `(ok, milliseconds)` samples. Pure.
    pub fn of(samples: &[(bool, u64)]) -> Stats {
        let mut times: Vec<u64> = samples.iter().map(|(_, ms)| *ms).collect();
        times.sort_unstable();
        let p95_ms = if times.is_empty() {
            0
        } else {
            let index = (times.len() * 95).div_ceil(100).saturating_sub(1);
            times.get(index).copied().unwrap_or(0)
        };
        Stats {
            requests: samples.len(),
            errors: samples.iter().filter(|(ok, _)| !ok).count(),
            p95_ms,
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.errors as f64 / self.requests as f64
        }
    }
}

/// Counts breached windows in a row. Pure.
#[derive(Debug, Clone, Default)]
pub struct RollingWindows {
    in_a_row: u32,
}

impl RollingWindows {
    /// Takes one window's numbers; whether the fault must stop now.
    pub fn observe(&mut self, window: Stats, max_error_rate: f64, max_p95_ms: u64) -> bool {
        let breached = window.error_rate() > max_error_rate || window.p95_ms > max_p95_ms;
        self.in_a_row = if breached { self.in_a_row + 1 } else { 0 };
        self.in_a_row >= BREACHES_TO_STOP
    }
}

type Samples = Arc<Mutex<Vec<(bool, u64)>>>;

/// The load: workers reading list pages until `stop` is set.
#[derive(Debug)]
pub struct Load {
    samples: Samples,
    stop: Arc<std::sync::atomic::AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Load {
    pub fn start(args: &SteadyArgs) -> Result<Load, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        let samples: Samples = Arc::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let url = format!("{}/api/v1/{}?page_size=10", args.url, args.entity);
        let tasks = (0..WORKERS)
            .map(|_| {
                let (http, url, auth) = (http.clone(), url.clone(), args.auth.clone());
                let (samples, stop) = (samples.clone(), stop.clone());
                tokio::spawn(async move {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let started = Instant::now();
                        let ok = http
                            .get(&url)
                            .header("Authorization", &auth)
                            .send()
                            .await
                            .is_ok_and(|r| r.status().is_success());
                        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        samples
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((ok, ms));
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
            })
            .collect();
        Ok(Load {
            samples,
            stop,
            tasks,
        })
    }

    /// The samples since the last take.
    pub fn take(&self) -> Vec<(bool, u64)> {
        std::mem::take(&mut *self.samples.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub async fn finish(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Watches the load while the fault is on, for `duration` or until Ctrl+C:
/// every window is checked against the limits (three breaches in a row
/// stop it), and the fail-closed probe runs every [`PROBE_EVERY`]. The
/// numbers, whether it stopped itself, and each probe's result.
pub async fn during(
    load: &Load,
    args: &SteadyArgs,
    duration: Duration,
) -> (Stats, bool, Vec<Result<bool, String>>) {
    let started = Instant::now();
    let mut windows = RollingWindows::default();
    let mut all = Vec::new();
    let mut probes = Vec::new();
    let mut next_window = started + WINDOW;
    let mut next_probe = started + PROBE_EVERY;
    while started.elapsed() < duration {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("interrupted: undoing the fault now");
                break;
            }
        }
        let now = Instant::now();
        if now >= next_probe {
            probes.push(idempotency_probe(args).await);
            next_probe = now + PROBE_EVERY;
        }
        if now >= next_window {
            let window = load.take();
            let stats = Stats::of(&window);
            all.extend(window);
            next_window = now + WINDOW;
            if windows.observe(stats, args.max_error_rate, args.max_p95_ms) {
                return (Stats::of(&all), true, probes);
            }
        }
    }
    all.extend(load.take());
    (Stats::of(&all), false, probes)
}

/// Prints one phase's numbers.
pub fn print_phase(name: &str, stats: Stats) {
    println!(
        "{name}: {} requests, error rate {:.3}, p95 {} ms",
        stats.requests,
        stats.error_rate(),
        stats.p95_ms
    );
}

/// Two creates with one idempotency key and different bodies; whether the
/// second was refused (fail closed).
pub async fn idempotency_probe(args: &SteadyArgs) -> Result<bool, String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/api/v1/{}", args.url, args.entity);
    let key = uuid::Uuid::now_v7().to_string();
    let send = |name: &str| {
        http.post(&url)
            .header("Authorization", &args.auth)
            .header("Idempotency-Key", &key)
            .json(&serde_json::json!({ "name": name }))
            .send()
    };
    let first = send("chaos probe a").await.map_err(|e| e.to_string())?;
    if !first.status().is_success() {
        return Err(format!(
            "the probe's first create answered {}",
            first.status()
        ));
    }
    let second = send("chaos probe b").await.map_err(|e| e.to_string())?;
    Ok(!second.status().is_success())
}

/// Every organisation's audit chain in the database at `url`; the ones that
/// do not verify.
pub async fn audit_chain_failures(url: &str) -> Result<Vec<String>, String> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .map_err(|e| e.to_string())?;
    let orgs: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT organization_ref FROM audit_header \
          WHERE organization_ref IS NOT NULL LIMIT 50",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| e.to_string())?;
    let mut failed = Vec::new();
    for org in orgs {
        match attome_audit::verify::verify_chain(&pool, None, org).await {
            Ok(report) if report.is_ok() => {}
            Ok(_) => failed.push(org.to_string()),
            Err(error) => failed.push(format!("{org}: {error}")),
        }
    }
    pool.close().await;
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_window_triggers_stop_after_three() {
        let mut windows = RollingWindows::default();
        let bad = Stats {
            requests: 100,
            errors: 10,
            p95_ms: 100,
        };
        let good = Stats {
            requests: 100,
            errors: 0,
            p95_ms: 100,
        };
        let slow = Stats {
            requests: 100,
            errors: 0,
            p95_ms: 5000,
        };
        assert!(!windows.observe(bad, 0.05, 2000));
        assert!(!windows.observe(bad, 0.05, 2000));
        assert!(
            !windows.observe(good, 0.05, 2000),
            "a good window resets the run"
        );
        assert!(!windows.observe(bad, 0.05, 2000));
        assert!(!windows.observe(slow, 0.05, 2000));
        assert!(
            windows.observe(bad, 0.05, 2000),
            "the third breach in a row stops"
        );
    }

    #[test]
    fn stats_and_arguments() {
        let samples: Vec<(bool, u64)> = (1..=100).map(|ms| (ms % 10 != 0, ms)).collect();
        let stats = Stats::of(&samples);
        assert_eq!((stats.requests, stats.errors, stats.p95_ms), (100, 10, 95));
        let args: Vec<String> = [
            "--fault",
            "redis-down",
            "--steady-url",
            "https://rig.example.com/",
            "--api-key",
            "pub:secret",
            "--database-url",
            "postgres://rig/attome",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let (steady, rest) = take_args(&args).unwrap();
        let steady = steady.unwrap();
        assert_eq!(steady.url, "https://rig.example.com");
        assert_eq!(steady.auth, "ApiKey pub:secret");
        assert_eq!(
            steady.database_url.as_deref(),
            Some("postgres://rig/attome")
        );
        assert_eq!(
            rest,
            [
                "--fault",
                "redis-down",
                "--database-url",
                "postgres://rig/attome"
            ]
        );
        assert!(take_args(&["--steady-url".to_owned(), "x".to_owned()]).is_err());
    }
}

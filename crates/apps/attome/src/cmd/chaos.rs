//! `attome drill chaos run` (roadmap AB9-T2): injects one fault of the AB9-T1
//! catalogue (`attome_release::chaos`) for a while and always undoes it,
//! through the platform's own handles (V2-D1628 (3)), not Docker:
//!
//! | Fault | Linux | Windows |
//! |---|---|---|
//! | `process-kill` | `systemctl kill -s KILL <--service>`, then start | `taskkill /F` on the service's process, then `sc.exe start` |
//! | `postgres-restart` | `systemctl restart <--pg-service>` | `net stop` then `net start` |
//! | `postgres-pause`, `redis-pause` | `systemctl kill -s STOP`, then `CONT` | refused: no pause |
//! | `redis-down`, `file-store-down` | `systemctl stop`, then `start` | `net stop`, then `net start` |
//! | `disk-fill` | `fallocate` a file in `--fill-dir`, then remove it | `fsutil file createnew`, then remove it |
//! | `cert-expired` | copy `--expired-cert` over `--cert-path`, then put the original back | same |
//! | `queue-flood` | 10,000 `ops_cluster_poll` jobs into `--database-url`'s queue | same |
//! | `network-delay` | `tc qdisc ... netem delay 300ms loss 2%` on `--iface`, only with `--allow-net-admin` | refused |
//! | `ai-slow`, `ai-failing` | a model server on `127.0.0.1:<--port>` that answers after 30 s, or 500 | same |
//! | `email-down` | nothing listens on `127.0.0.1:<--port>`: SMTP is refused | same |
//!
//! The AI and email faults need the target booted against those addresses
//! beforehand; `--fake-endpoints` prints the configuration lines and stops.
//!
//! **Always undone.** The undo steps run when the fault's time is up, on
//! Ctrl+C, and from a drop guard if anything returns early ([`UndoGuard`]).
//! A deployment whose `app.deployment_profile` is `production` is refused,
//! and so is a `--database-url` naming the deployment's own database.
//!
//! **Production game days** (AB9-T7). `--production --approval-id <id>` runs
//! against a production deployment only when `ops.chaos.production_game_days`
//! is on and `<id>` is an approved `POST /api/v1/ops/chaos/requests` for
//! this fault, at most its approved duration and `ops.chaos.max_duration_secs`;
//! the approval's execution is claimed first, so it allows one run.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;
use std::time::Duration;

use attome_release::chaos::{FaultKind, FaultSpec};

pub const EXIT_OK: u8 = 0;
pub const EXIT_USAGE: u8 = 1;
pub const EXIT_FAILED: u8 = 3;

/// Jobs a queue flood enqueues.
pub const FLOOD_JOBS: usize = 10_000;
/// The port the fake model and SMTP addresses use by default.
pub const DEFAULT_FAKE_PORT: u16 = 18_080;

/// The operating system the steps are written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Windows,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }
}

/// One step of a fault or its undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Run { program: String, args: Vec<String> },
    Copy { from: PathBuf, to: PathBuf },
    Remove { path: PathBuf },
}

fn run(program: &str, args: &[&str]) -> Step {
    Step::Run {
        program: program.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// What injecting a fault means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Steps { inject: Vec<Step>, undo: Vec<Step> },
    FakeModel { fail: bool },
    SmtpRefused,
    QueueFlood,
}

/// The parsed arguments of `chaos run`.
#[derive(Debug, Clone)]
pub struct ChaosArgs {
    pub fault: &'static FaultSpec,
    pub duration: Duration,
    pub service: Option<String>,
    pub pg_service: Option<String>,
    pub redis_service: Option<String>,
    pub store_service: Option<String>,
    pub fill_dir: Option<PathBuf>,
    pub fill_mb: u64,
    pub cert_path: Option<PathBuf>,
    pub expired_cert: Option<PathBuf>,
    pub iface: String,
    pub allow_net_admin: bool,
    pub database_url: Option<String>,
    pub port: u16,
    pub fake_endpoints: bool,
    /// AB9-T7: the run targets a production deployment on an approval.
    pub production: bool,
    pub approval_id: Option<uuid::Uuid>,
}

/// Parses the arguments after `chaos run`. Pure.
pub fn parse_args(args: &[String]) -> Result<ChaosArgs, String> {
    let mut fault = None;
    let mut parsed = ChaosArgs {
        fault: &attome_release::chaos::CATALOGUE[0],
        duration: Duration::ZERO,
        service: None,
        pg_service: None,
        redis_service: None,
        store_service: None,
        fill_dir: None,
        fill_mb: 1024,
        cert_path: None,
        expired_cert: None,
        iface: "eth0".to_owned(),
        allow_net_admin: false,
        database_url: None,
        port: DEFAULT_FAKE_PORT,
        fake_endpoints: false,
        production: false,
        approval_id: None,
    };
    let mut duration = None;
    let mut problems = Vec::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--allow-net-admin" => {
                parsed.allow_net_admin = true;
                continue;
            }
            "--fake-endpoints" => {
                parsed.fake_endpoints = true;
                continue;
            }
            "--production" => {
                parsed.production = true;
                continue;
            }
            _ => {}
        }
        let Some(value) = iter.next() else {
            problems.push(format!("{flag} needs a value"));
            break;
        };
        let name_ok = |v: &str| {
            !v.is_empty()
                && v.len() <= 64
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
        };
        match flag.as_str() {
            "--fault" => fault = attome_release::chaos::by_name(value),
            "--duration" => duration = value.parse::<u64>().ok().filter(|s| (1..=3600).contains(s)),
            "--service" | "--pg-service" | "--redis-service" | "--store-service"
                if !name_ok(value) =>
            {
                problems.push(format!(
                    "{flag} is a service name (letters, digits, - _ . @)"
                ));
            }
            "--service" => parsed.service = Some(value.clone()),
            "--pg-service" => parsed.pg_service = Some(value.clone()),
            "--redis-service" => parsed.redis_service = Some(value.clone()),
            "--store-service" => parsed.store_service = Some(value.clone()),
            "--fill-dir" => parsed.fill_dir = Some(PathBuf::from(value)),
            "--fill-mb" => match value.parse::<u64>() {
                Ok(mb) if (1..=1_048_576).contains(&mb) => parsed.fill_mb = mb,
                _ => problems.push("--fill-mb is 1 to 1048576".into()),
            },
            "--cert-path" => parsed.cert_path = Some(PathBuf::from(value)),
            "--expired-cert" => parsed.expired_cert = Some(PathBuf::from(value)),
            "--iface" if name_ok(value) => parsed.iface = value.clone(),
            "--iface" => problems.push("--iface is an interface name".into()),
            "--database-url" => parsed.database_url = Some(value.clone()),
            "--approval-id" => match uuid::Uuid::parse_str(value) {
                Ok(id) => parsed.approval_id = Some(id),
                Err(_) => problems.push("--approval-id is the chaos request's id".into()),
            },
            "--port" => match value.parse::<u16>() {
                Ok(port) if port >= 1024 => parsed.port = port,
                _ => problems.push("--port is 1024 to 65535".into()),
            },
            other => problems.push(format!("unknown argument {other}")),
        }
    }
    match fault {
        Some(spec) => parsed.fault = spec,
        None => problems.push("--fault names a catalogue fault".into()),
    }
    if parsed.production != parsed.approval_id.is_some() {
        problems.push("--production and --approval-id go together".into());
    }
    parsed.duration = Duration::from_secs(
        duration.unwrap_or_else(|| u64::from(parsed.fault.default_duration_secs)),
    );
    if problems.is_empty() {
        Ok(parsed)
    } else {
        Err(problems.join("; "))
    }
}

fn need<'a, T>(value: &'a Option<T>, flag: &str) -> Result<&'a T, String> {
    value
        .as_ref()
        .ok_or_else(|| format!("this fault needs {flag}"))
}

fn stop_start(os: Os, service: &str) -> (Vec<Step>, Vec<Step>) {
    match os {
        Os::Linux => (
            vec![run("systemctl", &["stop", service])],
            vec![run("systemctl", &["start", service])],
        ),
        Os::Windows => (
            vec![run("net", &["stop", service])],
            vec![run("net", &["start", service])],
        ),
    }
}

fn pause(os: Os, service: &str) -> Result<(Vec<Step>, Vec<Step>), String> {
    match os {
        Os::Linux => Ok((
            vec![run("systemctl", &["kill", "-s", "STOP", service])],
            vec![run("systemctl", &["kill", "-s", "CONT", service])],
        )),
        Os::Windows => {
            Err("Windows services cannot be paused; use redis-down or postgres-restart".into())
        }
    }
}

/// The steps of `args.fault` on `os`. Pure.
pub fn plan(args: &ChaosArgs, os: Os) -> Result<Plan, String> {
    let steps = |(inject, undo): (Vec<Step>, Vec<Step>)| Plan::Steps { inject, undo };
    match args.fault.kind {
        FaultKind::ProcessKill => {
            let service = need(&args.service, "--service")?;
            Ok(match os {
                Os::Linux => steps((
                    vec![run("systemctl", &["kill", "-s", "KILL", service])],
                    vec![run("systemctl", &["start", service])],
                )),
                Os::Windows => {
                    let filter = format!("SERVICES eq {service}");
                    steps((
                        vec![run("taskkill", &["/F", "/FI", &filter])],
                        vec![run("sc.exe", &["start", service])],
                    ))
                }
            })
        }
        FaultKind::PostgresRestart => {
            let service = need(&args.pg_service, "--pg-service")?;
            Ok(match os {
                Os::Linux => steps((vec![run("systemctl", &["restart", service])], vec![])),
                Os::Windows => steps((
                    vec![
                        run("net", &["stop", service]),
                        run("net", &["start", service]),
                    ],
                    vec![],
                )),
            })
        }
        FaultKind::PostgresPause => pause(os, need(&args.pg_service, "--pg-service")?).map(steps),
        FaultKind::RedisPause => {
            pause(os, need(&args.redis_service, "--redis-service")?).map(steps)
        }
        FaultKind::RedisDown => Ok(steps(stop_start(
            os,
            need(&args.redis_service, "--redis-service")?,
        ))),
        FaultKind::FileStoreDown => Ok(steps(stop_start(
            os,
            need(&args.store_service, "--store-service")?,
        ))),
        FaultKind::DiskFill => {
            let file = need(&args.fill_dir, "--fill-dir")?.join("attome-chaos.fill");
            let path = file.display().to_string();
            let inject = match os {
                Os::Linux => run("fallocate", &["-l", &format!("{}M", args.fill_mb), &path]),
                Os::Windows => run(
                    "fsutil",
                    &[
                        "file",
                        "createnew",
                        &path,
                        &(args.fill_mb * 1024 * 1024).to_string(),
                    ],
                ),
            };
            Ok(steps((vec![inject], vec![Step::Remove { path: file }])))
        }
        FaultKind::CertExpired => {
            let cert = need(&args.cert_path, "--cert-path")?.clone();
            let expired = need(&args.expired_cert, "--expired-cert")?.clone();
            let backup = cert.with_extension("attome-chaos.bak");
            Ok(steps((
                vec![
                    Step::Copy {
                        from: cert.clone(),
                        to: backup.clone(),
                    },
                    Step::Copy {
                        from: expired,
                        to: cert.clone(),
                    },
                ],
                vec![
                    Step::Copy {
                        from: backup.clone(),
                        to: cert,
                    },
                    Step::Remove { path: backup },
                ],
            )))
        }
        FaultKind::NetworkDelay => {
            if !args.allow_net_admin {
                return Err(
                    "network-delay changes the host's network; pass --allow-net-admin".into(),
                );
            }
            match os {
                Os::Linux => Ok(steps((
                    vec![run(
                        "tc",
                        &[
                            "qdisc",
                            "add",
                            "dev",
                            &args.iface,
                            "root",
                            "netem",
                            "delay",
                            "300ms",
                            "loss",
                            "2%",
                        ],
                    )],
                    vec![run("tc", &["qdisc", "del", "dev", &args.iface, "root"])],
                ))),
                Os::Windows => Err("network-delay needs Linux tc".into()),
            }
        }
        FaultKind::AiSlow => Ok(Plan::FakeModel { fail: false }),
        FaultKind::AiFailing => Ok(Plan::FakeModel { fail: true }),
        FaultKind::EmailDown => Ok(Plan::SmtpRefused),
        FaultKind::QueueFlood => {
            need(&args.database_url, "--database-url")?;
            Ok(Plan::QueueFlood)
        }
    }
}

/// Runs steps; a test records them instead.
pub trait Exec {
    fn exec(&mut self, step: &Step) -> Result<(), String>;
}

/// The real thing: the step's program, or the file operation.
#[derive(Debug)]
pub struct System;

impl Exec for System {
    fn exec(&mut self, step: &Step) -> Result<(), String> {
        match step {
            Step::Run { program, args } => {
                let status = std::process::Command::new(program)
                    .args(args)
                    .status()
                    .map_err(|e| format!("{program}: {e}"))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("{program} {} exited with {status}", args.join(" ")))
                }
            }
            Step::Copy { from, to } => std::fs::copy(from, to)
                .map(|_| ())
                .map_err(|e| format!("copy {} to {}: {e}", from.display(), to.display())),
            Step::Remove { path } => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("remove {}: {e}", path.display())),
            },
        }
    }
}

/// Holds a fault's undo steps and runs them exactly once: by [`finish`], or
/// when dropped (an early return, a panic unwinding).
///
/// [`finish`]: UndoGuard::finish
pub struct UndoGuard<'a, E: Exec> {
    exec: &'a mut E,
    undo: Vec<Step>,
    done: bool,
}

impl<E: Exec> std::fmt::Debug for UndoGuard<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndoGuard")
            .field("undo_steps", &self.undo.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<'a, E: Exec> UndoGuard<'a, E> {
    pub fn new(exec: &'a mut E, undo: Vec<Step>) -> Self {
        UndoGuard {
            exec,
            undo,
            done: false,
        }
    }

    /// Runs the undo steps; every failure, in order.
    pub fn finish(mut self) -> Vec<String> {
        self.undo_now()
    }

    fn undo_now(&mut self) -> Vec<String> {
        if self.done {
            return Vec::new();
        }
        self.done = true;
        let undo = std::mem::take(&mut self.undo);
        undo.iter()
            .filter_map(|step| self.exec.exec(step).err())
            .collect()
    }
}

impl<E: Exec> Drop for UndoGuard<'_, E> {
    fn drop(&mut self) {
        for error in self.undo_now() {
            tracing::error!(%error, "chaos: an undo step failed; undo it by hand");
        }
    }
}

/// Injects `inject` and returns the guard over `undo`; when a step fails,
/// what was injected is undone at once (the guard drops).
pub fn inject<'a, E: Exec>(
    exec: &'a mut E,
    inject: &[Step],
    undo: Vec<Step>,
) -> Result<UndoGuard<'a, E>, String> {
    let guard = UndoGuard::new(exec, undo);
    for step in inject {
        guard.exec.exec(step)?;
    }
    Ok(guard)
}

/// Why a run is refused before anything is touched: a production
/// deployment, or a queue flood aimed at the deployment's own database.
/// Pure.
pub fn refusal(args: &ChaosArgs, profile: &str, own_database: Option<&str>) -> Option<String> {
    match (profile == "production", args.production) {
        (true, false) => {
            return Some(
                "this deployment's profile is production; chaos runs on a test rig, or on an \
                 approved game day with --production --approval-id"
                    .into(),
            );
        }
        (false, true) => {
            return Some("--production is only for a production deployment".into());
        }
        _ => {}
    }
    match (args.database_url.as_deref(), own_database) {
        (Some(url), Some(own)) if url.contains(own) => Some(format!(
            "{own} is this deployment's own database; flood a copy"
        )),
        _ => None,
    }
}

/// The configuration lines a target needs for the AI and email faults.
/// Pure.
pub fn fake_endpoint_lines(port: u16) -> String {
    format!(
        "inference.generation.base_url = \"http://127.0.0.1:{port}/v1\"   # ai-slow, ai-failing\n\
         email.smtp_host = \"127.0.0.1\"\nemail.smtp_port = {port}   # email-down: nothing listens"
    )
}

/// Serves the fake model on `127.0.0.1:port` until `until` ends: every
/// request waits 30 s and answers an empty completion, or answers 500.
async fn fake_model(port: u16, fail: bool, until: impl std::future::Future<Output = ()>) -> u8 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("attome drill chaos: 127.0.0.1:{port}: {error}");
            return EXIT_FAILED;
        }
    };
    let serve = async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
                let reply = if fail {
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_owned()
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let body = r#"{"choices":[{"message":{"content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0}}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    };
    tokio::select! {
        _ = serve => {}
        _ = until => {}
    }
    EXIT_OK
}

/// Enqueues [`FLOOD_JOBS`] `ops_cluster_poll` jobs (a no-op without Patroni
/// addresses) into the queue at `url`.
async fn queue_flood(url: &str) -> Result<usize, String> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(url)
        .map_err(|e| format!("the database address does not read: {e}"))?;
    crate::jobs::register_job_types();
    let job = attome_core::jobs::JOB_TYPES
        .job(crate::jobs::OPS_CLUSTER_POLL.name, &())
        .map_err(|e| e.to_string())?;
    let mut sent = 0;
    for _ in 0..FLOOD_JOBS {
        attome_jobs::enqueue_on_pool(&pool, attome_core::jobs::EngineJob::Registered(job.clone()))
            .await
            .map_err(|e| format!("enqueue failed after {sent} jobs: {e}"))?;
        sent += 1;
    }
    pool.close().await;
    Ok(sent)
}

/// Waits `duration`, or until Ctrl+C.
async fn hold(duration: Duration) {
    tokio::select! {
        () = tokio::time::sleep(duration) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("interrupted: undoing the fault now");
        }
    }
}

/// AB9-T4: what one fault run found, as the checks of its evidence:
/// `fault_injected` and `fault_undone` always, and with the steady state
/// `auto_stopped` (passes when it did not trigger), `security_failed_closed`,
/// `error_rate_within_limit` and `p95_within_limit` (after the fault is
/// undone) and `audit_chain_ok`.
#[derive(Debug, Default)]
pub struct FaultOutcome {
    pub checks: Vec<attome_ops::evidence::Check>,
}

impl FaultOutcome {
    /// Records one check: passed, failed, or (`None`) not checked.
    pub fn record(&mut self, name: &str, result: Option<bool>, detail: impl Into<String>) {
        use attome_ops::evidence::{Check, CheckResult};
        let detail: String = detail.into();
        self.checks.push(Check {
            name: name.to_owned(),
            result: match result {
                Some(true) => CheckResult::Pass,
                Some(false) => CheckResult::Fail,
                None => CheckResult::Skipped,
            },
            detail: (!detail.is_empty()).then_some(detail),
        });
    }

    /// A check failed (one not checked is not a failure).
    pub fn failed(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.result == attome_ops::evidence::CheckResult::Fail)
    }
}

/// Injects the fault `plan` describes, holds it for its duration (watching
/// the steady state when `steady` is given), undoes it and answers what it
/// found. `Err` when the run could not start (the load did not start).
pub async fn run_plan(
    args: &ChaosArgs,
    steady: Option<&super::chaos_steady::SteadyArgs>,
    plan: Plan,
) -> Result<FaultOutcome, String> {
    use super::chaos_steady as steady_state;
    let spec = args.fault;
    println!(
        "{} for {} s. Expected: {}",
        spec.name,
        args.duration.as_secs(),
        spec.expected
    );
    let mut outcome = FaultOutcome::default();
    match plan {
        Plan::Steps {
            inject: steps,
            undo,
        } => {
            // AB9-T3: the load runs before, during and after the fault.
            let load = match steady.map(steady_state::Load::start) {
                Some(Ok(load)) => Some(load),
                Some(Err(error)) => return Err(format!("the load could not start: {error}")),
                None => None,
            };
            if let Some(load) = &load {
                tokio::time::sleep(steady_state::PHASE).await;
                steady_state::print_phase("before", steady_state::Stats::of(&load.take()));
            }
            let mut system = System;
            let guard = match inject(&mut system, &steps, undo) {
                Ok(guard) => guard,
                Err(error) => {
                    eprintln!(
                        "attome drill chaos: the fault was not injected ({error}); what was done is undone"
                    );
                    if let Some(load) = load {
                        load.finish().await;
                    }
                    outcome.record("fault_injected", Some(false), error);
                    return Ok(outcome);
                }
            };
            outcome.record("fault_injected", Some(true), "");
            match (&load, steady) {
                (Some(load), Some(steady)) => {
                    let (stats, auto_stopped, probes) =
                        steady_state::during(load, steady, args.duration).await;
                    steady_state::print_phase("during", stats);
                    if auto_stopped {
                        println!(
                            "auto_stopped: Fail (the limits were passed three windows in a row)"
                        );
                    }
                    outcome.record(
                        "auto_stopped",
                        Some(!auto_stopped),
                        if auto_stopped {
                            "the limits were passed three windows in a row"
                        } else {
                            ""
                        },
                    );
                    let mut refused = 0usize;
                    let mut accepted = 0usize;
                    for probe in &probes {
                        match probe {
                            Ok(true) => refused += 1,
                            Ok(false) => {
                                accepted += 1;
                                println!(
                                    "fail_closed: Fail (a reused idempotency key was accepted)"
                                );
                            }
                            Err(error) => println!("fail_closed: not checked ({error})"),
                        }
                    }
                    let verdict = match (accepted, refused) {
                        (0, 0) => None,
                        (0, _) => Some(true),
                        _ => Some(false),
                    };
                    outcome.record(
                        "security_failed_closed",
                        verdict,
                        format!("{refused} reused key(s) refused, {accepted} accepted"),
                    );
                }
                _ => hold(args.duration).await,
            }
            let failures = guard.finish();
            for failure in &failures {
                eprintln!("attome drill chaos: undo failed: {failure}. {}", spec.undo);
            }
            outcome.record(
                "fault_undone",
                Some(failures.is_empty()),
                failures.join("; "),
            );
            if let Some(load) = load {
                tokio::time::sleep(steady_state::PHASE).await;
                let after = steady_state::Stats::of(&load.take());
                steady_state::print_phase("after", after);
                load.finish().await;
                if let Some(steady) = steady {
                    let rate = after.error_rate();
                    outcome.record(
                        "error_rate_within_limit",
                        Some(rate <= steady.max_error_rate),
                        format!(
                            "{rate:.3} after the fault (limit {})",
                            steady.max_error_rate
                        ),
                    );
                    outcome.record(
                        "p95_within_limit",
                        Some(after.p95_ms <= steady.max_p95_ms),
                        format!(
                            "{} ms after the fault (limit {})",
                            after.p95_ms, steady.max_p95_ms
                        ),
                    );
                }
                if let Some(url) = steady.and_then(|s| s.database_url.as_deref()) {
                    match steady_state::audit_chain_failures(url).await {
                        Ok(failed) if failed.is_empty() => {
                            println!("audit_chain: Pass");
                            outcome.record("audit_chain_ok", Some(true), "");
                        }
                        Ok(failed) => {
                            println!("audit_chain: Fail ({})", failed.join(", "));
                            outcome.record("audit_chain_ok", Some(false), failed.join(", "));
                        }
                        Err(error) => {
                            println!("audit_chain: not checked ({error})");
                            outcome.record("audit_chain_ok", None, error);
                        }
                    }
                }
            }
            if failures.is_empty() {
                println!("undone");
            }
        }
        Plan::FakeModel { fail } => {
            println!(
                "serving the fake model on 127.0.0.1:{} (the target must already point at it)",
                args.port
            );
            let code = fake_model(args.port, fail, hold(args.duration)).await;
            outcome.record("fault_injected", Some(code == EXIT_OK), "");
            outcome.record("fault_undone", Some(true), "the fake model stopped");
        }
        Plan::SmtpRefused => {
            println!(
                "nothing listens on 127.0.0.1:{}; a target pointed at it cannot send email",
                args.port
            );
            hold(args.duration).await;
            outcome.record("fault_injected", Some(true), "");
            outcome.record("fault_undone", Some(true), "");
        }
        Plan::QueueFlood => {
            let url = args.database_url.clone().unwrap_or_default();
            match queue_flood(&url).await {
                Ok(sent) => {
                    println!("{sent} jobs queued; they drain on their own");
                    outcome.record("fault_injected", Some(true), format!("{sent} jobs queued"));
                }
                Err(error) => {
                    eprintln!("attome drill chaos: {error}");
                    outcome.record("fault_injected", Some(false), error);
                }
            }
            outcome.record("fault_undone", Some(true), "the jobs drain on their own");
        }
    }
    Ok(outcome)
}

/// `attome drill chaos run ...` and (AB9-T4) `attome drill chaos suite ...`.
#[tokio::main]
pub async fn run_cli(args: &[String]) -> u8 {
    match args {
        [first, rest @ ..] if first == "run" => run_one(rest).await,
        [first, rest @ ..] if first == "suite" => super::chaos_suite::run(rest).await,
        _ => {
            eprintln!(
                "attome drill chaos: usage: attome drill chaos run --fault <name> [--duration <s>] ..."
            );
            eprintln!(
                "                           attome drill chaos suite --key <file> --out <dir> ..."
            );
            EXIT_USAGE
        }
    }
}

/// `attome drill chaos run ...`: one fault.
async fn run_one(args: &[String]) -> u8 {
    // AB9-T3: the steady-state checks' own arguments.
    let (steady, args) = match super::chaos_steady::take_args(args) {
        Ok(split) => split,
        Err(message) => {
            eprintln!("attome drill chaos: {message}");
            return EXIT_USAGE;
        }
    };
    let args = match parse_args(&args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome drill chaos: {message}");
            return EXIT_USAGE;
        }
    };
    if args.fake_endpoints {
        println!("{}", fake_endpoint_lines(args.port));
        return EXIT_OK;
    }
    match attome_config::AppConfig::from_file() {
        Ok(config) => {
            let own = format!(
                "{}:{}/{}",
                config.database.host, config.database.port, config.database.dbname
            );
            if let Some(reason) = refusal(&args, &config.app.deployment_profile, Some(&own)) {
                eprintln!("attome drill chaos: {reason}");
                return EXIT_USAGE;
            }
            // AB9-T7: a production run claims its approved request first.
            if let (true, Some(approval)) = (args.production, args.approval_id) {
                let db = match attome_db::create_pool(&config).await {
                    Ok(db) => db,
                    Err(e) => {
                        eprintln!("attome drill chaos: the database could not be reached: {e}");
                        return EXIT_FAILED;
                    }
                };
                if let Err(reason) = attome_ops::chaos_requests::claim_for_run(
                    &db,
                    &config.ops.chaos,
                    approval,
                    args.fault.name,
                    args.duration.as_secs(),
                )
                .await
                {
                    eprintln!("attome drill chaos: {reason}");
                    return EXIT_USAGE;
                }
                println!("production game day: chaos request {approval} approved and claimed");
            }
        }
        Err(_) => {
            if let Some(reason) = refusal(&args, "", None) {
                eprintln!("attome drill chaos: {reason}");
                return EXIT_USAGE;
            }
        }
    }
    let plan = match plan(&args, Os::current()) {
        Ok(plan) => plan,
        Err(message) => {
            eprintln!("attome drill chaos: {message}");
            return EXIT_USAGE;
        }
    };
    match run_plan(&args, steady.as_ref(), plan).await {
        Ok(outcome) if outcome.failed() => EXIT_FAILED,
        Ok(_) => EXIT_OK,
        Err(message) => {
            eprintln!("attome drill chaos: {message}");
            EXIT_USAGE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        done: Vec<Step>,
        fail_on: Option<usize>,
    }

    impl Exec for Recorder {
        fn exec(&mut self, step: &Step) -> Result<(), String> {
            if self.fail_on == Some(self.done.len()) {
                self.done.push(step.clone());
                return Err("refused".into());
            }
            self.done.push(step.clone());
            Ok(())
        }
    }

    fn args(list: &[&str]) -> ChaosArgs {
        parse_args(&list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap()
    }

    fn early_return(recorder: &mut Recorder) -> Result<(), String> {
        let plan = plan(
            &args(&["--fault", "redis-down", "--redis-service", "redis"]),
            Os::Linux,
        )?;
        let Plan::Steps {
            inject: steps,
            undo,
        } = plan
        else {
            return Err("not steps".into());
        };
        let _guard = inject(recorder, &steps, undo)?;
        Err("something went wrong while the fault was on".into())
    }

    #[test]
    fn undo_runs_on_early_return() {
        let mut recorder = Recorder::default();
        assert!(early_return(&mut recorder).is_err());
        assert_eq!(
            recorder.done,
            vec![
                run("systemctl", &["stop", "redis"]),
                run("systemctl", &["start", "redis"]),
            ],
            "the stop was undone by the guard"
        );

        // A failing inject step undoes what came before it.
        let mut recorder = Recorder {
            fail_on: Some(1),
            ..Recorder::default()
        };
        let cert = args(&[
            "--fault",
            "cert-expired",
            "--cert-path",
            "/etc/attome/tls.pem",
            "--expired-cert",
            "/tmp/expired.pem",
        ]);
        let Ok(Plan::Steps {
            inject: steps,
            undo,
        }) = plan(&cert, Os::Linux)
        else {
            panic!("cert-expired is steps");
        };
        assert!(inject(&mut recorder, &steps, undo).is_err());
        assert_eq!(
            recorder.done.len(),
            4,
            "two inject steps tried, then both undo steps"
        );
    }

    #[test]
    fn production_and_own_database_are_refused() {
        let flood = args(&[
            "--fault",
            "queue-flood",
            "--database-url",
            "postgres://u@db:5432/attome",
        ]);
        assert!(refusal(&flood, "production", None).is_some());
        assert!(refusal(&flood, "team", Some("db:5432/attome")).is_some());
        assert!(refusal(&flood, "team", Some("db:5432/other")).is_none());
    }

    #[test]
    fn production_needs_an_approval_id() {
        let id = "0190a8b4-0000-7000-8000-000000000001";
        let game_day = args(&["--fault", "redis-down", "--production", "--approval-id", id]);
        // Past the profile check; the approval itself is checked and
        // claimed against the database (`claim_for_run`).
        assert!(refusal(&game_day, "production", None).is_none());
        assert!(refusal(&game_day, "team", None).is_some());
        let to_strings = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(parse_args(&to_strings(&["--fault", "redis-down", "--production"])).is_err());
        assert!(parse_args(&to_strings(&["--fault", "redis-down", "--approval-id", id])).is_err());
        assert!(
            parse_args(&to_strings(&[
                "--fault",
                "redis-down",
                "--production",
                "--approval-id",
                "x"
            ]))
            .is_err()
        );
    }

    #[test]
    fn faults_need_their_targets_and_os() {
        assert!(plan(&args(&["--fault", "process-kill"]), Os::Linux).is_err());
        assert!(
            plan(
                &args(&["--fault", "redis-pause", "--redis-service", "redis"]),
                Os::Windows
            )
            .is_err()
        );
        assert!(plan(&args(&["--fault", "network-delay"]), Os::Linux).is_err());
        assert!(
            plan(
                &args(&["--fault", "network-delay", "--allow-net-admin"]),
                Os::Linux
            )
            .is_ok()
        );
        assert!(
            parse_args(&[
                "--fault".to_owned(),
                "process-kill".to_owned(),
                "--service".to_owned(),
                "x; rm -rf /".to_owned()
            ])
            .is_err()
        );
        let windows = plan(
            &args(&["--fault", "process-kill", "--service", "attome"]),
            Os::Windows,
        )
        .unwrap();
        assert_eq!(
            windows,
            Plan::Steps {
                inject: vec![run("taskkill", &["/F", "/FI", "SERVICES eq attome"])],
                undo: vec![run("sc.exe", &["start", "attome"])],
            }
        );
        let slow = args(&["--fault", "ai-slow"]);
        assert_eq!(
            slow.duration.as_secs(),
            u64::from(slow.fault.default_duration_secs)
        );
    }
}

//! AB4-T8 (V2-D1935): `attome drill agent`, the long-running mode of the
//! drill host. It asks the deployment which drills are due, checks the host is
//! ready, runs each due drill and uploads the signed evidence.
//!
//! ```text
//! attome drill agent --deployment-url <url> --api-key-file <file> --config <drill-agent.json> [--once]
//! ```
//!
//! Every 10 minutes (once with `--once`):
//!
//! 1. `GET /api/v1/ops/drills/due` (a key holding `ops.drill.run`).
//! 2. For a non-empty answer, `attome drill readiness` on the host. When it
//!    fails, a signed `Restore` evidence with the check `readiness` failed and
//!    `overall_ok` false is uploaded, so the failure is visible on the
//!    deployment, and nothing else runs.
//! 3. Otherwise each due kind runs as `attome drill <kind> ...` with the
//!    parameters of the configuration file, and its signed evidence is
//!    uploaded to `POST /api/v1/ops/drills/evidence`, retried five times
//!    with growing waits. A kind the agent has no parameters for is reported
//!    and left due.
//!
//! The configuration file is JSON (the CLI carries no TOML reader; V2-D1935):
//!
//! ```json
//! { "signing_key": "drill-signing.key", "out": "evidence",
//!   "restore": { "server_binary": "/opt/attome/attome", "expected_digest": "<sha256>",
//!                "api_key_file": "restore-read.key", "archive": "latest", "port": 7999,
//!                "config": "/etc/attome/config.json" } }
//! ```
//!
//! It names files, never a key's contents. Run the agent on a drill host,
//! never on a production node (`deploy/drill-host/README.md`).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use attome_ops::evidence::{
    self, Check, CheckResult, Evidence, EvidenceKind, SCHEMA, SignedEvidence,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::cmd::output::{take_flag, take_value};

const USAGE: &str = "usage: attome drill agent --deployment-url <url> --api-key-file <file> --config <drill-agent.json> [--once]";

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_FAILED: u8 = 3;
const EXIT_NOT_READY: u8 = 4;

/// How often the agent asks.
pub const POLL_INTERVAL: Duration = Duration::from_secs(600);
/// How many times an upload is tried.
pub const UPLOAD_ATTEMPTS: u32 = 5;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What `drill agent` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentArgs {
    pub deployment_url: String,
    pub api_key_file: PathBuf,
    pub config: PathBuf,
    pub once: bool,
}

/// Parses the arguments after `drill agent`. Pure.
pub fn parse_args(args: &[String]) -> Result<AgentArgs, String> {
    let mut args = args.to_vec();
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required"));
    let deployment_url = need(
        take_value(&mut args, "--deployment-url")?,
        "--deployment-url",
    )?;
    let api_key_file = need(take_value(&mut args, "--api-key-file")?, "--api-key-file")?;
    let config = need(take_value(&mut args, "--config")?, "--config")?;
    let once = take_flag(&mut args, "--once");
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    Ok(AgentArgs {
        deployment_url: deployment_url.trim_end_matches('/').to_owned(),
        api_key_file: PathBuf::from(api_key_file),
        config: PathBuf::from(config),
        once,
    })
}

/// The parameters of the restore drill.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RestoreParams {
    pub server_binary: String,
    pub expected_digest: String,
    pub api_key_file: String,
    #[serde(default = "latest")]
    pub archive: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub config: Option<String>,
}

fn latest() -> String {
    "latest".to_owned()
}

fn default_port() -> u16 {
    crate::cmd::drill_restore::DEFAULT_PORT
}

/// The agent's configuration file.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub signing_key: String,
    pub out: String,
    #[serde(default)]
    pub restore: Option<RestoreParams>,
}

/// Parses the configuration file's text. Pure.
pub fn parse_config(text: &str) -> Result<AgentConfig, String> {
    let config: AgentConfig =
        serde_json::from_str(text).map_err(|e| format!("the configuration file: {e}"))?;
    if config.signing_key.trim().is_empty() || config.out.trim().is_empty() {
        return Err("the configuration file needs signing_key and out".into());
    }
    Ok(config)
}

/// The kinds of a due list's items. Pure.
pub fn due_kinds(body: &Value) -> Vec<String> {
    body["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["kind"].as_str().map(str::to_owned))
        .collect()
}

/// The wait before upload attempt `attempt` (1-based): 2, 4, 8, 16 seconds.
/// Pure.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.clamp(1, 5))
}

/// The `drill restore` arguments for `params`, the signing key and the out
/// directory. Pure.
pub fn restore_args(params: &RestoreParams, key: &str, out: &str) -> Vec<String> {
    let mut args = vec![
        "drill".to_owned(),
        "restore".to_owned(),
        "--server-binary".to_owned(),
        params.server_binary.clone(),
        "--expected-digest".to_owned(),
        params.expected_digest.clone(),
        "--api-key-file".to_owned(),
        params.api_key_file.clone(),
        "--key".to_owned(),
        key.to_owned(),
        "--out".to_owned(),
        out.to_owned(),
        "--archive".to_owned(),
        params.archive.clone(),
        "--port".to_owned(),
        params.port.to_string(),
    ];
    if let Some(config) = &params.config {
        args.push("--config".to_owned());
        args.push(config.clone());
    }
    args
}

/// The evidence a failed readiness leaves: a `Restore` run whose only check,
/// `readiness`, failed. Pure.
pub fn readiness_failure(detail: &str, now: chrono::DateTime<Utc>) -> Evidence {
    let mut report = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Restore,
        drill_id: Uuid::now_v7(),
        started_at: now,
        finished_at: now,
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        image_digest: None,
        deployment_id: None,
        checks: vec![Check {
            name: "readiness".to_owned(),
            result: CheckResult::Fail,
            detail: Some(detail.to_owned()),
        }],
        rpo_seconds: None,
        rto_seconds: None,
        data_size_bytes: None,
        restore_ok: false,
        provenance_ok: false,
        overall_ok: false,
        extra: Map::new(),
    };
    report.compute_overall();
    report
}

/// What the agent runs on the host: the readiness check and a drill.
pub trait DrillRunner: Send + Sync {
    /// `Ok` when the host is ready; else what failed (lines naming checks,
    /// never a secret).
    fn readiness(&self) -> BoxFut<'_, Result<(), String>>;
    /// Runs the drill of `kind`; the signed evidence file it wrote.
    fn run<'a>(&'a self, kind: &'a str) -> BoxFut<'a, Result<PathBuf, String>>;
}

/// The runner that starts this same binary as a child process.
pub struct ChildRunner {
    config: AgentConfig,
    config_path: PathBuf,
}

impl ChildRunner {
    async fn child(&self, args: &[String]) -> Result<std::process::Output, String> {
        let exe = std::env::current_exe().map_err(|e| format!("find this program: {e}"))?;
        tokio::process::Command::new(exe)
            .args(args)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| format!("start a drill: {e}"))
    }
}

impl DrillRunner for ChildRunner {
    fn readiness(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move {
            let mut args = vec!["drill".to_owned(), "readiness".to_owned()];
            if let Some(restore) = &self.config.restore
                && let Some(config) = &restore.config
            {
                args.push("--config".to_owned());
                args.push(config.clone());
            }
            let output = self.child(&args).await?;
            if output.status.success() {
                return Ok(());
            }
            let failed: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| l.starts_with("FAIL"))
                .map(str::to_owned)
                .collect();
            Err(if failed.is_empty() {
                format!("drill readiness exited with {}", output.status)
            } else {
                failed.join("; ")
            })
        })
    }

    fn run<'a>(&'a self, kind: &'a str) -> BoxFut<'a, Result<PathBuf, String>> {
        Box::pin(async move {
            let out = Path::new(&self.config.out);
            std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
            match kind {
                "restore" => {
                    let params = self
                        .config
                        .restore
                        .as_ref()
                        .ok_or("no restore parameters in the configuration file")?;
                    let file = out.join(crate::cmd::drill_restore::evidence_file_name(
                        Utc::now().date_naive(),
                    ));
                    // A file of an earlier run must not be uploaded as this one's.
                    let _ = std::fs::remove_file(&file);
                    let key = resolve(&self.config_path, &self.config.signing_key);
                    let args = restore_args(params, &key, &self.config.out);
                    // Exit 3 still wrote evidence (a check failed); only a
                    // missing file is a failure to run.
                    let _ = self.child(&args).await?;
                    if file.exists() {
                        Ok(file)
                    } else {
                        Err("the restore drill wrote no evidence".into())
                    }
                }
                other => Err(format!("the agent does not run `{other}` drills yet")),
            }
        })
    }
}

/// `value` as a path next to the configuration file when it is relative.
fn resolve(config_path: &Path, value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        return value.to_owned();
    }
    config_path
        .parent()
        .map_or_else(|| path.to_path_buf(), |dir| dir.join(path))
        .display()
        .to_string()
}

fn client(base: &str) -> Result<reqwest::Client, String> {
    attome_outbound::http::client(
        attome_outbound::http::Purpose::public("drill_agent").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(30)),
    )
    .map_err(|e| e.to_string())
}

async fn fetch_due(base: &str, key: &str) -> Result<Vec<String>, String> {
    let response = client(base)?
        .get(format!("{base}/api/v1/ops/drills/due"))
        .header("authorization", format!("ApiKey {key}"))
        .send()
        .await
        .map_err(|e| format!("the deployment did not answer: {e}"))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!("the due list answered {status}"));
    }
    let body: Value = response.json().await.map_err(|e| e.to_string())?;
    Ok(due_kinds(&body))
}

/// Uploads `signed`, trying [`UPLOAD_ATTEMPTS`] times with growing waits
/// (`wait` is injectable so a test need not sleep).
async fn upload(
    base: &str,
    key: &str,
    signed: &SignedEvidence,
    wait: impl Fn(Duration) -> BoxFut<'static, ()>,
) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 1..=UPLOAD_ATTEMPTS {
        match crate::cmd::upgrade_rehearse::store_evidence(base, key, signed).await {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        if attempt < UPLOAD_ATTEMPTS {
            wait(backoff(attempt)).await;
        }
    }
    Err(format!("after {UPLOAD_ATTEMPTS} tries: {last}"))
}

/// What one poll did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollOutcome {
    pub due: usize,
    pub uploaded: usize,
    pub readiness_failed: bool,
    pub failures: Vec<String>,
}

/// One poll: due drills, readiness, the drills, the uploads.
pub async fn poll_once(
    args: &AgentArgs,
    api_key: &str,
    config: &AgentConfig,
    key: &evidence::SigningKey,
    runner: &dyn DrillRunner,
    wait: impl Fn(Duration) -> BoxFut<'static, ()> + Copy,
) -> Result<PollOutcome, String> {
    let kinds = fetch_due(&args.deployment_url, api_key).await?;
    let mut outcome = PollOutcome {
        due: kinds.len(),
        ..PollOutcome::default()
    };
    if kinds.is_empty() {
        return Ok(outcome);
    }
    if let Err(detail) = runner.readiness().await {
        outcome.readiness_failed = true;
        let report = readiness_failure(&detail, Utc::now());
        let signed = evidence::sign(&report, key).map_err(|e| e.to_string())?;
        // Kept beside the other evidence too.
        let _ = std::fs::create_dir_all(&config.out);
        let path = Path::new(&config.out).join(format!(
            "readiness-failure-{}.json",
            Utc::now().format("%Y%m%d%H%M%S")
        ));
        let _ = evidence::write_signed(&path, &report, key);
        match upload(&args.deployment_url, api_key, &signed, wait).await {
            Ok(()) => outcome.uploaded += 1,
            Err(e) => outcome.failures.push(format!("readiness evidence: {e}")),
        }
        return Ok(outcome);
    }
    for kind in kinds {
        let file = match runner.run(&kind).await {
            Ok(file) => file,
            Err(e) => {
                outcome.failures.push(format!("{kind}: {e}"));
                continue;
            }
        };
        let signed = match evidence::read_signed(&file) {
            Ok(signed) => signed,
            Err(e) => {
                outcome
                    .failures
                    .push(format!("{kind}: {}: {e}", file.display()));
                continue;
            }
        };
        match upload(&args.deployment_url, api_key, &signed, wait).await {
            Ok(()) => outcome.uploaded += 1,
            Err(e) => outcome.failures.push(format!("{kind}: {e}")),
        }
    }
    Ok(outcome)
}

fn sleep(d: Duration) -> BoxFut<'static, ()> {
    Box::pin(tokio::time::sleep(d))
}

/// `attome drill agent ...`.
#[tokio::main]
pub async fn run(args: &[String]) -> u8 {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome drill agent: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let config = match std::fs::read_to_string(&args.config)
        .map_err(|e| format!("{}: {e}", args.config.display()))
        .and_then(|text| parse_config(&text))
    {
        Ok(config) => config,
        Err(e) => {
            eprintln!("attome drill agent: {e}");
            return EXIT_USAGE;
        }
    };
    let key_path = PathBuf::from(resolve(&args.config, &config.signing_key));
    let key = match evidence::read_signing_key(&key_path) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("attome drill agent: {}: {e}", key_path.display());
            return EXIT_USAGE;
        }
    };
    let api_key = match std::fs::read_to_string(&args.api_key_file) {
        Ok(text) if !text.trim().is_empty() => text.trim().to_owned(),
        _ => {
            eprintln!(
                "attome drill agent: {} is missing or empty",
                args.api_key_file.display()
            );
            return EXIT_USAGE;
        }
    };
    let runner = ChildRunner {
        config: config.clone(),
        config_path: args.config.clone(),
    };
    let mut last_exit = EXIT_OK;
    loop {
        match poll_once(&args, &api_key, &config, &key, &runner, sleep).await {
            Ok(outcome) => {
                println!(
                    "{} due, {} uploaded{}",
                    outcome.due,
                    outcome.uploaded,
                    if outcome.readiness_failed {
                        ", readiness failed"
                    } else {
                        ""
                    }
                );
                for failure in &outcome.failures {
                    eprintln!("attome drill agent: {failure}");
                }
                last_exit = if outcome.readiness_failed {
                    EXIT_NOT_READY
                } else if outcome.failures.is_empty() {
                    EXIT_OK
                } else {
                    EXIT_FAILED
                };
            }
            Err(e) => {
                eprintln!("attome drill agent: {e}");
                last_exit = EXIT_FAILED;
            }
        }
        if args.once {
            return last_exit;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct FailingReadiness;

    impl DrillRunner for FailingReadiness {
        fn readiness(&self) -> BoxFut<'_, Result<(), String>> {
            Box::pin(async { Err("FAIL backup.recent  no backup in 3 days".to_owned()) })
        }
        fn run<'a>(&'a self, _kind: &'a str) -> BoxFut<'a, Result<PathBuf, String>> {
            Box::pin(async { panic!("no drill runs when readiness fails") })
        }
    }

    fn no_wait(_: Duration) -> BoxFut<'static, ()> {
        Box::pin(async {})
    }

    #[tokio::test]
    async fn agent_uploads_failed_readiness_evidence() {
        use axum::{Json, Router, routing::get, routing::post};
        let uploads: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = uploads.clone();
        let app = Router::new()
            .route(
                "/api/v1/ops/drills/due",
                get(|| async {
                    Json(serde_json::json!({
                        "items": [{ "kind": "restore" }], "total": 1, "page": 1, "page_size": 50
                    }))
                }),
            )
            .route(
                "/api/v1/ops/drills/evidence",
                post(move |Json(body): Json<Value>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(body);
                        Json(serde_json::json!({ "id": Uuid::now_v7() }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = std::env::temp_dir().join(format!("attome-agent-{}", Uuid::now_v7()));
        let args = AgentArgs {
            deployment_url: format!("http://{addr}"),
            api_key_file: PathBuf::from("unused"),
            config: dir.join("drill-agent.json"),
            once: true,
        };
        let config = AgentConfig {
            signing_key: "unused".into(),
            out: dir.display().to_string(),
            restore: None,
        };
        let key = evidence::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let outcome = poll_once(&args, "k", &config, &key, &FailingReadiness, no_wait)
            .await
            .unwrap();
        assert!(outcome.readiness_failed);
        assert_eq!((outcome.due, outcome.uploaded), (1, 1));
        let got = uploads.lock().unwrap();
        assert_eq!(got.len(), 1);
        let report = &got[0]["evidence"];
        assert_eq!(report["kind"], "restore");
        assert_eq!(report["overall_ok"], false);
        assert_eq!(report["checks"][0]["name"], "readiness");
        assert_eq!(report["checks"][0]["result"], "fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn arguments_configuration_and_backoff() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let ok = parse_args(&words(
            "--deployment-url http://h/ --api-key-file k --config c.json --once",
        ))
        .unwrap();
        assert!(ok.once);
        assert_eq!(ok.deployment_url, "http://h");
        assert!(parse_args(&words("--deployment-url http://h --api-key-file k")).is_err());

        let config = parse_config(
            r#"{"signing_key":"k","out":"o","restore":{"server_binary":"b","expected_digest":"d","api_key_file":"a"}}"#,
        )
        .unwrap();
        let restore = config.restore.unwrap();
        assert_eq!((restore.archive.as_str(), restore.port), ("latest", 7999));
        assert!(parse_config(r#"{"signing_key":"","out":"o"}"#).is_err());
        assert!(
            restore_args(&restore, "k", "o")
                .windows(2)
                .any(|w| w == ["--archive", "latest"])
        );

        assert_eq!(
            due_kinds(
                &serde_json::json!({ "items": [{ "kind": "restore" }, { "kind": "failover" }] })
            ),
            vec!["restore".to_owned(), "failover".to_owned()]
        );
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(4), Duration::from_secs(16));
        assert_eq!(backoff(9), Duration::from_secs(32));
    }
}

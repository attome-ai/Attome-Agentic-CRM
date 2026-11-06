//! AB4-T4 (V2-D1927): `attome drill restore`, part 1 of the restore drill,
//! on v2's daily `pg_dump` archive (U6-T1) rather than pgBackRest (V2-D1387).
//!
//! ```text
//! attome drill restore --server-binary <path> --expected-digest <sha256>
//!                      --api-key-file <path> --key <signing key> --out <dir>
//!                      [--archive latest|<name>] [--port 7999] [--config <path>]
//! ```
//!
//! 1. Restores the archive into a throwaway database on the deployment's own
//!    PostgreSQL server (U6-T3's `restore_into`), timed: the database's
//!    recovery time.
//! 2. RPO: the newest audit row of the restored copy against the live
//!    deployment's newest one: the writes a restore now would lose.
//! 3. Provenance: the SHA-256 of `--server-binary` against
//!    `--expected-digest`.
//! 4. Boots that binary (`serve`) against the copy on `--port` with a
//!    throwaway configuration: the deployment's own file (placeholders kept,
//!    so no secret is written) with the database name and port replaced, the
//!    cache in process memory (no shared Redis), no inline job worker or
//!    scheduler, no email and no backup. So the copy sends nothing and
//!    touches no live cache. Waits up to 300 s for `/health/ready`: the
//!    application's recovery time.
//! 5. `verify-audit-chain` against the copy.
//! 6. With the drill's API key (a read-only key of the live deployment,
//!    restored with it), reads a first page of the first five entities.
//! 7. Stops the server, deletes the throwaway configuration and drops the
//!    database, checking it is gone (`scratch_destroyed`).
//! 8. Writes signed `Restore` evidence (`attome-evidence/v1`) into `--out`.
//!
//! The evidence names checks, counts and times only, never record contents.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use attome_ops::evidence::{self, Check, CheckResult, Evidence, EvidenceKind, SCHEMA};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome drill restore --server-binary <path> --expected-digest <sha256> --api-key-file <path> --key <signing key> --out <dir> [--archive latest|<name>] [--port 7999] [--config <path>]";

/// The port the drill's server listens on unless `--port` says otherwise.
pub const DEFAULT_PORT: u16 = 7999;
/// How long the restored server has to answer ready.
const READY_WAIT: Duration = Duration::from_secs(300);
/// How many entities the sample reads cover.
const SAMPLE_ENTITIES: usize = 5;

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_FAILED: u8 = 3;

/// What `attome drill restore` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreArgs {
    pub archive: String,
    pub server_binary: PathBuf,
    pub expected_digest: String,
    pub api_key_file: PathBuf,
    pub key: PathBuf,
    pub out: PathBuf,
    pub port: u16,
    pub config: Option<String>,
}

/// Parses the arguments after `drill restore`. Pure.
pub fn parse_args(args: &[String]) -> Result<RestoreArgs, String> {
    let mut args = args.to_vec();
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required"));
    let server_binary = need(take_value(&mut args, "--server-binary")?, "--server-binary")?;
    let expected_digest = need(
        take_value(&mut args, "--expected-digest")?,
        "--expected-digest",
    )?;
    let api_key_file = need(take_value(&mut args, "--api-key-file")?, "--api-key-file")?;
    let key = need(take_value(&mut args, "--key")?, "--key")?;
    let out = need(take_value(&mut args, "--out")?, "--out")?;
    let archive = take_value(&mut args, "--archive")?.unwrap_or_else(|| "latest".to_owned());
    let port = take_value(&mut args, "--port")?
        .map(|p| p.parse::<u16>().map_err(|_| format!("--port: `{p}`")))
        .transpose()?
        .unwrap_or(DEFAULT_PORT);
    if port == 0 {
        return Err("--port must be above 0".into());
    }
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    if !is_sha256_hex(&expected_digest) {
        return Err("--expected-digest must be 64 hexadecimal characters".into());
    }
    Ok(RestoreArgs {
        archive,
        server_binary: PathBuf::from(server_binary),
        expected_digest: expected_digest.to_ascii_lowercase(),
        api_key_file: PathBuf::from(api_key_file),
        key: PathBuf::from(key),
        out: PathBuf::from(out),
        port,
        config,
    })
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether the binary's digest is the one expected (case does not matter).
/// Pure.
pub fn provenance_ok(actual: &str, expected: &str) -> bool {
    is_sha256_hex(actual) && actual.eq_ignore_ascii_case(expected)
}

/// The recovery point in seconds: how far the restored copy's newest audit
/// row is behind the live deployment's. With no audit row on either side,
/// the archive's age at `now` stands in. Never negative. Pure.
pub fn rpo_seconds(
    live_newest: Option<DateTime<Utc>>,
    restored_newest: Option<DateTime<Utc>>,
    archive_written: DateTime<Utc>,
    now: DateTime<Utc>,
) -> f64 {
    let gap = match (live_newest, restored_newest) {
        (Some(live), Some(restored)) => live - restored,
        (Some(live), None) => live - archive_written,
        _ => now - archive_written,
    };
    (gap.num_milliseconds().max(0) as f64) / 1000.0
}

/// The throwaway configuration: the deployment's own file with the copy's
/// database, the drill's port, an in-process cache, no inline jobs, no
/// email and no backup. Placeholders such as `${DB_PASSWORD}` are kept as
/// they are, so no secret is written. Pure.
pub fn drill_config(base: &Value, dbname: &str, port: u16) -> Result<Value, String> {
    let mut config = base.clone();
    let root = config
        .as_object_mut()
        .ok_or("the configuration file is not a JSON object")?;
    let mut set = |section: &str, key: &str, value: Value| {
        let entry = root
            .entry(section.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(map) = entry.as_object_mut() {
            map.insert(key.to_owned(), value);
        }
    };
    set("database", "dbname", json!(dbname));
    set("app", "port", json!(port));
    set("cache", "backend", json!("memory"));
    set("jobs", "run_worker_inline", json!(false));
    set("email", "enabled", json!(false));
    set("backup", "enabled", json!(false));
    Ok(config)
}

/// The evidence file's name for a drill on `date`. Pure.
pub fn evidence_file_name(date: chrono::NaiveDate) -> String {
    format!("restore-drill-evidence-{date}.json")
}

fn check(name: &str, passed: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_owned(),
        result: if passed {
            CheckResult::Pass
        } else {
            CheckResult::Fail
        },
        detail: Some(detail.into()),
    }
}

fn skipped(name: &str, why: &str) -> Check {
    Check {
        name: name.to_owned(),
        result: CheckResult::Skipped,
        detail: Some(why.to_owned()),
    }
}

pub(crate) async fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let digest = tokio::task::spawn_blocking(move || Sha256::digest(&bytes))
        .await
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(digest))
}

pub(crate) async fn newest_audit(conn: &mut sqlx::PgConnection) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, Option<DateTime<Utc>>>("SELECT max(created_at) FROM audit_header")
        .fetch_one(conn)
        .await
        .ok()
        .flatten()
}

pub(crate) async fn wait_ready(base: &str) -> Result<(), String> {
    let url = format!("{base}/health/ready");
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("restore_drill_ready").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(5)),
    )
    .map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    loop {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("{url} did not answer ready within {READY_WAIT:?}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// A first page of the first [`SAMPLE_ENTITIES`] entities, with the drill's
/// key: each entity's status. Only statuses are kept, never bodies.
pub(crate) async fn sample_reads(base: &str, key: &str) -> Result<Vec<(String, u16)>, String> {
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("restore_drill_reads").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(30)),
    )
    .map_err(|e| e.to_string())?;
    let auth = format!("ApiKey {key}");
    let listed = client
        .get(format!(
            "{base}/api/v1/admin/entities?page=1&page_size={SAMPLE_ENTITIES}"
        ))
        .header("authorization", &auth)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = listed.status().as_u16();
    if status != 200 {
        return Err(format!("listing entities answered {status}"));
    }
    let listed: Value = listed.json().await.map_err(|e| e.to_string())?;
    let names: Vec<String> = listed["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i["logicalname"].as_str().map(str::to_owned))
                .take(SAMPLE_ENTITIES)
                .collect()
        })
        .unwrap_or_default();
    let mut reads = Vec::with_capacity(names.len());
    for name in names {
        let status = client
            .get(format!("{base}/api/v1/{name}?page=1&page_size=1"))
            .header("authorization", &auth)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0);
        reads.push((name, status));
    }
    Ok(reads)
}

/// Every read answered 200 and there was at least one. Pure.
pub fn sample_reads_check(reads: &[(String, u16)]) -> Check {
    let failed: Vec<String> = reads
        .iter()
        .filter(|(_, s)| *s != 200)
        .map(|(n, s)| format!("{n}={s}"))
        .collect();
    let passed = !reads.is_empty() && failed.is_empty();
    let detail = if failed.is_empty() {
        format!("{} entities read", reads.len())
    } else {
        format!(
            "{} of {} failed: {}",
            failed.len(),
            reads.len(),
            failed.join(", ")
        )
    };
    check("sample_api_reads", passed, detail)
}

async fn run_audit_chain(binary: &Path, config: &Path) -> Result<(), String> {
    let output = tokio::process::Command::new(binary)
        .arg("verify-audit-chain")
        .env("CONFIG_FILE", config)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("run verify-audit-chain: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("verify-audit-chain exited with {}", output.status))
    }
}

/// What the drill measured, for the evidence.
struct Measured {
    checks: Vec<Check>,
    restore_ok: bool,
    provenance_ok: bool,
    rpo_seconds: Option<f64>,
    postgres_rto_seconds: Option<f64>,
    app_rto_seconds: Option<f64>,
    digest: Option<String>,
}

/// Steps 2 to 6 against the restored copy `temp`. Never drops it: the caller
/// does, whatever happened here.
#[allow(
    clippy::too_many_arguments,
    reason = "one drill's inputs, each used once; a struct would only rename them"
)]
async fn exercise(
    args: &RestoreArgs,
    config: &attome_config::AppConfig,
    config_path: &str,
    admin: &mut sqlx::PgConnection,
    archive: &Path,
    temp: &str,
    drill_config_path: &Path,
    api_key: &str,
    started: DateTime<Utc>,
) -> Measured {
    use sqlx::Connection;
    let mut m = Measured {
        checks: Vec::new(),
        restore_ok: false,
        provenance_ok: false,
        rpo_seconds: None,
        postgres_rto_seconds: None,
        app_rto_seconds: None,
        digest: None,
    };

    match sha256_file(&args.server_binary).await {
        Ok(digest) => {
            m.provenance_ok = provenance_ok(&digest, &args.expected_digest);
            m.checks.push(check(
                "provenance",
                m.provenance_ok,
                if m.provenance_ok {
                    "the server binary's digest is the expected one".to_owned()
                } else {
                    format!("digest {digest} is not the expected one")
                },
            ));
            m.digest = Some(digest);
        }
        Err(e) => m.checks.push(check("provenance", false, e)),
    }

    let clock = Instant::now();
    let restored = crate::backup::restore_into(config, admin, archive, temp).await;
    m.postgres_rto_seconds = Some(clock.elapsed().as_secs_f64());
    m.restore_ok = restored.is_ok();
    m.checks.push(match &restored {
        Ok(()) => check(
            "database_restore",
            true,
            "archive restored into a throwaway database",
        ),
        Err(e) => check("database_restore", false, e.clone()),
    });
    if restored.is_err() {
        for name in ["readiness", "audit_chain_verify", "sample_api_reads"] {
            m.checks.push(skipped(name, "the restore failed"));
        }
        return m;
    }

    let live_newest = newest_audit(admin).await;
    let restored_newest =
        match sqlx::PgConnection::connect_with(&crate::backup::connect_options(config, temp)).await
        {
            Ok(mut copy) => {
                let newest = newest_audit(&mut copy).await;
                let _ = copy.close().await;
                newest
            }
            Err(_) => None,
        };
    let written = tokio::fs::metadata(archive)
        .await
        .and_then(|meta| meta.modified())
        .map(DateTime::<Utc>::from)
        .unwrap_or(started);
    m.rpo_seconds = Some(rpo_seconds(live_newest, restored_newest, written, started));

    // The throwaway configuration, from the deployment's own file.
    let base: Value = match tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| format!("read {config_path}: {e}"))
        .and_then(|text| serde_json::from_str(&text).map_err(|e| format!("{config_path}: {e}")))
        .and_then(|base| drill_config(&base, temp, args.port))
    {
        Ok(v) => v,
        Err(e) => {
            m.checks.push(check("readiness", false, e));
            m.checks
                .push(skipped("audit_chain_verify", "no drill configuration"));
            m.checks
                .push(skipped("sample_api_reads", "no drill configuration"));
            return m;
        }
    };
    if let Err(e) = tokio::fs::write(
        drill_config_path,
        serde_json::to_vec_pretty(&base).unwrap_or_default(),
    )
    .await
    {
        m.checks.push(check(
            "readiness",
            false,
            format!("write {}: {e}", drill_config_path.display()),
        ));
        m.checks
            .push(skipped("audit_chain_verify", "no drill configuration"));
        m.checks
            .push(skipped("sample_api_reads", "no drill configuration"));
        return m;
    }

    let clock = Instant::now();
    let child = tokio::process::Command::new(&args.server_binary)
        .arg("serve")
        .env("CONFIG_FILE", drill_config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            m.checks
                .push(check("readiness", false, format!("start the server: {e}")));
            m.checks
                .push(skipped("audit_chain_verify", "the server did not start"));
            m.checks
                .push(skipped("sample_api_reads", "the server did not start"));
            return m;
        }
    };
    let base_url = format!("http://127.0.0.1:{}", args.port);
    let ready = wait_ready(&base_url).await;
    m.app_rto_seconds = Some(clock.elapsed().as_secs_f64());
    m.checks.push(match &ready {
        Ok(()) => check("readiness", true, "the server answered ready"),
        Err(e) => check("readiness", false, e.clone()),
    });
    m.checks.push(
        match run_audit_chain(&args.server_binary, drill_config_path).await {
            Ok(()) => check("audit_chain_verify", true, "intact"),
            Err(e) => check("audit_chain_verify", false, e),
        },
    );
    m.checks.push(if ready.is_ok() {
        match sample_reads(&base_url, api_key).await {
            Ok(reads) => sample_reads_check(&reads),
            Err(e) => check("sample_api_reads", false, e),
        }
    } else {
        skipped("sample_api_reads", "the server never answered ready")
    });
    let _ = child.kill().await;
    let _ = child.wait().await;
    m
}

#[tokio::main]
pub async fn run_cli(args: &[String]) -> u8 {
    use sqlx::{Connection, Executor};
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome drill restore: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let key = match evidence::read_signing_key(&args.key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("attome drill restore: {}: {e}", args.key.display());
            return EXIT_USAGE;
        }
    };
    let api_key = match std::fs::read_to_string(&args.api_key_file) {
        Ok(text) if !text.trim().is_empty() => text.trim().to_owned(),
        Ok(_) => {
            eprintln!(
                "attome drill restore: {} is empty",
                args.api_key_file.display()
            );
            return EXIT_USAGE;
        }
        Err(e) => {
            eprintln!("attome drill restore: {}: {e}", args.api_key_file.display());
            return EXIT_USAGE;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&args.out) {
        eprintln!("attome drill restore: {}: {e}", args.out.display());
        return EXIT_USAGE;
    }
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(attome_config::AppConfig::config_file_path);
    let config = match crate::secret_sources::load_config_from(config_path.clone()).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("attome drill restore: load the configuration: {e}");
            return EXIT_USAGE;
        }
    };
    let archive = match crate::backup::archive_for(&config, &args.archive).await {
        Ok(path) => path,
        Err(e) => {
            eprintln!("attome drill restore: {e}");
            return EXIT_USAGE;
        }
    };
    let mut admin = match sqlx::PgConnection::connect_with(&crate::backup::connect_options(
        &config,
        &config.database.dbname,
    ))
    .await
    {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("attome drill restore: connect the database: {e}");
            return EXIT_FAILED;
        }
    };

    let started = Utc::now();
    let temp = crate::backup::drill_database_name(started);
    let drill_config_path = args.out.join(format!(".{temp}.config.json"));
    let mut measured = exercise(
        &args,
        &config,
        &config_path,
        &mut admin,
        &archive,
        &temp,
        &drill_config_path,
        &api_key,
        started,
    )
    .await;

    // Step 7: nothing of the copy stays.
    let _ = tokio::fs::remove_file(&drill_config_path).await;
    let dropped = admin
        .execute(format!("DROP DATABASE IF EXISTS \"{temp}\" WITH (FORCE)").as_str())
        .await;
    let gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(&temp)
            .fetch_one(&mut admin)
            .await
            .unwrap_or(false);
    let config_gone = tokio::fs::metadata(&drill_config_path).await.is_err();
    measured.checks.push(check(
        "scratch_destroyed",
        dropped.is_ok() && gone && config_gone,
        if gone && config_gone {
            "the throwaway database and configuration are gone".to_owned()
        } else {
            format!("database dropped: {gone}, configuration removed: {config_gone}")
        },
    ));
    let _ = admin.close().await;

    let data_size_bytes = tokio::fs::metadata(&archive).await.ok().map(|m| m.len());
    let mut extra = Map::new();
    extra.insert(
        "archive".into(),
        json!(
            archive
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        ),
    );
    extra.insert(
        "postgres_rto_seconds".into(),
        json!(measured.postgres_rto_seconds),
    );
    extra.insert("app_rto_seconds".into(), json!(measured.app_rto_seconds));
    let rto_seconds = match (measured.postgres_rto_seconds, measured.app_rto_seconds) {
        (Some(db), Some(app)) => Some(db + app),
        (db, _) => db,
    };
    let mut report = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Restore,
        drill_id: Uuid::now_v7(),
        started_at: started,
        finished_at: Utc::now(),
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        image_digest: measured.digest.clone(),
        deployment_id: None,
        checks: measured.checks,
        rpo_seconds: measured.rpo_seconds,
        rto_seconds,
        data_size_bytes,
        restore_ok: measured.restore_ok,
        provenance_ok: measured.provenance_ok,
        overall_ok: false,
        extra,
    };
    report.compute_overall();
    let path = args.out.join(evidence_file_name(started.date_naive()));
    match evidence::write_signed(&path, &report, &key) {
        Ok(hash) => {
            println!("wrote {} (sha256 {hash})", path.display());
            for c in &report.checks {
                println!(
                    "{} {:?} {}",
                    c.name,
                    c.result,
                    c.detail.as_deref().unwrap_or("")
                );
            }
            println!("overall_ok {}", report.overall_ok);
            if report.overall_ok {
                EXIT_OK
            } else {
                EXIT_FAILED
            }
        }
        Err(e) => {
            eprintln!("attome drill restore: {}: {e}", path.display());
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn rpo_from_backup_info_json() {
        // v2 has no pgBackRest info JSON (V2-D1387): the recovery point is
        // the newest restored audit row against the live one.
        let now = at("2026-11-06T12:00:00Z");
        let written = at("2026-11-06T02:00:00Z");
        let live = Some(at("2026-11-06T11:59:00Z"));
        let restored = Some(at("2026-11-06T01:59:30Z"));
        assert_eq!(rpo_seconds(live, restored, written, now), 36_570.0);
        // A copy newer than live (clock skew) never reads negative.
        assert_eq!(rpo_seconds(restored, live, written, now), 0.0);
        // No audit rows: the archive's age stands in.
        assert_eq!(rpo_seconds(None, None, written, now), 36_000.0);
    }

    #[test]
    fn provenance_mismatch_fails() {
        let a = "a".repeat(64);
        assert!(provenance_ok(&a, &a.to_ascii_uppercase()));
        assert!(!provenance_ok(&a, &"b".repeat(64)));
        assert!(!provenance_ok("short", "short"));
    }

    #[test]
    fn drill_config_isolates_the_copy() {
        let base = json!({
            "database": { "dbname": "attome", "password": "${DB_PASSWORD}" },
            "app": { "port": 7865 },
            "jobs": { "run_worker_inline": true },
        });
        let c = drill_config(&base, "attome_drill_20261106", 7999).unwrap();
        assert_eq!(c["database"]["dbname"], "attome_drill_20261106");
        assert_eq!(
            c["database"]["password"], "${DB_PASSWORD}",
            "placeholders stay"
        );
        assert_eq!(c["app"]["port"], 7999);
        assert_eq!(c["cache"]["backend"], "memory");
        assert_eq!(c["jobs"]["run_worker_inline"], false);
        assert_eq!(c["email"]["enabled"], false);
        assert_eq!(c["backup"]["enabled"], false);
        assert!(drill_config(&json!([]), "x", 1).is_err());
    }

    #[test]
    fn args_need_the_binary_digest_and_keys() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let digest = "A".repeat(64);
        let ok = parse_args(&words(&format!(
            "--server-binary bin --expected-digest {digest} --api-key-file k --key s --out o"
        )))
        .unwrap();
        assert_eq!(ok.port, DEFAULT_PORT);
        assert_eq!(ok.archive, "latest");
        assert_eq!(ok.expected_digest, "a".repeat(64));
        assert!(
            parse_args(&words(
                "--server-binary bin --api-key-file k --key s --out o"
            ))
            .is_err()
        );
        assert!(
            parse_args(&words(
                "--server-binary bin --expected-digest abc --api-key-file k --key s --out o"
            ))
            .is_err()
        );
    }

    #[test]
    fn sample_reads_need_every_entity_ok() {
        assert_eq!(
            sample_reads_check(&[("account".into(), 200)]).result,
            CheckResult::Pass
        );
        assert_eq!(sample_reads_check(&[]).result, CheckResult::Fail);
        let failed = sample_reads_check(&[("account".into(), 200), ("deal".into(), 500)]);
        assert_eq!(failed.result, CheckResult::Fail);
        assert!(failed.detail.unwrap().contains("deal=500"));
    }
}

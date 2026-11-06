//! AB8-T4 (V2-D1928): `attome upgrade rehearse`, an upgrade tried on a copy.
//!
//! ```text
//! attome upgrade rehearse --manifest <file> --old-binary <path> --new-binary <path>
//!                         --admin-key-file <path> --key <signing key> --out <dir>
//!                         [--archive latest|<name>] [--base-url <live url>] [--config <path>]
//! ```
//!
//! 1. Restores the backup into a throwaway database (`attome_rehearse_<time>`,
//!    AB4-T4's steps), and reads its columns: schema A.
//! 2. Runs the new binary's `migrate` against the copy, timed, and reads
//!    schema B; the difference is the release's schema change.
//! 3. Boots the new binary on port 7998 against the copy, waits for ready,
//!    reads a first page of five entities and runs every customer test
//!    (`POST /api/v1/admin/customer-tests/run-all`, AC5-T11); stops it.
//! 4. Boots the OLD binary on port 7997 against the migrated copy with
//!    `database.migrate_on_boot = false`, as an old node runs during a
//!    rolling upgrade (so it never meets the newer migrations it does not
//!    know), and makes the same reads: `old_binary_against_new_schema`.
//! 5. Drops the copy, writes `rehearsal-<version>.json` (the impact report:
//!    schema changes, durations, failing reads, customer tests, the old
//!    binary's result) and signed `Upgrade` evidence with the report in
//!    `extra`, and with `--base-url` stores the evidence on the live
//!    deployment (`/api/v1/ops/drills/evidence`).
//!
//! `attome upgrade apply --rehearsal <file>` then keeps the report in the
//! upgrade's `check_report.rehearsal`, which the Upgrades page shows (AB8-T8).
//! The copy is never the live database, and every server it boots runs with
//! no job worker, no email, no backup and an in-process cache.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use attome_ops::evidence::{self, Check, CheckResult, Evidence, EvidenceKind, SCHEMA};
use attome_ops::release_manifest::verify_manifest;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::cmd::drill_restore::{drill_config, sample_reads, sample_reads_check, wait_ready};
use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome upgrade rehearse --manifest <file> --old-binary <path> --new-binary <path> --admin-key-file <path> --key <signing key> --out <dir> [--archive latest|<name>] [--base-url <live url>] [--config <path>]";

/// The new binary's port during the rehearsal.
pub const NEW_PORT: u16 = 7998;
/// The old binary's port during the rehearsal.
pub const OLD_PORT: u16 = 7997;

/// What `upgrade rehearse` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehearseArgs {
    pub manifest: PathBuf,
    pub old_binary: PathBuf,
    pub new_binary: PathBuf,
    pub admin_key_file: PathBuf,
    pub key: PathBuf,
    pub out: PathBuf,
    pub archive: String,
    pub base_url: Option<String>,
    pub config: Option<String>,
}

/// Parses the arguments after `upgrade rehearse`. Pure.
pub fn parse_args(args: &[String]) -> Result<RehearseArgs, String> {
    let mut args = args.to_vec();
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required"));
    let manifest = need(take_value(&mut args, "--manifest")?, "--manifest")?;
    let old_binary = need(take_value(&mut args, "--old-binary")?, "--old-binary")?;
    let new_binary = need(take_value(&mut args, "--new-binary")?, "--new-binary")?;
    let admin_key_file = need(
        take_value(&mut args, "--admin-key-file")?,
        "--admin-key-file",
    )?;
    let key = need(take_value(&mut args, "--key")?, "--key")?;
    let out = need(take_value(&mut args, "--out")?, "--out")?;
    let archive = take_value(&mut args, "--archive")?.unwrap_or_else(|| "latest".to_owned());
    let base_url = take_value(&mut args, "--base-url")?;
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    if old_binary == new_binary {
        return Err("--old-binary and --new-binary are the same file".into());
    }
    Ok(RehearseArgs {
        manifest: PathBuf::from(manifest),
        old_binary: PathBuf::from(old_binary),
        new_binary: PathBuf::from(new_binary),
        admin_key_file: PathBuf::from(admin_key_file),
        key: PathBuf::from(key),
        out: PathBuf::from(out),
        archive,
        base_url: base_url.map(|u| u.trim_end_matches('/').to_owned()),
        config,
    })
}

/// One column as `information_schema.columns` has it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Column {
    pub table_name: String,
    pub column_name: String,
    pub data_type: String,
    pub is_nullable: String,
}

/// What a migration did to the columns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SchemaDiff {
    /// `table.column type`.
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// `table.column: old -> new` (type or nullability).
    pub changed: Vec<String>,
}

impl SchemaDiff {
    /// One line per change, for the impact report and the Upgrades page.
    pub fn lines(&self) -> Vec<String> {
        self.added
            .iter()
            .map(|c| format!("added {c}"))
            .chain(self.removed.iter().map(|c| format!("removed {c}")))
            .chain(self.changed.iter().map(|c| format!("changed {c}")))
            .collect()
    }
}

fn shape(c: &Column) -> String {
    let null = if c.is_nullable == "YES" {
        ""
    } else {
        " not null"
    };
    format!("{}{null}", c.data_type)
}

/// The columns added, removed and changed between schema `a` and `b`, each
/// list sorted. Pure.
pub fn schema_diff(a: &[Column], b: &[Column]) -> SchemaDiff {
    let index = |cols: &[Column]| -> BTreeMap<(String, String), String> {
        cols.iter()
            .map(|c| ((c.table_name.clone(), c.column_name.clone()), shape(c)))
            .collect()
    };
    let (a, b) = (index(a), index(b));
    let mut diff = SchemaDiff::default();
    for ((t, c), shape_b) in &b {
        match a.get(&(t.clone(), c.clone())) {
            None => diff.added.push(format!("{t}.{c} {shape_b}")),
            Some(shape_a) if shape_a != shape_b => {
                diff.changed
                    .push(format!("{t}.{c}: {shape_a} -> {shape_b}"));
            }
            Some(_) => {}
        }
    }
    for ((t, c), shape_a) in &a {
        if !b.contains_key(&(t.clone(), c.clone())) {
            diff.removed.push(format!("{t}.{c} {shape_a}"));
        }
    }
    diff
}

async fn read_schema(
    config: &attome_config::AppConfig,
    dbname: &str,
) -> Result<Vec<Column>, String> {
    use sqlx::Connection;
    let mut conn =
        sqlx::PgConnection::connect_with(&crate::backup::connect_options(config, dbname))
            .await
            .map_err(|e| format!("open the copy: {e}"))?;
    let cols = sqlx::query_as::<_, Column>(
        "SELECT table_name::text, column_name::text, data_type::text, is_nullable::text \
           FROM information_schema.columns WHERE table_schema = current_schema() \
          ORDER BY table_name, column_name",
    )
    .fetch_all(&mut conn)
    .await
    .map_err(|e| format!("read the columns: {e}"));
    let _ = conn.close().await;
    cols
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

/// The customer tests' outcome as the Upgrades page reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CustomerTests {
    pub passed: u64,
    pub failed: u64,
    pub failures: Vec<String>,
}

/// Reads `POST /api/v1/admin/customer-tests/run-all`'s answer. Pure.
pub fn customer_tests_from(body: &Value) -> CustomerTests {
    let failures = body["results"]
        .as_array()
        .map(|rs| {
            rs.iter()
                .filter(|r| r["passed"].as_bool() == Some(false))
                .filter_map(|r| r["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    CustomerTests {
        passed: body["passed"].as_u64().unwrap_or(0),
        failed: body["failed"].as_u64().unwrap_or(0),
        failures,
    }
}

async fn run_customer_tests(base: &str, key: &str) -> Result<CustomerTests, String> {
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("upgrade_rehearse_tests").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(600)),
    )
    .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{base}/api/v1/admin/customer-tests/run-all"))
        .header("authorization", format!("ApiKey {key}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!("run-all answered {status}"));
    }
    let body: Value = response.json().await.map_err(|e| e.to_string())?;
    Ok(customer_tests_from(&body))
}

/// A server booted for the rehearsal: killed when dropped.
async fn boot(binary: &Path, config: &Path) -> Result<tokio::process::Child, String> {
    tokio::process::Command::new(binary)
        .arg("serve")
        .env("CONFIG_FILE", config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("start {}: {e}", binary.display()))
}

async fn write_config(path: &Path, config: &Value) -> Result<(), String> {
    tokio::fs::write(path, serde_json::to_vec_pretty(config).unwrap_or_default())
        .await
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// The impact report a rehearsal writes, and `apply --rehearsal` keeps.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Rehearsal {
    pub to_version: String,
    pub schema_changes: Vec<String>,
    pub conflicts: Vec<Value>,
    pub customer_tests: Option<CustomerTests>,
    pub old_binary: Option<Value>,
    pub failing_reads: Vec<String>,
    /// Seconds per step: restore, migrate, new_boot, old_boot.
    pub durations: BTreeMap<String, f64>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the rehearsal's steps in order; each is a few lines"
)]
async fn rehearse(
    args: &RehearseArgs,
    config: &attome_config::AppConfig,
    config_path: &str,
    admin: &mut sqlx::PgConnection,
    temp: &str,
    api_key: &str,
    report: &mut Rehearsal,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let archive = match crate::backup::archive_for(config, &args.archive).await {
        Ok(path) => path,
        Err(e) => {
            checks.push(check("database_restore", false, e));
            return checks;
        }
    };
    let clock = Instant::now();
    let restored = crate::backup::restore_into(config, admin, &archive, temp).await;
    report
        .durations
        .insert("restore".into(), clock.elapsed().as_secs_f64());
    checks.push(match &restored {
        Ok(()) => check(
            "database_restore",
            true,
            "backup restored into a throwaway database",
        ),
        Err(e) => check("database_restore", false, e.clone()),
    });
    if restored.is_err() {
        return checks;
    }
    let schema_a = read_schema(config, temp).await;

    let base: Value = match tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| format!("read {config_path}: {e}"))
        .and_then(|t| serde_json::from_str(&t).map_err(|e| format!("{config_path}: {e}")))
    {
        Ok(v) => v,
        Err(e) => {
            checks.push(check("migrate", false, e));
            return checks;
        }
    };
    let new_config_path = args.out.join(format!(".{temp}.new.json"));
    let old_config_path = args.out.join(format!(".{temp}.old.json"));
    let new_config = drill_config(&base, temp, NEW_PORT);
    let old_config = drill_config(&base, temp, OLD_PORT).map(|mut c| {
        c["database"]["migrate_on_boot"] = json!(false);
        c
    });
    let written = match (new_config, old_config) {
        (Ok(n), Ok(o)) => match write_config(&new_config_path, &n).await {
            Ok(()) => write_config(&old_config_path, &o).await,
            Err(e) => Err(e),
        },
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    if let Err(e) = written {
        checks.push(check("migrate", false, e));
        return checks;
    }

    // Step 2: the new migrate, then schema B.
    let clock = Instant::now();
    let migrated = tokio::process::Command::new(&args.new_binary)
        .arg("migrate")
        .env("CONFIG_FILE", &new_config_path)
        .kill_on_drop(true)
        .status()
        .await;
    report
        .durations
        .insert("migrate".into(), clock.elapsed().as_secs_f64());
    let migrate_ok = matches!(&migrated, Ok(status) if status.success());
    checks.push(match &migrated {
        Ok(status) if status.success() => check("migrate", true, "the new migrations applied"),
        Ok(status) => check("migrate", false, format!("migrate exited with {status}")),
        Err(e) => check("migrate", false, format!("run migrate: {e}")),
    });
    if !migrate_ok {
        return checks;
    }
    match (schema_a, read_schema(config, temp).await) {
        (Ok(a), Ok(b)) => report.schema_changes = schema_diff(&a, &b).lines(),
        (Err(e), _) | (_, Err(e)) => checks.push(check("schema_diff", false, e)),
    }

    // Step 3: the new binary.
    let clock = Instant::now();
    let new_base = format!("http://127.0.0.1:{NEW_PORT}");
    match boot(&args.new_binary, &new_config_path).await {
        Ok(mut child) => {
            let ready = wait_ready(&new_base).await;
            report
                .durations
                .insert("new_boot".into(), clock.elapsed().as_secs_f64());
            checks.push(match &ready {
                Ok(()) => check("new_binary_ready", true, "answered ready"),
                Err(e) => check("new_binary_ready", false, e.clone()),
            });
            if ready.is_ok() {
                let reads = sample_reads(&new_base, api_key).await;
                let mut read_check = match &reads {
                    Ok(r) => sample_reads_check(r),
                    Err(e) => check("sample_api_reads", false, e.clone()),
                };
                read_check.name = "new_binary_reads".into();
                if let Ok(r) = &reads {
                    report.failing_reads.extend(
                        r.iter()
                            .filter(|(_, s)| *s != 200)
                            .map(|(n, s)| format!("new {n}={s}")),
                    );
                }
                checks.push(read_check);
                match run_customer_tests(&new_base, api_key).await {
                    Ok(tests) => {
                        checks.push(check(
                            "customer_tests",
                            tests.failed == 0,
                            format!("{} passed, {} failed", tests.passed, tests.failed),
                        ));
                        report.customer_tests = Some(tests);
                    }
                    Err(e) => checks.push(check("customer_tests", false, e)),
                }
            } else {
                checks.push(skipped(
                    "new_binary_reads",
                    "the new binary never answered ready",
                ));
                checks.push(skipped(
                    "customer_tests",
                    "the new binary never answered ready",
                ));
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        Err(e) => {
            checks.push(check("new_binary_ready", false, e));
            checks.push(skipped("new_binary_reads", "the new binary did not start"));
            checks.push(skipped("customer_tests", "the new binary did not start"));
        }
    }

    // Step 4: the old binary on the new schema (required, never skipped by
    // choice).
    let clock = Instant::now();
    let old_base = format!("http://127.0.0.1:{OLD_PORT}");
    let old = match boot(&args.old_binary, &old_config_path).await {
        Ok(mut child) => {
            let outcome = match wait_ready(&old_base).await {
                Ok(()) => match sample_reads(&old_base, api_key).await {
                    Ok(reads) => {
                        report.failing_reads.extend(
                            reads
                                .iter()
                                .filter(|(_, s)| *s != 200)
                                .map(|(n, s)| format!("old {n}={s}")),
                        );
                        let c = sample_reads_check(&reads);
                        (c.result == CheckResult::Pass, c.detail.unwrap_or_default())
                    }
                    Err(e) => (false, e),
                },
                Err(e) => (false, e),
            };
            report
                .durations
                .insert("old_boot".into(), clock.elapsed().as_secs_f64());
            let _ = child.kill().await;
            let _ = child.wait().await;
            outcome
        }
        Err(e) => (false, e),
    };
    report.old_binary = Some(json!({ "ok": old.0, "detail": old.1 }));
    checks.push(check("old_binary_against_new_schema", old.0, old.1));
    checks
}

async fn store_evidence(
    base: &str,
    key: &str,
    signed: &evidence::SignedEvidence,
) -> Result<(), String> {
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("upgrade_rehearse_evidence")
            .with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(30)),
    )
    .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{base}/api/v1/ops/drills/evidence"))
        .header("authorization", format!("ApiKey {key}"))
        .json(signed)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    if status == 200 || status == 201 {
        Ok(())
    } else {
        Err(format!("storing the evidence answered {status}"))
    }
}

#[tokio::main]
async fn run_async(args: RehearseArgs) -> Result<bool, String> {
    use sqlx::{Connection, Executor};
    let key = evidence::read_signing_key(&args.key)
        .map_err(|e| format!("{}: {e}", args.key.display()))?;
    let api_key = std::fs::read_to_string(&args.admin_key_file)
        .map_err(|e| format!("{}: {e}", args.admin_key_file.display()))?
        .trim()
        .to_owned();
    if api_key.is_empty() {
        return Err(format!("{} is empty", args.admin_key_file.display()));
    }
    let bytes = std::fs::read(&args.manifest)
        .map_err(|e| format!("read {}: {e}", args.manifest.display()))?;
    let manifest = verify_manifest(&bytes, crate::release_keys::RELEASE_PUBLIC_KEYS)
        .map_err(|e| format!("{}: {e}", args.manifest.display()))?;
    std::fs::create_dir_all(&args.out).map_err(|e| format!("{}: {e}", args.out.display()))?;
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(attome_config::AppConfig::config_file_path);
    let config = crate::secret_sources::load_config_from(config_path.clone())
        .await
        .map_err(|e| format!("load the configuration: {e}"))?;
    let mut admin = sqlx::PgConnection::connect_with(&crate::backup::connect_options(
        &config,
        &config.database.dbname,
    ))
    .await
    .map_err(|e| format!("connect the database: {e}"))?;

    let started = Utc::now();
    let temp = format!("attome_rehearse_{}", started.format("%Y%m%d%H%M%S"));
    let mut report = Rehearsal {
        to_version: manifest.version.clone(),
        ..Rehearsal::default()
    };
    let mut checks = rehearse(
        &args,
        &config,
        &config_path,
        &mut admin,
        &temp,
        &api_key,
        &mut report,
    )
    .await;

    // Nothing of the copy stays.
    for suffix in ["new", "old"] {
        let _ = tokio::fs::remove_file(args.out.join(format!(".{temp}.{suffix}.json"))).await;
    }
    let dropped = admin
        .execute(format!("DROP DATABASE IF EXISTS \"{temp}\" WITH (FORCE)").as_str())
        .await;
    let gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(&temp)
            .fetch_one(&mut admin)
            .await
            .unwrap_or(false);
    checks.push(check(
        "scratch_destroyed",
        dropped.is_ok() && gone,
        if gone {
            "the copy is gone"
        } else {
            "the copy was not dropped"
        },
    ));
    let _ = admin.close().await;

    let report_value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    let report_path = args
        .out
        .join(format!("rehearsal-{}.json", manifest.version));
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report_value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {}: {e}", report_path.display()))?;
    println!("wrote {}", report_path.display());

    let mut extra = Map::new();
    extra.insert("rehearsal".into(), report_value);
    let restored = checks
        .iter()
        .any(|c| c.name == "database_restore" && c.result == CheckResult::Pass);
    let mut evidence_doc = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Upgrade,
        drill_id: Uuid::now_v7(),
        started_at: started,
        finished_at: Utc::now(),
        platform_version: manifest.version.clone(),
        image_digest: None,
        deployment_id: None,
        checks,
        rpo_seconds: None,
        rto_seconds: None,
        data_size_bytes: None,
        restore_ok: restored,
        provenance_ok: true,
        overall_ok: false,
        extra,
    };
    evidence_doc.compute_overall();
    let evidence_path = args.out.join(format!(
        "upgrade-rehearsal-evidence-{}-{}.json",
        manifest.version,
        started.date_naive()
    ));
    let hash = evidence::write_signed(&evidence_path, &evidence_doc, &key)
        .map_err(|e| format!("{}: {e}", evidence_path.display()))?;
    println!("wrote {} (sha256 {hash})", evidence_path.display());
    for c in &evidence_doc.checks {
        println!(
            "{} {:?} {}",
            c.name,
            c.result,
            c.detail.as_deref().unwrap_or("")
        );
    }
    if let Some(base) = &args.base_url {
        let signed = evidence::sign(&evidence_doc, &key).map_err(|e| e.to_string())?;
        match store_evidence(base, &api_key, &signed).await {
            Ok(()) => println!("stored the evidence on {base}"),
            Err(e) => eprintln!("attome upgrade rehearse: {e}"),
        }
    }
    println!("overall_ok {}", evidence_doc.overall_ok);
    Ok(evidence_doc.overall_ok)
}

/// `attome upgrade rehearse ...` (the arguments after `rehearse`).
pub fn run(args: &[String]) -> ExitCode {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome upgrade rehearse: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run_async(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(3),
        Err(message) => {
            eprintln!("attome upgrade rehearse: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(t: &str, c: &str, ty: &str, null: &str) -> Column {
        Column {
            table_name: t.into(),
            column_name: c.into(),
            data_type: ty.into(),
            is_nullable: null.into(),
        }
    }

    #[test]
    fn schema_diff_lists_added_and_removed_columns() {
        let a = vec![
            col("account", "id", "uuid", "NO"),
            col("account", "fax", "text", "YES"),
            col("account", "name", "text", "YES"),
        ];
        let b = vec![
            col("account", "id", "uuid", "NO"),
            col("account", "name", "character varying", "YES"),
            col("account", "tier", "text", "YES"),
            col("invoice", "id", "uuid", "NO"),
        ];
        let d = schema_diff(&a, &b);
        assert_eq!(
            d.added,
            vec!["account.tier text", "invoice.id uuid not null"]
        );
        assert_eq!(d.removed, vec!["account.fax text"]);
        assert_eq!(d.changed, vec!["account.name: text -> character varying"]);
        assert_eq!(d.lines()[0], "added account.tier text");
        assert!(schema_diff(&a, &a).lines().is_empty());
    }

    #[test]
    fn customer_test_answer_names_the_failures() {
        let body = json!({
            "passed": 2, "failed": 1,
            "results": [
                { "name": "discount_cap", "passed": false },
                { "name": "vat", "passed": true },
            ],
        });
        let t = customer_tests_from(&body);
        assert_eq!((t.passed, t.failed), (2, 1));
        assert_eq!(t.failures, vec!["discount_cap"]);
    }

    #[test]
    fn rehearsal_needs_two_different_binaries() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let base = "--manifest m --admin-key-file k --key s --out o";
        assert!(parse_args(&words(&format!("{base} --old-binary a --new-binary b"))).is_ok());
        assert!(parse_args(&words(&format!("{base} --old-binary a --new-binary a"))).is_err());
        assert!(parse_args(&words(&format!("{base} --old-binary a"))).is_err());
    }
}

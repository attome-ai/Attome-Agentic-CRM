//! AB3-T4 (V2-D1931): `attome drill recover --continue`, part 2 of a disaster
//! recovery. It continues from the `recover-state.json` part 1 (AB3-T3) wrote.
//!
//! ```text
//! attome drill recover --continue <out dir> --key <signing key>
//!                      [--api-key-file <path>] [--port 7999] [--config <path>]
//! ```
//!
//! Adjusted to v2 (V2-D1931): the file store has no object versioning (the
//! task's stop condition), so the recovery point of the files is the file
//! manifest written beside the archive: [`crate::backup::restore_files`]
//! puts back each file that manifest lists, after checking its SHA-256.
//!
//! 1. Files: unless the recovery is a side copy (which never writes the live
//!    store), the manifest's files are written to the configured store, then the
//!    recovered database's file rows are compared with the store: `missing`
//!    (a row without an object) and `orphan` (an object without a row), as
//!    counts plus the first 20 keys.
//! 2. On the recovered database: the backup's file copies against the
//!    recorded checksums, the sealed values opened with the key ring, the
//!    search index against its records (AB4-T5's checks, shared).
//! 3. Boots the pinned server binary against the recovered database on
//!    `--port` (an isolated configuration: in-process cache, no inline worker,
//!    no email, no backup) and waits for `/health/ready`; the recovered
//!    database already carries its search index and its queued jobs, which
//!    are idempotent and resume when the real server starts.
//! 4. `verify-audit-chain`, and with `--api-key-file` a first page of the first
//!    five entities.
//! 5. Signed `Recovery` evidence (`attome-evidence/v1`) with every check, the
//!    recovery point and time, written into the out directory and, with an API
//!    key, stored on the booted deployment (`/api/v1/ops/drills/evidence`).
//!
//! A decryption failure fails the evidence: success is never reported before
//! the sealed values open. Evidence names checks, counts and times, never
//! record contents or secrets.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use attome_ops::evidence::{self, Check, Evidence, EvidenceKind, SCHEMA};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::cmd::drill_recover::{RecoverState, STATE_FILE};
use crate::cmd::drill_restore::{
    check, copy_checks, drill_config, provenance_ok, rpo_seconds, run_audit_chain, sample_reads,
    sample_reads_check, sha256_file, skipped, wait_ready,
};
use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome drill recover --continue <out dir> --key <signing key> [--api-key-file <path>] [--port 7999] [--config <path>]";

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_FAILED: u8 = 3;

/// How many keys a missing or orphan list names.
const LIST_CAP: usize = 20;

/// What `drill recover --continue` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishArgs {
    pub dir: PathBuf,
    pub key: PathBuf,
    pub api_key_file: Option<PathBuf>,
    pub port: u16,
    pub config: Option<String>,
}

/// Parses the arguments of a `--continue` run. Pure.
pub fn parse_args(args: &[String]) -> Result<FinishArgs, String> {
    let mut args = args.to_vec();
    let dir = take_value(&mut args, "--continue")?.ok_or("--continue needs the out directory")?;
    let key = take_value(&mut args, "--key")?.ok_or("--key is required")?;
    let api_key_file = take_value(&mut args, "--api-key-file")?;
    let port = match take_value(&mut args, "--port")? {
        Some(p) => p.parse::<u16>().map_err(|_| format!("--port: `{p}`"))?,
        None => crate::cmd::drill_restore::DEFAULT_PORT,
    };
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    Ok(FinishArgs {
        dir: PathBuf::from(dir),
        key: PathBuf::from(key),
        api_key_file: api_key_file.map(PathBuf::from),
        port,
        config,
    })
}

/// The rows of the recovered database against the objects of the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyLists {
    pub missing: usize,
    pub orphans: usize,
    /// The first [`LIST_CAP`] keys of each, in order.
    pub missing_first: Vec<String>,
    pub orphans_first: Vec<String>,
}

/// Keys a row names with no object (`missing`) and objects no row names
/// (`orphans`), counted in full and listed to the first 20. Pure.
pub fn key_lists(row_keys: &[String], store_keys: &[String]) -> KeyLists {
    let store: HashSet<&str> = store_keys.iter().map(String::as_str).collect();
    let rows: HashSet<&str> = row_keys.iter().map(String::as_str).collect();
    let mut missing: Vec<&String> = row_keys
        .iter()
        .filter(|k| !store.contains(k.as_str()))
        .collect();
    let mut orphans: Vec<&String> = store_keys
        .iter()
        .filter(|k| !rows.contains(k.as_str()))
        .collect();
    missing.sort();
    missing.dedup();
    orphans.sort();
    orphans.dedup();
    KeyLists {
        missing: missing.len(),
        orphans: orphans.len(),
        missing_first: missing
            .iter()
            .take(LIST_CAP)
            .map(|k| (*k).clone())
            .collect(),
        orphans_first: orphans
            .iter()
            .take(LIST_CAP)
            .map(|k| (*k).clone())
            .collect(),
    }
}

/// The `files_reconciled` check: a row without an object fails; objects
/// without a row are reported (the store may hold files a record dropped). Pure.
pub fn reconciled_check(lists: &KeyLists, written: usize) -> Check {
    check(
        "files_reconciled",
        lists.missing == 0,
        format!(
            "{written} files put back, {} missing, {} orphan",
            lists.missing, lists.orphans
        ),
    )
}

/// The recovery point of the files: the archive's age when recovery started.
/// Pure.
pub fn recovery_point_seconds(archive_written: DateTime<Utc>, started: DateTime<Utc>) -> f64 {
    rpo_seconds(None, None, archive_written, started)
}

/// The Recovery evidence's `extra` object. Holds no secret. Pure.
pub fn recovery_extra(
    state: &RecoverState,
    lists: Option<&KeyLists>,
    files_seconds: f64,
) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("recovery_id".into(), json!(state.recovery_id));
    extra.insert("approval".into(), json!(state.approval));
    extra.insert("archive".into(), json!(state.archive));
    extra.insert("target_database".into(), json!(state.target_database));
    extra.insert("side_copy".into(), json!(state.side_copy));
    extra.insert(
        "database_rto_seconds".into(),
        json!(state.database_rto_seconds),
    );
    extra.insert("files_seconds".into(), json!(files_seconds));
    if let Some(l) = lists {
        extra.insert(
            "files".into(),
            json!({
                "missing": l.missing,
                "orphans": l.orphans,
                "missing_first": l.missing_first,
                "orphans_first": l.orphans_first,
            }),
        );
    }
    extra
}

fn read_state(dir: &Path) -> Result<RecoverState, String> {
    let path = dir.join(STATE_FILE);
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The recovered database's file keys and the store's, and the number of files
/// the manifest put back. A side copy never touches the store.
async fn reconcile_files(
    config: &attome_config::AppConfig,
    state: &RecoverState,
    archive: &Path,
) -> (Check, Option<KeyLists>, f64) {
    if state.side_copy {
        return (
            skipped(
                "files_reconciled",
                "a side copy never writes or reads the live file store",
            ),
            None,
            0.0,
        );
    }
    let clock = Instant::now();
    let written = match crate::backup::restore_files(config, archive).await {
        Ok(n) => n,
        Err(e) => {
            return (
                check(
                    "files_reconciled",
                    false,
                    format!("put the files back: {e}"),
                ),
                None,
                clock.elapsed().as_secs_f64(),
            );
        }
    };
    let seconds = clock.elapsed().as_secs_f64();
    let store_keys: Vec<String> = match attome_storage::create_storage_client(config).await {
        Ok(client) => match attome_storage::mirror::list_all(&client).await {
            Ok(entries) => entries.into_iter().map(|e| e.key).collect(),
            Err(e) => {
                return (
                    check("files_reconciled", false, format!("list the store: {e}")),
                    None,
                    seconds,
                );
            }
        },
        Err(e) => {
            return (
                check("files_reconciled", false, format!("reach the store: {e}")),
                None,
                seconds,
            );
        }
    };
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(crate::backup::connect_options(
            config,
            &state.target_database,
        ))
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            return (
                check("files_reconciled", false, format!("open the database: {e}")),
                None,
                seconds,
            );
        }
    };
    let rows: Result<Vec<String>, sqlx::Error> = sqlx::query_scalar(
        "SELECT final_key FROM upload_session \
          WHERE status = 'clean' AND NOT is_deleted AND final_key IS NOT NULL \
         UNION SELECT object_key FROM file_version WHERE object_key IS NOT NULL",
    )
    .fetch_all(&pool)
    .await;
    pool.close().await;
    match rows {
        Ok(rows) => {
            let lists = key_lists(&rows, &store_keys);
            (reconciled_check(&lists, written), Some(lists), seconds)
        }
        Err(e) => (
            check(
                "files_reconciled",
                false,
                format!("read the file rows: {e}"),
            ),
            None,
            seconds,
        ),
    }
}

/// Part 2, called from `drill recover`.
pub async fn run(args: &[String]) -> u8 {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome drill recover: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let state = match read_state(&args.dir) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("attome drill recover: part 1 left no usable state: {e}");
            return EXIT_USAGE;
        }
    };
    let key = match evidence::read_signing_key(&args.key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("attome drill recover: {}: {e}", args.key.display());
            return EXIT_USAGE;
        }
    };
    let api_key = match &args.api_key_file {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
            Ok(_) => {
                eprintln!("attome drill recover: {} is empty", path.display());
                return EXIT_USAGE;
            }
            Err(e) => {
                eprintln!("attome drill recover: {}: {e}", path.display());
                return EXIT_USAGE;
            }
        },
        None => None,
    };
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| state.config_path.clone());
    let config = match crate::secret_sources::load_config_from(config_path.clone()).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("attome drill recover: load the configuration: {e}");
            return EXIT_FAILED;
        }
    };
    let archive = match crate::backup::archive_for(&config, &state.archive).await {
        Ok(path) => path,
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            return EXIT_USAGE;
        }
    };
    let mut checks: Vec<Check> = Vec::new();
    let mut digest = None;

    // What part 1 proved, and the binary still being the pinned one.
    checks.push(check(
        "secrets_restored",
        state.secrets_restored,
        "the configuration loaded with every secret resolved",
    ));
    checks.push(check(
        "database_restore",
        true,
        format!(
            "{} restored in {:.1} s",
            state.target_database, state.database_rto_seconds
        ),
    ));
    let binary = PathBuf::from(&state.server_binary);
    let provenance = match sha256_file(&binary).await {
        Ok(d) => {
            let ok = state.provenance_ok && provenance_ok(&d, &state.server_digest);
            digest = Some(d);
            checks.push(check(
                "provenance",
                ok,
                if ok {
                    "the server binary is the pinned one"
                } else {
                    "the server binary is not the pinned one"
                },
            ));
            ok
        }
        Err(e) => {
            checks.push(check("provenance", false, e));
            false
        }
    };

    // Step 1: files.
    let (files_check, lists, files_seconds) = reconcile_files(&config, &state, &archive).await;
    checks.push(files_check);

    // Step 2: AB4-T5's checks on the recovered database.
    let (copy, size) = copy_checks(&config, &archive, &state.target_database).await;
    checks.extend(copy);

    // Step 3 to 4: boot, audit chain, reads.
    let boot_path = args
        .dir
        .join(format!(".{}.boot.json", state.target_database));
    let boot_config: Result<Value, String> = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| format!("read {config_path}: {e}"))
        .and_then(|text| serde_json::from_str(&text).map_err(|e| format!("{config_path}: {e}")))
        .and_then(|base| drill_config(&base, &state.target_database, args.port));
    let mut app_seconds = None;
    let mut stored = None;
    let mut child = None;
    let base_url = format!("http://127.0.0.1:{}", args.port);
    match boot_config {
        Ok(cfg) => {
            if let Err(e) = tokio::fs::write(
                &boot_path,
                serde_json::to_vec_pretty(&cfg).unwrap_or_default(),
            )
            .await
            {
                checks.push(check(
                    "readiness",
                    false,
                    format!("write {}: {e}", boot_path.display()),
                ));
            } else {
                let clock = Instant::now();
                match tokio::process::Command::new(&binary)
                    .arg("serve")
                    .env("CONFIG_FILE", &boot_path)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                {
                    Ok(c) => {
                        child = Some(c);
                        let ready = wait_ready(&base_url).await;
                        app_seconds = Some(clock.elapsed().as_secs_f64());
                        checks.push(match &ready {
                            Ok(()) => check("readiness", true, "the server answered ready"),
                            Err(e) => check("readiness", false, e.clone()),
                        });
                        checks.push(match run_audit_chain(&binary, &boot_path).await {
                            Ok(()) => check("audit_chain_verify", true, "intact"),
                            Err(e) => check("audit_chain_verify", false, e),
                        });
                        checks.push(match (&api_key, ready.is_ok()) {
                            (Some(k), true) => match sample_reads(&base_url, k).await {
                                Ok(reads) => sample_reads_check(&reads),
                                Err(e) => check("sample_api_reads", false, e),
                            },
                            (None, _) => skipped("sample_api_reads", "no --api-key-file given"),
                            (_, false) => {
                                skipped("sample_api_reads", "the server never answered ready")
                            }
                        });
                    }
                    Err(e) => {
                        checks.push(check("readiness", false, format!("start the server: {e}")))
                    }
                }
            }
        }
        Err(e) => checks.push(check("readiness", false, e)),
    }

    let written = tokio::fs::metadata(&archive)
        .await
        .and_then(|m| m.modified())
        .map(DateTime::<Utc>::from)
        .unwrap_or(state.started_at);
    let rto = state.database_rto_seconds + files_seconds + app_seconds.unwrap_or(0.0);
    let restore_ok = checks
        .iter()
        .find(|c| c.name == "database_restore")
        .is_some_and(|c| c.result == evidence::CheckResult::Pass);
    let mut report = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Recovery,
        drill_id: Uuid::now_v7(),
        started_at: state.started_at,
        finished_at: Utc::now(),
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        image_digest: digest,
        deployment_id: None,
        checks,
        rpo_seconds: Some(recovery_point_seconds(written, state.started_at)),
        rto_seconds: Some(rto),
        data_size_bytes: size,
        restore_ok,
        provenance_ok: provenance,
        overall_ok: false,
        extra: recovery_extra(&state, lists.as_ref(), files_seconds),
    };
    report.compute_overall();

    let path = args.dir.join(format!(
        "recovery-evidence-{}.json",
        state.started_at.date_naive()
    ));
    let mut exit = if report.overall_ok {
        EXIT_OK
    } else {
        EXIT_FAILED
    };
    match evidence::write_signed(&path, &report, &key) {
        Ok(hash) => {
            println!("wrote {} (sha256 {hash})", path.display());
            // Step 5: stored on the recovered deployment, while it is up.
            if let (Some(k), Some(_)) = (&api_key, &child) {
                stored = Some(match evidence::read_signed(&path) {
                    Ok(signed) => {
                        crate::cmd::upgrade_rehearse::store_evidence(&base_url, k, &signed).await
                    }
                    Err(e) => Err(e.to_string()),
                });
            }
        }
        Err(e) => {
            eprintln!("attome drill recover: {}: {e}", path.display());
            exit = EXIT_FAILED;
        }
    }
    if let Some(mut c) = child {
        let _ = c.kill().await;
        let _ = c.wait().await;
    }
    let _ = tokio::fs::remove_file(&boot_path).await;
    for c in &report.checks {
        println!(
            "{} {:?} {}",
            c.name,
            c.result,
            c.detail.as_deref().unwrap_or("")
        );
    }
    match stored {
        Some(Ok(())) => println!("evidence stored on the recovered deployment"),
        Some(Err(e)) => {
            eprintln!("attome drill recover: the evidence was not stored: {e}");
            exit = EXIT_FAILED;
        }
        None => println!("evidence not stored: no --api-key-file or no running deployment"),
    }
    println!("overall_ok {}", report.overall_ok);
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i:03}")).collect()
    }

    #[test]
    fn key_lists_count_everything_and_name_the_first_20() {
        let rows = keys("r", 30);
        let mut store = keys("r", 28);
        store.extend(keys("o", 25));
        let l = key_lists(&rows, &store);
        assert_eq!(l.missing, 2);
        assert_eq!(l.orphans, 25);
        assert_eq!(l.missing_first, vec!["r028".to_owned(), "r029".to_owned()]);
        assert_eq!(l.orphans_first.len(), LIST_CAP);
        assert_eq!(l.orphans_first[0], "o000");
        assert_eq!(reconciled_check(&l, 3).result, evidence::CheckResult::Fail);
        let clean = key_lists(&keys("r", 3), &keys("r", 5));
        assert_eq!(
            reconciled_check(&clean, 0).result,
            evidence::CheckResult::Pass,
            "orphans are reported, not failed"
        );
    }

    #[test]
    fn continue_needs_the_directory_and_a_key() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(parse_args(&words("--continue out")).is_err());
        let ok = parse_args(&words("--continue out --key k --port 8001")).unwrap();
        assert_eq!(ok.port, 8001);
        assert_eq!(ok.api_key_file, None);
        assert!(parse_args(&words("--key k")).is_err());
        assert!(parse_args(&words("--continue out --key k extra")).is_err());
    }
}

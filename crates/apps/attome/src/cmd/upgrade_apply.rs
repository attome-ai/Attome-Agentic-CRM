//! AB8-T7: `attome upgrade apply`, `rollback` and `contract`.
//!
//! ```text
//! attome upgrade apply --manifest <file> --new-binary <path> --restart <command>
//!                      --ready-url <url> --base-url <url> --admin-key-file <path>
//!                      --no-role-key-file <path> [--evidence-dir <dir>]
//!                      [--pgbackrest-stanza <name>] [--config <path>]
//!                      [--free-bytes <n>] [--key <cosign.pub>] [--allow-unsigned --reason <text>]
//!                      [--rehearsal <rehearsal.json>] --yes
//! attome upgrade rollback --to <version> --restart <command> [--config <path>] --yes
//! attome upgrade contract --manifest <file> --dir <dir> [--config <path>] --yes
//! ```
//!
//! `apply` runs from the old binary: it refuses a failing check, names a
//! restore point, records the upgrade, runs the new binary's `migrate`, runs
//! the restart command with `ATTOME_BINARY` naming the binary to start, waits
//! for the ready URL, then verifies: the migration ledger against the manifest,
//! the audit chain, a first page of up to 50 entities, a sample of sealed
//! values, metadata drift, and that a key with no roles is refused. The report
//! is signed, stored through `/api/v1/ops/drills/evidence`, and the upgrade
//! moves to `verified` or `failed` through the API, which audits it.
//!
//! A key can only be minted by a person's own session (D-510, D-535), so the
//! no-role key is the operator's, made once, not a temporary one made here.
//! Anything `apply` needs and lacks refuses it before it changes anything.
//!
//! `rollback` runs the same command with the binary
//! `apply` recorded, until contract SQL has run. `contract` runs the held-back
//! removals whose hold period has passed, and is the only thing that does.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;
use std::time::Duration;

use attome_ops::evidence::{self, Check};
use attome_ops::release_manifest::verify_manifest;
use attome_ops::upgrade_apply as rules;
use attome_ops::upgrade_verify as verification;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cmd::output::{take_flag, take_value};
use crate::cmd::upgrade_check::{self, CheckArgs};

const USAGE: &str = "usage: attome upgrade apply --manifest <file> --new-binary <path> --restart <command> --ready-url <url> --base-url <url> --admin-key-file <path> --no-role-key-file <path> [--evidence-dir <dir>] [--pgbackrest-stanza <name>] [--config <path>] [--free-bytes <n>] [--rehearsal <file>] --yes\n       attome upgrade rollback --to <version> --restart <command> [--config <path>] --yes\n       attome upgrade contract --manifest <file> --dir <dir> [--config <path>] --yes";
/// Exit code of a refused or failed step.
const REFUSED: u8 = 5;
/// How long a restarted service has to answer ready.
const READY_WAIT: Duration = Duration::from_secs(120);
/// How many entities verification reads a first page of.
const SAMPLE_ENTITIES: u32 = 50;

/// The words of `--restart`, split on spaces and never given to a shell. Pure.
fn command_words(command: &str) -> Result<Vec<String>, String> {
    let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    if words.is_empty() {
        return Err(USAGE.to_owned());
    }
    Ok(words)
}

/// A restore point's name, which PostgreSQL limits to 63 bytes. Pure.
fn restore_point_name(to_version: &str, stamp: &str) -> String {
    format!("attome-upgrade-{to_version}-{stamp}")
        .chars()
        .take(63)
        .collect()
}

fn run_restart(words: &[String], binary: &str) -> Result<(), String> {
    let (program, rest) = words.split_first().ok_or(USAGE)?;
    let status = std::process::Command::new(program)
        .args(rest)
        .env("ATTOME_BINARY", binary)
        .status()
        .map_err(|error| format!("run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

fn run_migrate(binary: &str) -> Result<(), String> {
    let status = std::process::Command::new(binary)
        .arg("migrate")
        .status()
        .map_err(|error| format!("run {binary} migrate: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{binary} migrate exited with {status}"))
    }
}

/// Takes the incremental backup that goes with the restore point.
fn run_pgbackrest(stanza: &str) -> Result<(), String> {
    let status = std::process::Command::new("pgbackrest")
        .arg(format!("--stanza={stanza}"))
        .args(["backup", "--type=incr"])
        .status()
        .map_err(|error| format!("run pgbackrest: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("pgbackrest exited with {status}"))
    }
}

/// Runs the new binary's audit chain verifier.
fn run_audit_chain(binary: &str) -> Result<(), String> {
    let output = std::process::Command::new(binary)
        .arg("verify-audit-chain")
        .output()
        .map_err(|error| format!("run {binary} verify-audit-chain: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("verify-audit-chain exited with {}", output.status))
    }
}

fn read_key(path: &str) -> Result<String, String> {
    let key = std::fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))?;
    let key = key.trim().to_owned();
    if key.is_empty() {
        return Err(format!("{path} is empty"));
    }
    Ok(key)
}

/// What verification reads the running service with.
struct Probe {
    client: attome_outbound::http::Outbound,
    base: String,
    admin: String,
    no_role: String,
}

impl Probe {
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        key: &str,
    ) -> Result<(u16, Value), String> {
        let response = request
            .header("authorization", format!("ApiKey {key}"))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let body = response.json().await.unwrap_or(Value::Null);
        Ok((status, body))
    }

    async fn get(&self, path: &str, key: &str) -> Result<(u16, Value), String> {
        let url = format!("{}{path}", self.base);
        self.send(self.client.get(url), key).await
    }

    async fn sample_reads(&self) -> Result<Vec<(String, u16)>, String> {
        let path = format!("/api/v1/admin/entities?page=1&page_size={SAMPLE_ENTITIES}");
        let (status, listed) = self.get(&path, &self.admin).await?;
        if status != 200 {
            return Err(format!("listing entities answered {status}"));
        }
        let names: Vec<String> = listed["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["logicalname"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let mut reads = Vec::with_capacity(names.len());
        for name in names {
            let (status, _) = self.get(&format!("/api/v1/{name}"), &self.admin).await?;
            reads.push((name, status));
        }
        Ok(reads)
    }
}

/// Every check, each one running whatever the others found.
async fn run_checks(
    probe: &Probe,
    db: &attome_db::DbPool,
    ring: &attome_config::KeyRing,
    binary: &str,
    migrations: u32,
) -> Result<Vec<Check>, String> {
    let (applied, unfinished) = verification::migration_ledger(db)
        .await
        .map_err(|error| format!("read the migration ledger: {error}"))?;
    let (opened, failed) = attome_records::attr_crypto::sample_open(db, ring)
        .await
        .map_err(|error| format!("sample the sealed values: {error}"))?;
    let (denied, _) = probe
        .get("/api/v1/admin/api-usage/summary", &probe.no_role)
        .await?;
    let (drift_status, drift) = probe
        .get("/api/v1/admin/metadata/drift", &probe.admin)
        .await?;
    Ok(vec![
        verification::migration_check(applied, unfinished, migrations),
        verification::audit_chain_check(run_audit_chain(binary)),
        verification::sample_read_check(&probe.sample_reads().await?),
        verification::permission_check(denied),
        verification::metadata_check(drift_status, &drift),
        verification::decrypt_check(opened, failed),
    ])
}

/// Signs the report, stores it, and moves the upgrade through the API.
/// Answers whether it verified.
async fn record_verification(
    probe: &Probe,
    db: &attome_db::DbPool,
    key: &evidence::SigningKey,
    report: &evidence::Evidence,
    file: &std::path::Path,
) -> Result<bool, String> {
    evidence::write_signed(file, report, key).map_err(|error| error.to_string())?;
    let signed = evidence::sign(report, key).map_err(|error| error.to_string())?;
    let url = format!("{}/api/v1/ops/drills/evidence", probe.base);
    let (status, stored) = probe
        .send(probe.client.post(url).json(&signed), &probe.admin)
        .await?;
    if status != 200 && status != 201 {
        return Err(format!("storing the evidence answered {status}"));
    }
    let upgrade = report.drill_id;
    let version = rules::row_version(db, upgrade)
        .await
        .map_err(|error| format!("read the upgrade: {error}"))?;
    let url = format!("{}/api/v1/ops/upgrades/{upgrade}", probe.base);
    let body = json!({
        "status": if report.overall_ok { "verified" } else { "failed" },
        "verification_evidence_id": stored["id"],
    });
    let request = probe
        .client
        .patch(url)
        .header("if-match", format!("\"{version}\""))
        .json(&body);
    let (status, _) = probe.send(request, &probe.admin).await?;
    if status != 200 {
        return Err(format!("recording the outcome answered {status}"));
    }
    Ok(report.overall_ok)
}

/// What `apply` needs before it may change anything; an error refuses it.
fn signing_key(settings: &attome_config::AppConfig) -> Result<evidence::SigningKey, String> {
    let path = settings
        .ops
        .drill_signing_key_path
        .as_deref()
        .ok_or("ops.drill_signing_key_path is not set, so the evidence could not be signed")?;
    let key = evidence::read_signing_key(std::path::Path::new(path))
        .map_err(|error| error.to_string())?;
    if !settings
        .ops
        .drill_public_keys
        .contains(&evidence::public_key_base64(&key))
    {
        return Err("ops.drill_public_keys does not hold the signing key's public half".to_owned());
    }
    Ok(key)
}

async fn wait_ready(url: &str) -> Result<(), String> {
    // The server this machine just started: the operator names its URL, so
    // its host is listed private for this purpose (Q21-T1).
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("upgrade_ready").with_private_urls([url]),
        |builder| builder.timeout(Duration::from_secs(5)),
    )
    .map_err(|error| error.to_string())?;
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    loop {
        if let Ok(response) = client.get(url).send().await
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

async fn config_at(path: Option<&str>) -> Result<attome_config::AppConfig, String> {
    let path = path.map_or_else(attome_config::AppConfig::config_file_path, str::to_owned);
    crate::secret_sources::load_config_from(path)
        .await
        .map_err(|error| format!("load the configuration: {error}"))
}

/// The pool that may name restore points and run removals.
async fn owner_pool(config: &attome_config::AppConfig) -> Result<attome_db::DbPool, String> {
    attome_db::create_direct_pool(config)
        .await
        .map_err(|error| format!("connect the database: {error}"))
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))
}

fn apply(args: &[String]) -> Result<ExitCode, String> {
    let mut args = args.to_vec();
    let yes = take_flag(&mut args, "--yes");
    let manifest = take_value(&mut args, "--manifest")?.ok_or(USAGE)?;
    let new_binary = take_value(&mut args, "--new-binary")?.ok_or(USAGE)?;
    let restart = command_words(&take_value(&mut args, "--restart")?.ok_or(USAGE)?)?;
    let ready_url = take_value(&mut args, "--ready-url")?.ok_or(USAGE)?;
    let base_url = take_value(&mut args, "--base-url")?.ok_or(USAGE)?;
    let admin_key = read_key(&take_value(&mut args, "--admin-key-file")?.ok_or(USAGE)?)?;
    let no_role_key = read_key(&take_value(&mut args, "--no-role-key-file")?.ok_or(USAGE)?)?;
    let evidence_dir = take_value(&mut args, "--evidence-dir")?.unwrap_or_else(|| ".".to_owned());
    let stanza = take_value(&mut args, "--pgbackrest-stanza")?;
    let config = take_value(&mut args, "--config")?;
    let free_bytes = take_value(&mut args, "--free-bytes")?
        .map(|n| n.parse().map_err(|_| format!("--free-bytes: `{n}`")))
        .transpose()?;
    let verify_key = take_value(&mut args, "--key")?;
    let unsigned_reason = crate::cmd::verify::take_override(&mut args)?;
    // AB8-T8: the impact report `attome upgrade rehearse` wrote, kept with
    // the upgrade for the Upgrades page.
    let rehearsal: Option<Value> = take_value(&mut args, "--rehearsal")?
        .map(|path| {
            std::fs::read(&path)
                .map_err(|error| format!("read {path}: {error}"))
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes).map_err(|error| format!("{path}: {error}"))
                })
        })
        .transpose()?;
    if !args.is_empty() || !yes {
        return Err(USAGE.to_owned());
    }
    // AC7-T8: the new binary is the release's own, signed with the release
    // key, before anything runs it; an override is logged with its reason.
    let verified = crate::cmd::verify::check_file(
        &crate::cmd::verify::System,
        std::path::Path::new(&new_binary),
        crate::cmd::verify::key_path(verify_key.as_deref()).as_deref(),
    );
    if crate::cmd::verify::decide(
        &verified,
        &new_binary,
        unsigned_reason.as_deref(),
        &crate::cmd::verify::install_dir(),
    )? != 0
    {
        return Ok(ExitCode::from(REFUSED));
    }
    let bytes = std::fs::read(&manifest).map_err(|error| format!("read {manifest}: {error}"))?;
    let release = verify_manifest(&bytes, crate::release_keys::RELEASE_PUBLIC_KEYS)
        .map_err(|error| format!("{manifest}: {error}"))?;
    let migrations = release
        .migration_count
        .ok_or("the manifest names no migration_count, so the upgrade could not be verified")?;
    let report = upgrade_check::build_report(&CheckArgs {
        manifest,
        config: config.clone(),
        free_bytes,
        json: false,
    })?;
    upgrade_check::print(&report, false)?;
    if !report.passes() {
        println!("refused: the check has a failure, nothing was changed");
        return Ok(ExitCode::from(REFUSED));
    }
    let previous = std::env::current_exe()
        .map_err(|error| format!("find this binary: {error}"))?
        .display()
        .to_string();
    let mut record = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    record["previous_binary"] = json!(previous);
    // AB8-T8: what the release changes per module, in both languages, kept
    // with the upgrade so the upgrade page can show it without the manifest
    // file (the page filters it to the modules switched on).
    record["impact"] = json!(release.impact);
    if let Some(rehearsal) = rehearsal {
        record["rehearsal"] = rehearsal;
    }
    let name = restore_point_name(
        &report.to_version,
        &chrono::Utc::now().format("%Y%m%d%H%M%S").to_string(),
    );

    let runtime = runtime()?;
    let (db, id, settings, key) = runtime.block_on(async {
        let settings = config_at(config.as_deref()).await?;
        let key = signing_key(&settings)?;
        let db = owner_pool(&settings).await?;
        rules::create_restore_point(&db, &name)
            .await
            .map_err(|error| format!("name the restore point: {error}"))?;
        if let Some(stanza) = &stanza {
            run_pgbackrest(stanza)?;
        }
        let id = rules::record_start(
            &db,
            &report.from_version,
            &report.to_version,
            &name,
            &record,
        )
        .await
        .map_err(|error| format!("record the upgrade: {error}"))?;
        Ok::<_, String>((db, id, settings, key))
    })?;
    println!("safety point {name}, upgrade {id}");

    let steps = run_migrate(&new_binary)
        .and_then(|()| run_restart(&restart, &new_binary))
        .and_then(|()| runtime.block_on(wait_ready(&ready_url)));
    let outcome = steps.and_then(|()| {
        runtime.block_on(async {
            let probe = Probe {
                client: attome_outbound::http::client(
                    attome_outbound::http::Purpose::public("upgrade_probe")
                        .with_private_urls([base_url.as_str()]),
                    |builder| builder.timeout(Duration::from_secs(30)),
                )
                .map_err(|error| error.to_string())?,
                base: base_url.trim_end_matches('/').to_owned(),
                admin: admin_key,
                no_role: no_role_key,
            };
            let started = chrono::Utc::now();
            let ring = &settings.storage.attribute_encryption_key;
            let checks = run_checks(&probe, &db, ring, &new_binary, migrations).await?;
            let evidence =
                verification::evidence(id, started, chrono::Utc::now(), &report.to_version, checks);
            for check in &evidence.checks {
                let detail = check.detail.as_deref().unwrap_or_default();
                println!("{}: {:?}, {detail}", check.name, check.result);
            }
            let file = std::path::Path::new(&evidence_dir).join(format!("upgrade-{id}.json"));
            let verified = record_verification(&probe, &db, &key, &evidence, &file).await?;
            println!("evidence {}", file.display());
            Ok::<_, String>(verified)
        })
    });
    let rollback_hint = format!("Run `attome upgrade rollback --to {}`", report.to_version);
    match outcome {
        Ok(true) => {
            println!("upgraded to {}", report.to_version);
            Ok(ExitCode::SUCCESS)
        }
        Ok(false) => {
            println!("failed: verification did not pass. {rollback_hint} to go back");
            Ok(ExitCode::from(REFUSED))
        }
        Err(message) => {
            record_failed(&runtime, &db, id)?;
            println!("failed: {message}. {rollback_hint} to go back");
            Ok(ExitCode::from(REFUSED))
        }
    }
}

/// The upgrade could not reach the API, or stopped before it; the record is
/// direct because the service may be down.
fn record_failed(
    runtime: &tokio::runtime::Runtime,
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<(), String> {
    runtime
        .block_on(rules::record_status(db, id, "started", "failed"))
        .map(|_| ())
        .map_err(|error| format!("record the outcome: {error}"))
}

fn rollback(args: &[String]) -> Result<ExitCode, String> {
    let mut args = args.to_vec();
    let yes = take_flag(&mut args, "--yes");
    let version = take_value(&mut args, "--to")?.ok_or(USAGE)?;
    let restart = command_words(&take_value(&mut args, "--restart")?.ok_or(USAGE)?)?;
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() || !yes {
        return Err(USAGE.to_owned());
    }
    let runtime = runtime()?;
    let (db, upgrade) = runtime.block_on(async {
        let settings = config_at(config.as_deref()).await?;
        let db = attome_db::create_pool(&settings)
            .await
            .map_err(|error| format!("connect the database: {error}"))?;
        let upgrade = rules::upgrade_to(&db, &version)
            .await
            .map_err(|error| format!("read the upgrade: {error}"))?
            .ok_or_else(|| format!("no upgrade to {version} is recorded"))?;
        Ok::<_, String>((db, upgrade))
    })?;
    if let Err(message) = rules::rollback_allowed(&upgrade, chrono::Utc::now()) {
        println!("refused: {message}");
        return Ok(ExitCode::from(REFUSED));
    }
    if !attome_ops::upgrades::transition_allowed(&upgrade.status, "rolled_back") {
        println!("refused: the upgrade is {}", upgrade.status);
        return Ok(ExitCode::from(REFUSED));
    }
    let previous = upgrade
        .check_report
        .as_ref()
        .and_then(|report| report["previous_binary"].as_str())
        .ok_or("the upgrade did not record its previous binary")?;
    run_restart(&restart, previous)?;
    runtime
        .block_on(rules::record_status(
            &db,
            upgrade.id,
            &upgrade.status,
            "rolled_back",
        ))
        .map_err(|error| format!("record the rollback: {error}"))?;
    println!("rolled back to {previous}");
    Ok(ExitCode::SUCCESS)
}

fn contract(args: &[String]) -> Result<ExitCode, String> {
    let mut args = args.to_vec();
    let yes = take_flag(&mut args, "--yes");
    let manifest = take_value(&mut args, "--manifest")?.ok_or(USAGE)?;
    let dir = take_value(&mut args, "--dir")?.ok_or(USAGE)?;
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() || !yes {
        return Err(USAGE.to_owned());
    }
    let bytes = std::fs::read(&manifest).map_err(|error| format!("read {manifest}: {error}"))?;
    let manifest = verify_manifest(&bytes, crate::release_keys::RELEASE_PUBLIC_KEYS)
        .map_err(|error| format!("{manifest}: {error}"))?;
    runtime()?.block_on(async {
        let settings = config_at(config.as_deref()).await?;
        let db = owner_pool(&settings).await?;
        let upgrade = rules::upgrade_to(&db, &manifest.version)
            .await
            .map_err(|error| format!("read the upgrade: {error}"))?
            .ok_or_else(|| format!("no upgrade to {} is recorded", manifest.version))?;
        let finished = upgrade
            .finished_at
            .filter(|_| upgrade.status == "verified")
            .ok_or_else(|| rules::ContractError::NotFinished.to_string())?;
        let due = rules::eligible(&manifest.contract_sql, finished, chrono::Utc::now());
        if due.is_empty() {
            println!("no contract SQL is past its hold period");
            return Ok(ExitCode::SUCCESS);
        }
        // Every file is checked before the first one runs.
        let mut files = Vec::with_capacity(due.len());
        for file in due {
            let path = std::path::Path::new(&dir).join(&file.file);
            let bytes = std::fs::read(&path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            rules::check_file(file, &bytes).map_err(|error| error.to_string())?;
            let sql = String::from_utf8(bytes).map_err(|_| format!("{} is not text", file.file))?;
            files.push((file.file.clone(), sql));
        }
        for (file, sql) in files {
            let ran = rules::run_contract_file(&db, upgrade.id, &file, &sql)
                .await
                .map_err(|error| format!("{file}: {error}"))?;
            println!(
                "{file}: {}",
                if ran { "applied" } else { "already applied" }
            );
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// `attome upgrade apply|rollback|contract`.
pub fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [command, rest @ ..] if command == "apply" => apply(rest),
        [command, rest @ ..] if command == "rollback" => rollback(rest),
        [command, rest @ ..] if command == "contract" => contract(rest),
        _ => Err(USAGE.to_owned()),
    };
    outcome.unwrap_or_else(|message| {
        println!("{message}");
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restart_command_needs_a_word() {
        assert_eq!(
            command_words("sc.exe  start attome").expect("words"),
            ["sc.exe", "start", "attome"]
        );
        assert!(command_words("  ").is_err());
    }

    #[test]
    fn a_restore_point_name_fits_postgres() {
        let name = restore_point_name(&"9".repeat(64), "20261031");
        assert_eq!(name.len(), 63);
        assert!(name.starts_with("attome-upgrade-9"));
    }
}

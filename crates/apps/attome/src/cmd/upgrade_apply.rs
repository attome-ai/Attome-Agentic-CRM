//! AB8-T7: `attome upgrade apply`, `rollback` and `contract`.
//!
//! ```text
//! attome upgrade apply --manifest <file> --new-binary <path> --restart <command>
//!                      --ready-url <url> [--config <path>] [--free-bytes <n>] --yes
//! attome upgrade rollback --to <version> --restart <command> [--config <path>] --yes
//! attome upgrade contract --manifest <file> --dir <dir> [--config <path>] --yes
//! ```
//!
//! `apply` runs from the old binary: it refuses a failing check, names a
//! restore point, records the upgrade, runs the new binary's `migrate`, runs
//! the restart command with `ATTOME_BINARY` naming the binary to start, and
//! waits for the ready URL. `rollback` runs the same command with the binary
//! `apply` recorded, until contract SQL has run. `contract` runs the held-back
//! removals whose hold period has passed, and is the only thing that does.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;
use std::time::Duration;

use attome_ops::release_manifest::verify_manifest;
use attome_ops::upgrade_apply as rules;
use serde_json::json;

use crate::cmd::output::{take_flag, take_value};
use crate::cmd::upgrade_check::{self, CheckArgs};

const USAGE: &str = "usage: attome upgrade apply --manifest <file> --new-binary <path> --restart <command> --ready-url <url> [--config <path>] [--free-bytes <n>] --yes\n       attome upgrade rollback --to <version> --restart <command> [--config <path>] --yes\n       attome upgrade contract --manifest <file> --dir <dir> [--config <path>] --yes";
/// Exit code of a refused or failed step.
const REFUSED: u8 = 5;
/// How long a restarted service has to answer ready.
const READY_WAIT: Duration = Duration::from_secs(120);

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

async fn wait_ready(url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
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
    let config = take_value(&mut args, "--config")?;
    let free_bytes = take_value(&mut args, "--free-bytes")?
        .map(|n| n.parse().map_err(|_| format!("--free-bytes: `{n}`")))
        .transpose()?;
    if !args.is_empty() || !yes {
        return Err(USAGE.to_owned());
    }
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
    let name = restore_point_name(
        &report.to_version,
        &chrono::Utc::now().format("%Y%m%d%H%M%S").to_string(),
    );

    let runtime = runtime()?;
    let (db, id) = runtime.block_on(async {
        let settings = config_at(config.as_deref()).await?;
        let db = owner_pool(&settings).await?;
        rules::create_restore_point(&db, &name)
            .await
            .map_err(|error| format!("name the restore point: {error}"))?;
        let id = rules::record_start(
            &db,
            &report.from_version,
            &report.to_version,
            &name,
            &record,
        )
        .await
        .map_err(|error| format!("record the upgrade: {error}"))?;
        Ok::<_, String>((db, id))
    })?;
    println!("safety point {name}, upgrade {id}");

    let steps = run_migrate(&new_binary)
        .and_then(|()| run_restart(&restart, &new_binary))
        .and_then(|()| runtime.block_on(wait_ready(&ready_url)));
    let status = if steps.is_ok() { "verified" } else { "failed" };
    runtime
        .block_on(rules::record_status(&db, id, "started", status))
        .map_err(|error| format!("record the outcome: {error}"))?;
    match steps {
        Ok(()) => {
            println!("upgraded to {}", report.to_version);
            Ok(ExitCode::SUCCESS)
        }
        Err(message) => {
            println!(
                "failed: {message}. Run `attome upgrade rollback --to {}` to go back",
                report.to_version
            );
            Ok(ExitCode::from(REFUSED))
        }
    }
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

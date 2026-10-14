//! The daily local database backup (roadmap U6-T1), on Windows and Linux.
//!
//! Once a day at `backup.hour` (UTC) the server runs `pg_dump` in custom
//! format into `backup.dir` (default: a `backups` folder next to the
//! configuration file), names the archive by its UTC time
//! (`attome-YYYYMMDD-HHMM.dump`), and keeps the newest `backup.keep`.
//! `pg_restore` restores one into an empty database. `attome backup now` runs
//! one at once.
//!
//! The password reaches `pg_dump` through `PGPASSWORD` in its environment,
//! never on its command line, where any user of the machine could read it.
//! An archive is written under a temporary name and renamed when `pg_dump`
//! succeeds, so a crash never leaves a half archive that looks complete.
//!
//! Same disk as the database by default: it protects against mistakes and
//! corruption, not against losing the disk; point `backup.dir` at another
//! disk or a network share for that. pgBackRest (incremental backups and
//! point-in-time recovery) is the Linux option for larger deployments.

use std::path::{Path, PathBuf};
use std::time::Duration;

use attome_config::AppConfig;
use chrono::{DateTime, Timelike, Utc};

/// The longest one backup may run.
const BACKUP_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const PREFIX: &str = "attome-";
const SUFFIX: &str = ".dump";

/// An archive's file name for `at`: sortable by name, newest last.
pub fn archive_name(at: DateTime<Utc>) -> String {
    format!("{PREFIX}{}{SUFFIX}", at.format("%Y%m%d-%H%M"))
}

/// The archives to delete so that only the newest `keep` remain. Names that
/// are not this module's archives are never touched.
pub fn to_prune(names: &[String], keep: usize) -> Vec<String> {
    let mut ours: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .collect();
    ours.sort();
    let surplus = ours.len().saturating_sub(keep.max(1));
    ours.into_iter().take(surplus).cloned().collect()
}

/// How long to wait from `now` until the next `hour`:00 UTC.
pub fn until_next(now: DateTime<Utc>, hour: u32) -> Duration {
    let today = now
        .date_naive()
        .and_hms_opt(hour.min(23), 0, 0)
        .map(|t| t.and_utc());
    let next = match today {
        Some(t) if t > now => t,
        Some(t) => t + chrono::Duration::days(1),
        None => now + chrono::Duration::days(1),
    };
    (next - now).to_std().unwrap_or(Duration::from_secs(60))
}

/// Where archives go.
pub fn backup_dir(config: &AppConfig) -> PathBuf {
    match config
        .backup
        .dir
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(dir) => PathBuf::from(dir),
        None => {
            let config_file = PathBuf::from(AppConfig::config_file_path());
            config_file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .join("backups")
        }
    }
}

/// The `pg_dump` arguments: everything but the password.
pub fn pg_dump_args(config: &AppConfig, file: &Path) -> Vec<String> {
    let db = &config.database;
    vec![
        "--format=custom".into(),
        "--no-owner".into(),
        format!("--file={}", file.display()),
        format!("--host={}", db.host),
        format!("--port={}", db.port),
        format!("--username={}", db.user),
        format!("--dbname={}", db.dbname),
    ]
}

/// Runs one backup now and prunes old ones. Returns the archive's path.
pub async fn run_once(config: &AppConfig) -> Result<PathBuf, String> {
    let dir = backup_dir(config);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let name = archive_name(Utc::now());
    let partial = dir.join(format!("{name}.partial"));
    let file = dir.join(&name);
    let program = config
        .backup
        .pg_dump
        .clone()
        .unwrap_or_else(|| "pg_dump".to_owned());
    let mut command = tokio::process::Command::new(&program);
    command
        .args(pg_dump_args(config, &partial))
        .kill_on_drop(true);
    if let Some(password) = config.database.password.as_deref() {
        command.env("PGPASSWORD", password);
    }
    let output = tokio::time::timeout(BACKUP_TIMEOUT, command.output())
        .await
        .map_err(|_| "pg_dump did not finish within two hours".to_owned())?
        .map_err(|e| format!("cannot run {program}: {e} (install the PostgreSQL client tools or set backup.pg_dump)"))?;
    if !output.status.success() {
        let _ = tokio::fs::remove_file(&partial).await;
        let reason = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "pg_dump failed ({}): {}",
            output.status,
            reason.lines().last().unwrap_or_default()
        ));
    }
    tokio::fs::rename(&partial, &file)
        .await
        .map_err(|e| format!("cannot finish {}: {e}", file.display()))?;
    prune(&dir, config.backup.keep as usize).await;
    Ok(file)
}

async fn prune(dir: &Path, keep: usize) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    let mut names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    for name in to_prune(&names, keep) {
        if let Err(error) = tokio::fs::remove_file(dir.join(&name)).await {
            tracing::warn!(%error, archive = %name, "backup: an old archive could not be removed");
        }
    }
}

/// Starts the daily backup when `backup.enabled`. Process-lifetime
/// supervision: a missed day is logged and the next one runs as usual.
pub fn spawn_daily(config: std::sync::Arc<AppConfig>) {
    if !config.backup.enabled {
        tracing::info!("backup: the daily local backup is off (backup.enabled = false)");
        return;
    }
    // One process on one machine: Solo. Several nodes would each dump the
    // same database; they use pgBackRest or the database host's backups.
    if config.cache.backend != attome_config::CacheBackend::Memory {
        tracing::info!(
            "backup: the daily local backup runs on Solo only; this deployment uses \
             pgBackRest or its database host's backups"
        );
        return;
    }
    tracing::info!(
        dir = %backup_dir(&config).display(),
        hour = config.backup.hour,
        keep = config.backup.keep,
        "backup: the daily local backup is on; archives stay on this machine unless backup.dir points elsewhere"
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(until_next(Utc::now(), config.backup.hour)).await;
            let started = std::time::Instant::now();
            match run_once(&config).await {
                Ok(file) => {
                    tracing::info!(file = %file.display(), seconds = started.elapsed().as_secs(), "backup: done");
                }
                Err(error) => {
                    tracing::error!(%error, "backup: the daily backup failed");
                }
            }
            // Never twice in the same hour, however quick the run was.
            let past = Utc::now().minute() as u64 * 60;
            tokio::time::sleep(Duration::from_secs(3600_u64.saturating_sub(past).max(60))).await;
        }
    });
}

/// `attome backup now`: one backup at once, whatever `backup.enabled` says.
#[allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
#[tokio::main]
pub async fn run_now() -> std::process::ExitCode {
    let config = match AppConfig::from_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("attome backup: cannot read the configuration: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match run_once(&config).await {
        Ok(file) => {
            println!("backup written: {}", file.display());
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("attome backup: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The `pg_restore` beside the configured `pg_dump`, or the one on the PATH.
pub fn pg_restore_program(config: &AppConfig) -> String {
    match config.backup.pg_dump.as_deref().map(Path::new) {
        Some(dump) if dump.parent().is_some_and(|p| !p.as_os_str().is_empty()) => {
            let name = if cfg!(windows) {
                "pg_restore.exe"
            } else {
                "pg_restore"
            };
            dump.with_file_name(name).display().to_string()
        }
        _ => "pg_restore".to_owned(),
    }
}

/// The `pg_restore` arguments: the archive replaces what the database holds,
/// all or nothing.
pub fn pg_restore_args(config: &AppConfig, file: &Path) -> Vec<String> {
    let db = &config.database;
    vec![
        "--clean".into(),
        "--if-exists".into(),
        "--no-owner".into(),
        "--single-transaction".into(),
        "--exit-on-error".into(),
        format!("--host={}", db.host),
        format!("--port={}", db.port),
        format!("--username={}", db.user),
        format!("--dbname={}", db.dbname),
        file.display().to_string(),
    ]
}

/// The newest archive among `names` (archives sort by their time).
pub fn latest_archive(names: &[String]) -> Option<&String> {
    names
        .iter()
        .filter(|n| n.starts_with("attome-") && n.ends_with(".dump"))
        .max()
}

/// Which archive `target` names: `latest`, a path, or a file in `backup.dir`.
async fn archive_for(config: &AppConfig, target: &str) -> Result<PathBuf, String> {
    let dir = backup_dir(config);
    if target == "latest" {
        let mut entries = tokio::fs::read_dir(&dir)
            .await
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let mut names = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        return latest_archive(&names)
            .map(|n| dir.join(n))
            .ok_or_else(|| format!("no backup in {}", dir.display()));
    }
    let given = PathBuf::from(target);
    if tokio::fs::metadata(&given).await.is_ok() {
        return Ok(given);
    }
    let in_dir = dir.join(target);
    if tokio::fs::metadata(&in_dir).await.is_ok() {
        return Ok(in_dir);
    }
    Err(format!(
        "no backup named {target} here or in {}",
        dir.display()
    ))
}

/// `attome restore <archive | latest> --yes` (roadmap U6-T2): puts the
/// database back to a backup. Stop the server first. A backup of the
/// database as it is now is written before anything changes, and
/// `pg_restore` runs in one transaction, so a failure leaves the database
/// as it was.
#[allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
#[tokio::main]
pub async fn run_restore(args: Vec<String>) -> std::process::ExitCode {
    let confirmed = args.iter().any(|a| a == "--yes");
    let Some(target) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: attome restore <archive | latest> --yes");
        return std::process::ExitCode::from(2);
    };
    let config = match AppConfig::from_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("attome restore: cannot read the configuration: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let archive = match archive_for(&config, target).await {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("attome restore: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if !confirmed {
        println!(
            "This replaces everything in database {} with {}.\n\
             Stop the Attome server first, then run again with --yes.",
            config.database.dbname,
            archive.display()
        );
        return std::process::ExitCode::from(2);
    }
    match run_once(&config).await {
        Ok(safety) => println!("the database as it was: {}", safety.display()),
        Err(error) => {
            eprintln!("attome restore: the safety backup failed, nothing was changed: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    let program = pg_restore_program(&config);
    let mut command = tokio::process::Command::new(&program);
    command
        .args(pg_restore_args(&config, &archive))
        .kill_on_drop(true);
    if let Some(password) = config.database.password.as_deref() {
        command.env("PGPASSWORD", password);
    }
    let output = match tokio::time::timeout(BACKUP_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            eprintln!("attome restore: cannot run {program}: {error}");
            return std::process::ExitCode::FAILURE;
        }
        Err(_) => {
            eprintln!("attome restore: pg_restore did not finish within two hours");
            return std::process::ExitCode::FAILURE;
        }
    };
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "attome restore: pg_restore failed ({}); the database is unchanged: {}",
            output.status,
            reason.lines().last().unwrap_or_default()
        );
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "restored {} into {}",
        archive.display(),
        config.database.dbname
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn restore_picks_the_newest_archive_and_replaces_in_one_transaction() {
        let names: Vec<String> = [
            "attome-20261010-0200.dump",
            "attome-20261014-0200.dump",
            "attome-20261012-0200.dump",
            "attome-20261015-0200.dump.partial",
            "notes.txt",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(
            latest_archive(&names).map(String::as_str),
            Some("attome-20261014-0200.dump")
        );
        assert_eq!(latest_archive(&[]), None);

        let config: AppConfig =
            serde_json::from_str(include_str!("../../../../config.example.json")).unwrap();
        let args = pg_restore_args(&config, Path::new("a.dump"));
        for flag in [
            "--clean",
            "--if-exists",
            "--single-transaction",
            "--exit-on-error",
        ] {
            assert!(args.contains(&flag.to_owned()), "{flag}");
        }
        assert_eq!(args.last().map(String::as_str), Some("a.dump"));
        assert!(!args.iter().any(|a| a.contains("password")));
        assert_eq!(pg_restore_program(&config), "pg_restore");
    }

    #[test]
    fn archives_are_named_by_time_and_the_oldest_are_pruned() {
        let at = Utc.with_ymd_and_hms(2026, 10, 14, 2, 0, 0).unwrap();
        assert_eq!(archive_name(at), "attome-20261014-0200.dump");
        let names: Vec<String> = [
            "attome-20261010-0200.dump",
            "attome-20261012-0200.dump",
            "attome-20261011-0200.dump",
            "attome-20261013-0200.dump.partial",
            "notes.txt",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(to_prune(&names, 2), ["attome-20261010-0200.dump"]);
        assert!(to_prune(&names, 5).is_empty());
        // Keep is at least one, whatever the setting says.
        assert_eq!(to_prune(&names, 0).len(), 2);
    }

    #[test]
    fn the_next_run_is_the_coming_hour() {
        let before = Utc.with_ymd_and_hms(2026, 10, 14, 1, 30, 0).unwrap();
        assert_eq!(until_next(before, 2), Duration::from_secs(30 * 60));
        let after = Utc.with_ymd_and_hms(2026, 10, 14, 2, 0, 0).unwrap();
        assert_eq!(until_next(after, 2), Duration::from_secs(24 * 3600));
    }

    #[test]
    fn the_password_is_never_an_argument() {
        let mut config: AppConfig =
            serde_json::from_str(include_str!("../../../../config.example.json")).unwrap();
        config.database.password = Some("s3cret".into());
        let args = pg_dump_args(&config, Path::new("x.dump"));
        assert!(args.iter().all(|a| !a.contains("s3cret")));
        assert!(args.contains(&"--format=custom".to_owned()));
    }
}

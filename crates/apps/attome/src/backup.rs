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
//! Right after the database, the object store's files are copied into
//! `files/` in the same folder (only new or changed objects are read again),
//! and `attome-YYYYMMDD-HHMM.files.json` lists each file the backup holds
//! with its size and SHA-256, so a restore puts back exactly those.
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
/// Beside each archive: the files it holds.
const FILES_SUFFIX: &str = ".files.json";
/// The folder under `backup.dir` that holds file copies.
const FILES_DIR: &str = "files";
/// The mirror's record of what it holds, so unchanged objects are not
/// read again.
const INDEX_FILE: &str = ".index.json";
/// Left in the backup folder by `attome restore`: the next boot must apply
/// the erasure ledger before it serves (R2-T1), and removes it once done.
pub const RESTORE_PENDING: &str = "restore-pending";
/// One line per restore drill (U6-T3), newest last.
pub const DRILLS_FILE: &str = "drills.jsonl";

/// The evidence one restore drill leaves (U6-T3).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DrillRecord {
    pub at: DateTime<Utc>,
    pub archive: String,
    pub seconds: u64,
    pub passed: bool,
    /// What was checked, or why the drill failed.
    pub detail: String,
}

/// The throwaway database a drill restores into.
pub fn drill_database_name(at: DateTime<Utc>) -> String {
    format!("attome_drill_{}", at.format("%Y%m%d%H%M%S"))
}

pub(crate) fn connect_options(
    config: &AppConfig,
    dbname: &str,
) -> sqlx::postgres::PgConnectOptions {
    let db = &config.database;
    let mut options = sqlx::postgres::PgConnectOptions::new()
        .host(&db.host)
        .port(db.port)
        .username(&db.user)
        .database(dbname);
    if let Some(password) = db.password.as_ref().map(|p| p.expose()) {
        options = options.password(password);
    }
    options
}

/// The checks a restored copy must pass: migrations applied, entities
/// registered, people present.
const DRILL_CHECKS: [(&str, &str); 3] = [
    ("migrations", "SELECT COUNT(*) FROM _sqlx_migrations"),
    ("entities", "SELECT COUNT(*) FROM entity_info"),
    ("people", "SELECT COUNT(*) FROM user_account"),
];

/// Restores `archive` into a new throwaway database, runs [`DRILL_CHECKS`]
/// there, and drops it. Returns what the checks found.
async fn drill_into(config: &AppConfig, archive: &Path, temp: &str) -> Result<String, String> {
    use sqlx::{Connection, Executor};
    let mut admin =
        sqlx::PgConnection::connect_with(&connect_options(config, &config.database.dbname))
            .await
            .map_err(|e| format!("cannot connect: {e}"))?;
    let outcome = async {
        restore_into(config, &mut admin, archive, temp).await?;
        let mut copy = sqlx::PgConnection::connect_with(&connect_options(config, temp))
            .await
            .map_err(|e| format!("cannot open the restored copy: {e}"))?;
        let mut found = Vec::new();
        for (name, sql) in DRILL_CHECKS {
            let count: i64 = sqlx::query_scalar(sql)
                .fetch_one(&mut copy)
                .await
                .map_err(|e| format!("check {name} failed: {e}"))?;
            if count == 0 {
                return Err(format!("check {name} found nothing"));
            }
            found.push(format!("{name}={count}"));
        }
        let _ = copy.close().await;
        Ok(found.join(", "))
    }
    .await;
    if let Err(error) = admin
        .execute(format!("DROP DATABASE IF EXISTS \"{temp}\" WITH (FORCE)").as_str())
        .await
    {
        tracing::warn!(%error, database = %temp, "restore drill: the throwaway database was not dropped");
    }
    outcome
}

/// Creates the database `name` (letters, digits and underscores, checked by
/// the caller; never request input) over `admin` and restores `archive`
/// into it with `pg_restore`. T5-T1's sandbox copies use it too.
pub(crate) async fn restore_into(
    config: &AppConfig,
    admin: &mut sqlx::PgConnection,
    archive: &Path,
    name: &str,
) -> Result<(), String> {
    use sqlx::Executor;
    admin
        .execute(format!("CREATE DATABASE \"{name}\"").as_str())
        .await
        .map_err(|e| format!("cannot create {name}: {e}"))?;
    let program = pg_restore_program(config);
    let mut command = tokio::process::Command::new(&program);
    command
        .args([
            "--no-owner".to_owned(),
            "--exit-on-error".to_owned(),
            format!("--host={}", config.database.host),
            format!("--port={}", config.database.port),
            format!("--username={}", config.database.user),
            format!("--dbname={name}"),
            archive.display().to_string(),
        ])
        .kill_on_drop(true);
    if let Some(password) = config.database.password.as_ref().map(|p| p.expose()) {
        command.env("PGPASSWORD", password);
    }
    let output = tokio::time::timeout(BACKUP_TIMEOUT, command.output())
        .await
        .map_err(|_| "pg_restore did not finish within two hours".to_owned())?
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "pg_restore failed ({}): {}",
            output.status,
            reason.lines().last().unwrap_or_default()
        ));
    }
    Ok(())
}

/// U6-T3: restores the newest backup into a throwaway database, checks it,
/// drops it, and appends the result to [`DRILLS_FILE`] in the backup folder.
pub async fn run_drill(config: &AppConfig) -> Result<DrillRecord, String> {
    let archive = archive_for(config, "latest").await?;
    let started = std::time::Instant::now();
    let at = Utc::now();
    let outcome = drill_into(config, &archive, &drill_database_name(at)).await;
    let record = DrillRecord {
        at,
        archive: archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        seconds: started.elapsed().as_secs(),
        passed: outcome.is_ok(),
        detail: match &outcome {
            Ok(found) => found.clone(),
            Err(error) => error.clone(),
        },
    };
    let line = serde_json::to_string(&record).map_err(|e| e.to_string())? + "\n";
    let path = backup_dir(config).join(DRILLS_FILE);
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    tokio::io::AsyncWriteExt::write_all(&mut file, line.as_bytes())
        .await
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(record)
}

/// R11-T1: the newest restore drill recorded in [`DRILLS_FILE`], if any.
pub async fn last_drill(config: &AppConfig) -> Option<DrillRecord> {
    let path = backup_dir(config).join(DRILLS_FILE);
    let text = tokio::fs::read_to_string(&path).await.ok()?;
    last_drill_in(&text)
}

/// The newest well-formed drill line of a drills file. Pure.
pub fn last_drill_in(text: &str) -> Option<DrillRecord> {
    text.lines()
        .rev()
        .find_map(|line| serde_json::from_str::<DrillRecord>(line).ok())
}

/// Whether today's run also drills: the first day of each month.
pub fn drill_due(now: DateTime<Utc>) -> bool {
    use chrono::Datelike;
    now.day() == 1
}

/// One file a backup holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileCopy {
    pub key: String,
    pub size: u64,
    pub sha256: String,
    /// The store's entity tag when the copy was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e_tag: Option<String>,
}

/// The manifest beside `archive` (`attome-….dump` → `attome-….files.json`).
pub fn manifest_name(archive: &str) -> String {
    format!("{}{FILES_SUFFIX}", archive.trim_end_matches(SUFFIX))
}

/// Where the copy of `key` lives under the mirror folder. Keys use `/`;
/// anything that could leave the folder (`..`, a drive or root) is refused.
pub fn mirror_path(mirror: &Path, key: &str) -> Option<PathBuf> {
    let mut path = mirror.to_path_buf();
    for part in key.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':']) {
            return None;
        }
        path.push(part);
    }
    Some(path)
}

/// Whether the mirror's copy can stand for `entry` without reading it again:
/// same size and the same entity tag.
fn unchanged(copy: Option<&FileCopy>, entry: &attome_storage::mirror::ObjectEntry) -> bool {
    copy.is_some_and(|c| c.size == entry.size && c.e_tag.is_some() && c.e_tag == entry.e_tag)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Copies the object store's files into `dir/files/` and writes the
/// manifest beside `archive`. Returns how many files the backup holds.
async fn backup_files(config: &AppConfig, dir: &Path, archive: &str) -> Result<usize, String> {
    let client = attome_storage::create_storage_client(config)
        .await
        .map_err(|e| format!("cannot reach the file store: {e}"))?;
    let entries = attome_storage::mirror::list_all(&client)
        .await
        .map_err(|e| format!("cannot list the file store: {e}"))?;
    let mirror = dir.join(FILES_DIR);
    tokio::fs::create_dir_all(&mirror)
        .await
        .map_err(|e| format!("cannot create {}: {e}", mirror.display()))?;
    let index_path = mirror.join(INDEX_FILE);
    let mut index: std::collections::BTreeMap<String, FileCopy> = tokio::fs::read(&index_path)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let mut manifest = Vec::with_capacity(entries.len());
    for entry in &entries {
        let Some(target) = mirror_path(&mirror, &entry.key) else {
            tracing::warn!(key = %entry.key, "backup: a file key cannot be copied to disk; skipped");
            continue;
        };
        let have_copy = tokio::fs::metadata(&target).await.is_ok();
        if !(have_copy && unchanged(index.get(&entry.key), entry)) {
            let bytes = attome_storage::mirror::read_object(&client, &entry.key)
                .await
                .map_err(|e| format!("cannot read {}: {e}", entry.key))?;
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            let partial = target.with_extension("partial");
            tokio::fs::write(&partial, &bytes)
                .await
                .map_err(|e| format!("cannot write {}: {e}", partial.display()))?;
            tokio::fs::rename(&partial, &target)
                .await
                .map_err(|e| format!("cannot finish {}: {e}", target.display()))?;
            index.insert(
                entry.key.clone(),
                FileCopy {
                    key: entry.key.clone(),
                    size: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    e_tag: entry.e_tag.clone(),
                },
            );
        }
        if let Some(copy) = index.get(&entry.key) {
            manifest.push(copy.clone());
        }
    }
    let index_json = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    tokio::fs::write(&index_path, index_json)
        .await
        .map_err(|e| format!("cannot write {}: {e}", index_path.display()))?;
    let manifest_path = dir.join(manifest_name(archive));
    let manifest_json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    tokio::fs::write(&manifest_path, manifest_json)
        .await
        .map_err(|e| format!("cannot write {}: {e}", manifest_path.display()))?;
    Ok(manifest.len())
}

/// Removes file copies no kept manifest lists any more.
async fn prune_files(dir: &Path) {
    let mirror = dir.join(FILES_DIR);
    let index_path = mirror.join(INDEX_FILE);
    let Ok(bytes) = tokio::fs::read(&index_path).await else {
        return;
    };
    let Ok(mut index) =
        serde_json::from_slice::<std::collections::BTreeMap<String, FileCopy>>(&bytes)
    else {
        return;
    };
    let mut kept = std::collections::BTreeSet::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with(PREFIX) && name.ends_with(FILES_SUFFIX)) {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(entry.path()).await else {
            // An unreadable manifest: keep every copy rather than guess.
            return;
        };
        let Ok(files) = serde_json::from_slice::<Vec<FileCopy>>(&bytes) else {
            return;
        };
        kept.extend(files.into_iter().map(|f| f.key));
    }
    let gone: Vec<String> = index
        .keys()
        .filter(|k| !kept.contains(*k))
        .cloned()
        .collect();
    for key in gone {
        if let Some(path) = mirror_path(&mirror, &key)
            && let Err(error) = tokio::fs::remove_file(&path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, %key, "backup: an old file copy could not be removed");
            continue;
        }
        index.remove(&key);
    }
    if let Ok(json) = serde_json::to_vec(&index)
        && let Err(error) = tokio::fs::write(&index_path, json).await
    {
        tracing::warn!(%error, "backup: the file index could not be rewritten");
    }
}

/// Puts back every file the manifest beside `archive` lists that the store
/// is missing or holds at another size, after checking the copy's SHA-256.
/// Returns how many files were written.
async fn restore_files(config: &AppConfig, archive: &Path) -> Result<usize, String> {
    let Some(dir) = archive.parent() else {
        return Ok(0);
    };
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let manifest_path = dir.join(manifest_name(&name));
    let Ok(bytes) = tokio::fs::read(&manifest_path).await else {
        return Ok(0);
    };
    let files: Vec<FileCopy> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let client = attome_storage::create_storage_client(config)
        .await
        .map_err(|e| format!("cannot reach the file store: {e}"))?;
    let present: std::collections::BTreeMap<String, u64> =
        attome_storage::mirror::list_all(&client)
            .await
            .map_err(|e| format!("cannot list the file store: {e}"))?
            .into_iter()
            .map(|e| (e.key, e.size))
            .collect();
    let mirror = dir.join(FILES_DIR);
    let mut written = 0;
    for file in files {
        if present.get(&file.key) == Some(&file.size) {
            continue;
        }
        let path = mirror_path(&mirror, &file.key)
            .ok_or_else(|| format!("the manifest names an unsafe key: {}", file.key))?;
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| format!("the copy of {} is missing: {e}", file.key))?;
        if sha256_hex(&bytes) != file.sha256 {
            return Err(format!(
                "the copy of {} does not match its checksum",
                file.key
            ));
        }
        attome_storage::mirror::write_object(&client, &file.key, bytes)
            .await
            .map_err(|e| format!("cannot write {}: {e}", file.key))?;
        written += 1;
    }
    Ok(written)
}

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
    config.backup.resolved_dir()
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
    if let Some(password) = config.database.password.as_ref().map(|p| p.expose()) {
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
    if config.backup.files {
        // The database backup stands on its own; a file store that cannot
        // be copied is reported, and the next run tries again.
        match backup_files(config, &dir, &name).await {
            Ok(count) => tracing::info!(files = count, "backup: files copied"),
            Err(error) => tracing::error!(%error, "backup: the files were not copied"),
        }
    }
    prune(&dir, config.backup.keep as usize).await;
    prune_files(&dir).await;
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
        let manifest = manifest_name(&name);
        if let Err(error) = tokio::fs::remove_file(dir.join(&manifest)).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, %manifest, "backup: an old file list could not be removed");
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
                    if drill_due(Utc::now()) {
                        match run_drill(&config).await {
                            Ok(drill) if drill.passed => tracing::info!(
                                seconds = drill.seconds, detail = %drill.detail,
                                "backup: the monthly restore drill passed"
                            ),
                            Ok(drill) => tracing::error!(
                                detail = %drill.detail,
                                "backup: the monthly restore drill failed"
                            ),
                            Err(error) => {
                                tracing::error!(%error, "backup: the monthly restore drill could not run")
                            }
                        }
                    }
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

/// `attome backup drill`: one restore drill now.
#[allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
#[tokio::main]
pub async fn run_drill_now() -> std::process::ExitCode {
    let config = match AppConfig::from_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("attome backup drill: cannot read the configuration: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match run_drill(&config).await {
        Ok(drill) if drill.passed => {
            println!(
                "restore drill passed in {}s on {}: {}",
                drill.seconds, drill.archive, drill.detail
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(drill) => {
            eprintln!(
                "attome backup drill: failed on {}: {}",
                drill.archive, drill.detail
            );
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("attome backup drill: {error}");
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
pub(crate) async fn archive_for(config: &AppConfig, target: &str) -> Result<PathBuf, String> {
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
    if let Some(password) = config.database.password.as_ref().map(|p| p.expose()) {
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
    // R2-T1: the next boot applies every erasure since this backup before
    // it serves, and refuses to serve if it cannot.
    let marker = backup_dir(&config).join(RESTORE_PENDING);
    if let Err(error) = tokio::fs::write(&marker, archive.display().to_string()).await {
        eprintln!(
            "attome restore: cannot write {}: {error}; do not start the server until it exists",
            marker.display()
        );
        return std::process::ExitCode::FAILURE;
    }
    match restore_files(&config, &archive).await {
        Ok(0) => {}
        Ok(count) => println!("put back {count} files"),
        Err(error) => {
            eprintln!("attome restore: the database is restored but the files are not: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    println!("start the server: it applies erasures made since this backup before it serves");
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
    fn file_copies_stay_inside_the_mirror_and_match_their_archive() {
        let mirror = Path::new("backups").join("files");
        assert_eq!(
            mirror_path(&mirror, "branding/abc/logo-1"),
            Some(mirror.join("branding").join("abc").join("logo-1"))
        );
        for bad in ["../etc/passwd", "a//b", "/abs", "a/./b", "c:/x", "a\\b"] {
            assert_eq!(mirror_path(&mirror, bad), None, "{bad}");
        }
        assert_eq!(
            manifest_name("attome-20261014-0200.dump"),
            "attome-20261014-0200.files.json"
        );
        let entry = attome_storage::mirror::ObjectEntry {
            key: "k".into(),
            size: 3,
            e_tag: Some("\"e1\"".into()),
        };
        let copy = FileCopy {
            key: "k".into(),
            size: 3,
            sha256: sha256_hex(b"abc"),
            e_tag: Some("\"e1\"".into()),
        };
        assert!(unchanged(Some(&copy), &entry));
        let changed = attome_storage::mirror::ObjectEntry {
            e_tag: Some("\"e2\"".into()),
            ..entry.clone()
        };
        assert!(!unchanged(Some(&copy), &changed));
        let untagged = FileCopy {
            e_tag: None,
            ..copy
        };
        assert!(
            !unchanged(Some(&untagged), &entry),
            "no tag means read it again"
        );
        assert!(!unchanged(None, &entry));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn drills_run_monthly_into_a_named_throwaway_database() {
        let first = Utc.with_ymd_and_hms(2026, 11, 1, 2, 0, 0).unwrap();
        let second = Utc.with_ymd_and_hms(2026, 11, 2, 2, 0, 0).unwrap();
        assert!(drill_due(first));
        assert!(!drill_due(second));
        let name = drill_database_name(first);
        assert_eq!(name, "attome_drill_20261101020000");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        let record = DrillRecord {
            at: first,
            archive: "attome-20261101-0200.dump".into(),
            seconds: 42,
            passed: true,
            detail: "migrations=23, entities=95, people=3".into(),
        };
        let line = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<DrillRecord>(&line).unwrap(), record);
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

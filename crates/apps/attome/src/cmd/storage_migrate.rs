//! `attome storage migrate` (roadmap Z6-T5): copy every file from one
//! storage backend to another, then switch over by hand.
//!
//! `attome storage migrate --from <config.json> --to <config.json> [--state <file>]`
//! reads the `storage` section of each file (the same loading and checks as
//! the server), lists every object of the source and copies it to the
//! target, 100 keys a batch, 8 at a time. Each copy is read back from the
//! target and must match the source's size and SHA-256 before its key is
//! appended to the state file (`storage-migrate.state` by default), so a
//! rerun after a stop skips what is done. Encryption follows each side's
//! own settings: an encrypted source is read as plaintext and an encrypting
//! target seals what it receives.
//!
//! It refuses a target outside the deployment's `deployment.data_region`
//! (the source file's), never deletes a source file, and ends with the
//! config change to make.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};
use std::process::ExitCode;

use attome_config::{AppConfig, StorageBackend, StorageSection};
use attome_storage::object_store::path::Path;
use attome_storage::object_store::{ObjectStore, ObjectStoreExt};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

const USAGE: &str =
    "usage: attome storage migrate --from <config.json> --to <config.json> [--state <file>]";
/// Keys copied per batch.
pub const BATCH: usize = 100;
/// Copies running at once.
pub const CONCURRENCY: usize = 8;
const DEFAULT_STATE: &str = "storage-migrate.state";

/// What a run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub copied: u64,
    pub skipped: u64,
    pub bytes: u64,
    pub failed: Vec<(String, String)>,
}

/// Whether `target` may hold this deployment's files: with a declared
/// `data_region`, an S3 target must be in it; local disk is where the
/// server is; Azure and GCS settings name no region, so they are refused
/// under a residency claim rather than assumed. Pure.
pub fn region_allowed(data_region: Option<&str>, target: &StorageSection) -> Result<(), String> {
    let Some(region) = data_region.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(());
    };
    match target.backend {
        StorageBackend::Local => Ok(()),
        StorageBackend::S3 if region.eq_ignore_ascii_case(target.s3_region.trim()) => Ok(()),
        StorageBackend::S3 => Err(format!(
            "the target bucket's region {:?} is outside deployment.data_region {region:?}",
            target.s3_region
        )),
        StorageBackend::Azure | StorageBackend::Gcs => Err(format!(
            "deployment.data_region is {region:?} and an Azure or GCS target names no region to \
             check; migrate to S3 in {region:?} or local disk, or clear the claim first"
        )),
    }
}

/// The keys a state file says are done.
pub fn read_state(path: &FsPath) -> std::io::Result<HashSet<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
        Err(e) => Err(e),
    }
}

/// Copies one object and checks the target's copy: `Ok(bytes)` when it
/// matches the source in size and SHA-256.
async fn copy_one(
    source: &dyn ObjectStore,
    target: &dyn ObjectStore,
    key: &Path,
) -> Result<u64, String> {
    let bytes = source
        .get(key)
        .await
        .map_err(|e| format!("read: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read: {e}"))?;
    let want = Sha256::digest(&bytes);
    let len = bytes.len() as u64;
    target
        .put(key, bytes.into())
        .await
        .map_err(|e| format!("write: {e}"))?;
    let back = target
        .get(key)
        .await
        .map_err(|e| format!("verify: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("verify: {e}"))?;
    if back.len() as u64 != len || Sha256::digest(&back) != want {
        return Err("verify: the copy differs from the source".into());
    }
    Ok(len)
}

/// Copies every object of `source` not yet in the state file to `target`,
/// recording each verified key in it.
pub async fn copy_all(
    source: &dyn ObjectStore,
    target: &dyn ObjectStore,
    state: &FsPath,
) -> Result<Summary, String> {
    let done = read_state(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state)
        .map_err(|e| format!("{}: {e}", state.display()))?;
    let mut summary = Summary::default();
    let mut listing = source.list(None).chunks(BATCH);
    while let Some(batch) = listing.next().await {
        let mut keys = Vec::with_capacity(batch.len());
        for meta in batch {
            let meta = meta.map_err(|e| format!("list: {e}"))?;
            if done.contains(meta.location.as_ref()) {
                summary.skipped += 1;
            } else {
                keys.push(meta.location);
            }
        }
        let results: Vec<(Path, Result<u64, String>)> = futures_util::stream::iter(keys)
            .map(|key| async move {
                let result = copy_one(source, target, &key).await;
                (key, result)
            })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        for (key, result) in results {
            match result {
                Ok(len) => {
                    writeln!(log, "{key}").map_err(|e| format!("{}: {e}", state.display()))?;
                    summary.copied += 1;
                    summary.bytes += len;
                }
                Err(reason) => summary.failed.push((key.to_string(), reason)),
            }
        }
        log.flush()
            .map_err(|e| format!("{}: {e}", state.display()))?;
        println!(
            "copied {} ({} bytes), skipped {}, failed {}",
            summary.copied,
            summary.bytes,
            summary.skipped,
            summary.failed.len()
        );
    }
    Ok(summary)
}

struct Args {
    from: String,
    to: String,
    state: PathBuf,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut from = None;
    let mut to = None;
    let mut state = PathBuf::from(DEFAULT_STATE);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--from" => from = Some(value.clone()),
            "--to" => to = Some(value.clone()),
            "--state" => state = PathBuf::from(value),
            other => return Err(format!("unknown flag {other}\n{USAGE}")),
        }
    }
    Ok(Args {
        from: from.ok_or_else(|| USAGE.to_owned())?,
        to: to.ok_or_else(|| USAGE.to_owned())?,
        state,
    })
}

async fn migrate(args: &Args) -> Result<Summary, String> {
    let source = AppConfig::from_path(args.from.clone()).map_err(|e| format!("--from: {e}"))?;
    let target = AppConfig::from_path(args.to.clone()).map_err(|e| format!("--to: {e}"))?;
    region_allowed(source.deployment.data_region.as_deref(), &target.storage)?;
    let from = attome_storage::create_storage_client(&source)
        .await
        .map_err(|e| format!("--from storage: {e}"))?;
    let to = attome_storage::create_storage_client(&target)
        .await
        .map_err(|e| format!("--to storage: {e}"))?;
    copy_all(from.store(), to.store(), &args.state).await
}

/// `attome storage …`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let Some(("migrate", rest)) = args.split_first().map(|(c, r)| (c.as_str(), r)) else {
        println!("{USAGE}");
        return ExitCode::from(2);
    };
    let parsed = match parse_args(rest) {
        Ok(p) => p,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(2);
        }
    };
    match migrate(&parsed).await {
        Ok(summary) => {
            for (key, reason) in &summary.failed {
                println!("failed {key}: {reason}");
            }
            println!(
                "done: {} copied ({} bytes), {} already copied, {} failed; no source file was deleted",
                summary.copied,
                summary.bytes,
                summary.skipped,
                summary.failed.len()
            );
            if summary.failed.is_empty() {
                println!(
                    "next: stop the server, run this once more to copy what arrived meanwhile, \
                     then copy the `storage` section of {} into the deployment's config and start it",
                    parsed.to
                );
                ExitCode::SUCCESS
            } else {
                println!("run it again to retry the failed files");
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            println!("attome storage migrate: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_storage::object_store::local::LocalFileSystem;
    use futures_util::TryStreamExt;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attome-storage-migrate-{name}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn local(path: &FsPath) -> LocalFileSystem {
        LocalFileSystem::new_with_prefix(path).unwrap()
    }

    #[tokio::test]
    async fn storage_migrate_copies_verifies_and_resumes() {
        let (src_dir, dst_dir, work) = (dir("src"), dir("dst"), dir("work"));
        let (source, target) = (local(&src_dir), local(&dst_dir));
        for i in 0..(BATCH + 7) {
            let key = Path::from(format!("e/{}/f/file-{i}.txt", i % 3));
            source
                .put(&key, format!("contents {i}").into_bytes().into())
                .await
                .unwrap();
        }
        let state = work.join("state");
        let first = copy_all(&source, &target, &state).await.unwrap();
        assert_eq!(first.copied, (BATCH + 7) as u64);
        assert!(first.failed.is_empty());
        let copied = target
            .get(&Path::from("e/1/f/file-4.txt"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&copied[..], b"contents 4");
        // The source is untouched.
        assert_eq!(
            source
                .list(None)
                .try_collect::<Vec<_>>()
                .await
                .unwrap()
                .len(),
            BATCH + 7
        );

        // A rerun copies only what is new.
        source
            .put(&Path::from("e/9/f/late.txt"), b"late".to_vec().into())
            .await
            .unwrap();
        let second = copy_all(&source, &target, &state).await.unwrap();
        assert_eq!((second.copied, second.skipped), (1, (BATCH + 7) as u64));
    }

    #[test]
    fn storage_migrate_refuses_a_target_outside_the_region() {
        let mut target = StorageSection {
            backend: StorageBackend::S3,
            s3_region: "eu-west-1".into(),
            ..serde_json::from_str("{}").unwrap()
        };
        assert!(region_allowed(Some("me-central-1"), &target).is_err());
        assert!(region_allowed(None, &target).is_ok());
        target.s3_region = "ME-CENTRAL-1".into();
        assert!(region_allowed(Some("me-central-1"), &target).is_ok());
        target.backend = StorageBackend::Local;
        assert!(region_allowed(Some("me-central-1"), &target).is_ok());
        target.backend = StorageBackend::Azure;
        assert!(region_allowed(Some("me-central-1"), &target).is_err());
    }

    #[test]
    fn storage_migrate_reads_a_missing_state_as_empty() {
        let work = dir("state");
        assert!(read_state(&work.join("none")).unwrap().is_empty());
        std::fs::write(work.join("some"), "a/b\n\nc/d\n").unwrap();
        assert_eq!(read_state(&work.join("some")).unwrap().len(), 2);
    }
}

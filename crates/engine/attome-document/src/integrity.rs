//! Z6-T3: a weekly check that stored files are still what was uploaded.
//!
//! Every file version records its size and SHA-256 when it is uploaded (the
//! scan pass hashes the object as it streams, `files_scan`, and the version
//! row copies `upload_session.actual_size_bytes` and
//! `actual_checksum_sha256`). Once a week [`sample_check`] reads back 1% of
//! the live versions, at most [`SAMPLE_MAX`], streaming each one through
//! SHA-256 (never the whole file in memory), and compares. A file whose size
//! or hash differs, or that is gone, is logged with its version id and key
//! and counted in `file_integrity_failures_total{kind}`, which the built-in
//! `FileIntegrityFailures` alert watches. Nothing is changed or deleted: what
//! to do with a damaged file (restore it from a backup) is an operator's call.

use std::time::Duration;

use attome_db::DbPool;
use attome_types::AppError;
use futures_util::TryStreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The share of live versions read back each run, in percent.
pub const SAMPLE_PERCENT: i64 = 1;

/// The most versions one run reads back.
pub const SAMPLE_MAX: i64 = 1_000;

/// The longest one file's read may take.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// What one run found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IntegrityStats {
    pub checked: u64,
    /// Read back, but its size or hash differs from the recorded one.
    pub mismatched: u64,
    /// No object at its key.
    pub missing: u64,
}

/// Which versions a run reads.
#[derive(Debug, Clone, Default)]
pub struct SampleScope {
    /// How many, at most.
    pub limit: i64,
    /// Only versions whose key starts with this (a test's own files).
    pub key_prefix: Option<String>,
}

impl SampleScope {
    /// 1% of `live` versions, at least one when there is any, at most
    /// [`SAMPLE_MAX`].
    pub fn weekly(live: i64) -> Self {
        let share = (live * SAMPLE_PERCENT + 99) / 100;
        Self {
            limit: share.clamp(0, SAMPLE_MAX),
            key_prefix: None,
        }
    }
}

fn failure(kind: &'static str) {
    metrics::counter!("file_integrity_failures_total", "kind" => kind).increment(1);
}

/// The size and lowercase hex SHA-256 of the object at `key`, streamed;
/// `None` when there is no such object.
async fn read_back(store: &dyn ObjectStore, key: &str) -> Result<Option<(i64, String)>, AppError> {
    let path = ObjectPath::parse(key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let stream = match store.get(&path).await {
        Ok(object) => object.into_stream(),
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(AppError::internal(e)),
    };
    tokio::time::timeout(READ_TIMEOUT, async move {
        let mut stream = stream;
        let mut hasher = Sha256::new();
        let mut size: i64 = 0;
        while let Some(chunk) = stream.try_next().await.map_err(AppError::internal)? {
            size += chunk.len() as i64;
            hasher.update(&chunk);
        }
        Ok(Some((size, hex::encode(hasher.finalize()))))
    })
    .await
    .map_err(|_| AppError::internal("reading a file back for its integrity check timed out"))?
}

/// The number of live versions with a recorded hash.
pub async fn live_versions(db: &DbPool) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM file_version WHERE is_deleted = false AND hash IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Reads back the versions `scope` picks, at random, and compares each with
/// its recorded size and hash. A storage error other than a missing object
/// stops the run (the job retries); every finding is logged and counted.
pub async fn sample_check(
    db: &DbPool,
    store: &dyn ObjectStore,
    scope: &SampleScope,
) -> Result<IntegrityStats, AppError> {
    let mut stats = IntegrityStats::default();
    if scope.limit <= 0 {
        return Ok(stats);
    }
    let rows: Vec<(Uuid, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, object_key, size, hash FROM file_version
          WHERE is_deleted = false AND hash IS NOT NULL
            AND ($2::text IS NULL OR starts_with(object_key, $2))
          ORDER BY random()
          LIMIT $1",
    )
    .bind(scope.limit)
    .bind(scope.key_prefix.as_deref())
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for (version_id, key, size, hash) in rows {
        stats.checked += 1;
        match read_back(store, &key).await? {
            None => {
                stats.missing += 1;
                failure("missing");
                tracing::error!(%version_id, key = %key, "file integrity: the stored file is missing");
            }
            Some((actual_size, actual_hash)) => {
                let size_differs = size.is_some_and(|expected| expected != actual_size);
                if size_differs || !actual_hash.eq_ignore_ascii_case(hash.trim()) {
                    stats.mismatched += 1;
                    failure("mismatch");
                    tracing::error!(
                        %version_id,
                        key = %key,
                        expected_size = ?size,
                        actual_size,
                        "file integrity: the stored file differs from what was uploaded"
                    );
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_sample_is_one_percent_capped() {
        assert_eq!(SampleScope::weekly(0).limit, 0);
        assert_eq!(SampleScope::weekly(1).limit, 1);
        assert_eq!(SampleScope::weekly(250).limit, 3);
        assert_eq!(SampleScope::weekly(10_000).limit, 100);
        assert_eq!(SampleScope::weekly(5_000_000).limit, SAMPLE_MAX);
    }
}

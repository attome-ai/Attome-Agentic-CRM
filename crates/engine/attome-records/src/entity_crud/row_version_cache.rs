//! AA7-T8: the live row version a record GET's `If-None-Match` is compared
//! with, from process memory, so a matching `304` costs no query.
//!
//! The cache holds the version only, never record data, and is read after
//! the caller's access to the record was checked; a hit answers `304`
//! exactly as the primary-key probe it replaces would have. Contract
//! (guidelines §5):
//!
//! - source of truth: the entity table's `row_version`;
//! - key: `attome-records:rowver:{entity}:{id}`, process memory only;
//! - invalidation: a generic write drops its record's entry on the writing
//!   node as it commits (`mutation_ring`), and every node's change-feed bus
//!   drops it within about a second ([`Dependency::Record`]); a write that
//!   bypasses the change feed is bounded by the TTL;
//! - TTL: [`TTL`], short on purpose, for that last case;
//! - failure and cold start: a miss or an unavailable cache runs the probe.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use attome_cache::depends::Dependency;
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::TieredCache;
use attome_types::AppError;
use uuid::Uuid;

/// How long a cached version is trusted without a change-feed event.
pub const TTL: Duration = Duration::from_secs(30);

static SPEC: CacheSpec = CacheSpec {
    name: "attome-records:rowver",
    crate_name: "attome-records",
    purpose: "rowver",
    source_of_truth: "each entity table's row_version column",
    ttl: TTL,
    jitter_pct: 10,
    l1_capacity: 50_000,
    partition: Partition::Shared,
    sensitivity: CacheSensitivity::LocalOnly,
    failure: FailureMode::FallBackToSource,
    invalidation: "dropped on the writing node as a generic write commits; every node's \
                   change-feed bus drops the record's entry; TTL for writes outside the feed",
    cold_start: "empty; the first conditional read of a record runs the primary-key probe",
    warm_on_start: false,
};

static CACHE: LazyLock<Option<Arc<TieredCache<i64>>>> = LazyLock::new(|| {
    match TieredCache::new(&SPEC, None) {
        Ok(cache) => {
            let cache = Arc::new(cache);
            attome_core::cache_invalidation::bus().register(Arc::clone(&cache) as _);
            Some(cache)
        }
        Err(error) => {
            tracing::error!(cache = SPEC.name, %error, "row-version cache refused; probing instead");
            None
        }
    }
});

fn id(entity: &str, record_id: Uuid) -> String {
    format!("{entity}:{record_id}")
}

/// The live record's row version, `None` when there is no live record:
/// cached, else loaded by `probe` (today's primary-key read).
pub(super) async fn live_row_version<F>(
    entity: &str,
    record_id: Uuid,
    probe: F,
) -> Result<Option<i64>, AppError>
where
    F: Future<Output = Result<Option<i64>, AppError>>,
{
    let Some(cache) = CACHE.as_ref() else {
        return probe.await;
    };
    let found = cache
        .get_or_load_depending(
            None,
            &id(entity, record_id),
            &[Dependency::Record(entity.to_owned(), record_id)],
            async { probe.await?.ok_or(AppError::NotFound) },
        )
        .await;
    match found {
        Ok(version) => Ok(Some(version)),
        // Not cached: a missing record is never remembered.
        Err(AppError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Drops the record's entry on this node, as its write commits.
pub async fn forget(entity: &str, record_id: Uuid) {
    if let Some(cache) = CACHE.as_ref() {
        cache.invalidate_local(&id(entity, record_id)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn if_none_match_cached_version_skips_the_probe_until_forgotten() {
        let id = Uuid::now_v7();
        let probes = Arc::new(AtomicUsize::new(0));
        let probe = |v: Option<i64>| {
            let probes = Arc::clone(&probes);
            async move {
                probes.fetch_add(1, Ordering::Relaxed);
                Ok(v)
            }
        };
        let ran = || probes.load(Ordering::Relaxed);
        assert_eq!(
            live_row_version("acct", id, probe(Some(3))).await.unwrap(),
            Some(3)
        );
        assert_eq!(ran(), 1);
        // A hit answers from memory: the probe never runs.
        assert_eq!(
            live_row_version("acct", id, probe(Some(9))).await.unwrap(),
            Some(3)
        );
        assert_eq!(ran(), 1);
        // A write forgets it; the next read probes again.
        forget("acct", id).await;
        assert_eq!(
            live_row_version("acct", id, probe(Some(4))).await.unwrap(),
            Some(4)
        );
        assert_eq!(ran(), 2);
        // A missing record is never remembered.
        let gone = Uuid::now_v7();
        assert_eq!(
            live_row_version("acct", gone, probe(None)).await.unwrap(),
            None
        );
        assert_eq!(
            live_row_version("acct", gone, probe(Some(1)))
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(ran(), 4);
    }
}

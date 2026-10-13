use arc_swap::ArcSwap;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

/// Zero-cost arc-swap snapshot for read-heavy shared data (metadata, config).
/// Reads are a single atomic pointer load; an update is one atomic pointer
/// swap.
///
/// This type holds no cross-node machinery of its own and broadcasts nothing.
/// A caller that needs every node to agree owns that contract: it publishes a
/// pub/sub doorbell and every node — the publisher included — calls
/// [`MetadataCache::swap`] after rebuilding from PostgreSQL. Process-local by
/// construction and correctly so: the snapshot is always rebuildable from its
/// source of truth, so a node that misses a message is stale, never wrong.
#[derive(Clone)]
pub struct MetadataCache<T: Send + Sync + 'static> {
    inner: Arc<ArcSwap<T>>,
}

impl<T: Send + Sync + 'static> std::fmt::Debug for MetadataCache<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataCache").finish_non_exhaustive()
    }
}

impl<T: Send + Sync + 'static> MetadataCache<T> {
    pub fn new(initial: T) -> Self {
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(initial))),
        }
    }

    /// Zero-cost read — single atomic pointer load.
    pub fn load(&self) -> arc_swap::Guard<Arc<T>> {
        self.inner.load()
    }

    /// Atomically replace the snapshot. Call after rebuilding from Postgres
    /// in response to a Redis invalidation pub/sub message.
    pub fn swap(&self, new_value: T) {
        self.inner.store(Arc::new(new_value));
    }
}

/// Moka in-process LRU/TTL cache for hot records and permission resolutions.
/// Key format is purpose-specific and always two-part (single-tenant, D-002):
/// `"{entity}:{record_id}"` for hot records, `"{user_id}:sec"` for resolved
/// `SecurityContext`s.
pub type HotCache<V> = Cache<String, V>;

/// Reads `key` from `cache` and records the outcome as
/// `hot_cache_lookups_total{cache=<name>, outcome=hit|miss}`.
///
/// OPS-2. moka keeps no hit/miss counters of its own, so a hit rate has to be
/// counted at the lookup. Doing that here rather than at each call site is the
/// point: the counter cannot drift from the lookup it describes, and the two
/// L1 caches cannot end up with differently-spelled metric names or label
/// sets — which is what makes the resulting series comparable at all.
///
/// `name` is the cache's stable identity in the metric and must be a
/// compile-time constant, never anything derived from a key: a per-user or
/// per-record label would give this counter unbounded cardinality and take the
/// scrape endpoint down with it.
///
/// A miss here is not an error and usually not even interesting on its own —
/// a cold cache and an evicting one look identical at a single point. The
/// signal is the *rate over time*: a hit rate that falls without a
/// corresponding change in traffic means the entries are being evicted or
/// invalidated faster than they are being used, which is the condition that
/// silently turns an L1 into pure overhead.
pub async fn get_recorded<V>(cache: &HotCache<V>, key: &str, name: &'static str) -> Option<V>
where
    V: Clone + Send + Sync + 'static,
{
    let hit = cache.get(key).await;
    metrics::counter!(
        "hot_cache_lookups_total",
        "cache" => name,
        "outcome" => if hit.is_some() { "hit" } else { "miss" },
    )
    .increment(1);
    hit
}

pub fn create_hot_cache<V>(max_capacity: u64, ttl_secs: u64) -> HotCache<V>
where
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(ttl_secs))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OPS-2. The property worth pinning is not that the counter increments —
    /// that is one line and a recorder harness to observe — but that wrapping
    /// the lookup did not change what the lookup *returns*. `get_recorded` is
    /// on the authz hot path via `SecurityCache::resolve`; a wrapper that
    /// altered hit semantics would be a correctness bug wearing an
    /// observability change's clothes.
    #[tokio::test]
    async fn get_recorded_returns_exactly_what_get_returns() {
        let cache: HotCache<u32> = create_hot_cache(10, 60);

        // Miss on an absent key, for both paths.
        assert_eq!(cache.get("absent").await, None);
        assert_eq!(get_recorded(&cache, "absent", "test").await, None);

        cache.insert("present".to_string(), 7).await;
        assert_eq!(cache.get("present").await, Some(7));
        assert_eq!(get_recorded(&cache, "present", "test").await, Some(7));

        // Repeated reads stay hits — the wrapper must not consume the entry.
        assert_eq!(get_recorded(&cache, "present", "test").await, Some(7));
        assert_eq!(cache.get("present").await, Some(7));
    }

    #[tokio::test]
    async fn get_recorded_observes_invalidation() {
        let cache: HotCache<u32> = create_hot_cache(10, 60);
        cache.insert("k".to_string(), 1).await;
        assert_eq!(get_recorded(&cache, "k", "test").await, Some(1));

        cache.invalidate("k").await;
        assert_eq!(
            get_recorded(&cache, "k", "test").await,
            None,
            "an invalidated entry must read as a miss, not a stale hit"
        );
    }
}

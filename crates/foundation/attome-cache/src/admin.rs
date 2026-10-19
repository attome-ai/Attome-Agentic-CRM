//! Z3-T9: what an operator sees of this node's declared caches, and the
//! purge.
//!
//! Every [`TieredCache`](crate::tiered::TieredCache) registers a handle here
//! when it is built (the latest one under a name wins, as when a cache is
//! rebuilt with a quota). [`stats`] lists each cache's entries, hits, misses
//! and evictions on this node since it started; [`purge`] drops one key, or
//! everything, from a cache's in-process tier on this node, and one key of a
//! shared cache from the shared store too. A whole-cache purge, or a
//! partitioned cache's per-reader copies, are not deleted from the shared
//! store: those live out their TTL. Reaching the
//! other nodes is the caller's (the admin route sends a Postgres
//! notification every node's listener answers with [`purge`]).
//!
//! Cache contract (guidelines §5): the counters are this node's own and
//! observational; they start at zero with the process and agree with nothing
//! else.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// One cache's numbers on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStats {
    pub name: &'static str,
    /// Entries in the in-process tier now (moka's estimate).
    pub entries: u64,
    /// Reads answered by the in-process tier.
    pub hits: u64,
    /// Reads that went on to the shared store or the source.
    pub misses: u64,
    /// Entries pushed out by the capacity or the quota (not expiry, not a
    /// purge).
    pub evictions: u64,
}

/// A cache's counters, shared by the cache and its eviction listener.
#[derive(Debug, Default)]
pub struct Counters {
    pub(crate) hits: AtomicU64,
    pub(crate) misses: AtomicU64,
    pub(crate) evictions: AtomicU64,
}

impl Counters {
    pub(crate) fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn read(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// What the admin surface needs of a cache.
pub trait AdminCache: Send + Sync {
    fn stats(&self) -> CacheStats;
    /// Drops `id` (as the cache's readers name it), or every entry when
    /// `None`, from this node's in-process tier.
    fn purge<'a>(&'a self, id: Option<&'a str>) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The handle a `TieredCache` registers.
pub(crate) struct Handle<V: Clone + Send + Sync + 'static> {
    pub(crate) spec: &'static crate::spec::CacheSpec,
    pub(crate) l1: moka::future::Cache<String, V>,
    pub(crate) counters: Arc<Counters>,
    /// The shared store, when this cache may use one: a purged key is
    /// deleted there too, so no node reloads it from there.
    pub(crate) store: Option<crate::Store>,
}

impl<V: Clone + Send + Sync + 'static> AdminCache for Handle<V> {
    fn stats(&self) -> CacheStats {
        let entries = self.l1.entry_count();
        metrics::gauge!("cache_entries", "cache" => self.spec.name).set(entries as f64);
        CacheStats {
            name: self.spec.name,
            entries,
            hits: Counters::read(&self.counters.hits),
            misses: Counters::read(&self.counters.misses),
            evictions: Counters::read(&self.counters.evictions),
        }
    }

    fn purge<'a>(&'a self, id: Option<&'a str>) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match id {
                // A partitioned cache's entries are `{reader}:{id}`: purging
                // an id drops it for every reader.
                Some(id) => {
                    let key = self.spec.key(id);
                    let suffix = format!(":{id}");
                    let prefix = self.spec.key("");
                    self.l1.invalidate(&key).await;
                    if let Some(store) = &self.store
                        && let Err(error) =
                            tokio::time::timeout(crate::timeouts::BACKGROUND, store.del(&key))
                                .await
                                .unwrap_or(Err(attome_types::AppError::Overloaded("cache")))
                    {
                        tracing::warn!(cache = self.spec.name, %error, "purge could not reach the shared store; the entry lives its TTL there");
                    }
                    if self.spec.partition != crate::spec::Partition::Shared {
                        let _ = self.l1.invalidate_entries_if(move |k, _| {
                            k.starts_with(&prefix) && k.ends_with(&suffix)
                        });
                    }
                }
                None => self.l1.invalidate_all(),
            }
        })
    }
}

static CACHES: OnceLock<Mutex<BTreeMap<&'static str, Arc<dyn AdminCache>>>> = OnceLock::new();

fn caches() -> &'static Mutex<BTreeMap<&'static str, Arc<dyn AdminCache>>> {
    CACHES.get_or_init(Mutex::default)
}

/// Registers (or replaces) the handle of the cache `name`.
pub(crate) fn register(name: &'static str, cache: Arc<dyn AdminCache>) {
    caches()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(name, cache);
}

/// Every built cache's numbers on this node, by name.
pub fn stats() -> Vec<CacheStats> {
    let all: Vec<Arc<dyn AdminCache>> = caches()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .cloned()
        .collect();
    all.iter().map(|cache| cache.stats()).collect()
}

/// Purges `id` (or everything) from the cache `name` on this node; `false`
/// when no cache of that name was built here.
pub async fn purge(name: &str, id: Option<&str>) -> bool {
    let cache = caches()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(name)
        .cloned();
    match cache {
        Some(cache) => {
            cache.purge(id).await;
            true
        }
        None => false,
    }
}

/// Whether a cache of that name was built on this node.
pub fn known(name: &str) -> bool {
    caches()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains_key(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
    use crate::tiered::TieredCache;
    use std::time::Duration;

    static SPEC: CacheSpec = CacheSpec {
        name: "attome-cache:admin-test",
        crate_name: "attome-cache",
        purpose: "admin-test",
        source_of_truth: "the test",
        ttl: Duration::from_secs(60),
        jitter_pct: 0,
        l1_capacity: 10,
        partition: Partition::Shared,
        sensitivity: CacheSensitivity::LocalOnly,
        failure: FailureMode::FallBackToSource,
        invalidation: "TTL",
        cold_start: "empty",
        warm_on_start: false,
    };

    fn mine() -> CacheStats {
        stats()
            .into_iter()
            .find(|s| s.name == SPEC.name)
            .expect("the cache registered itself")
    }

    #[tokio::test]
    async fn counts_hits_and_misses_and_purges_a_key() {
        let cache: TieredCache<String> = TieredCache::new(&SPEC, None).unwrap();
        let load = || async { Ok::<_, attome_types::AppError>("value".to_owned()) };
        cache.get_or_load("a", load()).await.unwrap();
        cache.get_or_load("a", load()).await.unwrap();
        let after = mine();
        assert_eq!((after.hits, after.misses), (1, 1));
        assert!(known(SPEC.name));

        assert!(purge(SPEC.name, Some("a")).await);
        cache.get_or_load("a", load()).await.unwrap();
        assert_eq!(
            mine().misses,
            2,
            "a purged key is read from the source again"
        );
        assert!(!purge("attome-cache:nothing", None).await);
    }
}

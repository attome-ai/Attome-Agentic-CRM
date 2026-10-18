//! Z3-T2: the one cache shape. A [`TieredCache`] reads its in-process tier
//! (L1, moka), then the shared store (Redis, or the in-process store on one
//! server), then the loader, and fills the tiers it missed on the way back.
//! Concurrent callers for one key on a node share one load (moka's
//! `try_get_with`); every entry lives its declared TTL plus or minus its
//! jitter, so entries written together do not expire together.
//!
//! Its behaviour comes from its [`CacheSpec`]: the key shape
//! (`{crate}:{purpose}:{id}`), the TTL and jitter, the L1 capacity, whether a
//! value may reach the shared store (`LocalOnly` never does), and what a
//! store failure does: `FallBackToSource` runs the loader (a `warn`
//! `cache.redis_degraded` at most once a minute per cache), `FailClosed`
//! refuses with `AppError::Overloaded("cache")`.
//!
//! A partitioned cache (Z3-T4) is read with
//! [`get_or_load_for`](TieredCache::get_or_load_for), naming whose value it
//! is: `PerUser` takes the user id, `PerSession` the session id, and
//! `PerPermissionSet` the reader's `SecurityContext::permission_fingerprint`.
//! Only a cache declared `PerPermissionSet` may hold permission-filtered
//! rows, and only rows filtered by privileges and field security: a row set
//! filtered by record ownership depends on the user, so it is `PerUser`.
//! A `Shared` cache is read with [`get_or_load`](TieredCache::get_or_load).

use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::BuildHasher;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use attome_types::AppError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Store;
use crate::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};

/// `ttl` plus or minus up to `jitter_pct` percent, from `seed`.
pub fn jittered(ttl: Duration, jitter_pct: u8, seed: u64) -> Duration {
    let pct = u64::from(jitter_pct.min(50));
    if pct == 0 {
        return ttl;
    }
    let span = 2 * pct + 1;
    // -pct ..= +pct percent.
    let offset = i64::try_from(seed % span).unwrap_or(0) - i64::try_from(pct).unwrap_or(0);
    let millis = i128::try_from(ttl.as_millis()).unwrap_or(i128::MAX);
    let moved = millis + millis * i128::from(offset) / 100;
    Duration::from_millis(u64::try_from(moved.max(1)).unwrap_or(u64::MAX))
}

fn seed(key: &str) -> u64 {
    // A fresh RandomState per call: different keys, and the same key twice,
    // get different jitter.
    RandomState::new().hash_one(key)
}

/// Per-entry expiry: the spec's TTL with jitter, decided when the entry is
/// written.
struct JitterExpiry {
    ttl: Duration,
    jitter_pct: u8,
}

impl<V> moka::Expiry<String, V> for JitterExpiry {
    fn expire_after_create(
        &self,
        key: &String,
        _value: &V,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(jittered(self.ttl, self.jitter_pct, seed(key)))
    }
}

/// An `AppError` again, for each caller that waited on one shared load.
fn reissue(error: &AppError) -> AppError {
    match error {
        AppError::NotFound => AppError::NotFound,
        AppError::Forbidden => AppError::Forbidden,
        AppError::Unauthorized => AppError::Unauthorized,
        AppError::Overloaded(what) => AppError::Overloaded(what),
        AppError::Conflict(what) => AppError::Conflict(what),
        AppError::Validation(message) => AppError::Validation(message.clone()),
        other => AppError::internal(other.to_string()),
    }
}

/// One declared cache over values `V`.
pub struct TieredCache<V: Clone + Send + Sync + 'static> {
    spec: &'static CacheSpec,
    l1: moka::future::Cache<String, V>,
    store: Option<Store>,
    last_degraded_warning: Mutex<Option<Instant>>,
}

impl<V: Clone + Send + Sync + 'static> std::fmt::Debug for TieredCache<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TieredCache")
            .field("cache", &self.spec.name)
            .finish_non_exhaustive()
    }
}

impl<V> TieredCache<V>
where
    V: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    /// A cache for `spec` (validated and registered), over `store` when the
    /// deployment has one; `None` keeps it in process (one server).
    pub fn new(spec: &'static CacheSpec, store: Option<Store>) -> Result<Self, AppError> {
        spec.validate()
            .map_err(|e| AppError::internal(e.to_string()))?;
        crate::spec::register(spec);
        let l1 = moka::future::Cache::builder()
            .max_capacity(spec.l1_capacity)
            .expire_after(JitterExpiry {
                ttl: spec.ttl,
                jitter_pct: spec.jitter_pct,
            })
            .build();
        Ok(Self {
            spec,
            l1,
            store,
            last_degraded_warning: Mutex::new(None),
        })
    }

    fn shared_store(&self) -> Option<&Store> {
        match self.spec.sensitivity {
            CacheSensitivity::LocalOnly => None,
            _ => self.store.as_ref(),
        }
    }

    fn warn_degraded(&self, error: &AppError) {
        let mut last = self
            .last_degraded_warning
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = last.is_none_or(|at| at.elapsed() >= Duration::from_secs(60));
        if due {
            *last = Some(Instant::now());
            tracing::warn!(event = "cache.redis_degraded", cache = self.spec.name, %error, "cache store unavailable; reading the source");
        }
    }

    /// The value for `id`: L1, then the shared store, then `loader`. Only
    /// for a `Shared` cache; a partitioned one is read with
    /// [`get_or_load_for`](Self::get_or_load_for).
    pub async fn get_or_load<F>(&self, id: &str, loader: F) -> Result<V, AppError>
    where
        F: Future<Output = Result<V, AppError>>,
    {
        if self.spec.partition != Partition::Shared {
            return Err(AppError::internal(format!(
                "cache {} is partitioned {:?}; read it with get_or_load_for",
                self.spec.name, self.spec.partition
            )));
        }
        self.fetch(self.spec.key(id), loader).await
    }

    /// Z3-T4: the value for `id` as one reader sees it. `reader` is the
    /// partition's owner: the user id (`PerUser`), the session id
    /// (`PerSession`) or the reader's permission fingerprint
    /// (`PerPermissionSet`). An empty `reader` is refused, so a caller cannot
    /// fall into one shared entry by mistake.
    pub async fn get_or_load_for<F>(&self, reader: &str, id: &str, loader: F) -> Result<V, AppError>
    where
        F: Future<Output = Result<V, AppError>>,
    {
        let key = self.reader_key(reader, id)?;
        self.fetch(key, loader).await
    }

    fn reader_key(&self, reader: &str, id: &str) -> Result<String, AppError> {
        if self.spec.partition == Partition::Shared {
            return Ok(self.spec.key(id));
        }
        let reader = reader.trim();
        if reader.is_empty() {
            return Err(AppError::internal(format!(
                "cache {} is partitioned {:?}; a reader is required",
                self.spec.name, self.spec.partition
            )));
        }
        Ok(self.spec.key(&format!("{reader}:{id}")))
    }

    async fn fetch<F>(&self, key: String, loader: F) -> Result<V, AppError>
    where
        F: Future<Output = Result<V, AppError>>,
    {
        self.l1
            .try_get_with(key.clone(), self.load(&key, loader))
            .await
            .map_err(|shared| reissue(&shared))
    }

    async fn load<F>(&self, key: &str, loader: F) -> Result<V, AppError>
    where
        F: Future<Output = Result<V, AppError>>,
    {
        let Some(store) = self.shared_store() else {
            return loader.await;
        };
        match store.get(key).await {
            Ok(Some(text)) => match serde_json::from_str::<V>(&text) {
                Ok(value) => return Ok(value),
                // A value written by another version: read the source.
                Err(error) => {
                    tracing::debug!(cache = self.spec.name, %error, "cache entry does not decode; reloading");
                }
            },
            Ok(None) => {}
            Err(error) => match self.spec.failure {
                FailureMode::FailClosed => return Err(AppError::Overloaded("cache")),
                FailureMode::FallBackToSource => {
                    self.warn_degraded(&error);
                    return loader.await;
                }
            },
        }
        let value = loader.await?;
        if let Ok(text) = serde_json::to_string(&value) {
            let ttl = jittered(self.spec.ttl, self.spec.jitter_pct, seed(key));
            if let Err(error) = store.set(key, &text, Some(ttl)).await {
                self.warn_degraded(&error);
            }
        }
        Ok(value)
    }

    /// Drops `id` from this node and the shared store.
    pub async fn invalidate(&self, id: &str) -> Result<(), AppError> {
        let key = self.spec.key(id);
        self.l1.invalidate(&key).await;
        if let Some(store) = self.shared_store() {
            store.del(&key).await?;
        }
        Ok(())
    }

    /// Drops `id` from this node only (another node's change arrived).
    pub async fn invalidate_local(&self, id: &str) {
        self.l1.invalidate(&self.spec.key(id)).await;
    }

    /// Z3-T4: drops one reader's `id` from this node and the shared store.
    pub async fn invalidate_for(&self, reader: &str, id: &str) -> Result<(), AppError> {
        let key = self.reader_key(reader, id)?;
        self.l1.invalidate(&key).await;
        if let Some(store) = self.shared_store() {
            store.del(&key).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const fn spec(name: &'static str, purpose: &'static str, failure: FailureMode) -> CacheSpec {
        CacheSpec {
            name,
            crate_name: "cache",
            purpose,
            source_of_truth: "a test",
            ttl: Duration::from_secs(60),
            jitter_pct: 20,
            l1_capacity: 100,
            partition: Partition::Shared,
            sensitivity: CacheSensitivity::Plain,
            failure,
            invalidation: "none",
            cold_start: "empty",
            warm_on_start: false,
        }
    }

    static LOCAL: CacheSpec = spec(
        "cache:tiered_local",
        "tiered_local",
        FailureMode::FallBackToSource,
    );
    static CLOSED: CacheSpec = spec(
        "cache:tiered_closed",
        "tiered_closed",
        FailureMode::FailClosed,
    );

    #[tokio::test]
    async fn l1_only_loads_once_for_concurrent_callers() {
        let cache = Arc::new(TieredCache::<u32>::new(&LOCAL, None).unwrap());
        let loads = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let loads = Arc::clone(&loads);
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_load("k", async {
                        loads.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(7)
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap(), 7);
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        cache.invalidate("k").await.unwrap();
        let again = cache.get_or_load("k", async { Ok(8) }).await.unwrap();
        assert_eq!(again, 8, "invalidated, so loaded again");
    }

    #[test]
    fn ttl_jitter_within_bounds() {
        let ttl = Duration::from_secs(100);
        for seed in 0..500 {
            let d = jittered(ttl, 20, seed);
            assert!(
                d >= Duration::from_secs(80) && d <= Duration::from_secs(120),
                "{d:?}"
            );
        }
        assert_eq!(jittered(ttl, 0, 12345), ttl);
        // Jitter over 50% is held to 50%.
        assert!(jittered(ttl, 90, 0) >= Duration::from_secs(50));
    }

    static PER_PERMISSIONS: CacheSpec = CacheSpec {
        partition: Partition::PerPermissionSet,
        ..spec(
            "cache:tiered_per_permissions",
            "tiered_per_permissions",
            FailureMode::FallBackToSource,
        )
    };

    #[tokio::test]
    async fn a_partitioned_cache_needs_a_reader() {
        let cache = TieredCache::<u32>::new(&PER_PERMISSIONS, None).unwrap();
        assert!(cache.get_or_load("k", async { Ok(1) }).await.is_err());
        assert!(
            cache
                .get_or_load_for(" ", "k", async { Ok(1) })
                .await
                .is_err()
        );
        assert_eq!(
            cache
                .get_or_load_for("fp-a", "k", async { Ok(1) })
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            cache
                .get_or_load_for("fp-b", "k", async { Ok(2) })
                .await
                .unwrap(),
            2,
            "another permission set has its own entry"
        );
        assert_eq!(
            cache
                .get_or_load_for("fp-a", "k", async { Ok(9) })
                .await
                .unwrap(),
            1
        );
        cache.invalidate_for("fp-a", "k").await.unwrap();
        assert_eq!(
            cache
                .get_or_load_for("fp-a", "k", async { Ok(3) })
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn fail_closed_without_redis_errors_only_when_redis_configured() {
        // No store: nothing to fail, the loader answers.
        let local = TieredCache::<u32>::new(&CLOSED, None).unwrap();
        assert_eq!(local.get_or_load("x", async { Ok(1) }).await.unwrap(), 1);
        // A loader error reaches the caller as itself.
        let err = local
            .get_or_load("y", async { Err(AppError::NotFound) })
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound));
    }
}

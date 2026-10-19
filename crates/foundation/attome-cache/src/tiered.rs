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
//!
//! Sensitivity (Z3-T3): a `LocalOnly` cache never reaches the shared store.
//! An `EncryptedInRedis` cache seals each value with a [`ValueSealer`]
//! before it reaches Redis and opens it on the way back; a value that does
//! not open (a rotated-out key, a foreign value) is a miss, logged at
//! `warn`. Over Redis such a cache needs a sealer and refuses to start
//! without one; the in-process store keeps values in this process and is not
//! sealed. This crate holds no cryptography: the sealer comes from
//! `attome-auth` (`envelope::CacheSealer`, over `cache.encryption_key`).
//!
//! Warm start and quotas (Z3-T7): a cache built [`with_warm`](TieredCache::with_warm)
//! can fill its L1 from a loader at start ([`warm_now`](TieredCache::warm_now)); one whose
//! spec says `warm_on_start` and that its owner registers ([`register_warm`]) is warmed when
//! the server starts, within a shared time budget ([`warm_registered`]). A cache built
//! [`with_quota`](TieredCache::with_quota) bounds its L1 by the serialized size of its
//! entries instead of their count, so an engine's or an extension's partition cannot grow
//! past its share of memory.
//!
//! Dependencies (Z3-T5): a value read through
//! [`get_or_load_depending`](TieredCache::get_or_load_depending) is recorded under the
//! entities and records it was computed from ([`Dependency`]); the change-feed bus
//! (`attome_core::cache_invalidation`) drops it on every node when one of them is written.

use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::BuildHasher;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use attome_types::AppError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Store;
use crate::depends::{DepIndex, Dependency, InvalidateDeps};
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

/// Z3-T3: seals a cache value before it reaches Redis and opens it after.
/// `attome-auth`'s `envelope::CacheSealer` is the deployment's.
pub trait ValueSealer: Send + Sync {
    fn seal(&self, plaintext: &str) -> Result<String, AppError>;
    fn open(&self, sealed: &str) -> Result<String, AppError>;
}

/// Z3-T7: what a cache's warm loader returns: `(id, value)` pairs.
pub type WarmFuture<V> = std::pin::Pin<Box<dyn Future<Output = Vec<(String, V)>> + Send + 'static>>;

/// Z3-T7: a cache's warm loader.
pub type WarmLoader<V> = Box<dyn Fn() -> WarmFuture<V> + Send + Sync>;

/// Z3-T7: a cache that can fill itself at start.
pub trait Warmable: Send + Sync {
    /// The cache's name, for the log.
    fn cache_name(&self) -> &'static str;
    /// Fills the L1; answers how many entries went in.
    fn warm(&self) -> std::pin::Pin<Box<dyn Future<Output = usize> + Send + '_>>;
}

static WARMABLE: Mutex<Vec<std::sync::Weak<dyn Warmable>>> = Mutex::new(Vec::new());

/// Z3-T7: registers a cache to be warmed at server start. Held weakly: a
/// dropped cache is skipped.
pub fn register_warm(cache: &std::sync::Arc<dyn Warmable>) {
    WARMABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(std::sync::Arc::downgrade(cache));
}

/// Z3-T7: warms every registered cache in turn until `budget` runs out;
/// answers how many entries went in. A cache the budget cuts off starts
/// cold, as without warming.
pub async fn warm_registered(budget: Duration) -> usize {
    let caches: Vec<std::sync::Arc<dyn Warmable>> = WARMABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect();
    let started = Instant::now();
    let mut total = 0;
    for cache in caches {
        let Some(left) = budget.checked_sub(started.elapsed()) else {
            tracing::warn!(
                cache = cache.cache_name(),
                "cache warm budget spent; starting cold"
            );
            continue;
        };
        match tokio::time::timeout(left, cache.warm()).await {
            Ok(n) => {
                tracing::info!(cache = cache.cache_name(), entries = n, "cache warmed");
                total += n;
            }
            Err(_) => {
                tracing::warn!(cache = cache.cache_name(), "cache warm ran out of budget");
            }
        }
    }
    total
}

/// Z3-T11: a store call bounded by `bound`; running past it is the same
/// failure as a store error (guidelines §5: every Redis call is bounded).
async fn bounded<T>(
    bound: Duration,
    call: impl Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::time::timeout(bound, call)
        .await
        .unwrap_or(Err(AppError::Overloaded("cache")))
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
    sealer: Option<std::sync::Arc<dyn ValueSealer>>,
    warm_loader: Option<WarmLoader<V>>,
    last_degraded_warning: Mutex<Option<Instant>>,
    /// Z3-T5: this node's dependency -> keys index.
    deps: Mutex<DepIndex>,
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
        Self::with_sealer(spec, store, None)
    }

    /// Z3-T3: [`new`](Self::new) with the sealer an `EncryptedInRedis`
    /// cache needs over Redis. Such a cache over Redis without one is
    /// refused.
    pub fn with_sealer(
        spec: &'static CacheSpec,
        store: Option<Store>,
        sealer: Option<std::sync::Arc<dyn ValueSealer>>,
    ) -> Result<Self, AppError> {
        spec.validate()
            .map_err(|e| AppError::internal(e.to_string()))?;
        if spec.sensitivity == CacheSensitivity::EncryptedInRedis
            && matches!(store, Some(Store::Redis(_)))
            && sealer.is_none()
        {
            return Err(AppError::internal(format!(
                "cache {} is EncryptedInRedis over Redis and needs cache.encryption_key",
                spec.name
            )));
        }
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
            sealer,
            warm_loader: None,
            last_degraded_warning: Mutex::new(None),
            deps: Mutex::new(DepIndex::default()),
        })
    }

    /// Z3-T7: the loader [`warm_now`](Self::warm_now) fills the L1 from.
    pub fn with_warm(mut self, loader: WarmLoader<V>) -> Self {
        self.warm_loader = Some(loader);
        self
    }

    /// Z3-T7: bounds the L1 by the serialized size of its entries, at most
    /// `bytes` in all, instead of by `l1_capacity` entries. Entries already
    /// held are dropped.
    pub fn with_quota(mut self, bytes: u64) -> Self {
        self.l1 = moka::future::Cache::builder()
            .max_capacity(bytes)
            .weigher(|key: &String, value: &V| {
                let size = key.len() + serde_json::to_vec(value).map_or(0, |b| b.len());
                u32::try_from(size).unwrap_or(u32::MAX)
            })
            .expire_after(JitterExpiry {
                ttl: self.spec.ttl,
                jitter_pct: self.spec.jitter_pct,
            })
            .build();
        self
    }

    /// Z3-T7: fills the L1 from the warm loader; answers how many entries
    /// went in (none without a loader). Ids are as for
    /// [`get_or_load`](Self::get_or_load) (a partitioned cache's loader
    /// returns `"{reader}:{id}"`).
    pub async fn warm_now(&self) -> usize {
        let Some(loader) = &self.warm_loader else {
            return 0;
        };
        let pairs = loader().await;
        let n = pairs.len();
        for (id, value) in pairs {
            self.l1.insert(self.spec.key(&id), value).await;
        }
        n
    }

    fn shared_store(&self) -> Option<&Store> {
        match self.spec.sensitivity {
            CacheSensitivity::LocalOnly => None,
            _ => self.store.as_ref(),
        }
    }

    /// The sealer for values bound for `store`: only Redis values of an
    /// `EncryptedInRedis` cache are sealed.
    fn sealer_for(&self, store: &Store) -> Option<&dyn ValueSealer> {
        match (self.spec.sensitivity, store) {
            (CacheSensitivity::EncryptedInRedis, Store::Redis(_)) => self.sealer.as_deref(),
            _ => None,
        }
    }

    fn warn_degraded(&self, error: &AppError) {
        let mut last = self
            .last_degraded_warning
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = last.is_none_or(|at| at.elapsed() >= crate::timeouts::DEGRADED_WARNING_EVERY);
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
        let sealer = self.sealer_for(store);
        match bounded(crate::timeouts::REQUEST_PATH, store.get(key)).await {
            Ok(Some(stored)) => {
                let text = match sealer {
                    Some(sealer) => sealer.open(&stored).map_err(|error| {
                        tracing::warn!(cache = self.spec.name, %error, "sealed cache entry does not open; reloading");
                    }),
                    None => Ok(stored),
                };
                if let Ok(text) = text {
                    match serde_json::from_str::<V>(&text) {
                        Ok(value) => return Ok(value),
                        // A value written by another version: read the source.
                        Err(error) => {
                            tracing::debug!(cache = self.spec.name, %error, "cache entry does not decode; reloading");
                        }
                    }
                }
            }
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
            let stored = match sealer {
                Some(sealer) => sealer.seal(&text),
                None => Ok(text),
            };
            match stored {
                Ok(stored) => {
                    let ttl = jittered(self.spec.ttl, self.spec.jitter_pct, seed(key));
                    if let Err(error) = bounded(
                        crate::timeouts::REQUEST_PATH,
                        store.set(key, &stored, Some(ttl)),
                    )
                    .await
                    {
                        self.warn_degraded(&error);
                    }
                }
                // Never written unsealed: the value stays in this node only.
                Err(error) => {
                    tracing::warn!(cache = self.spec.name, %error, "cache value could not be sealed; not shared");
                }
            }
        }
        Ok(value)
    }

    /// Drops `id` from this node and the shared store.
    pub async fn invalidate(&self, id: &str) -> Result<(), AppError> {
        let key = self.spec.key(id);
        self.l1.invalidate(&key).await;
        if let Some(store) = self.shared_store() {
            bounded(crate::timeouts::BACKGROUND, store.del(&key)).await?;
        }
        Ok(())
    }

    /// Drops `id` from this node only (another node's change arrived).
    pub async fn invalidate_local(&self, id: &str) {
        self.l1.invalidate(&self.spec.key(id)).await;
    }

    /// Z3-T5: the value for `id` (as [`get_or_load`](Self::get_or_load), or
    /// [`get_or_load_for`](Self::get_or_load_for) with `reader`), recorded
    /// under `depends_on` so the change-feed bus drops it on this node when
    /// one of them is written. The key is recorded before the value loads
    /// and the value is kept only if no dependency was written meanwhile.
    pub async fn get_or_load_depending<F>(
        &self,
        reader: Option<&str>,
        id: &str,
        depends_on: &[Dependency],
        loader: F,
    ) -> Result<V, AppError>
    where
        F: Future<Output = Result<V, AppError>>,
    {
        let key = match reader {
            Some(reader) => self.reader_key(reader, id)?,
            None if self.spec.partition == Partition::Shared => self.spec.key(id),
            None => {
                return Err(AppError::internal(format!(
                    "cache {} is partitioned {:?}; a reader is required",
                    self.spec.name, self.spec.partition
                )));
            }
        };
        let limit = usize::try_from(self.spec.l1_capacity)
            .unwrap_or(usize::MAX)
            .saturating_mul(2);
        let recorded = self.index().record(&key, depends_on, limit);
        if !recorded {
            self.l1.invalidate_all();
        }
        let value = self.fetch(key.clone(), loader).await?;
        let current = self.index().still_recorded(&key, depends_on);
        if !current {
            self.drop_key(&key).await;
        }
        Ok(value)
    }

    fn index(&self) -> std::sync::MutexGuard<'_, DepIndex> {
        self.deps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drops `key` from the L1 and the shared store; a store failure is
    /// the degraded warning, the entry then lives its TTL there.
    async fn drop_key(&self, key: &str) {
        self.l1.invalidate(key).await;
        if let Some(store) = self.shared_store()
            && let Err(error) = bounded(crate::timeouts::BACKGROUND, store.del(key)).await
        {
            self.warn_degraded(&error);
        }
    }

    /// Z3-T4: drops one reader's `id` from this node and the shared store.
    pub async fn invalidate_for(&self, reader: &str, id: &str) -> Result<(), AppError> {
        let key = self.reader_key(reader, id)?;
        self.l1.invalidate(&key).await;
        if let Some(store) = self.shared_store() {
            bounded(crate::timeouts::BACKGROUND, store.del(&key)).await?;
        }
        Ok(())
    }
}

impl<V> Warmable for TieredCache<V>
where
    V: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    fn cache_name(&self) -> &'static str {
        self.spec.name
    }

    fn warm(&self) -> std::pin::Pin<Box<dyn Future<Output = usize> + Send + '_>> {
        Box::pin(async move {
            if self.spec.warm_on_start {
                self.warm_now().await
            } else {
                0
            }
        })
    }
}

impl<V> InvalidateDeps for TieredCache<V>
where
    V: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    fn cache_name(&self) -> &'static str {
        self.spec.name
    }

    fn invalidate_dependency<'a>(
        &'a self,
        dependency: &'a Dependency,
    ) -> std::pin::Pin<Box<dyn Future<Output = usize> + Send + 'a>> {
        Box::pin(async move {
            let keys = self.index().take(dependency);
            for key in &keys {
                self.drop_key(key).await;
            }
            keys.len()
        })
    }

    fn flush_local(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.index().clear();
            self.l1.invalidate_all();
        })
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

    #[tokio::test]
    async fn warm_now_fills_l1() {
        static WARM: CacheSpec = CacheSpec {
            warm_on_start: true,
            ..spec(
                "cache:tiered_warm",
                "tiered_warm",
                FailureMode::FallBackToSource,
            )
        };
        let cache = Arc::new(
            TieredCache::<u32>::new(&WARM, None)
                .unwrap()
                .with_warm(Box::new(|| -> WarmFuture<u32> {
                    Box::pin(async { vec![("a".to_string(), 1), ("b".to_string(), 2)] })
                })),
        );
        let as_warmable: Arc<dyn Warmable> = cache.clone();
        register_warm(&as_warmable);
        assert!(warm_registered(Duration::from_secs(5)).await >= 2);
        let a = cache.get_or_load("a", async { Ok(99) }).await.unwrap();
        assert_eq!(a, 1, "served from the warmed L1, not the loader");
        assert_eq!(cache.warm_now().await, 2);
    }

    #[tokio::test]
    async fn quota_evicts_over_limit() {
        static QUOTA: CacheSpec = spec(
            "cache:tiered_quota",
            "tiered_quota",
            FailureMode::FallBackToSource,
        );
        let cache = TieredCache::<String>::new(&QUOTA, None)
            .unwrap()
            .with_quota(1_000);
        for i in 0..50 {
            let value = format!("{i:0>100}");
            cache
                .get_or_load(&i.to_string(), async move { Ok(value) })
                .await
                .unwrap();
        }
        cache.l1.run_pending_tasks().await;
        assert!(
            cache.l1.weighted_size() <= 1_000,
            "{}",
            cache.l1.weighted_size()
        );
        assert!(cache.l1.entry_count() < 50);
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

//! G-9 (web portal plan §4.2): the portal's per-node L1 cache.
//!
//! A portal record request used to read the portal by keyword, its auth
//! policy and the principal's whole grant (conditions, field profile, entity
//! config, every lookup target's grant) from PostgreSQL on every call: 18
//! statements for one record `GET` against C7's budget of 8. This module
//! caches the parts that change only through the portal admin API.
//!
//! **Source of truth:** PostgreSQL. Nothing here is written anywhere but
//! process memory; a fresh node behaves identically, only slower.
//!
//! **What is cached** (two declared [`TieredCache`]s, [`PORTALS_SPEC`] and
//! [`PLANS_SPEC`] (Z3-T8), in process memory only, [`TTL_SECS`] each, at
//! most [`CAPACITY`] entries each, listed in `/api/v1/admin/caches`):
//! - `attome-portal:portal:{keyword}:{version}` → the live portal
//!   ([`PortalDetail`]) and its [`AuthPolicy`] (CIDR list, record budget,
//!   page-size cap, consent versions). Unknown, disabled and anonymous
//!   keywords are never cached.
//! - `attome-portal:plan:{portal_id}:{role_id}:{entity}:{version}` → the role's
//!   grant on the entity **before** anything user-specific is applied
//!   ([`crate::context::PlanTemplate`]): actions, the raw conditions, the field
//!   profile, the portal user field and each readable lookup's target grant.
//!   Stamped with the metadata registry snapshot it was built against; a
//!   different snapshot is a miss, so a field dropped or retyped since is never
//!   served from here.
//!
//! **Never cached**, read on every request: the credential epoch, the refresh
//! family, the account's status, its role assignment and the portal's own
//! liveness (one statement, [`crate::auth::resolve_principal`]); the portal
//! user's `value_ref` sources and label (one statement: those are ordinary
//! `webportal_user` fields generic CRUD may change, so a cached value
//! could scope a user to a company they no longer belong to); consent; the
//! owning team (writes only); budgets.
//!
//! **Invalidation:** `{version}` is [`ACCESS_VERSION_KEY`], a random token in
//! Redis (the cache pool). Every portal-admin write replaces it after its
//! transaction commits ([`invalidate`], called by every mutating handler in
//! [`crate::admin`]). Each request reads it once ([`current_version`]) before
//! any cached read, so every node misses on its next request after a write —
//! no subscriber is needed, and a lost pub/sub message cannot leave a node
//! stale. A portal entry also depends on the `webportal` entity, so a
//! generic write of a portal record drops this node's entries through the
//! change feed (Z3-T5). The token is random rather than a counter so that an evicted,
//! expired or flushed key starts a version no earlier entry can carry
//! (D-625's absence rule): absence means "cold", never "reuse".
//!
//! **Failure:** a Redis error or timeout reading the version, or an absent
//! version, bypasses the cache for that request (PostgreSQL reads, nothing
//! inserted) and counts `portal_cache_bypass_total{reason}`. The cache never
//! widens anything: without a version it is not consulted. A failed version
//! bump after a committed admin write is logged at `error` and counted in
//! `portal_cache_invalidation_failed_total`; other nodes may then serve the
//! previous grant for at most [`TTL_SECS`] (the same best-effort posture as
//! the staff authz cache's `invalidate`, D-051/D-116). Revocation of a user
//! (disable, erase, delete, password or MFA reset) never depends on this
//! cache: it bumps the credential epoch, which is read live.
//!
//! **Cold start:** empty; the first request per portal and per role/entity
//! reads PostgreSQL. A missing version key is created on first read.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use attome_cache::Store;
use attome_cache::depends::Dependency;
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::TieredCache;
use attome_core::{EngineState, EntityMetaRegistry};
use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::context::PlanTemplate;
use crate::policy::AuthPolicy;
use crate::provision::PortalDetail;
use crate::telemetry;

/// The portal access version. Cache pool (a coherence cache, not a security
/// control: a missing or unreadable value only disables the cache). A random
/// token, replaced on every portal-admin write; expires after
/// [`ACCESS_VERSION_TTL_SECS`] of no writes, which only costs one cold miss.
pub const ACCESS_VERSION_KEY: &str = "attome-portal:access-version:global";
const ACCESS_VERSION_TTL_SECS: i64 = 86_400;
/// L1 time to live: the bound on staleness if a version bump is lost.
pub const TTL_SECS: u64 = 30;
/// Entries per L1 (portals, and role × entity plans).
pub const CAPACITY: u64 = 10_000;
/// Bounds every Redis call here (caching-and-state: a call site outside
/// `attome-cache` bounds its own fred calls). The same class as the staff
/// authz cache's L2 reads. Deliberately 200 ms, below
/// `attome_cache::timeouts::REQUEST_PATH` (300 ms): a miss falls back to
/// PostgreSQL, so a slow Redis should give up sooner than a coordination call.
const OP_TIMEOUT: Duration = Duration::from_millis(200);

/// The metadata entity a portal entry is read from; a generic write of it
/// drops this node's portal entries through the change feed (Z3-T5).
const PORTAL_ENTITY: &str = "webportal";

/// Z3-T8: the live portals by keyword and access version. Process memory
/// only: the per-node shape this cache has always had, and the access
/// version in the id already makes every node miss after an admin write.
pub static PORTALS_SPEC: CacheSpec = CacheSpec {
    name: "attome-portal:portal",
    crate_name: "attome-portal",
    purpose: "portal",
    source_of_truth: "PostgreSQL webportal and webportal_auth_policy",
    ttl: Duration::from_secs(TTL_SECS),
    jitter_pct: 0,
    l1_capacity: CAPACITY,
    partition: Partition::Shared,
    sensitivity: CacheSensitivity::LocalOnly,
    failure: FailureMode::FallBackToSource,
    invalidation: "the access version in the id, replaced by every portal-admin write; \
                   a generic webportal write through the change feed; TTL_SECS",
    cold_start: "empty; the first request per portal reads PostgreSQL",
    warm_on_start: false,
};

/// Z3-T8: each role's plan template per entity and access version. Process
/// memory only: a template is stamped with this node's metadata snapshot,
/// which does not travel.
pub static PLANS_SPEC: CacheSpec = CacheSpec {
    name: "attome-portal:plan",
    crate_name: "attome-portal",
    purpose: "plan",
    source_of_truth: "PostgreSQL webportal_grant, webportal_grant_condition, \
                      webportal_grant_field and webportal_entity",
    ttl: Duration::from_secs(TTL_SECS),
    jitter_pct: 0,
    l1_capacity: CAPACITY,
    partition: Partition::Shared,
    sensitivity: CacheSensitivity::LocalOnly,
    failure: FailureMode::FallBackToSource,
    invalidation: "the access version in the id, replaced by every portal-admin write; \
                   a template built against an older metadata snapshot is rebuilt; TTL_SECS",
    cold_start: "empty; the first request per role and entity reads PostgreSQL",
    warm_on_start: false,
};

/// A live, enabled, non-anonymous portal and its auth policy.
#[derive(Debug, Serialize, Deserialize)]
pub struct PortalEntry {
    pub detail: PortalDetail,
    pub policy: AuthPolicy,
}

/// A cached value shared by reference, as the L1 has always held it. The
/// cache never writes it anywhere (`LocalOnly`), so the (de)serialization a
/// `TieredCache` value must offer is never used on the request path.
#[derive(Debug)]
struct Held<T>(Arc<T>);

impl<T> Clone for Held<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: Serialize> Serialize for Held<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Held<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(|value| Self(Arc::new(value)))
    }
}

/// The per-node L1. One per portal router ([`crate::router::app`]). Each
/// tier is `None` only if its declaration was refused at start, which
/// [`tests::portal_spec_validates`] rules out; the cache is then bypassed.
pub struct PortalCache {
    portals: Option<Arc<TieredCache<Held<PortalEntry>>>>,
    plans: Option<TieredCache<Held<PlanTemplate>>>,
}

impl std::fmt::Debug for PortalCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalCache").finish_non_exhaustive()
    }
}

fn declared<V>(spec: &'static CacheSpec) -> Option<TieredCache<V>>
where
    V: Clone + Send + Sync + Serialize + serde::de::DeserializeOwned + 'static,
{
    TieredCache::new(spec, None)
        .map_err(|error| {
            tracing::error!(cache = spec.name, %error, "portal cache refused; bypassing it");
        })
        .ok()
}

impl Default for PortalCache {
    fn default() -> Self {
        let portals = declared(&PORTALS_SPEC).map(Arc::new);
        if let Some(portals) = &portals {
            attome_core::cache_invalidation::bus().register(Arc::clone(portals) as _);
        }
        Self {
            portals,
            plans: declared(&PLANS_SPEC),
        }
    }
}

fn portal_id(keyword: &str, version: &str) -> String {
    format!("{keyword}:{version}")
}

fn plan_id(portal_id: Uuid, role_id: Uuid, entity: &str, version: &str) -> String {
    format!("{portal_id}:{role_id}:{entity}:{version}")
}

/// `hot_cache_lookups_total{cache, outcome}`, as before Z3-T8.
fn record_lookup(cache: &'static str, loaded: &AtomicBool) {
    metrics::counter!(
        "hot_cache_lookups_total",
        "cache" => cache,
        "outcome" => if loaded.load(Ordering::Relaxed) { "miss" } else { "hit" },
    )
    .increment(1);
}

/// The live portal named by `keyword` (already lowercased) and its policy,
/// from PostgreSQL, or `None`.
pub(crate) async fn load_portal_entry(
    db: &DbPool,
    keyword: &str,
) -> Result<Option<PortalEntry>, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let Some(detail) = crate::auth::resolve_portal_with_users(&mut conn, keyword).await? else {
        return Ok(None);
    };
    let policy = crate::policy::load(&mut conn, detail.id).await?;
    Ok(Some(PortalEntry { detail, policy }))
}

impl PortalCache {
    /// The live portal named by `keyword` (already lowercased), or `None`.
    /// With a `version`, served from and written to the L1; without one,
    /// PostgreSQL only. An unknown, disabled or anonymous keyword is never
    /// cached (the load answers not-found, which the cache does not keep).
    pub(crate) async fn portal(
        &self,
        db: &DbPool,
        keyword: &str,
        version: Option<&str>,
    ) -> Result<Option<Arc<PortalEntry>>, AppError> {
        let (Some(version), Some(cache)) = (version, &self.portals) else {
            return Ok(load_portal_entry(db, keyword).await?.map(Arc::new));
        };
        let loaded = AtomicBool::new(false);
        let found = cache
            .get_or_load_depending(
                None,
                &portal_id(keyword, version),
                &[Dependency::Entity(PORTAL_ENTITY.to_owned())],
                async {
                    loaded.store(true, Ordering::Relaxed);
                    load_portal_entry(db, keyword)
                        .await?
                        .map(|entry| Held(Arc::new(entry)))
                        .ok_or(AppError::NotFound)
                },
            )
            .await;
        record_lookup("portal_entry", &loaded);
        match found {
            Ok(entry) => Ok(Some(entry.0)),
            Err(AppError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The role's plan template for `entity`: from the L1 when `version` is
    /// known and the entry was built against `registry`, else built by `build`
    /// (and cached when `version` is known). A template built against an
    /// older snapshot is dropped and rebuilt.
    pub(crate) async fn plan<F>(
        &self,
        key: (Uuid, Uuid, &str),
        version: Option<&str>,
        registry: &Arc<EntityMetaRegistry>,
        build: F,
    ) -> Result<Arc<PlanTemplate>, AppError>
    where
        F: Future<Output = Result<PlanTemplate, AppError>>,
    {
        let (Some(version), Some(cache)) = (version, &self.plans) else {
            return Ok(Arc::new(build.await?));
        };
        let (portal_id, role_id, entity) = key;
        let id = plan_id(portal_id, role_id, entity, version);
        let mut build = Some(build);
        let loaded = AtomicBool::new(false);
        let fill = |build: &mut Option<F>| {
            let build = build.take();
            let loaded = &loaded;
            async move {
                loaded.store(true, Ordering::Relaxed);
                match build {
                    Some(build) => build.await.map(|template| Held(Arc::new(template))),
                    None => Err(AppError::internal("portal plan template built twice")),
                }
            }
        };
        let hit = cache.get_or_load(&id, fill(&mut build)).await?;
        record_lookup("portal_plan", &loaded);
        if hit.0.built_against(registry) {
            return Ok(hit.0);
        }
        cache.invalidate_local(&id).await;
        let fresh = cache.get_or_load(&id, fill(&mut build)).await?;
        if fresh.0.built_against(registry) {
            return Ok(fresh.0);
        }
        // Another request filled the id from an older snapshot meanwhile:
        // build this one without caching it.
        match build.take() {
            Some(build) => Ok(Arc::new(build.await?)),
            None => Ok(fresh.0),
        }
    }
}

/// The current access version, or `None` when the cache must be bypassed
/// (Redis error or timeout, or no version yet — one is then started).
pub(crate) async fn current_version(redis: &Store) -> Option<String> {
    match tokio::time::timeout(OP_TIMEOUT, redis.get(ACCESS_VERSION_KEY)).await {
        Ok(Ok(Some(version))) => Some(version),
        Ok(Ok(None)) => {
            // Cold, expired or evicted. Start a version no earlier entry can
            // carry; `NX` so racing nodes agree on one. This request still
            // bypasses: it can't know which node's token won.
            let started = tokio::time::timeout(
                OP_TIMEOUT,
                redis.set_nx(
                    ACCESS_VERSION_KEY,
                    &Uuid::now_v7().to_string(),
                    Some(std::time::Duration::from_secs(
                        ACCESS_VERSION_TTL_SECS as u64,
                    )),
                ),
            )
            .await;
            if !matches!(started, Ok(Ok(_))) {
                tracing::warn!("portal cache: could not start an access version; bypassing");
            }
            telemetry::cache_bypass(telemetry::CACHE_BYPASS_ABSENT);
            None
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "portal cache: access version read failed; bypassing");
            telemetry::cache_bypass(telemetry::CACHE_BYPASS_REDIS);
            None
        }
        Err(_) => {
            tracing::warn!("portal cache: access version read timed out; bypassing");
            telemetry::cache_bypass(telemetry::CACHE_BYPASS_REDIS);
            None
        }
    }
}

/// Replaces the access version: every node's next portal request misses.
/// Call after the admin write's transaction commits, never inside it. Public
/// for code (and tests) that write portal configuration through the engine
/// functions directly instead of the admin API.
pub async fn bump_version(redis: &Store) -> Result<(), String> {
    match tokio::time::timeout(
        OP_TIMEOUT,
        redis.set(
            ACCESS_VERSION_KEY,
            &Uuid::now_v7().to_string(),
            Some(std::time::Duration::from_secs(
                ACCESS_VERSION_TTL_SECS as u64,
            )),
        ),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

/// After a committed portal-admin write: invalidates every node's portal
/// cache. Best-effort — the write already committed — so a failure is logged
/// for the operator and counted, and the stale window is at most [`TTL_SECS`].
pub(crate) async fn invalidate(state: &EngineState) {
    if let Err(error) = bump_version(&state.base.redis).await {
        telemetry::cache_invalidation_failed();
        tracing::error!(
            %error,
            ttl_secs = TTL_SECS,
            "portal cache invalidation failed after a committed portal-admin write; \
             nodes may serve the previous portal grants until their entries expire. \
             Check Redis (cache pool) health"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool whose server does not exist: every command fails or times out.
    fn unreachable_pool() -> Store {
        use fred::interfaces::ClientLike;
        use fred::prelude::{Builder, RedisConfig};
        let config = RedisConfig::from_url("redis://127.0.0.1:1").unwrap();
        let pool = Builder::from_config(config)
            .with_performance_config(|c| {
                c.default_command_timeout = Duration::from_millis(100);
            })
            .build_pool(1)
            .unwrap();
        pool.connect();
        Store::Redis(pool)
    }

    /// Redis down: no version, so the caller bypasses the cache and reads
    /// PostgreSQL; the read is bounded, never hangs.
    #[tokio::test]
    async fn an_unreachable_redis_yields_no_version_within_the_bound() {
        let pool = unreachable_pool();
        let started = std::time::Instant::now();
        assert_eq!(current_version(&pool).await, None);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(bump_version(&pool).await.is_err());
    }

    #[test]
    fn keys_carry_every_input_and_the_version() {
        let (p, r) = (Uuid::nil(), Uuid::max());
        assert_eq!(
            PORTALS_SPEC.key(&portal_id("customers", "v1")),
            "attome-portal:portal:customers:v1"
        );
        let k = PLANS_SPEC.key(&plan_id(p, r, "case", "v2"));
        assert!(k.starts_with("attome-portal:plan:"));
        assert!(k.contains(&p.to_string()) && k.contains(&r.to_string()));
        assert!(k.ends_with(":case:v2"));
        assert_ne!(plan_id(p, r, "case", "v1"), plan_id(p, r, "case", "v2"));
    }

    #[test]
    fn portal_spec_validates() {
        assert_eq!(PORTALS_SPEC.validate(), Ok(()));
        assert_eq!(PLANS_SPEC.validate(), Ok(()));
        assert_eq!(PORTALS_SPEC.ttl, Duration::from_secs(TTL_SECS));
        assert_eq!(PLANS_SPEC.l1_capacity, CAPACITY);
        assert_eq!(
            PORTALS_SPEC.partition,
            Partition::Shared,
            "no per-user data"
        );
        let cache = PortalCache::default();
        assert!(cache.portals.is_some() && cache.plans.is_some());
    }
}

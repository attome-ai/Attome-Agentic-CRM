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
//! **What is cached** (two moka [`HotCache`]s, [`TTL_SECS`] each, at most
//! [`CAPACITY`] entries each):
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
//! stale. The token is random rather than a counter so that an evicted,
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
use std::time::Duration;

use attome_cache::{HotCache, RedisPool, create_hot_cache, get_recorded};
use attome_core::{EngineState, EntityMetaRegistry};
use attome_db::DbPool;
use attome_types::AppError;
use fred::prelude::*;
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

/// A live, enabled, non-anonymous portal and its auth policy.
#[derive(Debug)]
pub struct PortalEntry {
    pub detail: PortalDetail,
    pub policy: AuthPolicy,
}

/// The per-node L1. One per portal router ([`crate::router::app`]).
pub struct PortalCache {
    portals: HotCache<Arc<PortalEntry>>,
    plans: HotCache<Arc<PlanTemplate>>,
}

impl std::fmt::Debug for PortalCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalCache").finish_non_exhaustive()
    }
}

impl Default for PortalCache {
    fn default() -> Self {
        Self {
            portals: create_hot_cache(CAPACITY, TTL_SECS),
            plans: create_hot_cache(CAPACITY, TTL_SECS),
        }
    }
}

fn portal_key(keyword: &str, version: &str) -> String {
    format!("attome-portal:portal:{keyword}:{version}")
}

fn plan_key(portal_id: Uuid, role_id: Uuid, entity: &str, version: &str) -> String {
    format!("attome-portal:plan:{portal_id}:{role_id}:{entity}:{version}")
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
    /// PostgreSQL only.
    pub(crate) async fn portal(
        &self,
        db: &DbPool,
        keyword: &str,
        version: Option<&str>,
    ) -> Result<Option<Arc<PortalEntry>>, AppError> {
        let key = version.map(|v| portal_key(keyword, v));
        if let Some(key) = &key
            && let Some(hit) = get_recorded(&self.portals, key, "portal_entry").await
        {
            return Ok(Some(hit));
        }
        let Some(entry) = load_portal_entry(db, keyword).await?.map(Arc::new) else {
            return Ok(None);
        };
        if let Some(key) = key {
            self.portals.insert(key, Arc::clone(&entry)).await;
        }
        Ok(Some(entry))
    }

    /// The role's plan template for `entity`: from the L1 when `version` is
    /// known and the entry was built against `registry`, else built by `build`
    /// (and cached when `version` is known). Misses fill without
    /// `try_get_with`: the fill is a handful of primary-key reads and misses
    /// follow only an admin write, a metadata change or the TTL.
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
        let (portal_id, role_id, entity) = key;
        let key = version.map(|v| plan_key(portal_id, role_id, entity, v));
        if let Some(key) = &key
            && let Some(hit) = get_recorded(&self.plans, key, "portal_plan").await
        {
            if hit.built_against(registry) {
                return Ok(hit);
            }
            self.plans.invalidate(key).await;
        }
        let template = Arc::new(build.await?);
        if let Some(key) = key {
            self.plans.insert(key, Arc::clone(&template)).await;
        }
        Ok(template)
    }
}

/// The current access version, or `None` when the cache must be bypassed
/// (Redis error or timeout, or no version yet — one is then started).
pub(crate) async fn current_version(redis: &RedisPool) -> Option<String> {
    match tokio::time::timeout(
        OP_TIMEOUT,
        redis.get::<Option<String>, _>(ACCESS_VERSION_KEY),
    )
    .await
    {
        Ok(Ok(Some(version))) => Some(version),
        Ok(Ok(None)) => {
            // Cold, expired or evicted. Start a version no earlier entry can
            // carry; `NX` so racing nodes agree on one. This request still
            // bypasses: it can't know which node's token won.
            let started = tokio::time::timeout(
                OP_TIMEOUT,
                redis.set::<Option<String>, _, _>(
                    ACCESS_VERSION_KEY,
                    Uuid::now_v7().to_string(),
                    Some(Expiration::EX(ACCESS_VERSION_TTL_SECS)),
                    Some(SetOptions::NX),
                    false,
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
pub async fn bump_version(redis: &RedisPool) -> Result<(), String> {
    match tokio::time::timeout(
        OP_TIMEOUT,
        redis.set::<Option<String>, _, _>(
            ACCESS_VERSION_KEY,
            Uuid::now_v7().to_string(),
            Some(Expiration::EX(ACCESS_VERSION_TTL_SECS)),
            None,
            false,
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
    fn unreachable_pool() -> RedisPool {
        let config = RedisConfig::from_url("redis://127.0.0.1:1").unwrap();
        let pool = Builder::from_config(config)
            .with_performance_config(|c| {
                c.default_command_timeout = Duration::from_millis(100);
            })
            .build_pool(1)
            .unwrap();
        pool.connect();
        pool
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
            portal_key("customers", "v1"),
            "attome-portal:portal:customers:v1"
        );
        let k = plan_key(p, r, "case", "v2");
        assert!(k.starts_with("attome-portal:plan:"));
        assert!(k.contains(&p.to_string()) && k.contains(&r.to_string()));
        assert!(k.ends_with(":case:v2"));
        assert_ne!(plan_key(p, r, "case", "v1"), plan_key(p, r, "case", "v2"));
    }
}

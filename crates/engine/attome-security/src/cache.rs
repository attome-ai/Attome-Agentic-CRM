//! L1 (moka, in-process) + L2 (Redis, cross-replica) cache for resolved
//! `SecurityContext`s. 60s TTL on both layers per guidelines §5/§14.4.

use std::sync::Arc;

use attome_cache::{HotCache, Store, create_hot_cache};
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use std::time::Duration;
use uuid::Uuid;

use crate::db::{resolve_field_grants, resolve_privileges};

const TTL_SECS: u64 = 60;
/// "{crate}:{purpose}:{id}" per guidelines §5. The `v2` segment (D-789
/// §4.3) retires every entry written before `SecurityContext.role_ids`
/// existed: such an entry would deserialize with `role_ids: None`, which
/// reads as a system writer and skips business-rule locks. Bump it again
/// whenever a new field's `#[serde(default)]` would not fail closed.
const REDIS_PREFIX: &str = "security:ctx:v2";
/// Cross-node authz-cache invalidation doorbell (D-051) — mirrors the
/// `meta_version` pattern (`attome-server/src/admin.rs`/`system.rs`), except the
/// payload itself has to carry the `user_id` being invalidated: unlike
/// metadata, there's no change-log table here for a remote node to re-derive
/// "what changed" from, so the message IS the instruction. Subscriber lives
/// in `attome-server/src/system.rs`, alongside the metadata one.
pub const SECURITY_VERSION_CHANNEL: &str = "security_version";
/// P1.15 §4(d): the L2 cache already degrades to L1/DB on any Redis error
/// (§4c — cache concern, not a security control); bounding these calls just
/// keeps a slow/unreachable Redis from adding latency on top of that,
/// instead of leaving them to fred's ambient connection-pool default.
/// Deliberately tighter than `attome_cache::timeouts::REQUEST_PATH`: a miss falls back to L1/DB.
const OP_TIMEOUT: Duration = Duration::from_millis(200);

/// P-authz-revocation-epoch (D-116): the per-user revocation counter's own
/// Redis prefix — deliberately `xrm:` (not `security:`, see `REDIS_PREFIX`
/// above) per the plan's key-shape choice, and its own 300ms timeout class
/// (P1.15/D-027's fail-closed pattern, mirroring `attome-s2s`'s guard) rather
/// than reusing `OP_TIMEOUT`, since this counter is consulted by a security
/// control (`resolve_strict`), not just a cache-coherence path.
const EPOCH_REDIS_PREFIX: &str = "xrm:authz_epoch";
const EPOCH_OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

fn moka_key(user_id: Uuid) -> String {
    format!("{user_id}:sec")
}

fn redis_key(user_id: Uuid) -> String {
    format!("{REDIS_PREFIX}:{user_id}")
}

fn epoch_key(user_id: Uuid) -> String {
    format!("{EPOCH_REDIS_PREFIX}:{user_id}")
}

/// Fail-OPEN epoch read — used only to opportunistically stamp a freshly
/// (DB-)resolved `SecurityContext` with the epoch it was resolved under, on
/// the ordinary D-012 cache path. A Redis hiccup here must never break an
/// otherwise-successful resolve; `0` is the same value an absent key GETs
/// as, so failing open never manufactures a false "stale" reading later.
async fn get_epoch_fail_open(redis_coordination: &Store, user_id: Uuid) -> i64 {
    match tokio::time::timeout(
        EPOCH_OP_TIMEOUT,
        redis_coordination.get(&epoch_key(user_id)),
    )
    .await
    {
        Ok(Ok(Some(n))) => n.parse().unwrap_or(0),
        Ok(Ok(None)) => 0,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %user_id, "authz epoch GET failed (ordinary path — failing open to 0)");
            0
        }
        Err(_) => {
            tracing::warn!(%user_id, "authz epoch GET timed out (ordinary path — failing open to 0)");
            0
        }
    }
}

/// Fail-CLOSED epoch read — the security control itself (`resolve_strict`,
/// and `security.strict_revocation`'s always-on mode). Mirrors
/// `attome_auth::revocation::is_revoked`/`attome_s2s::rate_limit::check_with_nonce`'s
/// posture: a Redis error or timeout here must never be mistaken for "no
/// revocation happened," so it's a hard `Err`, not a stale value.
async fn get_epoch_fail_closed(redis_coordination: &Store, user_id: Uuid) -> Result<i64, AppError> {
    tokio::time::timeout(
        EPOCH_OP_TIMEOUT,
        redis_coordination.get(&epoch_key(user_id)),
    )
    .await
    .map_err(|_| AppError::internal("authz epoch check timed out"))?
    .map(|opt| opt.and_then(|n| n.parse().ok()).unwrap_or(0))
    .map_err(|e| AppError::internal(format!("authz epoch check failed: {e}")))
}

/// INCRs the per-user epoch, fail-closed — the caller decides whether a
/// failure here is acceptable (`invalidate`, best-effort) or must abort the
/// whole operation (`invalidate_sync`, goal (b)'s acknowledged path).
async fn incr_epoch(redis_coordination: &Store, user_id: Uuid) -> Result<i64, AppError> {
    tokio::time::timeout(
        EPOCH_OP_TIMEOUT,
        redis_coordination.incr(&epoch_key(user_id)),
    )
    .await
    .map_err(|_| AppError::internal("authz epoch bump timed out"))?
    .map_err(|e| AppError::internal(format!("authz epoch bump failed: {e}")))
}

pub struct SecurityCache {
    hot: HotCache<Arc<SecurityContext>>,
    redis: Store,
    /// P-authz-revocation-epoch (D-116): the epoch counter is a security
    /// control (P1.15/D-027), so it lives on the coordination-role pool —
    /// same classification as the S2S nonce/rate-limit guard and the general
    /// HTTP rate limiter, never the general `redis` pool above.
    redis_coordination: Store,
    db: DbPool,
}

impl std::fmt::Debug for SecurityCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityCache").finish_non_exhaustive()
    }
}

impl SecurityCache {
    /// The pool this cache resolves from.
    pub(crate) fn db(&self) -> &DbPool {
        &self.db
    }

    pub fn new(db: DbPool, redis: impl Into<Store>, redis_coordination: impl Into<Store>) -> Self {
        Self {
            hot: create_hot_cache(10_000, TTL_SECS),
            redis: redis.into(),
            redis_coordination: redis_coordination.into(),
            db,
        }
    }

    /// Recomputes from Postgres unconditionally and writes the result through
    /// to L2 + L1, stamped with the given `epoch` (the caller has already
    /// resolved — or fail-closed-checked — the epoch it wants this entry
    /// associated with). Shared by the ordinary miss path (`resolve`, which
    /// passes a fail-open-read epoch) and `resolve_strict`'s mismatch branch
    /// (which passes the just-confirmed-live epoch).
    async fn resolve_fresh(
        &self,
        user_id: Uuid,
        epoch: i64,
    ) -> Result<Arc<SecurityContext>, AppError> {
        let privileges = resolve_privileges(&self.db, user_id).await?;
        let (field_grants, field_write_grants) = resolve_field_grants(&self.db, user_id).await?;
        let bulk_fields = crate::db::resolve_bulk_fields(&self.db, user_id).await?;
        let is_admin = privileges.contains(crate::context::ADMIN_PRIVILEGE_KEY);
        let rlc = crate::resolver::resolve_record_level_context(&self.db, user_id).await?;
        let condition_grants = crate::db::resolve_condition_grants(&self.db, user_id).await?;
        let ctx = SecurityContext {
            user_id,
            is_admin,
            privileges,
            field_grants,
            field_write_grants,
            bulk_fields,
            epoch,
            accessible_org_ids: rlc.accessible_org_ids,
            team_ids: rlc.team_ids,
            position_hierarchy_enabled: rlc.position_hierarchy_enabled,
            subordinate_user_ids: rlc.subordinate_user_ids,
            condition_grants,
            role_ids: Some(rlc.role_ids),
            service_principal: false,
        };

        if let Ok(json) = serde_json::to_string(&ctx) {
            let _ = tokio::time::timeout(
                OP_TIMEOUT,
                self.redis.set(
                    &redis_key(user_id),
                    &json,
                    Some(std::time::Duration::from_secs(TTL_SECS)),
                ),
            )
            .await;
        }
        let ctx = Arc::new(ctx);
        self.hot.insert(moka_key(user_id), Arc::clone(&ctx)).await;

        Ok(ctx)
    }

    pub async fn resolve(&self, user_id: Uuid) -> Result<Arc<SecurityContext>, AppError> {
        // OPS-2: `hot_cache_lookups_total{cache="security_context"}`. This is
        // the L1 whose hit rate matters most — it is consulted on essentially
        // every authenticated request, and a collapse here turns each one into
        // a Redis round trip and then a Postgres resolve.
        if let Some(ctx) =
            attome_cache::get_recorded(&self.hot, &moka_key(user_id), "security_context").await
        {
            return Ok(ctx);
        }

        if let Ok(Ok(Some(json))) =
            tokio::time::timeout(OP_TIMEOUT, self.redis.get(&redis_key(user_id))).await
            && let Ok(ctx) = serde_json::from_str::<SecurityContext>(&json)
        {
            let ctx = Arc::new(ctx);
            self.hot.insert(moka_key(user_id), Arc::clone(&ctx)).await;
            return Ok(ctx);
        }

        let epoch = get_epoch_fail_open(&self.redis_coordination, user_id).await;
        self.resolve_fresh(user_id, epoch).await
    }

    /// P-authz-revocation-epoch (D-116) goal (a): the synchronous, fail-closed
    /// re-check. Resolves normally first (cheap — almost always an L1 hit),
    /// then compares its `epoch` against the live counter; a mismatch means
    /// this entry (on THIS node, and possibly others) was resolved before a
    /// revocation that hasn't propagated here yet — drop it and re-resolve
    /// straight from Postgres, stamped with the epoch just confirmed live, so
    /// the corrected value is what every subsequent ordinary resolve sees
    /// too. Returns `Err` on a Redis error/timeout — never silently trusts
    /// the possibly-stale cached value in that case.
    pub async fn resolve_strict(&self, user_id: Uuid) -> Result<Arc<SecurityContext>, AppError> {
        let cached = self.resolve(user_id).await?;
        let live_epoch = get_epoch_fail_closed(&self.redis_coordination, user_id).await?;

        if live_epoch == cached.epoch {
            return Ok(cached);
        }

        self.hot.invalidate(&moka_key(user_id)).await;
        self.resolve_fresh(user_id, live_epoch).await
    }

    /// Called on every privilege grant/revoke (user or role) via
    /// `SecurityResolver::invalidate` — see `attome-security/src/admin.rs`. Bumps
    /// the revocation epoch (best-effort here — see `invalidate_sync` for the
    /// acknowledged variant), clears this node's own L1 + the shared L2, then
    /// publishes on `SECURITY_VERSION_CHANNEL` so every OTHER node's
    /// subscriber drops its own stale L1 entry too (D-051) — without this, a
    /// revoke handled by one node left every other node serving the old
    /// privileges for up to the 60s TTL, since L1 is per-process and nothing
    /// told them to drop it. The epoch bump happens BEFORE the cache purge
    /// (order matters: a `resolve_strict` racing this purge must see the new
    /// epoch, not the old one, however the race lands) — cache purge/publish
    /// failures are logged, never fail the request; the epoch bump itself is
    /// also best-effort here (P1.15/D-027 cache-coherence posture) — use
    /// `invalidate_sync` where a failed bump must be surfaced.
    pub async fn invalidate(&self, user_id: Uuid) {
        if let Err(e) = incr_epoch(&self.redis_coordination, user_id).await {
            tracing::warn!(error = %e, %user_id, "authz epoch bump failed (best-effort invalidate)");
        }

        self.hot.invalidate(&moka_key(user_id)).await;
        let _ = tokio::time::timeout(OP_TIMEOUT, self.redis.del(&redis_key(user_id))).await;

        match tokio::time::timeout(
            OP_TIMEOUT,
            self.redis
                .publish(SECURITY_VERSION_CHANNEL, &user_id.to_string()),
        )
        .await
        {
            Ok(Err(e)) => {
                tracing::warn!(error = %e, %user_id, "failed to publish security_version doorbell")
            }
            Err(_) => tracing::warn!(%user_id, "publishing security_version doorbell timed out"),
            Ok(Ok(_)) => {}
        }
    }

    /// P-authz-revocation-epoch (D-116) goal (b): the acknowledged
    /// counterpart to `invalidate` — the epoch bump and this node's own L2
    /// purge must both succeed before returning `Ok`, so a grant/revoke
    /// handler can 500 instead of returning 200 while cache convergence was
    /// never actually confirmed. Cross-node fan-out (the pub/sub publish)
    /// stays best-effort even here: that's exactly the pub/sub-loss case
    /// `resolve_strict`'s epoch compare exists to catch on every OTHER
    /// node's next privileged request, not something the caller should block
    /// the response on.
    pub async fn invalidate_sync(&self, user_id: Uuid) -> Result<(), AppError> {
        incr_epoch(&self.redis_coordination, user_id).await?;

        self.hot.invalidate(&moka_key(user_id)).await;
        tokio::time::timeout(OP_TIMEOUT, self.redis.del(&redis_key(user_id)))
            .await
            .map_err(|_| AppError::internal("authz cache purge (L2 delete) timed out"))?
            .map_err(|e| {
                AppError::internal(format!("authz cache purge (L2 delete) failed: {e}"))
            })?;

        match tokio::time::timeout(
            OP_TIMEOUT,
            self.redis
                .publish(SECURITY_VERSION_CHANNEL, &user_id.to_string()),
        )
        .await
        {
            Ok(Err(e)) => {
                tracing::warn!(error = %e, %user_id, "failed to publish security_version doorbell")
            }
            Err(_) => tracing::warn!(%user_id, "publishing security_version doorbell timed out"),
            Ok(Ok(_)) => {}
        }

        Ok(())
    }

    /// L1-only invalidation, driven by the `security_version` subscriber
    /// (`attome-server/src/system.rs`) when a REMOTE node published a revoke —
    /// no Redis DEL here, the publishing node already did that.
    pub async fn invalidate_local(&self, user_id: Uuid) {
        self.hot.invalidate(&moka_key(user_id)).await;
    }
}

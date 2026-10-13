//! Redis `jti` denylist (Plan 1.6a) — the mechanism that makes `logout` and an
//! admin-initiated session revoke actually take effect mid-life, instead of a
//! stolen/compromised token staying valid until it naturally expires.
//!
//! Key shape: `auth:denylist:{jti}`, `{crate}:{purpose}:{id}` per guidelines §5.
//! Self-expiring by design (`EX <ttl>`) — bounded growth, no cleanup job needed.
//!
//! **Pool (BAU-9 / OD-1, D-625).** Every caller passes the **coordination**
//! pool (`AppState.redis_coordination` / `XrmState.base.redis_coordination`),
//! never the general cache pool. The mechanism is fail-closed on a store
//! *error*, but it cannot be fail-closed on *absence*: no entry reads as "not
//! revoked". The cache role is the one an operator may give an eviction policy
//! or issue `FLUSHDB` against (Dragonfly without `cache_mode` has no
//! eviction today, which is why the defect was latent), and an eviction there
//! would silently un-revoke every token minted in the last access-token
//! lifetime. D-625 amends D-161, which had reaffirmed the cache placement
//! without weighing absence. The three sites — logout write
//! (`crates/server/src/auth/session.rs`), admin revoke write
//! (`crates/xrm/xrm-security/src/admin/sessions.rs`) and authn read
//! (`crates/base/attome-server/src/middleware/auth.rs`) — move together.
//! The epoch cache deliberately stays on the cache pool: a miss there re-reads
//! Postgres, so absence is safe.

use std::time::Duration;

use attome_cache::RedisPool;
use attome_types::AppError;
use fred::prelude::*;
use uuid::Uuid;

/// Tight bound so a Redis blip can't hang an authenticated request (guidelines §10).
const CHECK_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

fn key(jti: Uuid) -> String {
    format!("auth:denylist:{jti}")
}

/// Denylists `jti` for `ttl_secs` — pass the token's actual remaining lifetime
/// (`exp - now`) when the caller holds the token (logout), or the max
/// access-token TTL when it doesn't (admin revoke by `jti` alone): any token
/// with that `jti` was issued at most `ttl_secs` ago, so it cannot outlive a
/// denylist entry with that TTL. A non-positive `ttl_secs` means the token is
/// already expired on its own — nothing to denylist.
pub async fn revoke(redis: &RedisPool, jti: Uuid, ttl_secs: i64) -> Result<(), AppError> {
    if ttl_secs <= 0 {
        return Ok(());
    }
    tokio::time::timeout(
        CHECK_TIMEOUT,
        redis.set::<(), _, _>(key(jti), 1, Some(Expiration::EX(ttl_secs)), None, false),
    )
    .await
    .map_err(|_| AppError::internal("redis denylist write timed out"))?
    .map_err(|e| AppError::internal(format!("redis denylist write failed: {e}")))
}

/// Fail-closed revocation check: a Redis error or timeout is treated as
/// "revoked" — a network blip must never let a possibly-revoked token through.
///
/// `redis` MUST be the coordination pool — the one `revoke` writes to and the
/// one no eviction policy is pointed at; see this module's doc. A miss on the
/// cache pool after an eviction would read as "not revoked".
pub async fn is_revoked(redis: &RedisPool, jti: Uuid) -> bool {
    match tokio::time::timeout(CHECK_TIMEOUT, redis.get::<Option<i64>, _>(key(jti))).await {
        Ok(Ok(Some(_))) => true,
        Ok(Ok(None)) => false,
        Ok(Err(e)) => {
            tracing::warn!("auth denylist read failed, failing closed: {e}");
            true
        }
        Err(_) => {
            tracing::warn!("auth denylist read timed out, failing closed");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client built but never connected — sufficient for `revoke`'s
    /// non-positive-ttl path below, which returns before issuing any Redis
    /// command at all.
    fn unconnected_pool() -> RedisPool {
        let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        Builder::from_config(config).build_pool(1).unwrap()
    }

    #[tokio::test]
    async fn revoke_is_a_no_op_when_ttl_is_zero_or_negative_without_touching_redis() {
        let redis = unconnected_pool();
        assert!(revoke(&redis, Uuid::now_v7(), 0).await.is_ok());
        assert!(revoke(&redis, Uuid::now_v7(), -1).await.is_ok());
    }

    #[test]
    fn key_is_namespaced_per_guidelines_crate_purpose_id_shape() {
        let jti = Uuid::now_v7();
        assert_eq!(key(jti), format!("auth:denylist:{jti}"));
    }

    /// `is_revoked`'s actual fail-closed branch had no test at all before
    /// this — only `revoke`'s no-op-below-zero-ttl short-circuit above ever
    /// touched `unconnected_pool`, which never issues a Redis command in the
    /// first place. This deliberately reuses the same never-connected pool
    /// for `is_revoked` instead, whose read path always issues a real `GET`:
    /// with nothing listening on `127.0.0.1:1`, that call either fails fast
    /// (connection refused) or is caught by `is_revoked`'s own 300ms
    /// `CHECK_TIMEOUT` — either way it exercises the real fail-closed branch,
    /// the one D-027/guidelines §5 rely on to keep a Redis outage from ever
    /// letting a possibly-revoked token through, and needs no live Redis to
    /// run (it works precisely because there is none reachable).
    #[tokio::test]
    async fn is_revoked_fails_closed_when_redis_is_unreachable() {
        let redis = unconnected_pool();
        assert!(is_revoked(&redis, Uuid::now_v7()).await);
    }
}

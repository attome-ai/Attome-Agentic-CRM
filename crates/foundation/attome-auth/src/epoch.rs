//! Per-user auth epoch — P-account-state-enforcement Phase 2 (audit finding
//! #2; D-121 rules it, and `document/base/auth/plans/attome-auth-plan.md` §5.1
//! records what shipped). A monotonic integer on `user_account.auth_epoch`
//! (migration 0041) that lets a stateless JWT `session_token` stay
//! revocable without a server-side session table: bump the epoch on
//! disable/password-reset-confirm/other privilege-sensitive events, stamp
//! the epoch a token was issued under into its claims, and reject any token
//! whose stamped epoch has fallen behind the account's current one.
//!
//! Wired (D-121, extends D-113): `SessionClaims.epoch` is stamped by
//! `accounts::issue_access_token` (the sole chokepoint every login/register/
//! MFA-completion/refresh path calls through) and checked by `authn`
//! (`attome-server/src/middleware/auth.rs`) on the cookie-session branch. The
//! synthetic per-request `SessionClaims` the API-key branch builds is not
//! epoch-checked — `resolve_api_key` already re-derives liveness from
//! `api_key.is_active`/`user_account.is_active` fresh on every call,
//! so there is no cached "is this token still good" state for an epoch to
//! correct there.
//!
//! Fail-closed posture mirrors `revocation::is_revoked` exactly: a Redis
//! error or timeout on the cached read is treated as "stale" (reject), never
//! "still valid" — a network blip must never be mistaken for "not revoked".
//! A missing/deleted `user_account` row is likewise fail-closed
//! (`Unauthorized`), never epoch 0 — see `check`'s doc comment for why a
//! silent "treat as valid" default here would have been an actual
//! vulnerability once this module was wired in.

use std::time::Duration;

use attome_cache::Store;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Same bound as `revocation::CHECK_TIMEOUT` — a Redis blip must not hang an
/// authenticated request (guidelines §10).
const CHECK_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;
/// Short cache TTL: this is a cache in front of Postgres, not a second
/// source of truth. The bump on disable (`bump_in_tx` + `invalidate_cache`)
/// is what actually changes the value in the steady state; this TTL only
/// bounds the staleness of a request that raced the cache invalidation
/// (e.g. a concurrent request on another node that read the cache a moment
/// before the DEL landed).
const CACHE_TTL_SECS: i64 = 5;

fn key(user_id: Uuid) -> String {
    format!("auth:epoch:{user_id}")
}

/// Reads `(is_active, auth_epoch)` directly from Postgres in one query — the
/// authoritative snapshot. Used both by `check`'s cache-miss path and by
/// anything minting a fresh `session_token`, which must stamp the *current*
/// epoch at issue time, not a possibly-stale cached one. Read together, not
/// as two separate queries, so a login racing a concurrent disable can never
/// observe "new epoch" and "still active" from two different snapshots
/// (D-121 review item: reading them separately would let such a login mint
/// a token that looks epoch-valid for an account that was disabled a moment
/// before). A missing row is `Err(Unauthorized)` — a deleted/nonexistent
/// account must never be treated as epoch-0-and-active, which is what an
/// `unwrap_or` default would do.
async fn current_state(db: &DbPool, user_id: Uuid) -> Result<(bool, i32), AppError> {
    // `is_active` is NOT NULL since migration 0460 (attome-auth hardening 2.4).
    let row: Option<(bool, i32)> =
        sqlx::query_as("SELECT is_active, auth_epoch FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    row.ok_or(AppError::Unauthorized)
}

/// Reads the current epoch only — used by `accounts::issue_access_token` to
/// stamp a fresh token. Issuance always follows a successful active-account
/// check earlier in the same call (login/register/MFA-completion all query
/// `is_active` themselves before ever reaching token issuance), so
/// `current_state`'s active-check would be redundant here; a missing row is
/// still `Err(Unauthorized)`, never epoch 0, for the same reason as above.
pub async fn current_epoch(db: &DbPool, user_id: Uuid) -> Result<i32, AppError> {
    current_state(db, user_id).await.map(|(_, epoch)| epoch)
}

/// Fail-closed validation of a `SessionClaims`-carried epoch against the
/// account's current state. Rejects when the account is no longer active,
/// or when `claimed_epoch != current` — **exact equality, not `<`**: a
/// token stamped with an epoch newer than the account's current value is
/// exactly as invalid as one that's behind (it can only mean a Postgres
/// restore/rollback replayed an old row, or a bug elsewhere minted a token
/// against a value that was never actually committed) — treating a `>`
/// claim as valid would accept a token no legitimate issuance path could
/// have produced. Redis is a read-through cache of the `(is_active, epoch)`
/// pair with `CACHE_TTL_SECS`; a Redis error or timeout fails closed
/// (`Unauthorized`), same posture as `revocation::is_revoked`.
pub async fn check(
    store: &Store,
    db: &DbPool,
    user_id: Uuid,
    claimed_epoch: i32,
) -> Result<(), AppError> {
    let cached: Option<(bool, i32)> =
        match tokio::time::timeout(CHECK_TIMEOUT, store.get(&key(user_id))).await {
            Ok(Ok(v)) => v.and_then(|s| decode_cached(&s)),
            Ok(Err(e)) => {
                tracing::warn!("auth epoch cache read failed, failing closed: {e}");
                return Err(AppError::Unauthorized);
            }
            Err(_) => {
                tracing::warn!("auth epoch cache read timed out, failing closed");
                return Err(AppError::Unauthorized);
            }
        };

    let (is_active, current) = match cached {
        Some(v) => v,
        None => {
            let v = current_state(db, user_id).await?;
            let _ = tokio::time::timeout(
                CHECK_TIMEOUT,
                store.set(
                    &key(user_id),
                    &encode_cached(v),
                    Some(Duration::from_secs(CACHE_TTL_SECS as u64)),
                ),
            )
            .await;
            v
        }
    };

    if !is_active || claimed_epoch != current {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

fn encode_cached((is_active, epoch): (bool, i32)) -> String {
    format!("{}:{epoch}", is_active as u8)
}

fn decode_cached(s: &str) -> Option<(bool, i32)> {
    let (active, epoch) = s.split_once(':')?;
    Some((active == "1", epoch.parse().ok()?))
}

/// Increments `auth_epoch` for `user_id` inside the caller's transaction.
/// Called by password-reset confirm (`reset::confirm`) and admin disable
/// (`xrm_security::admin::account_state`); any future privilege-sensitive
/// event should call it too. Returns the new value. The caller must
/// also call `invalidate_cache` AFTER the transaction commits (same
/// commit-then-invalidate split as `SecurityResolver::invalidate` elsewhere
/// in this codebase) — never invalidate the cache before the bump is
/// durable, or a concurrent request could re-cache the pre-bump value.
pub async fn bump_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<i32, AppError> {
    sqlx::query_scalar(
        "UPDATE user_account SET auth_epoch = auth_epoch + 1 WHERE id = $1 RETURNING auth_epoch",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Drops the cached epoch value so the next request re-reads Postgres
/// immediately instead of waiting out `CACHE_TTL_SECS` — best-effort
/// (mirrors `SecurityCache::invalidate`'s Redis DEL): a failure here just
/// means the bounded TTL is the fallback, not a correctness break, since
/// `CACHE_TTL_SECS` is already short by design.
pub async fn invalidate_cache(store: &Store, user_id: Uuid) {
    let _ = tokio::time::timeout(CHECK_TIMEOUT, store.del(&key(user_id))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // No test here exercises `check`/`bump_in_tx`/`invalidate_cache` against
    // an unconnected pool — unlike `revocation.rs`'s `revoke`, this module has
    // no early-return path that resolves before touching Redis/Postgres,
    // so (per that file's own convention) there is nothing safe to assert
    // without a live Redis + Postgres. See `tests/` for the DB/Redis-backed
    // integration coverage this module needs once it's wired in.

    #[test]
    fn key_is_namespaced_per_guidelines_crate_purpose_id_shape() {
        let user_id = Uuid::now_v7();
        assert_eq!(key(user_id), format!("auth:epoch:{user_id}"));
    }

    #[test]
    fn cached_value_roundtrips_active_and_epoch() {
        assert_eq!(decode_cached(&encode_cached((true, 0))), Some((true, 0)));
        assert_eq!(decode_cached(&encode_cached((false, 7))), Some((false, 7)));
    }

    #[test]
    fn decode_cached_rejects_malformed_input() {
        assert_eq!(decode_cached("no-colon-here"), None);
        assert_eq!(decode_cached("1:not-a-number"), None);
    }
}

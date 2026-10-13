//! Generic Redis-hash write-coalescing buffer (P-job-system-hardening (b)).
//!
//! Built for high-frequency writes a durable, replay-safe queue row per write
//! would be unnecessary amplification for. Two write shapes share the same
//! hash-plus-periodic-drain mechanism, differing only in which Redis command
//! writes a field:
//! - `set` (`HSET`) — "touch to now" writes where only the *latest* value per
//!   key matters (e.g. `last_used_at` timestamps). Last write before a drain
//!   wins.
//! - `incr` (`HINCRBY`) — "add one more" writes where every concurrent
//!   caller's contribution must be summed, not overwritten (e.g. a
//!   per-route/per-identity request counter, M61 Phase 1's `api_usage`). Every
//!   call durably adds to whatever is already buffered for that field.
//!
//! Either way, a periodic flusher `drain`s the whole hash atomically (plain
//! `HGETALL`+`DEL`, agnostic to which command wrote each field) and folds the
//! result into one bulk write, so at most one write per flush interval per
//! distinct key reaches Postgres, however many requests touched it in
//! between.
//!
//! Not a durable queue: an unflushed value is lost if Redis restarts before
//! the next drain. Callers must only use this for values that are safe to
//! lose for one flush interval — never for data that needs replay-safe
//! delivery (that's still apalis's job, see `attome_jobs`).

use attome_types::AppError;
use fred::interfaces::LuaInterface;
use fred::prelude::*;

use crate::ops::{self, Primitive};
// Tight bound so a Redis blip can never add meaningful latency to the
// request path this buffer is called from (guidelines §10). Callers should
// treat a failure here as best-effort — log and continue, never fail the
// request over a telemetry write. BCA-13 moved the value into
// `crate::timeouts`. `drain` runs on the flusher tick, so it takes the
// background bound instead.
use crate::timeouts::{BACKGROUND, REQUEST_PATH};

/// Atomic "read everything, then clear" drain — a single `EVAL` so no write
/// landing between the `HGETALL` and the `DEL` can be lost: Redis executes
/// the script as one atomic step, so any `HSET` from a concurrent caller
/// either lands entirely before this script runs (and is included in the
/// drained result) or entirely after (and survives to the next drain). There
/// is no window where a value could be read by `HGETALL` and then wiped by a
/// `DEL` without ever having been returned to a caller.
const DRAIN_SCRIPT: &str = r#"
local vals = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
return vals
"#;

/// Sets `field` to `value` in the coalescing hash at `hash_key`. Last write
/// before the next `drain` wins — callers doing "touch to now" writes
/// (last-used timestamps, counters meant to be overwritten, not summed)
/// should call this on every occurrence rather than trying to batch client-side.
pub async fn set(
    redis: &RedisPool,
    hash_key: &str,
    field: &str,
    value: &str,
) -> Result<(), AppError> {
    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.hset::<(), _, _>(hash_key, (field, value)),
    )
    .await;
    ops::record_op(Primitive::Coalesce, &attempt);
    attempt
        .map_err(|_| AppError::internal(format!("write-coalesce hset timed out (key={hash_key})")))?
        .map_err(|e| {
            AppError::internal(format!("write-coalesce hset failed (key={hash_key}): {e}"))
        })
}

/// Script for [`set_with_ttl`] — `HSET` + `PEXPIRE` as one atomic step, so a
/// caller that wants a real TTL on a `set`-style touch gets it without a
/// second round trip and without the window where the value exists unbounded
/// (BCA-43).
///
/// KEYS[1] = the coalescing hash
/// ARGV[1] = field, ARGV[2] = value, ARGV[3] = TTL in milliseconds
const SET_TTL_SCRIPT: &str = r#"
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"#;

/// [`set`] with a TTL (BCA-43). `set` alone writes no expiry, so a keyspace
/// whose flusher never runs again (`attome-server:touch:apikey` is the shipped
/// example, BCA-F6) lives forever. This is the additive form: the existing
/// `set` signature is unchanged for the two callers outside this crate that
/// still use it.
pub async fn set_with_ttl(
    redis: &RedisPool,
    hash_key: &str,
    field: &str,
    value: &str,
    ttl_secs: i64,
) -> Result<(), AppError> {
    // At least 1 ms: `PEXPIRE 0` deletes the key immediately, which would
    // silently drop the touch this call exists to record.
    let ttl_ms = ttl_secs.saturating_mul(1000).max(1);
    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.eval(
            SET_TTL_SCRIPT,
            vec![hash_key.to_owned()],
            vec![field.to_owned(), value.to_owned(), ttl_ms.to_string()],
        ),
    )
    .await;
    ops::record_op(Primitive::Coalesce, &attempt);
    let _: i64 = attempt
        .map_err(|_| {
            AppError::internal(format!(
                "write-coalesce set-with-ttl timed out (key={hash_key})"
            ))
        })?
        .map_err(|e| {
            AppError::internal(format!(
                "write-coalesce set-with-ttl failed (key={hash_key}): {e}"
            ))
        })?;
    Ok(())
}

/// Script for [`incr`] — `HINCRBY` + `PEXPIRE` as one atomic step (BCA-33).
/// The old shape was two round trips on every authenticated request: an
/// `HINCRBY` whose reply the caller waited for, then a `PEXPIRE` whose failure
/// was only logged. One script means one round trip, and the TTL now lands in
/// the same atomic step as the increment rather than after it.
///
/// KEYS[1] = the coalescing hash
/// ARGV[1] = field, ARGV[2] = increment, ARGV[3] = TTL in milliseconds
const INCR_SCRIPT: &str = r#"
redis.call('HINCRBY', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"#;

/// Atomically increments `field` in the coalescing hash at `hash_key` by
/// `by` (`HINCRBY`) — the counterpart to `set` above, for callers doing
/// "add one more" writes (usage counts meant to be summed across every
/// concurrent caller since the last drain) rather than "last write wins"
/// touches. `drain` above is shape-agnostic (a plain `HGETALL`+`DEL`), so it
/// reads a hash written by `incr` exactly the same way it reads one written
/// by `set` — the two writers just disagree on which Redis command to use.
///
/// Refreshes `hash_key`'s TTL to `ttl_secs` on every call, in the same atomic
/// step as the increment (see [`INCR_SCRIPT`]) so an unflushed buffer still
/// self-expires — bounded data loss, not unbounded growth — if the periodic
/// flusher is ever skipped for a stretch (guidelines §5: every Redis key needs
/// either a TTL or a stated append-forever reason; this buffer's callers are
/// guidelines §5's "coherence concern, degrade-and-recover" class, not the
/// fail-closed security class, so losing a buffer no flusher ever drained is
/// an accepted tradeoff, not a correctness bug).
pub async fn incr(
    redis: &RedisPool,
    hash_key: &str,
    field: &str,
    by: i64,
    ttl_secs: i64,
) -> Result<(), AppError> {
    // At least 1 ms: `PEXPIRE 0` would delete the field this call just
    // incremented, silently losing the count it exists to record.
    let ttl_ms = ttl_secs.saturating_mul(1000).max(1);
    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.eval(
            INCR_SCRIPT,
            vec![hash_key.to_owned()],
            vec![field.to_owned(), by.to_string(), ttl_ms.to_string()],
        ),
    )
    .await;
    ops::record_op(Primitive::Coalesce, &attempt);
    let _: i64 = attempt
        .map_err(|_| AppError::internal(format!("write-coalesce incr timed out (key={hash_key})")))?
        .map_err(|e| {
            AppError::internal(format!("write-coalesce incr failed (key={hash_key}): {e}"))
        })?;
    Ok(())
}

/// Atomically drains every field currently in the hash at `hash_key`,
/// returning `(field, value)` pairs, and clears the hash. An empty hash
/// (nothing to flush) returns an empty `Vec`, not an error.
pub async fn drain(redis: &RedisPool, hash_key: &str) -> Result<Vec<(String, String)>, AppError> {
    let attempt = tokio::time::timeout(
        BACKGROUND,
        redis.eval(
            DRAIN_SCRIPT,
            vec![hash_key.to_owned()],
            Vec::<String>::new(),
        ),
    )
    .await;
    ops::record_op(Primitive::Coalesce, &attempt);

    let flat: Vec<String> = attempt
        .map_err(|_| {
            AppError::internal(format!("write-coalesce drain timed out (key={hash_key})"))
        })?
        .map_err(|e| {
            AppError::internal(format!("write-coalesce drain failed (key={hash_key}): {e}"))
        })?;

    Ok(flat
        .chunks_exact(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-logic coverage here; the live round trips are covered by
    // tests/write_coalesce.rs, which scripts/test-attome-cache-backends.ps1 runs
    // against every pinned image. (The old note here claimed no Redis was
    // reachable in this environment, which stopped being true the day the
    // local matrix replaced the retired CI lane — BCA-44/BCA-F8.)

    /// BCA-33: `incr` must be one round trip. A second EXPIRE call in Rust is
    /// exactly the two-round-trip shape this replaced, so its absence is the
    /// property; the script owning both writes is the other half.
    ///
    /// The needle is assembled at runtime on purpose: spelling it out here
    /// would make this test's own source match it.
    #[test]
    fn incr_is_one_round_trip() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/write_coalesce.rs"),
        )
        .expect("read this module");
        let separate_expire = format!("redis.{}{}", "expire", "::<");
        assert!(
            !source.contains(&separate_expire),
            "incr must not issue a separate EXPIRE round trip (BCA-33)"
        );
        assert!(INCR_SCRIPT.contains("HINCRBY"), "{INCR_SCRIPT}");
        assert!(INCR_SCRIPT.contains("PEXPIRE"), "{INCR_SCRIPT}");
    }

    /// BCA-43: the TTL form must land the field and the expiry in one step, or
    /// a `set`-style touch can exist unbounded (BCA-F6).
    #[test]
    fn set_with_ttl_writes_the_field_and_the_expiry_together() {
        assert!(SET_TTL_SCRIPT.contains("HSET"), "{SET_TTL_SCRIPT}");
        assert!(SET_TTL_SCRIPT.contains("PEXPIRE"), "{SET_TTL_SCRIPT}");
    }

    #[test]
    fn chunking_pairs_flat_hgetall_reply_into_field_value_tuples() {
        let flat = [
            "field-a".to_string(),
            "value-a".to_string(),
            "field-b".to_string(),
            "value-b".to_string(),
        ];
        let paired: Vec<(String, String)> = flat
            .chunks_exact(2)
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect();
        assert_eq!(
            paired,
            vec![
                ("field-a".to_string(), "value-a".to_string()),
                ("field-b".to_string(), "value-b".to_string()),
            ]
        );
    }
}

//! Read-your-own-write pin (P1.12, extended by P-read-your-writes-lsn) — the
//! mechanism that keeps a user from seeing their own just-made write as stale
//! when reads are routed to a lagging read replica (`AppState::read_pool`).
//!
//! Key shape: `attome-db:rw-pin:{user_id}`, `{crate}:{purpose}:{id}` per
//! guidelines §5. Self-expiring by design (`EX <ttl>`) — bounded growth, no
//! cleanup job needed. Deliberately Redis, not an in-process flag: an
//! in-memory pin would diverge between nodes and violate the platform's
//! CRITICAL Multi-Server statelessness rule (a write on node A must be
//! visible to a read on node B).
//!
//! P-read-your-writes-lsn changed the pin's *value*, not its key shape: it
//! now carries the write's commit-adjacent WAL LSN (`format!("lsn:{lsn}")`,
//! written by `pin_write_with_lsn`) instead of the bare sentinel `1`, so
//! `AppState::read_pool` can compare it against the replica's actual replay
//! position (`attome_server::replica_watermark`) instead of trusting a fixed
//! TTL. The original P1.12 sentinel writer/reader pair (`pin_write`/`has_pin`)
//! outlived its one-release window and is gone (BCA-47); `check_pin` still
//! reads a bare `1` as `Legacy` so a pin left by an old node keeps routing to
//! the primary until its TTL lapses.

use attome_types::AppError;
use fred::prelude::*;
use uuid::Uuid;

use crate::ops::{self, Primitive};
/// Tight bound so a Redis blip can't hang a request (guidelines §10). BCA-13
/// moved the value into `crate::timeouts`, and the pin's *writes* are bounded
/// now too — they were not before (BCA-F3), so a wedged connection could hold
/// a post-commit best-effort write open indefinitely.
use crate::timeouts::REQUEST_PATH;

/// The pin's Redis key. Public so a caller's test can seed a value no
/// current writer produces (the legacy bare `1`) without restating the shape.
pub fn pin_key(user_id: Uuid) -> String {
    format!("attome-db:rw-pin:{user_id}")
}

/// Result of `check_pin` — lets `AppState::read_pool` (P-read-your-writes-lsn)
/// distinguish "no pin", "pinned but replica may already have caught up", and
/// the two fail-closed-to-primary cases (`RedisError`, `Legacy`), instead of
/// the old bare `bool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// Redis was unreachable or the check timed out — fail closed toward the
    /// primary, same posture `has_pin` always had.
    RedisError,
    /// A pin exists but its value isn't `lsn:<pg_lsn>` — either a pre-P-read-
    /// your-writes-lsn bare `1` sentinel written by a node still running the
    /// old code (rolling upgrade), or defensively any other unexpected
    /// value. Routes to the primary for the rest of the pin's TTL: today's
    /// exact pre-LSN behavior, never a regression to "no pin at all".
    Legacy,
    /// A pin exists and carries the write's captured LSN, `lsn:` prefix
    /// already stripped (raw `pg_lsn` text, e.g. `"16/B374D848"`).
    Pinned(String),
    /// No pin for this user — caller may route to the replica, subject to
    /// the lag circuit breaker (`AppState::route_if_lag_ok`).
    None,
}

/// Pins `user_id` to the primary, storing the write's captured LSN
/// (`format!("lsn:{lsn}")`) rather than the legacy bare sentinel. `ttl_secs`
/// is the caller's chosen ceiling — `AppState::read_pool`'s call site passes
/// `max(sticky_primary_ttl_secs, replica_max_lag_secs)` so the TTL never
/// expires before the deployment's own declared lag tolerance. Call this
/// right after every successful mutation's transaction commits, with the
/// primary's `pg_current_wal_insert_lsn()` captured at that same point
/// (`xrm_server`'s `pin_write_with_current_lsn` helper does both steps in
/// one call). Best-effort: callers log a warning and continue on error
/// rather than fail an otherwise-successful write over a caching concern.
pub async fn pin_write_with_lsn(
    redis: &RedisPool,
    user_id: Uuid,
    lsn: &str,
    ttl_secs: u64,
) -> Result<(), AppError> {
    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.set::<(), _, _>(
            pin_key(user_id),
            format!("lsn:{lsn}"),
            Some(Expiration::EX(ttl_secs as i64)),
            None,
            false,
        ),
    )
    .await;
    ops::record_op(Primitive::RwPin, &attempt);
    attempt
        .map_err(|_| AppError::internal("redis rw-pin write timed out"))?
        .map_err(|e| AppError::internal(format!("redis rw-pin write failed: {e}")))
}

/// Fail-closed check (toward the primary, never toward possibly-stale data):
/// a Redis error or timeout is `PinCheck::RedisError`, treated as pinned by
/// every caller — same posture `has_pin` always had, now expressed as an enum
/// so a caller can also branch on the LSN once it *is* pinned.
pub async fn check_pin(redis: &RedisPool, user_id: Uuid) -> PinCheck {
    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.get::<Option<String>, _>(pin_key(user_id)),
    )
    .await;
    ops::record_op(Primitive::RwPin, &attempt);
    match attempt {
        Ok(Ok(None)) => PinCheck::None,
        Ok(Ok(Some(value))) => match value.strip_prefix("lsn:") {
            Some(lsn) => PinCheck::Pinned(lsn.to_string()),
            None => PinCheck::Legacy,
        },
        Ok(Err(e)) => {
            tracing::warn!("rw-pin read failed, failing closed to primary: {e}");
            PinCheck::RedisError
        }
        Err(_) => {
            tracing::warn!("rw-pin read timed out, failing closed to primary");
            PinCheck::RedisError
        }
    }
}

/// Parses Postgres's `pg_lsn` text representation (`"XXXX/YYYYYYYY"`, hex,
/// case-insensitive, no fixed width per segment) into one comparable `u64` —
/// see <https://www.postgresql.org/docs/current/datatype-pg-lsn.html>.
/// Returns `None` for anything that doesn't match that shape: malformed
/// input is never trusted for a comparison that gates routing.
pub fn parse_lsn(s: &str) -> Option<u64> {
    let (hi, lo) = s.split_once('/')?;
    let hi = u32::from_str_radix(hi, 16).ok()?;
    let lo = u32::from_str_radix(lo, 16).ok()?;
    Some(((hi as u64) << 32) | lo as u64)
}

/// True iff replica watermark `replica_lsn` has replayed at least as far as
/// pinned write LSN `write_lsn`. Malformed input on either side fails closed
/// (`false` — never treat an unparseable value as "caught up").
pub fn lsn_ge(replica_lsn: &str, write_lsn: &str) -> bool {
    match (parse_lsn(replica_lsn), parse_lsn(write_lsn)) {
        (Some(replica), Some(write)) => replica >= write,
        _ => false,
    }
}

#[cfg(test)]
mod lsn_tests {
    use super::*;

    #[test]
    fn pin_key_has_the_documented_shape() {
        let user_id = Uuid::nil();
        assert_eq!(
            pin_key(user_id),
            "attome-db:rw-pin:00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn parse_lsn_basic() {
        assert_eq!(parse_lsn("0/0"), Some(0));
        assert_eq!(
            parse_lsn("16/B374D848"),
            Some((0x16u64 << 32) | 0xB374D848u64)
        );
    }

    #[test]
    fn parse_lsn_rejects_malformed() {
        assert_eq!(parse_lsn(""), None);
        assert_eq!(parse_lsn("not-an-lsn"), None);
        assert_eq!(parse_lsn("16"), None);
        assert_eq!(parse_lsn("ZZ/00"), None);
        assert_eq!(parse_lsn("16/"), None);
        assert_eq!(parse_lsn("/00"), None);
    }

    #[test]
    fn parse_lsn_is_case_insensitive() {
        assert_eq!(parse_lsn("16/b374d848"), parse_lsn("16/B374D848"));
    }

    #[test]
    fn lsn_ge_equal_is_caught_up() {
        assert!(lsn_ge("16/B374D848", "16/B374D848"));
    }

    #[test]
    fn lsn_ge_ahead_is_caught_up() {
        assert!(lsn_ge("16/B374D900", "16/B374D848"));
    }

    #[test]
    fn lsn_ge_behind_is_not_caught_up() {
        assert!(!lsn_ge("16/B374D700", "16/B374D848"));
    }

    #[test]
    fn lsn_ge_wraps_across_the_slash_boundary_correctly() {
        // Replica has replayed into the next high-word segment — must
        // compare as one combined 64-bit value, not lexically or per-segment
        // (a naive string/segment compare would say "17/00000000" < "16/FFFFFFFF").
        assert!(lsn_ge("17/00000000", "16/FFFFFFFF"));
    }

    #[test]
    fn lsn_ge_malformed_fails_closed() {
        assert!(!lsn_ge("garbage", "16/B374D848"));
        assert!(!lsn_ge("16/B374D848", "garbage"));
        assert!(!lsn_ge("", ""));
    }

    #[test]
    fn pin_check_variants_are_distinguishable() {
        assert_eq!(
            PinCheck::Pinned("16/B374D848".into()),
            PinCheck::Pinned("16/B374D848".into())
        );
        assert_ne!(PinCheck::Pinned("16/B374D848".into()), PinCheck::Legacy);
        assert_ne!(PinCheck::Legacy, PinCheck::None);
        assert_ne!(PinCheck::RedisError, PinCheck::None);
    }
}

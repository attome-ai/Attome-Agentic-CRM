//! Failed-login audit events without flooding the backlog (audit plan item
//! 3.5, D-541 rule 6).
//!
//! A failed password login writes `Security` + `FailedLogin`, **after** the
//! per-account throttle (a 429 is not an event). Failures are coalesced per
//! key and 5-minute fixed window:
//!
//! - known account: `acct:{user_id}:{ip_key}`; the user id stands in for the
//!   identifier key because the account is known, and it lets the sweep name
//!   the account without storing the typed identifier anywhere;
//! - unknown identifier: `ip:{ip_key}` — nothing from the typed string is kept
//!   (G3-1 a).
//!
//! `ip_key` is the first 16 hex characters of SHA-256(client IP), so Redis
//! and the event name never hold a raw address. The IP and user-agent
//! columns of the event stay NULL: request context (plan 4.1) and its
//! actor-DEK encryption (plan 4.4, D-540) belong to Phase 4.
//!
//! **Redis** (coordination pool, every call bounded by [`OP_TIMEOUT`]):
//!
//! - `attome-audit:failed-login:{key}:{window}` — the attempt counter, TTL two
//!   windows;
//! - `attome-audit:failed-login:pending:{window}` — the set of keys that failed in
//!   that window, TTL two windows.
//!
//! One Lua call increments the counter and, on the first failure, registers
//! the key in the pending set, so a counter can never exist without the sweep
//! being able to find it. The first failure in a window is written at once
//! (`occurrence_count = 1`), so detection is never delayed. A Redis error or
//! timeout writes the failure individually: the fail-safe direction is to audit
//! everything.
//!
//! **Sweep** (`EngineJob::FailedLoginSweep`, once a minute): for each closed
//! window still inside the counters' TTL it writes one summary event with
//! `occurrence_count = N - 1` for every key with N > 1, then deletes the
//! counter. The summary's `event_name` carries the window bounds and the key,
//! and is written under a transaction-scoped advisory lock after an existence
//! check against `audit_ingest` and `audit_header`, so a retried or
//! concurrent sweep never writes a second summary for the same key and window.

use std::time::Duration;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityAuditor, SecurityEvent};
use attome_cache::RedisPool;
use attome_types::AppError;
use chrono::{DateTime, TimeZone, Utc};
use fred::interfaces::{KeysInterface, LuaInterface, SetsInterface};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// D-541 rule 6: a 5-minute fixed window.
pub const WINDOW_SECS: i64 = 300;
/// Counter and pending-set TTL: two windows.
pub const KEY_TTL_SECS: i64 = 2 * WINDOW_SECS;
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;
const KEY_PREFIX: &str = "attome-audit:failed-login";
/// Advisory-lock key prefix for the summary guard, under `attome_audit`'s
/// namespace (the event is an `attome-audit` row).
const SUMMARY_LOCK_PREFIX: &str = "attome-audit/failed-login-summary";

/// Who the failure was against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// The identifier named an account.
    Known {
        user_id: Uuid,
        organization_ref: Option<Uuid>,
    },
    /// The identifier matched no account; nothing about it is recorded.
    Unknown,
}

/// The start (unix seconds) of the fixed window holding `now`.
pub fn window_start(now: i64) -> i64 {
    now - now.rem_euclid(WINDOW_SECS)
}

/// First 16 hex characters of SHA-256(`ip`).
pub fn ip_key(ip: &str) -> String {
    let digest = Sha256::digest(ip.as_bytes());
    hex::encode(digest)[..16].to_owned()
}

/// The coalescing key for `subject` failing from `ip`.
pub fn coalesce_key(subject: Subject, ip: &str) -> String {
    match subject {
        Subject::Known { user_id, .. } => format!("acct:{user_id}:{}", ip_key(ip)),
        Subject::Unknown => format!("ip:{}", ip_key(ip)),
    }
}

pub fn counter_key(key: &str, window: i64) -> String {
    format!("{KEY_PREFIX}:{key}:{window}")
}

pub fn pending_key(window: i64) -> String {
    format!("{KEY_PREFIX}:pending:{window}")
}

/// Parses a coalescing key back into what the summary event needs:
/// `(Some(user_id), ip_key)` or `(None, ip_key)`.
pub fn parse_key(key: &str) -> Option<(Option<Uuid>, String)> {
    if let Some(rest) = key.strip_prefix("acct:") {
        let (user, ip) = rest.split_once(':')?;
        return Some((Some(user.parse().ok()?), ip.to_owned()));
    }
    key.strip_prefix("ip:").map(|ip| (None, ip.to_owned()))
}

fn rfc3339(secs: i64) -> String {
    Utc.timestamp_opt(secs, 0)
        .single()
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339()
}

/// The `event_name` of a failed-login event. `summary` distinguishes the
/// window-close summary from the immediate first-failure event.
pub fn event_name(known: bool, ip_key: &str, window: i64, summary: bool) -> String {
    format!(
        "failed_login{} {} ip_key={ip_key} window={}/{}",
        if summary { " summary" } else { "" },
        if known {
            "account"
        } else {
            "unknown_identifier"
        },
        rfc3339(window),
        rfc3339(window + WINDOW_SECS),
    )
}

fn event(
    user_id: Option<Uuid>,
    organization_ref: Option<Uuid>,
    name: String,
    n: i32,
) -> SecurityEvent {
    // The caller is unauthenticated: the actor is nil (D-541 rule 6), and a
    // known account is the event's record.
    let mut e = SecurityEvent::new(
        MandatoryCategory::Security,
        AuditOperation::FailedLogin,
        Uuid::nil(),
        "user_account",
        user_id,
    )
    .named(name)
    .occurrence_count(n);
    if let Some(org) = organization_ref {
        e = e.organization(org);
    }
    e
}

/// INCR the counter; on the first failure also register the key in the
/// window's pending set. Both TTLs are two windows. Returns the new count.
const RECORD_SCRIPT: &str = r#"
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  redis.call('SADD', KEYS[2], ARGV[2])
  redis.call('EXPIRE', KEYS[2], ARGV[1])
end
return n
"#;

async fn increment(redis: &RedisPool, key: &str, window: i64) -> Result<i64, String> {
    tokio::time::timeout(
        OP_TIMEOUT,
        redis.eval::<i64, _, _, _>(
            RECORD_SCRIPT,
            vec![counter_key(key, window), pending_key(window)],
            vec![KEY_TTL_SECS.to_string(), key.to_owned()],
        ),
    )
    .await
    .map_err(|_| "timed out".to_owned())?
    .map_err(|e| e.to_string())
}

/// Records one failed login at `now` (unix seconds). Writes an event for the
/// first failure of the window, or for every failure while Redis is
/// unavailable; later failures in the window only count. An audit write
/// failure is returned, so the caller fails the request rather than silently
/// dropping evidence.
pub async fn record_failure(
    auditor: &SecurityAuditor,
    redis: &RedisPool,
    subject: Subject,
    ip: &str,
    now: i64,
) -> Result<(), AppError> {
    let window = window_start(now);
    let key = coalesce_key(subject, ip);
    let first = match increment(redis, &key, window).await {
        Ok(n) => n == 1,
        Err(error) => {
            tracing::warn!(
                %error,
                "failed-login coalescing unavailable; writing this failure individually"
            );
            true
        }
    };
    if !first {
        return Ok(());
    }
    let (user_id, organization_ref) = match subject {
        Subject::Known {
            user_id,
            organization_ref,
        } => (Some(user_id), organization_ref),
        Subject::Unknown => (None, None),
    };
    auditor
        .write(event(
            user_id,
            organization_ref,
            event_name(user_id.is_some(), &ip_key(ip), window, false),
            1,
        ))
        .await
        .map(|_| ())
}

/// What one sweep pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepSummary {
    pub keys_seen: usize,
    pub summaries_written: usize,
}

/// Sweeps every closed window whose counters can still exist at `now`.
pub async fn sweep(
    auditor: &SecurityAuditor,
    db: &attome_db::DbPool,
    redis: &RedisPool,
    now: i64,
) -> Result<SweepSummary, AppError> {
    let current = window_start(now);
    let mut total = SweepSummary::default();
    let mut window = current - KEY_TTL_SECS;
    while window < current {
        let s = sweep_window(auditor, db, redis, window).await?;
        total.keys_seen += s.keys_seen;
        total.summaries_written += s.summaries_written;
        window += WINDOW_SECS;
    }
    Ok(total)
}

fn redis_err(what: &'static str) -> impl FnOnce(String) -> AppError {
    move |e| AppError::internal(format!("failed-login sweep: redis {what}: {e}"))
}

async fn bounded<T, F>(f: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, fred::error::RedisError>>,
{
    tokio::time::timeout(OP_TIMEOUT, f)
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.to_string())
}

/// Sweeps one closed window. Public so a test can close a window by passing
/// its start directly.
pub async fn sweep_window(
    auditor: &SecurityAuditor,
    db: &attome_db::DbPool,
    redis: &RedisPool,
    window: i64,
) -> Result<SweepSummary, AppError> {
    let pending = pending_key(window);
    // The set holds one member per (account or unknown, IP) that failed in
    // this window, and expires two windows after its last addition.
    let keys: Vec<String> = bounded(redis.smembers(&pending))
        .await
        .map_err(redis_err("smembers"))?;
    let mut summary = SweepSummary {
        keys_seen: keys.len(),
        summaries_written: 0,
    };
    for key in keys.into_iter() {
        let counter = counter_key(&key, window);
        let n: Option<i64> = bounded(redis.get(&counter))
            .await
            .map_err(redis_err("get"))?;
        if let (Some(n), Some((user_id, ip))) = (n, parse_key(&key))
            && n > 1
            && write_summary_once(auditor, db, user_id, &ip, window, n - 1).await?
        {
            summary.summaries_written += 1;
        }
        // Only after the summary committed (or was already there): a crash
        // before this line leaves the counter for the next pass, whose
        // existence check then skips the write.
        bounded(redis.del::<i64, _>(&counter))
            .await
            .map_err(redis_err("del"))?;
        bounded(redis.srem::<i64, _, _>(&pending, key))
            .await
            .map_err(redis_err("srem"))?;
    }
    Ok(summary)
}

/// Writes the summary unless one already exists for this record, key and
/// window. Returns whether it wrote.
async fn write_summary_once(
    auditor: &SecurityAuditor,
    db: &attome_db::DbPool,
    user_id: Option<Uuid>,
    ip: &str,
    window: i64,
    count: i64,
) -> Result<bool, AppError> {
    let name = event_name(user_id.is_some(), ip, window, true);
    let organization_ref: Option<Uuid> = match user_id {
        Some(id) => sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT organization_ref FROM user_account WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .flatten(),
        None => None,
    };
    let count = i32::try_from(count).unwrap_or(i32::MAX);
    let mut stx = auditor
        .begin(event(user_id, organization_ref, name.clone(), count))
        .await?;

    let lock_key = format!(
        "{SUMMARY_LOCK_PREFIX}:{name}:{}",
        user_id.unwrap_or_default()
    );
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_audit::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *stx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        // A concurrent sweep holds it and will write (or has written) the
        // summary; leave the counter for it.
        return Err(AppError::Conflict(
            "failed-login summary is being written by a concurrent sweep",
        ));
    }

    // Header rows are range-partitioned on the event time, so the lower bound
    // keeps this to the partitions that can hold the summary.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM audit_header
             WHERE changed_on >= to_timestamp($1) AND operation = $2 AND event_name = $3
               AND record_id IS NOT DISTINCT FROM $4)
         OR EXISTS (
             SELECT 1 FROM audit_ingest
             WHERE payload->>'event_name' = $3
               AND (payload->>'record_id') IS NOT DISTINCT FROM $5)",
    )
    .bind(window as f64)
    .bind(AuditOperation::FailedLogin as i32)
    .bind(&name)
    .bind(user_id)
    .bind(user_id.map(|u| u.to_string()))
    .fetch_one(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    stx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_fixed_five_minute_buckets() {
        assert_eq!(window_start(0), 0);
        assert_eq!(window_start(299), 0);
        assert_eq!(window_start(300), 300);
        assert_eq!(
            window_start(1_000_000_123),
            1_000_000_123 - 1_000_000_123 % 300
        );
        assert_eq!(window_start(-1), -300);
    }

    #[test]
    fn keys_never_hold_the_ip_or_identifier() {
        let user = Uuid::now_v7();
        let known = coalesce_key(
            Subject::Known {
                user_id: user,
                organization_ref: None,
            },
            "203.0.113.7",
        );
        let unknown = coalesce_key(Subject::Unknown, "203.0.113.7");
        assert!(!known.contains("203.0.113.7") && !unknown.contains("203.0.113.7"));
        assert_eq!(ip_key("203.0.113.7").len(), 16);
        assert_eq!(parse_key(&known), Some((Some(user), ip_key("203.0.113.7"))));
        assert_eq!(parse_key(&unknown), Some((None, ip_key("203.0.113.7"))));
        assert_eq!(parse_key("garbage"), None);
        assert_eq!(parse_key("acct:not-a-uuid:abc"), None);
        assert_eq!(
            counter_key(&unknown, 600),
            format!("attome-audit:failed-login:{unknown}:600")
        );
        assert_eq!(pending_key(600), "attome-audit:failed-login:pending:600");
    }

    #[test]
    fn event_names_carry_the_window_bounds() {
        let name = event_name(false, "abcd", 300, true);
        assert_eq!(
            name,
            "failed_login summary unknown_identifier ip_key=abcd \
             window=1970-01-01T00:05:00+00:00/1970-01-01T00:10:00+00:00"
        );
        assert!(event_name(true, "abcd", 0, false).starts_with("failed_login account "));
    }
}

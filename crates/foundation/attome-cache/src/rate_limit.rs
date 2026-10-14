use attome_types::AppError;
use chrono::Utc;
use fred::interfaces::LuaInterface;
use std::borrow::Cow;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::memory::Keyspace;
use crate::ops::{self, Primitive};
use crate::store::Store;
// P1.15 §4(d): a security control (rate limiting) must fail closed and fast,
// never hang on a slow/unreachable Redis (guidelines §10). BCA-13 moved the
// bound itself into `crate::timeouts`, where every module shares one value.
use crate::timeouts::REQUEST_PATH;

const WINDOW_MS: i64 = 60_000;

/// The key `check` actually stores `key` under: `key` itself, except during a
/// test run that set [`TEST_NAMESPACE_ENV`]. A test that reads the counter back
/// from Redis (`TTL`, `ZCARD`) must go through this.
pub fn storage_key(key: &str) -> String {
    namespaced(key).into_owned()
}

/// Names the test binary whose rate-limit counters these are (set by
/// `scripts/run-test-binaries.mjs`, one value per child process).
const TEST_NAMESPACE_ENV: &str = "ATTOME_TEST_RATE_LIMIT_NAMESPACE";

/// Test-run isolation: test binaries run side by side against one Redis, and
/// every one of them is `127.0.0.1`, so the IP-keyed counters (`pre_auth`,
/// the anonymous category bucket) were shared. Eight binaries at once tripped
/// each other's limits (2026-09-24: 25 of 80 failing binaries were 429s that
/// passed alone). With the variable set, every key gets a per-binary prefix,
/// and the limits themselves stay exactly as configured, so the tests that
/// assert a 429 keep working unchanged.
///
/// Honoured only under `APP_ENV=debug`, the profile the test script and dev
/// stack already use for their relaxed behaviour; a production process never
/// reads it. It only *splits* counters, so even when set it can not admit a
/// request that a single counter would refuse for that process's own traffic.
fn namespaced(key: &str) -> Cow<'_, str> {
    static NAMESPACE: OnceLock<Option<String>> = OnceLock::new();
    let ns = NAMESPACE.get_or_init(|| {
        if !attome_config::is_debug_env() {
            return None;
        }
        std::env::var(TEST_NAMESPACE_ENV)
            .ok()
            .filter(|v| !v.is_empty())
    });
    match ns {
        Some(ns) => Cow::Owned(format!("{ns}:{key}")),
        None => Cow::Borrowed(key),
    }
}

/// Result of one `check()` call — enough for the caller to build both an
/// accepted response's informational headers and a rejected response's
/// `Retry-After`/`X-RateLimit-*` headers from the same atomic read the
/// admit/reject decision was made from (P-rate-limit-atomicity §4.1/§4.3 —
/// never a second, separately-timed lookup that could disagree with the
/// decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitOutcome {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    /// Seconds until the oldest counted request ages out of the window —
    /// always >= 1. Meaningful on every outcome, not just rejections: a
    /// well-behaved client can use it to self-throttle before ever hitting 429.
    pub retry_after_secs: u64,
    /// Unix seconds at which the window resets (`now + retry_after_secs`).
    pub reset_unix: i64,
}

/// Enterprise-audit remediation (Phase 2.3) + P-rate-limit-atomicity (D-145):
/// evict + count(+record) as one atomic script, same pattern
/// `xrm-s2s/src/rate_limit.rs::check_with_nonce` already established — a
/// four-round-trip read-modify-write was not atomic as a unit, and its
/// `ZADD` used `now_ms` as both score and member, so two requests landing in
/// the same millisecond collided into a single zset entry and undercounted.
///
/// **Only an admitted request is recorded** (`ZADD`/`PEXPIRE` run only when
/// `count < limit`, before incrementing) — a request that gets rejected does
/// not extend the window. This is deliberate, not an oversight: if every
/// request (admitted or not) re-added an entry and re-extended the TTL, a
/// sustained flood past the limit would keep the window open indefinitely,
/// turning a transient burst into an unbounded lockout for whatever
/// legitimate traffic shares that bucket. Recording only admitted requests
/// means the window self-recovers exactly `WINDOW_MS` after the caller's
/// last *admitted* request — standard sliding-window-log semantics, matching
/// "N requests per rolling minute" as configured.
///
/// KEYS[1] = the caller-namespaced rate-limit zset key
/// ARGV[1] = now_ms (score for this request, if admitted)
/// ARGV[2] = window_start_ms (evict anything scored below this)
/// ARGV[3] = limit
/// ARGV[4] = member (unique per call: "{now_ms}:{uuid}") — a `Uuid::now_v7()`
///           per D-018, not raw `now_ms` or Lua-side randomness (per-node
///           seeding discipline would be needed to avoid cross-fleet
///           collisions there; generating it in Rust costs nothing new).
///
/// Returns `{admitted, count, oldest_score}` — `admitted` is 1 if this call
/// was recorded, 0 if it was rejected (count was already at `limit`); since a
/// rejected request is never added, `count` alone can no longer distinguish
/// "admitted, now at the limit" from "rejected, already at the limit" (both
/// leave `count == limit`), hence the explicit flag. `oldest_score` is the
/// oldest counted entry's score, used to compute `retry_after_secs`/`reset_unix`.
const RATE_LIMIT_SCRIPT: &str = r#"
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[2])
local count = redis.call('ZCARD', KEYS[1])
local limit = tonumber(ARGV[3])
local admitted = 0
if count < limit then
    redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
    count = count + 1
    admitted = 1
    redis.call('PEXPIRE', KEYS[1], 61000)
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return {admitted, count, oldest[2] or ARGV[1]}
"#;

/// Generic sliding-window rate limiter (60-second window, limit in requests-per-minute).
///
/// `key` must already be fully namespaced by the caller (e.g.
/// `"base:rl:user:{uuid}:credential"` or `"s2s:rl:{client_id}"`) — this
/// function adds no prefix of its own, so unrelated callers never collide on
/// the same counter. The one exception is [`namespaced`]'s test-run prefix.
///
/// Uses a Redis sorted set scored by request timestamp, evicted/counted/
/// recorded atomically via `RATE_LIMIT_SCRIPT` in a single round-trip. Shared
/// by every app node against the same Redis instance, so the count is
/// correct across a multi-node deployment (never per-process). A Redis
/// error or timeout here is always returned as `Err` (P1.15 §4c) — never a
/// silent pass-through — so a Redis outage fails this control closed, not
/// open; the caller decides what response that produces.
///
/// **Diagnostic context on timeout (D-208/D-251).** A prior live drill
/// (D-208, 2026-07-30) hit this exact timeout against a real Dragonfly
/// instance under Docker Desktop/WSL2, while `redis-cli EVAL` of the
/// identical script and the general connection pool were both fine — the
/// anomaly did not reproduce in a later targeted investigation (D-196) or a
/// later full drill run (D-251), so it is most likely environment-specific,
/// not a code defect. It was never root-caused, though, so `key`/`limit_rpm`
/// and the wall-clock time actually spent are recorded on timeout — cheap,
/// always-safe fields (no secrets: `key` is this repo's own namespaced
/// counter identifier, e.g. `"base:rl:user:{uuid}:credential"`, never a
/// credential itself) — so a future recurrence has an immediate log
/// correlation point instead of requiring a blind re-reproduction attempt.
pub async fn check(store: &Store, key: &str, limit_rpm: i32) -> Result<RateLimitOutcome, AppError> {
    let key = &*namespaced(key);
    let now_ms = Utc::now().timestamp_millis();
    let window_start_ms = now_ms - WINDOW_MS;
    let member = format!("{now_ms}:{}", Uuid::now_v7());
    let attempt_started = std::time::Instant::now();

    let redis = match store {
        Store::Redis(pool) => pool,
        Store::Memory(memory) => {
            let (admitted, count, oldest) = memory.transaction(|ks| {
                window_step(ks, key, now_ms, window_start_ms, limit_rpm, &member)
            })?;
            return Ok(outcome(admitted, count, oldest, limit_rpm, now_ms));
        }
    };

    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.eval(
            RATE_LIMIT_SCRIPT,
            vec![key.to_owned()],
            vec![
                now_ms.to_string(),
                window_start_ms.to_string(),
                limit_rpm.to_string(),
                member,
            ],
        ),
    )
    .await;
    ops::record_op(Primitive::RateLimit, &attempt);

    let (admitted, count, oldest_score_raw): (i64, i64, String) = attempt
        .map_err(|_| {
            tracing::warn!(
                key,
                limit_rpm,
                elapsed_ms = attempt_started.elapsed().as_millis() as u64,
                timeout_ms = REQUEST_PATH.as_millis() as u64,
                "redis rate-limit eval timed out — see D-208/D-251 in document/decisions/ \
                 if this recurs on a Linux Docker host (rules out the Docker \
                 Desktop/WSL2 variable D-208/D-196 could not confirm or rule out)"
            );
            AppError::internal("redis rate-limit eval timed out")
        })?
        .map_err(|e| AppError::internal(format!("redis rate-limit eval failed: {e}")))?;

    let oldest_score: i64 = oldest_score_raw.parse::<f64>().map_err(|e| {
        AppError::internal(format!(
            "redis rate-limit eval returned a non-numeric score: {e}"
        ))
    })? as i64;

    Ok(outcome(
        admitted == 1,
        count,
        oldest_score,
        limit_rpm,
        now_ms,
    ))
}

/// The in-process form of [`RATE_LIMIT_SCRIPT`]: evict, count, record when
/// under the limit, all while the store is locked. Returns
/// `(admitted, count, oldest_score_ms)`.
fn window_step(
    ks: &mut Keyspace,
    key: &str,
    now_ms: i64,
    window_start_ms: i64,
    limit_rpm: i32,
    member: &str,
) -> Result<(bool, i64, i64), AppError> {
    let wrong_type = |_| AppError::internal("rate-limit key holds a non-window value");
    let zset = ks.zset(key).map_err(wrong_type)?;
    zset.remove_range_by_score(0.0, window_start_ms as f64);
    let mut count = zset.len() as i64;
    let admitted = count < i64::from(limit_rpm);
    if admitted {
        zset.add(now_ms as f64, member);
        count += 1;
    }
    let oldest = zset.first().map_or(now_ms, |(score, _)| score as i64);
    if admitted {
        ks.expire(key, std::time::Duration::from_millis(61_000));
    }
    Ok((admitted, count, oldest))
}

/// Builds the caller-facing outcome from one atomic read, identically for
/// both backends.
fn outcome(
    admitted: bool,
    count: i64,
    oldest_score: i64,
    limit_rpm: i32,
    now_ms: i64,
) -> RateLimitOutcome {
    let remaining = (i64::from(limit_rpm) - count).max(0) as u32;
    let reset_ms = (oldest_score + WINDOW_MS - now_ms).max(0);
    let retry_after_secs = ((reset_ms as f64) / 1000.0).ceil().max(1.0) as u64;
    let reset_unix = (now_ms + reset_ms) / 1000;
    RateLimitOutcome {
        allowed: admitted,
        limit: limit_rpm.max(0) as u32,
        remaining,
        retry_after_secs,
        reset_unix,
    }
}

/// The per-account throttle key for `subject` (a user id, or a hash of a
/// normalized email) and `purpose` (`"login"`, `"mfa"`): exactly
/// `server:rl:account:{subject}:{purpose}`. Every per-account budget builds
/// its key here, so the login-time MFA routes and the self-service MFA routes
/// share one bucket byte-for-byte, and buckets already live in Redis carry
/// over unchanged (attome-auth hardening 1.5).
pub fn account_key(subject: &str, purpose: &str) -> String {
    format!("server:rl:account:{subject}:{purpose}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_window_admits_up_to_the_limit_then_refuses() {
        let store = Store::memory();
        for n in 1..=3 {
            let out = check(&store, "t:rl:a", 3).await.unwrap();
            assert!(out.allowed, "request {n} is under the limit");
            assert_eq!(out.remaining, 3 - n);
        }
        let refused = check(&store, "t:rl:a", 3).await.unwrap();
        assert!(!refused.allowed);
        assert_eq!(refused.remaining, 0);
        assert!(refused.retry_after_secs >= 1);
        // Another key has its own window.
        assert!(check(&store, "t:rl:b", 3).await.unwrap().allowed);
    }

    #[test]
    fn account_key_keeps_the_existing_bucket_shape() {
        assert_eq!(
            account_key("0190c3a4-0000-7000-8000-000000000001", "mfa"),
            "server:rl:account:0190c3a4-0000-7000-8000-000000000001:mfa"
        );
        assert_eq!(
            account_key("abc123", "login"),
            "server:rl:account:abc123:login"
        );
    }
}

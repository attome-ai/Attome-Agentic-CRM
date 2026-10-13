use attome_cache::RedisPool;
use attome_types::AppError;
use chrono::Utc;
use fred::interfaces::LuaInterface;
use std::time::Duration;
use uuid::Uuid;

/// P1.15 §4(c)/(d): the S2S nonce+rate-limit guard is a security control —
/// fail closed, no exception. A Redis timeout here must reject the request,
/// not silently let a replay/over-quota call through (guidelines §10).
const GUARD_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// Clock-skew tolerance of the S2S protocol: a request's `x-s2s-timestamp`
/// must fall within ± this many seconds of server time or `s2s_authn`
/// rejects it before any Redis or crypto work. A protocol constant, never
/// varied per-deployment — not a config knob.
pub const TIMESTAMP_WINDOW_SECS: u64 = 300;

/// Redis TTL of a used nonce (`s2s:nonce:{client_id}:{nonce}`) — derived
/// from [`TIMESTAMP_WINDOW_SECS`], never a second literal (B10).
///
/// Why twice the window and not equal to it: the nonce is stored at the
/// moment the server *receives* the request, while the window is measured
/// against the *client-supplied* timestamp, which may legitimately lead
/// server time by up to a full window. A request stamped `now + window`
/// therefore stays timestamp-valid until `receive + 2·window`; with a TTL of
/// only one window the nonce expired at `receive + window`, and a byte-for-
/// byte replay in the remaining stretch was accepted as fresh. The TTL must
/// outlive every instant at which the timestamp is still acceptable.
pub const NONCE_TTL_SECS: u64 = 2 * TIMESTAMP_WINDOW_SECS;

// Keeps a future edit from decoupling the two: a nonce that can expire while
// its timestamp is still inside the window reopens B10.
const _: () = assert!(
    NONCE_TTL_SECS >= 2 * TIMESTAMP_WINDOW_SECS,
    "the S2S nonce TTL must cover the whole timestamp-acceptance window in both directions"
);

/// Nonce replay-guard (`SET NX`) and sliding-window rate limiter (evict +
/// record + count + refresh TTL) as one atomic script instead of five
/// sequential round-trips (P1.11d). fred's `Pipeline` type doesn't expose the
/// Lua/EVAL interface (only plain commands and Redis Functions), so a single
/// script is actually the only way to get both checks down to one round-trip
/// — as a side effect it's also fully atomic across both keys, stronger than
/// pipelining would have been.
///
/// KEYS[1] = nonce key (`s2s:nonce:{client_id}:{nonce}`)
/// KEYS[2] = rate-limit zset key (`s2s:rl:{client_id}`)
/// ARGV[1] = nonce ttl_secs (always [`NONCE_TTL_SECS`])
/// ARGV[2] = now_ms (score for this request)
/// ARGV[3] = window_start_ms (evict anything scored below this)
/// ARGV[4] = member (unique per call: "{now_ms}:{uuid}")
///
/// Returns `{nonce_fresh, count}` — `nonce_fresh` is 1 if the nonce was newly
/// stored, 0 if it was a replay; `count` is the rate-limit window's size
/// after recording this request.
///
/// The member is `{now_ms}:{uuid}`, not bare `now_ms` — see the same fix in
/// `attome-cache::rate_limit::check` (Enterprise-audit remediation Phase 2.3),
/// which named this script as the pattern's origin. Using `now_ms` as both
/// score and member let same-millisecond requests collide into one zset
/// entry, undercounting bursts; the unique member makes collisions
/// structurally impossible.
const GUARD_SCRIPT: &str = r#"
local nonce_fresh = redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX')
redis.call('ZREMRANGEBYSCORE', KEYS[2], 0, ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[4])
local count = redis.call('ZCARD', KEYS[2])
redis.call('EXPIRE', KEYS[2], 61)
if nonce_fresh == false then
    return {0, count}
else
    return {1, count}
end
"#;

/// Nonce uniqueness (replay protection) + sliding-window rate limit
/// (60-second window, limit in requests-per-minute), combined into one
/// atomic Redis round-trip (P1.11d) — both gate the same request.
///
/// Returns `Err(AppError::Conflict(_))` on nonce replay, `Err(AppError::TooManyRequests { retry_after_secs: None })`
/// over quota — callers distinguish these to shape different HTTP responses.
///
/// The nonce is retained for [`NONCE_TTL_SECS`]; callers cannot choose a
/// shorter TTL, because one shorter than the timestamp window reopens the
/// replay gap that constant's doc comment describes.
pub async fn check_with_nonce(
    redis: &RedisPool,
    client_id: &str,
    nonce: &str,
    limit_rpm: i32,
) -> Result<(), AppError> {
    let now_ms = Utc::now().timestamp_millis();
    let window_start_ms = now_ms - 60_000;
    let rl_key = format!("s2s:rl:{client_id}");
    let nonce_key = format!("s2s:nonce:{client_id}:{nonce}");
    let member = format!("{now_ms}:{}", Uuid::new_v4());

    let (nonce_fresh, count): (i64, i64) = tokio::time::timeout(
        GUARD_TIMEOUT,
        redis.eval(
            GUARD_SCRIPT,
            vec![nonce_key, rl_key],
            vec![
                NONCE_TTL_SECS.to_string(),
                now_ms.to_string(),
                window_start_ms.to_string(),
                member,
            ],
        ),
    )
    .await
    .map_err(|_| AppError::internal("redis s2s guard eval timed out"))?
    .map_err(|e| AppError::internal(format!("redis s2s guard eval failed: {e}")))?;

    if nonce_fresh == 0 {
        // P-observability-completion — SecurityAnomalyRateHigh alert source.
        // No-op if no recorder was ever installed (observability.metrics_port
        // == 0), same convention as every other `metrics::` call site in this
        // platform.
        metrics::counter!("security_rejection_total", "reason" => "s2s_replay").increment(1);
        return Err(AppError::Conflict("replay: nonce already used"));
    }

    if count > limit_rpm as i64 {
        metrics::counter!("security_rejection_total", "reason" => "s2s_rate_limit").increment(1);
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NONCE_TTL_SECS, TIMESTAMP_WINDOW_SECS};

    /// B10: a request stamped up to `TIMESTAMP_WINDOW_SECS` in the future is
    /// still inside the window `2·window` seconds after it was received, so
    /// the nonce must be retained at least that long or the replay is
    /// accepted as fresh. The `const _` assertion above enforces this at
    /// compile time; this test names it in the suite so a regression reads
    /// as a failing test rather than a build error nobody looks for.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn nonce_ttl_covers_the_timestamp_window_in_both_directions() {
        assert!(
            NONCE_TTL_SECS >= 2 * TIMESTAMP_WINDOW_SECS,
            "NONCE_TTL_SECS={NONCE_TTL_SECS} must be at least \
             2 x TIMESTAMP_WINDOW_SECS={TIMESTAMP_WINDOW_SECS}"
        );
    }
}

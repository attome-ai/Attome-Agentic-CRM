use attome_cache::RedisPool;
use attome_types::AppError;
use chrono::Utc;
use fred::interfaces::LuaInterface;
use std::time::Duration;
use uuid::Uuid;

/// P1.15 §4(d): the concurrency guard is an availability control — fail
/// closed and fast, never hang on a slow/unreachable Redis (guidelines §10).
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// Safety net for a slot whose request crashed/panicked before calling
/// [`ConcurrencyGuard::release`]: anything older than this is treated as
/// abandoned and evicted on the next `acquire`, so a leaked slot self-heals
/// instead of permanently consuming a client's concurrency budget. Well
/// above any legitimate S2S request's lifetime.
const MAX_SLOT_AGE_MS: i64 = 5 * 60 * 1000;

/// Evict + count + (conditionally) record as one atomic script, same
/// evict-before-count shape as `rate_limit::check_with_nonce`'s
/// `GUARD_SCRIPT` — the eviction here is a crash-recovery safety net rather
/// than a sliding time window, but atomicity matters for the same reason:
/// two requests racing this script must never both read a stale count and
/// both get admitted past `max_concurrent`.
///
/// KEYS[1] = the client's concurrency zset key (`s2s:concurrent:{client_id}`)
/// ARGV[1] = now_ms (score for this request's slot)
/// ARGV[2] = stale_before_ms (evict abandoned slots older than this)
/// ARGV[3] = max_concurrent
/// ARGV[4] = member (unique per call: "{now_ms}:{uuid}")
///
/// Returns 1 if the slot was admitted, 0 if the client is already at its
/// concurrency limit.
const ACQUIRE_SCRIPT: &str = r#"
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[2])
local count = redis.call('ZCARD', KEYS[1])
if count >= tonumber(ARGV[3]) then
    return 0
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('EXPIRE', KEYS[1], 300)
return 1
"#;

const RELEASE_SCRIPT: &str = r#"
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
"#;

/// Holds a client's concurrency slot for the lifetime of one S2S request.
/// Call [`Self::release`] once the request finishes so the slot frees up
/// immediately; if it's dropped without that call (e.g. a panic), the slot
/// still self-heals via `MAX_SLOT_AGE_MS` on the client's next `acquire`.
pub struct ConcurrencyGuard {
    redis: RedisPool,
    key: String,
    member: String,
}

impl std::fmt::Debug for ConcurrencyGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyGuard").finish_non_exhaustive()
    }
}

impl ConcurrencyGuard {
    pub async fn release(self) {
        let outcome: Result<Result<i64, _>, _> = tokio::time::timeout(
            OP_TIMEOUT,
            self.redis
                .eval(RELEASE_SCRIPT, vec![self.key.clone()], vec![self.member]),
        )
        .await;

        match outcome {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    "s2s: failed to release concurrency slot for key '{}': {e}",
                    self.key
                );
            }
            Err(_) => {
                tracing::warn!(
                    "s2s: timed out releasing concurrency slot for key '{}'",
                    self.key
                );
            }
        }
    }
}

/// Admits or rejects a request against `s2s_client.max_concurrent` —
/// the cap on how many of this client's requests may be in flight at once,
/// enforced across every app node via the shared `redis_coordination` pool
/// (never per-process, per guidelines §5).
///
/// Returns `Err(AppError::TooManyRequests { retry_after_secs: None })` once the client is at its limit.
pub async fn acquire(
    redis: &RedisPool,
    client_id: &str,
    max_concurrent: i32,
) -> Result<ConcurrencyGuard, AppError> {
    let now_ms = Utc::now().timestamp_millis();
    let stale_before_ms = now_ms - MAX_SLOT_AGE_MS;
    let key = format!("s2s:concurrent:{client_id}");
    let member = format!("{now_ms}:{}", Uuid::new_v4());

    let admitted: i64 = tokio::time::timeout(
        OP_TIMEOUT,
        redis.eval(
            ACQUIRE_SCRIPT,
            vec![key.clone()],
            vec![
                now_ms.to_string(),
                stale_before_ms.to_string(),
                max_concurrent.to_string(),
                member.clone(),
            ],
        ),
    )
    .await
    .map_err(|_| AppError::internal("redis s2s concurrency eval timed out"))?
    .map_err(|e| AppError::internal(format!("redis s2s concurrency eval failed: {e}")))?;

    if admitted == 0 {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }

    Ok(ConcurrencyGuard {
        redis: redis.clone(),
        key,
        member,
    })
}

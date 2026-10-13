//! Rolling-window **token** accumulator — the shared-state half of
//! `attome_inference::budget`.
//!
//! ## Why this exists
//!
//! `attome_inference::budget` has shipped since D-360 as pure policy:
//! [`check`](../../attome_inference/budget/fn.check.html) decides
//! allow-or-reject given `consumed`, an estimate, and how far into the window
//! we are. Nothing ever supplied `consumed`, so the budget had **zero call
//! sites anywhere in the workspace** — verified 2026-09-10 by grepping every
//! crate for `budget::`. The mechanism was complete and inert.
//!
//! It could not supply its own: `attome-inference` is transport-only by
//! construction (I-11, D-360) and carries no Redis dependency, while a token
//! budget must be shared across app nodes or it is not a budget at all
//! (guidelines §5 — never process memory as the source of truth for
//! cross-node behaviour). So the counter lives here, beside every other Redis
//! primitive, and the policy stays where it was.
//!
//! ## Shape: bucketed hash, not a sorted set
//!
//! [`rate_limit`](crate::rate_limit) counts *events*, so one zset member per
//! request is natural. This counts *tokens*, and a zset stores scores rather
//! than summable values — one member per call would mean parsing the payload
//! back out of member strings, and an hour of chat is a lot of members.
//!
//! Instead: a Redis hash whose fields are time buckets and whose values are
//! token counts, `HINCRBY`-ed. Bucket width is derived from the window so the
//! field count stays near [`TARGET_BUCKETS`] regardless of whether the window
//! is an hour (`PER_SESSION_DEFAULT`) or a day (`PER_CALLER_DEFAULT`) — ~60
//! fields either way, one `HGETALL` to read, and the resolution loss is at
//! most one bucket's width at the trailing edge.
//!
//! ## Source of truth, key shape, TTL, failure, cold start
//!
//! Required by `caching-and-state` for every new cache:
//!
//! - **Source of truth:** this *is* the source of truth for in-window spend.
//!   It is deliberately not reconstructable — token spend that Redis loses is
//!   spend nobody is billed for, which is the safe direction for a cost
//!   control and the wrong direction for an audit trail. The audit trail is
//!   `xrm_ai_suggestion_outcome`'s per-suggestion token columns, in Postgres,
//!   written independently.
//! - **Key shape:** caller-namespaced `{crate}:{purpose}:{id}`; this module
//!   adds no prefix, exactly like [`rate_limit::check`](crate::rate_limit::check).
//! - **TTL:** `window + one bucket`, refreshed on every write, so an idle key
//!   disappears rather than accumulating forever.
//! - **Failure behaviour:** **fails closed.** A Redis error or timeout is
//!   returned as `Err`, never silently admitted. See [`read`].
//! - **Cold start:** an absent key reads as zero consumed and zero elapsed,
//!   which `budget::check` treats as a full allowance. A fresh node, a
//!   flushed Redis, and a genuinely new caller are indistinguishable and all
//!   correct.

use std::time::Duration;

use attome_types::AppError;
use chrono::Utc;
use fred::interfaces::LuaInterface;

use crate::ops::{self, Primitive};
use crate::redis_pool::RedisPool;
// Same posture and same number as every other Redis guard in this crate: a
// cost control must fail fast rather than hang a request on a slow Redis
// (guidelines §10). BCA-13 moved the value to `crate::timeouts`.
use crate::timeouts::REQUEST_PATH;

/// Roughly how many buckets a window is divided into. Sets the resolution/
/// size trade-off: more buckets means a tighter trailing edge and a larger
/// `HGETALL`.
const TARGET_BUCKETS: u64 = 60;

/// Narrowest bucket, so a short window cannot degenerate into per-second
/// fields.
const MIN_BUCKET_SECS: u64 = 60;

/// Bucket width for a given window — `window / TARGET_BUCKETS`, floored at
/// [`MIN_BUCKET_SECS`].
///
/// An hour window gives 60s buckets (60 fields); a day window gives 1440s
/// buckets (60 fields). The trailing-edge error is at most one bucket: tokens
/// spent early in the oldest live bucket stay counted until that whole bucket
/// ages out. That over-counts slightly, which is the safe direction for a
/// budget — it never lets a caller spend more than configured.
pub fn bucket_secs(window: Duration) -> u64 {
    (window.as_secs() / TARGET_BUCKETS).max(MIN_BUCKET_SECS)
}

/// What the window currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowState {
    /// Tokens spent inside the window.
    pub consumed: u64,
    /// Age of the oldest still-counted bucket — what
    /// `attome_inference::budget::check` wants for `window_elapsed`, and what
    /// makes its `retry_after` land on the moment that bucket ages out rather
    /// than on an arbitrary later time.
    ///
    /// `Duration::ZERO` when nothing is counted.
    pub elapsed: Duration,
}

/// Evicts out-of-window buckets, then sums and reports the rest.
///
/// KEYS[1] = the caller-namespaced hash key
/// ARGV[1] = cutoff bucket index — anything strictly below it is stale
///
/// Returns `{sum, oldest_bucket}` with `oldest_bucket = -1` when nothing is
/// counted. Eviction happens here rather than relying on the key TTL because
/// the TTL covers the *whole* key: without per-field eviction a long-lived
/// caller's hash would keep buckets from many windows ago and over-report.
///
/// Deletes stale fields one at a time rather than `HDEL key unpack(stale)`.
/// `unpack` is Lua 5.1 spelling and this script also runs against Dragonfly;
/// a per-field call costs nothing measurable at ~60 fields and removes a
/// portability question nobody wants to debug at 3am.
const READ_SCRIPT: &str = r#"
local cutoff = tonumber(ARGV[1])
local fields = redis.call('HGETALL', KEYS[1])
local sum = 0
local oldest = -1
local stale = {}
for i = 1, #fields, 2 do
    local bucket = tonumber(fields[i])
    local value = tonumber(fields[i + 1]) or 0
    if bucket == nil or bucket < cutoff then
        table.insert(stale, fields[i])
    else
        sum = sum + value
        if oldest < 0 or bucket < oldest then
            oldest = bucket
        end
    end
end
for _, field in ipairs(stale) do
    redis.call('HDEL', KEYS[1], field)
end
return {sum, oldest}
"#;

/// Adds tokens to the current bucket and refreshes the key's TTL.
///
/// KEYS[1] = the caller-namespaced hash key
/// ARGV[1] = current bucket index
/// ARGV[2] = tokens to add
/// ARGV[3] = key TTL in milliseconds
const ADD_SCRIPT: &str = r#"
redis.call('HINCRBY', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"#;

fn current_bucket(window: Duration) -> i64 {
    Utc::now().timestamp() / bucket_secs(window).max(1) as i64
}

/// Reads the window's current state.
///
/// **Fails closed.** A Redis error or timeout is an `Err`, never a
/// `WindowState { consumed: 0, .. }` — reporting an empty window on an outage
/// would hand every caller a full allowance at exactly the moment nothing can
/// be metered, which is the runaway `attome_inference::budget`'s module doc
/// exists to prevent. The caller decides what response that produces; in
/// practice a deployment whose Redis is unreachable is already failing
/// sessions and rate limits, so this costs little that was still working.
pub async fn read(redis: &RedisPool, key: &str, window: Duration) -> Result<WindowState, AppError> {
    let width = bucket_secs(window).max(1) as i64;
    let now_bucket = current_bucket(window);
    // `window / width` buckets back, inclusive of the current one.
    let cutoff = now_bucket - (window.as_secs() as i64 / width);

    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.eval(READ_SCRIPT, vec![key.to_owned()], vec![cutoff.to_string()]),
    )
    .await;
    ops::record_op(Primitive::TokenWindow, &attempt);

    let (sum, oldest): (i64, i64) = attempt
        .map_err(|_| {
            tracing::warn!(
                key,
                timeout_ms = REQUEST_PATH.as_millis() as u64,
                "redis token-window read timed out — the budget fails closed"
            );
            AppError::internal("redis token-window read timed out")
        })?
        .map_err(|e| AppError::internal(format!("redis token-window read failed: {e}")))?;

    let elapsed = if oldest < 0 {
        Duration::ZERO
    } else {
        // Age of the oldest counted bucket's *start*, so `retry_after` lands
        // on the instant it ages out.
        Duration::from_secs(((now_bucket - oldest) * width).max(0) as u64)
    };

    Ok(WindowState {
        consumed: sum.max(0) as u64,
        elapsed,
    })
}

/// Charges `tokens` against the window.
///
/// Called twice per generation: once with the pre-flight estimate (so a
/// caller cannot start an unbounded generation while sitting just under
/// budget — `budget::check`'s own doc comment requires the estimate be
/// charged up front), and once afterwards with the signed difference between
/// estimate and actual. See `xrm_ai::budget_guard`.
pub async fn add(
    redis: &RedisPool,
    key: &str,
    tokens: u64,
    window: Duration,
) -> Result<(), AppError> {
    if tokens == 0 {
        return Ok(());
    }
    charge(redis, key, tokens as i64, window).await
}

/// Charges a signed amount — the reconciliation path, where an over-estimate
/// must be given back.
///
/// Redis `HINCRBY` accepts a negative increment, and a field is allowed to go
/// negative; the read path clamps the *sum* at zero rather than each field,
/// so an over-refund can only ever under-count within a window, never wrap.
pub async fn charge(
    redis: &RedisPool,
    key: &str,
    delta: i64,
    window: Duration,
) -> Result<(), AppError> {
    if delta == 0 {
        return Ok(());
    }
    let ttl_ms = (window.as_millis() as u64).saturating_add(bucket_secs(window) * 1_000);

    let attempt = tokio::time::timeout(
        REQUEST_PATH,
        redis.eval(
            ADD_SCRIPT,
            vec![key.to_owned()],
            vec![
                current_bucket(window).to_string(),
                delta.to_string(),
                ttl_ms.to_string(),
            ],
        ),
    )
    .await;
    ops::record_op(Primitive::TokenWindow, &attempt);

    let _: i64 = attempt
        .map_err(|_| {
            tracing::warn!(
                key,
                timeout_ms = REQUEST_PATH.as_millis() as u64,
                "redis token-window charge timed out"
            );
            AppError::internal("redis token-window charge timed out")
        })?
        .map_err(|e| AppError::internal(format!("redis token-window charge failed: {e}")))?;

    Ok(())
}

/// One window [`reserve_all`] checks and charges: the caller-namespaced hash
/// key, the window it spans, and the caller's allowance inside it.
#[derive(Debug, Clone, Copy)]
pub struct ReserveWindow<'a> {
    pub key: &'a str,
    pub window: Duration,
    pub limit: u64,
}

/// A successful all-or-nothing reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reserved {
    /// Tokens charged against every window by this call.
    pub tokens: u64,
}

/// A refusal: which window ran out (`index` into the slice passed to
/// [`reserve_all`]) and what it held at the moment of the decision, so the
/// caller can build the same `retry_after` [`check`](attome_inference::budget)
/// would have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub index: usize,
    pub state: WindowState,
}

/// The outcome of [`reserve_all`]. A Redis failure is the `Err` case instead —
/// the caller must treat it as a refusal, never as an admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    Reserved(Reserved),
    Refused(Refused),
}

/// The atomic check-and-reserve script (BCA-31, ai-10-10 A0.1).
///
/// Every window is evicted, summed, and checked **before** any window is
/// written to, and the writes happen only if every window passes. That is the
/// property the read-then-add sequence in `xrm_ai::budget_guard` cannot have:
/// N concurrent generations each reading `consumed` below the limit and then
/// each charging an estimate overshoot by up to N x estimate (BCA-F2).
///
/// The rules are `attome_inference::budget::check`'s, ported row for row
/// (BIN-5.2's `CONFORMANCE` table is the shared spec): an estimate larger than
/// the whole allowance is refused however empty the window, and otherwise the
/// window admits only while `consumed + tokens <= limit`. There is deliberately
/// no "the window rolled, allow it" branch — the store's per-bucket eviction
/// is what frees allowance (BIN-F7/BIN-D8).
///
/// KEYS[i] = window i's caller-namespaced hash key
/// ARGV[1] = tokens to reserve
/// then four arguments per window, in key order:
///   base = 2 + (i-1)*4
///   ARGV[base]   = limit
///   ARGV[base+1] = current bucket index
///   ARGV[base+2] = cutoff bucket index (anything strictly below is stale)
///   ARGV[base+3] = key TTL in milliseconds
///
/// Returns `{allowed, refused_index_1based, sum_at_index, oldest_bucket}`.
/// `refused_index` is 0 when allowed; `oldest_bucket` is -1 when the window
/// held nothing. Per-field `HDEL` rather than `HDEL key unpack(stale)` —
/// `unpack` is Lua 5.1 spelling and this script runs against Dragonfly too
/// (the same portability rule `READ_SCRIPT` follows).
const RESERVE_ALL_SCRIPT: &str = r#"
local tokens = tonumber(ARGV[1])
local n = #KEYS
local sums = {}
local oldests = {}
for i = 1, n do
    local base = 2 + (i - 1) * 4
    local cutoff = tonumber(ARGV[base + 2])
    local fields = redis.call('HGETALL', KEYS[i])
    local sum = 0
    local oldest = -1
    local stale = {}
    for j = 1, #fields, 2 do
        local bucket = tonumber(fields[j])
        local value = tonumber(fields[j + 1]) or 0
        if bucket == nil or bucket < cutoff then
            table.insert(stale, fields[j])
        else
            sum = sum + value
            if oldest < 0 or bucket < oldest then
                oldest = bucket
            end
        end
    end
    for _, field in ipairs(stale) do
        redis.call('HDEL', KEYS[i], field)
    end
    sums[i] = sum
    oldests[i] = oldest
end
for i = 1, n do
    local base = 2 + (i - 1) * 4
    local limit = tonumber(ARGV[base])
    if tokens > limit or sums[i] + tokens > limit then
        return {0, i, sums[i], oldests[i]}
    end
end
for i = 1, n do
    local base = 2 + (i - 1) * 4
    redis.call('HINCRBY', KEYS[i], ARGV[base + 1], ARGV[1])
    redis.call('PEXPIRE', KEYS[i], ARGV[base + 3])
end
return {1, 0, 0, 0}
"#;

/// Checks every window and, only if all of them have room, charges `tokens` to
/// all of them — **atomically** (BCA-31). This is the shared-state primitive
/// `xrm_ai::budget_guard` needs to stop read-then-charging across windows:
/// whichever way concurrent callers interleave, the number that pass is exactly
/// the number the allowance admits.
///
/// The policy stays in `attome_inference::budget` (D-360); this function ports
/// its `check` rules into one Redis script and returns the same two answers.
/// Switching `budget_guard::admit` onto it is ai-10-10 A0.1's, not this
/// crate's.
///
/// **Fails closed.** A Redis error or timeout is `Err`, never an admission —
/// the same posture as [`read`] and [`charge`].
///
/// An empty `windows` slice reserves nothing and succeeds vacuously; a
/// zero-token reservation likewise succeeds without a round trip.
pub async fn reserve_all(
    redis: &RedisPool,
    windows: &[ReserveWindow<'_>],
    tokens: u64,
) -> Result<Reservation, AppError> {
    if tokens == 0 || windows.is_empty() {
        return Ok(Reservation::Reserved(Reserved { tokens }));
    }

    let mut keys: Vec<String> = Vec::with_capacity(windows.len());
    let mut args: Vec<String> = Vec::with_capacity(1 + windows.len() * 4);
    // A refusal reports elapsed time against the exact bucket index the script
    // was told about; re-reading the clock afterwards is off by one bucket
    // whenever the call straddles a bucket boundary.
    let mut now_buckets: Vec<i64> = Vec::with_capacity(windows.len());
    args.push(tokens.to_string());
    for w in windows {
        let width = bucket_secs(w.window).max(1) as i64;
        let now_bucket = current_bucket(w.window);
        let cutoff = now_bucket - (w.window.as_secs() as i64 / width);
        let ttl_ms = (w.window.as_millis() as u64).saturating_add(width as u64 * 1_000);
        keys.push(w.key.to_owned());
        args.push(w.limit.to_string());
        args.push(now_bucket.to_string());
        args.push(cutoff.to_string());
        args.push(ttl_ms.to_string());
        now_buckets.push(now_bucket);
    }

    let attempt =
        tokio::time::timeout(REQUEST_PATH, redis.eval(RESERVE_ALL_SCRIPT, keys, args)).await;
    ops::record_op(Primitive::TokenWindow, &attempt);

    let (allowed, refused_index, sum, oldest): (i64, i64, i64, i64) = attempt
        .map_err(|_| {
            tracing::warn!(
                timeout_ms = REQUEST_PATH.as_millis() as u64,
                "redis token-window reserve_all timed out — the budget fails closed"
            );
            AppError::internal("redis token-window reserve_all timed out")
        })?
        .map_err(|e| AppError::internal(format!("redis token-window reserve_all failed: {e}")))?;

    if allowed == 1 {
        return Ok(Reservation::Reserved(Reserved { tokens }));
    }

    // The script reports a 1-based index; the slice the caller handed in is
    // 0-based. An out-of-range index would be a script bug, not a caller
    // decision — fail closed rather than panic on the caller's slice.
    let index = usize::try_from(refused_index - 1)
        .ok()
        .filter(|i| *i < windows.len())
        .ok_or_else(|| AppError::internal("token-window reserve_all: bad refused index"))?;
    let width = bucket_secs(windows[index].window).max(1) as i64;
    let elapsed = if oldest < 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(((now_buckets[index] - oldest) * width).max(0) as u64)
    };

    Ok(Reservation::Refused(Refused {
        index,
        state: WindowState {
            consumed: sum.max(0) as u64,
            elapsed,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reserve script must not use `unpack`/`table.unpack` either — same
    /// Dragonfly portability rule as `READ_SCRIPT`/`ADD_SCRIPT`.
    #[test]
    fn the_reserve_script_avoids_lua_version_dependent_builtins() {
        assert!(
            !RESERVE_ALL_SCRIPT.contains("unpack"),
            "{RESERVE_ALL_SCRIPT}"
        );
    }

    /// The all-or-nothing property is structural: every `HINCRBY` must appear
    /// after the refusal loop, and the refusal loop must return before any
    /// write. A future "optimisation" that writes while checking reintroduces
    /// the overshoot (BCA-F2) the script exists to remove.
    #[test]
    fn the_reserve_script_checks_every_window_before_writing_any() {
        let refusal = RESERVE_ALL_SCRIPT
            .find("if tokens > limit or sums[i] + tokens > limit")
            .expect("the refusal check is present");
        let first_write = RESERVE_ALL_SCRIPT
            .find("HINCRBY")
            .expect("the charge is present");
        assert!(
            refusal < first_write,
            "the refusal check must precede every write"
        );
        assert_eq!(
            RESERVE_ALL_SCRIPT.matches("HINCRBY").count(),
            1,
            "one HINCRBY site, inside the write loop"
        );
    }

    /// A reservation of nothing is a no-op, not a round trip — and it must
    /// still report the tokens so the caller can settle against it.
    #[tokio::test]
    async fn a_zero_token_reservation_succeeds_without_a_store() {
        let config = fred::prelude::RedisConfig::from_url("redis://127.0.0.1:1").expect("config");
        let pool = crate::redis_pool::RedisPool::new(config, None, None, None, 1).expect("pool");
        let outcome = reserve_all(
            &pool,
            &[ReserveWindow {
                key: "test:tw:noop",
                window: Duration::from_secs(3600),
                limit: 10,
            }],
            0,
        )
        .await
        .expect("a zero reservation must not fail closed");
        assert_eq!(outcome, Reservation::Reserved(Reserved { tokens: 0 }));
    }

    /// Both shipped budgets land near the target field count. This is the
    /// property that lets one `HGETALL` serve an hour window and a day window
    /// alike.
    #[test]
    fn bucket_width_keeps_the_field_count_near_the_target_for_both_budgets() {
        for window in [
            Duration::from_secs(60 * 60),      // PER_SESSION_DEFAULT
            Duration::from_secs(24 * 60 * 60), // PER_CALLER_DEFAULT
        ] {
            let buckets = window.as_secs() / bucket_secs(window);
            assert!(
                (30..=TARGET_BUCKETS).contains(&buckets),
                "window {:?} produced {buckets} buckets",
                window
            );
        }
    }

    /// A short window must not degenerate into per-second fields — that would
    /// make the hash unbounded in the only dimension this design bounds.
    #[test]
    fn a_tiny_window_still_gets_a_sane_bucket_width() {
        assert_eq!(bucket_secs(Duration::from_secs(1)), MIN_BUCKET_SECS);
        assert_eq!(bucket_secs(Duration::ZERO), MIN_BUCKET_SECS);
    }

    /// Bucket width grows with the window rather than staying fixed, which is
    /// what keeps the day-long budget from carrying 1440 fields.
    #[test]
    fn a_longer_window_gets_wider_buckets() {
        let hour = bucket_secs(Duration::from_secs(60 * 60));
        let day = bucket_secs(Duration::from_secs(24 * 60 * 60));
        assert!(day > hour, "hour={hour} day={day}");
        assert_eq!(hour, 60);
        assert_eq!(day, 24 * 60);
    }

    /// The scripts must not use `unpack`/`table.unpack` — see [`READ_SCRIPT`]'s
    /// doc comment. Pinned as a test because the tempting "optimisation" is a
    /// one-line change that only fails against one of the two supported
    /// servers.
    #[test]
    fn the_scripts_avoid_lua_version_dependent_builtins() {
        for script in [READ_SCRIPT, ADD_SCRIPT] {
            assert!(!script.contains("unpack"), "{script}");
        }
    }

    /// Eviction is by explicit cutoff, not by relying on the key TTL. A key
    /// TTL expires the *whole* window at once; without per-field eviction a
    /// continuously-active caller would keep buckets from previous windows and
    /// over-report spend forever.
    #[test]
    fn the_read_script_evicts_stale_buckets_itself() {
        assert!(READ_SCRIPT.contains("HDEL"));
        assert!(READ_SCRIPT.contains("cutoff"));
    }

    /// The TTL must outlive the window it covers, or a still-relevant bucket
    /// disappears and the caller silently gets allowance back.
    #[test]
    fn the_key_ttl_outlives_the_window() {
        for window in [
            Duration::from_secs(60 * 60),
            Duration::from_secs(24 * 60 * 60),
        ] {
            let ttl_ms = (window.as_millis() as u64) + bucket_secs(window) * 1_000;
            assert!(
                ttl_ms > window.as_millis() as u64,
                "ttl must exceed the window for {window:?}"
            );
        }
    }
}

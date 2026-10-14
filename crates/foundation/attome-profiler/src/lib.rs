//! attome-profiler: lightweight, developer-named performance probes dropped
//! anywhere in `base-*`/`xrm-*` code via `measure!("name", { .. })`,
//! aggregated cluster-wide in Redis into call count / avg / min / max /
//! total-since-start, plus a small capped ring of recent per-request traces
//! for a waterfall-style detail view. Powers the Angular "Profiler" admin
//! dashboard (`GET /api/v1/admin/profiler/*`, xrm-server's `profiler_admin`).
//!
//! **Naming rule (enforced by the crate):** a probe name is a constant or a
//! route template, never request data. Every name is checked before it reaches
//! Redis: empty, longer than `NAME_MAX_BYTES` bytes, or containing a byte
//! outside printable ASCII (`0x20..=0x7E`) is replaced with `"(invalid)"`, so
//! a raw path or a token can never become a key, and the replacement is
//! counted as `DroppedReason::InvalidName`. Dot-separated hierarchy is the
//! convention: `"entity.create"` for an API-level probe,
//! `"entity.create.db_insert"` for one of its sub-parts. `group_hierarchy`
//! groups sub-part rows under their shortest dotted-prefix parent; a name with
//! no such parent is its own top-level group.
//!
//! **Why Redis instead of in-process atomics:** this platform runs multiple
//! identical stateless nodes behind a load balancer (see the workspace
//! CLAUDE.md's multi-server hard constraint) — an in-process counter would
//! diverge per node. To keep the hot-path cost flat, `record`/`measure!` only
//! push into a `tokio::task_local!` accumulator (pure in-memory) and the write
//! side is a single `EVAL` per flush: `FLUSH_SCRIPT` admits new names
//! against a cross-node cap, bumps every stat hash, extends each TTL and
//! pushes the trace sample in one round-trip.
//!
//! **Keys, bounds and retention (constants, not config):**
//!
//! | Key | Type | TTL |
//! |---|---|---|
//! | `attome-profiler:stat:{name}` | hash (`count`/`sum_ms`/`min_ms`/`max_ms`) | sliding `STAT_TTL` (7 d) |
//! | `attome-profiler:trace:{name}` | list, capped at `TRACE_CAP` entries | sliding `TRACE_TTL` (24 h) |
//! | `attome-profiler:names` | set of admitted names, capped at `MAX_NAMES` | sliding `STAT_TTL` (7 d) |
//!
//! The name cap is atomic in Lua and cluster-wide: once `MAX_NAMES` distinct
//! names exist, a new name is refused (and counted) instead of creating keys,
//! so an unauthenticated scanner cannot grow the keyspace without bound.
//!
//! **Store:** the general `cache`/`state.redis` pool (D-027's degrade class)
//! at every site — never `redis_coordination`. The profiler is fail-open
//! telemetry; sharing memory with the pre-auth limiter and S2S nonces risks
//! D-397's fail-closed outage.
//!
//! **Fail-open, not fail-closed:** this is a debug/perf-introspection tool,
//! not a security control (contrast `xrm-s2s`'s nonce/rate-limit, which fails
//! *closed* on Redis errors per guidelines §7/§5). A Redis error or timeout
//! here just drops that data point — never fails or delays the request it
//! describes — and the drop is counted by reason (`DroppedReason`,
//! `dropped`); the flush path is additionally bounded by
//! `Flusher`'s `FLUSH_QUEUE_CAP`-entry queue.
//!
//! **`measure!` records only completed bodies.** The elapsed time is recorded
//! after `$body` finishes, so an early `?`, `return` or panic inside the block
//! skips the record — e.g. a rejected `entity.create.validate` does not appear
//! in the create trace. Wrap the part you want measured, not the early return.
//!
//! **Upgrade note (namespace rename):** keys written before the
//! `attome-profiler:` rename live under `profiler:` and never expired. They are
//! ignored by the read path; call
//! `DELETE /api/v1/admin/profiler/stats` (`reset`) once after upgrading to
//! sweep them.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use attome_cache::Store;
use fred::prelude::*;
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

tokio::task_local! {
    static PROBES: RefCell<Vec<ProbeRecord>>;
}

/// One `measure!()`/`record()` call's result: a name and how long it took.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub name: String,
    pub duration: Duration,
}

/// Records one probe measurement into the current request's local
/// accumulator. A no-op outside an active `scope` (e.g. a boot-time task or
/// a background job with no request context) — callers never need to guard
/// "am I inside a request" themselves.
pub fn record(name: impl Into<String>, duration: Duration) {
    let _ = PROBES.try_with(|probes| {
        probes.borrow_mut().push(ProbeRecord {
            name: name.into(),
            duration,
        });
    });
}

/// Times `$body` (sync or async — `.await` inside is timed too, since the
/// elapsed time is measured around however long the block actually takes to
/// resolve) and records it under `$name` via `record`.
///
/// The record happens only when `$body` finishes normally: an early `?`,
/// `return` or panic skips it (see the module doc's `measure!` note).
#[macro_export]
macro_rules! measure {
    ($name:expr, $body:block) => {{
        let __start = ::std::time::Instant::now();
        let __result = $body;
        $crate::record($name, __start.elapsed());
        __result
    }};
}

/// Runs `f` with a fresh probe accumulator active, returning both its output
/// and every probe recorded during it. The request entry point
/// (`attome-server`'s profiler middleware) wraps the whole handler chain in
/// this once per request; anything the handler calls into (`measure!` in
/// `xrm-entity`, `xrm-audit`, etc.) records into the same accumulator as long
/// as it stays on the same async task — true for ordinary `.await`ed calls,
/// not for anything `tokio::spawn`ed off to run independently.
pub async fn scope<F: Future>(f: F) -> (F::Output, Vec<ProbeRecord>) {
    PROBES
        .scope(RefCell::new(Vec::new()), async move {
            let result = f.await;
            let probes = PROBES.with(|p| p.borrow().clone());
            (result, probes)
        })
        .await
}

#[derive(Debug, Error)]
pub enum ProfilerError {
    #[error("redis profiler op timed out")]
    Timeout,
    #[error("redis profiler op failed: {0}")]
    Redis(String),
    #[error("profiler trace sample could not be serialized: {0}")]
    Serialize(String),
}

/// Per-operation Redis timeout — fail-open, so a slow store drops points
/// rather than stalling the flusher. Deliberately the request-path bound, not
/// `BACKGROUND`: a dropped profiler point costs nothing, so wait less.
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// Overall deadline for `read_stats`. `GET /admin/profiler/stats` must stay
/// fast even at the `MAX_NAMES` ceiling (S5: p95 <= 300 ms, hard deadline
/// 2 s), so the whole scan+pipeline read is bounded, not just each command.
const READ_DEADLINE: Duration = Duration::from_secs(2);

/// Cross-node cap on distinct probe names (OD-4). Enforced atomically in
/// `FLUSH_SCRIPT` against `attome-profiler:names`; once reached, new names are
/// refused and counted as `DroppedReason::Cardinality`.
pub const MAX_NAMES: i64 = 2_000;

/// Sliding TTL on stat hashes and the names set (OD-3).
pub const STAT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Sliding TTL on trace lists (OD-3).
pub const TRACE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Recent-trace ring size per top-level probe name — enough for a useful
/// waterfall sample without unbounded growth (guidelines §5's TTL/cap
/// discipline for anything cached in Redis).
pub const TRACE_CAP: i64 = 50;

/// Longest accepted probe name, in bytes (guidelines §5: names are constants
/// or route templates, never request data).
pub const NAME_MAX_BYTES: usize = 128;

/// Bounded in-flight flush queue (guidelines §10: bounded concurrency for
/// background work).
pub const FLUSH_QUEUE_CAP: usize = 1_024;

/// The set of admitted probe names — the cap's own key.
pub const NAMES_KEY: &str = "attome-profiler:names";
/// Stat-hash key prefix.
pub const STAT_PREFIX: &str = "attome-profiler:stat:";
/// Trace-list key prefix.
pub const TRACE_PREFIX: &str = "attome-profiler:trace:";
/// Pre-rename namespace, swept (never read) by `reset`.
pub const LEGACY_PATTERN: &str = "profiler:*";
/// Replacement name for any rejected probe name.
pub const INVALID_NAME: &str = "(invalid)";

/// How many keys `reset` unlinks per command.
const RESET_BATCH: usize = 500;

/// Why a profiler data point was dropped. The five variants are the
/// `reason` label set of `profiler_points_dropped_total` (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DroppedReason {
    /// The `Flusher` queue was full (or its task had stopped).
    QueueFull,
    /// Redis returned an error.
    RedisError,
    /// The operation exceeded `OP_TIMEOUT` (or `READ_DEADLINE`).
    Timeout,
    /// The name could not be admitted: `MAX_NAMES` reached.
    Cardinality,
    /// The name was empty, oversized or non-printable, and became `INVALID_NAME`.
    InvalidName,
}

impl DroppedReason {
    /// Every reason, in a stable order.
    pub const ALL: [DroppedReason; 5] = [
        DroppedReason::QueueFull,
        DroppedReason::RedisError,
        DroppedReason::Timeout,
        DroppedReason::Cardinality,
        DroppedReason::InvalidName,
    ];

    /// The label value used for this reason (`profiler_points_dropped_total{reason=...}`).
    pub const fn as_str(self) -> &'static str {
        match self {
            DroppedReason::QueueFull => "queue_full",
            DroppedReason::RedisError => "redis_error",
            DroppedReason::Timeout => "timeout",
            DroppedReason::Cardinality => "cardinality",
            DroppedReason::InvalidName => "invalid_name",
        }
    }

    const fn index(self) -> usize {
        match self {
            DroppedReason::QueueFull => 0,
            DroppedReason::RedisError => 1,
            DroppedReason::Timeout => 2,
            DroppedReason::Cardinality => 3,
            DroppedReason::InvalidName => 4,
        }
    }
}

/// Per-reason drop counters, process-lifetime. The counter is the source of
/// truth for `profiler_points_dropped_total`; a monitor-facing exporter reads
/// them through `dropped_counts`.
static DROPPED: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Count of trace-ring entries that could not be parsed on read (BPR-24).
static CORRUPT_TRACE_SAMPLES: AtomicU64 = AtomicU64::new(0);

/// At most one drop `warn!` per process per minute (BPR-23). A Redis outage
/// drops a point per request, and one log line each would be the flood the
/// profiler is supposed to make visible, not cause.
const DROP_WARN_INTERVAL_MS: u64 = 60_000;
/// `LAST_DROP_WARN_MS` before the first warn. `0` would read as "warned at
/// process start" and silence the first drop of every process.
const NEVER_WARNED: u64 = u64::MAX;
static PROCESS_START: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);
static LAST_DROP_WARN_MS: AtomicU64 = AtomicU64::new(NEVER_WARNED);

fn should_warn_drop(now_ms: u64, last_ms: u64) -> bool {
    last_ms == NEVER_WARNED || now_ms.saturating_sub(last_ms) >= DROP_WARN_INTERVAL_MS
}

fn note_drop(reason: DroppedReason) {
    note_drops(reason, 1);
}

fn note_drops(reason: DroppedReason, count: u64) {
    if count == 0 {
        return;
    }
    DROPPED[reason.index()].fetch_add(count, Ordering::Relaxed);
    // BPR-23: the counter is the primary signal. No recorder installed (a bare
    // unit-test binary, the profiler off in another process) is a no-op.
    metrics::counter!("profiler_points_dropped_total", "reason" => reason.as_str())
        .increment(count);
    let now = PROCESS_START.elapsed().as_millis() as u64;
    let last = LAST_DROP_WARN_MS.load(Ordering::Relaxed);
    if should_warn_drop(now, last)
        && LAST_DROP_WARN_MS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            reason = reason.as_str(),
            dropped = count,
            "profiler point(s) dropped"
        );
    }
}

/// How many data points have been dropped for `reason` since process start.
pub fn dropped(reason: DroppedReason) -> u64 {
    DROPPED[reason.index()].load(Ordering::Relaxed)
}

/// Every drop counter, for a monitor exporter to publish as
/// `profiler_points_dropped_total{reason}`.
pub fn dropped_counts() -> [(DroppedReason, u64); 5] {
    DroppedReason::ALL.map(|reason| (reason, dropped(reason)))
}

/// How many stored trace samples could not be deserialized on read. A corrupt
/// sample is skipped, never treated as an error, but it is visible here.
pub fn corrupt_trace_samples() -> u64 {
    CORRUPT_TRACE_SAMPLES.load(Ordering::Relaxed)
}

/// Parses the `cmdstat_<name>:calls=N` line out of an `INFO commandstats`
/// payload. Returns `None` when the store does not report that command.
pub fn parse_commandstat(info: &str, command: &str) -> Option<u64> {
    let needle = format!("cmdstat_{command}:calls=");
    info.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&needle)
            .and_then(|rest| rest.split(',').next())
            .and_then(|calls| calls.trim().parse().ok())
    })
}

fn stat_key(name: &str) -> String {
    format!("{STAT_PREFIX}{name}")
}

fn trace_key(name: &str) -> String {
    format!("{TRACE_PREFIX}{name}")
}

/// The §4.1 name guard: a name is acceptable only when it is non-empty, at
/// most `NAME_MAX_BYTES` bytes, and entirely printable ASCII. `count`
/// distinguishes a write-path rejection (counted) from a read-path lookup of a
/// name that could never have been stored (not counted).
fn sanitize_name(name: &str, count: bool) -> Cow<'_, str> {
    if !name.is_empty()
        && name.len() <= NAME_MAX_BYTES
        && name.bytes().all(|b| (0x20..=0x7E).contains(&b))
    {
        Cow::Borrowed(name)
    } else {
        if count {
            note_drop(DroppedReason::InvalidName);
        }
        Cow::Borrowed(INVALID_NAME)
    }
}

fn probe_name(name: &str) -> Cow<'_, str> {
    sanitize_name(name, true)
}

fn lookup_name(name: &str) -> Cow<'_, str> {
    sanitize_name(name, false)
}

/// The single Lua script behind one `flush`: admits new names against
/// `MAX_NAMES`, bumps count/sum and widens min/max for the top-level probe
/// and every sub-part, extends each key's sliding TTL, and pushes the trace
/// sample onto a `TRACE_CAP`-capped list — one `EVAL`, so one Redis command
/// per flush regardless of probe count (BPR-21).
///
/// `KEYS` = `[names, trace, stat_0, stat_1, ...]` (stat_0 is the top-level
/// probe); `ARGV` = `[stat_ttl_ms, trace_ttl_ms, trace_cap, name_cap,
/// trace_json, name_0, ms_0, name_1, ms_1, ...]`. Returns the number of names
/// the cap refused.
///
/// No `unpack`, no `redis.call` table tricks, no Dragonfly-unsupported forms:
/// a plain loop over `KEYS` (Dragonfly v2.0.0 compatible; proven by
/// `tests/redis.rs`).
const FLUSH_SCRIPT: &str = r#"
local names_key  = KEYS[1]
local trace_key  = KEYS[2]
local stat_ttl   = math.floor(tonumber(ARGV[1]))
local trace_ttl  = math.floor(tonumber(ARGV[2]))
local trace_cap  = tonumber(ARGV[3])
local name_cap   = tonumber(ARGV[4])
local trace_json = ARGV[5]

local dropped = 0
local top_ok = false

local function admit(name)
    if redis.call('SISMEMBER', names_key, name) == 1 then
        return true
    end
    if redis.call('SCARD', names_key) < name_cap then
        redis.call('SADD', names_key, name)
        return true
    end
    return false
end

local function bump(stat_key, ms)
    redis.call('HINCRBY', stat_key, 'count', 1)
    redis.call('HINCRBYFLOAT', stat_key, 'sum_ms', ms)
    local min = redis.call('HGET', stat_key, 'min_ms')
    if not min or tonumber(ms) < tonumber(min) then
        redis.call('HSET', stat_key, 'min_ms', ms)
    end
    local max = redis.call('HGET', stat_key, 'max_ms')
    if not max or tonumber(ms) > tonumber(max) then
        redis.call('HSET', stat_key, 'max_ms', ms)
    end
    redis.call('PEXPIRE', stat_key, stat_ttl)
end

for i = 3, #KEYS do
    local offset = (i - 3) * 2
    local name = ARGV[6 + offset]
    local ms = ARGV[7 + offset]
    if admit(name) then
        bump(KEYS[i], ms)
        if i == 3 then
            top_ok = true
        end
    else
        dropped = dropped + 1
    end
end

-- Slide on every flush, not only on SADD: a stable name set must live as long
-- as the stat hashes it accounts for, or the cap's count resets under them.
redis.call('PEXPIRE', names_key, stat_ttl)

if top_ok then
    redis.call('LPUSH', trace_key, trace_json)
    redis.call('LTRIM', trace_key, 0, trace_cap - 1)
    redis.call('PEXPIRE', trace_key, trace_ttl)
end

return dropped
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePart {
    pub name: String,
    pub ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSample {
    pub ts: i64,
    pub total_ms: f64,
    pub parts: Vec<TracePart>,
}

fn to_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Flushes one request's worth of probes as exactly one Redis command: bumps
/// the aggregate stat for the top-level probe name and every sub-part, extends
/// their sliding TTLs, and pushes a capped recent-trace sample under the
/// top-level name. Best-effort and fail-open — every failure path counts a
/// `DroppedReason` and returns, and the request it describes is unaffected.
pub async fn flush(
    redis: &Store,
    top_level: &str,
    total: Duration,
    parts: &[ProbeRecord],
) -> Result<(), ProfilerError> {
    // Probe statistics live in Redis, shared across nodes. A Solo install has
    // one process and no Redis, and its profiler page reports no samples
    // rather than holding a second copy of the aggregation in process memory.
    let redis = match redis {
        Store::Redis(pool) => pool,
        Store::Memory(_) => return Ok(()),
    };
    let top = probe_name(top_level);

    let sample = TraceSample {
        ts: chrono::Utc::now().timestamp_millis(),
        total_ms: to_ms(total),
        parts: parts
            .iter()
            .map(|p| TracePart {
                name: probe_name(&p.name).into_owned(),
                ms: to_ms(p.duration),
            })
            .collect(),
    };
    let serialized = serde_json::to_string(&sample).map_err(|e| {
        note_drop(DroppedReason::RedisError);
        ProfilerError::Serialize(e.to_string())
    })?;

    let mut entries: Vec<(Cow<'_, str>, f64)> = Vec::with_capacity(parts.len() + 1);
    entries.push((top, to_ms(total)));
    for part in parts {
        entries.push((probe_name(&part.name), to_ms(part.duration)));
    }

    let mut keys: Vec<String> = Vec::with_capacity(entries.len() + 2);
    keys.push(NAMES_KEY.to_string());
    keys.push(trace_key(&entries[0].0));
    for (name, _) in &entries {
        keys.push(stat_key(name));
    }

    let mut args: Vec<String> = Vec::with_capacity(entries.len() * 2 + 5);
    args.push(STAT_TTL.as_millis().to_string());
    args.push(TRACE_TTL.as_millis().to_string());
    args.push(TRACE_CAP.to_string());
    args.push(MAX_NAMES.to_string());
    args.push(serialized);
    for (name, ms) in &entries {
        args.push(name.to_string());
        args.push(ms.to_string());
    }

    let dropped_by_cap: i64 = tokio::time::timeout(
        OP_TIMEOUT,
        redis.eval::<i64, _, _, _>(FLUSH_SCRIPT, keys, args),
    )
    .await
    .map_err(|_| {
        note_drop(DroppedReason::Timeout);
        ProfilerError::Timeout
    })?
    .map_err(|e| {
        note_drop(DroppedReason::RedisError);
        ProfilerError::Redis(e.to_string())
    })?;

    note_drops(DroppedReason::Cardinality, dropped_by_cap.max(0) as u64);
    Ok(())
}

struct FlushJob {
    top_level: String,
    total: Duration,
    parts: Vec<ProbeRecord>,
}

type FlushFuture = Pin<Box<dyn Future<Output = Result<(), ProfilerError>> + Send>>;
type FlushSink = Arc<dyn Fn(FlushJob) -> FlushFuture + Send + Sync>;

/// A process-lifetime flush worker fed by a bounded queue (guidelines §10:
/// supervision work whose loss is harmless). Callers do not await Redis on
/// the response path: `Flusher::try_send` is non-blocking and drops (and
/// counts) a point when the queue is full, so a slow store cannot spawn
/// unbounded tasks the way one `tokio::spawn` per request does.
#[derive(Clone)]
pub struct Flusher {
    tx: mpsc::Sender<FlushJob>,
}

impl std::fmt::Debug for Flusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flusher").finish_non_exhaustive()
    }
}

impl Flusher {
    /// Starts the worker over `redis` (the general `cache`/`state.redis` pool
    /// for live deployments — never `redis_coordination`).
    pub fn new(redis: Store) -> Self {
        let sink: FlushSink = Arc::new(move |job: FlushJob| {
            let redis = redis.clone();
            Box::pin(async move { flush(&redis, &job.top_level, job.total, &job.parts).await })
        });
        Self::spawn(sink)
    }

    fn spawn(sink: FlushSink) -> Self {
        let (tx, mut rx) = mpsc::channel::<FlushJob>(FLUSH_QUEUE_CAP);
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                // `flush` already counts its own failure reasons; the sink is
                // deliberately infallible here so the worker never dies.
                let _ = sink(job).await;
            }
        });
        Self { tx }
    }

    /// Queues one flush without waiting. Returns `true` when it was accepted;
    /// a full (or stopped) queue drops the point and counts
    /// `DroppedReason::QueueFull`.
    pub fn try_send(
        &self,
        top_level: impl Into<String>,
        total: Duration,
        parts: Vec<ProbeRecord>,
    ) -> bool {
        if self
            .tx
            .try_send(FlushJob {
                top_level: top_level.into(),
                total,
                parts,
            })
            .is_ok()
        {
            true
        } else {
            note_drop(DroppedReason::QueueFull);
            false
        }
    }

    /// The process-wide `Flusher`, started over `redis` on first call (later
    /// calls ignore their argument). For call sites with no state to carry one
    /// in, such as the job wrapper apalis invokes. Must first be called from
    /// inside a Tokio runtime that outlives the process's flushes.
    pub fn shared(redis: &Store) -> &'static Flusher {
        static SHARED: std::sync::OnceLock<Flusher> = std::sync::OnceLock::new();
        SHARED.get_or_init(|| Flusher::new(redis.clone()))
    }
}

/// Deletes every profiler key in the store, in `RESET_BATCH`-sized `UNLINK`
/// batches: the current `attome-profiler:*` namespace plus the pre-rename
/// `profiler:*` one (which never expired). Idempotent — a second call deletes
/// nothing and still succeeds. Returns the number of keys removed.
pub async fn reset(redis: &Store) -> Result<u64, ProfilerError> {
    // Probe statistics live in Redis, shared across nodes. A Solo install has
    // one process and no Redis, and its profiler page reports no samples
    // rather than holding a second copy of the aggregation in process memory.
    let redis = match redis {
        Store::Redis(pool) => pool,
        Store::Memory(_) => return Ok(0),
    };
    let mut keys = scan_keys(redis, "attome-profiler:*").await?;
    keys.extend(scan_keys(redis, LEGACY_PATTERN).await?);

    let mut deleted = 0u64;
    for batch in keys.chunks(RESET_BATCH) {
        let n: i64 = tokio::time::timeout(OP_TIMEOUT, redis.unlink(batch.to_vec()))
            .await
            .map_err(|_| ProfilerError::Timeout)?
            .map_err(|e| ProfilerError::Redis(e.to_string()))?;
        deleted += n.max(0) as u64;
    }
    Ok(deleted)
}

/// One probe's aggregate stats. Values are accumulated cluster-wide in Redis
/// (not per node) and live under a sliding `STAT_TTL`; they are therefore
/// *not* reset when a process restarts — only TTL expiry or `reset` clears
/// them.
#[derive(Debug, Clone, Serialize)]
pub struct StatRow {
    pub name: String,
    pub count: u64,
    pub total_ms: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
}

/// Cursor-based `SCAN` (never blocking `KEYS`) over the probe-name keyspace —
/// small and bounded by `MAX_NAMES`, not by request volume.
async fn scan_keys(
    redis: &attome_cache::RedisPool,
    pattern: &str,
) -> Result<Vec<String>, ProfilerError> {
    use fred::types::Scanner;

    let mut keys = Vec::new();
    // `scan` depends on per-connection cursor state, so it isn't implemented
    // directly on `Store` (round-robin) — pin it to one client via
    // `next()`, same restriction fred documents for pubsub/client commands.
    let mut stream = redis.next().scan(pattern, Some(200u32), None);
    loop {
        let next = tokio::time::timeout(OP_TIMEOUT, stream.try_next())
            .await
            .map_err(|_| ProfilerError::Timeout)?
            .map_err(|e| ProfilerError::Redis(e.to_string()))?;
        let Some(mut page) = next else { break };
        if let Some(page_keys) = page.take_results() {
            keys.extend(page_keys.into_iter().filter_map(|k| k.into_string()));
        }
    }
    Ok(keys)
}

/// Reads every probe's current aggregate stats, sorted by name.
///
/// One pipelined `HGETALL` per `SCAN` page (not one round-trip per key), under
/// a single `READ_DEADLINE` for the whole read — at the `MAX_NAMES` ceiling
/// this is the difference between a fast admin page and one that stalls a 3 s
/// poll.
pub async fn read_stats(redis: &Store) -> Result<Vec<StatRow>, ProfilerError> {
    tokio::time::timeout(READ_DEADLINE, read_stats_inner(redis))
        .await
        .map_err(|_| ProfilerError::Timeout)?
}

async fn read_stats_inner(redis: &Store) -> Result<Vec<StatRow>, ProfilerError> {
    // Probe statistics live in Redis, shared across nodes. A Solo install has
    // one process and no Redis, and its profiler page reports no samples
    // rather than holding a second copy of the aggregation in process memory.
    let redis = match redis {
        Store::Redis(pool) => pool,
        Store::Memory(_) => return Ok(Vec::new()),
    };
    let pattern = format!("{STAT_PREFIX}*");
    let keys = scan_keys(redis, &pattern).await?;

    let mut rows = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(200) {
        let client = redis.next();
        let pipeline = client.pipeline();
        for key in chunk {
            let queued: Result<(), RedisError> = pipeline.hgetall(key.as_str()).await;
            queued.map_err(|e| ProfilerError::Redis(e.to_string()))?;
        }
        let maps: Vec<Result<HashMap<String, String>, RedisError>> =
            pipeline.try_all::<HashMap<String, String>>().await;

        for (key, map) in chunk.iter().zip(maps) {
            let map = map.map_err(|e| ProfilerError::Redis(e.to_string()))?;
            let count: u64 = map.get("count").and_then(|v| v.parse().ok()).unwrap_or(0);
            let total_ms: f64 = map
                .get("sum_ms")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let min_ms: f64 = map
                .get("min_ms")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let max_ms: f64 = map
                .get("max_ms")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let name = key.strip_prefix(STAT_PREFIX).unwrap_or(key).to_string();
            let avg_ms = if count > 0 {
                total_ms / count as f64
            } else {
                0.0
            };
            rows.push(StatRow {
                name,
                count,
                total_ms,
                avg_ms,
                min_ms,
                max_ms,
            });
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Reads up to `limit` recent trace samples for a top-level probe name,
/// newest first. A stored sample that no longer parses is skipped and counted
/// (`corrupt_trace_samples`) rather than failing the whole read.
pub async fn read_trace(
    redis: &Store,
    top_level: &str,
    limit: i64,
) -> Result<Vec<TraceSample>, ProfilerError> {
    // Probe statistics live in Redis, shared across nodes. A Solo install has
    // one process and no Redis, and its profiler page reports no samples
    // rather than holding a second copy of the aggregation in process memory.
    let redis = match redis {
        Store::Redis(pool) => pool,
        Store::Memory(_) => return Ok(Vec::new()),
    };
    let key = trace_key(&lookup_name(top_level));
    let raw: Vec<String> = tokio::time::timeout(OP_TIMEOUT, redis.lrange(&key, 0, limit - 1))
        .await
        .map_err(|_| ProfilerError::Timeout)?
        .map_err(|e| ProfilerError::Redis(e.to_string()))?;
    Ok(raw
        .into_iter()
        .filter_map(|s| match serde_json::from_str(&s) {
            Ok(sample) => Some(sample),
            Err(_) => {
                CORRUPT_TRACE_SAMPLES.fetch_add(1, Ordering::Relaxed);
                None
            }
        })
        .collect())
}

/// One top-level API probe plus every sub-part nested under it (dotted-name
/// convention — see the module doc).
#[derive(Debug, Clone, Serialize)]
pub struct ApiGroup {
    pub api: StatRow,
    pub parts: Vec<StatRow>,
}

/// Groups flat probe rows into API + sub-part trees. A row is a sub-part of
/// another row if its name is exactly that row's name plus a `.`-prefixed
/// suffix (`"entity.create.db_insert"` nests under `"entity.create"`, not
/// under `"entity"`) — the *shortest* matching dotted prefix wins, and
/// shortest-first processing guarantees a parent is always placed before its
/// children. A row with no such parent is its own top-level group even if
/// nothing nests under it.
///
/// One sort plus a name -> group-index map: O(n log n) instead of the former
/// O(rows x groups) scan, which at `MAX_NAMES` pins a runtime worker on
/// every 3 s dashboard poll (BPR-26).
pub fn group_hierarchy(rows: Vec<StatRow>) -> Vec<ApiGroup> {
    let mut rows = rows;
    rows.sort_by(|a, b| {
        a.name
            .len()
            .cmp(&b.name.len())
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut index: HashMap<String, usize> = HashMap::with_capacity(rows.len());
    let mut groups: Vec<ApiGroup> = Vec::new();
    for row in rows {
        let mut parent: Option<usize> = None;
        for (i, byte) in row.name.bytes().enumerate() {
            // Dots ascend the name from left to right, so the first prefix hit
            // in the map is the shortest matching dotted prefix.
            if byte == b'.'
                && let Some(&group) = index.get(&row.name[..i])
            {
                parent = Some(group);
                break;
            }
        }
        match parent {
            Some(group) => groups[group].parts.push(row),
            None => {
                index.insert(row.name.clone(), groups.len());
                groups.push(ApiGroup {
                    api: row,
                    parts: Vec::new(),
                });
            }
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str) -> StatRow {
        StatRow {
            name: name.to_string(),
            count: 1,
            total_ms: 1.0,
            avg_ms: 1.0,
            min_ms: 1.0,
            max_ms: 1.0,
        }
    }

    #[test]
    fn sub_parts_nest_under_their_exact_dotted_parent() {
        let groups = group_hierarchy(vec![
            row("entity.create.db_insert"),
            row("entity.create"),
            row("entity.create.validate"),
            row("entity.update"),
        ]);
        assert_eq!(groups.len(), 2);
        let create = groups
            .iter()
            .find(|g| g.api.name == "entity.create")
            .unwrap();
        assert_eq!(create.parts.len(), 2);
        let update = groups
            .iter()
            .find(|g| g.api.name == "entity.update")
            .unwrap();
        assert!(update.parts.is_empty());
    }

    #[test]
    fn a_name_with_no_parent_is_its_own_top_level_group() {
        let groups = group_hierarchy(vec![row("standalone")]);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].parts.is_empty());
    }

    #[test]
    fn a_nested_name_binds_to_its_shortest_matching_prefix() {
        // Preserves the pre-BPR-26 behaviour exactly: `a.b.c` nests under `a`
        // (the shortest dotted prefix that is a row), not under `a.b`.
        let groups = group_hierarchy(vec![row("a.b.c"), row("a.b"), row("a")]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].api.name, "a");
        let parts: Vec<&str> = groups[0].parts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(parts, vec!["a.b", "a.b.c"]);
    }

    #[test]
    fn group_hierarchy_scales_to_twenty_thousand_rows() {
        let mut rows = Vec::with_capacity(20_200);
        for i in 0..200 {
            rows.push(row(&format!("api{i}")));
            for j in 0..100 {
                rows.push(row(&format!("api{i}.part{j}")));
            }
        }
        let start = std::time::Instant::now();
        let groups = group_hierarchy(rows);
        let elapsed = start.elapsed();

        assert_eq!(groups.len(), 200);
        assert!(groups.iter().all(|g| g.parts.len() == 100));
        assert!(
            elapsed < Duration::from_millis(100),
            "group_hierarchy over 20,200 rows took {elapsed:?}, budget is 100 ms"
        );
    }

    #[test]
    fn name_guard_replaces_oversized_and_non_printable_names() {
        assert_eq!(probe_name("entity.create"), "entity.create");
        assert_eq!(
            probe_name("GET /api/v1/entities/{id}"),
            "GET /api/v1/entities/{id}"
        );

        let before = dropped(DroppedReason::InvalidName);
        assert_eq!(probe_name(""), INVALID_NAME);
        assert_eq!(probe_name("bad\tname"), INVALID_NAME);
        assert_eq!(probe_name("non\u{00e9}ascii"), INVALID_NAME);
        assert_eq!(probe_name(&"x".repeat(NAME_MAX_BYTES + 1)), INVALID_NAME);
        assert_eq!(
            probe_name(&"x".repeat(NAME_MAX_BYTES)),
            "x".repeat(NAME_MAX_BYTES)
        );
        assert!(
            dropped(DroppedReason::InvalidName) >= before + 4,
            "every rejected write-path name must be counted"
        );

        // A read-path lookup of an impossible name is not a dropped point.
        let quiet = dropped(DroppedReason::InvalidName);
        assert_eq!(lookup_name("bad\tname"), INVALID_NAME);
        assert_eq!(dropped(DroppedReason::InvalidName), quiet);
    }

    #[test]
    fn dropped_counter_records_each_reason() {
        assert_eq!(DroppedReason::ALL.len(), 5);
        for reason in DroppedReason::ALL {
            let before = dropped(reason);
            note_drop(reason);
            assert!(
                dropped(reason) > before,
                "{reason:?} must increase its own counter"
            );
        }
        let reasons: Vec<&str> = DroppedReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            reasons,
            vec![
                "queue_full",
                "redis_error",
                "timeout",
                "cardinality",
                "invalid_name"
            ]
        );
        assert_eq!(dropped_counts().len(), 5);
    }

    #[tokio::test]
    async fn flusher_bounds_its_queue_and_counts_overflows() {
        let before = dropped(DroppedReason::QueueFull);
        // A sink that never completes: the worker takes at most the first job
        // and the bounded channel holds the rest. On the single-threaded test
        // runtime the worker is not polled during the send loop at all.
        let sink: FlushSink =
            Arc::new(|_job| Box::pin(std::future::pending::<Result<(), ProfilerError>>()));
        let flusher = Flusher::spawn(sink);

        let mut accepted = 0usize;
        for _ in 0..10_000 {
            if flusher.try_send("bounded.probe", Duration::from_millis(1), Vec::new()) {
                accepted += 1;
            }
        }

        let rejected = 10_000 - accepted;
        assert!(
            accepted <= FLUSH_QUEUE_CAP,
            "in-flight work must be bounded to {FLUSH_QUEUE_CAP}, accepted {accepted}"
        );
        assert!(
            rejected >= 10_000 - FLUSH_QUEUE_CAP,
            "overflow must be rejected, rejected {rejected}"
        );
        assert!(
            dropped(DroppedReason::QueueFull) >= before + rejected as u64,
            "every rejected flush must be counted"
        );
    }

    #[test]
    fn the_first_drop_warns_and_later_ones_at_most_once_a_minute() {
        // The first drop in a process arrives with `now` near 0 (PROCESS_START
        // is first touched by it) and must still warn (BPR-23).
        assert!(should_warn_drop(0, NEVER_WARNED));
        assert!(should_warn_drop(5, NEVER_WARNED));
        assert!(!should_warn_drop(5, 0));
        assert!(!should_warn_drop(DROP_WARN_INTERVAL_MS - 1, 0));
        assert!(should_warn_drop(DROP_WARN_INTERVAL_MS, 0));
        assert!(!should_warn_drop(90_000, 60_000));
        assert!(should_warn_drop(120_000, 60_000));
    }

    #[test]
    fn commandstat_parsing_reads_the_calls_column() {
        let info = "# Commandstats\r\ncmdstat_eval:calls=7,usec=10,usec_per_call=1.4\r\ncmdstat_get:calls=3,usec=1\r\n";
        assert_eq!(parse_commandstat(info, "eval"), Some(7));
        assert_eq!(parse_commandstat(info, "get"), Some(3));
        assert_eq!(parse_commandstat(info, "lpush"), None);
    }

    #[tokio::test]
    async fn record_outside_a_scope_is_a_silent_no_op() {
        // Must not panic — background/boot-time code calls `measure!`/`record`
        // with no active request scope.
        record("no-scope", Duration::from_millis(1));
    }

    #[tokio::test]
    async fn scope_collects_every_probe_recorded_inside_it() {
        let (value, probes) = scope(async {
            measure!("a", { 1 + 1 });
            record("b", Duration::from_millis(5));
            "done"
        })
        .await;
        assert_eq!(value, "done");
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].name, "a");
        assert_eq!(probes[1].name, "b");
    }

    /// Counter totals keyed by `name{label=value,...}`, for the BPR-23
    /// recorder-level check. Hand-rolled like attome-storage's `TestRecorder`
    /// so the crate gains no `metrics-util` dev-dependency.
    #[derive(Clone, Default)]
    struct LabelledCounters(Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>);

    impl LabelledCounters {
        fn install() -> Self {
            static RECORDER: std::sync::OnceLock<LabelledCounters> = std::sync::OnceLock::new();
            let recorder = RECORDER.get_or_init(LabelledCounters::default).clone();
            let _ = metrics::set_global_recorder(recorder.clone());
            recorder
        }

        fn get(&self, key: &str) -> u64 {
            self.0
                .lock()
                .expect("recorder lock")
                .get(key)
                .copied()
                .unwrap_or(0)
        }
    }

    struct LabelledCounter {
        key: String,
        totals: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    }

    impl metrics::CounterFn for LabelledCounter {
        fn increment(&self, value: u64) {
            *self
                .totals
                .lock()
                .expect("recorder lock")
                .entry(self.key.clone())
                .or_insert(0) += value;
        }

        fn absolute(&self, value: u64) {
            self.totals
                .lock()
                .expect("recorder lock")
                .insert(self.key.clone(), value);
        }
    }

    impl metrics::Recorder for LabelledCounters {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            metrics::Counter::from_arc(Arc::new(LabelledCounter {
                key: format!("{}{{{}}}", key.name(), labels.join(",")),
                totals: self.0.clone(),
            }))
        }

        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// BPR-23: every drop reaches the metrics facade as
    /// `profiler_points_dropped_total{reason}`, one label value per reason,
    /// not just the in-process atomic `dropped()` reads.
    #[test]
    fn dropped_points_reach_the_metrics_recorder_per_reason() {
        let recorder = LabelledCounters::install();
        for reason in DroppedReason::ALL {
            let key = format!(
                "profiler_points_dropped_total{{reason={}}}",
                reason.as_str()
            );
            let before = recorder.get(&key);
            note_drops(reason, 3);
            assert!(
                recorder.get(&key) >= before + 3,
                "{key} must reach the recorder (before {before}, after {})",
                recorder.get(&key)
            );
        }
    }

    async fn five_probe_handler() -> usize {
        for part in [
            "entity.create.validate",
            "entity.create.insert",
            "entity.create.audit",
            "entity.create.hooks",
            "entity.create.cache",
        ] {
            record(part, Duration::from_micros(10));
        }
        5
    }

    fn percentile(sorted: &[Duration], p: f64) -> Duration {
        sorted[((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize]
    }

    /// BPR-25 (in-process half): what the profiler adds to one request's
    /// response path — `scope` around the handler, five `record`s and one
    /// `try_send` — against the same handler with the profiler off, where
    /// `record` is a no-op. The Redis `EVAL` runs on the flusher task, off
    /// this path, so it is deliberately not in the measured span.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "timing; run: cargo test --release -p attome-profiler --lib -- --ignored --nocapture timing"]
    async fn timing_request_overhead_on_vs_off() {
        const N: usize = 20_000;
        let sink: FlushSink = Arc::new(|_job| Box::pin(async { Ok(()) }));
        let flusher = Flusher::spawn(sink);

        let mut off = Vec::with_capacity(N);
        let mut on = Vec::with_capacity(N);
        for _ in 0..N {
            let t = std::time::Instant::now();
            std::hint::black_box(five_probe_handler().await);
            off.push(t.elapsed());

            let t = std::time::Instant::now();
            let (out, parts) = scope(five_probe_handler()).await;
            flusher.try_send("POST /api/v1/{entity}", t.elapsed(), parts);
            std::hint::black_box(out);
            on.push(t.elapsed());
        }
        off.sort();
        on.sort();
        let (off50, off95) = (percentile(&off, 50.0), percentile(&off, 95.0));
        let (on50, on95) = (percentile(&on, 50.0), percentile(&on, 95.0));
        let added95 = on95.saturating_sub(off95);
        println!(
            "profiler overhead over {N} requests: off p50 {off50:?} p95 {off95:?}; on p50 {on50:?} p95 {on95:?}; added p95 {added95:?} (budget 300us)"
        );
        assert!(
            added95 <= Duration::from_micros(300),
            "S4: the profiler must add at most 0.3 ms at p95, added {added95:?}"
        );
    }
}

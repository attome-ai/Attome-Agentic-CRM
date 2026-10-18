//! `attome-jobs`: the durable job queue. Jobs are rows in PostgreSQL
//! (`apalis.jobs`, migration `0001_job_queue.sql`), written in the producer's
//! own transaction when it has one, so a crash after commit never loses one.
//!
//! This crate knows no job kinds: the application implements [`Job`] for its
//! own job enum, and every function here is generic over it.

mod job;

/// The schedule ledger that makes a periodic job run once per slot across
/// workers and restarts. See the module docs.
pub mod schedule;

use chrono::{DateTime, Utc};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub use apalis_sql::Config as JobsConfig;
pub use apalis_sql::postgres::PostgresStorage;
pub use job::{CURRENT_ENVELOPE_VERSION, Job, JobEnvelope, JobPriority, MALFORMED_VARIANT_TAG};

/// Postgres-backed handle for one queue of `J`. Cheap to `.clone()` (it wraps
/// a pooled `PgPool`).
pub type JobsStorage<J> = PostgresStorage<JobEnvelope<J>>;

/// Namespace stored in `apalis.jobs.job_type` for every non-batch job, set
/// explicitly (rather than defaulting to `std::any::type_name`) so the column
/// stays a stable, readable value across refactors.
pub const NAMESPACE: &str = "attome_job";

/// The batch queue's namespace: open-ended, record-count-proportional jobs
/// ([`Job::is_batch`]) run on their own worker, so a flood of bulk work can
/// never starve the fast queue's latency-sensitive jobs.
pub const NAMESPACE_BATCH: &str = "attome_job_batch";

fn namespace_for<J: Job>(job: &J) -> &'static str {
    if job.is_batch() {
        NAMESPACE_BATCH
    } else {
        NAMESPACE
    }
}

/// The ambient tracing span's W3C `traceparent`, stamped onto every envelope
/// by the `enqueue*` functions, so no producer threads trace context by hand.
/// `None` when there is no valid OpenTelemetry span context, which is always
/// the case while distributed tracing is off.
fn current_traceparent() -> Option<String> {
    attome_types::w3c_trace::format_current_traceparent(&tracing::Span::current().context())
}

/// Both queues' storage handles. Every `enqueue*` call routes to the right
/// queue through [`Job::is_batch`]; no producer chooses one.
pub struct Jobs<J: Job> {
    fast: JobsStorage<J>,
    batch: JobsStorage<J>,
}

impl<J: Job> Clone for Jobs<J> {
    fn clone(&self) -> Self {
        Self {
            fast: self.fast.clone(),
            batch: self.batch.clone(),
        }
    }
}

impl<J: Job> std::fmt::Debug for Jobs<J> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jobs")
            .field("fast", &NAMESPACE)
            .field("batch", &NAMESPACE_BATCH)
            .finish()
    }
}

/// Both queues' apalis tuning, pinned rather than inherited
/// (PLATFORM-REVIEW-2026-08-24 CONC-5).
///
/// `JobsConfig::new(ns)` is `Config::default().set_namespace(ns)`, so calling
/// it alone accepts whatever apalis-sql's `Default` happens to say. Every
/// value below except `poll_interval` (D-619) is **exactly** apalis-sql
/// 0.7.4's default; pinning them means a future `apalis-sql` bump can no
/// longer move the platform's job-processing timing silently. If
/// an upgrade wants different numbers, that now shows up as a deliberate edit
/// here instead of a diff nobody reads in a transitive dependency.
///
/// - `poll_interval` **2s** (D-619, was apalis's 100 ms) — the *safety net*
///   only. A worker normally starts a job because every enqueue path below
///   notifies [`WAKE_CHANNEL`] with its namespace and
///   [`attach_wakeup_listener`] wakes that queue's poller; the poll catches
///   what a notification missed (a listener reconnecting, a dead letter
///   replayed by `UPDATE`, a retry whose `run_at` arrives later). At 100 ms two
///   namespaces across N nodes cost 20·N polls/sec at idle; at 2 s, 1·N.
/// - `keep_alive` **30s** — how often a worker refreshes `apalis.workers.last_seen`.
///   `worker_last_seen_age_seconds` (below) reads exactly that column, so this
///   value is the floor on how stale the `apalis_worker_last_seen_age_seconds`
///   gauge can look while everything is healthy: alert above it, not near it.
/// - `reenqueue_orphaned_after` **300s** — the visibility timeout. A job whose
///   worker died stays claimed this long before `reenqueue_orphaned` returns it
///   to the queue. It is the correctness-relevant one: lowering it risks running
///   a job twice that was merely slow, raising it lengthens recovery after a
///   node loss. Every job is required to be retry-safe (§10), which is what
///   makes the 5-minute default tolerable in the first place.
/// - `buffer_size` **10** — rows fetched per poll. Concurrency is bounded
///   separately, by each queue's own `WorkerBuilder` in `main.rs`.
fn queue_config(namespace: &str) -> JobsConfig {
    JobsConfig::new(namespace)
        .set_poll_interval(SAFETY_POLL_INTERVAL)
        .set_keep_alive(std::time::Duration::from_secs(30))
        .set_buffer_size(10)
        .set_reenqueue_orphaned_after(std::time::Duration::from_secs(300))
}

/// D-619 — how often an idle worker polls when no wake-up arrives.
pub const SAFETY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// D-619 — the channel every enqueue path notifies, with the job's namespace
/// as the payload (what apalis-sql's `PgListen` matches a queue on). Migration
/// `0014`'s `notify_workers` trigger uses the same channel with the payload
/// `insert`, which matches no queue, so that trigger alone never woke anyone.
pub const WAKE_CHANNEL: &str = "apalis::job";

/// How long the wake-up listener keeps retrying a lost connection before it
/// gives up and leaves the queues on the safety poll.
pub const LISTENER_RECONNECT_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// D-619 — subscribes both queues of `jobs` to one `LISTEN` session and
/// returns the future that runs it (the caller spawns it; this crate stays
/// runtime-agnostic). Call before the storages are cloned into their
/// `WorkerBuilder`s: a clone taken earlier carries no subscription.
///
/// `connect` must be a session-pinned endpoint (`LISTEN` does not survive
/// transaction-mode pgbouncer) as the runtime identity — D-619 ruling 2;
/// `attome_db::runtime_session_options` builds exactly that. The session is
/// held through a one-connection pool, so sqlx reconnects and re-issues
/// `LISTEN` after a dropped connection, retrying for up to
/// [`LISTENER_RECONNECT_BUDGET`]; `on_connect` runs on every (re)connect so
/// the caller can count them. Notifications missed meanwhile are covered by
/// [`SAFETY_POLL_INTERVAL`]. The returned future ends only if reconnecting
/// fails for good; job processing continues on the poll either way.
pub async fn attach_wakeup_listener<J: Job>(
    connect: sqlx::postgres::PgConnectOptions,
    jobs: &mut Jobs<J>,
    on_connect: fn(),
) -> Result<impl std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'static, sqlx::Error>
{
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(LISTENER_RECONNECT_BUDGET)
        .after_connect(move |_, _| {
            Box::pin(async move {
                on_connect();
                Ok(())
            })
        })
        .connect_lazy_with(connect);
    let mut listener = apalis_sql::postgres::PgListen::new(pool).await?;
    listener.subscribe_with(&mut jobs.fast);
    listener.subscribe_with(&mut jobs.batch);
    Ok(listener.listen())
}

impl<J: Job> Jobs<J> {
    /// Builds both queues' storage handles over the shared pool. The tables
    /// come from migration `0001_job_queue.sql`, never from apalis's runtime
    /// `setup()`. Tuning comes from `queue_config`, pinned rather than
    /// inherited.
    pub fn new(pool: attome_db::DbPool) -> Self {
        Self {
            fast: PostgresStorage::new_with_config(pool.clone(), queue_config(NAMESPACE)),
            batch: PostgresStorage::new_with_config(pool, queue_config(NAMESPACE_BATCH)),
        }
    }

    /// The default queue's storage handle — for registering its
    /// `WorkerBuilder` in `main.rs`.
    pub fn fast(&self) -> &JobsStorage<J> {
        &self.fast
    }

    /// The batch queue's storage handle — for registering its own,
    /// independently-concurrency-limited `WorkerBuilder` in `main.rs`.
    pub fn batch(&self) -> &JobsStorage<J> {
        &self.batch
    }
}

/// Enqueues one job through apalis's `Storage::push`, on the fast or batch
/// queue by [`Job::is_batch`].
///
/// Awaited directly in the request path (no `tokio::spawn`): the whole point
/// of P1.4 is that the job is durable — written to Postgres — before the
/// handler returns, so a crash immediately after can't lose it. The insert
/// itself is a single indexed row write, not meaningfully slower than the
/// direct UPDATE/INSERT it replaces.
pub async fn enqueue<J: Job>(jobs: &mut Jobs<J>, job: J) -> Result<(), sqlx::Error> {
    use apalis::prelude::{Request, Storage};
    use apalis_sql::context::SqlContext;

    // Computed from `&job` before it's moved into the envelope below (M08
    // checklist item 1 — priority lanes).
    let is_batch = job.is_batch();
    let priority = job.priority().apalis_priority();
    // BJB-2 (J3): the kind's own declared budget, not the enqueue path's
    // accidental default (5 for `enqueue`, 25 for the three SQL paths).
    let max_attempts = job.max_attempts();
    let storage = if is_batch {
        &mut jobs.batch
    } else {
        &mut jobs.fast
    };
    // `SqlContext::default()` is exactly what `Storage::push`'s own default
    // implementation (`push_request(Request::new(job))`) would have built —
    // see `Ctx::default()` in apalis-core's `Request::new` — so overriding
    // only `priority` and `max_attempts` changes nothing else about how this
    // job is stored.
    //
    // BJB-2 (J3): `SqlContext::new` defaults `max_attempts` to **5** — its own
    // doc comment at `apalis-sql-0.7.4/src/context.rs:48` says 25, which
    // the source contradicts — while `apalis.push_job`/`push_job_dedup`
    // default the column to 25. So the budget used to depend on which enqueue
    // function a producer happened to call (BJB-F3). The kind declares it now.
    let mut ctx = SqlContext::default();
    ctx.set_priority(priority);
    ctx.set_max_attempts(max_attempts);
    storage
        .push_request(Request::new_with_ctx(
            JobEnvelope::new_with_trace_context(job, current_traceparent()),
            ctx,
        ))
        .await?;
    // D-619: a separate statement because `push_request` is apalis's own. A
    // failed notify only delays the job to the next safety poll.
    let namespace = storage.config().namespace().to_owned();
    if let Err(e) = sqlx::query(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT pg_notify($1, $2)"
    ))
    .bind(WAKE_CHANNEL)
    .bind(&namespace)
    .execute(storage.pool())
    .await
    {
        tracing::warn!(error = %e, namespace, "job enqueued, but the worker wake-up notify failed");
    }
    Ok(())
}

/// Transactional counterpart to [`enqueue`]. Use when a job is the durable
/// follow-up to a metadata write, so both become visible at the same commit.
/// Same queue/priority/max_attempts routing as `enqueue`, via
/// `apalis.push_job`'s own named parameters — no new SQL function needed,
/// `0014_apalis_jobs.sql` already exposes both `max_attempts` and `priority`.
/// Named-parameter call syntax (`param => $n`) rather than positional, so
/// `status`/`run_at` keep their function defaults while `job_type`/`job`/
/// `priority`/`max_attempts` are bound explicitly — BJB-2 binds the kind's own
/// declared budget (`Job::max_attempts`) instead of leaving the
/// column's SQL default (25).
pub async fn enqueue_in_tx<J: Job>(tx: &mut attome_db::Tx<'_>, job: J) -> Result<(), sqlx::Error> {
    let namespace = namespace_for(&job);
    let priority = job.priority().apalis_priority();
    // BJB-2 (J3): the kind's own declared budget, not the enqueue path's
    // accidental default (5 for `enqueue`, 25 for the three SQL paths).
    let max_attempts = job.max_attempts();
    let payload = serde_json::to_value(JobEnvelope::new_with_trace_context(
        job,
        current_traceparent(),
    ))
    .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    // D-619: the notify is transactional, so it is delivered at commit.
    sqlx::query(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT apalis.push_job(\
             job_type => $1, job => $2::json, priority => $3, max_attempts => $4), \
             pg_notify($5, $1)"
    ))
    .bind(namespace)
    .bind(payload)
    .bind(priority)
    .bind(max_attempts)
    .bind(WAKE_CHANNEL)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// [`enqueue`] for a caller that holds a pool rather than a typed storage
/// handle: the same queue, priority and attempt routing, through
/// `apalis.push_job`, with the same worker wake-up.
pub async fn enqueue_on_pool<J: Job>(pool: &attome_db::DbPool, job: J) -> Result<(), sqlx::Error> {
    let namespace = namespace_for(&job);
    let priority = job.priority().apalis_priority();
    let max_attempts = job.max_attempts();
    let payload = serde_json::to_value(JobEnvelope::new_with_trace_context(
        job,
        current_traceparent(),
    ))
    .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    sqlx::query(
        attome_db::tagged_sql!("jobs.queue", "SELECT apalis.push_job( job_type => $1, job => $2::json, priority => $3, max_attempts => $4), pg_notify($5, $1)"),
    )
    .bind(namespace)
    .bind(payload)
    .bind(priority)
    .bind(max_attempts)
    .bind(WAKE_CHANNEL)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deduplicated counterpart to [`enqueue`] — `Ok(true)` if a new row was
/// actually inserted, `Ok(false)` if an eligible (`Pending`/`Running`/
/// `Failed`) row with the same `(job_type, dedup_key)` already existed and
/// this call was a no-op (`apalis.push_job_dedup`, migration `0060`). Not
/// apalis's typed `Storage::push` — that has no conflict-handling hook — so
/// this takes the pool directly rather than `&mut Jobs`.
pub async fn enqueue_dedup<J: Job>(
    pool: &attome_db::DbPool,
    job: J,
    dedup_key: &str,
) -> Result<bool, sqlx::Error> {
    let namespace = namespace_for(&job);
    let priority = job.priority().apalis_priority();
    // BJB-2 (J3): the kind's own declared budget, not the enqueue path's
    // accidental default (5 for `enqueue`, 25 for the three SQL paths).
    let max_attempts = job.max_attempts();
    let payload = serde_json::to_value(JobEnvelope::new_with_trace_context(
        job,
        current_traceparent(),
    ))
    .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    // D-619: one notify per inserted row; a deduplicated no-op wakes nobody.
    let id: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT id, pg_notify($6, $1) FROM apalis.push_job_dedup(\
             p_job_type => $1, p_job => $2::json, p_dedup_key => $3, p_priority => $4, \
             p_max_attempts => $5)"
    ))
    .bind(namespace)
    .bind(payload)
    .bind(dedup_key)
    .bind(priority)
    .bind(max_attempts)
    .bind(WAKE_CHANNEL)
    .fetch_optional(pool)
    .await?;
    Ok(id.is_some())
}

/// Transactional counterpart to [`enqueue_dedup`].
pub async fn enqueue_in_tx_dedup<J: Job>(
    tx: &mut attome_db::Tx<'_>,
    job: J,
    dedup_key: &str,
) -> Result<bool, sqlx::Error> {
    let namespace = namespace_for(&job);
    let priority = job.priority().apalis_priority();
    // BJB-2 (J3): the kind's own declared budget, not the enqueue path's
    // accidental default (5 for `enqueue`, 25 for the three SQL paths).
    let max_attempts = job.max_attempts();
    let payload = serde_json::to_value(JobEnvelope::new_with_trace_context(
        job,
        current_traceparent(),
    ))
    .map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    // D-619: one notify per inserted row; a deduplicated no-op wakes nobody.
    let id: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT id, pg_notify($6, $1) FROM apalis.push_job_dedup(\
             p_job_type => $1, p_job => $2::json, p_dedup_key => $3, p_priority => $4, \
             p_max_attempts => $5)"
    ))
    .bind(namespace)
    .bind(payload)
    .bind(dedup_key)
    .bind(priority)
    .bind(max_attempts)
    .bind(WAKE_CHANNEL)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(id.is_some())
}

/// Count of not-yet-run rows in one queue (`apalis.jobs`,
/// P-observability-bcdr Track A / P-job-queue-hardening) — a
/// metrics-refresh-loop gauge, not a hot request path, so a plain
/// `COUNT(*)` is fine. `batch = false` for the default/fast queue.
pub async fn pending_count(pool: &attome_db::DbPool, batch: bool) -> Result<i64, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT COUNT(*) FROM apalis.jobs WHERE status = 'Pending' AND job_type = $1"
    ))
    .bind(namespace)
    .fetch_one(pool)
    .await
}

/// Per-lane counterpart to [`pending_count`] — M08 checklist item 1's
/// "worker metrics per lane". Same `COUNT(*)`-on-a-metrics-loop tradeoff as
/// `pending_count`, scoped further by `priority` so an operator can see
/// whether one lane is backing up behind another instead of only the flat
/// per-queue total.
pub async fn pending_count_by_priority(
    pool: &attome_db::DbPool,
    batch: bool,
    priority: JobPriority,
) -> Result<i64, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT COUNT(*) FROM apalis.jobs \
         WHERE status = 'Pending' AND job_type = $1 AND priority = $2"
    ))
    .bind(namespace)
    .bind(priority.apalis_priority())
    .fetch_one(pool)
    .await
}

/// BJB-3 (BJB-F8) — rows currently waiting out a retry backoff: `Failed` with
/// attempts still left. `pending_count` counts only `Pending`, so a backlog
/// sitting in backoff reads as zero on the backlog gauge; this is its
/// companion. Exported beside `apalis_pending_jobs` as
/// `apalis_retrying_jobs{queue}` in `attome-server/src/metrics.rs` (that
/// export is BJB-14b's sibling change and lives outside this crate).
pub async fn retrying_count(pool: &attome_db::DbPool, batch: bool) -> Result<i64, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT COUNT(*) FROM apalis.jobs \
         WHERE status = 'Failed' AND attempts < max_attempts AND job_type = $1"
    ))
    .bind(namespace)
    .fetch_one(pool)
    .await
}

/// BJB-14b — seconds since the oldest `Pending` row in one queue was due
/// (`run_at`), or `None` when the queue is empty. Backs
/// `apalis_oldest_pending_age_seconds{queue}`: `pending_count` alone cannot
/// distinguish a queue that is busy from one whose oldest row has been waiting
/// an hour, and the age is the trigger the no-aging decision (§9) is watching
/// for.
pub async fn oldest_pending_age_seconds(
    pool: &attome_db::DbPool,
    batch: bool,
) -> Result<Option<f64>, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT EXTRACT(EPOCH FROM (now() - MIN(run_at)))::float8 FROM apalis.jobs \
         WHERE status = 'Pending' AND job_type = $1"
    ))
    .bind(namespace)
    .fetch_one(pool)
    .await
}

/// Count of dead-lettered rows in one queue — apalis's own terminal state
/// for a job that exhausted `max_attempts` (`status = 'Killed'`, confirmed
/// against apalis-sql 0.7.4's `calculate_status`; distinct from `'Failed'`,
/// which is still-retryable). Backs `apalis_dead_letter_jobs` and the
/// dead-letter admin list's count.
pub async fn dead_letter_count(pool: &attome_db::DbPool, batch: bool) -> Result<i64, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT COUNT(*) FROM apalis.jobs WHERE status = 'Killed' AND job_type = $1"
    ))
    .bind(namespace)
    .fetch_one(pool)
    .await
}

/// Seconds since any worker process of one queue last heartbeat
/// (`apalis.workers.last_seen`, refreshed every `keep_alive` by apalis's own
/// poll loop) — `None` if no worker of that type has ever registered.
/// Backs `apalis_worker_last_seen_age_seconds`: the correct "is this queue's
/// worker alive at all" signal, since apalis already self-heals individual
/// orphaned job rows (`reenqueue_orphaned`) as long as *some* worker of that
/// type is up — a per-row "stuck" gauge would be redundant with that
/// built-in behavior.
pub async fn worker_last_seen_age_seconds(
    pool: &attome_db::DbPool,
    batch: bool,
) -> Result<Option<f64>, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT EXTRACT(EPOCH FROM (now() - MAX(last_seen)))::float8 \
         FROM apalis.workers WHERE worker_type = $1"
    ))
    .bind(namespace)
    .fetch_one(pool)
    .await
}

/// AB7-T2: a worker name unique to this process (`{kind}@{host}:{pid}`).
/// A stopping process can then release the jobs it still holds without
/// touching a live worker's, and a dead process's jobs look orphaned instead
/// of being kept alive by a namesake's heartbeat.
pub fn worker_name(kind: &str) -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".to_owned());
    format!("{kind}@{host}:{}", std::process::id())
}

/// AB7-T2: returns the jobs `worker` still holds to `Pending` at once, so a
/// job interrupted by a worker stop is picked up by another worker within
/// seconds instead of after the orphan timeout. Safe because every job is
/// idempotent and retry-safe (guidelines section 10): a job that had half
/// run simply runs again. Returns how many were released.
pub async fn release_claimed(pool: &attome_db::DbPool, worker: &str) -> Result<u64, sqlx::Error> {
    sqlx::query(attome_db::tagged_sql!(
        "jobs.queue",
        "UPDATE apalis.jobs SET status = 'Pending', lock_at = NULL, lock_by = NULL, \
             run_at = now() \
         WHERE lock_by = $1 AND status = 'Running'"
    ))
    .bind(worker)
    .execute(pool)
    .await
    .map(|done| done.rows_affected())
}

/// AB7-T2: [`release_claimed`] for each of a stopping process's workers,
/// logged; a failure is logged and the orphan timeout recovers the jobs.
pub async fn release_claimed_on_stop(pool: &attome_db::DbPool, workers: &[&str]) {
    for worker in workers {
        match release_claimed(pool, worker).await {
            Ok(0) => {}
            Ok(released) => {
                tracing::info!(
                    worker,
                    released,
                    "jobs this worker still held returned to the queue"
                )
            }
            Err(error) => tracing::warn!(
                worker,
                %error,
                "could not return this worker's jobs to the queue; the orphan timeout will"
            ),
        }
    }
}

/// One dead-lettered (`status = 'Killed'`) row, for the admin dead-letter
/// list. `job` is the full versioned-envelope payload
/// (`{"version","variant","payload","trace_context"}`, see [`JobEnvelope`]) —
/// callers extract only the variant tag from it and must never return the
/// whole thing to a client; some variants (`SendEmail`) carry live
/// reset/verification tokens in their body.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeadLetterJobRow {
    pub id: String,
    pub job: serde_json::Value,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub run_at: DateTime<Utc>,
    pub done_at: Option<DateTime<Utc>>,
}

/// Paginated list of dead-lettered rows in one queue, most recently
/// dead-lettered first. `offset` and `page_size` are the caller's
/// responsibility to clamp (`attome_types::PageWindow` does it) — this
/// function does no clamping of its own.
pub async fn list_dead_letter_jobs(
    pool: &attome_db::DbPool,
    batch: bool,
    offset: i64,
    page_size: i64,
) -> Result<Vec<DeadLetterJobRow>, sqlx::Error> {
    let namespace = if batch { NAMESPACE_BATCH } else { NAMESPACE };
    sqlx::query_as(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT id, job, attempts, max_attempts, last_error, run_at, done_at \
         FROM apalis.jobs \
         WHERE status = 'Killed' AND job_type = $1 \
         ORDER BY done_at DESC NULLS LAST \
         LIMIT $2 OFFSET $3"
    ))
    .bind(namespace)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// BJB-6a (BJB-D6) — what one replay attempt did.
///
/// The two failure modes are deliberately distinct. A row that is not
/// dead-lettered is a no-op the caller can ignore; a row whose
/// `(job_type, dedup_key)` is already held by a **live** row is a refusal the
/// operator must be told about, because the live row is already doing the
/// work (BJB-D6). Before BJB-6a that second case surfaced as a raw `23505`
/// from `apalis_jobs_dedup_key_idx`, which the admin handler mapped to a masked
/// 500 (BJB-F7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The row was `Killed` and is `Pending` again.
    Replayed,
    /// `id` does not name a currently dead-lettered row: already replayed,
    /// never existed, or still mid-retry.
    NotDeadLettered,
    /// The row was dead-lettered, but a live row already holds the same
    /// `(job_type, dedup_key)`. `live_id` names that row so the caller can
    /// tell the operator which job is already in flight.
    DedupSlotTaken {
        /// The live row's `apalis.jobs.id`.
        live_id: String,
    },
}

/// Replays one dead-lettered job and reports the outcome (BJB-6a).
///
/// One transaction: lock the dead-letter row, refuse if a live row already
/// holds its dedup slot, otherwise reset it to `Pending` so the next
/// `get_jobs` poll of its queue picks it up again. The `FOR UPDATE` makes two
/// concurrent replays of the same row resolve to exactly one `Replayed` — the
/// loser then sees `Pending` and gets `NotDeadLettered` — and the guarded
/// `UPDATE` plus the `23505` fallback cover the narrow window where a
/// producer inserts a same-key row between the check and the write. The old
/// `WHERE status = 'Killed'` guard stays race-safe either way: replay can never
/// force-nudge a job apalis is legitimately still working through.
#[expect(
    clippy::disallowed_methods,
    reason = "attome-jobs' whole public surface is `sqlx::Error`, so it cannot adopt \
              `attome_db::tx::begin`'s `AppError`; the caller maps this error to its own HTTP \
              response"
)]
pub async fn replay_dead_letter_job_checked(
    pool: &attome_db::DbPool,
    id: &str,
) -> Result<ReplayOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let target: Option<(String, Option<String>)> = sqlx::query_as(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT job_type, dedup_key FROM apalis.jobs \
         WHERE id = $1 AND status = 'Killed' FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((job_type, dedup_key)) = target else {
        tx.rollback().await?;
        return Ok(ReplayOutcome::NotDeadLettered);
    };

    if let Some(key) = dedup_key.as_deref()
        && let Some(live_id) = live_row_with_key(&mut *tx, &job_type, key, id).await?
    {
        tx.rollback().await?;
        return Ok(ReplayOutcome::DedupSlotTaken { live_id });
    }

    let updated = sqlx::query(attome_db::tagged_sql!(
        "jobs.queue",
        "UPDATE apalis.jobs SET status = 'Pending', attempts = 0, last_error = NULL, \
             run_at = now(), lock_at = NULL, lock_by = NULL, done_at = NULL \
         WHERE id = $1 AND status = 'Killed' \
           AND NOT EXISTS ( \
               SELECT 1 FROM apalis.jobs live \
               WHERE live.job_type = $2 AND live.dedup_key = $3 \
                 AND live.status IN ('Pending', 'Running', 'Failed') AND live.id <> $1 \
           )"
    ))
    .bind(id)
    .bind(&job_type)
    .bind(dedup_key.as_deref())
    .execute(&mut *tx)
    .await;

    match updated {
        Ok(result) if result.rows_affected() > 0 => {
            tx.commit().await?;
            Ok(ReplayOutcome::Replayed)
        }
        // The guarded UPDATE matched nothing: either another replay won first
        // (the row is no longer Killed), or a live same-key row appeared
        // between the check and the write.
        Ok(_) => {
            let live_id = match dedup_key.as_deref() {
                Some(key) => live_row_with_key(&mut *tx, &job_type, key, id).await?,
                None => None,
            };
            tx.rollback().await?;
            Ok(match live_id {
                Some(live_id) => ReplayOutcome::DedupSlotTaken { live_id },
                None => ReplayOutcome::NotDeadLettered,
            })
        }
        // Backstop: the partial unique index fired (23505) because a live
        // same-key row committed in the window above. Name it rather than
        // surfacing a masked 500. Postgres has already aborted `tx` (any
        // further statement on it is 25P02), so roll back first and read the
        // now-committed live row on a fresh pool connection.
        Err(e) if attome_db::is_unique_violation(&e) => {
            tx.rollback().await?;
            let live_id = match dedup_key.as_deref() {
                Some(key) => live_row_with_key(pool, &job_type, key, id).await?,
                None => None,
            };
            Ok(match live_id {
                Some(live_id) => ReplayOutcome::DedupSlotTaken { live_id },
                None => ReplayOutcome::NotDeadLettered,
            })
        }
        Err(e) => {
            tx.rollback().await?;
            Err(e)
        }
    }
}

/// The id of a live row holding `(job_type, dedup_key)`, if any — the
/// `DedupSlotTaken` payload. Read inside the caller's transaction where that
/// transaction is still usable, and on the pool after a `23505` aborted it.
async fn live_row_with_key<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    job_type: &str,
    dedup_key: &str,
    excluding_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT id FROM apalis.jobs \
         WHERE job_type = $1 AND dedup_key = $2 \
           AND status IN ('Pending', 'Running', 'Failed') AND id <> $3 \
         ORDER BY run_at ASC LIMIT 1"
    ))
    .bind(job_type)
    .bind(dedup_key)
    .bind(excluding_id)
    .fetch_optional(executor)
    .await
}

/// What `discard_dead_letter_job` deleted — enough for the caller's audit
/// event to name the row, never the payload (see `DeadLetterJobRow`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedJob {
    /// The deleted row's `apalis.jobs.id`.
    pub id: String,
    /// The queue namespace (`apalis.jobs.job_type`).
    pub queue: String,
    /// The job's variant name, when the payload carried one
    /// (`job_variant_tag`).
    pub variant: Option<String>,
}

/// BJB-6c — discards one dead-lettered row: deletes it, but only while it is
/// still `Killed`. `Ok(Some(_))` names the deleted row, `Ok(None)` if `id` does
/// not name a dead letter (already replayed, already discarded, or still
/// live) — the same race-safe status guard `replay_dead_letter_job_checked`
/// uses. Operators need this because a dead letter that will never be
/// replayed otherwise sits until the retention sweep deletes it untriaged
/// (BJB-F9).
pub async fn discard_dead_letter_job(
    pool: &attome_db::DbPool,
    id: &str,
) -> Result<Option<DiscardedJob>, sqlx::Error> {
    let deleted: Option<(String, String, serde_json::Value)> =
        sqlx::query_as(attome_db::tagged_sql!(
            "jobs.queue",
            "DELETE FROM apalis.jobs WHERE id = $1 AND status = 'Killed' \
         RETURNING id, job_type, job"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(deleted.map(|(id, queue, job)| DiscardedJob {
        variant: job_variant_tag(&job).map(str::to_string),
        id,
        queue,
    }))
}

/// T2-12 (TECHNICAL-DUE-DILIGENCE-2026-08-24 §3.11) — exponential backoff
/// delay, in whole seconds, for retrying a failed job.
///
/// apalis-sql 0.7.4's own failure path (`PostgresStorage::update`, called by
/// the worker after a handler returns `Err`) writes `status`/`attempts` but
/// never touches `run_at` — confirmed against the vendored source
/// (`apalis-sql-0.7.4/src/postgres.rs`, the `update` fn's `UPDATE apalis.jobs
/// SET status = $1, attempts = $2, ...` has no `run_at` in its `SET` list).
/// `apalis.get_jobs` (migration `0014_apalis_jobs.sql`) re-claims any row
/// with `run_at < now()`, so a `Failed` row is eligible again on the very
/// next `poll_interval` tick (100 ms before D-619, 2 s now) — a transient
/// outage burns the whole `max_attempts` budget (3–10 per kind since BJB-2,
/// BJB-D2) in a couple of seconds and dead-letters the job. apalis's own `BackoffRetryPolicy`
/// (`apalis::layers::retry`, `tower::retry`-based) isn't a fit either: it
/// retries in-process, holding the worker's concurrency slot for the whole
/// backoff instead of releasing the row back to the queue.
///
/// Base 10s, doubling, capped at 900s (15 minutes) — `attempt` 1 -> 10s,
/// 2 -> 20s, 3 -> 40s, ... 8+ -> capped. `attempt` is apalis's own
/// `Attempt::current()` (1-based: `TrackerLayer` increments it once per call
/// before the handler runs, and `PostgresStorage::update` writes that same
/// value into the `attempts` column), so this lines up with what a caller
/// reads off the row.
pub fn retry_backoff_seconds(attempt: usize) -> i64 {
    const BASE_SECS: i64 = 10;
    const MAX_SECS: i64 = 900;
    // attempt=0 (shouldn't happen — TrackerLayer always increments before a
    // handler runs) is treated the same as attempt=1, never as a negative
    // shift. `min(62)` keeps `1i64 << shift` in range regardless of how large
    // `attempt` gets (the largest declared budget is `SendEmail`/`EventsDeliverWebhook`'s
    // 8 since BJB-2, but this must never panic on a future value).
    let shift = attempt.saturating_sub(1).min(62);
    BASE_SECS.saturating_mul(1i64 << shift).min(MAX_SECS)
}

/// Applies [`retry_backoff_seconds`] to one job row by id — the actual fix
/// for T2-12, called from the worker's job-dispatch wrapper
/// after a handler returns `Err`, with the `Attempt`/`TaskId` apalis's own
/// extractors hand it.
///
/// Always runs *before* the handler's `Err` propagates back through apalis
/// and reaches `PostgresStorage::update`, so there is no ordering race to
/// worry about even though `update` never touches `run_at` anyway.
pub async fn apply_retry_backoff(
    pool: &attome_db::DbPool,
    task_id: &str,
    attempt: usize,
) -> Result<(), sqlx::Error> {
    let delay_secs = retry_backoff_seconds(attempt) as f64;
    sqlx::query(attome_db::tagged_sql!(
        "jobs.queue",
        "UPDATE apalis.jobs SET run_at = now() + make_interval(secs => $1) WHERE id = $2"
    ))
    .bind(delay_secs)
    .bind(task_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Y12-T4: how many times one queued run may be pushed back because a table
/// it changes stayed locked, and how far each time.
pub const MAX_LOCK_DEFERRALS: i32 = 12;
pub const LOCK_DEFERRAL_SECS: f64 = 300.0;

/// Y12-T4: re-enqueues the row `task_id` as a fresh copy that runs
/// [`LOCK_DEFERRAL_SECS`] from now, with the same kind, payload, priority and
/// attempt budget. The count rides in the stored envelope's `deferrals` key,
/// which decoding ignores. `Ok(false)`, writing nothing, once the row has
/// been deferred [`MAX_LOCK_DEFERRALS`] times or is gone: the caller then
/// fails the run. The caller returns success for the run that deferred, so
/// apalis marks the original row done and the copy is the only live one.
pub async fn defer_for_lock(pool: &attome_db::DbPool, task_id: &str) -> Result<bool, sqlx::Error> {
    let pushed: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "WITH src AS ( \
             SELECT job_type, job, max_attempts, priority, \
                    COALESCE((job->>'deferrals')::int, 0) AS deferrals \
             FROM apalis.jobs WHERE id = $1) \
         SELECT p.id FROM src CROSS JOIN LATERAL apalis.push_job( \
             job_type => src.job_type, \
             job => jsonb_set(src.job::jsonb, '{deferrals}', to_jsonb(src.deferrals + 1))::json, \
             run_at => now() + make_interval(secs => $2), \
             max_attempts => src.max_attempts, \
             priority => src.priority) p \
         WHERE src.deferrals < $3"
    ))
    .bind(task_id)
    .bind(LOCK_DEFERRAL_SECS)
    .bind(MAX_LOCK_DEFERRALS)
    .fetch_optional(pool)
    .await?;
    Ok(pushed.is_some())
}

/// True when a failure of the attempt now running would dead-letter the row —
/// the moment a handler with its own ledger must close it out instead of
/// leaving it for a retry that will never come (attome-email BEM-17).
///
/// `attempt` is apalis's `Attempt::current()` inside the handler: 1-based,
/// because `TrackerService` increments it before the call. apalis-sql kills
/// the row when `max_attempts <= attempt` after an `Err`
/// (`apalis-sql-0.7.4/src/lib.rs` `calculate_status`), and the extractor does
/// not carry `max_attempts`, so it is read from the row. `Ok(false)` when the
/// row is gone (a discarded or pruned job has nothing left to retry either
/// way, and the caller's retry path is the harmless one).
pub async fn is_final_attempt(
    pool: &attome_db::DbPool,
    task_id: &str,
    attempt: usize,
) -> Result<bool, sqlx::Error> {
    let max_attempts: Option<i32> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.queue",
        "SELECT max_attempts FROM apalis.jobs WHERE id = $1"
    ))
    .bind(task_id)
    .fetch_optional(pool)
    .await?;
    Ok(max_attempts.is_some_and(|max| attempt >= usize::try_from(max).unwrap_or(0)))
}

/// The variant name of a stored [`JobEnvelope`], read without decoding the
/// payload: the dead-letter list needs only the name, and some payloads carry
/// data (live tokens in an email) that must never be shown.
pub fn job_variant_tag(envelope: &serde_json::Value) -> Option<&str> {
    envelope.get("variant").and_then(serde_json::Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_variant_tag_reads_the_current_envelope_shape() {
        let envelope = serde_json::json!({
            "version": 1,
            "variant": "BulkEdit",
            "payload": {"op": 1},
            "trace_context": null
        });
        assert_eq!(job_variant_tag(&envelope), Some("BulkEdit"));
    }

    #[test]
    fn job_variant_tag_reads_a_unit_variant_under_the_current_envelope_shape() {
        let envelope = serde_json::json!({
            "version": 1,
            "variant": "Sweep",
            "payload": "Sweep",
            "trace_context": null
        });
        assert_eq!(job_variant_tag(&envelope), Some("Sweep"));
    }

    #[test]
    fn job_variant_tag_returns_none_without_a_variant() {
        assert_eq!(job_variant_tag(&serde_json::json!({"version": 1})), None);
    }

    #[test]
    fn retry_backoff_seconds_doubles_from_a_ten_second_base() {
        assert_eq!(retry_backoff_seconds(1), 10);
        assert_eq!(retry_backoff_seconds(2), 20);
        assert_eq!(retry_backoff_seconds(3), 40);
        assert_eq!(retry_backoff_seconds(4), 80);
    }

    #[test]
    fn retry_backoff_seconds_caps_at_fifteen_minutes() {
        assert_eq!(retry_backoff_seconds(7), 640);
        assert_eq!(retry_backoff_seconds(8), 900); // 1280 uncapped -> capped
        assert_eq!(retry_backoff_seconds(25), 900); // max_attempts today
        assert_eq!(retry_backoff_seconds(1_000_000), 900); // never overflows/panics
    }

    #[test]
    fn retry_backoff_seconds_treats_attempt_zero_like_attempt_one() {
        // TrackerLayer always increments before a handler runs, so a caller
        // should never actually see attempt=0 — but this must not panic
        // (saturating_sub) or produce a smaller delay than attempt=1.
        assert_eq!(retry_backoff_seconds(0), retry_backoff_seconds(1));
    }

    /// The T2-12 checklist's own verify line: "SMTP down for 60s consumes
    /// <=3 attempts, not 25." With this curve, attempt k actually happens at
    /// wall-clock time T_k = sum of backoff(1..k-1) (T_1 = 0, since the first
    /// attempt isn't delayed by anything). An outage lasting `window_secs`
    /// consumes exactly the attempts whose T_k falls inside the window.
    #[test]
    fn a_sixty_second_outage_consumes_at_most_three_attempts() {
        let window_secs: i64 = 60;
        let mut elapsed: i64 = 0;
        let mut attempts_within_window = 0;
        for attempt in 1..=25 {
            if elapsed >= window_secs {
                break;
            }
            attempts_within_window += 1;
            elapsed += retry_backoff_seconds(attempt);
        }
        assert_eq!(
            attempts_within_window, 3,
            "a 60s outage must consume exactly 3 of the 25-attempt budget, not all 25"
        );
    }
}

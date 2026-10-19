# Background jobs

Work that must survive a restart goes through the job queue in `attome-jobs`, never through a bare
`tokio::spawn`. A job is a row in PostgreSQL written in the producer's own transaction, so a crash after
the commit never loses it, and a rollback never leaves an orphaned job behind. Jobs retry within their
attempt budget and then land in the dead letters, where an administrator can see and retry them.

There are three shapes: a registered job type (one piece of work), a schedule (a job that runs
periodically), and a batch job (long work in chunks with progress and cancel).

## Registering a job type

An engine adds a job without touching the application's job enum. Declare the type, register a handler
at start-up, and enqueue jobs of that type by name.

```rust
use attome_jobs::{JobType, RegisteredJob, registry::BoxError};

// 1. The type: a fixed name (also a metric label) and the payload version the handler reads.
pub const REINDEX: JobType = JobType::new("search_reindex", 1);

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReindexPayload {
    pub entity: String,
}

// 2. The handler, registered once at start-up (crates/apps/attome/src/jobs.rs holds the others).
attome_core::jobs::JOB_TYPES.register(REINDEX, |state: EngineState, job: RegisteredJob| async move {
    let payload: ReindexPayload = job.payload()?;
    reindex(&state, &payload.entity).await.map_err(|e| Box::new(e) as BoxError)?;
    Ok::<(), BoxError>(())
})?;

// 3. Enqueue, in the transaction that makes the change the job follows from.
let job = attome_core::jobs::JOB_TYPES.job(REINDEX.name, &ReindexPayload { entity })?;
attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job)).await?;
attome_db::tx::commit(tx).await?;
```

`JobType::new` gives a fast-lane, normal-priority type with five attempts and no concurrency cap. Set
the fields to change that:

- `lane: Lane::Batch` for open-ended work whose cost grows with the number of records. It runs on its
  own worker, so a flood of bulk work never delays short jobs.
- `priority`, `max_attempts`, and `max_concurrency` (a cap per node).

`JOB_TYPES.job` refuses a name that is not registered, so a typo fails at the producer and not in the
dead letters. A job whose name no handler on a worker knows fails the attempt and retries, since a
newer node may know it. It is never dropped.

**Versions.** Raise `version` when the payload's shape changes. A job written with a higher version than
the worker's handler reads fails with `newer_job_version` until that node is upgraded. A job with a
lower version reaches the handler, which must read the old shape too.

**Retries.** A handler can run more than once for one job: after a crash, a timeout, or a retry. Make it
safe to repeat. Check whether the work is already done, write with `ON CONFLICT`, or key each write by
the job.

**Running as a person.** A job that acts for the person who asked carries their user id in its payload
and checks their permissions again when it runs, because they may have changed since the job was
queued.

## Schedules

A periodic job runs once per slot across every server and restart. Each schedule has one row in the
`job_schedule` ledger, and a tick claims the slot with a compare-and-swap before it enqueues, so exactly
one server wins each slot.

```rust
// A fixed interval: claims the slot, then enqueues `job`, at most once per interval.
attome_jobs::schedule::tick(&db, "search_reindex_nightly", Duration::from_secs(86_400), job).await?;

// A cron expression, a Hijri day of the month, a one-off instant or every working day of a
// business calendar, on a time zone's wall clock.
let nightly = attome_jobs::schedule::Schedule::cron("0 2 * * *", "Asia/Riyadh")?;
attome_jobs::schedule::tick_at(&db, "search_reindex_nightly", &nightly, job).await?;
```

The name is both the ledger row and the overlap guard: while a slot's job is still running, the next
slot cannot enqueue a second one. A tick that fails is logged, and the next tick claims the next slot.
Clock changes are handled on the wall clock: a time the clocks skip runs one hour later, and a time
they repeat runs once.

In tests, `attome_testkit::jobs` runs a job at once in process (`run_now`) and moves schedule time
forward (`advance`), so a schedule's behaviour is tested without waiting.

## Batch jobs

Long work, such as a re-index, a backfill or an import, runs in chunks. The job reads a checkpoint,
does one chunk in a transaction, and commits the chunk's writes together with the new checkpoint and
its progress. A worker that dies mid-job loses at most the chunk it was in, and the retry starts from
the last committed checkpoint.

```rust
use attome_jobs::batch::{self, BatchJob};
use attome_jobs::registry::BoxError;
use serde_json::{Value, json};

struct Reindex {
    entity: String,
}

impl BatchJob for Reindex {
    type Chunk = Vec<Uuid>;

    // The next chunk after `checkpoint` (None: from the start) and the checkpoint once it is done.
    async fn next_chunk(&self, checkpoint: Option<&Value>) -> Result<Option<(Self::Chunk, Value)>, BoxError> {
        let after = checkpoint.and_then(|c| c["after"].as_str()).map(str::to_owned);
        let ids = next_ids(&self.entity, after.as_deref(), 1_000).await?;
        Ok(ids.last().map(|last| (ids.clone(), json!({ "after": last }))))
    }

    // One chunk's writes, in the transaction the runner commits with the checkpoint.
    async fn process(&self, tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, ids: Self::Chunk) -> Result<i64, BoxError> {
        reindex_rows(tx, &self.entity, &ids).await?;
        Ok(ids.len() as i64)
    }
}

// Start: create the batch row and enqueue the job that runs it, in one transaction.
let id = batch::start(&mut tx, "search_reindex", Some(total), Some(user_id)).await?;
// ... enqueue a registered job carrying `id` ...

// The job's handler runs the batch from its last checkpoint.
batch::run(&pool, id, &Reindex { entity }).await?;
```

Between chunks the runner reads whether someone asked to cancel, and stops cleanly. Progress, cancel
and the list of a person's own batches are on the API: `GET /api/v1/jobs/{id}`,
`POST /api/v1/jobs/{id}/cancel` and `GET /api/v1/jobs`. People see the work they started under
**My background work**.

Keep chunks bounded (a thousand rows is typical) and read them by keyset, never by offset. Never call
external services inside `process`: the transaction must stay short, so do outside calls before or
after the chunk.

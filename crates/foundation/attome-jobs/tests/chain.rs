//! Z7-T5: a chain runs its jobs in order, a fan-out runs its final job once
//! after every member, and a continuation repeated (a retried job) enqueues
//! its follow-up only once.
//!
//! Runs against attome-testkit's migrated throwaway database: set
//! `DATABASE_URL`; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test chain -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Mutex;
use std::time::Duration;

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::chain::{after_success, fan_out};
use attome_jobs::{Job, JobEnvelope, JobPriority, JobRegistry, JobType, RegisteredJob};
use attome_testkit::skip_if_no_db;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// What the handler ran, in order.
static RAN: Mutex<Vec<String>> = Mutex::new(Vec::new());

static TYPES: JobRegistry<()> = JobRegistry::new();

/// The pool the worker's continuations use: the current test's database
/// (each test gets its own).
static POOL: Mutex<Option<PgPool>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AppJob {
    Registered(RegisteredJob),
}

impl Job for AppJob {
    fn kind(&self) -> &'static str {
        "Registered"
    }

    fn is_batch(&self) -> bool {
        false
    }

    fn priority(&self) -> JobPriority {
        JobPriority::Normal
    }

    fn max_attempts(&self) -> i32 {
        2
    }
}

fn register_once() {
    let _ = TYPES.register(JobType::new("record", 1), |(), job| async move {
        let label: String = job.payload()?;
        RAN.lock().unwrap().push(label);
        Ok(())
    });
}

fn record(label: &str) -> RegisteredJob {
    TYPES.job("record", &label).expect("registered")
}

/// The worker's dispatch: the registered handler, then what follows it.
async fn handle(job: JobEnvelope<AppJob>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match job {
        JobEnvelope::Known {
            job: AppJob::Registered(job),
            ..
        } => {
            let next = job.next.clone();
            TYPES.run((), job).await?;
            let pool = POOL.lock().unwrap().clone().expect("pool set");
            after_success(&pool, next.as_ref(), AppJob::Registered).await
        }
        JobEnvelope::Unrecognized { variant, version } => {
            Err(format!("unrecognized envelope: variant='{variant}' version={version}").into())
        }
    }
}

async fn test_pool() -> Option<PgPool> {
    let pool = attome_testkit::migrated_pool(5).await?;
    *POOL.lock().unwrap() = Some(pool.clone());
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");
    register_once();
    Some(pool)
}

/// The labels with `prefix` the handler ran, in order.
fn ran(prefix: &str) -> Vec<String> {
    RAN.lock()
        .unwrap()
        .iter()
        .filter(|label| label.starts_with(prefix))
        .cloned()
        .collect()
}

/// Runs a one-slot worker until `done` says so or 20 s pass.
async fn run_worker_until(pool: &PgPool, name: &str, done: impl Fn() -> bool) {
    let storage = attome_jobs::Jobs::<AppJob>::new(pool.clone())
        .fast()
        .clone();
    let monitor = Monitor::new().register(
        WorkerBuilder::new(name)
            .concurrency(1)
            .backend(storage)
            .build_fn(handle),
    );
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let worker_task = tokio::spawn(async move {
        monitor
            .run_with_signal(async move {
                let _ = shutdown_rx.wait_for(|shutting_down| *shutting_down).await;
                Ok(())
            })
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !done() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Room for a stray extra run to show up before the counts are read.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = shutdown_tx.send(true);
    let _ = worker_task.await;
}

#[tokio::test]
async fn a_chain_runs_its_jobs_in_order() {
    let pool = skip_if_no_db!(test_pool().await);
    let p = format!("chain-{}-", uuid::Uuid::now_v7().simple());
    let chain =
        record(&format!("{p}a")).then(record(&format!("{p}b")).then(record(&format!("{p}c"))));
    attome_jobs::enqueue_on_pool(&pool, AppJob::Registered(chain))
        .await
        .expect("enqueue");
    run_worker_until(&pool, "chain-worker", || ran(&p).len() >= 3).await;
    assert_eq!(ran(&p), [format!("{p}a"), format!("{p}b"), format!("{p}c")]);
}

#[tokio::test]
async fn a_fan_out_runs_its_final_job_once_after_every_member() {
    let pool = skip_if_no_db!(test_pool().await);
    let p = format!("fan-{}-", uuid::Uuid::now_v7().simple());
    let members = (1..=3).map(|n| record(&format!("{p}m{n}"))).collect();
    let mut tx = attome_db::tx::begin(&pool).await.expect("begin");
    fan_out(
        &mut tx,
        AppJob::Registered,
        members,
        record(&format!("{p}final")),
    )
    .await
    .expect("fan out");
    attome_db::tx::commit(tx).await.expect("commit");
    run_worker_until(&pool, "fan-out-worker", || {
        ran(&p).iter().any(|label| label.ends_with("final"))
    })
    .await;
    let order = ran(&p);
    assert_eq!(order.len(), 4, "{order:?}");
    assert_eq!(
        order[3],
        format!("{p}final"),
        "the final job runs last: {order:?}"
    );
    let finals = order
        .iter()
        .filter(|label| label.ends_with("final"))
        .count();
    assert_eq!(finals, 1, "{order:?}");
}

#[tokio::test]
async fn a_repeated_continuation_enqueues_its_follow_up_once() {
    let pool = skip_if_no_db!(test_pool().await);
    let p = format!("once-{}-", uuid::Uuid::now_v7().simple());
    let job = record(&format!("{p}first")).then(record(&format!("{p}second")));
    let next = job.next.clone();
    after_success(&pool, next.as_ref(), AppJob::Registered)
        .await
        .expect("first");
    after_success(&pool, next.as_ref(), AppJob::Registered)
        .await
        .expect("again, as a retried job would");
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'",
    )
    .bind(format!("{p}second"))
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(queued, 1);
}

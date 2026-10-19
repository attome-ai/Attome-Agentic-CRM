//! Z7-T1: a job type registered at run time runs on a real worker without a
//! new enum variant, and a job naming a type the worker does not have ends in
//! the dead letters with `unknown_job_type`, never dropped.
//!
//! The application's job enum here has one variant, the one that carries a
//! [`RegisteredJob`]; its lane and budget come from the registry, as
//! `attome_core::jobs::EngineJob::Registered` does.
//!
//! Runs against attome-testkit's migrated throwaway database: set
//! `DATABASE_URL`; without it each test prints SKIP.
//!
//! Run: `cargo test -p attome-jobs --test registry -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::{Job, JobEnvelope, JobPriority, JobRegistry, JobType, Lane, RegisteredJob};
use attome_testkit::skip_if_no_db;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// How many greetings the registered handler has run.
static GREETED: AtomicUsize = AtomicUsize::new(0);

/// The registry the producer and the worker share in this process.
static TYPES: JobRegistry<()> = JobRegistry::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AppJob {
    Registered(RegisteredJob),
}

impl Job for AppJob {
    fn kind(&self) -> &'static str {
        "Registered"
    }

    fn is_batch(&self) -> bool {
        let Self::Registered(job) = self;
        TYPES
            .job_type(&job.name)
            .is_some_and(|job_type| job_type.lane == Lane::Batch)
    }

    fn priority(&self) -> JobPriority {
        let Self::Registered(job) = self;
        TYPES
            .job_type(&job.name)
            .map_or(JobPriority::Normal, |job_type| job_type.priority)
    }

    fn max_attempts(&self) -> i32 {
        let Self::Registered(job) = self;
        TYPES
            .job_type(&job.name)
            .map_or(2, |job_type| job_type.max_attempts)
    }
}

#[derive(Serialize, Deserialize)]
struct Greeting {
    to: String,
}

fn register_once() {
    // Each test may run first; a second registration is refused, and that
    // is fine here.
    let _ = TYPES.register(
        JobType {
            max_attempts: 2,
            ..JobType::new("greet", 1)
        },
        |(), job| async move {
            let greeting: Greeting = job.payload()?;
            if greeting.to.is_empty() {
                return Err("nobody to greet".into());
            }
            GREETED.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
}

async fn handle(job: JobEnvelope<AppJob>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match job {
        JobEnvelope::Known {
            job: AppJob::Registered(job),
            ..
        } => Ok(TYPES.run((), job).await?),
        JobEnvelope::Unrecognized { variant, version } => {
            Err(format!("unrecognized envelope: variant='{variant}' version={version}").into())
        }
    }
}

async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// Runs a one-slot worker on the fast queue until `done` says so or 20 s
/// pass.
async fn run_worker_until<F, Fut>(pool: &PgPool, name: &str, mut done: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
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
    while tokio::time::Instant::now() < deadline && !done().await {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(true);
    let _ = worker_task.await;
}

async fn job_row(pool: &PgPool) -> (String, i32, i32, Option<String>) {
    sqlx::query_as(
        "SELECT status, attempts, max_attempts, last_error FROM apalis.jobs \
         ORDER BY run_at DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("read the job row")
}

#[tokio::test]
async fn a_registered_type_is_enqueued_and_run_without_a_new_variant() {
    let pool = skip_if_no_db!(test_pool().await);
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");
    register_once();
    let before = GREETED.load(Ordering::SeqCst);

    let job = TYPES
        .job(
            "greet",
            &Greeting {
                to: "world".to_owned(),
            },
        )
        .expect("a registered name builds a job");
    attome_jobs::enqueue_on_pool(&pool, AppJob::Registered(job))
        .await
        .expect("enqueue");
    let (_, _, max_attempts, _) = job_row(&pool).await;
    assert_eq!(max_attempts, 2, "the registered type's budget is stored");

    run_worker_until(&pool, "registry-run-worker", || async {
        GREETED.load(Ordering::SeqCst) > before
    })
    .await;
    assert_eq!(
        GREETED.load(Ordering::SeqCst),
        before + 1,
        "the handler ran once"
    );
    let (status, _, _, _) = job_row(&pool).await;
    assert_eq!(status, "Done");
}

#[tokio::test]
async fn an_unknown_job_type_is_dead_lettered_not_dropped() {
    let pool = skip_if_no_db!(test_pool().await);
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");
    register_once();

    // Written by a node that knows a type this worker does not.
    let job = RegisteredJob {
        name: "from_a_newer_node".to_owned(),
        version: 1,
        payload: serde_json::json!({}),
        next: None,
    };
    attome_jobs::enqueue_on_pool(&pool, AppJob::Registered(job))
        .await
        .expect("enqueue");

    let pool_for_check = pool.clone();
    run_worker_until(&pool, "registry-unknown-worker", move || {
        let pool = pool_for_check.clone();
        async move { job_row(&pool).await.0 == "Killed" }
    })
    .await;
    let (status, attempts, _, last_error) = job_row(&pool).await;
    assert_eq!(status, "Killed", "the row ends in the dead letters");
    assert_eq!(attempts, 2, "after its budget");
    let last_error = last_error.expect("a failed attempt records its error");
    assert!(
        last_error.contains("unknown_job_type") && last_error.contains("from_a_newer_node"),
        "{last_error}"
    );
}

//! D-619 ruling 5 — the `LISTEN` wake-up's acceptance bar: a fast-queue job is
//! picked up within 1 s (p95) even though the idle poll is now 2 s. Without the
//! wake-up every pickup waits for the next poll tick (up to 2 s, about 1 s on
//! average), so a p95 under 1 s over 20 sequential jobs can only come from the
//! notification path.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`, every migration in
//! `crates/apps/attome/migrations` applied): set `DATABASE_URL` to a
//! PostgreSQL server; without it each test prints SKIP.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_jobs::{JobEnvelope, Jobs};
use attome_testkit::skip_if_no_db;
use common::TestJob;

static PICKED_UP: Mutex<Vec<Instant>> = Mutex::new(Vec::new());

async fn handle(
    _job: JobEnvelope<TestJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    PICKED_UP.lock().expect("pickup log").push(Instant::now());
    Ok(())
}

fn noop_connect() {}

#[tokio::test]
async fn a_fast_queue_job_is_picked_up_within_one_second_p95() {
    let pool = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(&pool)
        .await
        .expect("truncate apalis.jobs");

    let mut jobs = Jobs::<TestJob>::new(pool.clone());
    let listen = attome_jobs::attach_wakeup_listener(
        (*pool.connect_options()).clone(),
        &mut jobs,
        noop_connect,
    )
    .await
    .expect("the wake-up listener connects");
    tokio::spawn(listen);

    let monitor = Monitor::new().register(
        WorkerBuilder::new("wakeup-latency-test-worker")
            .concurrency(1)
            .backend(jobs.fast().clone())
            .build_fn(handle),
    );
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(async move {
        monitor
            .run_with_signal(async move {
                let _ = shutdown_rx.wait_for(|stop| *stop).await;
                Ok(())
            })
            .await
    });
    // Let the worker register and its first poll pass, so round one measures
    // a steady state rather than startup.
    tokio::time::sleep(attome_jobs::SAFETY_POLL_INTERVAL + Duration::from_millis(500)).await;

    let mut latencies = Vec::new();
    for round in 0..20 {
        let before = PICKED_UP.lock().expect("pickup log").len();
        let enqueued = Instant::now();
        attome_jobs::enqueue(&mut jobs, TestJob::Sweep)
            .await
            .expect("enqueue");
        let deadline = enqueued + Duration::from_secs(5);
        let picked = loop {
            if let Some(at) = PICKED_UP.lock().expect("pickup log").get(before).copied() {
                break at;
            }
            assert!(
                Instant::now() < deadline,
                "round {round}: no pickup within 5 s"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        latencies.push(picked.saturating_duration_since(enqueued));
        // De-phase from the poll timer so rounds don't all land at one offset.
        tokio::time::sleep(Duration::from_millis(137)).await;
    }

    let _ = shutdown_tx.send(true);
    let _ = worker.await;

    latencies.sort();
    let pct = |p: usize| latencies[(latencies.len() * p / 100).min(latencies.len() - 1)];
    let (p50, p95, max) = (pct(50), pct(95), latencies[latencies.len() - 1]);
    println!("D-619 fast-queue pickup over 20 jobs: p50 {p50:?}, p95 {p95:?}, max {max:?}");
    assert!(
        p95 <= Duration::from_secs(1),
        "fast-queue pickup p95 {p95:?} exceeds the 1 s budget (p50 {p50:?}, max {max:?})"
    );
}

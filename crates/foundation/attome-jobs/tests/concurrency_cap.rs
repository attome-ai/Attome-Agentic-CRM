//! Z7-T3: a kind with `max_concurrency = 1` never has two jobs running at
//! once, even when two workers claim at the same instant; other kinds in the
//! same queue are not held back.
//!
//! Claims through `apalis.get_jobs` (migration 0191) directly, as apalis's
//! pollers do. Runs against attome-testkit's migrated throwaway database:
//! set `DATABASE_URL`; without it the test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-jobs --test concurrency_cap -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use uuid::Uuid;

async fn push(pool: &PgPool, queue: &str, kind: &str) -> String {
    let envelope = serde_json::json!({
        "version": 1,
        "variant": kind,
        "payload": null,
        "trace_context": null,
    });
    sqlx::query_scalar("SELECT id FROM apalis.push_job(job_type => $1, job => $2::json)")
        .bind(queue)
        .bind(envelope)
        .fetch_one(pool)
        .await
        .expect("push a job")
}

/// The kinds `get_jobs` hands worker `name` from `queue` (the worker is
/// registered first: `lock_by` references `apalis.workers`).
async fn claim(pool: &PgPool, name: &str, queue: &str) -> Vec<(String, String)> {
    let worker = format!("{queue}-{name}");
    sqlx::query(
        "INSERT INTO apalis.workers (id, worker_type, storage_name) VALUES ($1, $2, 'test') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&worker)
    .bind(queue)
    .execute(pool)
    .await
    .expect("register the worker");
    sqlx::query_as("SELECT id, job ->> 'variant' FROM apalis.get_jobs($1, $2, 5)")
        .bind(&worker)
        .bind(queue)
        .fetch_all(pool)
        .await
        .expect("claim jobs")
}

async fn finish(pool: &PgPool, id: &str) {
    sqlx::query("UPDATE apalis.jobs SET status = 'Done', done_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("finish a job");
}

#[tokio::test]
async fn concurrency_cap_of_one_runs_one_job_of_the_kind_at_a_time() {
    let pool = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    let tag = Uuid::now_v7().simple().to_string();
    let queue = format!("cap_test_{tag}");
    let capped = format!("CapTest{tag}");
    let free = format!("Uncapped{tag}");
    attome_jobs::install_concurrency_caps(&pool, &[(capped.as_str(), 1)])
        .await
        .expect("install the cap");

    push(&pool, &queue, &capped).await;
    push(&pool, &queue, &capped).await;
    push(&pool, &queue, &free).await;
    // Both pushes are visible to `run_at < now()` once now() moves on.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // One of the capped kind, and the uncapped job beside it.
    let first = claim(&pool, "w1", &queue).await;
    let capped_ids: Vec<&String> = first
        .iter()
        .filter(|(_, k)| *k == capped)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(capped_ids.len(), 1, "{first:?}");
    assert!(first.iter().any(|(_, k)| *k == free), "{first:?}");

    // While it runs, nothing more of that kind is handed out.
    assert!(claim(&pool, "w2", &queue).await.is_empty());

    // Once it is done, the second one runs.
    finish(&pool, capped_ids[0]).await;
    let second = claim(&pool, "w3", &queue).await;
    assert_eq!(second.len(), 1, "{second:?}");
    assert_eq!(second[0].1, capped);
    finish(&pool, &second[0].0).await;

    // Two workers claiming at the same instant get one job between them.
    push(&pool, &queue, &capped).await;
    push(&pool, &queue, &capped).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let (a, b) = tokio::join!(claim(&pool, "w4", &queue), claim(&pool, "w5", &queue));
    assert_eq!(a.len() + b.len(), 1, "{a:?} {b:?}");

    // Uninstalling the cap frees the rest of the backlog.
    attome_jobs::install_concurrency_caps(&pool, &[])
        .await
        .expect("remove the cap");
    assert_eq!(claim(&pool, "w6", &queue).await.len(), 1);
    sqlx::query("DELETE FROM apalis.jobs WHERE job_type = $1")
        .bind(&queue)
        .execute(&pool)
        .await
        .expect("clean up the jobs");
    sqlx::query("DELETE FROM apalis.workers WHERE worker_type = $1")
        .bind(&queue)
        .execute(&pool)
        .await
        .expect("clean up the workers");
}

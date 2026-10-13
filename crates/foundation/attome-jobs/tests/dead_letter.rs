//! BJB-6a / BJB-6c (attome-jobs plan, Phase 1) — the dead-letter surface this
//! crate owns: list ordering and paging, replay outcomes, and discard.
//!
//! The plan put the replay-collision case in `xrm-server/tests/jobs_admin.rs`
//! (BJB-P0.3) because that is where the HTTP 409 is produced; that handler is
//! outside attome-jobs' write surface, so the *mechanism* it depends on —
//! `ReplayOutcome::DedupSlotTaken { live_id }` instead of a raw `23505` — is
//! pinned here, in-crate, which is what BJB-6a's own acceptance asks for.
//!
//! Run: `cargo test -p attome-jobs --test dead_letter -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_jobs::ReplayOutcome;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
/// Eight connections for the concurrent-replay case.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(8).await
}

async fn reset(pool: &PgPool) {
    sqlx::query("TRUNCATE apalis.jobs")
        .execute(pool)
        .await
        .expect("truncate apalis.jobs");
}

/// One row in `status`, with a unique id. `done_ago_secs` 0 means "done now".
async fn insert_row(
    pool: &PgPool,
    status: &str,
    dedup_key: Option<&str>,
    done_ago_secs: i64,
) -> String {
    let id = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO apalis.jobs \
             (job, id, job_type, status, attempts, max_attempts, run_at, dedup_key, done_at) \
         VALUES ('{}', $1, 'attome_job', $2, 0, 5, now(), $3, \
                 CASE WHEN $4 = 0 THEN now() ELSE now() - make_interval(secs => $4) END)",
    )
    .bind(&id)
    .bind(status)
    .bind(dedup_key)
    .bind(done_ago_secs)
    .execute(pool)
    .await
    .expect("insert apalis.jobs row");
    id
}

async fn status_of(pool: &PgPool, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT status FROM apalis.jobs WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("read row status")
}

#[tokio::test]
async fn list_orders_dead_letters_newest_first_and_pages() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let older = insert_row(&pool, "Killed", None, 120).await;
    let oldest = insert_row(&pool, "Killed", None, 240).await;
    let newest = insert_row(&pool, "Killed", None, 0).await;
    let live = insert_row(&pool, "Pending", None, 0).await;

    let first_page = attome_jobs::list_dead_letter_jobs(&pool, false, 0, 2)
        .await
        .expect("first window");
    let ids: Vec<&str> = first_page.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![newest.as_str(), older.as_str()],
        "dead letters come back most-recently-dead-lettered first"
    );

    let second_page = attome_jobs::list_dead_letter_jobs(&pool, false, 2, 2)
        .await
        .expect("second window");
    let ids: Vec<&str> = second_page.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(ids, vec![oldest.as_str()], "paging continues, not restarts");

    assert!(
        !ids.contains(&live.as_str()) && !first_page.iter().any(|row| row.id == live),
        "a live row must never appear in the dead-letter list"
    );
}

#[tokio::test]
async fn replay_moves_a_dead_letter_back_to_pending() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let id = insert_row(&pool, "Killed", None, 0).await;
    assert_eq!(
        attome_jobs::replay_dead_letter_job_checked(&pool, &id)
            .await
            .expect("replay"),
        ReplayOutcome::Replayed
    );

    let row: (
        String,
        i32,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT status, attempts, last_error, done_at FROM apalis.jobs WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .expect("read replayed row");
    assert_eq!(row.0, "Pending");
    assert_eq!(row.1, 0, "a replay restarts the attempt budget");
    assert!(row.2.is_none(), "a replay clears the last error");
    assert!(row.3.is_none(), "a replayed row is no longer 'done'");
}

#[tokio::test]
async fn replay_of_a_row_that_is_not_a_dead_letter_is_a_no_op() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let pending = insert_row(&pool, "Pending", None, 0).await;
    let failed = insert_row(&pool, "Failed", None, 0).await;

    assert_eq!(
        attome_jobs::replay_dead_letter_job_checked(&pool, &pending)
            .await
            .expect("replay pending"),
        ReplayOutcome::NotDeadLettered
    );
    assert_eq!(
        attome_jobs::replay_dead_letter_job_checked(&pool, &failed)
            .await
            .expect("replay failed"),
        ReplayOutcome::NotDeadLettered
    );
    assert_eq!(
        attome_jobs::replay_dead_letter_job_checked(&pool, "does-not-exist")
            .await
            .expect("replay missing"),
        ReplayOutcome::NotDeadLettered
    );
    assert_eq!(status_of(&pool, &pending).await.as_deref(), Some("Pending"));
    assert_eq!(status_of(&pool, &failed).await.as_deref(), Some("Failed"));
}

#[tokio::test]
async fn replay_onto_a_live_dedup_key_names_the_live_row_instead_of_erroring() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let key = format!("dead-letter-test/{}", Uuid::now_v7());
    let killed = insert_row(&pool, "Killed", Some(&key), 0).await;
    let live = insert_row(&pool, "Pending", Some(&key), 0).await;

    let outcome = attome_jobs::replay_dead_letter_job_checked(&pool, &killed)
        .await
        .expect("a live same-key row must be a named refusal, never a 23505 error");
    assert_eq!(
        outcome,
        ReplayOutcome::DedupSlotTaken {
            live_id: live.clone()
        },
        "the refusal must name the row that already holds the slot"
    );
    assert_eq!(
        status_of(&pool, &killed).await.as_deref(),
        Some("Killed"),
        "a refused replay must leave the dead letter exactly as it was"
    );
}

#[tokio::test]
async fn discard_removes_only_a_dead_letter() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let killed = insert_row(&pool, "Killed", None, 0).await;
    sqlx::query(
        "UPDATE apalis.jobs SET job = '{\"version\":2,\"variant\":\"SendEmail\",\"payload\":{}}' WHERE id = $1",
    )
    .bind(&killed)
    .execute(&pool)
    .await
    .expect("give the dead letter a variant");
    let discarded = attome_jobs::discard_dead_letter_job(&pool, &killed)
        .await
        .expect("discard a dead letter")
        .expect("discarding a Killed row deletes it");
    assert_eq!(
        discarded,
        attome_jobs::DiscardedJob {
            id: killed.clone(),
            queue: "attome_job".to_string(),
            variant: Some("SendEmail".to_string()),
        },
        "the discard names what it deleted, for the audit event"
    );
    assert!(status_of(&pool, &killed).await.is_none());

    let live = insert_row(&pool, "Pending", None, 0).await;
    assert!(
        attome_jobs::discard_dead_letter_job(&pool, &live)
            .await
            .expect("discard a live row")
            .is_none(),
        "a live row is not a dead letter and must not be discarded"
    );
    assert_eq!(status_of(&pool, &live).await.as_deref(), Some("Pending"));
    assert!(
        attome_jobs::discard_dead_letter_job(&pool, "does-not-exist")
            .await
            .expect("discard missing")
            .is_none(),
    );
}

/// BJB-F7's actual race: a producer's same-key row is still uncommitted when
/// the replay checks, so both the pre-check and the UPDATE's `NOT EXISTS` miss
/// it, and the partial unique index raises `23505` once it commits. Before the
/// fix the backstop arm queried the already-aborted transaction (`25P02`) and
/// the operator got a masked 500.
#[tokio::test]
async fn replay_racing_an_uncommitted_same_key_row_names_it_instead_of_erroring() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let key = format!("dead-letter-test/{}", Uuid::now_v7());
    let killed = insert_row(&pool, "Killed", Some(&key), 0).await;

    let mut producer = pool.acquire().await.expect("producer connection");
    sqlx::query("BEGIN")
        .execute(&mut *producer)
        .await
        .expect("begin producer");
    let live = Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO apalis.jobs \
             (job, id, job_type, status, attempts, max_attempts, run_at, dedup_key) \
         VALUES ('{}', $1, 'attome_job', 'Pending', 0, 5, now(), $2)",
    )
    .bind(&live)
    .bind(&key)
    .execute(&mut *producer)
    .await
    .expect("producer inserts the live same-key row");

    let replay = {
        let pool = pool.clone();
        let killed = killed.clone();
        tokio::spawn(
            async move { attome_jobs::replay_dead_letter_job_checked(&pool, &killed).await },
        )
    };

    // The replay's UPDATE blocks in the unique check on the producer's
    // uncommitted index entry; commit only once it is waiting there.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE 'UPDATE apalis.jobs SET status = ''Pending''%'",
        )
        .fetch_one(&pool)
        .await
        .expect("read pg_stat_activity");
        if waiting > 0 {
            break;
        }
        assert!(
            !replay.is_finished(),
            "the replay finished without blocking on the producer's uncommitted row: {:?}",
            replay.await
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the replay never blocked on the producer's uncommitted row"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    sqlx::query("COMMIT")
        .execute(&mut *producer)
        .await
        .expect("commit producer");

    let outcome = replay
        .await
        .expect("replay task")
        .expect("a 23505 from the unique index must be a named refusal, not an error");
    assert_eq!(outcome, ReplayOutcome::DedupSlotTaken { live_id: live });
    assert_eq!(
        status_of(&pool, &killed).await.as_deref(),
        Some("Killed"),
        "a refused replay must leave the dead letter exactly as it was"
    );
}

#[tokio::test]
async fn concurrent_replays_of_one_row_resolve_to_exactly_one() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    let id = insert_row(&pool, "Killed", None, 0).await;

    let mut replays = Vec::new();
    for _ in 0..4 {
        let pool = pool.clone();
        let id = id.clone();
        replays.push(tokio::spawn(async move {
            attome_jobs::replay_dead_letter_job_checked(&pool, &id).await
        }));
    }

    let mut replayed = 0;
    for replay in replays {
        if replay.await.expect("replay task").expect("replay") == ReplayOutcome::Replayed {
            replayed += 1;
        }
    }
    assert_eq!(
        replayed, 1,
        "the FOR UPDATE guard admits exactly one replay"
    );
    assert_eq!(status_of(&pool, &id).await.as_deref(), Some("Pending"));

    // …and the wrapper still reports it as a replayed row for the list.
    let listed = attome_jobs::list_dead_letter_jobs(&pool, false, 0, 10)
        .await
        .expect("list");
    assert!(
        listed.is_empty(),
        "the replayed row left the dead-letter list"
    );
}

#[tokio::test]
async fn a_row_without_a_dedup_key_replays_even_while_other_rows_are_live() {
    let pool = skip_if_no_db!(test_pool().await);
    reset(&pool).await;

    // A dedup-less kind (every pre-0060 row, and every enqueue() push whose
    // context carried no dedup key) has no slot to collide with.
    let killed = insert_row(&pool, "Killed", None, 0).await;
    let _live = insert_row(&pool, "Pending", None, 0).await;

    assert_eq!(
        attome_jobs::replay_dead_letter_job_checked(&pool, &killed)
            .await
            .expect("replay a dedup-less dead letter"),
        ReplayOutcome::Replayed
    );
}

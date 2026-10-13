//! M37 Knowledge Management Phase 2 (D-452) — article analytics, helpfulness
//! votes, and `review_by` reminders, against a real database. Same shape as
//! `tests/scheduling.rs`: call the engine function directly rather than
//! standing up a full authenticated HTTP request.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-content --test analytics -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::NotificationSection;
use attome_content::analytics::{
    page_stats, record_helpfulness_vote, record_page_view, rollup_page_stats,
    sweep_review_reminders,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::{NaiveDate, Utc};
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn notification_cfg() -> NotificationSection {
    NotificationSection::default()
}

async fn insert_active_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, is_active) VALUES ($1, $2, TRUE)")
        .bind(id)
        .bind(format!("{id}@test.invalid"))
        .execute(db)
        .await
        .expect("insert test user");
    id
}

async fn insert_space(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_space (id, name, created_by, updated_by, owner_layer) VALUES ($1, $2, $3, $3, 'project')",
    )
    .bind(id)
    .bind(format!("Analytics Test Space {id}"))
    .bind(actor)
    .execute(db)
    .await
    .expect("insert content_space");
    id
}

/// `review_by`/`updated_by` are the two columns this suite cares about;
/// everything else takes a plain published-page default.
async fn insert_page(
    db: &DbPool,
    space_id: Uuid,
    updated_by: Uuid,
    review_by: Option<NaiveDate>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             review_by, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, 'published', '[]'::jsonb, '[]'::jsonb, $5, $6, $6)",
    )
    .bind(id)
    .bind(space_id)
    .bind(format!("Analytics Test Page {id}"))
    .bind(format!("/analytics-test-{id}"))
    .bind(review_by)
    .bind(updated_by)
    .execute(db)
    .await
    .expect("insert content_page");
    id
}

// ── page_stats / rollup_page_stats ──────────────────────────────────────────

#[tokio::test]
async fn a_page_with_no_signal_yet_has_a_zeroed_stats_row() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let page_id = insert_page(&db, space, owner, None).await;

    let stats = page_stats(&db, page_id).await.expect("page_stats");
    assert_eq!(stats.page_ref, page_id);
    assert_eq!(stats.views, 0);
    assert_eq!(stats.retrievals, 0);
    assert_eq!(stats.helpfulness_up, 0);
    assert_eq!(stats.helpfulness_down, 0);
    assert_eq!(stats.last_useful_at, None);
}

#[tokio::test]
async fn the_rollup_folds_views_and_votes_into_the_stats_row() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let page_id = insert_page(&db, space, owner, None).await;

    record_page_view(&db, page_id).await.expect("record view 1");
    record_page_view(&db, page_id).await.expect("record view 2");
    record_helpfulness_vote(&db, page_id, true)
        .await
        .expect("record up vote");
    record_helpfulness_vote(&db, page_id, false)
        .await
        .expect("record down vote");

    let result = rollup_page_stats(&db, &HashMap::new())
        .await
        .expect("rollup_page_stats");
    assert_eq!(result.pages_touched, 1);
    assert_eq!(result.views_folded_in, 2);
    assert_eq!(result.votes_folded_in, 2);

    let stats = page_stats(&db, page_id).await.expect("page_stats");
    assert_eq!(stats.views, 2);
    assert_eq!(stats.helpfulness_up, 1);
    assert_eq!(stats.helpfulness_down, 1);
    assert!(
        stats.last_useful_at.is_some(),
        "an up-vote must set last_useful_at"
    );
}

#[tokio::test]
async fn the_rollup_composes_retrieval_counts_handed_in_by_the_caller() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    // No local view/vote activity at all — the retrieval count alone must
    // still surface the page as a rollup candidate (D-452's UNION note).
    let page_id = insert_page(&db, space, owner, None).await;

    let mut retrieval_counts = HashMap::new();
    retrieval_counts.insert(page_id, 7i64);

    let result = rollup_page_stats(&db, &retrieval_counts)
        .await
        .expect("rollup_page_stats");
    assert_eq!(result.pages_touched, 1);

    let stats = page_stats(&db, page_id).await.expect("page_stats");
    assert_eq!(stats.retrievals, 7);
}

#[tokio::test]
async fn running_the_rollup_twice_does_not_double_count() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let page_id = insert_page(&db, space, owner, None).await;

    record_page_view(&db, page_id).await.expect("record view");

    let first = rollup_page_stats(&db, &HashMap::new())
        .await
        .expect("first rollup");
    assert_eq!(first.views_folded_in, 1);

    let second = rollup_page_stats(&db, &HashMap::new())
        .await
        .expect("second rollup");
    assert_eq!(
        second.pages_touched, 0,
        "a page with no new signal since its own watermark must not be re-touched"
    );

    let stats = page_stats(&db, page_id).await.expect("page_stats");
    assert_eq!(
        stats.views, 1,
        "the watermark must prevent the same view row being folded in twice"
    );

    // A new view after the first rollup is picked up on the next run —
    // proves the watermark advanced, rather than being a one-shot flag.
    record_page_view(&db, page_id).await.expect("record view 2");
    let third = rollup_page_stats(&db, &HashMap::new())
        .await
        .expect("third rollup");
    assert_eq!(third.views_folded_in, 1);
    assert_eq!(page_stats(&db, page_id).await.expect("page_stats").views, 2);
}

// ── sweep_review_reminders ──────────────────────────────────────────────────

#[tokio::test]
async fn a_page_past_its_review_date_notifies_its_owner() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let past = (Utc::now() - chrono::Duration::days(3)).date_naive();
    let page_id = insert_page(&db, space, owner, Some(past)).await;

    let stats = sweep_review_reminders(&db, &notification_cfg())
        .await
        .expect("sweep_review_reminders");
    assert_eq!(stats.reminders_sent, 1);

    let dispatch: (String, Uuid) = sqlx::query_as(
        "SELECT d.route, r.user_ref FROM notification_dispatch d \
         JOIN notification_recipient r ON r.dispatch_ref = d.id \
         WHERE r.user_ref = $1",
    )
    .bind(owner)
    .fetch_one(&db)
    .await
    .expect("a dispatch addressed to the page's owner must exist");
    assert_eq!(dispatch.0, format!("/content/pages/{page_id}"));
}

#[tokio::test]
async fn a_page_not_yet_due_for_review_is_left_alone() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let future = (Utc::now() + chrono::Duration::days(30)).date_naive();
    insert_page(&db, space, owner, Some(future)).await;

    let stats = sweep_review_reminders(&db, &notification_cfg())
        .await
        .expect("sweep_review_reminders");
    assert_eq!(stats.reminders_sent, 0);
}

/// `sweep_review_reminders` scans the *whole* `content_page` table
/// (there is no per-page "already reminded" flag, by design — see the
/// production doc comment), so within one shared, non-transactional test
/// database an earlier test's still-overdue page keeps showing up in every
/// later test's raw `stats.reminders_sent` count. These two tests therefore
/// assert on a dispatch scoped to *this test's own owner*, the same
/// isolation `a_page_past_its_review_date_notifies_its_owner` already uses,
/// rather than the unscoped aggregate count.
async fn dispatch_count_for_owner(db: &DbPool, owner: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM notification_recipient WHERE user_ref = $1")
        .bind(owner)
        .fetch_one(db)
        .await
        .expect("count dispatches for owner")
}

#[tokio::test]
async fn a_page_with_no_review_cadence_set_is_never_swept() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    insert_page(&db, space, owner, None).await;

    sweep_review_reminders(&db, &notification_cfg())
        .await
        .expect("sweep_review_reminders");

    assert_eq!(
        dispatch_count_for_owner(&db, owner).await,
        0,
        "a NULL review_by means 'no cadence set', not 'always due'"
    );
}

#[tokio::test]
async fn running_the_sweep_twice_reminds_again_the_next_tick() {
    let db = skip_if_no_db!(test_db().await);
    let owner = insert_active_user(&db).await;
    let space = insert_space(&db).await;
    let past = (Utc::now() - chrono::Duration::days(1)).date_naive();
    insert_page(&db, space, owner, Some(past)).await;

    sweep_review_reminders(&db, &notification_cfg())
        .await
        .expect("first sweep");
    assert_eq!(dispatch_count_for_owner(&db, owner).await, 1);

    sweep_review_reminders(&db, &notification_cfg())
        .await
        .expect("second sweep");
    assert_eq!(
        dispatch_count_for_owner(&db, owner).await,
        2,
        "an overdue page has no 'already reminded' flag — it must keep nagging its owner"
    );
}

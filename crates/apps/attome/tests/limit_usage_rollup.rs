//! AA9-T5: a node's limit-hit tally reaches `limit_usage_daily`, adding to
//! the day's row and keeping the larger peak.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::limit_usage::{UsageRow, upsert};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

#[tokio::test]
async fn limit_usage_flush_upserts() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let user = Uuid::now_v7();
    let limit = format!("test.limit.{user}");
    let row = |hits, peak| UsageRow {
        limit_key: limit.clone(),
        principal_kind: "user",
        principal_id: user,
        hits,
        peak,
    };

    upsert(&db, &[row(2, 40)]).await.unwrap();
    upsert(&db, &[row(3, 10)]).await.unwrap();

    let (hits, peak): (i64, i64) = sqlx::query_as(
        "SELECT hits, peak FROM limit_usage_daily \
         WHERE limit_key = $1 AND principal_kind = 'user' AND principal_id = $2 \
           AND day = (now() AT TIME ZONE 'UTC')::date",
    )
    .bind(&limit)
    .bind(user)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((hits, peak), (5, 40));
}

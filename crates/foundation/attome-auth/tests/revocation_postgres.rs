//! Z4-T5: the session-token denylist of a deployment without Redis lives in
//! Postgres (`auth_jti_denylist`) and fails closed like the Redis one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::revocation::{RevocationStore, is_revoked, prune_expired, revoke};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

async fn pool() -> Option<attome_db::DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

#[tokio::test]
async fn postgres_revoke_then_is_revoked() {
    let db = skip_if_no_db!(pool().await);
    let store = RevocationStore::Postgres(&db);
    let jti = Uuid::now_v7();
    assert!(!is_revoked(store, jti).await);
    revoke(store, jti, 60).await.unwrap();
    assert!(is_revoked(store, jti).await);
    // Revoking again keeps the later expiry, never shortens it.
    revoke(store, jti, 1).await.unwrap();
    assert!(is_revoked(store, jti).await);
    // A token already expired is not written at all.
    let expired = Uuid::now_v7();
    revoke(store, expired, 0).await.unwrap();
    assert!(!is_revoked(store, expired).await);
    // The prune keeps a live entry.
    prune_expired(&db, 0, 1_000).await.unwrap();
    assert!(is_revoked(store, jti).await);
}

#[tokio::test]
async fn postgres_error_reads_as_revoked() {
    let db = skip_if_no_db!(pool().await);
    db.close().await;
    assert!(
        is_revoked(RevocationStore::Postgres(&db), Uuid::now_v7()).await,
        "a database that cannot answer must read as revoked"
    );
}

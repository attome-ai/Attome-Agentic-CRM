//! S11-T5: without Redis a nonce is claimed in Postgres, so a restarted
//! process (a fresh in-memory store) still refuses a replay; an expired
//! nonce may be claimed again; and an unreachable database refuses.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database).
//!
//! ```powershell
//! cargo test -p attome-s2s --test nonce_store -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_cache::Store;
use attome_db::DbPool;
use attome_s2s::rate_limit;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

/// The whole guard as the signed path runs it.
async fn guard(store: &Store, db: &DbPool, client: &str, nonce: &str) -> Result<(), AppError> {
    rate_limit::claim_nonce_durably(store, db, client, nonce).await?;
    rate_limit::check_with_nonce(store, client, nonce, 1000).await
}

#[tokio::test]
async fn solo_nonce_survives_a_restart() {
    let db = skip_if_no_db!(pool().await);
    let client = format!("nonce-{}", Uuid::now_v7());
    let nonce = Uuid::now_v7().to_string();

    let before_restart = Store::memory();
    guard(&before_restart, &db, &client, &nonce)
        .await
        .expect("a fresh nonce");
    assert!(matches!(
        guard(&before_restart, &db, &client, &nonce).await,
        Err(AppError::Conflict(_))
    ));

    // A restarted process has an empty memory store; Postgres remembers.
    let after_restart = Store::memory();
    assert!(
        matches!(
            guard(&after_restart, &db, &client, &nonce).await,
            Err(AppError::Conflict(_))
        ),
        "a replay after a restart is refused"
    );

    // Once it expired nobody can replay it inside the window: it may be
    // claimed again.
    sqlx::query(
        "UPDATE s2s_nonce SET expires_at = NOW() - interval '1 second' WHERE client_id = $1",
    )
    .bind(&client)
    .execute(&db)
    .await
    .unwrap();
    rate_limit::claim_nonce_durably(&after_restart, &db, &client, &nonce)
        .await
        .expect("an expired nonce is claimed again");
}

#[tokio::test]
async fn solo_nonce_store_outage_fails_closed() {
    // Nothing listens on port 1.
    let unreachable = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://attome:attome@127.0.0.1:1/attome")
        .expect("a lazy pool");
    let result =
        rate_limit::claim_nonce_durably(&Store::memory(), &unreachable, "any-client", "n-1").await;
    assert!(
        matches!(result, Err(AppError::Internal(_))),
        "an unreachable store refuses: {result:?}"
    );
}

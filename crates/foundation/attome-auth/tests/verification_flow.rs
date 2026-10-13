//! Integration test for the email-verification flow (P-account-lifecycle):
//! request → confirm → `email_verified` flips to true → token is single-use.
//!
//! Requires a live Postgres with migration 0022 applied. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test verification_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::password::hash_password_async;
use attome_auth::verification;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

/// The pepper ring verification tokens hash with (attome-auth hardening 1.4).
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-auth-test-pepper-0123456789abcdef", &[])
}

async fn create_test_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    let email = format!("verify-test-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "some-password",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active, email_verified)
         VALUES ($1, $2, $3, now(), true, false)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .expect("insert test user");
    id
}

async fn is_verified(db: &DbPool, user_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT email_verified FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("fetch email_verified")
}

#[tokio::test]
async fn full_round_trip_flips_email_verified_and_the_token_is_single_use() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    assert!(!is_verified(&db, user_id).await, "starts unverified");

    let issued = verification::request(&db, user_id, 48, &test_ring())
        .await
        .expect("request must succeed");

    let confirmed_user_id = verification::confirm(&db, &issued.bearer, &test_ring())
        .await
        .expect("confirm with a fresh valid token must succeed");
    assert_eq!(confirmed_user_id, user_id);
    assert!(is_verified(&db, user_id).await, "must flip to verified");

    let second_attempt = verification::confirm(&db, &issued.bearer, &test_ring()).await;
    assert!(
        matches!(second_attempt, Err(attome_types::AppError::Conflict(_))),
        "a reused verification token must be rejected as a conflict, got {second_attempt:?}"
    );
}

#[tokio::test]
async fn confirm_rejects_an_expired_token() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let issued = verification::request(&db, user_id, 48, &test_ring())
        .await
        .unwrap();
    let public_id_str = issued.bearer.split('.').next().unwrap();
    sqlx::query("UPDATE email_verification_token SET expires_at = NOW() - INTERVAL '1 minute' WHERE public_id = $1::uuid")
        .bind(public_id_str)
        .execute(&db)
        .await
        .expect("force-expire the token");

    let result = verification::confirm(&db, &issued.bearer, &test_ring()).await;
    assert!(matches!(result, Err(attome_types::AppError::Unauthorized)));
    assert!(!is_verified(&db, user_id).await, "must stay unverified");
}

/// D-500: new verification tokens are stored as peppered HMAC, and a token
/// row hashed any other way (here Argon2) is refused.
#[tokio::test]
async fn new_tokens_are_hmac_and_an_argon2_token_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let issued = verification::request(&db, user_id, 48, &test_ring())
        .await
        .expect("request must succeed");
    let public_id = issued.bearer.split('.').next().unwrap().to_owned();
    let stored: String = sqlx::query_scalar(
        "SELECT secret_hash FROM email_verification_token WHERE public_id = $1::uuid",
    )
    .bind(&public_id)
    .fetch_one(&db)
    .await
    .expect("fetch secret_hash");
    assert!(
        stored.starts_with("hmac256"),
        "a new verification token must be stored as peppered HMAC, got {stored}"
    );

    let legacy_public_id = Uuid::now_v7();
    let legacy_secret = "legacy-argon2-verification-secret-0123";
    let legacy_hash =
        hash_password_async(attome_auth::NewPassword::platform_generated(legacy_secret))
            .await
            .expect("hash");
    sqlx::query(
        "INSERT INTO email_verification_token (user_ref, public_id, secret_hash, expires_at)
         VALUES ($1, $2, $3, now() + interval '48 hours')",
    )
    .bind(user_id)
    .bind(legacy_public_id)
    .bind(&legacy_hash)
    .execute(&db)
    .await
    .expect("insert a legacy Argon2 token");

    let refused = verification::confirm(
        &db,
        &format!("{legacy_public_id}.{legacy_secret}"),
        &test_ring(),
    )
    .await;
    assert!(
        refused.is_err(),
        "an Argon2 verification token row must be refused"
    );
}

//! Integration test for `accounts::login`'s `require_verified_email` gate
//! (P-account-lifecycle). Requires a live Postgres with migration 0022
//! applied. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test login_verified_email -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{self, LoginOutcome};
use attome_auth::password::hash_password_async;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::{Builder, RedisConfig};
use uuid::Uuid;

const JWT_ISSUER: &str = "attome-login-verified-email-test";

/// P-key-rotation-and-jwt (a): the JWT secret is a `KeyRing` now, not a bare
/// `&str` — see `attome_auth::jwt`'s doc.
fn test_jwt_ring() -> KeyRing {
    KeyRing::single("login-verified-email-test-secret-value".to_string())
}

/// Every test in this file drives `accounts::login` with `mfa_policy = "off"`,
/// so the MFA challenge-marker path (`mfa::start_challenge`) is never
/// reached — a Redis client built but never connected is safe here, same
/// reasoning as `reset_flow.rs`'s `unconnected_redis`.
fn unconnected_redis() -> attome_cache::RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

async fn create_test_user(db: &DbPool, email_verified: bool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("login-verify-test-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "correct-password",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active, email_verified)
         VALUES ($1, $2, $3, now(), true, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .bind(email_verified)
    .execute(db)
    .await
    .expect("insert test user");
    (id, email)
}

#[tokio::test]
async fn login_succeeds_regardless_of_verification_when_policy_is_off() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, false).await;

    let redis = unconnected_redis();
    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "off",
        &test_jwt_ring(),
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await;
    assert!(matches!(result.unwrap(), LoginOutcome::Session(id) if id == user_id));
}

#[tokio::test]
async fn login_is_forbidden_for_an_unverified_account_when_policy_is_on() {
    let db = skip_if_no_db!(pool().await);
    let (_, email) = create_test_user(&db, false).await;

    let redis = unconnected_redis();
    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        true,
        "off",
        &test_jwt_ring(),
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)));
}

#[tokio::test]
async fn login_succeeds_for_a_verified_account_when_policy_is_on() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, true).await;

    let redis = unconnected_redis();
    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        true,
        "off",
        &test_jwt_ring(),
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await;
    assert!(matches!(result.unwrap(), LoginOutcome::Session(id) if id == user_id));
}

#[tokio::test]
async fn login_still_rejects_a_wrong_password_before_the_verification_check_runs() {
    let db = skip_if_no_db!(pool().await);
    let (_, email) = create_test_user(&db, false).await;

    // Wrong password must fail Unauthorized, not Forbidden — verification is
    // checked only after the password itself has already verified.
    let redis = unconnected_redis();
    let result = accounts::login(
        &db,
        &redis,
        &email,
        "wrong-password",
        true,
        "off",
        &test_jwt_ring(),
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

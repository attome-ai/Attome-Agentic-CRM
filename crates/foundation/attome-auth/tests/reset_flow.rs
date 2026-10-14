//! Integration test for the password-reset flow (P-account-lifecycle):
//! request → confirm → old password dead / new password works → token is
//! single-use → an unknown email is indistinguishable from a hit at the API
//! shape (`Ok(None)` vs `Ok(Some(_))`, both used identically by the caller).
//!
//! Requires a live Postgres with migration 0022 applied — same convention as
//! `xrm-server`'s integration tests. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test reset_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::apikey_hash::{VerifyOutcome, verify_api_key_secret};
use attome_auth::auth_context::AuthContext;
use attome_auth::mfa;
use attome_auth::password::{hash_password_async, verify_password_async};
use attome_auth::refresh::{self, RefreshLifetimes};
use attome_auth::reset;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use fred::prelude::{Builder, RedisConfig};
use totp_rs::{Algorithm, Builder as TotpBuilder, Secret, Totp};
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

/// The pepper ring reset tokens hash with (attome-auth hardening 1.4).
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-auth-test-pepper-0123456789abcdef", &[])
}

/// A Redis client built but never connected — `confirm`'s `epoch::invalidate_cache`
/// call is fire-and-forget (`let _ = timeout(...)`, per D-025's cache-coherence
/// fallback posture), so an unreachable pool is safe here, not just in the
/// early-return-only unit tests over in `reset.rs` itself.
fn unconnected_redis() -> attome_cache::RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

/// Inserts a throwaway password account and returns its (id, email).
async fn create_test_user(db: &DbPool, initial_password: &str) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("reset-test-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        initial_password,
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active)
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .expect("insert test user");
    (id, email)
}

async fn password_hash_of(db: &DbPool, user_id: Uuid) -> String {
    sqlx::query_scalar("SELECT password_hash FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("fetch password_hash")
}

#[tokio::test]
async fn full_round_trip_changes_the_password_and_the_token_is_single_use() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, "old-password-123").await;

    let issued = reset::request(&db, &email, 30, &test_ring())
        .await
        .expect("request must not error")
        .expect("a real account must issue a token");
    assert_eq!(issued.user_id, user_id);
    assert_eq!(issued.email, email);

    let old_hash = password_hash_of(&db, user_id).await;

    let confirmed_user_id = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "new-password-456",
        &test_ring(),
    )
    .await
    .expect("confirm with a fresh valid token must succeed");
    assert_eq!(confirmed_user_id, user_id);

    let new_hash = password_hash_of(&db, user_id).await;
    assert_ne!(old_hash, new_hash, "password_hash must actually change");
    assert!(
        attome_auth::password::verify_password_async("new-password-456", &new_hash)
            .await
            .unwrap()
    );
    assert!(
        !attome_auth::password::verify_password_async("old-password-123", &new_hash)
            .await
            .unwrap()
    );

    // Single-use: the same bearer must not work a second time.
    let second_attempt = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "yet-another-password",
        &test_ring(),
    )
    .await;
    assert!(
        matches!(second_attempt, Err(attome_types::AppError::Conflict(_))),
        "a reused reset token must be rejected as a conflict, got {second_attempt:?}"
    );
}

#[tokio::test]
async fn request_for_an_unknown_email_returns_none_without_erroring() {
    let db = skip_if_no_db!(pool().await);
    let result = reset::request(
        &db,
        "definitely-not-a-real-account@example.invalid",
        30,
        &test_ring(),
    )
    .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn confirm_rejects_an_expired_token() {
    let db = skip_if_no_db!(pool().await);
    let (_, email) = create_test_user(&db, "some-password").await;

    let issued = reset::request(&db, &email, 30, &test_ring())
        .await
        .unwrap()
        .expect("token issuance must succeed");

    // Force the token into the past directly — request()'s ttl_mins is
    // always positive, so this is the only way to exercise the expiry path.
    let public_id_str = issued.bearer.split('.').next().unwrap();
    sqlx::query("UPDATE password_reset_token SET expires_at = NOW() - INTERVAL '1 minute' WHERE public_id = $1::uuid")
        .bind(public_id_str)
        .execute(&db)
        .await
        .expect("force-expire the token");

    let result = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "new-password",
        &test_ring(),
    )
    .await;
    assert!(matches!(result, Err(attome_types::AppError::Unauthorized)));
}

#[tokio::test]
async fn confirm_rejects_a_wrong_secret_for_a_real_public_id() {
    let db = skip_if_no_db!(pool().await);
    let (_, email) = create_test_user(&db, "some-password").await;

    let issued = reset::request(&db, &email, 30, &test_ring())
        .await
        .unwrap()
        .unwrap();
    let public_id_str = issued.bearer.split('.').next().unwrap();
    let tampered = format!("{public_id_str}.wrong-secret-entirely");

    let result = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &tampered,
        "new-password",
        &test_ring(),
    )
    .await;
    assert!(matches!(result, Err(attome_types::AppError::Unauthorized)));
}

/// Security contract I2 (attome-auth hardening 1.2): a new password below the
/// policy minimum is rejected before the token is consumed or any hash is
/// written, so the same reset link still works with a valid password.
#[tokio::test]
async fn confirm_rejects_a_weak_new_password_without_consuming_the_token() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, "old-password-123").await;
    let issued = reset::request(&db, &email, 30, &test_ring())
        .await
        .expect("request must not error")
        .expect("a real account must issue a token");
    let old_hash = password_hash_of(&db, user_id).await;

    let result = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "too-short",
        &test_ring(),
    )
    .await;
    assert!(
        matches!(result, Err(attome_types::AppError::Validation(_))),
        "a 9-character password must fail the policy, got {result:?}"
    );
    assert_eq!(
        password_hash_of(&db, user_id).await,
        old_hash,
        "a rejected password must not be written"
    );

    let retry = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "long-enough-password",
        &test_ring(),
    )
    .await;
    assert!(
        retry.is_ok(),
        "the token must still be usable after a policy rejection, got {retry:?}"
    );
}

/// D-500: new reset tokens are stored as peppered HMAC, and a token row
/// hashed any other way (here Argon2) is refused.
#[tokio::test]
async fn new_reset_tokens_are_hmac_and_an_argon2_token_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, "old-password-123").await;

    let issued = reset::request(&db, &email, 30, &test_ring())
        .await
        .expect("request must not error")
        .expect("a real account must issue a token");
    let public_id = issued.bearer.split('.').next().unwrap().to_owned();
    let stored: String = sqlx::query_scalar(
        "SELECT secret_hash FROM password_reset_token WHERE public_id = $1::uuid",
    )
    .bind(&public_id)
    .fetch_one(&db)
    .await
    .expect("fetch secret_hash");
    assert!(
        stored.starts_with("hmac256"),
        "a new reset token must be stored as peppered HMAC, got {stored}"
    );

    let legacy_public_id = Uuid::now_v7();
    let legacy_secret = "legacy-argon2-reset-secret-0123456789";
    let legacy_hash =
        hash_password_async(attome_auth::NewPassword::platform_generated(legacy_secret))
            .await
            .expect("hash");
    sqlx::query(
        "INSERT INTO password_reset_token (user_ref, public_id, secret_hash, expires_at)
         VALUES ($1, $2, $3, now() + interval '30 minutes')",
    )
    .bind(user_id)
    .bind(legacy_public_id)
    .bind(&legacy_hash)
    .execute(&db)
    .await
    .expect("insert a legacy Argon2 token");

    let refused = reset::confirm(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &format!("{legacy_public_id}.{legacy_secret}"),
        "brand-new-password-789",
        &test_ring(),
    )
    .await;
    assert!(
        refused.is_err(),
        "an Argon2 reset token row must be refused"
    );
}

/// Base-auth hardening 2.4 (F9): the reset lookup matches accounts the way
/// login does. The requested email is normalized before an exact match, and a
/// row that never set `is_active` counts as active (NULL before migration
/// 0460, the TRUE default since).
#[tokio::test]
async fn request_finds_an_account_through_a_differently_cased_email() {
    let db = skip_if_no_db!(pool().await);
    let id = Uuid::now_v7();
    let email = format!("reset-casing-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "casing-password-123",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at)
         VALUES ($1, $2, $3, now())",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(&db)
    .await
    .expect("insert a user without an explicit is_active");

    let typed = format!("  {}  ", email.to_uppercase());
    let issued = reset::request(&db, &typed, 30, &test_ring())
        .await
        .expect("request must not error")
        .expect("a legacy active account must get a reset token");
    assert_eq!(issued.user_id, id);
    assert_eq!(issued.email, email);
}

// ── Atomic reset (D-509, attome-auth hardening 2.3) ────────────────────────────

const OLD_PASSWORD: &str = "old-password-123";

async fn confirm_with(db: &DbPool, bearer: &str, new_password: &str) -> Result<Uuid, AppError> {
    reset::confirm(
        db,
        &attome_cache::Store::Redis(unconnected_redis()),
        bearer,
        new_password,
        &test_ring(),
    )
    .await
}

async fn issue_reset(db: &DbPool, email: &str) -> String {
    reset::request(db, email, 30, &test_ring())
        .await
        .expect("request must not error")
        .expect("an active password account must get a reset token")
        .bearer
}

async fn password_verifies(db: &DbPool, user_id: Uuid, password: &str) -> bool {
    verify_password_async(password, &password_hash_of(db, user_id).await)
        .await
        .expect("verify password")
}

async fn auth_epoch_of(db: &DbPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT auth_epoch FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("read auth_epoch")
}

async fn is_active_of(db: &DbPool, user_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("read is_active")
}

/// `(used_at, expires_at)` of one reset token.
async fn reset_token_state(db: &DbPool, bearer: &str) -> (Option<DateTime<Utc>>, DateTime<Utc>) {
    let public_id: Uuid = bearer
        .split_once('.')
        .expect("token shape")
        .0
        .parse()
        .expect("public_id is a uuid");
    sqlx::query_as("SELECT used_at, expires_at FROM password_reset_token WHERE public_id = $1")
        .bind(public_id)
        .fetch_one(db)
        .await
        .expect("reset token row")
}

/// A live refresh token for the account, issued the way a sign-in issues one.
async fn issue_refresh(db: &DbPool, user_id: Uuid) -> String {
    let lifetimes = RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: 30 * 86_400,
    };
    refresh::issue(
        db,
        user_id,
        &AuthContext::password(),
        lifetimes,
        &test_ring(),
    )
    .await
    .expect("issue refresh token")
    .bearer
}

async fn live_refresh_tokens(db: &DbPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token WHERE user_ref = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
    .expect("count live refresh tokens")
}

/// Two confirms of one token race: exactly one succeeds, the other gets a 409,
/// and the loser writes nothing. Only the winner's password verifies, and the
/// epoch rises by exactly one.
#[tokio::test]
async fn concurrent_confirms_of_one_token_have_one_winner_and_the_loser_writes_nothing() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, OLD_PASSWORD).await;
    let bearer = issue_reset(&db, &email).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;
    let (first_password, second_password) = ("first-new-password-111", "second-new-password-222");

    let (first, second) = tokio::join!(
        confirm_with(&db, &bearer, first_password),
        confirm_with(&db, &bearer, second_password),
    );

    let (winner, loser, loser_result) = match (&first, &second) {
        (Ok(_), Err(_)) => (first_password, second_password, second),
        (Err(_), Ok(_)) => (second_password, first_password, first),
        _ => panic!("exactly one confirm must succeed, got {first:?} and {second:?}"),
    };
    assert!(
        matches!(loser_result, Err(AppError::Conflict(_))),
        "the losing confirm must see the token as already used, got {loser_result:?}"
    );
    assert!(password_verifies(&db, user_id, winner).await);
    assert!(
        !password_verifies(&db, user_id, loser).await,
        "the loser's password must never be written"
    );
    assert!(!password_verifies(&db, user_id, OLD_PASSWORD).await);
    assert_eq!(
        auth_epoch_of(&db, user_id).await,
        epoch_before + 1,
        "only the winner bumps the epoch"
    );
}

/// A real database failure inside the transaction, after the password write,
/// rolls every change back. A trigger raises on the refresh revocation (D-509
/// rule 3.5), the step after the password is set.
#[tokio::test]
async fn a_failure_inside_the_reset_transaction_rolls_every_change_back() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, OLD_PASSWORD).await;
    let bearer = issue_reset(&db, &email).await;
    let sibling = issue_reset(&db, &email).await;
    issue_refresh(&db, user_id).await;
    issue_refresh(&db, user_id).await;

    let token_before = reset_token_state(&db, &bearer).await;
    let sibling_before = reset_token_state(&db, &sibling).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;
    let active_before = is_active_of(&db, user_id).await;
    assert_eq!(live_refresh_tokens(&db, user_id).await, 2);

    let probe = format!("reset_rollback_probe_{}", user_id.simple());
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {probe}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             IF OLD.user_ref = '{user_id}'::uuid AND NEW.revoked_at IS NOT NULL THEN
                 RAISE EXCEPTION 'forced failure inside the reset transaction';
             END IF;
             RETURN NEW;
         END $$;
         CREATE TRIGGER {probe} BEFORE UPDATE ON refresh_token
             FOR EACH ROW EXECUTE FUNCTION {probe}();"
    ))
    .execute(&db)
    .await
    .expect("install the failpoint trigger");

    let result = confirm_with(&db, &bearer, "new-password-456").await;

    sqlx::raw_sql(&format!(
        "DROP TRIGGER {probe} ON refresh_token; DROP FUNCTION {probe}();"
    ))
    .execute(&db)
    .await
    .expect("remove the failpoint trigger");

    assert!(
        matches!(
            result,
            Err(ref error)
                if !matches!(error, AppError::Unauthorized | AppError::Conflict(_) | AppError::Validation(_))
        ),
        "the forced database failure must fail the confirm, got {result:?}"
    );
    assert!(
        password_verifies(&db, user_id, OLD_PASSWORD).await,
        "the old password must still verify"
    );
    assert!(
        !password_verifies(&db, user_id, "new-password-456").await,
        "the new password must not have been written"
    );
    assert_eq!(
        reset_token_state(&db, &bearer).await,
        token_before,
        "token consumption must roll back"
    );
    assert_eq!(
        reset_token_state(&db, &sibling).await,
        sibling_before,
        "the sibling token must be unchanged"
    );
    assert_eq!(
        live_refresh_tokens(&db, user_id).await,
        2,
        "refresh revocation must roll back"
    );
    assert_eq!(
        auth_epoch_of(&db, user_id).await,
        epoch_before,
        "the epoch bump must roll back"
    );
    assert_eq!(is_active_of(&db, user_id).await, active_before);

    confirm_with(&db, &bearer, "new-password-456")
        .await
        .expect("with the failure gone, the same token must still confirm");
}

/// D-509 rule 3.1: a disabled account cannot reset. The confirm is a 401 that
/// writes nothing and leaves the token unconsumed.
#[tokio::test]
async fn a_disabled_account_cannot_reset_and_nothing_is_written() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, OLD_PASSWORD).await;
    let bearer = issue_reset(&db, &email).await;
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the account");
    let token_before = reset_token_state(&db, &bearer).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;

    let result = confirm_with(&db, &bearer, "new-password-456").await;

    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a disabled account must not reset, got {result:?}"
    );
    assert!(password_verifies(&db, user_id, OLD_PASSWORD).await);
    assert_eq!(reset_token_state(&db, &bearer).await, token_before);
    assert_eq!(auth_epoch_of(&db, user_id).await, epoch_before);
}

/// D-509 rules 3.4 and 3.5: `confirm` itself expires the account's other reset
/// links and revokes every refresh token. No handler call is involved.
#[tokio::test]
async fn confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, OLD_PASSWORD).await;
    let bearer = issue_reset(&db, &email).await;
    let sibling = issue_reset(&db, &email).await;
    issue_refresh(&db, user_id).await;
    issue_refresh(&db, user_id).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;

    confirm_with(&db, &bearer, "new-password-456")
        .await
        .expect("confirm");

    assert_eq!(
        live_refresh_tokens(&db, user_id).await,
        0,
        "every refresh token must be revoked"
    );
    assert_eq!(auth_epoch_of(&db, user_id).await, epoch_before + 1);
    let (sibling_used_at, _) = reset_token_state(&db, &sibling).await;
    assert!(
        sibling_used_at.is_none(),
        "a sibling link is expired, not marked used"
    );
    let sibling_result = confirm_with(&db, &sibling, "another-password-789").await;
    assert!(
        matches!(sibling_result, Err(AppError::Unauthorized)),
        "a sibling link must answer like an expired one, got {sibling_result:?}"
    );
    assert!(password_verifies(&db, user_id, "new-password-456").await);
}

/// D-509 rule 1, sessions only: a reset leaves the account's API key usable and
/// its MFA enrollment in place.
#[tokio::test]
async fn a_reset_leaves_api_keys_usable_and_mfa_enrolled() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, OLD_PASSWORD).await;

    let public_key = format!("atk_pub_{}", Uuid::now_v7().simple());
    let api_secret = "reset-flow-api-key-secret-0123456789abcdef";
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, 'reset-survivor', $2, $3)",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(test_ring().hash(api_secret))
    .execute(&db)
    .await
    .expect("insert an api key");

    let mfa_ring = KeyRing::single("ab".repeat(32));
    let enrolled = mfa::enroll(&db, &mfa_ring, user_id).await.expect("enroll");
    let totp = TotpBuilder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolled.secret_base32).unwrap())
        .with_account_name("test".to_string())
        .build()
        .unwrap();
    mfa::confirm_enrollment(
        &db,
        &mfa_ring,
        &test_ring(),
        user_id,
        &totp.generate_current().to_string(),
    )
    .await
    .expect("confirm enrollment");

    let bearer = issue_reset(&db, &email).await;
    confirm_with(&db, &bearer, "new-password-456")
        .await
        .expect("confirm");

    // The same lookup attome-server's `resolve_api_key` performs.
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT k.secret_hash FROM api_key k
         JOIN user_account u ON u.id = k.user_ref AND u.is_active = TRUE
         WHERE k.public_key = $1 AND k.is_active = true
           AND (k.expires_at IS NULL OR k.expires_at > NOW())",
    )
    .bind(&public_key)
    .fetch_optional(&db)
    .await
    .expect("look up the api key");
    let stored = stored.expect("the api key must still be live after a reset");
    let outcome = verify_api_key_secret(&test_ring(), api_secret, &stored)
        .await
        .expect("verify api key");
    assert!(
        outcome != VerifyOutcome::Fail,
        "the api key secret must still verify after a reset"
    );

    assert!(
        mfa::is_enrolled(&db, user_id).await.expect("is_enrolled"),
        "MFA must stay enrolled after a reset"
    );
    mfa::verify_code(&db, &mfa_ring, user_id, &next_totp_code(&totp))
        .await
        .expect("a TOTP code must still verify after a reset");
}

/// A code for the step after the one enrollment consumed, so replay prevention
/// does not reject it (see `login_mfa.rs::next_code`).
fn next_totp_code(totp: &Totp) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(now + 30).to_string()
}

// ── BAU-13b (F15): pruning expired single-use tokens ─────────────────────────

/// Each single-use token table loses only rows whose `expires_at` passed more
/// than the retention ago; an unexpired row, used or unused, and a row that
/// expired inside the retention window both stay.
#[tokio::test]
async fn pruning_never_deletes_an_unexpired_or_unconsumed_token() {
    let db = skip_if_no_db!(pool().await);
    let (user_id, email) = create_test_user(&db, "prune-test-password-1").await;
    const DAY: i64 = 86_400;
    // (expires_at offset from now in seconds, used, expected to survive)
    let cases: [(i64, bool, bool); 5] = [
        (3600, false, true),
        (3600, true, true),
        (-3600, false, true),
        (-3 * DAY, false, false),
        (-3 * DAY, true, false),
    ];

    for table in [
        "password_reset_token",
        "email_verification_token",
        "invitation_token",
    ] {
        let mut ids = Vec::new();
        for (offset, used, _) in cases {
            let id = Uuid::now_v7();
            let expiry = "NOW() + make_interval(secs => $OFF::float8)";
            let used_at = "CASE WHEN $USED THEN NOW() - interval '4 days' END";
            let result = if table == "invitation_token" {
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, email, invited_by_ref, public_id, secret_hash, expires_at, used_at)
                     VALUES ($1, $2, $3, $4, 'x', {}, {})",
                    expiry.replace("$OFF", "$5"),
                    used_at.replace("$USED", "$6")
                ))
                .bind(id)
                .bind(&email)
                .bind(user_id)
                .bind(Uuid::now_v7())
                .bind(offset)
                .bind(used)
                .execute(&db)
                .await
            } else {
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, user_ref, public_id, secret_hash, expires_at, used_at)
                     VALUES ($1, $2, $3, 'x', {}, {})",
                    expiry.replace("$OFF", "$4"),
                    used_at.replace("$USED", "$5")
                ))
                .bind(id)
                .bind(user_id)
                .bind(Uuid::now_v7())
                .bind(offset)
                .bind(used)
                .execute(&db)
                .await
            };
            result.unwrap_or_else(|e| panic!("insert into {table}: {e}"));
            ids.push(id);
        }

        loop {
            let deleted = match table {
                "password_reset_token" => attome_auth::reset::prune_expired(&db, DAY, 500).await,
                "email_verification_token" => {
                    attome_auth::verification::prune_expired(&db, DAY, 500).await
                }
                _ => attome_auth::invitation::prune_expired(&db, DAY, 500).await,
            }
            .expect("prune");
            if deleted == 0 {
                break;
            }
        }

        for (id, (offset, used, survives)) in ids.iter().zip(cases) {
            let exists: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1)"
            ))
            .bind(id)
            .fetch_one(&db)
            .await
            .expect("probe");
            assert_eq!(
                exists, survives,
                "{table}: expires in {offset}s, used={used}"
            );
        }
    }
}

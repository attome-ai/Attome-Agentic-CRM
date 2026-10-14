//! Integration tests for the P2.8 step 7 (MFA/TOTP) login-flow branching in
//! `accounts::login`, the enroll/confirm/verify round trip in
//! `attome_auth::mfa`, and P-mfa-challenge-hardening's single-use Redis
//! challenge marker + attempt ceiling. Requires a live Postgres with
//! migration 0027 applied and a reachable Redis/Dragonfly (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, defaults 127.0.0.1:6379 — same convention as
//! `attome-cache/tests/rate_limit.rs`). Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test login_mfa -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{self, LoginOutcome};
use attome_auth::mfa;
use attome_auth::password::hash_password_async;
use attome_auth::session::TokenType;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::*;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;

const JWT_ISSUER: &str = "attome-login-mfa-test";

fn pepper() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "login-mfa-test-pepper-0123456789abcdef", &[])
}
const MAX_ATTEMPTS: u32 = 5;
/// Must match `attome_auth::mfa`'s own private `TOTP_STEP_SECS`/`TOTP_SKEW`.
const TOTP_STEP_SECS: u64 = 30;

/// A fresh login/verify code guaranteed to be for a *later* TOTP step than
/// whatever `enroll_and_confirm` just consumed to confirm enrollment —
/// `mfa::verify_code`'s replay-prevention rejects a code for a step at or
/// before the last accepted one (D-057), and generating "the current code"
/// twice in quick succession (once inside `enroll_and_confirm`, once for the
/// test's own login/verify call) can otherwise land on the identical 30s
/// step and get legitimately rejected as a replay, depending on exactly when
/// each call happens to run. `verify_code`'s `TOTP_SKEW = 1` still accepts a
/// code one step ahead of the server's own "now", so this stays valid.
fn next_code(totp: &Totp) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(now + TOTP_STEP_SECS).to_string()
}

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

async fn redis_pool() -> Option<attome_cache::Store> {
    let (host, port) = attome_testkit::test_redis()?;

    let config = RedisConfig::from_url(&format!("redis://{host}:{port}"))
        .expect("build redis config from test host/port");
    let pool = RedisPool::new(config, None, None, None, 2).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to local test Redis/Dragonfly");
    Some(attome_cache::Store::Redis(pool))
}

/// P-key-rotation-and-jwt (a): the MFA/JWT secrets are `KeyRing`s now, not
/// bare `[u8; 32]`/`&str` — see `attome_auth::envelope`/`jwt`'s doc.
fn test_mfa_ring() -> KeyRing {
    KeyRing::single("ab".repeat(32))
}

fn test_jwt_ring() -> KeyRing {
    KeyRing::single("login-mfa-test-secret-value-0123456789".to_string())
}

async fn create_test_user(db: &DbPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("login-mfa-test-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "correct-password",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active, email_verified)
         VALUES ($1, $2, $3, now(), true, true)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .expect("insert test user");
    (id, email)
}

/// Drives a full enroll -> confirm round trip and returns the confirmed
/// TOTP generator (so the test can produce valid codes) + the recovery codes.
async fn enroll_and_confirm(db: &DbPool, ring: &KeyRing, user_id: Uuid) -> (Totp, Vec<String>) {
    let enrolled = mfa::enroll(db, ring, user_id).await.expect("enroll");
    let secret = Secret::try_from_base32(&enrolled.secret_base32).unwrap();
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_account_name("test".to_string())
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();
    let recovery_codes = mfa::confirm_enrollment(db, ring, &pepper(), user_id, &code)
        .await
        .expect("confirm_enrollment");
    (totp, recovery_codes)
}

#[tokio::test]
async fn login_returns_a_bare_session_when_policy_is_off_regardless_of_enrollment() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    enroll_and_confirm(&db, &ring, user_id).await;

    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "off",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    assert!(matches!(result, LoginOutcome::Session(id) if id == user_id));
}

#[tokio::test]
async fn login_requires_enrollment_when_policy_is_required_and_account_is_unenrolled() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let jwt_ring = test_jwt_ring();
    let (_, email) = create_test_user(&db).await;

    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    assert!(matches!(result, LoginOutcome::MfaEnrollmentRequired { .. }));
}

#[tokio::test]
async fn login_stays_a_bare_session_when_policy_is_optional_and_account_is_unenrolled() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;

    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "optional",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    assert!(matches!(result, LoginOutcome::Session(id) if id == user_id));
}

#[tokio::test]
async fn login_challenges_an_enrolled_account_even_when_policy_is_only_optional() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    enroll_and_confirm(&db, &ring, user_id).await;

    let result = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "optional",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    assert!(matches!(result, LoginOutcome::MfaRequired { .. }));
}

#[tokio::test]
async fn complete_pending_login_succeeds_with_a_valid_code_and_the_correct_purpose() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired, got {outcome:?}");
    };

    let code = next_code(&totp);
    let resolved = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await
    .unwrap();
    assert_eq!(resolved, user_id);
}

/// BAU-12e (F11): a correct password with a second factor pending does not
/// stamp `last_login`; only issuing the session after the factor does.
#[tokio::test]
async fn last_login_is_stamped_only_when_the_session_is_issued() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;
    let last_login = || async {
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT last_login FROM user_account WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&db)
        .await
        .expect("read last_login")
    };
    let before = last_login().await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired, got {outcome:?}");
    };
    assert_eq!(
        last_login().await,
        before,
        "a pending second factor stamps nothing"
    );

    let resolved = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &next_code(&totp),
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await
    .unwrap();
    attome_auth::refresh::issue(
        &db,
        resolved,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: 3600,
            absolute_secs: 30 * 86_400,
        },
        &pepper(),
    )
    .await
    .expect("issue the session");
    let after = last_login().await;
    assert!(
        after.is_some() && after != before,
        "issuing the session stamps last_login"
    );
}

/// BAU-28 (F18): once a pending token's challenge is consumed, a correct code
/// for a later step is refused before the verifier runs, so it does not
/// advance `last_accepted_totp_step` and the user's current code survives.
#[tokio::test]
async fn a_dead_challenge_runs_no_verifier() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;
    let last_step = || async {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_accepted_totp_step FROM user_mfa
             WHERE user_ref = $1 AND is_deleted = false",
        )
        .bind(user_id)
        .fetch_one(&db)
        .await
        .expect("read last_accepted_totp_step")
    };

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired, got {outcome:?}");
    };
    let complete = |code: String| {
        let (db, ring, redis, jwt_ring, pending_token) = (
            db.clone(),
            ring.clone(),
            redis.clone(),
            jwt_ring.clone(),
            pending_token.clone(),
        );
        async move {
            mfa::complete_pending_login(
                &db,
                &ring,
                &redis,
                &pending_token,
                &code,
                &jwt_ring,
                JWT_ISSUER,
                JWT_ISSUER,
                MAX_ATTEMPTS,
            )
            .await
        }
    };
    // Exhaust the challenge with wrong codes.
    for _ in 0..MAX_ATTEMPTS {
        assert!(complete("000000".to_owned()).await.is_err());
    }
    let before = last_step().await;

    let result = complete(next_code(&totp)).await;
    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
    assert_eq!(
        last_step().await,
        before,
        "a dead challenge must not spend the user's current TOTP step"
    );
}

/// BAU-17 (D-627): recovery codes are stored as peppered HMAC, and verifying
/// one, right or wrong, takes no KDF permit.
#[tokio::test]
async fn an_hmac_recovery_code_takes_no_kdf_permit() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _) = create_test_user(&db).await;
    let (_totp, codes) = enroll_and_confirm(&db, &ring, user_id).await;
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT code_hash FROM user_mfa_recovery_code WHERE user_ref = $1")
            .bind(user_id)
            .fetch_all(&db)
            .await
            .expect("read recovery hashes");
    assert_eq!(stored.len(), codes.len());
    assert!(
        stored.iter().all(|hash| hash.starts_with("hmac256:v")),
        "{stored:?}"
    );

    let before = attome_auth::password::kdf_operations_started();
    let wrong = mfa::verify_recovery_code(&db, &pepper(), user_id, "ZZZZ-ZZZZ").await;
    assert!(matches!(wrong, Err(AppError::Unauthorized)), "{wrong:?}");
    mfa::verify_recovery_code(&db, &pepper(), user_id, &codes[0])
        .await
        .expect("a current code verifies");
    assert_eq!(
        attome_auth::password::kdf_operations_started(),
        before,
        "an HMAC recovery code must not run the KDF"
    );
}

/// D-627 rule 2: a recovery code written as Argon2 before D-627 still
/// verifies, once, during the compatibility window.
#[tokio::test]
async fn an_argon2_recovery_code_still_verifies() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _) = create_test_user(&db).await;
    enroll_and_confirm(&db, &ring, user_id).await;
    let legacy = "ABCD-EFGH";
    sqlx::query("INSERT INTO user_mfa_recovery_code (user_ref, code_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(
            hash_password_async(attome_auth::NewPassword::platform_generated(legacy))
                .await
                .expect("argon2 hash"),
        )
        .execute(&db)
        .await
        .expect("insert a legacy argon2 row");

    mfa::verify_recovery_code(&db, &pepper(), user_id, legacy)
        .await
        .expect("an argon2 row still verifies");
    let replay = mfa::verify_recovery_code(&db, &pepper(), user_id, legacy).await;
    assert!(matches!(replay, Err(AppError::Unauthorized)), "{replay:?}");
}

/// BAU-15b: a correct login against a hash weaker than the current
/// `auth.kdf` parameters succeeds and leaves the hash upgraded; the upgraded
/// hash still verifies, and a second login leaves it alone.
#[tokio::test]
async fn a_login_upgrades_a_hash_below_the_current_kdf_parameters() {
    use argon2::password_hash::{PasswordHasher, phc::PasswordHash};
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let weak_params = argon2::Params::new(
        argon2::Params::MIN_M_COST,
        argon2::Params::MIN_T_COST,
        argon2::Params::MIN_P_COST,
        None,
    )
    .expect("argon2's minimum parameters");
    let weak = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        weak_params,
    )
    .hash_password(b"correct-password")
    .expect("weak hash")
    .to_string();
    sqlx::query("UPDATE user_account SET password_hash = $1 WHERE id = $2")
        .bind(&weak)
        .bind(user_id)
        .execute(&db)
        .await
        .expect("store the weak hash");

    let login = || {
        accounts::login(
            &db,
            &redis,
            &email,
            "correct-password",
            false,
            "off",
            &jwt_ring,
            JWT_ISSUER,
            JWT_ISSUER,
        )
    };
    let outcome = login().await.expect("a correct login succeeds");
    assert!(matches!(outcome, LoginOutcome::Session(id) if id == user_id));

    let stored: String = sqlx::query_scalar("SELECT password_hash FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db)
        .await
        .expect("read the hash");
    let m_cost = |phc: &str| {
        argon2::Params::try_from(&PasswordHash::new(phc).expect("PHC"))
            .expect("params")
            .m_cost()
    };
    assert_ne!(stored, weak, "the weak hash must be replaced");
    assert_eq!(
        m_cost(&stored),
        argon2::Params::DEFAULT_M_COST,
        "the upgrade uses the current (default) parameters"
    );

    login().await.expect("the upgraded hash verifies");
    let again: String = sqlx::query_scalar("SELECT password_hash FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db)
        .await
        .expect("read the hash again");
    assert_eq!(again, stored, "a current hash is not rehashed again");
}

/// Pending MFA tokens intentionally remain stateless. The accepted TOTP
/// counter is nevertheless single-use, so replaying a captured pending token
/// and the same valid code cannot mint a second session.
#[tokio::test]
async fn complete_pending_login_rejects_replayed_totp_code_with_a_fresh_pending_token() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let first = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .expect("first MFA challenge");
    let LoginOutcome::MfaRequired {
        pending_token: first_token,
    } = first
    else {
        panic!("expected MfaRequired");
    };

    let code = next_code(&totp);
    mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &first_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await
    .expect("first code use succeeds");

    let second = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .expect("second MFA challenge");
    let LoginOutcome::MfaRequired {
        pending_token: second_token,
    } = second
    else {
        panic!("expected MfaRequired");
    };

    let replay = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &second_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await;
    assert!(matches!(replay, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn complete_pending_login_rejects_a_wrong_code() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired");
    };

    let result = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        "000000",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn an_enrollment_pending_token_cannot_be_used_to_complete_a_login_challenge() {
    // Cross-purpose rejection (D-069): a token minted for the "must enroll
    // first" path must never satisfy the "already enrolled, prove
    // possession" path even though both are signed under the same ring.
    let user_id = Uuid::now_v7();
    let jwt_ring = test_jwt_ring();
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let token = mfa::start_challenge(
        &redis,
        user_id,
        TokenType::MfaPendingEnroll,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();

    let result = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &token,
        "000000",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

/// P-mfa-challenge-hardening: the challenge marker is single-use — even a
/// pending token whose TOTP secret would still generate the *next* valid
/// code cannot be satisfied a second time once its marker is consumed.
#[tokio::test]
async fn complete_pending_login_rejects_reuse_of_an_already_consumed_pending_token() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired");
    };

    let code = next_code(&totp);
    mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await
    .expect("first use succeeds");

    // Reset the enrollment's own replay guard (last_accepted_totp_step) so
    // this isn't just re-proving that already-covered check — presenting
    // the exact same code again against the same (now-consumed) pending
    // token must still be rejected purely on the marker being gone, with
    // the per-enrollment TOTP-step guard taken out of the picture entirely.
    sqlx::query("UPDATE user_mfa SET last_accepted_totp_step = NULL WHERE user_ref = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("reset fixture TOTP counter");

    let replay = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        MAX_ATTEMPTS,
    )
    .await;
    assert!(matches!(replay, Err(AppError::Unauthorized)));
}

/// P-mfa-challenge-hardening: wrong-code submissions against one pending
/// token are capped — once `max_attempts` failures are recorded, the
/// challenge is dead even for a subsequent *correct* code.
#[tokio::test]
async fn complete_pending_login_locks_out_after_max_attempts_wrong_codes() {
    const CEILING: u32 = 3;
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired");
    };

    for attempt in 0..CEILING {
        let result = mfa::complete_pending_login(
            &db,
            &ring,
            &redis,
            &pending_token,
            "000000",
            &jwt_ring,
            JWT_ISSUER,
            JWT_ISSUER,
            CEILING,
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Unauthorized)),
            "attempt {attempt} should be rejected as a wrong code"
        );
    }

    // The ceiling is now hit — even the genuinely correct current code must
    // be rejected, because the marker was deleted once the ceiling tripped.
    let code = totp.generate_current().to_string();
    let result = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        CEILING,
    )
    .await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

/// P-mfa-challenge-hardening §6's still-open item as of D-149/D-168: "the
/// concurrent-request test proving the Lua script's atomicity under real
/// load." `complete_pending_login_locks_out_after_max_attempts_wrong_codes`
/// above only ever submits one request at a time — it cannot catch a broken
/// implementation that decomposed `MFA_CHALLENGE_STEP_SCRIPT` into separate
/// non-atomic GET/INCR/DEL round trips (the exact undercounting race class
/// ENTERPRISE-AUDIT-2026-07-24.md finding #7 documents against the ZSET rate
/// limiter), because sequential calls can never race each other.
///
/// This test cannot reach into `mfa.rs`'s private `challenge_step`/Redis
/// counter from an external integration-test crate, so it proves the same
/// atomicity guarantee via `complete_pending_login`'s own observable
/// contract instead of peeking at the raw Lua-script state directly:
/// firing `CEILING - 1` genuinely concurrent wrong-code requests (real OS
/// thread parallelism via a multi-threaded runtime + `tokio::spawn`, not
/// just interleaved `.await` points on one thread, synchronized to actually
/// overlap via a `Barrier`) must record *exactly* `CEILING - 1` failures —
/// no more, no fewer. A non-atomic INCR could either lose updates (some
/// concurrent writers reading the same stale counter value, undercounting —
/// the challenge survives with fewer recorded failures than requests, which
/// would then let a subsequent genuinely correct code wrongly succeed one
/// attempt "too early" relative to the ceiling) or, depending on the bug
/// shape, overcount (killing the marker before the real ceiling, a false
/// lockout). Submitting the real correct code immediately afterward
/// distinguishes both failure modes from the correct atomic behavior: it
/// must succeed, because exactly `CEILING - 1` failures were recorded and
/// the challenge is still alive with exactly one attempt of headroom.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn complete_pending_login_attempt_ceiling_is_exact_under_concurrent_wrong_code_requests() {
    const CEILING: u32 = 5;
    const CONCURRENT_WRONG_ATTEMPTS: usize = (CEILING - 1) as usize;

    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired");
    };

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CONCURRENT_WRONG_ATTEMPTS));
    let mut handles = Vec::with_capacity(CONCURRENT_WRONG_ATTEMPTS);
    for _ in 0..CONCURRENT_WRONG_ATTEMPTS {
        let db = db.clone();
        let redis = redis.clone();
        let ring = ring.clone();
        let jwt_ring = jwt_ring.clone();
        let pending_token = pending_token.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            mfa::complete_pending_login(
                &db,
                &ring,
                &redis,
                &pending_token,
                "000000",
                &jwt_ring,
                JWT_ISSUER,
                JWT_ISSUER,
                CEILING,
            )
            .await
        }));
    }
    for handle in handles {
        let result = handle.await.expect("task did not panic");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    // Exactly CEILING - 1 failures were (or should have been) recorded. If
    // the script's INCR were not atomic under real concurrency, this could
    // fail in either direction: an undercount leaves the marker alive but
    // this assertion (correct code succeeds) would still pass by accident,
    // so the decisive proof is the companion test below, which checks the
    // over-the-ceiling side. This assertion catches the overcount/false-
    // lockout direction — if concurrent writers each incremented from a
    // stale read and collectively pushed the counter to CEILING or beyond
    // despite only CEILING - 1 requests, the marker would already be dead
    // and this call would wrongly return Unauthorized.
    let code = next_code(&totp);
    let result = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        CEILING,
    )
    .await;
    assert!(
        result.is_ok(),
        "challenge should still be alive with exactly one attempt of headroom \
         after {CONCURRENT_WRONG_ATTEMPTS} concurrent wrong-code requests against \
         a ceiling of {CEILING} — got {result:?} instead, meaning the concurrent \
         attempt counter did not land on exactly {CONCURRENT_WRONG_ATTEMPTS}"
    );
}

/// Companion to the test above, proving the undercount direction: firing
/// `2 * CEILING` concurrent wrong-code requests must reliably trip the
/// ceiling and kill the marker — no request may "win" a race and let a
/// later genuinely correct code slip through as if the challenge were still
/// alive. `complete_pending_login`'s return value is deliberately
/// indistinguishable between "wrong code" and "ceiling already tripped"
/// (anti-enumeration, see `mfa.rs`'s `consume_or_record_failure` doc
/// comment), so every individual concurrent call is expected to return
/// `Unauthorized` regardless; the decisive assertion is the same as the
/// sequential ceiling test — a subsequent genuinely correct code must also
/// be rejected, because the marker must be dead, not merely "some requests
/// got through and some didn't" due to a lost-update race.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn complete_pending_login_ceiling_reliably_trips_under_concurrent_wrong_code_requests() {
    const CEILING: u32 = 5;
    const CONCURRENT_WRONG_ATTEMPTS: usize = (2 * CEILING) as usize;

    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let ring = test_mfa_ring();
    let jwt_ring = test_jwt_ring();
    let (user_id, email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let outcome = accounts::login(
        &db,
        &redis,
        &email,
        "correct-password",
        false,
        "required",
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
    )
    .await
    .unwrap();
    let LoginOutcome::MfaRequired { pending_token } = outcome else {
        panic!("expected MfaRequired");
    };

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CONCURRENT_WRONG_ATTEMPTS));
    let mut handles = Vec::with_capacity(CONCURRENT_WRONG_ATTEMPTS);
    for _ in 0..CONCURRENT_WRONG_ATTEMPTS {
        let db = db.clone();
        let redis = redis.clone();
        let ring = ring.clone();
        let jwt_ring = jwt_ring.clone();
        let pending_token = pending_token.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            mfa::complete_pending_login(
                &db,
                &ring,
                &redis,
                &pending_token,
                "000000",
                &jwt_ring,
                JWT_ISSUER,
                JWT_ISSUER,
                CEILING,
            )
            .await
        }));
    }
    for handle in handles {
        let result = handle.await.expect("task did not panic");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    let code = totp.generate_current().to_string();
    let result = mfa::complete_pending_login(
        &db,
        &ring,
        &redis,
        &pending_token,
        &code,
        &jwt_ring,
        JWT_ISSUER,
        JWT_ISSUER,
        CEILING,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "ceiling must have tripped and killed the marker after \
         {CONCURRENT_WRONG_ATTEMPTS} concurrent wrong-code requests against a \
         ceiling of {CEILING}, but the genuinely correct code was accepted \
         ({result:?}) — a request must have won a race against the ceiling"
    );
}

#[tokio::test]
async fn recovery_code_is_single_use() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    let (_totp, codes) = enroll_and_confirm(&db, &ring, user_id).await;
    let code = &codes[0];

    mfa::verify_recovery_code(&db, &pepper(), user_id, code)
        .await
        .expect("first use succeeds");
    let second = mfa::verify_recovery_code(&db, &pepper(), user_id, code).await;
    assert!(matches!(second, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn regenerating_recovery_codes_invalidates_the_previous_batch() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    let (totp, old_codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let code = next_code(&totp);
    let new_codes = mfa::regenerate_recovery_codes(&db, &ring, &pepper(), user_id, &code)
        .await
        .expect("regenerate");
    assert_eq!(new_codes.len(), 10);

    // None of the old codes work anymore.
    for old_code in &old_codes {
        let result = mfa::verify_recovery_code(&db, &pepper(), user_id, old_code).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
    // A code from the fresh batch does.
    mfa::verify_recovery_code(&db, &pepper(), user_id, &new_codes[0])
        .await
        .expect("new code must work");
}

#[tokio::test]
async fn disable_requires_proof_of_possession() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    enroll_and_confirm(&db, &ring, user_id).await;

    let result = mfa::disable(&db, &ring, &pepper(), user_id, "000000").await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
    assert!(mfa::is_enrolled(&db, user_id).await.unwrap());
}

#[tokio::test]
async fn disable_then_reenroll_round_trips() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let code = next_code(&totp);
    mfa::disable(&db, &ring, &pepper(), user_id, &code)
        .await
        .expect("disable");
    assert!(!mfa::is_enrolled(&db, user_id).await.unwrap());

    // A fresh enrollment must be possible immediately after.
    enroll_and_confirm(&db, &ring, user_id).await;
    assert!(mfa::is_enrolled(&db, user_id).await.unwrap());
}

/// Security contract I11 (attome-auth hardening 1.5): a six-digit code goes to
/// the TOTP verifier only. The account holds a recovery code that is itself
/// six digits, which the old TOTP-then-recovery fall-through would have
/// accepted; with one verifier per shape, `disable` must reject it.
#[tokio::test]
async fn disable_never_tries_the_recovery_verifier_for_a_digit_code() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let live_codes: Vec<String> = [now - TOTP_STEP_SECS, now, now + TOTP_STEP_SECS]
        .iter()
        .map(|t| totp.generate(*t).to_string())
        .collect();
    let decoy = ["123456", "654321", "112233"]
        .into_iter()
        .find(|c| !live_codes.iter().any(|live| live == c))
        .expect("three distinct decoys cannot all be live TOTP codes");

    let decoy_hash = hash_password_async(attome_auth::NewPassword::platform_generated(decoy))
        .await
        .expect("hash");
    sqlx::query("INSERT INTO user_mfa_recovery_code (user_ref, code_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&decoy_hash)
        .execute(&db)
        .await
        .expect("insert a digit-shaped recovery code");

    let result = mfa::disable(&db, &ring, &pepper(), user_id, decoy).await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a wrong TOTP code must not be retried as a recovery code, got {result:?}"
    );
    assert!(mfa::is_enrolled(&db, user_id).await.unwrap());
}

/// Security contract I11: a genuine recovery code still disables MFA, and
/// input matching neither shape is rejected without disabling anything.
#[tokio::test]
async fn disable_accepts_a_recovery_code_and_rejects_other_shapes() {
    let db = skip_if_no_db!(pool().await);
    let ring = test_mfa_ring();
    let (user_id, _email) = create_test_user(&db).await;
    let (_totp, codes) = enroll_and_confirm(&db, &ring, user_id).await;

    for malformed in [
        "",
        "12345",
        "1234567",
        "abcd-efgh",
        "ABCD0EFGH",
        "ABCD-EFG1",
    ] {
        let result = mfa::disable(&db, &ring, &pepper(), user_id, malformed).await;
        assert!(
            matches!(result, Err(AppError::Unauthorized)),
            "{malformed:?} matches neither shape and must be rejected, got {result:?}"
        );
    }
    assert!(mfa::is_enrolled(&db, user_id).await.unwrap());

    mfa::disable(&db, &ring, &pepper(), user_id, &codes[0])
        .await
        .expect("a recovery code must disable MFA");
    assert!(!mfa::is_enrolled(&db, user_id).await.unwrap());
}

/// D-130's §6 rotate-then-rewrap scenario, run live: enroll under key A, add
/// key B + flip active, verify a login code still verifies pre-rewrap (the
/// stored blob still names key A, which the ring still holds), run the
/// rewrap job, confirm the row now names key B, then retire key A entirely
/// and confirm verification still succeeds using only key B.
#[tokio::test]
async fn rotating_the_mfa_encryption_key_survives_rewrap_and_retirement() {
    let db = skip_if_no_db!(pool().await);
    let key_a = "aa".repeat(32);
    let key_b = "bb".repeat(32);

    let mut ring = KeyRing {
        keys: std::iter::once(("key-a".to_string(), key_a)).collect(),
        active_key_id: "key-a".to_string(),
    };

    // rewrap_secrets scans the whole table by design (a real rewrap job must
    // converge every row) -- other tests in this file/binary populate the
    // same shared throwaway database with rows under a different ring
    // (test_mfa_ring()'s "legacy" key id), which this test's own two-key
    // ring can't decrypt. Scope the scan to only rows created from this
    // point on, exactly the way a real cursor-resumed rewrap pass would.
    let before_id: Uuid = sqlx::query_scalar("SELECT id FROM user_mfa ORDER BY id DESC LIMIT 1")
        .fetch_optional(&db)
        .await
        .expect("fetch high-water mark")
        .unwrap_or_else(Uuid::nil);

    let (user_id, _email) = create_test_user(&db).await;
    let (totp, _codes) = enroll_and_confirm(&db, &ring, user_id).await;

    let stored: String =
        sqlx::query_scalar("SELECT secret_encrypted FROM user_mfa WHERE user_ref = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch stored secret");
    assert_eq!(
        attome_auth::envelope::stored_key_id(&stored).as_deref(),
        Some("key-a")
    );

    // Add key B, flip active -- both keys now live in the ring.
    ring.keys.insert("key-b".to_string(), key_b);
    ring.active_key_id = "key-b".to_string();

    // Pre-rewrap: the row is still ciphertext-under-key-a, but the ring
    // still holds key-a, so login verification must still succeed.
    let code = next_code(&totp);
    mfa::verify_code(&db, &ring, user_id, &code)
        .await
        .expect("verify pre-rewrap");

    // Rewrap converges the row onto the new active key.
    let progress = mfa::rewrap_secrets(&db, &ring, Some(before_id), 100)
        .await
        .expect("rewrap");
    assert_eq!(progress.rewrapped, 1);

    let stored_after: String =
        sqlx::query_scalar("SELECT secret_encrypted FROM user_mfa WHERE user_ref = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch stored secret after rewrap");
    assert_eq!(
        attome_auth::envelope::stored_key_id(&stored_after).as_deref(),
        Some("key-b")
    );

    // A second pass is idempotent -- nothing left to rewrap.
    let progress2 = mfa::rewrap_secrets(&db, &ring, Some(before_id), 100)
        .await
        .expect("rewrap again");
    assert_eq!(progress2.rewrapped, 0);

    // Retire key A entirely -- verification must still succeed on key B alone.
    ring.keys.remove("key-a");
    // The prior verification consumed this time-step. This test exercises key
    // rotation, not replay prevention, so reset its isolated fixture without
    // sleeping for a new 30-second time-step.
    sqlx::query("UPDATE user_mfa SET last_accepted_totp_step = NULL WHERE user_ref = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("reset fixture TOTP counter");
    let code2 = totp.generate_current().to_string();
    mfa::verify_code(&db, &ring, user_id, &code2)
        .await
        .expect("verify after key A retired");
}

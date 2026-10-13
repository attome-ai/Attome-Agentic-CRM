//! Integration test for `attome_auth::accounts::register` —
//! P-account-state-enforcement (audit finding #2, post-audit review item 6):
//! registering with a *disabled* account's email must be rejected, not
//! silently mint a second, brand-new active account with a clean privilege
//! slate (the `core_systemuser_email_unique` partial index, migration 0024,
//! only covers active rows, so a naive INSERT would otherwise succeed).
//!
//! Requires a live Postgres — same convention as `reset_flow.rs`. Run
//! manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test register_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::register;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test —
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

/// The pepper ring invitation tokens hash with (attome-auth hardening 1.4). Any
/// well-formed ring works; issue and validation only need to agree.
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-auth-test-pepper-0123456789abcdef", &[])
}

#[tokio::test]
async fn a_fresh_email_registers_successfully() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-fresh-{}@example.invalid", Uuid::now_v7());

    let result = register(&db, &email, "some-password-123", None, &test_ring()).await;
    assert!(result.is_ok(), "a fresh email must register: {result:?}");
}

#[tokio::test]
async fn a_live_duplicate_email_is_rejected_as_conflict() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-dup-{}@example.invalid", Uuid::now_v7());

    register(&db, &email, "first-password-123", None, &test_ring())
        .await
        .expect("first registration must succeed");
    let result = register(&db, &email, "second-password-456", None, &test_ring()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a live duplicate email must be a conflict, got {result:?}"
    );
}

/// The regression this plan closes: previously the `ON CONFLICT`-free plain
/// INSERT only failed on `core_systemuser_email_unique`, a *partial* index
/// that a disabled row sits outside of — so this call would have silently
/// succeeded and created a second active account before the fix.
#[tokio::test]
async fn a_disabled_accounts_email_is_rejected_not_resurrected() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-disabled-{}@example.invalid", Uuid::now_v7());

    let original_id = register(&db, &email, "original-password-123", None, &test_ring())
        .await
        .expect("first registration must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(original_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = register(&db, &email, "attacker-password-789", None, &test_ring()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "registering a disabled account's email must be rejected as a conflict \
         (same shape as a live duplicate, no enumeration delta), got {result:?}"
    );

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account WHERE email = $1 AND is_active = TRUE",
    )
    .bind(&email)
    .fetch_one(&db)
    .await
    .expect("count active rows for this email");
    assert_eq!(
        active_count, 0,
        "no second active account may exist for a disabled email"
    );
}

/// D-121: `login`/`register` must agree on case/whitespace canonicalization
/// — previously `login` used `lower(email) = lower($1)` but `register`
/// compared the raw column, so a disabled `User@Example.com` could be
/// bypassed by registering ` user@example.com ` (different case, extra
/// whitespace). Both now normalize through `email_identity::normalize_email`
/// before ever touching the database.
#[tokio::test]
async fn a_disabled_accounts_email_is_rejected_regardless_of_case_or_whitespace() {
    let db = skip_if_no_db!(pool().await);
    let unique = Uuid::now_v7();
    let canonical_email = format!("register-case-{unique}@example.invalid");

    let original_id = register(
        &db,
        &canonical_email,
        "original-password-123",
        None,
        &test_ring(),
    )
    .await
    .expect("first registration must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(original_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let differently_cased = format!("  Register-Case-{unique}@Example.Invalid  ");
    let result = register(
        &db,
        &differently_cased,
        "attacker-password-789",
        None,
        &test_ring(),
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a disabled account's email must be rejected under any case/whitespace \
         variant, got {result:?}"
    );

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account WHERE lower(btrim(email)) = lower(btrim($1)) AND is_active = TRUE",
    )
    .bind(&canonical_email)
    .fetch_one(&db)
    .await
    .expect("count active rows for this email");
    assert_eq!(
        active_count, 0,
        "no second active account may exist under a different case/whitespace variant"
    );
}

/// D-121: the advisory lock (`email_identity::try_lock_email`) must actually
/// serialize two concurrent registrations for the same email — a plain
/// READ COMMITTED check-then-insert would let both transactions read "no
/// conflict" before either commits. Exactly one of the two concurrent
/// registrations must succeed.
#[tokio::test]
async fn concurrent_registrations_for_the_same_email_only_one_wins() {
    let email = format!("register-race-{}@example.invalid", Uuid::now_v7());

    let db_a = skip_if_no_db!(pool().await);
    let db_b = skip_if_no_db!(pool().await);
    let email_a = email.clone();
    let email_b = email.clone();

    let ring = test_ring();
    let (result_a, result_b) = tokio::join!(
        register(&db_a, &email_a, "password-a-123", None, &ring),
        register(&db_b, &email_b, "password-b-456", None, &ring),
    );

    let ok_count = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent registration for the same email must succeed, got \
         a={result_a:?} b={result_b:?}"
    );

    let db = skip_if_no_db!(pool().await);
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account WHERE email = $1 AND is_active = TRUE",
    )
    .bind(&email)
    .fetch_one(&db)
    .await
    .expect("count active rows for this email");
    assert_eq!(
        active_count, 1,
        "the race must never leave two active accounts for the same email"
    );
}

// ── P-registration-gating Phase 2 (D-128) — invitation-gated registration ──

#[tokio::test]
async fn a_valid_invitation_token_for_the_same_email_lets_registration_proceed() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-invited-{}@example.invalid", Uuid::now_v7());
    let admin_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active) \
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(admin_id)
    .bind(format!("admin-{admin_id}@example.invalid"))
    .bind("unused-hash")
    .execute(&db)
    .await
    .expect("seed the inviting admin user");

    let issued = attome_auth::invitation::issue(&db, &email, admin_id, 24, &test_ring())
        .await
        .expect("mint an invitation");

    let result = register(
        &db,
        &email,
        "invitee-password-123",
        Some(&issued.bearer),
        &test_ring(),
    )
    .await;
    assert!(
        result.is_ok(),
        "a valid invitation for this exact email must let registration proceed: {result:?}"
    );

    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM invitation_token WHERE id = $1")
            .bind(issued.id)
            .fetch_one(&db)
            .await
            .expect("fetch the invitation row");
    assert!(
        used_at.is_some(),
        "the invitation must be consumed (used_at set) once registration succeeds"
    );
}

#[tokio::test]
async fn an_invitation_token_reused_after_registration_is_rejected() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-invited-reuse-{}@example.invalid", Uuid::now_v7());
    let admin_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active) \
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(admin_id)
    .bind(format!("admin-{admin_id}@example.invalid"))
    .bind("unused-hash")
    .execute(&db)
    .await
    .expect("seed the inviting admin user");

    let issued = attome_auth::invitation::issue(&db, &email, admin_id, 24, &test_ring())
        .await
        .expect("mint an invitation");
    register(
        &db,
        &email,
        "invitee-password-123",
        Some(&issued.bearer),
        &test_ring(),
    )
    .await
    .expect("first use of the invitation must succeed");

    let other_email = format!(
        "register-invited-reuse-2-{}@example.invalid",
        Uuid::now_v7()
    );
    let result = register(
        &db,
        &other_email,
        "second-password-456",
        Some(&issued.bearer),
        &test_ring(),
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a consumed invitation must not be usable a second time, got {result:?}"
    );
}

#[tokio::test]
async fn an_invitation_token_presented_with_a_different_email_is_rejected() {
    let db = skip_if_no_db!(pool().await);
    let invited_email = format!(
        "register-invited-mismatch-{}@example.invalid",
        Uuid::now_v7()
    );
    let attacker_email = format!(
        "register-invited-mismatch-attacker-{}@example.invalid",
        Uuid::now_v7()
    );
    let admin_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active) \
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(admin_id)
    .bind(format!("admin-{admin_id}@example.invalid"))
    .bind("unused-hash")
    .execute(&db)
    .await
    .expect("seed the inviting admin user");

    let issued = attome_auth::invitation::issue(&db, &invited_email, admin_id, 24, &test_ring())
        .await
        .expect("mint an invitation");

    let result = register(
        &db,
        &attacker_email,
        "attacker-password-789",
        Some(&issued.bearer),
        &test_ring(),
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a well-formed invitation for a different email must be rejected, got {result:?}"
    );
}

/// Security contract I2 (attome-auth hardening 1.2): the password policy runs
/// inside the engine, before any account row is written.
#[tokio::test]
async fn a_password_below_the_policy_minimum_is_rejected_and_creates_no_account() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-weak-{}@example.invalid", Uuid::now_v7());

    let result = register(&db, &email, "short-pw", None, &test_ring()).await;
    assert!(
        matches!(result, Err(AppError::Validation(_))),
        "an 8-character password must fail the policy, got {result:?}"
    );

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE email = $1)")
            .bind(&email)
            .fetch_one(&db)
            .await
            .expect("check for the account row");
    assert!(
        !exists,
        "a rejected registration must not create an account"
    );
}

/// D-500: new invitations are stored as peppered HMAC, and an invitation row
/// hashed any other way (here Argon2) does not let registration proceed.
#[tokio::test]
async fn new_invitations_are_hmac_and_an_argon2_invitation_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let admin_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active) \
         VALUES ($1, $2, $3, now(), true)",
    )
    .bind(admin_id)
    .bind(format!("admin-{admin_id}@example.invalid"))
    .bind("unused-hash")
    .execute(&db)
    .await
    .expect("seed the inviting admin user");

    let new_email = format!("register-hmac-invite-{}@example.invalid", Uuid::now_v7());
    let issued = attome_auth::invitation::issue(&db, &new_email, admin_id, 24, &test_ring())
        .await
        .expect("mint an invitation");
    let stored: String =
        sqlx::query_scalar("SELECT secret_hash FROM invitation_token WHERE id = $1")
            .bind(issued.id)
            .fetch_one(&db)
            .await
            .expect("fetch secret_hash");
    assert!(
        stored.starts_with("hmac256"),
        "a new invitation must be stored as peppered HMAC, got {stored}"
    );

    let legacy_email = format!("register-legacy-invite-{}@example.invalid", Uuid::now_v7());
    let legacy_public_id = Uuid::now_v7();
    let legacy_secret = "legacy-argon2-invitation-secret-0123";
    let legacy_hash = attome_auth::password::hash_password_async(
        attome_auth::NewPassword::platform_generated(legacy_secret),
    )
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO invitation_token (email, invited_by_ref, public_id, secret_hash, expires_at) \
         VALUES ($1, $2, $3, $4, now() + interval '24 hours')",
    )
    .bind(&legacy_email)
    .bind(admin_id)
    .bind(legacy_public_id)
    .bind(&legacy_hash)
    .execute(&db)
    .await
    .expect("insert a legacy Argon2 invitation");

    let bearer = format!("{legacy_public_id}.{legacy_secret}");
    let result = register(
        &db,
        &legacy_email,
        "legacy-invitee-password-123",
        Some(&bearer),
        &test_ring(),
    )
    .await;
    assert!(
        result.is_err(),
        "an Argon2 invitation row must be refused: {result:?}"
    );
}

/// BAU-27 (F17): no KDF work runs while the registration transaction is open.
/// The password is prepared first; `register_in_tx` starts no KDF operation.
#[tokio::test]
async fn no_kdf_permit_is_held_inside_an_open_transaction() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("register-no-kdf-in-tx-{}@example.invalid", Uuid::now_v7());
    let password = attome_auth::accounts::RegistrationPassword::prepare("some-password-123")
        .await
        .expect("prepare");

    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let before = attome_auth::password::kdf_operations_started();
    attome_auth::accounts::register_in_tx(&mut tx, &email, password, None, &test_ring())
        .await
        .expect("register in tx");
    assert_eq!(
        attome_auth::password::kdf_operations_started(),
        before,
        "no KDF operation may start inside the registration transaction"
    );
    tx.commit().await.expect("commit");

    let weak = attome_auth::accounts::RegistrationPassword::prepare("short").await;
    assert!(weak.is_err(), "the policy still runs before any hashing");
}

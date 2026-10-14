//! Integration tests for `attome_security::accounts` (Google/OIDC identity linking).
//!
//! Requires a live Postgres (`DATABASE_URL`) â€” see `tests/resolver.rs` header for the
//! full convention (throwaway DB, NEVER attome_dev, not wired into CI yet).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-security --test accounts -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::accounts::{
    link_google_account, link_google_to_user, link_identity_to_user, link_oidc_identity,
    list_identities_for_user,
};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Every linking path still takes the active licence (a parameter kept for its
/// callers), but since CLEANUP-REVIEW 1.2 (D-778) no path reads it to gate
/// admission: there is no seat cap. The tests below prove that.
fn test_license() -> attome_modules::ModuleSet {
    attome_modules::ModuleSet::core_only()
}

/// The module set the seat tests pass: seats are gone (v2 has no licences),
/// so any set must admit every account.
async fn license_with_no_free_seats(_db: &DbPool) -> attome_modules::ModuleSet {
    attome_modules::ModuleSet::core_only()
}

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

/// Regression test for the migration-0024 partial-unique-index regression:
/// `core_systemuser_email_unique` became `UNIQUE (email) WHERE (is_active IS NULL
/// OR is_active = TRUE)`, but `link_google_account`'s `ON CONFLICT (email)` didn't
/// repeat that predicate. Postgres requires an ON CONFLICT target to match a
/// partial index's predicate exactly to infer it, so every single call â€” not just
/// ones that hit an actual duplicate â€” failed with 42P10 ("no unique or exclusion
/// constraint matching the ON CONFLICT specification"), surfacing as a 500 on
/// POST /api/v1/auth/google. This must succeed on the very first call.
#[tokio::test]
async fn link_google_account_first_login_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-{}@example.test", Uuid::now_v7());
    let google_sub = format!("google-sub-first-login-{}", Uuid::now_v7());

    let user_id = link_google_account(&db, &email, &google_sub, &test_license())
        .await
        .expect("first-time link_google_account must not 500");

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch inserted row");
    assert_eq!(stored_sub, google_sub);
}

/// Same regression, exercised via the repeat-login (actual conflict) path.
///
/// BAU-8c (G-7): the repeat login presents the SAME subject. A *different*
/// one for an already-linked address is the reassigned-address takeover and is
/// refused by `link_google_account_refuses_a_second_sub_for_a_linked_email`
/// below — this test keeps the same-sub case green (it is the ordinary
/// "sign in again tomorrow" path).
#[tokio::test]
async fn link_google_account_repeat_login_upserts() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-{}@example.test", Uuid::now_v7());
    let sub = format!("sub-{}", Uuid::now_v7());

    let first_id = link_google_account(&db, &email, &sub, &test_license())
        .await
        .expect("first login must not 500");
    let second_id = link_google_account(&db, &email, &sub, &test_license())
        .await
        .expect("repeat login must not 500");

    assert_eq!(
        first_id, second_id,
        "same email must resolve to the same user"
    );

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(second_id)
            .fetch_one(&db)
            .await
            .expect("fetch updated row");
    assert_eq!(
        stored_sub, sub,
        "a repeat login keeps the subject the account is anchored on"
    );
}

/// BAU-F22 / BAU-8c (G-7) — Google sign-in is anchored on the provider's
/// `sub`, not on the email. A Workspace address reassigned to a new person
/// yields the *same verified email* with a *new* `sub`; before this anchor
/// the already-google-linked branch skipped the takeover gate entirely and the
/// `ON CONFLICT (email) DO UPDATE` overwrote `google_sub`, handing the
/// previous holder's account to whoever now controls the mailbox.
#[tokio::test]
async fn link_google_account_refuses_a_second_sub_for_a_linked_email() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-reassigned-{}@example.test", Uuid::now_v7());
    let original_sub = format!("google-sub-original-{}", Uuid::now_v7());
    let reassigned_sub = format!("google-sub-reassigned-{}", Uuid::now_v7());

    let original_id = link_google_account(&db, &email, &original_sub, &test_license())
        .await
        .expect("the first login for this address must link");

    let result = link_google_account(&db, &email, &reassigned_sub, &test_license()).await;

    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a second Google sub for an already-linked email must be refused with a \
         conflict, got {result:?}"
    );

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(original_id)
            .fetch_one(&db)
            .await
            .expect("fetch the original row");
    assert_eq!(
        stored_sub, original_sub,
        "the refused login must not have overwritten the anchored google_sub"
    );

    // And no second account may have been created for the same address.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_account WHERE email = $1")
        .bind(&email)
        .fetch_one(&db)
        .await
        .expect("count rows for the address");
    assert_eq!(
        rows, 1,
        "the refused login must not have created a second row"
    );
}

/// Same regression class, via the OIDC `link_external_identity` path
/// (its own `ON CONFLICT (email)` INSERT into `user_account` on first-seen sub).
#[tokio::test]
async fn link_oidc_identity_first_login_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-{}@example.test", Uuid::now_v7());
    let sub = format!("oidc-sub-first-login-{}", Uuid::now_v7());

    link_oidc_identity(&db, "test-provider", &sub, &email, &test_license())
        .await
        .expect("first-time link_oidc_identity must not 500");
}

// â”€â”€ P-account-state-enforcement (audit finding #2) regression tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A disabled user must never be reactivated by an existing Google link â€” the
/// original bug: `link_google_account`'s UPDATE branch unconditionally set
/// `is_active = true` on every repeat login.
#[tokio::test]
async fn link_google_account_rejects_a_disabled_existing_user() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-disabled-{}@example.test", Uuid::now_v7());
    let google_sub = format!("google-sub-disabled-{}", Uuid::now_v7());

    let user_id = link_google_account(&db, &email, &google_sub, &test_license())
        .await
        .expect("first login must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = link_google_account(&db, &email, &google_sub, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a disabled user's repeat Google login must be rejected, got {result:?}"
    );

    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch user row");
    assert_eq!(
        is_active,
        Some(false),
        "the rejected login must not have flipped is_active back to true"
    );
}

/// The adjacent resurrection bug (post-audit review item 6): a disabled row's
/// email sits outside the partial unique index, so a naive `ON CONFLICT`
/// upsert would silently INSERT a brand-new *active* account with the same
/// email instead of being blocked.
#[tokio::test]
async fn link_google_account_rejects_resurrection_of_a_disabled_email() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-resurrect-{}@example.test", Uuid::now_v7());
    let original_sub = format!("google-sub-original-{}", Uuid::now_v7());
    let new_sub = format!("google-sub-new-{}", Uuid::now_v7());

    let original_id = link_google_account(&db, &email, &original_sub, &test_license())
        .await
        .expect("first login must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(original_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = link_google_account(&db, &email, &new_sub, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a Google login for a disabled email must not mint a fresh active account, got {result:?}"
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

/// Same regression as `link_google_account_rejects_a_disabled_existing_user`,
/// via the OIDC `link_external_identity` existing-link branch.
#[tokio::test]
async fn link_oidc_identity_rejects_a_disabled_existing_user() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-disabled-{}@example.test", Uuid::now_v7());
    let sub = format!("oidc-sub-disabled-{}", Uuid::now_v7());

    let user_id = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license())
        .await
        .expect("first login must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a disabled user's repeat OIDC login must be rejected, got {result:?}"
    );
}

/// Same resurrection regression as the Google case, via the OIDC
/// first-login-by-email JIT-link branch (a never-before-seen provider `sub`).
#[tokio::test]
async fn link_oidc_identity_rejects_resurrection_of_a_disabled_email() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-resurrect-{}@example.test", Uuid::now_v7());
    let original_sub = format!("oidc-sub-original-{}", Uuid::now_v7());
    let new_sub = format!("oidc-sub-new-{}", Uuid::now_v7());

    let original_id =
        link_oidc_identity(&db, "test-provider", &original_sub, &email, &test_license())
            .await
            .expect("first login must succeed");
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(original_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = link_oidc_identity(&db, "test-provider", &new_sub, &email, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "an OIDC login for a disabled email (new sub, never linked before) must not \
         mint a fresh active account, got {result:?}"
    );
}

// â”€â”€ Enterprise-audit remediation Phase 2.1: federation must not silently
// take over an account that already has a different sign-in method â”€â”€â”€â”€â”€â”€â”€â”€

/// An OIDC login must not JIT-link to an account that already has a
/// password â€” the core takeover scenario the audit flagged: any
/// operator-configured IdP asserting a victim's email must not be enough to
/// gain access to a password-protected account with zero confirmation.
#[tokio::test]
async fn link_oidc_identity_rejects_linking_to_a_password_account() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-conflict-{}@example.test", Uuid::now_v7());

    // Simulate an existing password-registered account (attome_auth::accounts
    // ::register lives in a different crate; inserting directly here keeps
    // this test focused on attome_security::accounts's own guard).
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, is_active) \
         VALUES (uuidv7(), $1, 'not-a-real-hash', true)",
    )
    .bind(&email)
    .execute(&db)
    .await
    .expect("seed a password-registered account");

    let sub = format!("oidc-sub-conflict-{}", Uuid::now_v7());
    let result = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "an OIDC login must not silently link to an account that already has \
         a password, got {result:?}"
    );

    let identity_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_identity WHERE provider_sub = $1")
            .bind(&sub)
            .fetch_one(&db)
            .await
            .expect("count identity rows");
    assert_eq!(
        identity_count, 0,
        "the rejected link must not have written a user_identity row"
    );
}

/// Same guard, but from a *different* OIDC provider than one already linked
/// â€” proves the check isn't password-specific, it also blocks a second IdP
/// from silently attaching to an account another IdP already claimed.
#[tokio::test]
async fn link_oidc_identity_rejects_linking_from_a_second_provider() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-second-provider-{}@example.test", Uuid::now_v7());
    let sub_a = format!("provider-a-sub-{}", Uuid::now_v7());
    let sub_b = format!("provider-b-sub-{}", Uuid::now_v7());

    link_oidc_identity(&db, "provider-a", &sub_a, &email, &test_license())
        .await
        .expect("first provider's first login must succeed");

    let result = link_oidc_identity(&db, "provider-b", &sub_b, &email, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a second provider asserting the same email must not silently link \
         to the account the first provider already claimed, got {result:?}"
    );
}

/// A repeat login from the SAME provider (existing `(provider_key, sub)`
/// link) must keep working â€” the guard only applies to the first-seen-sub
/// JIT-link branch, never to an already-established link.
#[tokio::test]
async fn link_oidc_identity_repeat_login_same_provider_still_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-repeat-{}@example.test", Uuid::now_v7());
    let sub = format!("oidc-sub-repeat-{}", Uuid::now_v7());

    let first_id = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license())
        .await
        .expect("first login must succeed");
    let second_id = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license())
        .await
        .expect("repeat login from the same provider must not be blocked");
    assert_eq!(first_id, second_id);
}

/// A brand-new account (no password, no other identity) still JIT-creates
/// exactly as before â€” the guard must not turn every first-time OIDC signup
/// into a conflict.
#[tokio::test]
async fn link_oidc_identity_brand_new_account_still_jit_creates() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("oidc-fresh-{}@example.test", Uuid::now_v7());
    let sub = format!("oidc-sub-fresh-{}", Uuid::now_v7());

    link_oidc_identity(&db, "test-provider", &sub, &email, &test_license())
        .await
        .expect("a brand-new account with no prior credential must JIT-create, not conflict");
}

/// The same guard applies to `link_google_account`: an existing
/// password-registered account must not be silently claimed by a Google
/// login asserting the same email.
#[tokio::test]
async fn link_google_account_rejects_linking_to_a_password_account() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-conflict-{}@example.test", Uuid::now_v7());

    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, is_active) \
         VALUES (uuidv7(), $1, 'not-a-real-hash', true)",
    )
    .bind(&email)
    .execute(&db)
    .await
    .expect("seed a password-registered account");

    let google_sub = format!("google-sub-conflict-{}", Uuid::now_v7());
    let result = link_google_account(&db, &email, &google_sub, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a Google login must not silently link to an account that already \
         has a password, got {result:?}"
    );
}

/// B4 (TECHNICAL-DUE-DILIGENCE-2026-08-24, T1-4): a Google-only account is
/// a credentialed account too, even though its credential lives in
/// `user_account.google_sub` rather than `password_hash` or an
/// `user_identity` row. An OIDC IdP asserting that email must
/// get exactly the same rejection a password account gets â€” before this
/// guard consulted `google_sub`, `link_external_identity` upserted straight
/// onto the victim's row and issued a session.
#[tokio::test]
async fn link_oidc_identity_rejects_linking_to_a_google_only_account() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-only-{}@example.test", Uuid::now_v7());
    let google_sub = format!("google-only-sub-{}", Uuid::now_v7());

    // Seed the victim through the real Google path: no password, no
    // user_identity row â€” google_sub is the ONLY credential.
    let victim_id = link_google_account(&db, &email, &google_sub, &test_license())
        .await
        .expect("seed a Google-only account");

    let sub = format!("oidc-sub-vs-google-{}", Uuid::now_v7());
    let result = link_oidc_identity(&db, "test-provider", &sub, &email, &test_license()).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "an OIDC login must not silently link to a Google-only account, \
         got {result:?}"
    );

    let identity_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_identity WHERE provider_sub = $1")
            .bind(&sub)
            .fetch_one(&db)
            .await
            .expect("count identity rows");
    assert_eq!(
        identity_count, 0,
        "the rejected link must not have written a user_identity row"
    );

    let (stored_sub, password_hash): (String, Option<String>) =
        sqlx::query_as("SELECT google_sub, password_hash FROM user_account WHERE id = $1")
            .bind(victim_id)
            .fetch_one(&db)
            .await
            .expect("fetch the victim row");
    assert_eq!(
        stored_sub, google_sub,
        "the victim's Google link is untouched"
    );
    assert!(password_hash.is_none(), "the seed really was Google-only");
}

/// The Google-only guard must not break the Google-only account's OWN repeat
/// login: `link_google_account` skips the guard when `google_sub` is already
/// set, so a second Google sign-in still resolves to the same user.
#[tokio::test]
async fn link_google_account_repeat_login_on_a_google_only_account_still_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-only-repeat-{}@example.test", Uuid::now_v7());
    let google_sub = format!("google-only-repeat-sub-{}", Uuid::now_v7());

    let first_id = link_google_account(&db, &email, &google_sub, &test_license())
        .await
        .expect("first Google login must succeed");
    let second_id = link_google_account(&db, &email, &google_sub, &test_license())
        .await
        .expect("a repeat Google login on a Google-only account must not be rejected");
    assert_eq!(first_id, second_id);
}

// â”€â”€ P-federation-linking-policy Â§4.3 â€” link_identity_to_user â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// The session-gated self-service linking and admin-pre-provisioning write
// path â€” unlike link_oidc_identity/link_google_account,
// this never guesses a target account by email; user_ref is always given by
// the caller (a live session or an admin), so none of the email-collision
// guards above apply here by design.

async fn seed_bare_active_user(db: &DbPool, email: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO user_account (id, email, is_active, email_verified) \
         VALUES (uuidv7(), $1, true, true) RETURNING id",
    )
    .bind(email)
    .fetch_one(db)
    .await
    .expect("seed a bare active account with no password/identity")
}

#[tokio::test]
async fn link_identity_to_user_first_link_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("link-target-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    let sub = format!("link-sub-{}", Uuid::now_v7());

    link_identity_to_user(&db, user_id, "test-provider", &sub, &email)
        .await
        .expect("first-time link_identity_to_user must not fail");

    let stored_user_ref: Uuid = sqlx::query_scalar(
        "SELECT user_ref FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind("test-provider")
    .bind(&sub)
    .fetch_one(&db)
    .await
    .expect("fetch inserted user_identity row");
    assert_eq!(stored_user_ref, user_id);
}

/// Re-linking the same (provider_key, sub) to the SAME user must be a
/// no-op/idempotent success, not a Conflict â€” a user re-running the
/// self-service linking flow, or an admin re-running pre-provisioning,
/// should never be punished for repeating themselves.
#[tokio::test]
async fn link_identity_to_user_repeat_link_same_user_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("link-target-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    let sub = format!("link-sub-{}", Uuid::now_v7());

    link_identity_to_user(&db, user_id, "test-provider", &sub, &email)
        .await
        .expect("first link must succeed");
    link_identity_to_user(&db, user_id, "test-provider", &sub, &email)
        .await
        .expect("re-linking the same (provider_key, sub) to the same user must not fail");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind("test-provider")
    .bind(&sub)
    .fetch_one(&db)
    .await
    .expect("count user_identity rows");
    assert_eq!(count, 1, "must not insert a second row");
}

/// The whole point of this function: a (provider_key, sub) already linked to
/// a DIFFERENT user must never be silently reassigned â€” that would be a
/// worse takeover primitive than the email-JIT one this plan closes, since
/// it would bypass reject_if_linking_would_bypass_existing_credential
/// entirely (this function never runs that check â€” user_ref is given, not
/// guessed).
#[tokio::test]
async fn link_identity_to_user_rejects_reassigning_to_a_different_user() {
    let db = skip_if_no_db!(test_db().await);
    let email_a = format!("link-a-{}@example.test", Uuid::now_v7());
    let email_b = format!("link-b-{}@example.test", Uuid::now_v7());
    let user_a = seed_bare_active_user(&db, &email_a).await;
    let user_b = seed_bare_active_user(&db, &email_b).await;
    let sub = format!("link-sub-{}", Uuid::now_v7());

    link_identity_to_user(&db, user_a, "test-provider", &sub, &email_a)
        .await
        .expect("first link (to user_a) must succeed");

    let result = link_identity_to_user(&db, user_b, "test-provider", &sub, &email_b).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "linking the same identity to a second user must be rejected, got {result:?}"
    );

    let stored_user_ref: Uuid = sqlx::query_scalar(
        "SELECT user_ref FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind("test-provider")
    .bind(&sub)
    .fetch_one(&db)
    .await
    .expect("fetch the row");
    assert_eq!(
        stored_user_ref, user_a,
        "the original link must be unchanged"
    );
}

/// Defense-in-depth check, mirroring `link_oidc_identity_rejects_a_disabled_
/// existing_user` above: a concurrent admin disable between session-start and
/// IdP-callback (or between pre-provisioning and first login) must not let a
/// disabled account acquire a new sign-in method.
#[tokio::test]
async fn link_identity_to_user_rejects_a_disabled_target_user() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("link-disabled-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the account");
    let sub = format!("link-sub-{}", Uuid::now_v7());

    let result = link_identity_to_user(&db, user_id, "test-provider", &sub, &email).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "linking to a disabled account must be rejected, got {result:?}"
    );
}

// â”€â”€ P-federation-linking-policy Â§4.3(a) UI support â€” list_identities_for_user â”€
// Backs the new `GET /api/v1/auth/identity-links` self-service read endpoint
// (crates/server/src/auth.rs) the `/settings/security` page uses to render
// which providers are already linked.

#[tokio::test]
async fn list_identities_for_user_returns_only_this_users_links_ordered_by_link_time() {
    let db = skip_if_no_db!(test_db().await);
    let email_a = format!("list-links-a-{}@example.test", Uuid::now_v7());
    let email_b = format!("list-links-b-{}@example.test", Uuid::now_v7());
    let user_a = seed_bare_active_user(&db, &email_a).await;
    let user_b = seed_bare_active_user(&db, &email_b).await;

    let sub_1 = format!("list-sub-1-{}", Uuid::now_v7());
    let sub_2 = format!("list-sub-2-{}", Uuid::now_v7());
    let sub_other = format!("list-sub-other-{}", Uuid::now_v7());

    link_identity_to_user(&db, user_a, "provider-one", &sub_1, &email_a)
        .await
        .expect("link 1 for user_a must succeed");
    link_identity_to_user(&db, user_a, "provider-two", &sub_2, &email_a)
        .await
        .expect("link 2 for user_a must succeed");
    link_identity_to_user(&db, user_b, "provider-one", &sub_other, &email_b)
        .await
        .expect("link for user_b must succeed");

    let links = list_identities_for_user(&db, user_a)
        .await
        .expect("list_identities_for_user must not fail");

    assert_eq!(
        links.len(),
        2,
        "must return exactly user_a's two links, never user_b's, got {links:?}"
    );
    assert_eq!(links[0].0, "provider-one", "oldest link first");
    assert_eq!(links[1].0, "provider-two", "then the second link");
    assert!(
        links.iter().all(|(_, email, _)| email == &email_a),
        "every row's email must be user_a's, got {links:?}"
    );
}

#[tokio::test]
async fn list_identities_for_user_returns_empty_for_a_user_with_no_linked_identities() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("list-links-none-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;

    let links = list_identities_for_user(&db, user_id)
        .await
        .expect("list_identities_for_user must not fail for a user with no links");
    assert!(
        links.is_empty(),
        "a user who never linked anything must get an empty list, got {links:?}"
    );
}

// â”€â”€ link_google_to_user â€” Google's already-authenticated linking analog â”€â”€â”€â”€â”€
// Same `user_id`-is-given posture as link_identity_to_user above (no
// email-JIT guessing), plus one Google-specific rule: the linked identity's
// email must match the target account's own email.

#[tokio::test]
async fn link_google_to_user_first_link_succeeds() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("gauth-target-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    let sub = format!("gauth-sub-{}", Uuid::now_v7());

    link_google_to_user(&db, user_id, &sub, &email)
        .await
        .expect("first-time link_google_to_user must not fail");

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch updated row");
    assert_eq!(stored_sub, sub);
}

/// Re-linking the same Google identity to the SAME account must be a
/// no-op/idempotent success â€” a user re-clicking "Link" shouldn't be punished
/// for repeating themselves, same posture as link_identity_to_user's
/// equivalent test.
#[tokio::test]
async fn link_google_to_user_repeat_link_same_user_is_idempotent() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("gauth-target-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    let sub = format!("gauth-sub-{}", Uuid::now_v7());

    link_google_to_user(&db, user_id, &sub, &email)
        .await
        .expect("first link must succeed");
    link_google_to_user(&db, user_id, &sub, &email)
        .await
        .expect("re-linking the same Google identity to the same account must not fail");

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch row");
    assert_eq!(stored_sub, sub);
}

/// The whole point of this function: a Google identity already linked to a
/// DIFFERENT account must never be silently reassigned.
#[tokio::test]
async fn link_google_to_user_rejects_reassigning_to_a_different_user() {
    let db = skip_if_no_db!(test_db().await);
    let email_a = format!("gauth-a-{}@example.test", Uuid::now_v7());
    let email_b = format!("gauth-b-{}@example.test", Uuid::now_v7());
    let user_a = seed_bare_active_user(&db, &email_a).await;
    let user_b = seed_bare_active_user(&db, &email_b).await;
    let sub = format!("gauth-sub-{}", Uuid::now_v7());

    link_google_to_user(&db, user_a, &sub, &email_a)
        .await
        .expect("first link (to user_a) must succeed");

    let result = link_google_to_user(&db, user_b, &sub, &email_b).await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "linking the same Google identity to a second account must be rejected, got {result:?}"
    );

    let stored_sub: String =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_a)
            .fetch_one(&db)
            .await
            .expect("fetch user_a's row");
    assert_eq!(stored_sub, sub, "the original link must be unchanged");

    let user_b_sub: Option<String> =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_b)
            .fetch_one(&db)
            .await
            .expect("fetch user_b's row");
    assert_eq!(
        user_b_sub, None,
        "the rejected link must not have written to user_b's row"
    );
}

/// Defense-in-depth check, mirroring link_identity_to_user_rejects_a_disabled_
/// target_user: a concurrent admin disable must not let a disabled account
/// acquire a new sign-in method.
#[tokio::test]
async fn link_google_to_user_rejects_a_disabled_target_user() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("gauth-disabled-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &email).await;
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the account");
    let sub = format!("gauth-sub-{}", Uuid::now_v7());

    let result = link_google_to_user(&db, user_id, &sub, &email).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "linking to a disabled account must be rejected, got {result:?}"
    );
}

/// The Google-specific rule with no equivalent in link_identity_to_user: the
/// verified Google email must match the target account's own email, or a
/// linked-but-unreachable identity would result (see link_google_to_user's
/// doc comment for why â€” google_login's existing-account lookup is entirely
/// email-driven, unlike user_identity's provider-sub join key).
#[tokio::test]
async fn link_google_to_user_rejects_a_mismatched_email() {
    let db = skip_if_no_db!(test_db().await);
    let account_email = format!("gauth-owner-{}@example.test", Uuid::now_v7());
    let google_email = format!("gauth-different-{}@example.test", Uuid::now_v7());
    let user_id = seed_bare_active_user(&db, &account_email).await;
    let sub = format!("gauth-sub-{}", Uuid::now_v7());

    let result = link_google_to_user(&db, user_id, &sub, &google_email).await;
    assert!(
        matches!(result, Err(AppError::Validation(_))),
        "a Google identity whose email doesn't match the account's own email \
         must be rejected, got {result:?}"
    );

    let stored_sub: Option<String> =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("fetch row");
    assert_eq!(
        stored_sub, None,
        "the rejected link must not have written google_sub"
    );
}

// -- CLEANUP-REVIEW 1.2: no seat gate on the federation JIT paths ---------

/// CLEANUP-REVIEW 1.2 (D-778): account creation takes no seat gate. A
/// federated first login creates the account even when the licence row
/// reports zero free seats; the licence no longer caps anything.
#[tokio::test]
async fn oidc_jit_creates_a_new_account_even_with_no_free_seats() {
    let db = skip_if_no_db!(test_db().await);
    let license = license_with_no_free_seats(&db).await;
    let email = format!("oidc-no-seat-cap-{}@example.test", Uuid::now_v7());

    link_oidc_identity(
        &db,
        "seat-gate-provider",
        &format!("seat-gate-sub-{}", Uuid::now_v7()),
        &email,
        &license,
    )
    .await
    .expect("a federated JIT create must succeed with no seat cap");

    let created: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE email = $1)")
            .bind(&email)
            .fetch_one(&db)
            .await
            .expect("check the created email");
    assert!(created, "the JIT create must have written a row");
}

/// CLEANUP-REVIEW 1.2: the removed seat gate took a deployment-wide lock, so
/// two concurrent first logins could not both create accounts. Both must now
/// succeed.
#[tokio::test]
async fn concurrent_oidc_jit_creates_both_succeed() {
    let db = skip_if_no_db!(test_db().await);
    let license = test_license();
    let a = format!("oidc-concurrent-a-{}@example.test", Uuid::now_v7());
    let b = format!("oidc-concurrent-b-{}@example.test", Uuid::now_v7());
    let sub_a = format!("concurrent-sub-a-{}", Uuid::now_v7());
    let sub_b = format!("concurrent-sub-b-{}", Uuid::now_v7());
    let (ra, rb) = tokio::join!(
        link_oidc_identity(&db, "concurrent-provider", &sub_a, &a, &license),
        link_oidc_identity(&db, "concurrent-provider", &sub_b, &b, &license),
    );
    ra.expect("first concurrent JIT create must succeed");
    rb.expect("second concurrent JIT create must succeed");
}

/// The complement, and the property the old probe's doc comment called out:
/// re-linking an *existing* account consumes no seat, so it must never be
/// blocked by a limit reached after that account registered. Blocking it would
/// lock an existing user out of signing in.
#[tokio::test]
async fn google_relink_of_an_existing_account_is_not_blocked_at_the_seat_limit() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("google-relink-{}@example.test", Uuid::now_v7());

    // Create the account first, with room to spare. BAU-8c: the re-link below
    // must present this same subject — a new one is the reassigned-address
    // takeover, refused regardless of the seat count.
    let sub = format!("google-sub-{}", Uuid::now_v7());
    let user_id = link_google_account(&db, &email, &sub, &test_license())
        .await
        .expect("first link creates the account");

    // Now the deployment is full: this same account's next login must still
    // resolve, because it consumes nothing.
    let license = license_with_no_free_seats(&db).await;
    let again = link_google_account(&db, &email, &sub, &license)
        .await
        .expect("re-linking an existing account must not be seat-gated");
    assert_eq!(again, user_id, "the re-link must resolve the same account");
}

// ── D-786: service principals can never be signed in as ─────────────────────

/// Ensures a credential-less service-principal row exists, the shape
/// `attome-metric`'s and `attome-workflow`'s lazy provisioning creates.
async fn ensure_service_row(db: &DbPool, email: &str) -> Uuid {
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, created_at) \
         VALUES (uuidv7(), $1, $1, true, NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(email)
    .execute(db)
    .await
    .expect("ensure service row");
    sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1 AND is_active")
        .bind(email)
        .fetch_one(db)
        .await
        .expect("service row")
}

#[tokio::test]
async fn oidc_jit_for_a_service_principal_address_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    for email in [
        "metric-service@internal.attome",
        "workflow-system@internal.attome",
    ] {
        let user_id = ensure_service_row(&db, email).await;
        let sub = format!("attacker-{}", Uuid::now_v7());
        let result = link_oidc_identity(&db, "test-provider", &sub, email, &test_license()).await;
        assert!(
            matches!(result, Err(AppError::Forbidden)),
            "{email}: an IdP asserting a service address must be refused, got {result:?}"
        );
        let linked: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_identity WHERE user_ref = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .expect("count links");
        assert_eq!(linked, 0, "{email}: no identity may be linked");
    }
}

#[tokio::test]
async fn google_login_for_a_service_principal_address_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let email = "metric-service@internal.attome";
    ensure_service_row(&db, email).await;
    let result = link_google_account(
        &db,
        &email.to_uppercase(),
        &format!("g-{}", Uuid::now_v7()),
        &test_license(),
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)), "{result:?}");
}

#[tokio::test]
async fn admin_pre_provisioned_link_onto_a_service_principal_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = ensure_service_row(&db, "workflow-system@internal.attome").await;
    // Even when the IdP asserts an ordinary address, the target row decides.
    let result = link_identity_to_user(
        &db,
        user_id,
        "test-provider",
        &format!("admin-sub-{}", Uuid::now_v7()),
        "ordinary@example.test",
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)), "{result:?}");
    let result = link_google_to_user(
        &db,
        user_id,
        &format!("g-{}", Uuid::now_v7()),
        "workflow-system@internal.attome",
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)), "{result:?}");
}

#[tokio::test]
async fn generic_update_cannot_change_a_service_principal_email() {
    let db = skip_if_no_db!(test_db().await);
    let service = ensure_service_row(&db, "metric-service@internal.attome").await;
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let body = |email: serde_json::Value| {
        serde_json::json!({ "email": email })
            .as_object()
            .cloned()
            .unwrap_or_default()
    };
    for email in [
        serde_json::json!("attacker@example.test"),
        serde_json::Value::Null,
    ] {
        let result = attome_security::accounts::guard_service_principal_email_change(
            &mut tx,
            service,
            &body(email.clone()),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Validation(_))),
            "{email}: a service principal's email must be immutable, got {result:?}"
        );
    }
    // Resending the current address (a full-form save) is allowed.
    attome_security::accounts::guard_service_principal_email_change(
        &mut tx,
        service,
        &body(serde_json::json!("metric-service@internal.attome")),
    )
    .await
    .expect("an unchanged address is not a change");
    // An ordinary account keeps an editable email.
    attome_security::accounts::guard_service_principal_email_change(
        &mut tx,
        Uuid::now_v7(),
        &body(serde_json::json!("someone@example.test")),
    )
    .await
    .expect("a non-service row is not guarded");
    tx.rollback().await.expect("rollback");
}

//! Integration test for `attome_auth::accounts::bootstrap_admin` —
//! `crates/server`'s `--bootstrap-admin` CLI flow used to duplicate this as
//! raw SQL directly in `main.rs` (business logic in a thin handler,
//! guidelines §0/§1) and, unlike every other writer of
//! `user_account.email`, never normalized the argv value before
//! comparing/storing it — a mixed-case bootstrap email could store a row
//! `login`'s normalized-email lookup could never match. This file proves the
//! three CLI-facing outcomes and the normalization fix.
//!
//! Requires a live Postgres — same convention as `register_flow.rs`. Run
//! manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test bootstrap_admin_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{BootstrapOutcome, bootstrap_admin};
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

/// Base-auth hardening 2.4: a row that never set `is_active` counts as active.
/// `bootstrap_admin` used to decode the column as a plain `bool`, so a legacy
/// NULL row made the command fail; since migration 0460 such a row takes the
/// TRUE default instead, and bootstrap reports it as already active.
#[tokio::test]
async fn a_row_inserted_without_is_active_is_reported_already_active() {
    let db = skip_if_no_db!(pool().await);
    let id = Uuid::now_v7();
    let email = format!("bootstrap-defaulted-{id}@example.invalid");
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at)
         VALUES ($1, $2, now())",
    )
    .bind(id)
    .bind(&email)
    .execute(&db)
    .await
    .expect("insert a user without an explicit is_active");

    let outcome = bootstrap_admin(&db, &email)
        .await
        .expect("bootstrap must not fail on a row without an explicit is_active");
    match outcome {
        BootstrapOutcome::AlreadyActive { user_id } => assert_eq!(user_id, id),
        other => panic!("expected AlreadyActive for a defaulted row, got {other:?}"),
    }
}

#[tokio::test]
async fn a_fresh_email_creates_an_account_with_a_password() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("bootstrap-fresh-{}@example.invalid", Uuid::now_v7());

    let outcome = bootstrap_admin(&db, &email)
        .await
        .expect("bootstrapping a fresh email must succeed");
    match outcome {
        BootstrapOutcome::Created { password, .. } => {
            assert_eq!(password.len(), 24, "generated password must be 24 chars");
        }
        other => panic!("expected Created for a fresh email, got {other:?}"),
    }
}

#[tokio::test]
async fn re_running_against_an_active_account_grants_no_new_password() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("bootstrap-active-{}@example.invalid", Uuid::now_v7());

    let first = bootstrap_admin(&db, &email)
        .await
        .expect("first bootstrap must succeed");
    let first_id = match first {
        BootstrapOutcome::Created { user_id, .. } => user_id,
        other => panic!("expected Created on first run, got {other:?}"),
    };

    let second = bootstrap_admin(&db, &email)
        .await
        .expect("re-running bootstrap against the same email must succeed");
    match second {
        BootstrapOutcome::AlreadyActive { user_id } => {
            assert_eq!(user_id, first_id, "must resolve to the same existing row");
        }
        other => panic!("expected AlreadyActive on second run, got {other:?}"),
    }

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account WHERE email = $1 AND is_active = TRUE",
    )
    .bind(attome_types::text::normalize_email(&email))
    .fetch_one(&db)
    .await
    .expect("count active rows for this email");
    assert_eq!(
        active_count, 1,
        "re-running bootstrap must never create a second row for the same email"
    );
}

/// The regression this fix closes: the old `crates/server`-local
/// implementation stored the raw argv email (only trimmed, never
/// lowercased), so a mixed-case bootstrap argument could store a row that a
/// normalized-email `login` lookup could never match, and a second bootstrap
/// run with different casing would have inserted a *second* row instead of
/// resolving to the first.
#[tokio::test]
async fn bootstrap_normalizes_email_case_and_whitespace_before_comparing_or_storing() {
    let db = skip_if_no_db!(pool().await);
    let unique = Uuid::now_v7();
    let canonical_email = format!("bootstrap-case-{unique}@example.invalid");

    let first = bootstrap_admin(&db, &canonical_email)
        .await
        .expect("first bootstrap must succeed");
    let first_id = match first {
        BootstrapOutcome::Created { user_id, .. } => user_id,
        other => panic!("expected Created on first run, got {other:?}"),
    };

    let differently_cased = format!("  Bootstrap-Case-{unique}@Example.Invalid  ");
    let second = bootstrap_admin(&db, &differently_cased)
        .await
        .expect("bootstrapping a case/whitespace variant must succeed");
    match second {
        BootstrapOutcome::AlreadyActive { user_id } => {
            assert_eq!(
                user_id, first_id,
                "a case/whitespace variant of an existing email must resolve to \
                 the same row, not create a second one"
            );
        }
        other => panic!("expected AlreadyActive for a case/whitespace variant, got {other:?}"),
    }

    let stored_email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(first_id)
        .fetch_one(&db)
        .await
        .expect("fetch the stored email");
    assert_eq!(
        stored_email,
        attome_types::text::normalize_email(&canonical_email),
        "the stored email must be the normalized form, matching every other writer"
    );
}

#[tokio::test]
async fn a_disabled_accounts_email_is_reported_disabled_not_resurrected() {
    let db = skip_if_no_db!(pool().await);
    let email = format!("bootstrap-disabled-{}@example.invalid", Uuid::now_v7());

    let first = bootstrap_admin(&db, &email)
        .await
        .expect("first bootstrap must succeed");
    let user_id = match first {
        BootstrapOutcome::Created { user_id, .. } => user_id,
        other => panic!("expected Created on first run, got {other:?}"),
    };
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let second = bootstrap_admin(&db, &email)
        .await
        .expect("bootstrap must not error for a disabled row, it must report Disabled");
    assert!(
        matches!(second, BootstrapOutcome::Disabled),
        "a disabled account's email must report Disabled, not resurrect it, got {second:?}"
    );

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account WHERE email = $1 AND is_active = TRUE",
    )
    .bind(attome_types::text::normalize_email(&email))
    .fetch_one(&db)
    .await
    .expect("count active rows for this email");
    assert_eq!(
        active_count, 0,
        "no active account may exist for a disabled email after bootstrap"
    );
}

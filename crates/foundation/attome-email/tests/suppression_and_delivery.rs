//! `attome_email::suppression` and `attome_email::delivery` against real
//! `email_suppression` and `email_delivery` tables (migration `0002_email.sql`).
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`): set `DATABASE_URL` to a PostgreSQL
//! server; without it each test prints SKIP.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_email::delivery::{self, DeliveryStatus, EmailDeliveryKind};
use attome_email::suppression::{self, SuppressionReason};
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// Delegates to `attome_testkit`, whose domain is `.invalid` (RFC 2606) rather
/// than this file's former `.test` — a suppression fixture that ever escaped
/// into a real mail path must be undeliverable by construction.
fn unique_email() -> String {
    attome_testkit::unique_email("email-hardening-test")
}

/// Z8-T3: an unsubscribe stops bulk mail only; a sign-in code still goes.
/// A later hard bounce stops both.
#[tokio::test]
async fn bulk_unsubscribe_does_not_block_a_sign_in_code() {
    use attome_email::EmailStream;
    let pool = skip_if_no_db!(test_pool().await);
    let email = unique_email();

    suppression::suppress(&pool, &email, SuppressionReason::Unsubscribe, None, None)
        .await
        .unwrap();
    assert!(
        suppression::is_suppressed_for(&pool, &email, EmailStream::Bulk)
            .await
            .unwrap()
    );
    assert!(
        !suppression::is_suppressed_for(&pool, &email, EmailStream::Transactional)
            .await
            .unwrap(),
        "a bulk unsubscribe must not block transactional mail"
    );
    assert!(!suppression::is_suppressed(&pool, &email).await.unwrap());

    suppression::suppress(&pool, &email, SuppressionReason::HardBounce, None, None)
        .await
        .unwrap();
    assert!(
        suppression::is_suppressed_for(&pool, &email, EmailStream::Transactional)
            .await
            .unwrap()
    );
    assert!(
        suppression::is_suppressed_for(&pool, &email, EmailStream::Bulk)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn is_suppressed_is_false_for_an_address_never_suppressed() {
    let pool = skip_if_no_db!(test_pool().await);
    let email = unique_email();
    assert!(!suppression::is_suppressed(&pool, &email).await.unwrap());
}

#[tokio::test]
async fn suppress_then_is_suppressed_round_trips_and_normalizes_case() {
    let pool = skip_if_no_db!(test_pool().await);
    let email = unique_email();

    suppression::suppress(
        &pool,
        &email.to_uppercase(),
        SuppressionReason::HardBounce,
        Some("550 mailbox not found"),
        None,
    )
    .await
    .unwrap();

    assert!(
        suppression::is_suppressed(&pool, &email).await.unwrap(),
        "a differently-cased lookup must still find the suppression"
    );
}

#[tokio::test]
async fn suppress_is_idempotent_re_suppressing_the_same_address_updates_in_place() {
    let pool = skip_if_no_db!(test_pool().await);
    let email = unique_email();

    suppression::suppress(
        &pool,
        &email,
        SuppressionReason::HardBounce,
        Some("first"),
        None,
    )
    .await
    .unwrap();
    suppression::suppress(
        &pool,
        &email,
        SuppressionReason::Complaint,
        Some("second"),
        None,
    )
    .await
    .unwrap();

    let rows = suppression::list_paginated(&pool, 0, 200).await.unwrap();
    let matching: Vec<_> = rows.iter().filter(|r| r.email == email).collect();
    assert_eq!(
        matching.len(),
        1,
        "re-suppressing must update the existing active row, not create a second one"
    );
    assert_eq!(matching[0].reason, "complaint");
}

#[tokio::test]
async fn unsuppress_soft_deletes_and_frees_the_address_to_be_suppressed_again() {
    let pool = skip_if_no_db!(test_pool().await);
    let email = unique_email();

    suppression::suppress(&pool, &email, SuppressionReason::AdminManual, None, None)
        .await
        .unwrap();
    let rows = suppression::list_paginated(&pool, 0, 200).await.unwrap();
    let id = rows.iter().find(|r| r.email == email).unwrap().id;

    let removed = suppression::unsuppress(&pool, id).await.unwrap();
    assert!(removed);
    assert!(!suppression::is_suppressed(&pool, &email).await.unwrap());

    // Freed up: suppressing the same address again must succeed, not
    // collide with the soft-deleted row's partial unique index entry.
    suppression::suppress(&pool, &email, SuppressionReason::HardBounce, None, None)
        .await
        .unwrap();
    assert!(suppression::is_suppressed(&pool, &email).await.unwrap());
}

#[tokio::test]
async fn unsuppress_returns_false_for_an_id_that_is_not_an_active_suppression() {
    let pool = skip_if_no_db!(test_pool().await);
    let removed = suppression::unsuppress(&pool, Uuid::now_v7())
        .await
        .unwrap();
    assert!(!removed);
}

#[tokio::test]
async fn delivery_lifecycle_queued_to_sent() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut tx = pool.begin().await.unwrap();
    let id = Uuid::now_v7();
    let email = unique_email();
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::EmailVerification,
        &email,
        "Verify your email",
        Some(Uuid::now_v7()),
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "queued");
    assert_eq!(row.attempts, 0);
    assert_eq!(row.kind, "email_verification");
    assert_eq!(row.recipient, email);

    delivery::mark_sent(&pool, id).await.unwrap();
    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "sent");
    assert!(row.sent_at.is_some());
}

#[tokio::test]
async fn delivery_lifecycle_transient_attempts_then_terminal_failure() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut tx = pool.begin().await.unwrap();
    let id = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::PasswordReset,
        &unique_email(),
        "Reset your password",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    delivery::mark_transient_attempt(&pool, id, "connection refused")
        .await
        .unwrap();
    delivery::mark_transient_attempt(&pool, id, "timed out")
        .await
        .unwrap();
    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "queued",
        "still not terminal after transient attempts"
    );
    assert_eq!(row.attempts, 2);
    assert_eq!(row.last_error.as_deref(), Some("timed out"));

    delivery::mark_terminal(&pool, id, "failed", "gave up")
        .await
        .unwrap();
    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "failed");
    assert_eq!(row.last_error.as_deref(), Some("gave up"));
}

#[tokio::test]
async fn list_paginated_filters_by_status_kind_and_recipient() {
    let pool = skip_if_no_db!(test_pool().await);
    let email_a = unique_email();
    let email_b = unique_email();

    let mut tx = pool.begin().await.unwrap();
    let id_a = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id_a,
        EmailDeliveryKind::Invitation,
        &email_a,
        "You're invited",
        None,
        Some(Uuid::now_v7()),
        None,
    )
    .await
    .unwrap();
    let id_b = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id_b,
        EmailDeliveryKind::PasswordReset,
        &email_b,
        "Reset your password",
        Some(Uuid::now_v7()),
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    delivery::mark_sent(&pool, id_b).await.unwrap();

    let by_recipient = delivery::list_paginated(&pool, None, None, Some(&email_a), 0, 50)
        .await
        .unwrap();
    assert!(by_recipient.iter().any(|r| r.id == id_a));
    assert!(!by_recipient.iter().any(|r| r.id == id_b));

    let by_kind = delivery::list_paginated(&pool, None, Some("invitation"), None, 0, 200)
        .await
        .unwrap();
    assert!(by_kind.iter().any(|r| r.id == id_a));
    assert!(by_kind.iter().all(|r| r.kind == "invitation"));

    let by_status = delivery::list_paginated(&pool, Some("sent"), None, None, 0, 200)
        .await
        .unwrap();
    assert!(by_status.iter().any(|r| r.id == id_b));
    assert!(by_status.iter().all(|r| r.status == "sent"));
}
// ── BEM-4 / BEM-17 — guarded transitions and the terminal vocabulary ──────

/// The vocabulary itself, with no database: every variant round-trips through
/// its wire string, and only `queued` is non-terminal.
#[test]
fn the_delivery_status_vocabulary_round_trips() {
    use std::str::FromStr;
    for status in [
        DeliveryStatus::Queued,
        DeliveryStatus::Sent,
        DeliveryStatus::Failed,
        DeliveryStatus::Suppressed,
        DeliveryStatus::Unknown,
    ] {
        assert_eq!(DeliveryStatus::from_str(status.as_str()).unwrap(), status);
    }
    assert!(DeliveryStatus::from_str("bogus").is_err());
    assert!(!DeliveryStatus::Queued.is_terminal());
    assert!(DeliveryStatus::Unknown.is_terminal());
    assert_eq!(DeliveryStatus::Unknown.as_str(), "unknown");
}

/// BEM-4 acceptance — a transition is guarded on `queued`. A second write after
/// the row is closed out returns `false` and leaves the recorded state alone,
/// so a duplicate apalis execution (or a resend racing the job) cannot rewrite
/// history and cannot resurrect a `failed` row as `sent`.
#[tokio::test]
async fn transitions_are_guarded_on_queued() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut tx = pool.begin().await.unwrap();
    let id = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::PasswordReset,
        &unique_email(),
        "Reset your password",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert!(
        delivery::mark_terminal(&pool, id, DeliveryStatus::Failed, "gave up")
            .await
            .unwrap(),
        "the first terminal write applies"
    );
    assert!(
        !delivery::mark_sent(&pool, id).await.unwrap(),
        "a resolved row must not become sent"
    );
    assert!(
        !delivery::mark_terminal(&pool, id, DeliveryStatus::Suppressed, "late")
            .await
            .unwrap(),
        "a second terminal write is a no-op"
    );
    assert!(
        !delivery::mark_transient_attempt(&pool, id, "late")
            .await
            .unwrap(),
        "a terminal row cannot gain attempts"
    );

    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "failed");
    assert_eq!(row.last_error.as_deref(), Some("gave up"));
    assert_eq!(row.attempts, 1, "the no-op writes must not bump attempts");
}

/// BEM-17 acceptance — the ledger can hold the new terminal state, and it is
/// genuinely terminal: a later attempt is refused.
#[tokio::test]
async fn an_unknown_outcome_is_a_terminal_ledger_status() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut tx = pool.begin().await.unwrap();
    let id = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::Generic,
        &unique_email(),
        "Heads up",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    assert!(
        delivery::mark_terminal(
            &pool,
            id,
            DeliveryStatus::Unknown,
            "no SMTP outcome within 120s",
        )
        .await
        .unwrap()
    );
    let row = delivery::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "unknown");
    assert!(!delivery::mark_sent(&pool, id).await.unwrap());
    assert_eq!(
        delivery::get_by_id(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "unknown",
        "unknown is terminal — the row must never be re-sent blind"
    );
}

/// BEM-4 — an unrecognized status string is refused here rather than reaching
/// the CHECK constraint, so a typo cannot look like a new state.
#[tokio::test]
async fn an_unrecognized_status_string_is_refused() {
    let pool = skip_if_no_db!(test_pool().await);
    let mut tx = pool.begin().await.unwrap();
    let id = Uuid::now_v7();
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::Generic,
        &unique_email(),
        "Heads up",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let err = delivery::mark_terminal(&pool, id, "bogus", "x")
        .await
        .expect_err("an unknown status must be refused");
    assert!(matches!(err, sqlx::Error::Decode(_)), "got {err:?}");
    assert_eq!(
        delivery::get_by_id(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "queued",
        "the refused write must not have touched the row"
    );
}

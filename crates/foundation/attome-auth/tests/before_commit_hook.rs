//! Audit plan item 3.6 and the part A D-062 gap: attome-auth mutations that the
//! server audits run a caller's `attome_db::BeforeCommit` hook inside their own
//! transaction. A failing hook (in production, a failed audit write) leaves
//! no session, no revocation, no MFA enrolment and no password change behind;
//! a succeeding hook is handed the account id.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-auth --test before_commit_hook -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Mutex;

use attome_auth::auth_context::AuthContext;
use attome_auth::refresh::RefreshLifetimes;
use attome_auth::{PepperRing, mfa, refresh, reset};
use attome_config::KeyRing;
use attome_db::{BeforeCommit, DbPool, HookFuture, NoHook, Tx};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::{Builder, RedisConfig};
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

async fn create_test_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active)
         VALUES ($1, $2, now(), true)",
    )
    .bind(id)
    .bind(format!("hook-test-{id}@example.invalid"))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

fn ring() -> PepperRing {
    PepperRing::new(0, "before-commit-hook-test-pepper-0123456789", &[])
}

fn lifetimes() -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: 30 * 86_400,
    }
}

fn unconnected_redis() -> attome_cache::RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

struct FailingHook;

impl BeforeCommit<Uuid> for FailingHook {
    fn before_commit<'a>(&'a self, _tx: &'a mut Tx<'_>, _user: &'a Uuid) -> HookFuture<'a> {
        Box::pin(async { Err(AppError::internal("forced hook failure")) })
    }
}

#[derive(Default)]
struct RecordingHook(Mutex<Vec<Uuid>>);

impl BeforeCommit<Uuid> for RecordingHook {
    fn before_commit<'a>(&'a self, _tx: &'a mut Tx<'_>, user: &'a Uuid) -> HookFuture<'a> {
        self.0.lock().expect("lock").push(*user);
        Box::pin(async { Ok(()) })
    }
}

async fn refresh_rows(db: &DbPool, user_id: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE revoked_at IS NOT NULL)
         FROM refresh_token WHERE user_ref = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
    .expect("count refresh rows")
}

#[tokio::test]
async fn a_failing_hook_leaves_no_session_and_no_revocation() {
    let db = skip_if_no_db!(pool().await);
    let user = create_test_user(&db).await;

    refresh::issue_with(
        &db,
        user,
        &AuthContext::password(),
        lifetimes(),
        &ring(),
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails issuance");
    assert_eq!(
        refresh_rows(&db, user).await,
        (0, 0),
        "no refresh family survives"
    );

    let hook = RecordingHook::default();
    let issued = refresh::issue_with(
        &db,
        user,
        &AuthContext::password(),
        lifetimes(),
        &ring(),
        &hook,
    )
    .await
    .expect("issue");
    assert_eq!(*hook.0.lock().expect("lock"), vec![user]);
    assert_eq!(refresh_rows(&db, user).await, (1, 0));

    refresh::revoke_returning_user_with(&db, &issued.bearer, &ring(), &FailingHook)
        .await
        .expect_err("a failing hook fails the revocation");
    assert_eq!(
        refresh_rows(&db, user).await,
        (1, 0),
        "the token is still live"
    );

    let owner = refresh::revoke_returning_user_with(&db, &issued.bearer, &ring(), &NoHook)
        .await
        .expect("revoke");
    assert_eq!(owner, Some(user));
    assert_eq!(refresh_rows(&db, user).await, (1, 1));
}

#[tokio::test]
async fn a_failing_hook_rolls_back_mfa_enrolment_and_a_password_reset() {
    let db = skip_if_no_db!(pool().await);
    let user = create_test_user(&db).await;
    let mfa_ring = KeyRing::single("ab".repeat(32));

    assert!(
        mfa::enroll_with(&db, &mfa_ring, user, &FailingHook)
            .await
            .is_err(),
        "a failing hook fails enrolment"
    );
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_mfa WHERE user_ref = $1")
        .bind(user)
        .fetch_one(&db)
        .await
        .expect("count mfa rows");
    assert_eq!(pending, 0, "no pending factor survives");

    sqlx::query("UPDATE user_account SET password_hash = 'old-hash' WHERE id = $1")
        .bind(user)
        .execute(&db)
        .await
        .expect("give the account a local password");
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(user)
        .fetch_one(&mut *tx)
        .await
        .expect("email");
    let issued = reset::request_in_tx(&mut tx, &email, 30, &ring())
        .await
        .expect("request reset")
        .expect("known account");
    tx.commit().await.expect("commit");

    let (result, subject) = reset::confirm_with_subject_hook(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &issued.bearer,
        "a-brand-new-password-9",
        &ring(),
        &FailingHook,
    )
    .await;
    assert!(result.is_err(), "a failing hook fails the reset");
    assert_eq!(subject, Some(user));
    let (password_set, token_used): (bool, bool) = sqlx::query_as(
        "SELECT (SELECT password_hash <> 'old-hash' FROM user_account WHERE id = $1),
                EXISTS (SELECT 1 FROM password_reset_token WHERE user_ref = $1 AND used_at IS NOT NULL)",
    )
    .bind(user)
    .fetch_one(&db)
    .await
    .expect("read reset state");
    assert!(!password_set, "the new password did not commit");
    assert!(!token_used, "the token was not consumed");
}

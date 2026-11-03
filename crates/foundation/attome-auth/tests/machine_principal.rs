//! AH3-T3: a service or agent account (`principal_kind` <> 0, migration 0389)
//! never signs in interactively, even with a password set: the password
//! sign-in, a new session, a refresh, a password reset and MFA enrolment are
//! refused with the masked `Unauthorized`; a person still gets each.
//!
//! ```powershell
//! cargo test -p attome-auth --test machine_principal -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::auth_context::AuthContext;
use attome_auth::refresh::RefreshLifetimes;
use attome_auth::{PepperRing, accounts, mfa, refresh, reset};
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::{Builder, RedisConfig};
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn ring() -> PepperRing {
    PepperRing::new(0, "machine-principal-test-pepper-0123456789", &[])
}

fn jwt_ring() -> KeyRing {
    KeyRing::single("machine-principal-test-secret-0123456789".to_string())
}

/// Never connected: the refused paths stop before Redis.
fn unconnected_redis() -> attome_cache::Store {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    attome_cache::Store::Redis(Builder::from_config(config).build_pool(1).unwrap())
}

fn lifetimes() -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: 86_400,
    }
}

/// An active account of `kind` with the password `correct-password`.
async fn account(db: &DbPool, kind: i16) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("machine-principal-{id}@example.invalid");
    let hash = attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(
        "correct-password",
    ))
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO user_account \
             (id, email, password_hash, created_at, is_active, email_verified, principal_kind) \
         VALUES ($1, $2, $3, now(), true, true, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .bind(kind)
    .execute(db)
    .await
    .expect("insert account");
    (id, email)
}

#[tokio::test]
async fn agent_principal_cannot_log_in_reset_or_enrol_mfa() {
    let db = skip_if_no_db!(pool().await);
    for kind in [1_i16, 2] {
        let (agent, email) = account(&db, kind).await;

        let login = accounts::login(
            &db,
            &unconnected_redis(),
            &email,
            "correct-password",
            false,
            "optional",
            &jwt_ring(),
            "machine-principal-test",
            "attome",
        )
        .await;
        assert!(
            matches!(login, Err(AppError::Unauthorized)),
            "kind {kind}: password sign-in"
        );

        let session =
            refresh::issue(&db, agent, &AuthContext::password(), lifetimes(), &ring()).await;
        assert!(
            matches!(session, Err(AppError::Unauthorized)),
            "kind {kind}: a new session"
        );
        let families: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_token WHERE user_ref = $1")
                .bind(agent)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(families, 0, "kind {kind}: nothing written");

        let renewed = accounts::issue_access_token(
            &db,
            agent,
            Uuid::now_v7(),
            &jwt_ring(),
            "machine-principal-test",
            "attome",
            300,
        )
        .await;
        assert!(
            matches!(renewed, Err(AppError::Unauthorized)),
            "kind {kind}: a refresh"
        );

        let mut tx = attome_db::tx::begin(&db).await.unwrap();
        let reset = reset::request_in_tx(&mut tx, &email, 30, &ring())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(reset.is_none(), "kind {kind}: no reset token");

        let enrolled = mfa::enroll(&db, &KeyRing::single("ab".repeat(32)), agent).await;
        assert!(
            matches!(enrolled, Err(AppError::Unauthorized)),
            "kind {kind}: MFA enrolment"
        );
    }

    // A person still gets a session, a refresh and a reset.
    let (person, email) = account(&db, 0).await;
    let issued = refresh::issue(&db, person, &AuthContext::password(), lifetimes(), &ring())
        .await
        .expect("a person's session");
    accounts::issue_access_token(
        &db,
        person,
        issued.family_id,
        &jwt_ring(),
        "machine-principal-test",
        "attome",
        300,
    )
    .await
    .expect("a person's refresh");
    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    let reset = reset::request_in_tx(&mut tx, &email, 30, &ring())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(reset.is_some(), "a person's reset token");
}

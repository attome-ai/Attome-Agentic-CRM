//! Q5-T4: a browser remembered after a second factor skips it at the next
//! password sign-in, until the account's auth epoch moves on; a policy that
//! does not remember devices (an administrator's) never skips it. Needs a
//! throwaway Postgres and Redis, like `login_mfa.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{
    self, LoginOutcome, MfaPolicySource, RememberedDevice, UserMfaRequirement,
};
use attome_auth::mfa;
use attome_auth::password::hash_password_async;
use attome_auth::remembered_device;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::*;
use totp_rs::{Algorithm, Builder, Secret};
use uuid::Uuid;

const JWT_ISSUER: &str = "attome-remembered-device-test";

fn pepper() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "remembered-device-test-pepper-0123456789", &[])
}

fn mfa_ring() -> KeyRing {
    KeyRing::single("cd".repeat(32))
}

fn jwt_ring() -> KeyRing {
    KeyRing::single("remembered-device-test-secret-0123456789".to_string())
}

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

async fn redis_pool() -> Option<attome_cache::Store> {
    let (host, port) = attome_testkit::test_redis()?;
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}")).unwrap();
    let pool = RedisPool::new(config, None, None, None, 2).unwrap();
    pool.connect();
    pool.wait_for_connect().await.unwrap();
    Some(attome_cache::Store::Redis(pool))
}

/// A required second factor, remembering devices for `days`.
struct Policy {
    days: i32,
}

impl MfaPolicySource for Policy {
    fn policy_for(
        &self,
        _user_id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UserMfaRequirement, AppError>> + Send + '_>,
    > {
        let requirement = UserMfaRequirement {
            required: true,
            remember_device_days: self.days,
            ..UserMfaRequirement::default()
        };
        Box::pin(async move { Ok(requirement) })
    }
}

/// A user with a password and a confirmed TOTP factor.
async fn enrolled_user(db: &DbPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("remembered-device-{id}@example.invalid");
    let hash = hash_password_async(attome_auth::NewPassword::platform_generated(
        "correct-password",
    ))
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active, email_verified) \
         VALUES ($1, $2, $3, now(), true, true)",
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(db)
    .await
    .unwrap();
    let ring = mfa_ring();
    let enrolled = mfa::enroll(db, &ring, id).await.unwrap();
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolled.secret_base32).unwrap())
        .with_account_name("test".to_string())
        .build()
        .unwrap();
    mfa::confirm_enrollment(
        db,
        &ring,
        &pepper(),
        id,
        &totp.generate_current().to_string(),
    )
    .await
    .unwrap();
    (id, email)
}

async fn sign_in(
    db: &DbPool,
    redis: &attome_cache::Store,
    email: &str,
    policy: &Policy,
    device: Option<&str>,
) -> LoginOutcome {
    let ring = pepper();
    accounts::login_with_policy(
        db,
        redis,
        email,
        "correct-password",
        false,
        policy,
        &jwt_ring(),
        JWT_ISSUER,
        "attome-test",
        device.map(|bearer| RememberedDevice {
            bearer,
            ring: &ring,
        }),
    )
    .await
    .expect("sign in")
}

#[tokio::test]
async fn remembered_device_skips_mfa() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let (user_id, email) = enrolled_user(&db).await;
    let policy = Policy { days: 30 };

    let first = sign_in(&db, &redis, &email, &policy, None).await;
    assert!(
        matches!(first, LoginOutcome::MfaRequired { .. }),
        "{first:?}"
    );

    let epoch = attome_auth::epoch::current_epoch(&db, user_id)
        .await
        .unwrap();
    let bearer = remembered_device::remember(&db, &pepper(), user_id, epoch, 30, Some("test"))
        .await
        .unwrap();
    let again = sign_in(&db, &redis, &email, &policy, Some(&bearer)).await;
    assert!(
        matches!(again, LoginOutcome::Session(id) if id == user_id),
        "{again:?}"
    );

    // A wrong secret under the same id is not the device.
    let (id, _) = bearer.split_once('.').unwrap();
    let forged = format!("{id}.not-the-secret");
    let refused = sign_in(&db, &redis, &email, &policy, Some(&forged)).await;
    assert!(
        matches!(refused, LoginOutcome::MfaRequired { .. }),
        "{refused:?}"
    );
}

#[tokio::test]
async fn epoch_bump_forgets_device() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let (user_id, email) = enrolled_user(&db).await;
    let policy = Policy { days: 30 };
    let epoch = attome_auth::epoch::current_epoch(&db, user_id)
        .await
        .unwrap();
    let bearer = remembered_device::remember(&db, &pepper(), user_id, epoch, 30, None)
        .await
        .unwrap();
    assert!(
        remembered_device::is_remembered(&db, &pepper(), user_id, &bearer, epoch)
            .await
            .unwrap()
    );

    // A password change, reset or disable bumps the epoch.
    sqlx::query("UPDATE user_account SET auth_epoch = auth_epoch + 1 WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .unwrap();
    let outcome = sign_in(&db, &redis, &email, &policy, Some(&bearer)).await;
    assert!(
        matches!(outcome, LoginOutcome::MfaRequired { .. }),
        "{outcome:?}"
    );

    // Revoking every session forgets the device too.
    let epoch = attome_auth::epoch::current_epoch(&db, user_id)
        .await
        .unwrap();
    let bearer = remembered_device::remember(&db, &pepper(), user_id, epoch, 30, None)
        .await
        .unwrap();
    attome_auth::refresh::revoke_all_for_user(&db, user_id)
        .await
        .unwrap();
    assert!(
        !remembered_device::is_remembered(&db, &pepper(), user_id, &bearer, epoch)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn admin_policy_never_remembers() {
    let db = skip_if_no_db!(pool().await);
    let redis = attome_testkit::skip_if_no_redis!(redis_pool().await);
    let (user_id, email) = enrolled_user(&db).await;
    let epoch = attome_auth::epoch::current_epoch(&db, user_id)
        .await
        .unwrap();
    // A device remembered earlier, under a policy that allowed it...
    let bearer = remembered_device::remember(&db, &pepper(), user_id, epoch, 30, None)
        .await
        .unwrap();
    // ...is not honoured once the person's policy remembers nothing, as an
    // administrator's never does (Q5-T2).
    let admin = Policy { days: 0 };
    let outcome = sign_in(&db, &redis, &email, &admin, Some(&bearer)).await;
    assert!(
        matches!(outcome, LoginOutcome::MfaRequired { .. }),
        "{outcome:?}"
    );
    // And such a policy cannot remember a new one.
    let refused = remembered_device::remember(&db, &pepper(), user_id, epoch, 0, None).await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "{refused:?}"
    );
}

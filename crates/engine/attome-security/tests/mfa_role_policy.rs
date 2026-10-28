//! Q5-T3: the per-role second-factor policy as a sign-in applies it
//! (`attome_security::mfa_policy::requirement_for`), against Postgres. A role
//! that requires a factor gives a person without one a grace period in
//! which they may put enrolment off, and forces it after; a person whose
//! roles ask nothing gets the deployment's setting; a factor the identity
//! provider reported meets a required policy.
//!
//! Requires a live Postgres (`DATABASE_URL`), like `tests/sso_only_login.rs`.
//! Every test seeds its own random rows.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{MfaStep, federated_mfa_met, mfa_step};
use attome_db::DbPool;
use attome_security::mfa_policy::{postpone_enrolment, requirement_for};
use attome_testkit::skip_if_no_db;
use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

async fn seed_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("mfa-role-{id}"))
    .bind(format!(
        "mfa-{}@example.test",
        &id.simple().to_string()[20..]
    ))
    .execute(db)
    .await
    .expect("insert user");
    id
}

/// A role that requires a second factor with `grace_days`, given to `user`.
async fn require_mfa(db: &DbPool, user: Uuid, grace_days: i32) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("mfa-role-{}", &role.simple().to_string()[20..]))
        .execute(db)
        .await
        .expect("insert role");
    sqlx::query(
        "INSERT INTO role_auth_policy (role_ref, mfa_mode, mfa_grace_days) \
         VALUES ($1, 'required', $2)",
    )
    .bind(role)
    .bind(grace_days)
    .execute(db)
    .await
    .expect("role policy");
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user)
        .bind(role)
        .execute(db)
        .await
        .expect("grant the role");
}

#[tokio::test]
async fn role_required_forces_enrolment_after_grace() {
    let db = skip_if_no_db!(test_db().await);
    let user = seed_user(&db).await;
    require_mfa(&db, user, 7).await;
    let now = Utc::now();

    // The first sign-in starts the grace clock: enrolment is asked for and
    // may be put off.
    let requirement = requirement_for(&db, user, "optional").await.unwrap();
    assert!(requirement.required);
    assert!(requirement.in_grace(now));
    assert_eq!(mfa_step(&requirement, false, now), MfaStep::Enrol);
    let until = postpone_enrolment(&db, user, "optional", now)
        .await
        .unwrap()
        .expect("postponed within the grace period");
    assert!(until <= now + Duration::hours(24) + Duration::seconds(5));
    let requirement = requirement_for(&db, user, "optional").await.unwrap();
    assert_eq!(mfa_step(&requirement, false, now), MfaStep::Session);

    // Eight days on, the grace period is over.
    sqlx::query(
        "UPDATE user_mfa_grace SET required_since = now() - interval '8 days', \
                postpone_until = NULL WHERE user_ref = $1",
    )
    .bind(user)
    .execute(&db)
    .await
    .unwrap();
    let requirement = requirement_for(&db, user, "optional").await.unwrap();
    assert!(!requirement.in_grace(Utc::now()));
    assert_eq!(mfa_step(&requirement, false, Utc::now()), MfaStep::Enrol);
    assert!(
        postpone_enrolment(&db, user, "optional", Utc::now())
            .await
            .unwrap()
            .is_none(),
        "no postponing after the grace period"
    );
}

#[tokio::test]
async fn user_without_mfa_role_is_not_asked() {
    let db = skip_if_no_db!(test_db().await);
    let user = seed_user(&db).await;
    let now = Utc::now();
    for floor in ["optional", "off"] {
        let requirement = requirement_for(&db, user, floor).await.unwrap();
        assert!(!requirement.required, "{floor}");
        assert_eq!(
            mfa_step(&requirement, false, now),
            MfaStep::Session,
            "{floor}"
        );
    }
    // The deployment's own "required" still holds for someone with no role.
    let requirement = requirement_for(&db, user, "required").await.unwrap();
    assert!(requirement.required);
    let grace: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_mfa_grace WHERE user_ref = $1)")
            .bind(user)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(grace, "a required factor starts the grace clock");
    assert!(
        postpone_enrolment(&db, Uuid::now_v7(), "optional", now)
            .await
            .unwrap()
            .is_none(),
        "nobody without a requirement can postpone"
    );
}

#[tokio::test]
async fn provider_mfa_satisfies_required_policy() {
    let db = skip_if_no_db!(test_db().await);
    let user = seed_user(&db).await;
    require_mfa(&db, user, 0).await;
    let requirement = requirement_for(&db, user, "optional").await.unwrap();
    let now = Utc::now() + Duration::seconds(1);
    assert!(requirement.required && !requirement.in_grace(now));
    assert!(federated_mfa_met(&requirement, true, now));
    assert!(!federated_mfa_met(&requirement, false, now));
}

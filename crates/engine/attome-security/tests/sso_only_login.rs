//! Q1-T7: `attome_security::auth_policy::password_login` against Postgres.
//! An SSO-only verified domain or an SSO-only role refuses a password; a
//! break-glass account keeps it.
//!
//! Requires a live Postgres (`DATABASE_URL`), like `tests/resolver.rs`.
//! Every test seeds its own random rows and removes them.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::auth_policy::{PasswordLogin, password_login};
use attome_testkit::skip_if_no_db;
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

async fn seed_user(db: &DbPool, email: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("sso-test-{id}"))
    .bind(email)
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    id
}

/// A verified SSO-only domain on a throwaway provider; returns the provider.
async fn seed_sso_domain(db: &DbPool, domain: &str) -> Uuid {
    let provider = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oidc_provider (id, key, display_name, issuer, client_id, client_secret_enc, scopes) \
         VALUES ($1, $2, 'Test IdP', 'https://idp.test.invalid', 'client', 'sealed', ARRAY['openid'])",
    )
    .bind(provider)
    .bind(format!("t-{}", &provider.simple().to_string()[..12]))
    .execute(db)
    .await
    .expect("insert throwaway oidc_provider");
    sqlx::query(
        "INSERT INTO oidc_domain (domain, provider_ref, verification_token, verified_at, sso_only) \
         VALUES ($1, $2, 'token', now(), true)",
    )
    .bind(domain)
    .bind(provider)
    .execute(db)
    .await
    .expect("insert throwaway oidc_domain");
    provider
}

async fn cleanup(db: &DbPool, users: &[Uuid], provider: Option<Uuid>) {
    for user in users {
        sqlx::query("DELETE FROM user_account WHERE id = $1")
            .bind(user)
            .execute(db)
            .await
            .expect("cleanup user");
    }
    if let Some(provider) = provider {
        sqlx::query("DELETE FROM oidc_domain WHERE provider_ref = $1")
            .bind(provider)
            .execute(db)
            .await
            .expect("cleanup domain");
        sqlx::query("DELETE FROM oidc_provider WHERE id = $1")
            .bind(provider)
            .execute(db)
            .await
            .expect("cleanup provider");
    }
}

#[tokio::test]
async fn sso_only_domain_refuses_password() {
    let db = skip_if_no_db!(test_db().await);
    let domain = format!(
        "sso-{}.test.invalid",
        &Uuid::now_v7().simple().to_string()[..12]
    );
    let provider = seed_sso_domain(&db, &domain).await;
    let email = format!("sara@{domain}");
    let user = seed_user(&db, &email).await;
    let other = seed_user(&db, &format!("omar-{user}@elsewhere.test.invalid")).await;

    assert_eq!(
        password_login(&db, user, &email).await.unwrap(),
        PasswordLogin::Refused
    );
    assert_eq!(
        password_login(&db, other, &format!("omar-{user}@elsewhere.test.invalid"))
            .await
            .unwrap(),
        PasswordLogin::Allowed
    );
    cleanup(&db, &[user, other], Some(provider)).await;
}

#[tokio::test]
async fn break_glass_user_can_use_password() {
    let db = skip_if_no_db!(test_db().await);
    let domain = format!(
        "sso-{}.test.invalid",
        &Uuid::now_v7().simple().to_string()[..12]
    );
    let provider = seed_sso_domain(&db, &domain).await;
    let email = format!("admin@{domain}");
    let user = seed_user(&db, &email).await;
    sqlx::query("INSERT INTO break_glass_account (user_ref, reason) VALUES ($1, 'test')")
        .bind(user)
        .execute(&db)
        .await
        .expect("insert break-glass account");

    assert_eq!(
        password_login(&db, user, &email).await.unwrap(),
        PasswordLogin::BreakGlass
    );
    cleanup(&db, &[user], Some(provider)).await;
}

#[tokio::test]
async fn sso_only_role_refuses_its_holders() {
    let db = skip_if_no_db!(test_db().await);
    let email = format!("role-{}@plain.test.invalid", Uuid::now_v7());
    let user = seed_user(&db, &email).await;
    let role = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, 'sso test', 'project')",
    )
    .bind(role)
    .bind(format!("sso-role-{role}"))
    .execute(&db)
    .await
    .expect("insert role");
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(role)
        .execute(&db)
        .await
        .expect("grant role");
    assert_eq!(
        password_login(&db, user, &email).await.unwrap(),
        PasswordLogin::Allowed
    );
    sqlx::query("INSERT INTO role_auth_policy (role_ref, sso_only) VALUES ($1, true)")
        .bind(role)
        .execute(&db)
        .await
        .expect("make the role SSO-only");
    assert_eq!(
        password_login(&db, user, &email).await.unwrap(),
        PasswordLogin::Refused
    );

    cleanup(&db, &[user], None).await;
    sqlx::query("DELETE FROM role WHERE id = $1")
        .bind(role)
        .execute(&db)
        .await
        .expect("cleanup role");
}

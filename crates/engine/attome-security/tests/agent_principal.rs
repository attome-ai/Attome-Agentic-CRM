//! AH3-T9: negative paths for agent principals, against a throwaway
//! database: an agent holds only what it and its sponsor both hold, nothing
//! outside its entity scope, never `system.admin`, and nothing once revoked.
//! (Sponsor loss: attome-ai `agent_principal_session.rs`; the routes' audit
//! events: `audit_coverage_emission.rs`.)
//!
//! ```powershell
//! cargo test -p attome-security --test agent_principal -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::db::{ensure_privilege, ensure_user_privilege_grant};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("connect to DATABASE_URL"),
    )
}

async fn person(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, 'p', $2, true)",
    )
    .bind(id)
    .bind(format!("p-{}@test.invalid", id.simple()))
    .execute(db)
    .await
    .unwrap();
    id
}

async fn agent(db: &DbPool, sponsor: Uuid, scope: Option<Vec<String>>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, principal_kind) \
         VALUES ($1, 'agent', $2, true, 2)",
    )
    .bind(id)
    .bind(format!("agent-{}@internal.attome", id.simple()))
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO agent_principal (user_ref, sponsor_user_ref, entity_scope, created_by) \
         VALUES ($1, $2, $3, $2)",
    )
    .bind(id)
    .bind(sponsor)
    .bind(scope)
    .execute(db)
    .await
    .unwrap();
    id
}

async fn grant(db: &DbPool, user: Uuid, key: &str) {
    let privilege = ensure_privilege(db, key, key, "test", attome_core::changeset::Layer::Project)
        .await
        .unwrap();
    ensure_user_privilege_grant(db, user, privilege)
        .await
        .unwrap();
}

/// A fresh entity-like name, so keys never collide across runs.
fn entity() -> String {
    format!("apt{}", &Uuid::now_v7().simple().to_string()[20..])
}

#[tokio::test]
async fn privilege_matrix_is_an_intersection() {
    let db = skip_if_no_db!(test_db().await);
    let sponsor = person(&db).await;
    let agent = agent(&db, sponsor, None).await;
    let (both, agent_only, sponsor_only) = (
        format!("{}.read", entity()),
        format!("{}.read", entity()),
        format!("{}.read", entity()),
    );
    grant(&db, agent, &both).await;
    grant(&db, sponsor, &both).await;
    grant(&db, agent, &agent_only).await;
    grant(&db, sponsor, &sponsor_only).await;

    let ctx = attome_security::resolve_uncached(&db, agent).await.unwrap();
    assert!(ctx.privileges.contains(&both), "both hold it: allowed");
    assert!(!ctx.privileges.contains(&agent_only), "agent only: refused");
    assert!(
        !ctx.privileges.contains(&sponsor_only),
        "sponsor only: refused"
    );
}

#[tokio::test]
async fn entity_outside_scope_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let sponsor = person(&db).await;
    let (inside, outside) = (entity(), entity());
    let agent = agent(&db, sponsor, Some(vec![inside.clone()])).await;
    for key in [format!("{inside}.read"), format!("{outside}.read")] {
        grant(&db, agent, &key).await;
        grant(&db, sponsor, &key).await;
    }
    let ctx = attome_security::resolve_uncached(&db, agent).await.unwrap();
    assert!(ctx.privileges.contains(&format!("{inside}.read")));
    assert!(!ctx.privileges.contains(&format!("{outside}.read")));
}

#[tokio::test]
async fn system_admin_grant_to_agent_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let sponsor = person(&db).await;
    let agent = agent(&db, sponsor, None).await;
    assert!(
        attome_security::admin::agents::refuse_admin_grant(&db, agent, Some("system.admin"), None)
            .await
            .is_err()
    );
    assert!(
        attome_security::admin::agents::refuse_admin_grant(
            &db,
            sponsor,
            Some("system.admin"),
            None
        )
        .await
        .is_ok(),
        "a person may be granted it"
    );
    // Even granted behind the API's back, the resolver never makes it admin.
    grant(&db, agent, "system.admin").await;
    grant(&db, sponsor, "system.admin").await;
    let ctx = attome_security::resolve_uncached(&db, agent).await.unwrap();
    assert!(!ctx.is_admin);
    assert!(!ctx.privileges.contains("system.admin"));
}

#[tokio::test]
async fn revoked_agent_key_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let sponsor = person(&db).await;
    let agent = agent(&db, sponsor, None).await;
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash) VALUES ($1, 'k', $2, 'x')",
    )
    .bind(agent)
    .bind(format!("atk_pub_{}", Uuid::now_v7().simple()))
    .execute(&db)
    .await
    .unwrap();
    assert!(attome_security::resolve_uncached(&db, agent).await.is_ok());

    // Revoked: whatever key it presents, its context does not resolve.
    sqlx::query("UPDATE agent_principal SET lifecycle_state = 'revoked' WHERE user_ref = $1")
        .bind(agent)
        .execute(&db)
        .await
        .unwrap();
    assert!(matches!(
        attome_security::resolve_uncached(&db, agent).await,
        Err(attome_types::AppError::Forbidden)
    ));
    // And with its sponsor gone, an active agent is refused too.
    sqlx::query("UPDATE agent_principal SET lifecycle_state = 'active' WHERE user_ref = $1")
        .bind(agent)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(sponsor)
        .execute(&db)
        .await
        .unwrap();
    assert!(attome_security::resolve_uncached(&db, agent).await.is_err());
}

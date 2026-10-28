//! Q10-T1, Q5-T1, Q8-T1: the security policy columns and tables exist on a
//! freshly migrated database.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

async fn columns(db: &sqlx::PgPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_name = $1 AND table_schema = current_schema()",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .expect("read columns")
}

async fn pool() -> Option<sqlx::PgPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 2).await)
}

#[tokio::test]
async fn role_entity_access_ops_columns_exist() {
    let db = skip_if_no_db!(pool().await);
    let cols = columns(&db, "role_mm_entity_access").await;
    for c in [
        "create_access_level",
        "assign_access_level",
        "share_access_level",
        "export_access_level",
        "bulk_access_level",
        "read_bu_children",
        "share_bu_children",
    ] {
        assert!(cols.iter().any(|x| x == c), "role_mm_entity_access.{c}");
    }
}

#[tokio::test]
async fn mfa_policy_columns_exist() {
    let db = skip_if_no_db!(pool().await);
    let cols = columns(&db, "role_auth_policy").await;
    for c in [
        "mfa_mode",
        "mfa_factors",
        "mfa_grace_days",
        "remember_device_days",
    ] {
        assert!(cols.iter().any(|x| x == c), "role_auth_policy.{c}");
    }
    assert!(!columns(&db, "user_mfa_grace").await.is_empty());
    assert!(!columns(&db, "remembered_device").await.is_empty());
    // Q5-T6: what past sign-ins came from.
    assert!(!columns(&db, "sign_in_seen").await.is_empty());
}

#[tokio::test]
async fn session_policy_columns_exist() {
    let db = skip_if_no_db!(pool().await);
    let policy = columns(&db, "role_auth_policy").await;
    for c in [
        "idle_timeout_secs",
        "absolute_lifetime_secs",
        "max_sessions",
        "max_sessions_mode",
    ] {
        assert!(policy.iter().any(|x| x == c), "role_auth_policy.{c}");
    }
    let refresh = columns(&db, "refresh_token").await;
    for c in [
        "last_activity_at",
        "user_agent",
        "client_kind",
        "sign_in_method",
    ] {
        assert!(refresh.iter().any(|x| x == c), "refresh_token.{c}");
    }
}

#[tokio::test]
async fn sign_in_rule_columns_exist() {
    let db = skip_if_no_db!(pool().await);
    let policy = columns(&db, "role_auth_policy").await;
    for c in ["login_calendar_ref", "allowed_countries"] {
        assert!(policy.iter().any(|x| x == c), "role_auth_policy.{c}");
    }
}

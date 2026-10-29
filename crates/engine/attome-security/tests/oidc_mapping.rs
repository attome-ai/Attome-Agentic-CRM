//! Q1-T9: `attome_security::oidc_mapping` against Postgres. A group mapped
//! to a team gives the team at sign-in; a group no longer sent takes back
//! only what the provider gave, never an administrator's grant; a mapping to
//! a role carrying `system.admin` gives nothing.
//!
//! Requires a live Postgres (`DATABASE_URL`), like `tests/sso_only_login.rs`.
//! Every test seeds its own random rows.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::AuditService;
use attome_db::DbPool;
use attome_security::oidc_mapping::{MappingChanges, apply_mappings_in_tx};
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

fn short(id: Uuid) -> String {
    id.simple().to_string()[20..].to_owned()
}

async fn seed_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("map-test-{id}"))
    .bind(format!("map-{}@example.test", short(id)))
    .execute(db)
    .await
    .expect("insert user");
    id
}

async fn seed_provider(db: &DbPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let key = format!("m-{}", short(id));
    sqlx::query(
        "INSERT INTO oidc_provider (id, key, display_name, issuer, client_id, client_secret_enc, scopes) \
         VALUES ($1, $2, 'Test IdP', 'https://idp.test.invalid', 'client', 'sealed', ARRAY['openid'])",
    )
    .bind(id)
    .bind(&key)
    .execute(db)
    .await
    .expect("insert provider");
    (id, key)
}

async fn seed_team(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("map-team-{}", short(id)))
        .execute(db)
        .await
        .expect("insert team");
    id
}

async fn seed_role(db: &DbPool, admin: bool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(id)
        .bind(format!("map-role-{}", short(id)))
        .execute(db)
        .await
        .expect("insert role");
    if admin {
        sqlx::query(
            "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
             SELECT $1, 'system.admin', 'System administration', true, now(), 'platform' \
              WHERE NOT EXISTS (SELECT 1 FROM privilege WHERE key = 'system.admin')",
        )
        .bind(Uuid::now_v7())
        .execute(db)
        .await
        .expect("ensure system.admin");
        sqlx::query(
            "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) \
             SELECT $1, id, 'project' FROM privilege WHERE key = 'system.admin' LIMIT 1",
        )
        .bind(id)
        .execute(db)
        .await
        .expect("grant system.admin to the role");
    }
    id
}

async fn map(db: &DbPool, provider: Uuid, group: &str, team: Option<Uuid>, role: Option<Uuid>) {
    sqlx::query(
        "INSERT INTO oidc_group_mapping (provider_ref, claim_value, team_ref, role_ref) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(provider)
    .bind(group)
    .bind(team)
    .bind(role)
    .execute(db)
    .await
    .expect("insert mapping");
}

async fn sign_in(
    db: &DbPool,
    provider: (Uuid, &str),
    user: Uuid,
    groups: &[&str],
) -> MappingChanges {
    let audit = AuditService::new(db, None);
    let groups: Vec<String> = groups.iter().map(|g| (*g).to_owned()).collect();
    let mut tx = attome_db::tx::begin(db).await.expect("begin");
    let changes = apply_mappings_in_tx(&mut tx, &audit, provider.0, provider.1, user, &groups)
        .await
        .expect("apply mappings");
    tx.commit().await.expect("commit");
    changes
}

async fn live_teams(db: &DbPool, user: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT team_ref, source_provider_ref FROM user_account_mm_team \
          WHERE user_ref = $1 AND NOT is_deleted ORDER BY team_ref",
    )
    .bind(user)
    .fetch_all(db)
    .await
    .expect("teams")
}

async fn live_roles(db: &DbPool, user: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT role_ref FROM user_account_mm_role WHERE user_ref = $1 AND NOT is_deleted",
    )
    .bind(user)
    .fetch_all(db)
    .await
    .expect("roles")
}

#[tokio::test]
async fn group_added_grants_team() {
    let db = skip_if_no_db!(test_db().await);
    let (provider, key) = seed_provider(&db).await;
    let user = seed_user(&db).await;
    let (team, role) = (seed_team(&db).await, seed_role(&db, false).await);
    map(&db, provider, "sales", Some(team), None).await;
    map(&db, provider, "sales", None, Some(role)).await;

    let changes = sign_in(&db, (provider, &key), user, &["sales", "unmapped"]).await;
    assert_eq!(changes.teams_added, vec![team]);
    assert_eq!(changes.roles_added, vec![role]);
    assert_eq!(live_teams(&db, user).await, vec![(team, Some(provider))]);
    assert_eq!(live_roles(&db, user).await, vec![role]);

    // The next sign-in with the same groups changes nothing.
    assert!(
        sign_in(&db, (provider, &key), user, &["sales"])
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn group_removed_revokes_only_provider_grant() {
    let db = skip_if_no_db!(test_db().await);
    let (provider, key) = seed_provider(&db).await;
    let user = seed_user(&db).await;
    let (given, manual) = (seed_team(&db).await, seed_team(&db).await);
    map(&db, provider, "sales", Some(given), None).await;
    map(&db, provider, "ops", Some(manual), None).await;
    // An administrator put the person in `manual` themselves.
    sqlx::query("INSERT INTO user_account_mm_team (user_ref, team_ref) VALUES ($1, $2)")
        .bind(user)
        .bind(manual)
        .execute(&db)
        .await
        .expect("manual membership");

    let changes = sign_in(&db, (provider, &key), user, &["sales", "ops"]).await;
    // `manual` was already held: the provider neither re-adds nor claims it.
    assert_eq!(changes.teams_added, vec![given]);

    let changes = sign_in(&db, (provider, &key), user, &[]).await;
    assert_eq!(changes.teams_removed, vec![given]);
    assert_eq!(
        live_teams(&db, user).await,
        vec![(manual, None)],
        "the administrator's membership stays"
    );
}

#[tokio::test]
async fn admin_role_mapping_is_refused() {
    let db = skip_if_no_db!(test_db().await);
    let (provider, key) = seed_provider(&db).await;
    let user = seed_user(&db).await;
    let admin_role = seed_role(&db, true).await;
    // A team carrying the admin role is no way round it either.
    let admin_team = seed_team(&db).await;
    sqlx::query("INSERT INTO role_mm_team (role_ref, team_ref) VALUES ($1, $2)")
        .bind(admin_role)
        .bind(admin_team)
        .execute(&db)
        .await
        .expect("team role");
    map(&db, provider, "admins", None, Some(admin_role)).await;
    map(&db, provider, "admins", Some(admin_team), None).await;

    let mut conn = db.acquire().await.unwrap();
    assert!(
        attome_security::oidc_mapping::role_grants_admin(&mut conn, admin_role)
            .await
            .unwrap()
    );
    assert!(
        attome_security::oidc_mapping::team_grants_admin(&mut conn, admin_team)
            .await
            .unwrap()
    );
    drop(conn);

    let changes = sign_in(&db, (provider, &key), user, &["admins"]).await;
    assert!(changes.is_empty(), "{changes:?}");
    assert!(live_roles(&db, user).await.is_empty());
    assert!(live_teams(&db, user).await.is_empty());
}

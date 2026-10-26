//! Shared seeding for the Knowledge Base suites: `knowledge_pipeline` (the
//! producer and retrieval, end to end) and `knowledge_eval` (the D-498
//! benchmark).
//!
//! One copy on purpose. Both suites provision the platform's **real** entity
//! names and seed callers through the **production** access resolver; two
//! copies of either would let the benchmark measure a schema or a permission
//! shape the pipeline tests no longer exercise.

#![allow(dead_code)]

use std::future::Future;

use attome_db::DbPool;
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_server::security::SecurityContext;
use serde_json::json;
use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// The pool the suites seed through, with `statement_timeout` raised per
/// connection for the same reason `harness::test_db` gives: the platform role
/// sits at the 500 ms production bound, and seeding a corpus on a busy machine
/// does not fit inside it.
pub async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET statement_timeout = '300s'").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// A non-admin caller context for `user_id`. Never an admin: `is_admin`
/// short-circuits the record predicate, so an admin-run check measures a query
/// the product does not execute for ordinary users.
pub fn caller_ctx(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        service_principal: false,
    }
}

/// Serializes [`provision_kb`] within one test binary.
///
/// `tokio::sync::Mutex` rather than `std`: it is held across `.await`, and each
/// `#[tokio::test]` has its own runtime, which a tokio mutex does not care about.
static PROVISION_KB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Provisions the two Knowledge Base entities at their real logical names.
///
/// Idempotent, and deliberately the same shape the platform bundle applies at
/// boot — a test that created its own private table would prove the producer
/// works against a schema no deployment has.
///
/// **One caller at a time.** Tests in a binary run concurrently against that
/// binary's own fresh database, and concurrent first-time registration of the
/// same entity races inside Postgres: two `CREATE TABLE`s of one name fail on
/// `pg_type_typname_nsp_index`, and interleaved DDL deadlocks. Only the first
/// caller does any DDL; the rest take the steady-state path.
pub async fn provision_kb(db: &DbPool) {
    let _serialized = PROVISION_KB.lock().await;
    let source = ensure_entity(
        db,
        "knowledge_data_source",
        "Data Source",
        Some("name"),
        false,
    )
    .await
    .expect("provision knowledge_data_source");
    ensure_attribute(
        db, source, "name", "Name", "text", true, false, true, true, None, None,
    )
    .await
    .expect("data source name");
    ensure_attribute(
        db,
        source,
        "description",
        "Description",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("data source description");

    let item = ensure_entity(db, "knowledge_data_item", "Data Item", Some("title"), false)
        .await
        .expect("provision knowledge_data_item");
    ensure_attribute(
        db, item, "title", "Title", "text", true, false, true, true, None, None,
    )
    .await
    .expect("item title");
    ensure_attribute(
        db, item, "text", "Text", "text", false, false, false, false, None, None,
    )
    .await
    .expect("item text");
    ensure_attribute(
        db,
        item,
        "lifecycle",
        "Lifecycle",
        "choice",
        false,
        false,
        true,
        true,
        None,
        Some(json!({ "choices": ["draft", "published", "expired"], "multi": false })),
    )
    .await
    .expect("item lifecycle");
    ensure_attribute(
        db,
        item,
        "review_by",
        "Review By",
        "date",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("item review_by");
    ensure_attribute(
        db,
        item,
        "source_entity",
        "Source Entity",
        "text",
        false,
        false,
        false,
        true,
        None,
        None,
    )
    .await
    .expect("item source_entity");
    ensure_attribute(
        db,
        item,
        "source_record_id",
        "Source Record",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("item source_record_id");
    ensure_attribute(
        db,
        item,
        "data_source_ref",
        "Data Source",
        "lookup",
        true,
        false,
        false,
        true,
        Some(source),
        None,
    )
    .await
    .expect("item data_source_ref");
}

pub async fn insert_source(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO knowledge_data_source (id, name, is_active) VALUES ($1, $2, TRUE)")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert data source");
    id
}

pub async fn insert_article(
    db: &DbPool,
    source: Uuid,
    title: &str,
    text: &str,
    lifecycle: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO knowledge_data_item \
            (id, title, text, data_source_ref, lifecycle, is_active) \
         VALUES ($1, $2, $3, $4, $5, TRUE)",
    )
    .bind(id)
    .bind(title)
    .bind(text)
    .bind(source)
    .bind(lifecycle)
    .execute(db)
    .await
    .expect("insert data item");
    id
}

/// Deletes an article's chunks and row, and the Data Source if given.
pub async fn delete_article(db: &DbPool, item: Uuid, source: Option<Uuid>) {
    let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE source_id = $1")
        .bind(item)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM knowledge_data_item WHERE id = $1")
        .bind(item)
        .execute(db)
        .await;
    if let Some(source) = source {
        let _ = sqlx::query("DELETE FROM knowledge_data_source WHERE id = $1")
            .bind(source)
            .execute(db)
            .await;
    }
}

/// A real, non-admin user who can read exactly `sources`, through the
/// production resolver rather than a hand-built access map: a role holding
/// `knowledge_data_source.read` at `Team` depth (so the Global arm never
/// fires) plus one share row per readable source. Returns `(user_id, role_id)`.
pub async fn user_who_can_read(db: &DbPool, sources: &[Uuid]) -> (Uuid, Uuid) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("kb-test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert user");

    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("kb-test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert role");

    // The key is unique, and an earlier test in this database may own the row.
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
         VALUES ($1, 'knowledge_data_source.read', 'Read Data Source', true, NOW(), 'project') \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("insert privilege");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'knowledge_data_source.read'")
            .fetch_one(db)
            .await
            .expect("read privilege");
    let entity_ref: Uuid = sqlx::query_scalar(
        "SELECT id FROM entity_info WHERE logicalname = 'knowledge_data_source'",
    )
    .fetch_one(db)
    .await
    .expect("data source entity");

    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant privilege");
    sqlx::query(
        "INSERT INTO role_mm_entity_access (role_ref, entity_ref, read_access_level, owner_layer) \
         VALUES ($1, $2, 1, 'project')",
    )
    .bind(role_id)
    .bind(entity_ref)
    .execute(db)
    .await
    .expect("team read depth");
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role");
    for source in sources {
        sqlx::query(
            "INSERT INTO record_share \
                (record_id, entity_ref, principal_type, principal_id, capability) \
             VALUES ($1, $2, 0, $3, 0) ON CONFLICT DO NOTHING",
        )
        .bind(source)
        .bind(entity_ref)
        .bind(user_id)
        .execute(db)
        .await
        .expect("share a readable source");
    }

    (user_id, role_id)
}

pub async fn drop_user(db: &DbPool, user_id: Uuid, role_id: Uuid) {
    let _ = sqlx::query("DELETE FROM record_share WHERE principal_id = $1")
        .bind(user_id)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM role WHERE id = $1")
        .bind(role_id)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM user_account WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await;
}

/// Runs a test's assertions on their own task, **always** runs its cleanup
/// afterwards, then re-raises the assertions' panic.
///
/// A trailing `cleanup(..).await` never runs once an assertion panics, and the
/// rows it would have deleted stay in the binary's database for every test
/// after it. That has already knocked over an unrelated test: failing tests
/// left extra copies of an article behind, and a `limit = 5` citation test
/// lost its own article below the cut. Spawning the body turns its panic into
/// a `JoinError` that is held here while the cleanup runs.
///
/// Setup stays outside the body, so a panic in setup itself (a broken test
/// database rather than a failed assertion) can still leave rows behind.
pub async fn assert_then_cleanup<B, C>(body: B, cleanup: C)
where
    B: Future<Output = ()> + Send + 'static,
    C: Future<Output = ()>,
{
    let outcome = tokio::spawn(body).await;
    cleanup.await;
    if let Err(e) = outcome {
        match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(e) => panic!("the test body did not run to completion: {e}"),
        }
    }
}

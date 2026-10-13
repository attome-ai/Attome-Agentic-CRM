//! Phase 5 money path: `context::do_resolve_variables` — declared variable/
//! parameter defaults, built-in session variables, record-context
//! injection, and URL-override precedence — exercised directly against a
//! live database, same shape as `tests/dashboard_crud.rs`. The pure
//! built-in-resolution logic itself (`resolve_builtin_variables`) is
//! unit-tested in-crate (`context.rs`'s own `tests` module) since it needs
//! no database at all; this file covers the DB-backed merge with declared
//! rows.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`. Run with `--test-threads=1`:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test context_engine -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_dashboard::context::EmbedContext;
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

mod common;

fn security_context(user_id: Uuid, org_ids: &[Uuid], team_ids: &[Uuid]) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: org_ids.to_vec(),
        team_ids: team_ids.to_vec(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

async fn insert_dashboard(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO attome_dashboard (id, name, dashboard_type) VALUES ($1, $2, 'team')")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test attome_dashboard row");
    id
}

async fn insert_variable(db: &DbPool, dashboard_id: Uuid, name: &str, default_value: &str) {
    sqlx::query(
        "INSERT INTO dashboard_variable (id, dashboard_id, name, variable_type, default_value) \
         VALUES ($1, $2, $3, 'param_var', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(dashboard_id)
    .bind(name)
    .bind(default_value)
    .execute(db)
    .await
    .expect("insert test dashboard_variable row");
}

async fn insert_parameter(db: &DbPool, dashboard_id: Uuid, name: &str, default_value: &str) {
    sqlx::query(
        "INSERT INTO dashboard_parameter (id, dashboard_id, name, parameter_type, default_value) \
         VALUES ($1, $2, $3, 'text', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(dashboard_id)
    .bind(name)
    .bind(default_value)
    .execute(db)
    .await
    .expect("insert test dashboard_parameter row");
}

#[tokio::test]
async fn resolves_declared_defaults_builtins_and_url_overrides_in_precedence_order() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(db, "Context Test Dashboard").await;
    insert_variable(db, dashboard_id, "region", "EMEA").await;
    insert_parameter(db, dashboard_id, "fiscal_year", "2026").await;

    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    let team_id = Uuid::now_v7();
    let ctx = security_context(user_id, &[org_id], &[team_id]);
    let record_id = Uuid::now_v7();
    let embed = EmbedContext {
        record_id: Some(record_id),
        entity_logical_name: Some("attome_project".to_string()),
    };
    let mut url_overrides = HashMap::new();
    url_overrides.insert("region".to_string(), "APAC".to_string());

    let resolved = attome_dashboard::context::do_resolve_variables(
        db,
        dashboard_id,
        None,
        &ctx,
        &embed,
        &url_overrides,
    )
    .await
    .expect("resolve variables");

    // URL override wins over the declared default.
    assert_eq!(resolved["region"], "APAC");
    // Declared default survives when nothing overrides it.
    assert_eq!(resolved["fiscal_year"], "2026");
    // Built-ins, from the caller's own session/embed context.
    assert_eq!(resolved["@current_user"], user_id.to_string());
    assert_eq!(resolved["@current_user_bu"], serde_json::json!([org_id]));
    assert_eq!(resolved["@current_user_team"], serde_json::json!([team_id]));
    assert_eq!(resolved["@current_record_id"], record_id.to_string());
    assert_eq!(resolved["@current_entity"], "attome_project");
    assert!(resolved.contains_key("@current_date"));
}

#[tokio::test]
async fn page_scoped_variables_do_not_leak_into_a_different_page() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(db, "Page Scope Test Dashboard").await;
    let page_id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_page (id, dashboard_id, name) VALUES ($1, $2, 'Page')")
        .bind(page_id)
        .bind(dashboard_id)
        .execute(db)
        .await
        .expect("insert test dashboard_page row");
    sqlx::query(
        "INSERT INTO dashboard_variable (id, dashboard_id, page_id, name, variable_type, default_value) \
         VALUES ($1, $2, $3, 'scoped_var', 'param_var', 'only-this-page')",
    )
    .bind(Uuid::now_v7())
    .bind(dashboard_id)
    .bind(page_id)
    .execute(db)
    .await
    .expect("insert page-scoped test dashboard_variable row");

    let ctx = security_context(Uuid::now_v7(), &[], &[]);
    let no_page = attome_dashboard::context::do_resolve_variables(
        db,
        dashboard_id,
        None,
        &ctx,
        &EmbedContext::default(),
        &HashMap::new(),
    )
    .await
    .expect("resolve without a page");
    assert!(
        !no_page.contains_key("scoped_var"),
        "a page-scoped variable must not resolve when no page_id is given"
    );

    let with_page = attome_dashboard::context::do_resolve_variables(
        db,
        dashboard_id,
        Some(page_id),
        &ctx,
        &EmbedContext::default(),
        &HashMap::new(),
    )
    .await
    .expect("resolve with the matching page");
    assert_eq!(with_page["scoped_var"], "only-this-page");
}

//! M3.4 / MASTER-PLAN P0 0.5 — MCP entity admission, default-deny, through
//! the real `dispatch` and approved-execution paths.
//!
//! What is proven, for an agent on a session the MCP surface opened:
//! - an entity not admitted in `ai.mcp_entity_admission` is refused darkly
//!   (`NotFound`) for read and for every write — before the gate, so no
//!   confirmation and no four-eyes request is raised;
//! - an admitted entity works, for the admitted verbs only;
//! - security/identity/audit entities are refused even when admitted, and the
//!   engine's own ledger refusal still holds for a direct caller;
//! - admission only narrows: the caller's own privileges still apply;
//! - withdrawing admission invalidates an already-approved delete;
//! - a non-MCP agent session is not governed at all;
//! - the read tools that reach entities without an `entity` argument are
//!   governed too: `query.execute` runs only when every entity the stored
//!   query touches is admitted for read, `search.records` returns and counts
//!   admitted hits only, and `graph.traverse` refuses an unadmitted start and
//!   never walks through an unadmitted node — excluded entities stay
//!   invisible to all three even when admitted.
//! - an admitted row's lookup display name into an unadmitted entity is
//!   dropped from `query.execute` and `record.get` results (D-769).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test mcp_admission -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use std::sync::Arc;

use attome_ai::context::ActionContext;
use attome_ai::execute::{ActionOutcome, ApprovedExecution};
use attome_ai::session::AgentSession;
use attome_core::EngineState;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

use common::{Fixture, fixture, seed_user};

const KEY: &str = "ai.mcp_entity_admission";

/// Sets `entity`'s admitted verbs in the deployment-scope admission setting
/// (an empty slice removes the entity), merging rather than replacing so
/// tests running in parallel on their own entities do not clobber each other,
/// then refreshes `state.settings` as the real write handler does.
async fn admit(state: &EngineState, entity: &str, verbs: &[&str]) {
    let remove = verbs.is_empty();
    let patch = json!({ entity: verbs });
    for _ in 0..3 {
        let updated = sqlx::query(
            "UPDATE setting \
                SET value = CASE WHEN $3 THEN value - $1 ELSE value || $2 END, \
                    row_version = row_version + 1, updated_at = NOW() \
              WHERE key = $4 AND scope = 'deployment' AND scope_ref IS NULL \
                AND is_deleted = FALSE",
        )
        .bind(entity)
        .bind(&patch)
        .bind(remove)
        .bind(KEY)
        .execute(&state.base.db)
        .await
        .expect("update admission setting")
        .rows_affected();
        if updated > 0 {
            break;
        }
        let initial = if remove { json!({}) } else { patch.clone() };
        let inserted = sqlx::query(
            "INSERT INTO setting (key, scope, scope_ref, value, schema) \
             VALUES ($1, 'deployment', NULL, $2, $3)",
        )
        .bind(KEY)
        .bind(&initial)
        .bind(json!({"type": "object"}))
        .execute(&state.base.db)
        .await;
        // A concurrent test inserted the row first: loop and merge into it.
        if inserted.is_ok() {
            break;
        }
    }
    state.settings.swap(
        attome_core::load_all_settings(&state.base.db)
            .await
            .expect("reload settings"),
    );
}

/// A live session opened by the MCP surface, tainted as every MCP session is.
async fn mcp_session(f: &Fixture, owner: Uuid) -> AgentSession {
    attome_ai::session::start(
        f.db(),
        &attome_audit::audit_service(&f.state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
            allowed_action_ids: None,
            surface: attome_ai::mcp::MCP_SURFACE,
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: true,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start MCP session")
}

async fn mcp_ctx(f: &Fixture, session: &AgentSession, key: &str) -> ActionContext {
    let security = Arc::new(
        attome_security::resolve_uncached(f.db(), session.owner_user_id)
            .await
            .expect("security"),
    );
    let ctx = ActionContext::for_session(security, session).with_idempotency_key(key);
    assert!(ctx.is_mcp_agent(), "precondition: an MCP agent context");
    ctx
}

fn is_not_found<T: std::fmt::Debug>(result: &Result<T, AppError>) -> bool {
    matches!(result, Err(AppError::NotFound))
}

/// **Default-deny.** Nothing listed → every record tool is refused darkly,
/// read and write alike, and the writes are refused before the gate (no
/// confirmation proposal, no approval request).
#[tokio::test]
async fn an_unadmitted_entity_is_refused_for_read_and_every_write() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let session = mcp_session(&f, f.owner).await;

    let cases = [
        ("record.get", json!({"entity": f.entity, "record_id": id})),
        (
            "record.create",
            json!({"entity": f.entity, "values": {"status": "x"}}),
        ),
        (
            "record.update",
            json!({"entity": f.entity, "record_id": id, "values": {"status": "x"}, "row_version": 0}),
        ),
        (
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        ),
        (
            "record.restore",
            json!({"entity": f.entity, "record_id": id}),
        ),
    ];
    for (action, args) in cases {
        let ctx = mcp_ctx(&f, &session, &format!("unadmitted-{action}")).await;
        let result = f.dispatch(&ctx, action, args).await;
        assert!(is_not_found(&result), "{action}: {result:?}");
    }
    assert_eq!(
        f.record(id).await,
        (Some("open".into()), true, 0),
        "nothing changed"
    );
    assert_eq!(f.row_count().await, 1, "nothing created");
}

/// An admitted entity works — for its admitted verbs only.
#[tokio::test]
async fn an_admitted_entity_works_for_its_admitted_verbs_only() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    admit(&f.state, &f.entity, &["read", "delete"]).await;
    let session = mcp_session(&f, f.owner).await;

    let ctx = mcp_ctx(&f, &session, "admitted-get").await;
    let read = f
        .dispatch(
            &ctx,
            "record.get",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(read, Ok(ActionOutcome::Completed { .. })),
        "{read:?}"
    );

    let ctx = mcp_ctx(&f, &session, "admitted-create").await;
    let create = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": f.entity, "values": {"status": "x"}}),
        )
        .await;
    assert!(is_not_found(&create), "create is not admitted: {create:?}");

    let ctx = mcp_ctx(&f, &session, "admitted-delete").await;
    let delete = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(delete, Ok(ActionOutcome::ApprovalRequired { .. })),
        "an admitted delete still goes to four-eyes: {delete:?}"
    );
    assert!(f.record(id).await.1, "nothing deleted yet");
}

/// **MI-3.** Security, identity and audit entities are refused over MCP even
/// when the setting admits them, while the engine's own ledger refusal still
/// holds for a direct caller.
#[tokio::test]
async fn excluded_entities_are_refused_even_when_admitted_and_the_ledger_refusal_holds() {
    let f = skip_if_no_db!(fixture().await);
    admit(&f.state, "user_account", &["read", "update"]).await;
    admit(
        &f.state,
        "audit_header",
        &["read", "create", "update", "delete"],
    )
    .await;
    let session = mcp_session(&f, f.owner).await;

    let ctx = mcp_ctx(&f, &session, "excluded-user").await;
    let user = f
        .dispatch(
            &ctx,
            "record.get",
            json!({"entity": "user_account", "record_id": f.owner}),
        )
        .await;
    assert!(is_not_found(&user), "{user:?}");

    let ctx = mcp_ctx(&f, &session, "excluded-audit").await;
    let audit = f
        .dispatch(
            &ctx,
            "record.create",
            json!({"entity": "audit_header", "values": {}}),
        )
        .await;
    assert!(is_not_found(&audit), "{audit:?}");

    // The ledger refusal is the engine's, and it is unchanged for a caller
    // admission does not govern.
    let direct = f.user_ctx(f.owner).await;
    let ledger = f
        .dispatch(
            &direct,
            "record.create",
            json!({"entity": "audit_header", "values": {}}),
        )
        .await;
    assert!(matches!(ledger, Err(AppError::Forbidden)), "{ledger:?}");
}

/// Admission only narrows: an admitted entity is still refused to a caller
/// who lacks the privilege.
#[tokio::test]
async fn admission_does_not_bypass_the_callers_own_privileges() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    admit(&f.state, &f.entity, &["read", "create"]).await;
    let nobody = seed_user(f.db(), false).await;
    let session = mcp_session(&f, nobody).await;

    let ctx = mcp_ctx(&f, &session, "nopriv-get").await;
    let read = f
        .dispatch(
            &ctx,
            "record.get",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(read.is_err(), "no read privilege, no read: {read:?}");
}

/// An approval does not freeze admission: withdrawing it before execution
/// invalidates the approved delete, and nothing is deleted.
#[tokio::test]
async fn withdrawn_admission_invalidates_an_approved_delete() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    admit(&f.state, &f.entity, &["delete"]).await;
    let session = mcp_session(&f, f.owner).await;
    let ctx = mcp_ctx(&f, &session, "withdrawn-delete").await;
    let outcome = f
        .dispatch(
            &ctx,
            "record.delete",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await
        .expect("dispatch");
    let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("an admitted delete goes to four-eyes: {outcome:?}");
    };

    let approver = seed_user(f.db(), true).await;
    attome_approval::decide(
        f.db(),
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a second person approves");
    admit(&f.state, &f.entity, &[]).await;

    let request = attome_ai::approval::approved_payload(f.db(), approval_id)
        .await
        .expect("read")
        .expect("approved payload");
    let executed = attome_ai::execute::dispatch_approved_agent_action_under(
        &f.state,
        &request,
        Some(approval_id),
    )
    .await
    .expect("execution is decided, not errored");
    assert!(
        matches!(executed, ApprovedExecution::Invalidated { .. }),
        "{executed:?}"
    );
    assert!(f.record(id).await.1, "the record is still live");
}

/// Admission governs the MCP surface only: an in-platform agent session reads
/// an entity nobody admitted, exactly as before.
#[tokio::test]
async fn a_non_mcp_agent_session_is_not_governed() {
    let f = skip_if_no_db!(fixture().await);
    let id = f.insert_record("open").await;
    let ctx = f.agent_ctx("internal-get").await;
    assert!(!ctx.is_mcp_agent());
    let read = f
        .dispatch(
            &ctx,
            "record.get",
            json!({"entity": f.entity, "record_id": id}),
        )
        .await;
    assert!(
        matches!(read, Ok(ActionOutcome::Completed { .. })),
        "{read:?}"
    );
}

// ---------------------------------------------------------------------------
// The read tools that reach entities without naming one up front
// (D-769's open item): query.execute, search.records, graph.traverse.
// ---------------------------------------------------------------------------

fn completed(outcome: Result<ActionOutcome, AppError>) -> serde_json::Value {
    match outcome {
        Ok(ActionOutcome::Completed { result, .. }) => result,
        other => panic!("expected the read to execute, got {other:?}"),
    }
}

fn entity_id(state: &EngineState, entity: &str) -> Uuid {
    state
        .entities
        .load()
        .get(entity)
        .map(|meta| meta.entity_id)
        .expect("entity registered")
}

async fn insert_row(state: &EngineState, entity: &str) -> Uuid {
    let table = attome_core::quote_ident(entity);
    sqlx::query_scalar(&format!(
        "INSERT INTO {table} (id, status, is_active, row_version) \
         VALUES ($1, 'open', true, 0) RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .fetch_one(&state.base.db)
    .await
    .expect("insert row")
}

/// An admin-only stored query over `entity`'s table whose published relation
/// inventory names `relations` (a throwaway-database write). The SQL reads
/// only `entity`; the inventory is what admission judges, as it is what
/// record-level scoping judges.
async fn stored_query(state: &EngineState, entity: &str, relations: &[&str]) -> Uuid {
    let id = Uuid::now_v7();
    let table = attome_core::quote_ident(entity);
    let sql = format!("SELECT t.id FROM {table} t");
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, is_active, created_at, owner_layer) \
         VALUES ($1, $2, '[]', true, NOW(), 'project')",
    )
    .bind(id)
    .bind(&sql)
    .execute(&state.base.db)
    .await
    .expect("insert stored query");
    let relations: Vec<String> = relations.iter().map(|r| (*r).to_owned()).collect();
    sqlx::query(
        "INSERT INTO sql_query_version (query_id, sql_query, relations, cost_estimate) \
         VALUES ($1, $2, $3, 1.0)",
    )
    .bind(id)
    .bind(&sql)
    .bind(&relations)
    .execute(&state.base.db)
    .await
    .expect("insert query version");
    id
}

/// `query.execute` runs over MCP only when every entity the query touches —
/// its linked entity and every relation in its inventory — is admitted for
/// read; an excluded relation refuses it even when admitted.
#[tokio::test]
async fn query_execute_needs_every_touched_entity_admitted() {
    let f = skip_if_no_db!(fixture().await);
    let other = common::provision_entity(&f.state, false).await;
    let record = f.insert_record("open").await;
    attome_metadata::provision::ensure_entity_list_views(
        f.db(),
        entity_id(&f.state, &f.entity),
        &f.entity,
        "Record Write Test",
    )
    .await
    .expect("default views");
    let session = mcp_session(&f, f.owner).await;
    let default_view = json!({ "entity": f.entity });
    let joined = stored_query(&f.state, &f.entity, &[&f.entity, &other]).await;
    let with_user = stored_query(&f.state, &f.entity, &[&f.entity, "user_account"]).await;

    // Nothing admitted: the entity's default view is refused darkly.
    let ctx = mcp_ctx(&f, &session, "q-unadmitted").await;
    let refused = f
        .dispatch(&ctx, "query.execute", default_view.clone())
        .await;
    assert!(is_not_found(&refused), "{refused:?}");

    // Admitted for a write verb only: still not a read.
    admit(&f.state, &f.entity, &["update"]).await;
    let ctx = mcp_ctx(&f, &session, "q-update-only").await;
    let refused = f
        .dispatch(&ctx, "query.execute", default_view.clone())
        .await;
    assert!(is_not_found(&refused), "{refused:?}");

    // Admitted for read: the default view runs and returns the record.
    admit(&f.state, &f.entity, &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "q-admitted").await;
    let result = completed(
        f.dispatch(&ctx, "query.execute", default_view.clone())
            .await,
    );
    assert!(
        result.to_string().contains(&record.to_string()),
        "the admitted query returns the record: {result}"
    );

    // A query whose inventory names an unadmitted relation is refused ...
    let ctx = mcp_ctx(&f, &session, "q-joined-refused").await;
    let refused = f
        .dispatch(&ctx, "query.execute", json!({ "query_id": joined }))
        .await;
    assert!(is_not_found(&refused), "{refused:?}");
    // ... and runs once that relation is admitted too.
    admit(&f.state, &other, &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "q-joined-admitted").await;
    completed(
        f.dispatch(&ctx, "query.execute", json!({ "query_id": joined }))
            .await,
    );

    // An excluded relation refuses the query even when the setting admits it.
    admit(&f.state, "user_account", &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "q-excluded").await;
    let refused = f
        .dispatch(&ctx, "query.execute", json!({ "query_id": with_user }))
        .await;
    assert!(is_not_found(&refused), "{refused:?}");

    // In-product callers are not governed: the same query runs for them.
    let internal = f.agent_ctx("q-internal").await;
    completed(
        f.dispatch(&internal, "query.execute", json!({ "query_id": with_user }))
            .await,
    );
}

/// Indexes one search row for `(entity, id)` titled with `token`.
async fn index_row(state: &EngineState, entity: &str, id: Uuid, token: &str) {
    let row = attome_search::project::project(
        &format!("{token} Nimbrel"),
        None,
        &format!("{token} Nimbrel record"),
        Vec::new(),
    );
    attome_search::drain::upsert_row(&state.base.db, entity, id, &row, None, None, None)
        .await
        .expect("index row");
}

fn hit_ids(result: &serde_json::Value) -> Vec<(String, String)> {
    result["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|hit| {
            (
                hit["entity_logicalname"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                hit["record_id"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// `search.records` over MCP returns hits of admitted entities only, counts
/// only those, answers a filter naming an unadmitted entity with an empty
/// page, and never shows an excluded entity even when admitted.
#[tokio::test]
async fn search_records_returns_admitted_entities_only() {
    let f = skip_if_no_db!(fixture().await);
    let other = common::provision_entity(&f.state, false).await;
    // Letters only, so an agent's query takes the hybrid route (a digit
    // would make it an identifier lookup).
    let token: String = Uuid::now_v7().simple().to_string()[20..]
        .chars()
        .map(|c| match c.to_digit(10) {
            Some(d) => char::from(b'g' + u8::try_from(d).unwrap_or(0)),
            None => c,
        })
        .collect();
    let token = format!("zq{token}");
    let mine = f.insert_record("open").await;
    let hidden = insert_row(&f.state, &other).await;
    index_row(&f.state, &f.entity, mine, &token).await;
    index_row(&f.state, &other, hidden, &token).await;
    index_row(&f.state, "user_account", f.owner, &token).await;
    let session = mcp_session(&f, f.owner).await;

    // Positive control: an in-product agent sees all three.
    let internal = f.agent_ctx("s-internal").await;
    let all = completed(
        f.dispatch(&internal, "search.records", json!({ "query": token }))
            .await,
    );
    assert_eq!(
        hit_ids(&all).len(),
        3,
        "fixture: every row is findable: {all}"
    );

    // Nothing admitted: an empty, exact-zero page.
    let ctx = mcp_ctx(&f, &session, "s-none").await;
    let none = completed(
        f.dispatch(&ctx, "search.records", json!({ "query": token }))
            .await,
    );
    assert!(hit_ids(&none).is_empty(), "{none}");
    assert_eq!(none["total"]["value"], 0, "{none}");
    assert_eq!(none["has_more"], false, "{none}");

    // One entity admitted: only its hit, counted alone.
    admit(&f.state, &f.entity, &["read"]).await;
    admit(&f.state, "user_account", &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "s-one").await;
    let one = completed(
        f.dispatch(&ctx, "search.records", json!({ "query": token }))
            .await,
    );
    assert_eq!(
        hit_ids(&one),
        vec![(f.entity.clone(), mine.to_string())],
        "{one}"
    );
    assert_eq!(one["total"]["value"], 1, "{one}");
    assert_eq!(one["has_more"], false, "{one}");
    let text = one.to_string();
    assert!(!text.contains(&hidden.to_string()), "{text}");
    assert!(!text.contains(&f.owner.to_string()), "excluded: {text}");

    // An explicit filter naming an unadmitted or excluded entity: empty.
    for filter in [other.as_str(), "user_account"] {
        let ctx = mcp_ctx(&f, &session, &format!("s-filter-{filter}")).await;
        let filtered = completed(
            f.dispatch(
                &ctx,
                "search.records",
                json!({ "query": format!("type:{filter} {token}") }),
            )
            .await,
        );
        assert!(hit_ids(&filtered).is_empty(), "{filter}: {filtered}");
        assert_eq!(filtered["total"]["value"], 0, "{filter}: {filtered}");
    }

    // Admitting the other entity shows its hit; the excluded one stays out.
    admit(&f.state, &other, &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "s-two").await;
    let two = completed(
        f.dispatch(&ctx, "search.records", json!({ "query": token }))
            .await,
    );
    let mut ids = hit_ids(&two);
    ids.sort();
    let mut expected = vec![
        (f.entity.clone(), mine.to_string()),
        (other.clone(), hidden.to_string()),
    ];
    expected.sort();
    assert_eq!(ids, expected, "{two}");
    assert_eq!(two["total"]["value"], 2, "{two}");

    // Paging runs over admitted hits: page 2 of size 1 is the second one.
    let ctx = mcp_ctx(&f, &session, "s-page").await;
    let page2 = completed(
        f.dispatch(
            &ctx,
            "search.records",
            json!({ "query": token, "page": 2, "page_size": 1 }),
        )
        .await,
    );
    assert_eq!(hit_ids(&page2).len(), 1, "{page2}");
    assert_eq!(page2["has_more"], false, "{page2}");
}

/// A throwaway entity under an explicit name (with the fixture's `status`
/// column), so a test can own an entity in an excluded family.
async fn provision_named(state: &EngineState, logicalname: &str) -> String {
    let id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        logicalname,
        "Admission Test",
        None,
        false,
    )
    .await
    .expect("provision entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        id,
        "status",
        "Status",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision attribute");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname.to_owned()
}

fn walk(entity: &str, id: Uuid) -> serde_json::Value {
    // Lookup edges only: the walk the test builds is two lookup fields.
    json!({
        "start": { "entity": entity, "id": id },
        "edge_types": ["lookup:peer", "lookup:usr"],
        "direction": "both",
        "max_depth": 2
    })
}

fn node_ids(result: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = result["nodes"]["items"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|n| n["record_id"].as_str().unwrap_or_default().to_owned())
        .collect();
    ids.sort();
    ids
}

/// `graph.traverse` over MCP refuses an unadmitted start, drops nodes of
/// unadmitted entities and anything reached only through them, and never
/// shows an excluded entity even when admitted.
#[tokio::test]
async fn graph_traverse_walks_admitted_entities_only() {
    let f = skip_if_no_db!(fixture().await);
    let other = common::provision_entity(&f.state, false).await;
    let a_id = entity_id(&f.state, &f.entity);
    let b_id = entity_id(&f.state, &other);
    let excluded = provision_named(&f.state, &format!("s2s_t{}", Uuid::now_v7().simple())).await;
    let excluded_id = entity_id(&f.state, &excluded);
    for (field, target) in [("peer", b_id), ("usr", excluded_id)] {
        attome_metadata::provision::ensure_attribute(
            f.db(),
            a_id,
            field,
            field,
            "lookup",
            false,
            false,
            false,
            false,
            Some(target),
            None,
        )
        .await
        .expect("lookup attribute");
    }
    f.state.entities.swap(
        attome_core::build_registry(f.db())
            .await
            .expect("rebuild entity registry"),
    );
    let b1 = insert_row(&f.state, &other).await;
    let secret = insert_row(&f.state, &excluded).await;
    let a1 = f.insert_record("open").await;
    let a2 = f.insert_record("open").await;
    let table = attome_core::quote_ident(&f.entity);
    sqlx::query(&format!(
        "UPDATE {table} SET peer = $1, usr = CASE WHEN id = $2 THEN $3 END WHERE id IN ($2, $4)"
    ))
    .bind(b1)
    .bind(a1)
    .bind(secret)
    .bind(a2)
    .execute(f.db())
    .await
    .expect("link records");
    let session = mcp_session(&f, f.owner).await;

    // Positive control: an in-product agent reaches b1, a2 through b1, and
    // the excluded-family record.
    let internal = f.agent_ctx("g-internal").await;
    let all = completed(
        f.dispatch(&internal, "graph.traverse", walk(&f.entity, a1))
            .await,
    );
    let all_ids = node_ids(&all);
    for id in [a1, a2, b1, secret] {
        assert!(
            all_ids.contains(&id.to_string()),
            "fixture reaches {id}: {all}"
        );
    }

    // Nothing admitted: the start entity itself is refused darkly.
    let ctx = mcp_ctx(&f, &session, "g-none").await;
    let refused = f
        .dispatch(&ctx, "graph.traverse", walk(&f.entity, a1))
        .await;
    assert!(is_not_found(&refused), "{refused:?}");

    // Start admitted, the intermediate not: a2 (reached only through b1)
    // and the excluded-family record (admitted, still excluded) are gone.
    admit(&f.state, &f.entity, &["read"]).await;
    admit(&f.state, &excluded, &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "g-start-only").await;
    let narrow = completed(
        f.dispatch(&ctx, "graph.traverse", walk(&f.entity, a1))
            .await,
    );
    assert_eq!(node_ids(&narrow), vec![a1.to_string()], "{narrow}");
    assert_eq!(narrow["nodes"]["total"], 1, "{narrow}");
    assert!(
        narrow["edges"].as_array().expect("edges").is_empty(),
        "{narrow}"
    );

    // A walk starting from the unadmitted entity is refused darkly.
    let ctx = mcp_ctx(&f, &session, "g-hidden-start").await;
    let refused = f.dispatch(&ctx, "graph.traverse", walk(&other, b1)).await;
    assert!(is_not_found(&refused), "{refused:?}");

    // Admitting the intermediate restores the path; the excluded record
    // stays out.
    admit(&f.state, &other, &["read"]).await;
    let ctx = mcp_ctx(&f, &session, "g-both").await;
    let wide = completed(
        f.dispatch(&ctx, "graph.traverse", walk(&f.entity, a1))
            .await,
    );
    let mut expected = vec![a1.to_string(), a2.to_string(), b1.to_string()];
    expected.sort();
    assert_eq!(node_ids(&wide), expected, "{wide}");
    assert!(!wide.to_string().contains(&secret.to_string()), "{wide}");
}

/// D-769: an admitted row's lookup display entry into an entity not admitted
/// for read is dropped over MCP — from `query.execute`'s `__lookups` and from
/// `record.get`'s `lookups` — while a lookup into an admitted entity keeps
/// its name and the raw foreign-key id (the row's own column) stays.
#[tokio::test]
async fn lookup_display_names_into_unadmitted_entities_are_dropped() {
    let f = skip_if_no_db!(fixture().await);
    let hidden = common::provision_entity(&f.state, false).await;
    let shown = common::provision_entity(&f.state, false).await;
    let a_id = entity_id(&f.state, &f.entity);
    for (field, target) in [
        ("peer", entity_id(&f.state, &hidden)),
        ("buddy", entity_id(&f.state, &shown)),
    ] {
        attome_metadata::provision::ensure_attribute(
            f.db(),
            a_id,
            field,
            field,
            "lookup",
            false,
            false,
            false,
            false,
            Some(target),
            None,
        )
        .await
        .expect("lookup attribute");
    }
    // Both targets display their `status` as the record name.
    sqlx::query(
        "UPDATE entity_info SET primary_name_attribute = 'status' \
          WHERE logicalname = ANY($1)",
    )
    .bind(vec![hidden.clone(), shown.clone()])
    .execute(f.db())
    .await
    .expect("set primary name attribute");
    f.state.entities.swap(
        attome_core::build_registry(f.db())
            .await
            .expect("rebuild entity registry"),
    );
    let hidden_name = format!("Hidden{}", Uuid::now_v7().simple());
    let shown_name = format!("Shown{}", Uuid::now_v7().simple());
    let mut target_ids = Vec::new();
    for (entity, name) in [(&hidden, &hidden_name), (&shown, &shown_name)] {
        let table = attome_core::quote_ident(entity);
        let id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO {table} (id, status, is_active, row_version) \
             VALUES ($1, $2, true, 0) RETURNING id"
        ))
        .bind(Uuid::now_v7())
        .bind(name)
        .fetch_one(f.db())
        .await
        .expect("insert target row");
        target_ids.push(id);
    }
    let (hidden_id, shown_id) = (target_ids[0], target_ids[1]);
    let a1 = f.insert_record("open").await;
    let table = attome_core::quote_ident(&f.entity);
    sqlx::query(&format!(
        "UPDATE {table} SET peer = $1, buddy = $2 WHERE id = $3"
    ))
    .bind(hidden_id)
    .bind(shown_id)
    .bind(a1)
    .execute(f.db())
    .await
    .expect("link record");

    // A stored query linked to the admitted entity, selecting both lookups.
    let query_id = Uuid::now_v7();
    let sql = format!("SELECT t.id, t.peer, t.buddy FROM {table} t");
    sqlx::query(
        "INSERT INTO sql_query \
         (id, sql_query, table_definition, entity_logical_name, is_active, created_at, owner_layer) \
         VALUES ($1, $2, '[]', $3, true, NOW(), 'project')",
    )
    .bind(query_id)
    .bind(&sql)
    .bind(a_id)
    .execute(f.db())
    .await
    .expect("insert stored query");
    sqlx::query(
        "INSERT INTO sql_query_version (query_id, sql_query, relations, cost_estimate) \
         VALUES ($1, $2, $3, 1.0)",
    )
    .bind(query_id)
    .bind(&sql)
    .bind(vec![f.entity.clone()])
    .execute(f.db())
    .await
    .expect("insert query version");

    let row_of = |result: &serde_json::Value| -> serde_json::Value {
        result["data"]["records"]
            .as_array()
            .expect("records")
            .iter()
            .find(|r| r["id"] == json!(a1.to_string()))
            .cloned()
            .unwrap_or_else(|| panic!("row {a1} in {result}"))
    };
    let run = json!({ "query_id": query_id });
    let get = json!({ "entity": f.entity, "record_id": a1 });

    // Positive control: an in-product agent sees both display names.
    let internal = f.agent_ctx("lk-internal").await;
    let all = completed(f.dispatch(&internal, "query.execute", run.clone()).await);
    let row = row_of(&all);
    assert_eq!(
        row["__lookups"]["peer"]["name"],
        json!(hidden_name),
        "{row}"
    );
    assert_eq!(
        row["__lookups"]["buddy"]["name"],
        json!(shown_name),
        "{row}"
    );
    let internal = f.agent_ctx("lk-internal-get").await;
    let record = completed(f.dispatch(&internal, "record.get", get.clone()).await);
    assert_eq!(
        record["lookups"]["peer"]["name"],
        json!(hidden_name),
        "{record}"
    );

    // Over MCP, with the row entity and one target admitted: the unadmitted
    // target's display entry is gone, the admitted one's stays, and the raw
    // foreign keys are still the row's own data.
    admit(&f.state, &f.entity, &["read"]).await;
    admit(&f.state, &shown, &["read"]).await;
    let session = mcp_session(&f, f.owner).await;
    let ctx = mcp_ctx(&f, &session, "lk-query").await;
    let result = completed(f.dispatch(&ctx, "query.execute", run.clone()).await);
    let row = row_of(&result);
    assert!(row["__lookups"].get("peer").is_none(), "{row}");
    assert_eq!(
        row["__lookups"]["buddy"]["name"],
        json!(shown_name),
        "{row}"
    );
    assert_eq!(row["peer"], json!(hidden_id.to_string()), "{row}");
    assert!(!result.to_string().contains(&hidden_name), "{result}");

    let ctx = mcp_ctx(&f, &session, "lk-get").await;
    let record = completed(f.dispatch(&ctx, "record.get", get.clone()).await);
    assert!(record["lookups"].get("peer").is_none(), "{record}");
    assert_eq!(
        record["lookups"]["buddy"]["name"],
        json!(shown_name),
        "{record}"
    );
    assert_eq!(
        record["data"]["peer"],
        json!(hidden_id.to_string()),
        "{record}"
    );
    assert!(!record.to_string().contains(&hidden_name), "{record}");

    // Withdrawing the other target leaves no display entry at all.
    admit(&f.state, &shown, &[]).await;
    let ctx = mcp_ctx(&f, &session, "lk-get-none").await;
    let record = completed(f.dispatch(&ctx, "record.get", get).await);
    assert!(record.get("lookups").is_none(), "{record}");
}

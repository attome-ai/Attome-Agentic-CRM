//! E8-T9: journey node counts match the runs, a person's path shows the
//! nodes and the reason they were blocked, a caller who may not look into
//! journeys is refused, and erasing a person leaves no journey rows.
//!
//! Journey runs are fixture rows in this binary's throwaway database
//! (guidelines §4's test exemption).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::erasure_hook::ErasureHook;
use attome_marketing::journey::insight::{JourneyErasure, counts, person_path, recount};
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn install_crm(app: &TestApp) {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

struct Journey {
    definition: Uuid,
    version: Uuid,
}

async fn journey(app: &TestApp) -> Journey {
    let definition = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workflow_definition (id, logicalname, name, owner_layer, kind) \
         VALUES ($1, $2, 'insight test', 'customer', 'journey')",
    )
    .bind(definition)
    .bind(format!("journey_{}", definition.simple()))
    .execute(app.db())
    .await
    .unwrap();
    let version = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workflow_definition_version (id, definition_id, version_number, graph, status) \
         VALUES ($1, $2, 1, $3, 'published')",
    )
    .bind(version)
    .bind(definition)
    .bind(json!({ "nodes": [], "edges": [] }))
    .execute(app.db())
    .await
    .unwrap();
    Journey {
        definition,
        version,
    }
}

/// One person's run: `nodes` as `(node, status)` in order, the enrolment in
/// `enrolment_status`; the run's instance.
async fn run(
    app: &TestApp,
    j: &Journey,
    person: Uuid,
    nodes: &[(&str, &str)],
    enrolment_status: &str,
) -> Uuid {
    let instance = Uuid::now_v7();
    let instance_status = if enrolment_status == "active" {
        "waiting"
    } else {
        "completed"
    };
    sqlx::query(
        "INSERT INTO workflow_instance (id, definition_version_id, status) VALUES ($1, $2, $3)",
    )
    .bind(instance)
    .bind(j.version)
    .bind(instance_status)
    .execute(app.db())
    .await
    .unwrap();
    for (i, (node, status)) in nodes.iter().enumerate() {
        sqlx::query(
            "INSERT INTO workflow_node_run (instance_id, node_id, status, started_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(instance)
        .bind(*node)
        .bind(*status)
        .bind(i as f64)
        .execute(app.db())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO marketing_journey_enrolment \
            (definition_id, definition_version_id, person_id, person_entity, instance_id, status, \
             entry_source, ended_at, end_reason) \
         VALUES ($1, $2, $3, 'contact', $4, $5, 'api', \
                 CASE WHEN $5 = 'active' THEN NULL ELSE now() END, \
                 CASE WHEN $5 = 'exited' THEN 'exit_condition' END)",
    )
    .bind(j.definition)
    .bind(j.version)
    .bind(person)
    .bind(instance)
    .bind(enrolment_status)
    .execute(app.db())
    .await
    .unwrap();
    instance
}

async fn block(app: &TestApp, instance: Uuid, node: &str, reason: &str) {
    sqlx::query(
        "INSERT INTO marketing_journey_block (instance_id, node_id, reason) VALUES ($1, $2, $3)",
    )
    .bind(instance)
    .bind(node)
    .bind(reason)
    .execute(app.db())
    .await
    .unwrap();
}

async fn contact(app: &TestApp) -> Uuid {
    sqlx::query_scalar("INSERT INTO contact (full_name, email) VALUES ('Huda', $1) RETURNING id")
        .bind(format!("e8t9-{}@example.invalid", Uuid::now_v7().simple()))
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn admin_ctx(app: &TestApp) -> attome_server::security::SecurityContext {
    attome_security::resolve_uncached(app.db(), app.admin.id)
        .await
        .unwrap()
}

// feature: E8
#[test]
fn counts_match_enrolments() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let j = journey(&app).await;
        let first = run(
            &app,
            &j,
            Uuid::now_v7(),
            &[("a", "succeeded"), ("b", "waiting")],
            "active",
        )
        .await;
        run(
            &app,
            &j,
            Uuid::now_v7(),
            &[("a", "succeeded"), ("b", "waiting")],
            "active",
        )
        .await;
        run(&app, &j, Uuid::now_v7(), &[("a", "succeeded")], "exited").await;
        block(&app, first, "b", "consent").await;

        recount(app.db(), &[j.version]).await.unwrap();
        let ctx = admin_ctx(&app).await;
        let got = counts(&app.state, &ctx, j.definition).await.unwrap();
        let node = |id: &str| {
            got.nodes
                .iter()
                .find(|n| n.node_id == id)
                .unwrap_or_else(|| panic!("node {id}: {got:?}"))
                .clone()
        };
        let a = node("a");
        assert_eq!((a.entered, a.passed, a.waiting, a.exited), (3, 3, 0, 1));
        let b = node("b");
        assert_eq!((b.entered, b.waiting, b.blocked), (2, 2, 1));
        assert_eq!(got.enrolled, 3);

        // A recount changes nothing.
        recount(app.db(), &[j.version]).await.unwrap();
        assert_eq!(counts(&app.state, &ctx, j.definition).await.unwrap(), got);
    });
}

// feature: E8
#[test]
fn person_path_includes_block_reason() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_crm(&app).await;
        let j = journey(&app).await;
        let person = contact(&app).await;
        let instance = run(
            &app,
            &j,
            person,
            &[("start", "succeeded"), ("email", "skipped")],
            "active",
        )
        .await;
        block(&app, instance, "email", "frequency_cap").await;

        let ctx = admin_ctx(&app).await;
        let path = person_path(&app.state, &ctx, j.definition, person)
            .await
            .unwrap();
        assert_eq!(path.len(), 1);
        let steps: Vec<&str> = path[0].steps.iter().map(|s| s.node_id.as_str()).collect();
        assert_eq!(steps, ["start", "email"]);
        assert_eq!(path[0].blocks[0].reason, "frequency_cap");
    });
}

// feature: E8
#[test]
fn unreadable_person_path_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let j = journey(&app).await;
        let person = Uuid::now_v7();
        run(&app, &j, person, &[("start", "succeeded")], "active").await;
        let nobody =
            attome_testapp::seed_user(app.db(), &format!("e8t9-{}", Uuid::now_v7().simple())).await;
        let ctx = attome_security::resolve_uncached(app.db(), nobody.id)
            .await
            .unwrap();
        let refused = person_path(&app.state, &ctx, j.definition, person).await;
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
        let refused = counts(&app.state, &ctx, j.definition).await;
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
    });
}

// feature: E8
#[test]
fn erasure_removes_journey_rows() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let j = journey(&app).await;
        let person = Uuid::now_v7();
        let other = Uuid::now_v7();
        let instance = run(
            &app,
            &j,
            person,
            &[("start", "succeeded"), ("wait", "waiting")],
            "active",
        )
        .await;
        run(&app, &j, other, &[("start", "succeeded")], "active").await;
        block(&app, instance, "wait", "consent").await;
        sqlx::query(
            "INSERT INTO marketing_message_log (person_id, channel, purpose, source_kind, source_id) \
             VALUES ($1, 'email', 'promotions', 'journey', $2)",
        )
        .bind(person)
        .bind(j.definition)
        .execute(app.db())
        .await
        .unwrap();

        let mut conn = app.db().acquire().await.unwrap();
        let removed = JourneyErasure
            .erase(&mut conn, "contact", person)
            .await
            .unwrap();
        drop(conn);
        assert!(removed >= 4, "{removed}");

        let left: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM marketing_journey_enrolment WHERE person_id = $1), \
                    (SELECT COUNT(*) FROM marketing_journey_block WHERE instance_id = $2), \
                    (SELECT COUNT(*) FROM marketing_message_log WHERE person_id = $1)",
        )
        .bind(person)
        .bind(instance)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(left, (0, 0, 0));
        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
                .bind(instance)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "cancelled");
        let others: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM marketing_journey_enrolment WHERE person_id = $1",
        )
        .bind(other)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(others, 1, "another person's run is untouched");
    });
}

async fn install_marketing(app: &TestApp) {
    for pack in ["crm", "marketing"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

// feature: E8
// negative: DELETE /api/v1/marketing/journeys/{id}/enrolments/{enrolment_id}
#[test]
fn journey_routes_count_cap_and_remove() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_marketing(&app).await;
        let j = journey(&app).await;
        let logicalname: String =
            sqlx::query_scalar("SELECT logicalname FROM workflow_definition WHERE id = $1")
                .bind(j.definition)
                .fetch_one(app.db())
                .await
                .unwrap();
        let record: Uuid = sqlx::query_scalar(
            "INSERT INTO marketing_journey (workflow_definition_logicalname, status, is_active, row_version) VALUES ($1, 'live', true, 0) RETURNING id",
        )
        .bind(&logicalname)
        .fetch_one(app.db())
        .await
        .unwrap();
        let person = Uuid::now_v7();
        let instance = run(
            &app,
            &j,
            person,
            &[("start", "succeeded"), ("wait", "waiting")],
            "active",
        )
        .await;
        recount(app.db(), &[j.version]).await.unwrap();

        let base = format!("/api/v1/marketing/journeys/{record}");
        let (status, body) = app
            .request(Method::GET, &format!("{base}/counts"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("\"wait\""), "{body}");

        let too_many: Vec<Value> = (0..1001)
            .map(|_| json!({ "id": Uuid::now_v7(), "entity": "contact" }))
            .collect();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("{base}/enrolments"),
                Some(json!({ "people": too_many })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // The list joins the people's records: this person has no contact row,
        // so the reader-scoped list holds nobody.
        let (status, body) = app
            .request(Method::GET, &format!("{base}/enrolments"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 0, "{body}");
        let enrolment: Uuid =
            sqlx::query_scalar("SELECT id FROM marketing_journey_enrolment WHERE instance_id = $1")
                .bind(instance)
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, body) = app
            .request(
                Method::DELETE,
                &format!("{base}/enrolments/{enrolment}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("{base}/enrolments/{enrolment}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "removed once");
        let run_status: String =
            sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
                .bind(instance)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(run_status, "cancelled");
    });
}

// feature: E8
#[test]
fn pause_and_resume_a_journey() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_marketing(&app).await;
        let j = journey(&app).await;
        let logicalname: String =
            sqlx::query_scalar("SELECT logicalname FROM workflow_definition WHERE id = $1")
                .bind(j.definition)
                .fetch_one(app.db())
                .await
                .unwrap();
        let record: Uuid = sqlx::query_scalar(
            "INSERT INTO marketing_journey (workflow_definition_logicalname, status, is_active, row_version) VALUES ($1, 'live', true, 0) RETURNING id",
        )
        .bind(&logicalname)
        .fetch_one(app.db())
        .await
        .unwrap();
        let instance = run(&app, &j, Uuid::now_v7(), &[("wait", "waiting")], "active").await;
        let status = |table: &'static str, id: Uuid| {
            let app = &app;
            async move {
                sqlx::query_scalar::<_, String>(&format!(
                    "SELECT status FROM {table} WHERE id = $1"
                ))
                .bind(id)
                .fetch_one(app.db())
                .await
                .unwrap()
            }
        };

        let base = format!("/api/v1/marketing/journeys/{record}");
        let (code, body) = app
            .request(
                Method::POST,
                &format!("{base}/simulate"),
                Some(json!({ "sample_people": [] })),
            )
            .await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (code, body) = app
            .request(Method::POST, &format!("{base}/pause"), None)
            .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["runs"], 1, "{body}");
        assert_eq!(status("workflow_instance", instance).await, "paused");
        assert_eq!(status("marketing_journey", record).await, "paused");
        let (code, _) = app
            .request(Method::POST, &format!("{base}/pause"), None)
            .await;
        assert_eq!(code, StatusCode::CONFLICT, "pausing twice");

        let (code, body) = app
            .request(Method::POST, &format!("{base}/resume"), None)
            .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(status("workflow_instance", instance).await, "running");
        assert_eq!(status("marketing_journey", record).await, "live");
    });
}

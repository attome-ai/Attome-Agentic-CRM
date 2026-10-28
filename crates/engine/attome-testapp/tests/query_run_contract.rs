//! S4-T14: the query/run contract. Both forms (text `q` and JSON `spec`)
//! answer the same rows, and a reader who may see only their own records
//! never learns of the others through an aggregate total, an EXISTS filter
//! or a related attribute.
//!
//! The parity cases are this file's own, over a provisioned parent and
//! child entity: `query_spec::cases` (each text parses to exactly its JSON
//! spec, S4-T8) names fields no deployment has and is visible to the crate's
//! unit tests only.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

struct Fx {
    parent: String,
    child: String,
    /// Sees only the records it owns (Team depth, no teams).
    reader: TestUser,
}

async fn create_entity(app: &TestApp, name: &str, fields: &[Value]) -> Uuid {
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    for field in fields {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(field.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    id
}

/// A role reading `entity` at Team depth, held by `user`.
async fn grant_team_read(app: &TestApp, user: &TestUser, entity: &str, entity_id: Uuid) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("qrc-{role}"))
        .execute(app.db())
        .await
        .unwrap();
    let key = format!("{entity}.read");
    let privilege: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&key)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) \
         VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role)
    .bind(privilege)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 1, 0, 0, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role)
    .bind(entity_id)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .unwrap();
}

/// Parents 1 to 6 (amount n * 10), the reader owning 1 to 3 and nobody 4 to
/// 6; a child of parent 1 (the reader's) and of parent 4 (hidden from it).
async fn fixture(app: &TestApp) -> Fx {
    let suffix = &Uuid::now_v7().simple().to_string()[..12];
    let parent = format!("qrp_{suffix}");
    let child = format!("qrc_{suffix}");
    let parent_id = create_entity(
        app,
        &parent,
        &[
            json!({ "logicalname": "title", "name": "title", "field_type": "text",
                    "is_sortable": true, "is_filterable": true }),
            json!({ "logicalname": "amount", "name": "amount", "field_type": "number",
                    "is_sortable": true, "is_filterable": true }),
        ],
    )
    .await;
    let child_id = create_entity(
        app,
        &child,
        &[
            json!({ "logicalname": "note", "name": "note", "field_type": "text",
                    "is_filterable": true }),
            json!({ "logicalname": "parent", "name": "parent", "field_type": "lookup",
                    "lookup_entity_ref": parent_id, "is_filterable": true }),
        ],
    )
    .await;
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);

    let reader = attome_testapp::seed_user(app.db(), "qrc-reader").await;
    grant_team_read(app, &reader, &parent, parent_id).await;
    grant_team_read(app, &reader, &child, child_id).await;

    let mut parents = Vec::new();
    for n in 1..=6_i32 {
        let owner = (n <= 3).then_some(reader.id);
        let id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO \"{parent}\" (title, amount, owner_ref) VALUES ($1, $2, $3) RETURNING id"
        ))
        .bind(format!("p{n}"))
        .bind(n * 10)
        .bind(owner)
        .fetch_one(app.db())
        .await
        .unwrap();
        parents.push(id);
    }
    for (n, owner) in [(0_usize, Some(reader.id)), (3, None)] {
        sqlx::query(&format!(
            "INSERT INTO \"{child}\" (note, parent, owner_ref) VALUES ($1, $2, $3)"
        ))
        .bind(format!("child of p{}", n + 1))
        .bind(parents[n])
        .bind(owner)
        .execute(app.db())
        .await
        .unwrap();
    }
    Fx {
        parent,
        child,
        reader,
    }
}

async fn run(app: &TestApp, cookie: Option<&str>, body: Value) -> Value {
    let (status, answer) = match cookie {
        Some(cookie) => {
            app.request_as(cookie, Method::POST, "/api/v1/query/run", Some(body))
                .await
        }
        None => {
            app.request(Method::POST, "/api/v1/query/run", Some(body))
                .await
        }
    };
    assert_eq!(status, StatusCode::OK, "{answer}");
    answer
}

// feature: S4
#[test]
fn every_case_gives_identical_results_in_both_forms() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let fx = fixture(&app).await;
        let p = &fx.parent;
        let cases: Vec<(String, Value)> = vec![
            (
                format!("SELECT title FROM {p} ORDER BY amount"),
                json!({ "entity": p, "select": ["title"], "sort": [{"field": "amount"}] }),
            ),
            (
                format!(
                    "SELECT title FROM {p} WHERE amount > 20 AND amount <= 50 ORDER BY amount DESC"
                ),
                json!({ "entity": p, "select": ["title"],
                        "where": {"kind": "and", "all": [
                            {"kind": "compare", "field": "amount", "op": "gt", "value": 20},
                            {"kind": "compare", "field": "amount", "op": "lte", "value": 50}]},
                        "sort": [{"field": "amount", "desc": true}] }),
            ),
            (
                format!(
                    "SELECT title FROM {p} WHERE title IN ('p1', 'p6') OR amount = 30 ORDER BY title"
                ),
                json!({ "entity": p, "select": ["title"],
                        "where": {"kind": "or", "any": [
                            {"kind": "compare", "field": "title", "op": "in", "value": ["p1", "p6"]},
                            {"kind": "compare", "field": "amount", "op": "eq", "value": 30}]},
                        "sort": [{"field": "title"}] }),
            ),
            (
                format!(
                    "SELECT title FROM {p} WHERE EXISTS({}.parent) ORDER BY title",
                    fx.child
                ),
                json!({ "entity": p, "select": ["title"],
                        "where": {"kind": "exists", "path": format!("{}.parent", fx.child)},
                        "sort": [{"field": "title"}] }),
            ),
            (
                format!("SELECT count(*) AS n, sum(amount) AS total FROM {p}"),
                json!({ "entity": p,
                        "aggregates": [{"func": "count", "alias": "n"},
                                       {"func": "sum", "field": "amount", "alias": "total"}] }),
            ),
        ];
        for (text, spec) in cases {
            let by_text = run(&app, None, json!({ "q": text })).await;
            let by_spec = run(&app, None, json!({ "spec": spec })).await;
            for key in ["items", "groups"] {
                assert_eq!(
                    by_text[key], by_spec[key],
                    "{text}\ntext {by_text}\nspec {by_spec}"
                );
            }
        }
    });
}

// feature: S4
#[test]
fn aggregate_total_excludes_hidden_records() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let fx = fixture(&app).await;
        let spec = json!({ "spec": { "entity": fx.parent,
            "aggregates": [{"func": "count", "alias": "n"},
                           {"func": "sum", "field": "amount", "alias": "total"}] } });
        let admin = run(&app, None, spec.clone()).await;
        assert_eq!(
            admin["groups"][0]["values"]["n"].as_f64(),
            Some(6.0),
            "{admin}"
        );
        let reader = run(&app, Some(&fx.reader.cookie), spec).await;
        assert_eq!(
            reader["groups"][0]["values"]["n"].as_f64(),
            Some(3.0),
            "{reader}"
        );
        assert_eq!(
            reader["groups"][0]["values"]["total"].as_f64(),
            Some(60.0),
            "the reader's own 10 + 20 + 30: {reader}"
        );
    });
}

// feature: S4
#[test]
fn exists_filter_ignores_hidden_children() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let fx = fixture(&app).await;
        // p4 is hidden from the reader, and so is its child; a child of a
        // visible parent that the reader cannot see must not make it match
        // either, so look from the parents the reader can see.
        let spec = json!({ "spec": { "entity": fx.parent, "select": ["title"],
            "where": {"kind": "exists", "path": format!("{}.parent", fx.child)},
            "sort": [{"field": "title"}] } });
        let admin = run(&app, None, spec.clone()).await;
        let titles = |answer: &Value| {
            answer["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["title"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(titles(&admin), ["p1", "p4"], "{admin}");
        let reader = run(&app, Some(&fx.reader.cookie), spec).await;
        assert_eq!(titles(&reader), ["p1"], "{reader}");

        // The reader's own parent p2 has no child the reader sees, even if
        // a hidden one points at it.
        sqlx::query(&format!(
            "INSERT INTO \"{}\" (note, parent) SELECT 'hidden child', id FROM \"{}\" WHERE title = 'p2'",
            fx.child, fx.parent
        ))
        .execute(app.db())
        .await
        .unwrap();
        let reader = run(
            &app,
            Some(&fx.reader.cookie),
            json!({ "spec": { "entity": fx.parent, "select": ["title"],
                "where": {"kind": "exists", "path": format!("{}.parent", fx.child)},
                "sort": [{"field": "title"}] } }),
        )
        .await;
        assert_eq!(titles(&reader), ["p1"], "{reader}");
    });
}

// feature: S4
#[test]
fn related_attribute_is_null_when_target_hidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let fx = fixture(&app).await;
        // A child the reader owns, pointing at p5, which the reader cannot see.
        sqlx::query(&format!(
            "INSERT INTO \"{}\" (note, parent, owner_ref) \
             SELECT 'mine, hidden parent', id, $1 FROM \"{}\" WHERE title = 'p5'",
            fx.child, fx.parent
        ))
        .bind(fx.reader.id)
        .execute(app.db())
        .await
        .unwrap();
        let answer = run(
            &app,
            Some(&fx.reader.cookie),
            json!({ "spec": { "entity": fx.child, "select": ["note", "parent.title"],
                "sort": [{"field": "note"}] } }),
        )
        .await;
        let rows = answer["items"].as_array().unwrap();
        let by_note = |note: &str| {
            rows.iter()
                .find(|r| r["note"] == note)
                .unwrap_or_else(|| panic!("{note} missing: {answer}"))
        };
        assert_eq!(by_note("child of p1")["parent.title"], "p1", "{answer}");
        assert_eq!(
            by_note("mine, hidden parent")["parent.title"],
            Value::Null,
            "a hidden target's attribute reads as null: {answer}"
        );
        assert_eq!(
            rows.len(),
            2,
            "the hidden child of p4 is not listed: {answer}"
        );
    });
}

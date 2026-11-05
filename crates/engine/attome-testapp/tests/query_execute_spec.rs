//! V2-D1808: a stored KPI over one entity, run through `query/execute` by a
//! reader who may see only their own records. Declared as a QuerySpec it
//! counts only theirs (the scope applies before the aggregate); declared as
//! SQL whose output has no `id`, the record filter cannot narrow it, so the
//! reader is refused with 403, not a 500. An administrator gets the whole.

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

async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    for field in [
        json!({ "logicalname": "title", "name": "title", "field_type": "text",
                "is_sortable": true, "is_filterable": true }),
        json!({ "logicalname": "amount", "name": "amount", "field_type": "number",
                "is_sortable": true, "is_filterable": true }),
        json!({ "logicalname": "opened_at", "name": "opened_at", "field_type": "date_time",
                "is_filterable": true }),
        json!({ "logicalname": "closed_at", "name": "closed_at", "field_type": "date_time",
                "is_filterable": true }),
    ] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(field),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    id
}

/// A role reading `entity` at Team depth (its owner reaches their own
/// records), held by `user`.
async fn grant_team_read(app: &TestApp, user: &TestUser, entity: &str, entity_id: Uuid) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("qes-{role}"))
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
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, \
             read_owner_visible, owner_layer) \
         VALUES ($1, $2, $3, 1, 0, 0, true, 'project')",
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

async fn create_query(app: &TestApp, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, "/api/v1/admin/queries", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

/// A number from a record, as JSON number or numeric text.
fn number(record: &Value, key: &str) -> f64 {
    match &record[key] {
        Value::Number(n) => n.as_f64().unwrap(),
        Value::String(s) => s.parse().unwrap(),
        other => panic!("{key} is not a number: {other} in {record}"),
    }
}

// feature: S4
#[test]
fn a_kpi_counts_only_what_its_reader_may_see() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("qes_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let entity_id = create_entity(&app, &entity).await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let reader = attome_testapp::seed_user(app.db(), "qes-reader").await;
        grant_team_read(&app, &reader, &entity, entity_id).await;
        // Six records of 10 to 60; the reader owns the first three.
        for n in 1..=6_i32 {
            sqlx::query(&format!(
                "INSERT INTO \"{entity}\" (title, amount, owner_ref, opened_at, closed_at) \
                 VALUES ($1, $2, $3, now() - interval '1 day', \
                         now() - interval '1 day' + make_interval(hours => $4))"
            ))
            .bind(format!("r{n}"))
            .bind(n * 10)
            .bind((n <= 3).then_some(reader.id))
            .bind(n)
            .execute(app.db())
            .await
            .unwrap();
        }

        let spec_kpi = create_query(
            &app,
            json!({
                "name": "spec kpi",
                "entity_logical_name": entity_id,
                "required_privilege": format!("{entity}.read"),
                "is_report": true,
                "query_spec": {
                    "entity": entity,
                    "aggregates": [
                        { "func": "count", "alias": "n" },
                        { "func": "sum", "field": "amount", "alias": "total" },
                        { "func": "count", "alias": "big",
                          "filter": { "kind": "compare", "field": "amount", "op": "gt", "value": 15 } },
                        { "func": "avg", "field": "closed_at", "alias": "hours",
                          "since": { "field": "opened_at", "unit": "hours" } }
                    ]
                },
                "parameters": []
            }),
        )
        .await;
        let sql_kpi = create_query(
            &app,
            json!({
                "name": "sql kpi",
                "entity_logical_name": entity_id,
                "required_privilege": format!("{entity}.read"),
                "is_report": true,
                "sql_query": format!("SELECT COUNT(*)::bigint AS value FROM \"{entity}\" WHERE is_active = true")
            }),
        )
        .await;

        let run = |id: Uuid| json!({ "query_id": id, "page_size": 10 });

        // The QuerySpec counts the reader's three records only.
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                "/api/v1/query/execute",
                Some(run(spec_kpi)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = &body["data"]["records"][0];
        assert_eq!(number(row, "n"), 3.0, "{body}");
        assert_eq!(number(row, "total"), 60.0, "{body}");
        // A measure with its own filter counts only the rows that meet it.
        assert_eq!(number(row, "big"), 2.0, "{body}");
        // Record n closes n hours after it opens: the reader's 1, 2, 3.
        assert!((number(row, "hours") - 2.0).abs() < 1e-6, "{body}");
        let columns: Vec<&str> = body["data"]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert_eq!(columns, ["n", "total", "big", "hours"], "{body}");

        // The administrator, whom no filter narrows, counts all six.
        let (status, body) = app
            .request(Method::POST, "/api/v1/query/execute", Some(run(spec_kpi)))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(number(&body["data"]["records"][0], "n"), 6.0, "{body}");

        // The SQL aggregate has no id to narrow: 403 for the reader, not 500.
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                "/api/v1/query/execute",
                Some(run(sql_kpi)),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = app
            .request(Method::POST, "/api/v1/query/execute", Some(run(sql_kpi)))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(number(&body["data"]["records"][0], "value"), 6.0, "{body}");

        // A view-like query keeping `id` but not the owner columns the
        // reader's scope needs is scoped through the id: their three rows.
        let thin_view = create_query(
            &app,
            json!({
                "name": "thin view",
                "entity_logical_name": entity_id,
                "required_privilege": format!("{entity}.read"),
                "sql_query": format!("SELECT id, title FROM \"{entity}\" WHERE is_active = true")
            }),
        )
        .await;
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "query_id": thin_view, "page_size": 10, "include_total": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut titles: Vec<&str> = body["data"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["title"].as_str())
            .collect();
        titles.sort_unstable();
        assert_eq!(titles, ["r1", "r2", "r3"], "{body}");

        // What a QuerySpec cannot honour here is a 422, not ignored.
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "query_id": spec_kpi, "search": "r1" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

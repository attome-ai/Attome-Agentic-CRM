//! P2-T1 / P2-T2: an author's SQL report returns only what the author can
//! read. A reader who sees only their own records and holds no grant on a
//! sensitive field runs SQL through `POST /api/v1/reports/sql/run`: a join
//! never brings in a hidden record, the sensitive field does not exist for
//! them, a schema-qualified name, a function that reads a table by name and
//! a write all fail, and a session advisory lock does not outlive the run.

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

async fn privilege(app: &TestApp, key: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(key)
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// A role reading `entity` at Team depth (own records only), held by `user`.
async fn grant_team_read(app: &TestApp, user: &TestUser, entity: &str, entity_id: Uuid) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("ssql-{role}"))
        .execute(app.db())
        .await
        .unwrap();
    let read = privilege(app, &format!("{entity}.read")).await;
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) \
         VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role)
    .bind(read)
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

async fn grant_direct(app: &TestApp, user: &TestUser, key: &str) {
    let id = privilege(app, key).await;
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user.id)
    .bind(id)
    .execute(app.db())
    .await
    .unwrap();
}

/// Parents p1 to p6 with a sensitive `secret`, the reader owning p1 to p3;
/// a child of p1 (the reader's) and of p4 (hidden from it).
async fn fixture(app: &TestApp) -> Fx {
    let suffix = &Uuid::now_v7().simple().to_string()[..12];
    let parent = format!("ssp_{suffix}");
    let child = format!("ssc_{suffix}");
    let parent_id = create_entity(
        app,
        &parent,
        &[
            json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
            json!({ "logicalname": "secret", "name": "secret", "field_type": "text",
                    "is_sensitive": true }),
        ],
    )
    .await;
    let child_id = create_entity(
        app,
        &child,
        &[
            json!({ "logicalname": "note", "name": "note", "field_type": "text" }),
            json!({ "logicalname": "parent", "name": "parent", "field_type": "lookup",
                    "lookup_entity_ref": parent_id }),
        ],
    )
    .await;
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);

    let reader = attome_testapp::seed_user(app.db(), "ssql-reader").await;
    grant_team_read(app, &reader, &parent, parent_id).await;
    grant_team_read(app, &reader, &child, child_id).await;
    grant_direct(app, &reader, "attome_report.author_sql").await;

    let mut parents = Vec::new();
    for n in 1..=6_i32 {
        let owner = (n <= 3).then_some(reader.id);
        let id: Uuid = sqlx::query_scalar(&format!(
            "INSERT INTO \"{parent}\" (title, secret, owner_ref) VALUES ($1, $2, $3) RETURNING id"
        ))
        .bind(format!("p{n}"))
        .bind(format!("s{n}"))
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

async fn run_sql(app: &TestApp, cookie: Option<&str>, sql: &str) -> (StatusCode, Value) {
    let body = json!({ "sql": sql });
    match cookie {
        Some(cookie) => {
            app.request_as(cookie, Method::POST, "/api/v1/reports/sql/run", Some(body))
                .await
        }
        None => {
            app.request(Method::POST, "/api/v1/reports/sql/run", Some(body))
                .await
        }
    }
}

fn column(answer: &Value, name: &str) -> Vec<String> {
    let mut values: Vec<String> = answer["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[name].as_str().unwrap_or_default().to_owned())
        .collect();
    values.sort();
    values
}

// feature: P2
#[test]
fn user_sql_never_returns_what_the_author_cannot_read() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let fx = fixture(&app).await;
        let (p, c) = (&fx.parent, &fx.child);
        let reader = Some(fx.reader.cookie.as_str());

        let (status, answer) = run_sql(&app, reader, &format!("SELECT title FROM {p}")).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(column(&answer, "title"), ["p1", "p2", "p3"]);
        assert_eq!(answer["columns"], json!(["title"]));

        // A join reaches no hidden record, from either side.
        let (status, answer) = run_sql(
            &app,
            reader,
            &format!("SELECT x.note, y.title FROM {c} x JOIN {p} y ON y.id = x.parent"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(column(&answer, "note"), ["child of p1"]);

        // An aggregate counts only readable rows.
        let (_, answer) = run_sql(&app, reader, &format!("SELECT count(*) AS n FROM {p}")).await;
        assert_eq!(answer["rows"][0]["n"], json!(3));

        // The sensitive field does not exist for the reader.
        let (status, answer) = run_sql(&app, reader, &format!("SELECT secret FROM {p}")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");

        // Around the views: the real table, a function reading it by name,
        // a second statement and a write all fail.
        let schema: String = sqlx::query_scalar("SELECT current_schema()::text")
            .fetch_one(app.db())
            .await
            .unwrap();
        for sql in [
            format!("SELECT count(*) FROM \"{schema}\".\"{p}\""),
            format!(
                "SELECT query_to_xml('SELECT secret FROM \"{schema}\".\"{p}\"', true, true, '')"
            ),
            format!("SELECT 1; DELETE FROM {p}"),
            format!("WITH d AS (DELETE FROM {p} RETURNING 1) SELECT * FROM d"),
            "SELECT count(*) FROM user_account".to_owned(),
        ] {
            let (status, answer) = run_sql(&app, reader, &sql).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{sql}: {answer}");
        }
        let left: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"{p}\""))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(left, 6, "nothing was deleted");

        // A session advisory lock is released with the run.
        let (status, answer) = run_sql(
            &app,
            reader,
            "SELECT pg_advisory_lock(4242017) IS NULL AS x",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let held: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 4242017",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(held, 0, "the lock did not outlive the run");

        // The plan comes back on request; a non-author is refused.
        let (status, answer) = app
            .request_as(
                &fx.reader.cookie,
                Method::POST,
                "/api/v1/reports/sql/run",
                Some(json!({ "sql": format!("SELECT title FROM {p}"), "explain": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert!(answer["plan"].is_array(), "{answer}");
        let stranger = attome_testapp::seed_user(app.db(), "ssql-stranger").await;
        let (status, _) = run_sql(&app, Some(&stranger.cookie), "SELECT 1").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // An administrator reads every record and field.
        let (status, answer) = run_sql(&app, None, &format!("SELECT title, secret FROM {p}")).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(column(&answer, "secret").len(), 6);
    });
}

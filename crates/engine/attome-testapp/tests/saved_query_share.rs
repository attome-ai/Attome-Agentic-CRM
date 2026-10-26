//! A14-T2: a saved query with parameter defaults, shared with a role or a
//! team, runs for the users it is shared with; an edit share also lets them
//! change its QuerySpec and parameters, and nobody else.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::changeset::Layer;
use attome_testapp::{TestApp, TestUser, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// A fresh entity with a number `level`, two records, and a saved query
/// `level == :level` whose `level` defaults to 2. Returns the entity name and
/// the query id.
async fn saved_query(app: &TestApp) -> (String, String) {
    let entity = format!("sqs_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let entity_id = created["id"].as_str().unwrap().to_owned();
    for (name, field_type) in [("title", "text"), ("level", "number")] {
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": name, "name": name, "field_type": field_type })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for (title, level) in [("first", 1), ("second", 2)] {
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": title, "level": level })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
    }
    let (status, query) = app
        .request(
            Method::POST,
            "/api/v1/admin/queries",
            Some(json!({
                "name": format!("{entity} by level"),
                "query_spec": {
                    "entity": entity,
                    "select": ["title", "level"],
                    "where": {"kind": "param", "field": "level", "op": "eq", "param": "level"},
                },
                "parameters": [{"name": "level", "type": "number", "required": true, "default": 2}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{query}");
    assert_eq!(query["parameters"][0]["default"], 2, "{query}");
    (entity, query["id"].as_str().unwrap().to_owned())
}

/// A role that may read every `entity` record.
async fn reader_role(app: &TestApp, entity: &str) -> Uuid {
    let role = new_role(app, "reader").await;
    let read_key = format!("{entity}.read");
    attome_security::db::ensure_privilege(app.db(), &read_key, &read_key, "test", Layer::Project)
        .await
        .expect("ensure the entity's read privilege");
    for (path, body) in [
        (
            "/api/v1/admin/security/role-grants",
            json!({ "role_id": role, "privilege_key": read_key }),
        ),
        (
            "/api/v1/admin/security/role-entity-access",
            json!({ "role_id": role, "entity": entity, "read_access_level": 3 }),
        ),
    ] {
        let (status, body) = app.request(Method::POST, path, Some(body)).await;
        assert!(status.is_success(), "{path}: {status} {body}");
    }
    role
}

async fn new_role(app: &TestApp, label: &str) -> Uuid {
    let name = format!("{label}-{}", Uuid::now_v7().simple());
    let (status, role) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/roles",
            Some(json!({ "name": name })),
        )
        .await;
    assert!(status.is_success(), "{status} {role}");
    role["id"].as_str().unwrap().parse().unwrap()
}

async fn user_with(app: &TestApp, roles: &[Uuid], team: Option<Uuid>) -> TestUser {
    let user = seed_user(app.db(), "shared-query").await;
    for role in roles {
        sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
            .bind(user.id)
            .bind(role)
            .execute(app.db())
            .await
            .expect("grant the role");
    }
    if let Some(team) = team {
        sqlx::query("INSERT INTO user_account_mm_team (user_ref, team_ref) VALUES ($1, $2)")
            .bind(user.id)
            .bind(team)
            .execute(app.db())
            .await
            .expect("join the team");
    }
    user
}

async fn run_as(app: &TestApp, user: &TestUser, body: Value) -> (StatusCode, Value) {
    app.request_as(&user.cookie, Method::POST, "/api/v1/query/run", Some(body))
        .await
}

fn titles(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["title"].as_str().unwrap().to_owned())
        .collect()
}

// feature: A14
// negative: PUT /api/v1/admin/query-shares/{id}, PATCH /api/v1/admin/queries/{id}/spec
#[test]
fn shared_query_runs_with_params_for_shared_users() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, id) = saved_query(&app).await;
        let reader = reader_role(&app, &entity).await;
        let shared_role = new_role(&app, "shared").await;
        let team: Uuid = sqlx::query_scalar("INSERT INTO team (name) VALUES ($1) RETURNING id")
            .bind(format!("team-{}", Uuid::now_v7().simple()))
            .fetch_one(app.db())
            .await
            .unwrap();
        let by_role = user_with(&app, &[reader, shared_role], None).await;
        let by_team = user_with(&app, &[reader], Some(team)).await;
        let outsider = user_with(&app, &[reader], None).await;

        let (status, shares) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/query-shares/{id}"),
                Some(json!({"shares": [
                    {"principal_type": "role", "principal_id": shared_role, "access": "read"},
                    {"principal_type": "team", "principal_id": team, "access": "edit"},
                ]})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{shares}");
        assert_eq!(shares["shares"].as_array().unwrap().len(), 2, "{shares}");

        // The default applies when the run leaves the parameter out; a value
        // sent wins.
        let (status, page) = run_as(&app, &by_role, json!({ "query_id": id })).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(titles(&page), ["second"], "{page}");
        let (status, page) = run_as(
            &app,
            &by_team,
            json!({ "query_id": id, "params": { "level": 1 } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(titles(&page), ["first"], "{page}");
        let (status, body) = run_as(&app, &outsider, json!({ "query_id": id })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // Each user sees what is shared with them.
        let (status, listed) = app
            .request_as(&by_team.cookie, Method::GET, "/api/v1/queries/shared", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let mine: Vec<&Value> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|q| q["id"] == id.as_str())
            .collect();
        assert_eq!(mine.len(), 1, "{listed}");
        assert_eq!(mine[0]["access"], "edit", "{listed}");
        assert_eq!(mine[0]["parameters"][0]["name"], "level", "{listed}");
        let (status, listed) = app
            .request_as(
                &outsider.cookie,
                Method::GET,
                "/api/v1/queries/shared",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|q| q["id"] != id.as_str()),
            "{listed}"
        );

        // Only an edit share may change the spec; the change takes effect.
        let new_default = json!({"parameters": [
            {"name": "level", "type": "number", "required": true, "default": 1}
        ]});
        let path = format!("/api/v1/admin/queries/{id}/spec");
        let (status, body) = app
            .request_as(
                &by_role.cookie,
                Method::PATCH,
                &path,
                Some(new_default.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a read share: {body}");
        let (status, body) = app
            .request_as(&by_team.cookie, Method::PATCH, &path, Some(new_default))
            .await;
        assert_eq!(status, StatusCode::OK, "an edit share: {body}");
        let (status, page) = run_as(&app, &by_role, json!({ "query_id": id })).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(titles(&page), ["first"], "{page}");
        // An editor never changes the SQL or the privilege.
        let (status, body) = app
            .request_as(
                &by_team.cookie,
                Method::PATCH,
                &path,
                Some(json!({"sql_query": "SELECT 1 AS id"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // An empty list stops sharing.
        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/query-shares/{id}"),
                Some(json!({"shares": []})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = run_as(&app, &by_role, json!({ "query_id": id })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    });
}

// feature: A14
// negative: put_query_shares
#[test]
fn query_shares_are_admin_only_and_checked() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, id) = saved_query(&app).await;
        let user = seed_user(app.db(), "share-admin").await;
        let path = format!("/api/v1/admin/query-shares/{id}");
        let (status, _) = app.request_as(&user.cookie, Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .request_as(
                &user.cookie,
                Method::PUT,
                &path,
                Some(json!({"shares": []})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A role that does not exist, and the same role twice, are refused.
        let ghost = Uuid::now_v7();
        let (status, body) = app
            .request(
                Method::PUT,
                &path,
                Some(json!({"shares": [
                    {"principal_type": "role", "principal_id": ghost, "access": "read"}
                ]})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let role = new_role(&app, "twice").await;
        let (status, body) = app
            .request(
                Method::PUT,
                &path,
                Some(json!({"shares": [
                    {"principal_type": "role", "principal_id": role, "access": "read"},
                    {"principal_type": "role", "principal_id": role, "access": "edit"},
                ]})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/query-shares/{}", Uuid::now_v7()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

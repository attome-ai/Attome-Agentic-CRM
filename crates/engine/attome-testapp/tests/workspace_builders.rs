//! T1-T3: builders. A person holding `develop.build` (without the data-model
//! area) sees and enters the workspaces of their team; their publish of a
//! workspace someone else owns waits for the owner's review; a person who
//! does not build is refused.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// The privilege row, as platform changeset 0091 makes it.
async fn ensure_privilege(app: &TestApp, key: &str) -> Uuid {
    sqlx::query(
        "INSERT INTO privilege (id, key, name, owner_layer) \
         SELECT $1, $2, $2, 'platform' WHERE NOT EXISTS (SELECT 1 FROM privilege WHERE key = $2)",
    )
    .bind(Uuid::now_v7())
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// A person holding `develop.build` through a role of their own, on `team`.
async fn builder(app: &TestApp, team: Uuid) -> TestUser {
    let user = seed_user(app.db(), "ws-builder").await;
    let privilege = ensure_privilege(app, "develop.build").await;
    let role: Uuid = sqlx::query_scalar(
        "INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project') RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("builders-{}", Uuid::now_v7().simple()))
    .fetch_one(app.db())
    .await
    .unwrap();
    for (sql, a, b) in [
        (
            "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) VALUES ($1, $2, 'project')",
            role,
            privilege,
        ),
        (
            "INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)",
            user.id,
            role,
        ),
        (
            "INSERT INTO user_account_mm_team (user_ref, team_ref) VALUES ($1, $2)",
            user.id,
            team,
        ),
    ] {
        sqlx::query(sql)
            .bind(a)
            .bind(b)
            .execute(app.db())
            .await
            .unwrap();
    }
    user
}

async fn as_user(
    app: &TestApp,
    user: &TestUser,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    app.request_as(&user.cookie, method, path, body).await
}

// feature: T1
#[test]
fn a_builders_publish_waits_for_the_owners_review() {
    attome_testkit::run_shared(async {
        let Some(live) = TestApp::start().await else {
            return;
        };
        let team: Uuid =
            sqlx::query_scalar("INSERT INTO team (id, name) VALUES ($1, $2) RETURNING id")
                .bind(Uuid::now_v7())
                .bind(format!("ws-team-{}", Uuid::now_v7().simple()))
                .fetch_one(live.db())
                .await
                .unwrap();
        let builder = builder(&live, team).await;

        // An entity, then the administrator's workspace shared with the team.
        let entity = format!("ws_review_{}", &Uuid::now_v7().simple().to_string()[20..]);
        let (status, created) = live
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let (status, made) = live
            .request(
                Method::POST,
                "/api/v1/admin/workspaces",
                Some(json!({ "name": "Team work", "data": { "mode": "none" }, "team": team })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        assert_eq!(made["team_ref"], json!(team));
        let id: Uuid = made["id"].as_str().unwrap().parse().unwrap();
        let changeset = made["changeset_ref"].as_str().unwrap().to_owned();
        let schema = format!("ws_{}", id.simple());

        // The builder sees it.
        let (status, listed) = as_user(
            &live,
            &builder,
            Method::GET,
            "/api/v1/admin/workspaces",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["id"] == made["id"]),
            "{listed}"
        );

        // A change inside it (as its own process makes it).
        let live_schema: String = sqlx::query_scalar("SELECT current_schema()::text")
            .fetch_one(live.db())
            .await
            .unwrap();
        let inside = TestApp::start_in_schema(&format!("{schema},{live_schema},public"))
            .await
            .expect("the workspace app");
        let (status, body) = inside
            .request_with(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                &[("x-attome-changeset", changeset.as_str())],
                Some(json!({ "logicalname": "visit_note", "name": "Visit note", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        // The builder's publish waits for the owner.
        let (status, review) = as_user(
            &live,
            &builder,
            Method::POST,
            &format!("/api/v1/admin/workspaces/{id}/publish"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{review}");
        assert_eq!(review["status"], "in_review");
        let request: Uuid = review["review_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (status, shown) = live
            .request(Method::GET, &format!("/api/v1/admin/workspaces/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{shown}");
        assert_eq!(shown["status"], "in_review");
        assert_eq!(shown["review_request_ref"], json!(request));
        let action: String =
            sqlx::query_scalar("SELECT action_type FROM approval_request WHERE id = $1")
                .bind(request)
                .fetch_one(live.db())
                .await
                .unwrap();
        assert_eq!(action, "develop.workspace_publish");
    });
}

// feature: T1
#[test]
fn a_person_who_does_not_build_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let outsider = seed_user(app.db(), "ws-outsider").await;
        let (status, body) = as_user(
            &app,
            &outsider,
            Method::GET,
            "/api/v1/admin/workspaces",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = as_user(
            &app,
            &outsider,
            Method::POST,
            "/api/v1/admin/workspaces",
            Some(json!({ "name": "Mine", "data": { "mode": "none" } })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    });
}

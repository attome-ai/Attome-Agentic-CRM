//! L7-T4: delta tokens on the entity list and on `query/execute`: a first
//! token from `latest`, the records created, updated and deleted in the
//! filtered list since a token, a next token that lists only later changes,
//! and `410 resync_needed` for a token older than the change feed keeps.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_core::change_feed::CursorPosition;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn create_record(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

fn ids(delta: &Value, key: &str) -> Vec<Value> {
    delta[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            if v.is_object() {
                v["id"].clone()
            } else {
                v.clone()
            }
        })
        .collect()
}

/// Asks the filtered list for the changes since `token`, until `done` holds
/// (the feed shows an event once its transaction is older than every open
/// one, so a busy shared database can hold it back briefly).
async fn delta_until(
    app: &TestApp,
    entity: &str,
    token: &str,
    done: impl Fn(&Value) -> bool,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..50 {
        let (status, delta) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}?filter[stage][eq]=open&delta_token={token}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{delta}");
        if done(&delta) {
            return delta;
        }
        last = delta;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the changes never showed: {last}");
}

// feature: L7
#[test]
fn delta_token_returns_changes_and_next_token() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("delta_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let entity_id = create_entity(&app, &entity).await;
        for field in ["code", "stage"] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/admin/entities/{entity_id}/fields"),
                    Some(json!({ "logicalname": field, "name": field, "field_type": "text" })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        // A first token, and no changes with it.
        let (status, first) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}?delta_token=latest"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["created"], json!([]));
        assert_eq!(first["deleted"], json!([]));
        let token = first["next_token"].as_str().unwrap().to_owned();

        let open = create_record(&app, &entity, json!({ "code": "A", "stage": "open" })).await;
        let closed = create_record(&app, &entity, json!({ "code": "B", "stage": "closed" })).await;

        // Created since the token, as the filtered list holds them: the open
        // record; the closed one never entered it.
        let delta = delta_until(&app, &entity, &token, |d| {
            ids(d, "created").contains(&json!(open)) && ids(d, "deleted").contains(&json!(closed))
        })
        .await;
        assert_eq!(ids(&delta, "created"), vec![json!(open)], "{delta}");
        assert_eq!(delta["created"][0]["code"], "A", "{delta}");
        assert!(ids(&delta, "updated").is_empty(), "{delta}");
        let next = delta["next_token"].as_str().unwrap().to_owned();
        assert_ne!(next, token);

        // The next token lists only later changes: an update of the open
        // record, and the closed one moving into the list.
        let (_, current) = app
            .request(Method::GET, &format!("/api/v1/{entity}/{open}"), None)
            .await;
        let if_match = format!(
            "\"{}\"",
            current["row_version"].to_string().trim_matches('"')
        );
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{entity}/{open}"),
                &[("if-match", if_match.as_str())],
                Some(json!({ "code": "A2" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let later = delta_until(&app, &entity, &next, |d| {
            ids(d, "updated").contains(&json!(open))
        })
        .await;
        assert!(ids(&later, "created").is_empty(), "{later}");
        assert!(
            !ids(&later, "deleted").contains(&json!(closed)),
            "an earlier change is not listed again: {later}"
        );
        let shown = later["updated"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == json!(open))
            .unwrap();
        assert_eq!(shown["code"], "A2");

        // The same option on query/execute, over the entity's default view.
        let (status, executed) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "entity": entity, "delta_token": token })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{executed}");
        let all: Vec<Value> = [ids(&executed, "created"), ids(&executed, "updated")].concat();
        assert!(
            all.contains(&json!(open)) && all.contains(&json!(closed)),
            "{executed}"
        );

        // A token older than the feed keeps asks for a resync.
        let stale = attome_records::changes::seal_delta(
            CursorPosition {
                last_commit_xid: 0,
                last_id: None,
            },
            0,
        );
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}?delta_token={stale}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::GONE, "{body}");
        assert_eq!(body["error"], "resync_needed");
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}?delta_token=not-a-token"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Without a token the list is the page it always was.
        let (status, page) = app
            .request(Method::GET, &format!("/api/v1/{entity}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(
            page["items"].is_array() && page.get("created").is_none(),
            "{page}"
        );
    });
}

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: L7
#[test]
fn secret_attribute_never_in_payload() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!(
            "delta_secret_{}",
            &Uuid::now_v7().simple().to_string()[..12]
        );
        let entity_id = create_entity(&app, &entity).await;
        for field in [
            json!({ "logicalname": "code", "name": "code", "field_type": "text" }),
            json!({ "logicalname": "secret", "name": "secret", "field_type": "text", "is_sensitive": true }),
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/admin/entities/{entity_id}/fields"),
                    Some(field),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        // A reader who may read and create the entity, with no grant on the
        // sensitive field; the record is theirs, so only the field is hidden.
        let reader = attome_testapp::seed_user(app.db(), "delta-reader").await;
        grant(&app, reader.id, &format!("{entity}.read")).await;
        grant(&app, reader.id, &format!("{entity}.create")).await;
        let as_reader = |path: String| {
            let app = app.clone();
            let cookie = reader.cookie.clone();
            async move {
                let (status, body) = app.request_as(&cookie, Method::GET, &path, None).await;
                assert_eq!(status, StatusCode::OK, "{path}: {body}");
                body
            }
        };
        let first = as_reader(format!("/api/v1/{entity}?delta_token=latest")).await;
        let token = first["next_token"].as_str().unwrap().to_owned();
        let (status, created) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "code": "S1", "secret": "s3cr3t-value" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].clone();

        let mut delta = Value::Null;
        for _ in 0..50 {
            delta = as_reader(format!("/api/v1/{entity}?delta_token={token}")).await;
            if ids(&delta, "created").contains(&id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            ids(&delta, "created").contains(&id),
            "the record came back: {delta}"
        );
        let text = delta.to_string();
        assert!(
            !text.contains("s3cr3t-value"),
            "the secret never travels: {text}"
        );
        let row = &delta["created"][0];
        assert_eq!(row["code"], "S1", "{row}");

        // The same through query/execute's delta and the changes route.
        let (status, executed) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({ "entity": entity, "delta_token": token })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{executed}");
        assert!(!executed.to_string().contains("s3cr3t-value"), "{executed}");
    });
}

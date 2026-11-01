//! L3-T3: the steward inbox lists the open duplicates and quality issues of
//! the steward's domains, oldest first, and leaves out an entity whose
//! records the steward may read only in part.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// An entity created through the admin API; its logical name.
async fn entity(app: &TestApp, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Inbox test" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "label", "name": "Label", "field_type": "text" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    logicalname
}

/// A role reading `entity` at `level` (1 team, 3 all), given to `user`.
async fn read_at(app: &TestApp, user: Uuid, entity: &str, level: i16) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("inbox-reader-{role}"))
        .execute(app.db())
        .await
        .unwrap();
    let key = format!("{entity}.read");
    attome_security::db::ensure_privilege(
        app.db(),
        &key,
        &key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) \
         SELECT uuidv7(), $1, id, 'project' FROM privilege WHERE key = $2",
    )
    .bind(role)
    .bind(&key)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         SELECT uuidv7(), $1, id, $3, 0, 0, 'project' FROM entity_info WHERE logicalname = $2",
    )
    .bind(role)
    .bind(entity)
    .bind(level)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES (uuidv7(), $1, $2)",
    )
    .bind(user)
    .bind(role)
    .execute(app.db())
    .await
    .unwrap();
}

async fn record(app: &TestApp, entity: &str) -> Uuid {
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}"),
            Some(json!({ "label": "x" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn issue(app: &TestApp, entity: &str, record: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO quality_issue (entity_logicalname, period, dimension, record_id, detail) \
         VALUES ($1, 'inbox', 'completeness', $2, 'name is empty') RETURNING id",
    )
    .bind(entity)
    .bind(record)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: L3
#[test]
fn inbox_lists_duplicate_and_issue_hides_unreadable() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let readable = entity(&app, "inbox_full").await;
        let partial = entity(&app, "inbox_part").await;
        let steward = attome_testapp::seed_user(app.db(), "inbox-steward").await;
        read_at(&app, steward.id, &readable, 3).await;
        read_at(&app, steward.id, &partial, 1).await;
        let domain: Uuid = sqlx::query_scalar(
            "INSERT INTO data_domain (name, owner_layer, steward_ref) VALUES ($1, 'customer', $2) RETURNING id",
        )
        .bind(format!("Inbox domain {}", Uuid::now_v7().simple()))
        .bind(steward.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query("UPDATE entity_info SET domain_ref = $1 WHERE logicalname = ANY($2)")
            .bind(domain)
            .bind(vec![readable.clone(), partial.clone()])
            .execute(app.db())
            .await
            .unwrap();

        // A duplicate pair and an issue on the entity read in full ...
        let (a, b) = (record(&app, &readable).await, record(&app, &readable).await);
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        let rule: Uuid = sqlx::query_scalar(
            "INSERT INTO match_rule (entity_logicalname, name, fields, threshold, created_by) \
             VALUES ($1, 'same name', '[]'::jsonb, 0.9, $2) RETURNING id",
        )
        .bind(&readable)
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        let duplicate: Uuid = sqlx::query_scalar(
            "INSERT INTO duplicate_candidate (entity_logicalname, record_a, record_b, match_rule_id, score, detected_at) \
             VALUES ($1, $2, $3, $4, 0.95, now() - interval '1 day') RETURNING id",
        )
        .bind(&readable)
        .bind(low)
        .bind(high)
        .bind(rule)
        .fetch_one(app.db())
        .await
        .unwrap();
        let seen_issue = issue(&app, &readable, a).await;
        // ... and an issue on a record of the entity read only in part
        // (the administrator owns it; the steward reads their team's).
        let hidden = issue(&app, &partial, record(&app, &partial).await).await;

        let (code, inbox) = app
            .request_as(
                &steward.cookie,
                Method::GET,
                "/api/v1/governance/inbox?page_size=100",
                None,
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{inbox}");
        let items = inbox["items"].as_array().unwrap();
        let ids: Vec<&str> = items.iter().filter_map(|i| i["id"].as_str()).collect();
        assert_eq!(
            ids,
            vec![duplicate.to_string(), seen_issue.to_string()],
            "oldest first, the partly read entity left out: {inbox}"
        );
        assert!(!ids.contains(&hidden.to_string().as_str()));
        assert_eq!(inbox["total"], 2, "{inbox}");
        assert_eq!(items[0]["source"], "duplicate");
        assert_eq!(items[0]["link"], "/xrm/admin/duplicates");
        assert_eq!(items[1]["source"], "quality_issue");

        // Someone who stewards nothing sees an empty inbox.
        let other = attome_testapp::seed_user(app.db(), "inbox-other").await;
        let (code, empty): (StatusCode, Value) = app
            .request_as(&other.cookie, Method::GET, "/api/v1/governance/inbox", None)
            .await;
        assert_eq!(code, StatusCode::OK, "{empty}");
        assert_eq!(empty["total"], 0);
    });
}

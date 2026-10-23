//! K7-T1: a declared record refuses updates and deletes; its disposition
//! needs a second administrator, refuses a record under a legal hold, and
//! once approved purges the record and keeps a certificate.

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

async fn account(app: &TestApp, name: &str) -> (Uuid, i64) {
    let (status, body) = app
        .request(Method::POST, "/api/v1/account", Some(json!({"name": name})))
        .await;
    assert!(status.is_success(), "{status} {body}");
    (
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap(),
        body["row_version"].as_i64().unwrap_or(1),
    )
}

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
}

// feature: K7
#[test]
fn declared_record_is_immutable_and_disposes_with_a_certificate() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_crm(&app).await;
        let tag = Uuid::now_v7().simple().to_string();
        let (status, category) = app
            .request(
                Method::POST,
                "/api/v1/admin/records/categories",
                Some(json!({"name": format!("Contracts {tag}"), "retention_days": 3650})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{category}");
        let category = category["id"].clone();
        let (record, version) = account(&app, &format!("Declared Co {tag}")).await;

        let declare = json!({"entity": "account", "record_id": record, "category_id": category});
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/records/declarations",
                Some(declare.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/records/declarations",
                Some(declare),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "declared once");

        // The generic write path refuses it.
        let if_match = format!("\"{version}\"");
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/account/{record}"),
                &[("if-match", if_match.as_str())],
                Some(json!({"name": "Changed"})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) = app
            .request(Method::DELETE, &format!("/api/v1/account/{record}"), None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // The requester cannot approve their own disposition.
        let (status, request) = app
            .request(
                Method::POST,
                "/api/v1/admin/records/dispositions",
                Some(json!({"entity": "account", "record_id": record})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{request}");
        let decide = format!(
            "/api/v1/admin/records/dispositions/{}/decide",
            request["id"].as_str().unwrap()
        );
        let (status, _) = app
            .request(Method::POST, &decide, Some(json!({"decision": "approve"})))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A second administrator approves; a legal hold blocks it first.
        let reviewer = attome_testapp::seed_admin(app.db()).await;
        sqlx::query(
            "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
             VALUES ('account', $1, $2, $3)",
        )
        .bind(record)
        .bind(format!("M-{tag}"))
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        let (status, _) = app
            .request_as(
                &reviewer.cookie,
                Method::POST,
                &decide,
                Some(json!({"decision": "approve"})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "held");
        sqlx::query("UPDATE legal_hold SET released_at = now() WHERE record_id = $1")
            .bind(record)
            .execute(app.db())
            .await
            .unwrap();
        let (status, decided) = app
            .request_as(
                &reviewer.cookie,
                Method::POST,
                &decide,
                Some(json!({"decision": "approve", "reason": "kept ten years"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        assert_eq!(decided["status"], "approved");
        assert_eq!(
            decided["certificate"]["category"],
            format!("Contracts {tag}")
        );
        assert_eq!(decided["certificate_sha256"].as_str().unwrap().len(), 64);
        let disposed: bool = sqlx::query_scalar(
            "SELECT disposed_at IS NOT NULL FROM record_declaration \
              WHERE entity = 'account' AND record_id = $1",
        )
        .bind(record)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(disposed);
        let (status, _) = app
            .request_as(
                &reviewer.cookie,
                Method::POST,
                &decide,
                Some(json!({"decision": "approve"})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "decided once");
    });
}

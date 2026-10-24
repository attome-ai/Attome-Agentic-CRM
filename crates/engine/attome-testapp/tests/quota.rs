//! Z6-T7: storage caps. An entity's cap (`storage.max_entity_storage_bytes`)
//! refuses the upload that would pass it with `413 limit_exceeded` naming
//! the setting, and administrators are told once a day when a cap passes
//! `storage.quota_warning_pct`. The upload path is called directly
//! (`start_upload`, the route's own body), so no object store is needed: a
//! presigned URL is signed locally.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_document::files::{UploadSessionRequest, start_upload};
use attome_records::entity_mutation::FileOwner;
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use uuid::Uuid;

/// The entity, with a file field, and one record of it.
async fn entity_with_file(app: &TestApp, entity: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity_id = body["id"].as_str().unwrap().to_owned();
    for field in [
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
        json!({ "logicalname": "attachment", "name": "attachment", "field_type": "file" }),
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
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}"),
            Some(json!({ "title": "quota" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

fn upload(bytes: i64) -> UploadSessionRequest {
    UploadSessionRequest {
        filename: "report.pdf".into(),
        content_type: "application/pdf".into(),
        declared_size_bytes: bytes,
        checksum_sha256: None,
    }
}

async fn warnings(app: &TestApp, admin: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM notification_dispatch \
         WHERE recipient_user_ref = $1 AND subject LIKE 'File storage at %'",
    )
    .bind(admin)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: Z6
#[test]
fn entity_cap_refuses_past_the_limit_and_warns_once() {
    attome_testkit::run_shared(async {
        let entity = format!("z6_quota_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let cap_entity = entity.clone();
        let Some(app) = TestApp::start_with(move |config| {
            config
                .storage
                .max_entity_storage_bytes
                .insert(cap_entity, 1_000);
            config.storage.quota_warning_pct = 80;
        })
        .await
        else {
            return;
        };
        let record = entity_with_file(&app, &entity).await;
        let owner = FileOwner::Staff(app.admin.id);
        let before = warnings(&app, app.admin.id).await;

        // 850 of 1,000: allowed, and past 80%, so administrators are told.
        start_upload(
            &app.state,
            owner,
            &entity,
            record,
            "attachment",
            upload(850),
        )
        .await
        .expect("under the cap");
        assert_eq!(warnings(&app, app.admin.id).await, before + 1);

        // 850 + 200 passes the cap: refused, naming the setting, as a 413.
        let refused = start_upload(
            &app.state,
            owner,
            &entity,
            record,
            "attachment",
            upload(200),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &refused,
                AppError::LimitExceeded {
                    limit: "storage.max_entity_storage_bytes",
                    value: 1_000,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(
            refused.into_response().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        // Still past 80% after a smaller upload: no second warning today.
        start_upload(
            &app.state,
            owner,
            &entity,
            record,
            "attachment",
            upload(100),
        )
        .await
        .expect("still under the cap");
        assert_eq!(warnings(&app, app.admin.id).await, before + 1);

        // Another entity has no cap of its own.
        let other = format!("z6_free_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let free = entity_with_file(&app, &other).await;
        start_upload(&app.state, owner, &other, free, "attachment", upload(5_000))
            .await
            .expect("no cap on this entity");
    });
}

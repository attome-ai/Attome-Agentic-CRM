//! L1-T5: a steward releases a held contribution into its golden record,
//! pins a value the rebuild then keeps, detaches a contribution and
//! certifies the golden record; a person who stewards nothing is refused.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::entity_crud::master::{self, Ingested};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Map, Value, json};
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs")
        .join(pack)
        .join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
            .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

async fn phone(app: &TestApp, id: Uuid) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(t)->'phone' FROM account t WHERE t.id = $1")
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: L1
#[test]
fn steward_routes_pin_release_detach_certify() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        attome_metadata::provision::master::ensure_master_tables(app.db(), "account")
            .await
            .expect("master tables");
        sqlx::query("UPDATE entity_info SET is_master = true WHERE logicalname = 'account'")
            .execute(app.db())
            .await
            .unwrap();
        let ctx = app
            .state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let tag = Uuid::now_v7().simple().to_string();
        let crm = master::ingest(
            &app.state,
            &ctx,
            "account",
            "crm",
            &format!("C-{tag}"),
            &obj(json!({"name": format!("Steward Co {tag}"), "phone": "+966 11 000 0001"})),
        )
        .await
        .expect("crm contribution");
        let Ingested::Attached { golden, .. } = crm else {
            panic!("the CRM version is valid: {crm:?}");
        };
        sqlx::query(
            "INSERT INTO external_id_link (entity, record_id, system, external_id) \
             VALUES ('account', $1, 'erp', $2)",
        )
        .bind(golden)
        .bind(format!("E-{tag}"))
        .execute(app.db())
        .await
        .unwrap();
        let held = master::ingest(
            &app.state,
            &ctx,
            "account",
            "erp",
            &format!("E-{tag}"),
            &obj(json!({"phone": "+966 11 555 5555", "no_such_field": 1})),
        )
        .await
        .expect("held contribution");
        let Ingested::Held {
            contribution: held, ..
        } = held
        else {
            panic!("the ERP version is invalid: {held:?}");
        };

        // The held queue shows it.
        let (status, page) = app
            .request(Method::GET, "/api/v1/master/held?page_size=100", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["id"] == json!(held)),
            "{page}"
        );

        // Someone who stewards no domain is refused.
        let outsider = attome_testapp::seed_user(app.db(), "outsider").await;
        let release = format!("/api/v1/master/account/contributions/{held}/release");
        let (status, _) = app
            .request_as(&outsider.cookie, Method::POST, &release, Some(json!({})))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Still invalid as stored: refused. Corrected: attached.
        let (status, _) = app.request(Method::POST, &release, Some(json!({}))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body) = app
            .request(
                Method::POST,
                &release,
                Some(json!({"payload": {"phone": "+966 11 555 5555"}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["golden_id"], json!(golden));
        let (status, _) = app.request(Method::POST, &release, Some(json!({}))).await;
        assert_eq!(status, StatusCode::CONFLICT, "released once");
        master::rebuild(&app.state, "account", golden, app.admin.id)
            .await
            .expect("rebuild");
        assert_eq!(phone(&app, golden).await, json!("+966 11 555 5555"));

        // A pinned value survives the rebuild.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/master/account/{golden}/pins"),
                Some(json!({"attribute": "phone", "value": "+966 11 777 7777"})),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        master::rebuild(&app.state, "account", golden, app.admin.id)
            .await
            .expect("rebuild");
        assert_eq!(phone(&app, golden).await, json!("+966 11 777 7777"));

        // Detaching the ERP's contribution queues a rebuild without it.
        let detach = format!("/api/v1/master/account/contributions/{held}/detach");
        let (status, body) = app.request(Method::POST, &detach, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["golden_id"], json!(golden));
        let (status, _) = app.request(Method::POST, &detach, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "already detached");

        // Certification.
        let certify = format!("/api/v1/master/account/{golden}/certify");
        let (status, _) = app
            .request_as(
                &outsider.cookie,
                Method::POST,
                &certify,
                Some(json!({"status": "certified"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = app
            .request(Method::POST, &certify, Some(json!({"status": "approved"})))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body) = app
            .request(Method::POST, &certify, Some(json!({"status": "certified"})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous"], "draft");
        assert_eq!(body["status"], "certified");
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_header WHERE record_id = $1 \
              AND event_name IN ('master.value_pinned', 'master.certification_set')",
        )
        .bind(golden)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(events, 2, "the pin and the certification are audited");

        // Unpinning hands the value back to the rules; a second unpin finds
        // nothing.
        let unpin = format!("/api/v1/master/account/{golden}/pins/phone");
        let (status, _) = app.request(Method::DELETE, &unpin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app.request(Method::DELETE, &unpin, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

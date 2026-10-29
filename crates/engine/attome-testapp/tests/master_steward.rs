//! L1-T5: a steward releases a held contribution into its golden record,
//! pins a value the rebuild then keeps, detaches a contribution and
//! certifies the golden record; a person who stewards nothing is refused.
//! L1-T11: a steward of another data domain is refused too, and a reader
//! without the field grant does not see a hidden attribute's provenance.

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
// negative: POST /api/v1/master/{entity}/contributions/{cid}/release, POST /api/v1/master/{entity}/contributions/{cid}/detach, POST /api/v1/master/{entity}/{id}/certify
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
        attome_testapp::drain_audit(&app).await;
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
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at)          SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: L1
// negative: POST /api/v1/master/{entity}/{id}/pins, GET /api/v1/master/{entity}/{id}/provenance
#[test]
fn other_domain_steward_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        attome_metadata::provision::master::ensure_master_tables(app.db(), "account")
            .await
            .expect("master tables");
        let tag = Uuid::now_v7().simple().to_string();

        // Account belongs to one domain; the other user stewards another.
        let mut domains = Vec::new();
        for name in ["Customers", "Suppliers"] {
            let id: Uuid =
                sqlx::query_scalar("INSERT INTO data_domain (name) VALUES ($1) RETURNING id")
                    .bind(format!("{name} {tag}"))
                    .fetch_one(app.db())
                    .await
                    .unwrap();
            domains.push(id);
        }
        sqlx::query(
            "UPDATE entity_info SET is_master = true, domain_ref = $1 WHERE logicalname = 'account'",
        )
        .bind(domains[0])
        .execute(app.db())
        .await
        .unwrap();
        let other = attome_testapp::seed_user(app.db(), "other-steward").await;
        sqlx::query(
            "INSERT INTO governance_role (domain_ref, user_id, role) VALUES ($1, $2, 'steward')",
        )
        .bind(domains[1])
        .bind(other.id)
        .execute(app.db())
        .await
        .unwrap();

        // A hidden attribute on account, added for this test.
        let hidden = format!("note_{}", &tag[..8]);
        let account_id: Uuid =
            sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'account'")
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{account_id}/fields"),
                Some(
                    json!({ "logicalname": hidden, "name": hidden, "field_type": "text",
                             "is_sensitive": true }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let ctx = app
            .state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let ingested = master::ingest(
            &app.state,
            &ctx,
            "account",
            "crm",
            &format!("D-{tag}"),
            &obj(
                json!({"name": format!("Domain Co {tag}"), "phone": "+966 11 000 0002",
                        hidden.clone(): "internal only"}),
            ),
        )
        .await
        .expect("crm contribution");
        let Ingested::Attached { golden, .. } = ingested else {
            panic!("the CRM version is valid: {ingested:?}");
        };
        master::rebuild(&app.state, "account", golden, app.admin.id)
            .await
            .expect("rebuild");

        // A steward of another domain may not pin here.
        let (status, _) = app
            .request_as(
                &other.cookie,
                Method::POST,
                &format!("/api/v1/master/account/{golden}/pins"),
                Some(json!({"attribute": "phone", "value": "+966 11 999 9999"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(phone(&app, golden).await, json!("+966 11 000 0002"));

        // A reader of account without the hidden field's grant sees the
        // provenance of the other attributes, never the hidden one.
        let reader = attome_testapp::seed_user(app.db(), "master-reader").await;
        grant(&app, reader.id, "account.read").await;
        sqlx::query("UPDATE account SET owner_ref = $1 WHERE id = $2")
            .bind(reader.id)
            .bind(golden)
            .execute(app.db())
            .await
            .unwrap();
        let provenance = format!("/api/v1/master/account/{golden}/provenance");
        let (status, as_admin) = app.request(Method::GET, &provenance, None).await;
        assert_eq!(status, StatusCode::OK, "{as_admin}");
        let attributes = |page: &Value| -> Vec<String> {
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|i| i["attribute"].as_str().map(str::to_owned))
                .collect()
        };
        assert!(attributes(&as_admin).contains(&hidden), "{as_admin}");
        let (status, as_reader) = app
            .request_as(&reader.cookie, Method::GET, &provenance, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{as_reader}");
        let seen = attributes(&as_reader);
        assert!(seen.iter().any(|a| a == "name"), "{as_reader}");
        assert!(!seen.contains(&hidden), "{as_reader}");
        assert!(
            !as_reader.to_string().contains("internal only"),
            "{as_reader}"
        );
    });
}

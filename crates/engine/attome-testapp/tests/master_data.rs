//! L1-T1: master-data settings on entity metadata. Marking an entity as
//! master data needs a data domain, the settings are written as one
//! `set_entity_master_data` operation, and they are read back from the
//! entity's metadata after the registry reloads. L1-T6: the cross-reference
//! lookup and the point-in-time view keep attributes the caller cannot read
//! out of their answers. Later L1 tasks add their tests here.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::entity_crud::master::{self, Ingested};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

// feature: L1
#[test]
fn mark_entity_master_requires_domain_and_survives_reload() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let suffix = &Uuid::now_v7().simple().to_string()[..12];
        let entity = format!("mdm_{suffix}");
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let master = json!({ "master_data": { "is_master": true, "hub_style": "registry" } });

        // No data domain yet: refused, naming the field.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(master.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.to_string().contains("is_master"), "{body}");

        // An unknown hub style is refused too.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "master_data": { "is_master": false, "hub_style": "federated" } })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, domain) = app
            .request(
                Method::POST,
                "/api/v1/admin/governance/domains",
                Some(json!({ "name": format!("Customers {suffix}") })),
            )
            .await;
        assert!(status.is_success(), "{status} {domain}");
        let domain_id = domain["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                Some(json!({ "entity_logicalnames": [entity] })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");

        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(master),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Read back from the stored metadata, as any node reloading it sees it.
        let (status, detail) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/entities/{entity_id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(
            detail["master_data"],
            json!({ "is_master": true, "hub_style": "registry" })
        );
        let stored: (bool, Option<String>) =
            sqlx::query_as("SELECT is_master, hub_style FROM entity_info WHERE id = $1::uuid")
                .bind(&entity_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(stored, (true, Some("registry".to_owned())));
    });
}

/// A user whose role reads every record of `entity` (`entity_id`).
async fn reader_of(app: &TestApp, entity: &str, entity_id: Uuid) -> attome_testapp::TestUser {
    let user = attome_testapp::seed_user(app.db(), "reader").await;
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role)
        .bind(format!("mdm-reader-{role}"))
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
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 3, 0, 0, 'project')",
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
    user
}

// feature: L1
#[test]
fn xref_and_as_of_respect_attribute_security() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let suffix = &Uuid::now_v7().simple().to_string()[..12];
        let entity = format!("mdx_{suffix}");
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        for field in [
            json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
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
        let (status, domain) = app
            .request(
                Method::POST,
                "/api/v1/admin/governance/domains",
                Some(json!({ "name": format!("Xref {suffix}") })),
            )
            .await;
        assert!(status.is_success(), "{status} {domain}");
        let domain_id = domain["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/governance/domains/{domain_id}/entities"),
                Some(json!({ "entity_logicalnames": [entity] })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}"),
                Some(json!({ "master_data": { "is_master": true, "hub_style": "registry" } })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        attome_metadata::provision::master::ensure_master_tables(app.db(), &entity)
            .await
            .expect("master tables");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let ctx = app
            .state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let payload = json!({ "title": "Alpha", "secret": "first secret" });
        let ingested = master::ingest(
            &app.state,
            &ctx,
            &entity,
            "crm",
            "C-1",
            payload.as_object().unwrap(),
        )
        .await
        .expect("contribution");
        let Ingested::Attached { golden, .. } = ingested else {
            panic!("the version is valid: {ingested:?}");
        };
        master::rebuild(&app.state, &entity, golden, app.admin.id)
            .await
            .expect("rebuild");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let before_change = chrono::Utc::now();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let row_version: i64 = sqlx::query_scalar(&format!(
            "SELECT row_version FROM {} WHERE id = $1",
            attome_core::quote_ident(&entity)
        ))
        .bind(golden)
        .fetch_one(app.db())
        .await
        .unwrap();
        attome_records::entity_crud::update_record_for(
            &app.state,
            &ctx,
            app.admin.id,
            &entity,
            golden,
            row_version,
            json!({ "title": "Beta", "secret": "second secret" }),
        )
        .await
        .expect("change the golden record");
        // The field history is the audit chain, written by the chainer.
        attome_testapp::drain_audit(&app).await;

        let reader = reader_of(&app, &entity, entity_id).await;
        let outsider = attome_testapp::seed_user(app.db(), "xref-outsider").await;
        let base = format!("/api/v1/master/{entity}");

        // The golden record of a system id, in one lookup.
        let lookup = format!("{base}/xref?system=crm&external_id=C-1");
        let (status, body) = app
            .request_as(&reader.cookie, Method::GET, &lookup, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["golden_id"], json!(golden));
        assert_eq!(body["status"], "attached");
        let (status, _) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("{base}/xref?system=crm&external_id=nope"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = app
            .request_as(&outsider.cookie, Method::GET, &lookup, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no read privilege");

        // Every system id of the golden record; never a payload.
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("{base}/{golden}/xref"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 1, "{body}");
        assert_eq!(body["items"][0]["source_system"], "crm");
        assert_eq!(body["items"][0]["external_id"], "C-1");
        assert!(body["items"][0]["contribution_id"].is_string(), "{body}");
        assert!(!body.to_string().contains("secret"), "{body}");

        // The values held before the change, without the hidden attribute.
        let at = before_change.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("{base}/{golden}/as-of?at={at}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["values"]["title"], "Alpha", "{body}");
        assert!(!body.to_string().contains("secret"), "{body}");

        // An administrator reads the sensitive attribute, but its earlier
        // value is withheld by the history, never shown.
        let (status, body) = app
            .request(Method::GET, &format!("{base}/{golden}/as-of?at={at}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["values"]["title"], "Alpha", "{body}");
        assert!(body["values"].get("secret").is_none(), "{body}");
        assert_eq!(body["withheld"], json!(["secret"]), "{body}");

        // Provenance names the readable attributes only.
        let prov = format!("{base}/{golden}/provenance");
        let (status, body) = app
            .request_as(&reader.cookie, Method::GET, &prov, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let attributes: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["attribute"].as_str())
            .collect();
        assert!(attributes.contains(&"title"), "{body}");
        assert!(!attributes.contains(&"secret"), "{body}");
        let title = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["attribute"] == "title")
            .unwrap();
        assert_eq!(title["source_system"], "crm", "{body}");
        let (status, body) = app.request(Method::GET, &prov, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.to_string().contains("\"secret\""),
            "an administrator reads it: {body}"
        );

        // Now: the current values. Before it existed: not found.
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("{base}/{golden}/as-of?at={now}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["values"]["title"], "Beta", "{body}");
        let (status, _) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("{base}/{golden}/as-of?at=2000-01-01T00:00:00Z"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

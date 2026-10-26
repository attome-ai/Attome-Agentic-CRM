//! L4-T2: the catalog asset index is filled from the metadata, keeps the
//! descriptions people wrote, and drops assets that no longer exist.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::changeset::Layer;
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

// feature: L4
#[test]
fn rebuild_indexes_every_kind_and_removes_deleted() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // An entity the metadata has, a written description on it, and a row
        // for an asset that does not exist, before the rebuild.
        let entity: Option<String> = sqlx::query_scalar(
            "SELECT logicalname FROM entity_info WHERE is_active IS NOT FALSE               ORDER BY logicalname LIMIT 1",
        )
        .fetch_optional(app.db())
        .await
        .unwrap();
        let Some(entity) = entity else {
            return;
        };
        sqlx::query(
            "INSERT INTO catalog_asset (kind, ref, name_en) VALUES ('view', 'no-such-view', 'Gone')              ON CONFLICT (kind, ref) DO NOTHING",
        )
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO catalog_asset (kind, ref, description_en, description_status)              VALUES ('entity', $1, 'Written by a person', 'reviewed')              ON CONFLICT (kind, ref) DO UPDATE SET description_en = EXCLUDED.description_en,                     description_status = 'reviewed'",
        )
        .bind(&entity)
        .execute(app.db())
        .await
        .unwrap();

        let counts = attome_api::catalog_index::rebuild_assets(&app.state)
            .await
            .unwrap();
        assert!(counts.upserted > 0);
        assert!(counts.removed >= 1);

        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT kind FROM catalog_asset ORDER BY kind")
                .fetch_all(app.db())
                .await
                .unwrap();
        for kind in ["agent_tool", "attribute", "entity"] {
            assert!(kinds.iter().any(|k| k == kind), "{kind} in {kinds:?}");
        }
        let gone: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM catalog_asset WHERE kind = 'view' AND ref = 'no-such-view'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(gone, 0);
        let (description, status): (Option<String>, String) = sqlx::query_as(
            "SELECT description_en, description_status FROM catalog_asset \
              WHERE kind = 'entity' AND ref = $1",
        )
        .bind(&entity)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(description.as_deref(), Some("Written by a person"));
        assert_eq!(status, "reviewed");
        let searchable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM catalog_asset \
              WHERE kind = 'entity' AND ref = $1 AND search IS NOT NULL",
        )
        .bind(&entity)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(searchable, 1, "the entity has a search vector");
    });
}

/// L4-T3: a person with `metadata.read` and read access to an entity sees
/// its readable attributes in the catalogue; a sensitive attribute without
/// its field grant is never named, not in the fields and not in the
/// lineage. Without `metadata.read` the catalogue is refused.
// feature: L4
// negative: catalog_get_entity
#[test]
fn hidden_attribute_never_listed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("cat_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        for field in [
            json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
            json!({ "logicalname": "secret_code", "name": "secret_code", "field_type": "text",
                    "is_sensitive": true }),
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

        // A role with metadata.read and read access to the entity.
        let (status, role) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/roles",
                Some(json!({ "name": format!("catalog-{}", Uuid::now_v7().simple()) })),
            )
            .await;
        assert!(status.is_success(), "{status} {role}");
        let role_id = role["id"].as_str().unwrap().to_owned();
        let read_key = format!("{name}.read");
        for key in ["metadata.read", read_key.as_str()] {
            attome_security::db::ensure_privilege(app.db(), key, key, "test", Layer::Project)
                .await
                .unwrap();
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/admin/security/role-grants",
                    Some(json!({ "role_id": role_id, "privilege_key": key })),
                )
                .await;
            assert!(status.is_success(), "{key}: {status} {body}");
        }
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/role-entity-access",
                Some(json!({ "role_id": role_id, "entity": name, "read_access_level": 3 })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let reader = seed_user(app.db(), "catalog-reader").await;
        sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2::uuid)")
            .bind(reader.id)
            .bind(&role_id)
            .execute(app.db())
            .await
            .unwrap();

        let path = format!("/api/v1/catalog/entities/{name}");
        let (status, detail) = app
            .request_as(&reader.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        let names: Vec<&str> = detail["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["logicalname"].as_str())
            .collect();
        assert!(names.contains(&"title"), "{detail}");
        assert!(!names.contains(&"secret_code"), "never listed: {detail}");
        assert!(!detail.to_string().contains("secret_code"), "{detail}");
        // The listing shows the entity to this reader.
        let (status, listed) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                "/api/v1/catalog/entities?page_size=200",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e: &Value| e["logicalname"] == name.as_str()),
            "{listed}"
        );

        // An administrator sees every attribute.
        let (status, full) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(full.to_string().contains("secret_code"), "{full}");

        // Without metadata.read the catalogue is refused.
        let outsider = seed_user(app.db(), "catalog-outsider").await;
        let (status, _) = app
            .request_as(&outsider.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

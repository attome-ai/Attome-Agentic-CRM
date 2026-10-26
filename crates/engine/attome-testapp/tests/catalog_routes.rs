//! L4-T4: the asset catalogue routes end to end: search with facets, the
//! asset page, a drafted then approved description (each with If-Match),
//! and an access request decided by the owner with a role grant. L4-T5: the
//! personal data map.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

// feature: L4
#[test]
fn search_page_describe_and_request_access() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = format!("catalogview{}", &Uuid::now_v7().simple().to_string()[..10]);
        let asset: Uuid = sqlx::query_scalar(
            "INSERT INTO catalog_asset (kind, ref, name_en, label, search) \
             VALUES ('view', $1, $1, 'finance', to_tsvector('simple', $1)) RETURNING id",
        )
        .bind(&token)
        .fetch_one(app.db())
        .await
        .unwrap();

        // Search: the asset, and the facets over what the words match.
        let (status, page) = app
            .request(
                Method::GET,
                &format!("/api/v1/catalog/assets?q={token}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["total"], 1, "{page}");
        assert_eq!(page["items"][0]["id"], json!(asset), "{page}");
        assert_eq!(page["items"][0]["ref"], json!(token), "{page}");
        assert!(
            page["facets"]["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["value"] == "view" && f["count"] == 1),
            "{page}"
        );
        assert_eq!(page["facets"]["label"][0]["value"], "finance", "{page}");
        let (_, narrowed) = app
            .request(
                Method::GET,
                &format!("/api/v1/catalog/assets?q={token}&kind=entity"),
                None,
            )
            .await;
        assert_eq!(narrowed["total"], 0, "{narrowed}");

        // The asset page: facts this kind has none of are null.
        let (status, view) = app
            .request(
                Method::GET,
                &format!("/api/v1/catalog/assets/{asset}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["asset"]["id"], json!(asset));
        assert_eq!(view["label"], "finance");
        assert_eq!(view["terms"], Value::Null);
        assert_eq!(view["certification"], Value::Null);

        // A description is drafted with If-Match, then approved by a builder.
        let description = format!("/api/v1/catalog/assets/{asset}/description");
        let (status, body) = app
            .request(
                Method::PATCH,
                &description,
                Some(json!({"description_en": "Monthly revenue by branch."})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, drafted) = app
            .request_with(
                Method::PATCH,
                &description,
                &[("if-match", "\"0\"")],
                Some(json!({"description_en": "Monthly revenue by branch.", "description_ar": "الإيراد الشهري لكل فرع."})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{drafted}");
        assert_eq!(drafted["description_status"], "draft");
        assert_eq!(drafted["row_version"], 1);
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &description,
                &[("if-match", "\"0\"")],
                Some(json!({"description_en": "Stale."})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let outsider = seed_user(app.db(), "catalog-outsider").await;
        let approve = format!("/api/v1/catalog/assets/{asset}/description/approve");
        let (status, _) = app
            .request_as(&outsider.cookie, Method::POST, &approve, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "only a builder approves");
        let (status, approved) = app
            .request_with(Method::POST, &approve, &[("if-match", "\"1\"")], None)
            .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["description_status"], "reviewed");

        // Access: asked once, decided by the owner, who grants a role.
        let requests = format!("/api/v1/catalog/assets/{asset}/access-requests");
        let (status, request) = app
            .request(
                Method::POST,
                &requests,
                Some(json!({"reason": "Monthly board pack"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{request}");
        assert_eq!(request["status"], "pending");
        let (status, body) = app
            .request(Method::POST, &requests, Some(json!({"reason": "Again"})))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, role) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/roles",
                Some(json!({"name": format!("Catalog readers {token}")})),
            )
            .await;
        assert!(status.is_success(), "{role}");
        let role_id = role["id"].as_str().unwrap().to_owned();
        let decide = format!(
            "/api/v1/catalog/access-requests/{}/decide",
            request["id"].as_str().unwrap()
        );
        let (status, _) = app
            .request_as(
                &outsider.cookie,
                Method::POST,
                &decide,
                Some(json!({"grant": true, "role_id": role_id})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "only the owner decides");
        let (status, decided) = app
            .request(
                Method::POST,
                &decide,
                Some(json!({"grant": true, "role_id": role_id})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        assert_eq!(decided["status"], "granted");
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_account_mm_role \
              WHERE user_ref = $1 AND role_ref = $2::uuid AND is_deleted = false)",
        )
        .bind(app.admin.id)
        .bind(&role_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(held, "the role is granted through the role-grant path");
        let (status, body) = app
            .request(Method::POST, &decide, Some(json!({"grant": false})))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // The export stays off until the deployment turns it on.
        let (status, _) = app
            .request(Method::GET, "/api/v1/catalog/export", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// feature: L4
#[test]
fn personal_data_map_lists_labelled_attribute_and_reader() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("pdm_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
        for field in ["phone", "notes"] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/admin/entities/{entity_id}/fields"),
                    Some(json!({ "logicalname": field, "name": field, "field_type": "text" })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        sqlx::query(
            "UPDATE attribute_info SET sensitivity = 'personal', sensitivity_confirmed = true \
              WHERE entity_ref = $1 AND logicalname = 'phone'",
        )
        .bind(entity_id)
        .execute(app.db())
        .await
        .unwrap();
        let report = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO metadata_reference (from_kind, from_ref, from_label, to_entity, to_attribute) \
             VALUES ('query', $1, 'Monthly contact report', $2, 'phone'), \
                    ('workflow', $3, 'Welcome flow', $2, '')",
        )
        .bind(report)
        .bind(&name)
        .bind(Uuid::now_v7())
        .execute(app.db())
        .await
        .unwrap();

        // Walk the map until the entity shows up (other tests label too).
        let mut found = None;
        for page in 1..=50 {
            let (status, body) = app
                .request(
                    Method::GET,
                    &format!("/api/v1/catalog/personal-data-map?page={page}&page_size=100"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let items = body["items"].as_array().unwrap().clone();
            if let Some(item) = items.iter().find(|i| i["entity"] == json!(name)) {
                found = Some(item.clone());
                break;
            }
            if items.len() < 100 {
                break;
            }
        }
        let item = found.expect("the labelled attribute is on the map");
        assert_eq!(
            item["attribute"], "phone",
            "only the labelled attribute: {item}"
        );
        assert_eq!(item["sensitivity"], "personal");
        let readers = item["readers"].as_array().unwrap();
        assert!(
            readers.iter().any(|r| r["ref"] == json!(report)
                && r["label"] == "Monthly contact report"
                && r["whole_entity"] == false),
            "{item}"
        );
        assert!(
            readers
                .iter()
                .any(|r| r["kind"] == "workflow" && r["whole_entity"] == true),
            "{item}"
        );

        // The rollup flags an entity nobody reads or writes as unused.
        let now = chrono::Utc::now();
        assert!(attome_api::catalog_admin::is_unused(None, 0, 0, now));
        assert!(!attome_api::catalog_admin::is_unused(Some(now), 0, 0, now));
        assert!(!attome_api::catalog_admin::is_unused(None, 0, 2, now));
    });
}

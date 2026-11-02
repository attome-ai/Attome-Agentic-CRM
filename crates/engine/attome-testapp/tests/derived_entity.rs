//! A26-T1: a derived entity lists the anchor's rows matching its condition,
//! reads one member, refuses every write with 405, and refuses a condition
//! that reaches past the anchor's own fields.

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

// feature: A26
#[test]
fn derived_entity_lists_members_and_refuses_writes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }

        let prefix = format!("Derived {}", Uuid::now_v7().simple());
        let mut ids = Vec::new();
        for name in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            "Not a member".to_owned(),
        ] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(&name)
            .bind(app.admin.id)
            .fetch_one(app.db())
            .await
            .unwrap();
            ids.push(id);
        }
        let name = format!("dv_test_{}", &Uuid::now_v7().simple().to_string()[24..]);

        // A condition over a lookup's field is refused.
        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({"anchor": "account", "condition": "owner_ref.name == \"x\""})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({
                    "anchor": "account",
                    "condition": format!("startswith(name, \"{prefix}\")"),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "live");

        let (status, body) = app
            .request(Method::GET, &format!("/api/v1/{name}?page_size=50"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut listed: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect();
        listed.sort();
        let mut members = vec![ids[0].to_string(), ids[1].to_string()];
        members.sort();
        assert_eq!(listed, members);

        let (status, body) = app
            .request(Method::GET, &format!("/api/v1/{name}/{}", ids[0]), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = app
            .request(Method::GET, &format!("/api/v1/{name}/{}", ids[2]), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Every write is refused.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({"name": "x"})),
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/{name}/{}", ids[0]),
                Some(json!({"name": "x"})),
            )
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _) = app
            .request(Method::DELETE, &format!("/api/v1/{name}/{}", ids[0]), None)
            .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

        // The view exists with its members.
        let in_view: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"xrm_dv_{name}\""))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(in_view, 2);

        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/derived-entities/{name}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = app
            .request(Method::GET, &format!("/api/v1/{name}"), None)
            .await;
        assert_ne!(status, StatusCode::OK);
    });
}

/// Reads the change feed until the derived entity consumer has caught up.
async fn drain(app: &TestApp) {
    while attome_api::derived_maintain::tick(&app.state)
        .await
        .unwrap()
        > 0
    {}
}

// feature: A26
#[test]
fn derived_incremental_enter_leave_and_surge_pause() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
        // Whatever the feed held before this test is not its business.
        drain(&app).await;

        let prefix = format!("Stored {}", Uuid::now_v7().simple());
        let name = format!("dv_st_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({
                    "anchor": "account",
                    "condition": format!("startswith(name, \"{prefix}\")"),
                    "mode": "stored",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Created through the API, so each is a change event.
        let mut ids = Vec::new();
        for label in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            "Elsewhere".to_owned(),
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/account",
                    Some(json!({ "name": label })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            ids.push(Uuid::parse_str(body["id"].as_str().unwrap()).unwrap());
        }
        drain(&app).await;
        let members = |app: &TestApp| {
            let sql = format!("SELECT anchor_id FROM \"xrm_dm_{name}\" ORDER BY anchor_id");
            let db = app.db().clone();
            async move {
                sqlx::query_scalar::<_, Uuid>(&sql)
                    .fetch_all(&db)
                    .await
                    .unwrap()
            }
        };
        let mut expected = vec![ids[0], ids[1]];
        expected.sort();
        assert_eq!(members(&app).await, expected);

        // A deleted member leaves.
        let (status, _) = app
            .request(Method::DELETE, &format!("/api/v1/account/{}", ids[0]), None)
            .await;
        assert!(status.is_success(), "{status}");
        drain(&app).await;
        assert_eq!(members(&app).await, vec![ids[1]]);
        let history: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT anchor_id, change FROM derived_entity_history WHERE name = $1 ORDER BY at, change",
        )
        .bind(&name)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert!(
            history.contains(&(ids[0], "enter".to_owned())),
            "{history:?}"
        );
        assert!(
            history.contains(&(ids[0], "leave".to_owned())),
            "{history:?}"
        );
        assert!(
            history.contains(&(ids[1], "enter".to_owned())),
            "{history:?}"
        );
        assert!(!history.iter().any(|(id, _)| *id == ids[2]), "{history:?}");

        // The surge guard: a change larger than the limit writes nothing,
        // pauses the definition and holds the anchors until resumed.
        let def = attome_metadata::provision::derived_entity::find(app.db(), &name)
            .await
            .unwrap()
            .unwrap();
        let anchor = app.state.entities.load().get("account").cloned().unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/account",
                Some(json!({ "name": format!("{prefix} C") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let late = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        let outcome = attome_metadata::provision::derived_entity::reconcile(
            app.db(),
            &def,
            &anchor,
            &[late],
            "test",
            Some(0),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            attome_metadata::provision::derived_entity::Reconciled::Surge(1)
        );
        attome_api::derived_maintain::surge(&app.state, &def, &[late], 1)
            .await
            .unwrap();
        drain(&app).await;
        assert_eq!(
            members(&app).await,
            vec![ids[1]],
            "nothing moves while paused"
        );
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/derived-entities/{name}/resume"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["entered"], 1);
        let mut expected = vec![ids[1], late];
        expected.sort();
        assert_eq!(members(&app).await, expected);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/derived-entities/{name}/resume"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: A26
#[test]
fn derived_refresh_fills_and_heals_stored_membership() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
        // Rows written straight to the table: no change events, so only a
        // refresh can find them.
        let prefix = format!("Refresh {}", Uuid::now_v7().simple());
        let mut ids = Vec::new();
        for label in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            "Not it".to_owned(),
        ] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(&label)
            .bind(app.admin.id)
            .fetch_one(app.db())
            .await
            .unwrap();
            ids.push(id);
        }
        let name = format!("dv_rf_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({
                    "anchor": "account",
                    "condition": format!("startswith(name, \"{prefix}\")"),
                    "mode": "stored",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let payload = attome_api::derived_maintain::RefreshPayload {
            name: Some(name.clone()),
        };
        assert_eq!(
            attome_api::derived_maintain::run_refresh(&app.state, &payload)
                .await
                .unwrap(),
            1
        );
        let members = || {
            let sql = format!("SELECT anchor_id FROM \"xrm_dm_{name}\" ORDER BY anchor_id");
            let db = app.db().clone();
            async move {
                sqlx::query_scalar::<_, Uuid>(&sql)
                    .fetch_all(&db)
                    .await
                    .unwrap()
            }
        };
        let mut expected = vec![ids[0], ids[1]];
        expected.sort();
        assert_eq!(members().await, expected);

        // A hard-deleted anchor row leaves on the next refresh; a second
        // refresh with nothing changed moves nothing.
        sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(ids[0])
            .execute(app.db())
            .await
            .unwrap();
        attome_api::derived_maintain::run_refresh(&app.state, &payload)
            .await
            .unwrap();
        assert_eq!(members().await, vec![ids[1]]);
        let def = attome_metadata::provision::derived_entity::find(app.db(), &name)
            .await
            .unwrap()
            .unwrap();
        let anchor = app.state.entities.load().get("account").cloned().unwrap();
        let again = attome_metadata::provision::derived_entity::refresh(app.db(), &def, &anchor)
            .await
            .unwrap();
        assert!(again.is_empty(), "{again:?}");
    });
}

// feature: A26
// op: preview_derived_entity
// op: explain_derived_membership
// op: derived_entity_trend
#[test]
fn derived_explain_preview_and_trend() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
        let prefix = format!("Explain {}", Uuid::now_v7().simple());
        let mut ids = Vec::new();
        for label in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            "Other".to_owned(),
        ] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(&label)
            .bind(app.admin.id)
            .fetch_one(app.db())
            .await
            .unwrap();
            ids.push(id);
        }
        let condition = format!("startswith(name, \"{prefix}\")");

        // Preview with nothing saved: two match, both would enter.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/derived-entities/preview",
                Some(json!({ "anchor": "account", "condition": condition })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["matching"], 2);
        assert_eq!(body["entering"], 2);
        assert!(body["leaving"].is_null());
        assert_eq!(body["sample"].as_array().unwrap().len(), 2);

        let name = format!("dv_ex_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({ "anchor": "account", "condition": condition })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Narrowing it to A: none enter, one leaves.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/derived-entities/preview",
                Some(json!({
                    "name": name,
                    "anchor": "account",
                    "condition": format!("name == \"{prefix} A\""),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["matching"], 1);
        assert_eq!(body["entering"], 0);
        assert_eq!(body["leaving"], 1);

        // Explain: a member, and a record that is not one.
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/derived-entities/{name}/explain/{}", ids[0]),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["member"], true);
        assert_eq!(body["parts"][0]["holds"], true);
        assert_eq!(body["parts"][0]["values"]["name"], format!("{prefix} A"));
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/derived-entities/{name}/explain/{}", ids[2]),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["member"], false);
        assert_eq!(body["parts"][0]["holds"], false);
        assert_eq!(body["parts"][0]["values"]["name"], "Other");

        // A live derived entity's trend is this week's count.
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/derived-entities/{name}/trend"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"][0]["members"], 2);
    });
}

// feature: A26
// op: derived_entity_mass
#[test]
fn derived_mass_changes_only_the_members() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
        let prefix = format!("Mass {}", Uuid::now_v7().simple());
        let mut ids = Vec::new();
        for label in [
            format!("{prefix} A"),
            format!("{prefix} B"),
            format!("Outside {prefix}"),
        ] {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO account (name, owner_ref, owner_type) VALUES ($1, $2, 0) RETURNING id",
            )
            .bind(&label)
            .bind(app.admin.id)
            .fetch_one(app.db())
            .await
            .unwrap();
            ids.push(id);
        }
        let name = format!("dv_ms_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/derived-entities/{name}"),
                Some(json!({
                    "anchor": "account",
                    "condition": format!("startswith(name, \"{prefix}\")"),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let renamed = format!("{prefix} renamed");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/derived-entities/{name}/mass"),
                Some(json!({ "kind": "update", "payload": { "name": renamed }, "reason": "test" })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");
        let names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM account WHERE id = ANY($1) ORDER BY id")
                .bind(&ids)
                .fetch_all(app.db())
                .await
                .unwrap();
        assert_eq!(
            names.iter().filter(|n| **n == renamed).count(),
            2,
            "{names:?}"
        );
        assert!(
            names.contains(&format!("Outside {prefix}")),
            "a non-member is untouched"
        );
    });
}

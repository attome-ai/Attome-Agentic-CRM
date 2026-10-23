//! L1-T4: two systems contribute to one golden record; the rebuild follows
//! each attribute's source-system rank and records where each value came
//! from, and a contribution that fails validation is held and changes
//! nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::entity_crud::master::{self, Ingested};
use attome_testapp::TestApp;
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
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

async fn golden(app: &TestApp, id: Uuid) -> Value {
    sqlx::query_scalar("SELECT row_to_json(t)::jsonb FROM account t WHERE t.id = $1")
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: L1
#[test]
fn rebuild_follows_ranks_and_held_changes_nothing() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        attome_metadata::provision::master::ensure_master_tables(app.db(), "account")
            .await
            .expect("master tables");
        let owner = attome_testapp::seed_admin(app.db()).await.id;
        let ctx = app.state.base.security.resolve(owner).await.expect("ctx");
        // The ERP is trusted first for the phone, the CRM for the website.
        sqlx::query(
            "INSERT INTO survivorship_rule (entity_logicalname, field_logicalname, strategy, \
                                            config, created_by) \
             VALUES ('account', 'phone', 'source_system_rank', $1, $3), \
                    ('account', 'website', 'source_system_rank', $2, $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(json!({"ranks": {"phone": ["erp", "crm"]}}))
        .bind(json!({"ranks": {"website": ["crm", "erp"]}}))
        .bind(owner)
        .execute(app.db())
        .await
        .unwrap();

        let tag = Uuid::now_v7().simple().to_string();
        let crm = master::ingest(
            &app.state,
            &ctx,
            "account",
            "crm",
            &format!("C-{tag}"),
            &obj(
                json!({"name": "Acme", "phone": "+966 11 000 0001", "website": "https://acme.sa"}),
            ),
        )
        .await
        .expect("crm contribution");
        let Ingested::Attached { golden: id, .. } = crm else {
            panic!("the CRM version is valid: {crm:?}");
        };
        // The ERP's id is linked to the same company (A29).
        sqlx::query(
            "INSERT INTO external_id_link (entity, record_id, system, external_id) \
             VALUES ('account', $1, 'erp', $2)",
        )
        .bind(id)
        .bind(format!("E-{tag}"))
        .execute(app.db())
        .await
        .unwrap();
        let erp = master::ingest(
            &app.state,
            &ctx,
            "account",
            "erp",
            &format!("E-{tag}"),
            &obj(json!({"name": "ACME Trading", "phone": "+966 11 999 9999", "website": "http://old.acme"})),
        )
        .await
        .expect("erp contribution");
        let Ingested::Attached {
            golden: same,
            contribution: erp_id,
            ..
        } = erp
        else {
            panic!("the ERP version is valid: {erp:?}");
        };
        assert_eq!(same, id, "both systems feed one golden record");

        let rebuilt = master::rebuild(&app.state, "account", id, owner)
            .await
            .expect("rebuild");
        let record = golden(&app, id).await;
        assert_eq!(
            record["phone"], "+966 11 999 9999",
            "the ERP wins the phone"
        );
        assert_eq!(
            record["website"], "https://acme.sa",
            "the CRM wins the website"
        );
        assert!(rebuilt.changed.contains(&"phone".to_owned()), "{rebuilt:?}");
        let from: Uuid = sqlx::query_scalar(
            "SELECT contribution_id FROM account__provenance \
              WHERE golden_id = $1 AND attribute = 'phone'",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(from, erp_id, "provenance names the ERP's contribution");

        // An invalid version is held and the golden record does not move.
        let before = golden(&app, id).await;
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
        assert!(matches!(held, Ingested::Held { .. }), "{held:?}");
        master::rebuild(&app.state, "account", id, owner)
            .await
            .expect("rebuild");
        assert_eq!(
            golden(&app, id).await["phone"],
            before["phone"],
            "a held contribution changes nothing"
        );
    });
}

async fn golden_changed_events(app: &TestApp, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM entity_change_event \
          WHERE record_id = $1 AND event_name = 'master.golden_changed'",
    )
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: L1
#[test]
fn certified_change_emits_event_draft_does_not() {
    use axum::http::{Method, StatusCode};
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        attome_metadata::provision::master::ensure_master_tables(app.db(), "account")
            .await
            .expect("master tables");
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/master.certified_only",
                Some(json!({"scope": "deployment", "value": ["account"]})),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let owner = app.admin.id;
        let ctx = app.state.base.security.resolve(owner).await.expect("ctx");
        let tag = Uuid::now_v7().simple().to_string();
        let send = |system: &'static str, phone: &'static str| {
            let ctx = ctx.clone();
            let app = &app;
            let tag = tag.clone();
            async move {
                let prefix = if system == "crm" { "C" } else { "E" };
                master::ingest(
                    &app.state,
                    &ctx,
                    "account",
                    system,
                    &format!("{prefix}-{tag}"),
                    &obj(json!({"name": format!("Certified Co {tag}"), "phone": phone})),
                )
                .await
                .expect("contribution")
            }
        };
        let Ingested::Attached { golden: id, .. } = send("crm", "+966 11 100 0001").await else {
            panic!("the CRM version is valid");
        };
        sqlx::query(
            "INSERT INTO external_id_link (entity, record_id, system, external_id) \
             VALUES ('account', $1, 'erp', $2)",
        )
        .bind(id)
        .bind(format!("E-{tag}"))
        .execute(app.db())
        .await
        .unwrap();

        // A draft golden record's change is not sent.
        send("erp", "+966 11 100 0002").await;
        let rebuilt = master::rebuild(&app.state, "account", id, owner)
            .await
            .expect("rebuild");
        assert!(rebuilt.changed.contains(&"phone".to_owned()), "{rebuilt:?}");
        assert_eq!(golden_changed_events(&app, id).await, 0, "draft: no event");

        // Certified: one event per changing rebuild, naming what changed.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/master/account/{id}/certify"),
                Some(json!({"status": "certified"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        send("erp", "+966 11 100 0003").await;
        master::rebuild(&app.state, "account", id, owner)
            .await
            .expect("rebuild");
        assert_eq!(golden_changed_events(&app, id).await, 1);
        let changed: Vec<String> = sqlx::query_scalar(
            "SELECT changed_attributes FROM entity_change_event \
              WHERE record_id = $1 AND event_name = 'master.golden_changed'",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(changed, vec!["phone".to_owned()]);
        // A rebuild that changes nothing sends nothing.
        master::rebuild(&app.state, "account", id, owner)
            .await
            .expect("rebuild");
        assert_eq!(golden_changed_events(&app, id).await, 1);

        // Each subscriber gets its own id for the record.
        let erp = attome_events::master::block(app.db(), "account", id, Some("erp"))
            .await
            .expect("erp block");
        assert_eq!(erp["external_id"], json!(format!("E-{tag}")));
        assert_eq!(erp["certification"], "certified");
        let crm = attome_events::master::block(app.db(), "account", id, Some("crm"))
            .await
            .expect("crm block");
        assert_eq!(crm["external_id"], json!(format!("C-{tag}")));
        let stranger = attome_events::master::block(app.db(), "account", id, Some("wms"))
            .await
            .expect("wms block");
        assert_eq!(stranger["external_id"], Value::Null);
    });
}

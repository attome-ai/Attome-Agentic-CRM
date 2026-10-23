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

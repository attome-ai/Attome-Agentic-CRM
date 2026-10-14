//! A pack installs through the changeset ledger, and installing it again
//! changes nothing (the core CRM at first start, `attome init --pack crm`).

use attome_testapp::TestApp;

#[test]
fn the_crm_pack_installs_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("packs/crm/changesets")
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for _ in 0..2 {
            for file in &files {
                let value: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                        .expect("pack changeset JSON");
                attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                    .await
                    .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            }
        }
        for entity in ["account", "contact", "lead", "opportunity"] {
            let registered: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM entity_info WHERE logicalname = $1 AND is_active IS NOT FALSE)",
            )
            .bind(entity)
            .fetch_one(app.db())
            .await
            .expect("read entity_info");
            assert!(registered, "{entity} is installed by the crm pack");
        }
        let applied: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM changeset_apply WHERE scope = 'crm' AND status IN ('succeeded', 'adopted')",
        )
        .fetch_one(app.db())
        .await
        .expect("count ledger rows");
        assert!(applied >= 1, "the pack is in the ledger");
    });
}

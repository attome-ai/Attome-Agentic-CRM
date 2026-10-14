//! A pack installs through the changeset ledger, and installing it again
//! changes nothing (the core CRM at first start, `attome init --pack crm`).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;

/// Applies every changeset of `packs/<pack>` twice, as a repeated install
/// would, then checks each of `entities` is registered and the pack is in
/// the ledger.
async fn installs_once(app: &TestApp, pack: &str, entities: &[&str]) {
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
    for entity in entities {
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM entity_info WHERE logicalname = $1 AND is_active IS NOT FALSE)",
        )
        .bind(entity)
        .fetch_one(app.db())
        .await
        .expect("read entity_info");
        assert!(registered, "{entity} is installed by the {pack} pack");
    }
    let applied: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM changeset_apply WHERE scope = $1 AND status IN ('succeeded', 'adopted')",
    )
    .bind(pack)
    .fetch_one(app.db())
    .await
    .expect("count ledger rows");
    assert!(applied >= 1, "the {pack} pack is in the ledger");
}

#[test]
fn the_crm_pack_installs_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(&app, "crm", &["account", "contact", "lead", "opportunity"]).await;
    });
}

/// The MENA base library (A1-T12): party, person with the four-part Arabic
/// name and national identifiers, organisation, Saudi national address,
/// work item and agreement.
#[test]
fn the_library_core_pack_installs_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(
            &app,
            "library-core",
            &[
                "party",
                "person",
                "organisation",
                "address",
                "work_item",
                "agreement",
            ],
        )
        .await;
        let sensitive: Vec<String> = sqlx::query_scalar(
            "SELECT a.logicalname FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname = 'person' AND a.is_sensitive ORDER BY a.logicalname",
        )
        .fetch_all(app.db())
        .await
        .expect("read person fields");
        for id in ["emirates_id", "iqama_number", "national_id"] {
            assert!(
                sensitive.iter().any(|f| f == id),
                "person.{id} is sensitive"
            );
        }
    });
}

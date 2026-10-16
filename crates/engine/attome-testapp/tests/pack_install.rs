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
        installs_once(
            &app,
            "crm",
            &[
                "account",
                "contact",
                "lead",
                "opportunity",
                "contact_account_role",
                "account_team_member",
                "customer_address",
            ],
        )
        .await;
        let sensitive: Vec<String> = sqlx::query_scalar(
            "SELECT a.logicalname FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref WHERE e.logicalname = 'contact' AND a.is_sensitive ORDER BY a.logicalname",
        )
        .fetch_all(app.db())
        .await
        .expect("read contact fields");
        for field in ["birth_date", "iqama_no", "national_id"] {
            assert!(
                sensitive.iter().any(|f| f == field),
                "contact.{field} is sensitive"
            );
        }
    });
}

/// D5-T1, D8-T1: the sales pack, on top of the crm pack, adds pipelines with
/// stages as records (seeded for every pipeline), contact roles on deals and
/// the catalogue and pricing entities.
#[test]
fn the_sales_pack_installs_once_on_the_crm_pack() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(&app, "crm", &["opportunity"]).await;
        installs_once(
            &app,
            "sales",
            &[
                "product",
                "price_list",
                "opportunity_stage",
                "opportunity_contact_role",
                "unit_group",
                "unit",
                "product_family",
                "price_break",
                "account_price",
                "related_product",
            ],
        )
        .await;
        let stages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM opportunity_stage WHERE is_active = true AND pipeline = 'new_business'",
        )
        .fetch_one(app.db())
        .await
        .expect("count stages");
        assert_eq!(stages, 6, "every pipeline has its six default stages, once");
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

/// E1-T1, E7-T1, E9-T1: the marketing pack, on top of the crm pack, adds
/// campaigns, lists, events and nurture programmes, and a lifecycle stage on
/// leads.
#[test]
fn the_marketing_pack_installs_once_on_the_crm_pack() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(&app, "crm", &["lead", "contact"]).await;
        installs_once(
            &app,
            "marketing",
            &[
                "campaign",
                "marketing_list",
                "marketing_nurture_program",
                "marketing_nurture_track",
                "marketing_nurture_content",
            ],
        )
        .await;
        let lead_fields: Vec<String> = sqlx::query_scalar(
            "SELECT a.logicalname FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname = 'lead' ORDER BY a.logicalname",
        )
        .fetch_all(app.db())
        .await
        .expect("read lead fields");
        for field in ["campaign_ref", "lifecycle_stage", "wake_up_on"] {
            assert!(lead_fields.iter().any(|f| f == field), "lead.{field}");
        }
    });
}

/// F10-T13: the commission pack's pay roles; every amount is sensitive and
/// readable only through the Commission Amounts profile.
#[test]
fn the_commission_pack_installs_once_with_masked_amounts() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(
            &app,
            "commission",
            &["comp_plan", "comp_statement_line", "comp_payout"],
        )
        .await;
        let open: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname IN ('comp_credit', 'comp_statement_line', 'comp_payout') \
               AND a.logicalname = 'amount' AND NOT a.is_sensitive",
        )
        .fetch_one(app.db())
        .await
        .expect("read amount fields");
        assert_eq!(open, 0, "pay amounts are sensitive");
        let roles: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM role WHERE name IN \
             ('Commission Seller', 'Commission Manager', 'Sales Ops', 'Commission Finance')",
        )
        .fetch_one(app.db())
        .await
        .expect("count roles");
        assert_eq!(roles, 4, "the four pay roles, once");
    });
}

/// D21-T10: the calling metric queries run against the installed dialer
/// entities.
#[test]
fn the_calling_metric_queries_run() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        installs_once(&app, "crm", &["lead"]).await;
        installs_once(&app, "sales", &["call_attempt", "call_list_member"]).await;
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs/sales/changesets/0013-sales-calling-metrics.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read")).expect("json");
        let mut ran = 0;
        for op in doc["operations"].as_array().expect("operations") {
            if op["op"] != "upsert_query" {
                continue;
            }
            let sql = op["args"]["definition"]["sql"].as_str().expect("sql");
            sqlx::query(sql)
                .fetch_all(app.db())
                .await
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
            ran += 1;
        }
        assert_eq!(ran, 5, "the five calling metric queries");
    });
}

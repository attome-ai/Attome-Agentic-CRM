//! D25-T10: competitor tracking end to end: a note names a competitor, the
//! mention is proposed and confirmed onto the deal, the deal is lost to it
//! above the review threshold, the review is created with the competitor in
//! its snapshot, and the head-to-head analysis counts the loss.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 2] = ["crm", "sales"];

async fn install(app: &TestApp) {
    for pack in PACKS {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
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
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

// feature: D25
#[test]
fn competitor_tracking_full_flow() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let db = app.db();
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let name = format!("Rivalco{tag}");

        let competitor: Uuid = sqlx::query_scalar(
            "INSERT INTO competitor (name, is_tracked) VALUES ($1, true) RETURNING id",
        )
        .bind(&name)
        .fetch_one(db)
        .await
        .unwrap();
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Flow Co') RETURNING id")
                .fetch_one(db)
                .await
                .unwrap();
        let deal: Uuid = sqlx::query_scalar(
            "INSERT INTO opportunity (name, account_ref, pipeline, stage, amount, currency, \
                 close_date, owner_ref) \
             VALUES ('Flow deal', $1, 'new_business', 'negotiation', 500000, 'SAR', \
                 CURRENT_DATE + 10, $2) RETURNING id",
        )
        .bind(account)
        .bind(app.admin.id)
        .fetch_one(db)
        .await
        .unwrap();

        // A note on the deal names the competitor: a mention is proposed.
        let note: Uuid = sqlx::query_scalar(
            "INSERT INTO note (title, note_text, entity_name, record_id) \
             VALUES ('Call', $1, 'opportunity', $2) RETURNING id",
        )
        .bind(format!("They are also talking to {name} about price."))
        .bind(deal.to_string())
        .fetch_one(db)
        .await
        .unwrap();
        let names = attome_sales::competitor_mentions::competitor_names(&app.state)
            .await
            .unwrap();
        let written =
            attome_sales::competitor_mentions::scan_source(&app.state, "note", note, &names)
                .await
                .unwrap();
        assert_eq!(written, 1);
        let (mention, version): (Uuid, i64) = sqlx::query_as(
            "SELECT id, row_version FROM competitor_mention \
              WHERE opportunity_ref = $1 AND competitor_ref = $2 AND status = 'proposed'",
        )
        .bind(deal)
        .bind(competitor)
        .fetch_one(db)
        .await
        .unwrap();

        // Confirmed: the competitor is on the deal.
        let decided = attome_sales::competitor_routes::decide_mention(
            &app.state, &admin, mention, version, true,
        )
        .await
        .unwrap();
        assert!(decided.opportunity_competitor_id.is_some());
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_ingest WHERE payload->>'record_id' = $1",
        )
        .bind(mention.to_string())
        .fetch_one(db)
        .await
        .unwrap();
        assert!(audited >= 1, "the confirmation is audited");

        // A big loss to it is reviewed.
        sqlx::query(
            "UPDATE opportunity_stage SET review_amount_threshold = 1000 \
              WHERE stage = 'closed_lost' AND pipeline = 'new_business'",
        )
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE opportunity SET stage = 'closed_lost', lost_to_competitor_ref = $2 WHERE id = $1",
        )
        .bind(deal)
        .bind(competitor)
        .execute(db)
        .await
        .unwrap();
        assert!(
            attome_sales::win_loss::review_close(&app.state, deal)
                .await
                .unwrap()
        );
        let snapshot: Option<String> = sqlx::query_scalar(
            "SELECT competitors_snapshot FROM win_loss_review \
              WHERE opportunity_ref = $1 AND outcome = 'lost'",
        )
        .bind(deal)
        .fetch_one(db)
        .await
        .unwrap();
        assert!(
            snapshot
                .unwrap_or_default()
                .contains(&competitor.to_string()),
            "the review keeps the competitors on the deal"
        );
        // Reviewed once.
        assert!(
            !attome_sales::win_loss::review_close(&app.state, deal)
                .await
                .unwrap()
        );

        // The analysis counts the loss and the confirmed mention.
        let h2h = attome_sales::competitor_routes::head_to_head(&app.state, &admin, competitor)
            .await
            .unwrap();
        assert_eq!(h2h.lost, 1, "{h2h:?}");
        assert_eq!(h2h.won, 0);
        assert!(h2h.recent_mentions.iter().any(|m| m.mention_id == mention));
    });
}

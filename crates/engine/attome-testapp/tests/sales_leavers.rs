//! D7-T6: a disabled user's open deals are reported to the person above them
//! once per disable, and nothing on the deals changes.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
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

async fn position(app: &TestApp, parent: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO position (name, parent_position_ref) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("pos-{}", Uuid::now_v7().simple()))
    .bind(parent)
    .fetch_one(app.db())
    .await
    .expect("insert position")
}

async fn hold(app: &TestApp, user: Uuid, position: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_position (user_ref, position_ref) VALUES ($1, $2)")
        .bind(user)
        .bind(position)
        .execute(app.db())
        .await
        .expect("hold position");
}

async fn deal(app: &TestApp, owner: Uuid, name: &str, stage: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO opportunity (id, name, stage, owner_ref, is_active) \
         VALUES ($1, $2, $3, $4, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(name)
    .bind(stage)
    .bind(owner)
    .fetch_one(app.db())
    .await
    .expect("insert deal")
}

async fn disable(app: &TestApp, user: Uuid) {
    sqlx::query(
        "UPDATE user_account SET is_active = false, auth_epoch = auth_epoch + 1 WHERE id = $1",
    )
    .bind(user)
    .execute(app.db())
    .await
    .expect("disable user");
}

async fn reports_to(app: &TestApp, manager: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT COALESCE(body_text, '') FROM notification_dispatch \
         WHERE recipient_user_ref = $1 ORDER BY created_at",
    )
    .bind(manager)
    .fetch_all(app.db())
    .await
    .expect("read dispatches")
}

// feature: D7
#[test]
fn a_leavers_open_deals_go_to_their_manager_once_per_disable() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        let manager = attome_testapp::seed_user(app.db(), "leaver-manager")
            .await
            .id;
        let leaver = attome_testapp::seed_user(app.db(), "leaver").await.id;
        let top = position(&app, None).await;
        let below = position(&app, Some(top)).await;
        hold(&app, manager, top).await;
        hold(&app, leaver, below).await;
        let open = deal(&app, leaver, "Leaver open deal", "proposal").await;
        deal(&app, leaver, "Leaver second deal", "negotiation").await;
        deal(&app, leaver, "Leaver won deal", "closed_won").await;

        // Active: nothing to report.
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .expect("sweep");
        assert!(reports_to(&app, manager).await.is_empty());

        disable(&app, leaver).await;
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .expect("sweep");
        let reports = reports_to(&app, manager).await;
        assert_eq!(reports.len(), 1, "one report: {reports:?}");
        assert!(reports[0].contains("2 open deals"), "{}", reports[0]);
        assert!(reports[0].contains("Leaver open deal"));
        assert!(!reports[0].contains("Leaver won deal"));

        // Swept again: still one report.
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .expect("sweep");
        assert_eq!(reports_to(&app, manager).await.len(), 1);

        // The deals are untouched: still owned by the leaver.
        let owner: Uuid = sqlx::query_scalar("SELECT owner_ref FROM opportunity WHERE id = $1")
            .bind(open)
            .fetch_one(app.db())
            .await
            .expect("read deal");
        assert_eq!(owner, leaver);

        // Enabled and disabled again: reported again.
        sqlx::query(
            "UPDATE user_account SET is_active = true, auth_epoch = auth_epoch + 1 WHERE id = $1",
        )
        .bind(leaver)
        .execute(app.db())
        .await
        .expect("enable");
        disable(&app, leaver).await;
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .expect("sweep");
        assert_eq!(reports_to(&app, manager).await.len(), 2);
    });
}

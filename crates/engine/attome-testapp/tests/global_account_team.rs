//! D2-T2: the CRM pack's Global Account Manager role reaches a customer
//! group's subsidiaries through the owner subtree (A17-T3): the manager of
//! the parent account reads and updates the subsidiary accounts and deals
//! owned by the account managers in positions under theirs, and nothing
//! owned by anyone else.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_security::RecordAction;
use attome_testapp::{TestApp, seed_user};
use uuid::Uuid;

async fn install(app: &TestApp) {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
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

async fn grant_role(app: &TestApp, user: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO user_account_mm_role (user_ref, role_ref) \
         SELECT $1, id FROM role WHERE name = $2 AND is_deleted = false",
    )
    .bind(user)
    .bind(role)
    .execute(app.db())
    .await
    .expect("grant role");
}

async fn account(app: &TestApp, name: &str, owner: Uuid, parent: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, owner_ref, owner_type, parent_account_ref) \
         VALUES ($1, $2, 0, $3) RETURNING id",
    )
    .bind(name)
    .bind(owner)
    .bind(parent)
    .fetch_one(app.db())
    .await
    .expect("insert account")
}

async fn deal(app: &TestApp, account: Uuid, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO opportunity (name, account_ref, stage, owner_ref, owner_type) \
         VALUES ('Group deal', $1, 'proposal', $2, 0) RETURNING id",
    )
    .bind(account)
    .bind(owner)
    .fetch_one(app.db())
    .await
    .expect("insert opportunity")
}

async fn can(app: &TestApp, user: Uuid, entity: &str, record: Uuid, action: RecordAction) -> bool {
    let entity_id = app.state.entities.load().get(entity).unwrap().entity_id;
    app.state.base.security.invalidate_sync(user).await.unwrap();
    let ctx = app.state.base.security.resolve(user).await.unwrap();
    attome_records::entity_crud::require_record_access(
        &app.state, &ctx, entity_id, entity, record, action,
    )
    .await
    .is_ok()
}

// feature: D2
#[test]
fn global_account_manager_sees_subsidiaries() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let global = seed_user(app.db(), "d2-global").await.id;
        let local = seed_user(app.db(), "d2-subsidiary").await.id;
        let stranger = seed_user(app.db(), "d2-stranger").await.id;
        let top = position(&app, None).await;
        hold(&app, global, top).await;
        hold(&app, local, position(&app, Some(top)).await).await;
        hold(&app, stranger, position(&app, None).await).await;
        for user in [global, local, stranger] {
            grant_role(&app, user, "Global Account Manager").await;
        }

        let parent = account(&app, "Group Holding", global, None).await;
        let subsidiary = account(&app, "Group Subsidiary", local, Some(parent)).await;
        let other = account(&app, "Unrelated Co", stranger, None).await;
        let subsidiary_deal = deal(&app, subsidiary, local).await;

        for (entity, record) in [
            ("account", parent),
            ("account", subsidiary),
            ("opportunity", subsidiary_deal),
        ] {
            assert!(
                can(&app, global, entity, record, RecordAction::Read).await,
                "{entity} {record}"
            );
        }
        assert!(can(&app, global, "account", subsidiary, RecordAction::Update).await);
        assert!(
            !can(&app, global, "account", subsidiary, RecordAction::Delete).await,
            "the subtree reaches read and update only"
        );
        assert!(!can(&app, global, "account", other, RecordAction::Read).await);
        // The subtree runs downward only.
        assert!(!can(&app, local, "account", parent, RecordAction::Read).await);
    });
}

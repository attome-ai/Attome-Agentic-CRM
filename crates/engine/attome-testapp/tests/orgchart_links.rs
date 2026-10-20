//! D23-T4: a contact's manager is set only through the org chart route,
//! only within the contact's account or its group, and never into a loop.
//! D23-T7: a deal map shows influence and attitude only through the Deal
//! Attitude field profile.

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

async fn install(app: &TestApp) {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/crm/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

async fn account(app: &TestApp, name: &str, parent: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO account (name, parent_account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(parent)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn contact(app: &TestApp, name: &str, account: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO contact (full_name, account_ref, is_active, row_version) \
         VALUES ($1, $2, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn version(app: &TestApp, contact: Uuid) -> i64 {
    sqlx::query_scalar("SELECT row_version FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn set(app: &TestApp, contact: Uuid, manager: Option<Uuid>) -> (StatusCode, Value) {
    let if_match = format!("\"{}\"", version(app, contact).await);
    app.request_with(
        Method::PUT,
        &format!("/api/v1/sales/contacts/{contact}/manager"),
        &[("if-match", if_match.as_str())],
        Some(json!({ "manager_id": manager, "line": "solid" })),
    )
    .await
}

async fn manager_of(app: &TestApp, contact: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT reports_to FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: D23
#[test]
fn manager_at_unrelated_account_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let group = account(&app, "Holding", None).await;
        let branch = account(&app, "Holding Riyadh", Some(group)).await;
        let other = account(&app, "Unrelated Co", None).await;
        let rep = contact(&app, "Sara", branch).await;
        let group_boss = contact(&app, "Khalid", group).await;
        let stranger = contact(&app, "Omar", other).await;

        let (status, body) = set(&app, rep, Some(stranger)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(manager_of(&app, rep).await, None);

        let (status, body) = set(&app, rep, Some(group_boss)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous_manager_id"], Value::Null, "{body}");
        assert_eq!(manager_of(&app, rep).await, Some(group_boss));

        // Undo: set the previous manager back.
        let (status, body) = set(&app, rep, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["previous_manager_id"], json!(group_boss), "{body}");
        assert_eq!(manager_of(&app, rep).await, None);
    });
}

// feature: D23
#[test]
fn loop_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let acme = account(&app, "Acme", None).await;
        let ceo = contact(&app, "Ceo", acme).await;
        let vp = contact(&app, "Vp", acme).await;
        let rep = contact(&app, "Rep", acme).await;

        assert_eq!(set(&app, vp, Some(ceo)).await.0, StatusCode::OK);
        assert_eq!(set(&app, rep, Some(vp)).await.0, StatusCode::OK);
        let (status, body) = set(&app, ceo, Some(rep)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = set(&app, ceo, Some(ceo)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(manager_of(&app, ceo).await, None);
    });
}

// feature: D23
#[test]
fn generic_patch_of_reports_to_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let acme = account(&app, "Acme", None).await;
        let boss = contact(&app, "Boss", acme).await;
        let rep = contact(&app, "Rep", acme).await;
        let if_match = format!("\"{}\"", version(&app, rep).await);
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/contact/{rep}"),
                &[("if-match", if_match.as_str())],
                Some(json!({ "reports_to": boss })),
            )
            .await;
        assert!(status.is_client_error(), "{status}: {body}");
        assert_eq!(manager_of(&app, rep).await, None);
    });
}

/// D23-T7: the sales pack on the crm pack.
async fn install_sales(app: &TestApp) {
    install(app).await;
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/sales/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

/// A user who reads their own deals, contacts and accounts but holds no
/// field profile (so not Deal Attitude).
async fn deal_reader(app: &TestApp) -> Uuid {
    let user = attome_testapp::seed_user(app.db(), "deal-reader").await;
    let role: Uuid = sqlx::query_scalar(
        "INSERT INTO role (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
    )
    .bind(format!("Deal reader {}", Uuid::now_v7().simple()))
    .fetch_one(app.db())
    .await
    .unwrap();
    for entity in [
        "account",
        "contact",
        "opportunity",
        "opportunity_contact_role",
    ] {
        sqlx::query(
            "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) \
             SELECT $1, id, 'customer' FROM privilege WHERE key = $2",
        )
        .bind(role)
        .bind(format!("{entity}.read"))
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO role_mm_entity_access (role_ref, entity_ref, read_access_level, \
                 write_access_level, delete_access_level, read_owner_visible, owner_layer) \
             SELECT $1, id, 1, 1, 1, true, 'customer' FROM entity_info WHERE logicalname = $2",
        )
        .bind(role)
        .bind(entity)
        .execute(app.db())
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .unwrap();
    user.id
}

// feature: D23
#[test]
fn deal_map_hides_attitude_without_profile() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_sales(&app).await;
        let reader = deal_reader(&app).await;
        let account: Uuid = sqlx::query_scalar(
            "INSERT INTO account (name, owner_ref, is_active, row_version) \
             VALUES ('Committee Co', $1, true, 0) RETURNING id",
        )
        .bind(reader)
        .fetch_one(app.db())
        .await
        .unwrap();
        let contact: Uuid = sqlx::query_scalar(
            "INSERT INTO contact (full_name, account_ref, owner_ref, is_active, row_version) \
             VALUES ('Huda Sceptic', $1, $2, true, 0) RETURNING id",
        )
        .bind(account)
        .bind(reader)
        .fetch_one(app.db())
        .await
        .unwrap();
        let stage = format!("committee_{}", Uuid::now_v7().simple());
        sqlx::query(
            "INSERT INTO opportunity_stage (name, stage, required_contact_roles, is_active, \
                 row_version) VALUES ('Committee', $1, '[\"economic_buyer\", \"champion\"]', true, 0)",
        )
        .bind(&stage)
        .execute(app.db())
        .await
        .unwrap();
        let deal: Uuid = sqlx::query_scalar(
            "INSERT INTO opportunity (name, account_ref, stage, owner_ref, is_active, row_version) \
             VALUES ('Committee deal', $1, $2, $3, true, 0) RETURNING id",
        )
        .bind(account)
        .bind(&stage)
        .bind(reader)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO opportunity_contact_role (opportunity_ref, contact_ref, role, influence, \
                 attitude, owner_ref, is_active, row_version) \
             VALUES ($1, $2, 'champion', 'high', 'sceptic', $3, true, 0)",
        )
        .bind(deal)
        .bind(contact)
        .bind(reader)
        .execute(app.db())
        .await
        .unwrap();

        use attome_sales::orgchart::committee::{GapKind, deal_map};

        // Without the Deal Attitude profile: the role, not influence or
        // attitude, and no gap that would reveal influence.
        let ctx = attome_security::resolve_uncached(app.db(), reader)
            .await
            .unwrap();
        let map = deal_map(&app.state, &ctx, deal).await.unwrap();
        assert_eq!(map.contacts.len(), 1, "{map:?}");
        let c = &map.contacts[0];
        assert_eq!(c.role.as_deref(), Some("champion"));
        assert_eq!(c.full_name.as_deref(), Some("Huda Sceptic"));
        assert_eq!(
            (c.influence.as_deref(), c.attitude.as_deref()),
            (None, None)
        );
        assert_eq!(map.required_roles, vec!["economic_buyer", "champion"]);
        assert!(
            map.gaps
                .iter()
                .any(|g| g.kind == GapKind::MissingRole
                    && g.role.as_deref() == Some("economic_buyer"))
        );
        assert!(
            map.gaps
                .iter()
                .all(|g| g.kind != GapKind::UnmetHighInfluence)
        );

        // The administrator sees both, and the unmet high-influence contact.
        let admin = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let map = deal_map(&app.state, &admin, deal).await.unwrap();
        let c = &map.contacts[0];
        assert_eq!(
            (c.influence.as_deref(), c.attitude.as_deref()),
            (Some("high"), Some("sceptic"))
        );
        assert!(
            map.gaps
                .iter()
                .any(|g| g.kind == GapKind::UnmetHighInfluence && g.contact_id == Some(contact))
        );
    });
}

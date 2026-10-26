//! D7-T9: deal teams and splits against a real database, with the CRM and
//! sales packs installed and the deal-team switches on.
//!
//! The partner case (`partner_member_sees_only_that_deal`) is not here: a
//! partner contact reaches deals through the portal, which a test cannot
//! sign in to yet (the step's stop rule).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::changeset::Layer;
use attome_sales::split_store::{SalesSplitsBody, SplitInput, SplitProposal};
use attome_sales::team::{SalesTeamMemberBody, TeamAccess};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_testapp::{TestApp, TestUser, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
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
    for flag in ["sales.deal_teams", "sales.splits", "sales.team_suggestions"] {
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/settings/feature.{flag}"),
                Some(json!({ "scope": "deployment", "value": { "deployment": true } })),
            )
            .await;
        assert!(status.is_success(), "{flag}: {status} {body}");
    }
}

/// A user whose one role holds `privileges` and reads deals only when
/// shared with them (record access level 0).
async fn user_with(app: &TestApp, label: &str, privileges: &[&str]) -> TestUser {
    let (status, role) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/roles",
            Some(json!({ "name": format!("d7-{label}-{}", Uuid::now_v7().simple()) })),
        )
        .await;
    assert!(status.is_success(), "{status} {role}");
    let role_id = role["id"].as_str().unwrap().to_owned();
    for key in privileges {
        attome_security::db::ensure_privilege(app.db(), key, key, "test", Layer::Project)
            .await
            .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/role-grants",
                Some(json!({ "role_id": role_id, "privilege_key": key })),
            )
            .await;
        assert!(status.is_success(), "{key}: {status} {body}");
    }
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/security/role-entity-access",
            Some(json!({ "role_id": role_id, "entity": "opportunity", "read_access_level": 0 })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    let user = seed_user(app.db(), label).await;
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2::uuid)")
        .bind(user.id)
        .bind(&role_id)
        .execute(app.db())
        .await
        .unwrap();
    user
}

async fn ctx(app: &TestApp, user: Uuid) -> SecurityContext {
    app.state.base.security.invalidate_sync(user).await.unwrap();
    app.state.base.security.resolve(user).await.unwrap()
}

async fn admin(app: &TestApp) -> SecurityContext {
    ctx(app, app.admin.id).await
}

/// A deal owned by `owner`, at `stage` with `amount`.
async fn deal(app: &TestApp, owner: Uuid, stage: &str, amount: i64) -> Uuid {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Team Co') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    sqlx::query_scalar(
        "INSERT INTO opportunity (name, account_ref, stage, amount, currency, close_date, owner_ref) \
         VALUES ('Team deal', $1, $2, $3, 'SAR', CURRENT_DATE + 30, $4) RETURNING id",
    )
    .bind(account)
    .bind(stage)
    .bind(amount)
    .bind(owner)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn role_ref(app: &TestApp) -> Uuid {
    sqlx::query_scalar("SELECT id FROM sales_team_role WHERE name = 'Sales Engineer' LIMIT 1")
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn split_type(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM sales_split_type WHERE name = $1 LIMIT 1")
        .bind(name)
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn can_read(app: &TestApp, user: Uuid, deal: Uuid) -> bool {
    let entity = app
        .state
        .entities
        .load()
        .get("opportunity")
        .unwrap()
        .entity_id;
    let user_ctx = ctx(app, user).await;
    attome_records::entity_crud::require_record_access(
        &app.state,
        &user_ctx,
        entity,
        "opportunity",
        deal,
        RecordAction::Read,
    )
    .await
    .is_ok()
}

async fn add(
    app: &TestApp,
    deal: Uuid,
    user: Uuid,
    access: TeamAccess,
) -> Result<Uuid, attome_types::AppError> {
    let role = role_ref(app).await;
    let (_, member) = attome_sales::team::add_member(
        &app.state,
        &admin(app).await,
        deal,
        SalesTeamMemberBody {
            user_ref: Some(user),
            partner_contact_ref: None,
            team_role_ref: role,
            access_level: access,
        },
    )
    .await?;
    Ok(member.0.id)
}

async fn split_amounts(app: &TestApp, deal: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT amount::text FROM opportunity_split WHERE opportunity_ref = $1 ORDER BY percent DESC",
    )
    .bind(deal)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: D7
#[test]
fn member_gets_read_access() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let member = user_with(&app, "d7-reader", &["opportunity.read"]).await;
        let deal = deal(&app, app.admin.id, "prospecting", 1000).await;
        assert!(!can_read(&app, member.id, deal).await, "not shared yet");
        add(&app, deal, member.id, TeamAccess::Read).await.unwrap();
        assert!(can_read(&app, member.id, deal).await);
    });
}

// feature: D7
#[test]
fn removed_member_loses_access() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let member = user_with(&app, "d7-removed", &["opportunity.read"]).await;
        let deal = deal(&app, app.admin.id, "prospecting", 1000).await;
        let row = add(&app, deal, member.id, TeamAccess::Read).await.unwrap();
        assert!(can_read(&app, member.id, deal).await);
        attome_sales::team::remove_member(&app.state, &admin(&app).await, deal, row)
            .await
            .unwrap();
        assert!(!can_read(&app, member.id, deal).await);
    });
}

// feature: D7
// negative: post_sales_team_member
#[test]
fn access_above_role_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let member = user_with(&app, "d7-readonly", &["opportunity.read"]).await;
        let deal = deal(&app, app.admin.id, "prospecting", 1000).await;
        let refused = add(&app, deal, member.id, TeamAccess::Edit).await;
        assert!(
            matches!(&refused, Err(attome_types::AppError::Validation(m)) if m.contains("access_above_role")),
            "{refused:?}"
        );
    });
}

// feature: D7
#[test]
fn default_team_added_on_create() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let owner = user_with(
            &app,
            "d7-owner",
            &["opportunity.read", "opportunity.update"],
        )
        .await;
        let member = user_with(&app, "d7-default", &["opportunity.read"]).await;
        sqlx::query(
            "INSERT INTO user_default_team_member (owner_user_ref, member_user_ref, team_role_ref, \
                 access_level) VALUES ($1, $2, $3, 'read')",
        )
        .bind(owner.id)
        .bind(member.id)
        .bind(role_ref(&app).await)
        .execute(app.db())
        .await
        .unwrap();
        let deal = deal(&app, owner.id, "prospecting", 1000).await;
        let added = attome_sales::team_defaults::apply_defaults_to_deal(&app.state, deal, None)
            .await
            .unwrap();
        assert_eq!(added, 1);
        assert!(can_read(&app, member.id, deal).await);
        // A second pass adds nobody.
        assert_eq!(
            attome_sales::team_defaults::apply_defaults_to_deal(&app.state, deal, None)
                .await
                .unwrap(),
            0
        );
    });
}

// feature: D7
#[test]
fn copy_account_team_by_role() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let member = user_with(&app, "d7-account", &["opportunity.read"]).await;
        let deal = deal(&app, app.admin.id, "prospecting", 1000).await;
        sqlx::query(
            "INSERT INTO account_team_member (account_ref, user_ref, team_role, access) \
             SELECT account_ref, $2, 'pre_sales', 'read' FROM opportunity WHERE id = $1",
        )
        .bind(deal)
        .bind(member.id)
        .execute(app.db())
        .await
        .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{deal}/team/copy-account-team"),
                Some(json!({ "roles": ["pre_sales"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["added"], 1, "{body}");
        assert!(can_read(&app, member.id, deal).await);
    });
}

/// A won deal with its owner on the team, and the owner's member row.
async fn won_deal_with_owner_member(app: &TestApp) -> (Uuid, Uuid) {
    let deal = deal(app, app.admin.id, "closed_won", 1000).await;
    let member = add(app, deal, app.admin.id, TeamAccess::Edit)
        .await
        .unwrap();
    (deal, member)
}

async fn propose(app: &TestApp, deal: Uuid, member: Uuid) -> (StatusCode, Value) {
    let revenue = split_type(app, "Revenue").await;
    let (status, outcome) = attome_sales::split_store::replace_splits(
        &app.state,
        &admin(app).await,
        deal,
        SalesSplitsBody {
            splits: vec![SplitInput {
                member_id: member,
                split_type_id: revenue,
                line_id: None,
                percent: "100".into(),
            }],
            change_reason: Some("corrected credit".into()),
        },
    )
    .await
    .unwrap();
    (status, serde_json::to_value(&outcome.0).unwrap())
}

// feature: D7
#[test]
fn won_deal_split_change_needs_approval() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (deal, member) = won_deal_with_owner_member(&app).await;
        let (status, outcome) = propose(&app, deal, member).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{outcome}");
        assert!(outcome["approval_request_id"].is_string(), "{outcome}");
        assert!(
            split_amounts(&app, deal).await.is_empty(),
            "nothing applied yet"
        );
    });
}

// feature: D7
#[test]
fn approved_split_applies() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (deal, member) = won_deal_with_owner_member(&app).await;
        let (_, outcome) = propose(&app, deal, member).await;
        let request: Uuid = outcome["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let payload: Value =
            sqlx::query_scalar("SELECT payload FROM approval_request WHERE id = $1")
                .bind(request)
                .fetch_one(app.db())
                .await
                .unwrap();
        let proposal: SplitProposal = serde_json::from_value(payload).unwrap();
        let approver = seed_user(app.db(), "d7-approver").await;
        attome_sales::split_store::do_apply_proposal(&app.state, &proposal, approver.id)
            .await
            .unwrap();
        let amounts = split_amounts(&app, deal).await;
        assert_eq!(amounts.len(), 1, "{amounts:?}");
        assert_eq!(amounts[0].parse::<f64>().unwrap(), 1000.0);
    });
}

// feature: D7
#[test]
fn owner_change_keeps_old_owner_as_member() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let old = user_with(
            &app,
            "d7-old-owner",
            &["opportunity.read", "opportunity.update"],
        )
        .await;
        let new = user_with(
            &app,
            "d7-new-owner",
            &["opportunity.read", "opportunity.update"],
        )
        .await;
        let deal = deal(&app, old.id, "prospecting", 1000).await;
        let role = role_ref(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/opportunities/{deal}/change-owner"),
                Some(json!({ "new_owner": new.id, "old_owner_role": role })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let owner: Uuid = sqlx::query_scalar("SELECT owner_ref FROM opportunity WHERE id = $1")
            .bind(deal)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(owner, new.id);
        let kept: Option<Uuid> = sqlx::query_scalar(
            "SELECT team_role_ref FROM opportunity_team_member \
              WHERE opportunity_ref = $1 AND user_ref = $2",
        )
        .bind(deal)
        .bind(old.id)
        .fetch_optional(app.db())
        .await
        .unwrap()
        .flatten();
        assert_eq!(kept, Some(role), "the old owner stays on the team");
        assert!(can_read(&app, old.id, deal).await);
    });
}

// feature: D7
#[test]
fn leaver_deals_listed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let leaver = seed_user(app.db(), "d7-leaver").await;
        deal(&app, leaver.id, "prospecting", 1000).await;
        sqlx::query(
            "UPDATE user_account SET is_active = false, auth_epoch = auth_epoch + 1 WHERE id = $1",
        )
        .bind(leaver.id)
        .execute(app.db())
        .await
        .unwrap();
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .unwrap();
        let noticed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_leaver_notice WHERE user_ref = $1")
                .bind(leaver.id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(noticed, 1);
        // Reported once per disable.
        attome_sales::leavers::sweep_leavers(&app.state)
            .await
            .unwrap();
        let again: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_leaver_notice WHERE user_ref = $1")
                .bind(leaver.id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(again, 1);
    });
}

/// The deal-close consumer's cursor.
async fn close_cursor(app: &TestApp) -> Option<(String, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT last_commit_xid::text, last_id FROM change_consumer_cursor WHERE consumer = $1",
    )
    .bind(attome_sales::win_loss::DEAL_CLOSE_CONSUMER)
    .fetch_optional(app.db())
    .await
    .unwrap()
}

// feature: D7
#[test]
fn split_amount_follows_amount_change() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let member = user_with(&app, "d7-split", &["opportunity.read"]).await;
        let deal = deal(&app, app.admin.id, "prospecting", 1000).await;
        let owner_row = add(&app, deal, app.admin.id, TeamAccess::Edit)
            .await
            .unwrap();
        let member_row = add(&app, deal, member.id, TeamAccess::Read).await.unwrap();
        let revenue = split_type(&app, "Revenue").await;
        let (status, _) = attome_sales::split_store::replace_splits(
            &app.state,
            &admin(&app).await,
            deal,
            SalesSplitsBody {
                splits: vec![
                    SplitInput {
                        member_id: owner_row,
                        split_type_id: revenue,
                        line_id: None,
                        percent: "60".into(),
                    },
                    SplitInput {
                        member_id: member_row,
                        split_type_id: revenue,
                        line_id: None,
                        percent: "40".into(),
                    },
                ],
                change_reason: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        let amounts: Vec<f64> = split_amounts(&app, deal)
            .await
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(amounts, vec![600.0, 400.0]);

        let version: i64 = sqlx::query_scalar("SELECT row_version FROM opportunity WHERE id = $1")
            .bind(deal)
            .fetch_one(app.db())
            .await
            .unwrap();
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/opportunity/{deal}"),
                &[("if-match", &format!("\"{version}\""))],
                Some(json!({ "amount": 2000 })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        for _ in 0..500 {
            let before = close_cursor(&app).await;
            attome_sales::win_loss::sweep_closes(&app.state)
                .await
                .unwrap();
            if close_cursor(&app).await == before {
                break;
            }
        }
        let amounts: Vec<f64> = split_amounts(&app, deal)
            .await
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(amounts, vec![1200.0, 800.0]);
    });
}

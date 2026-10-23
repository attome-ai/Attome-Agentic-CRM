//! L2-T4: a new quality issue goes to the entity's domain steward with a due
//! date from the target, its owner moves it through its statuses (accepting
//! needs a reason), and a reader of profiles who may not read the entity
//! sees none of its issues.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::json;
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

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: L2
#[test]
fn issues_assigned_and_hidden_from_non_readers() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        let steward = attome_testapp::seed_user(app.db(), "issue-steward").await;
        grant(&app, steward.id, "metadata.read").await;
        grant(&app, steward.id, "account.read").await;
        let outsider = attome_testapp::seed_user(app.db(), "issue-outsider").await;
        grant(&app, outsider.id, "metadata.read").await;

        let domain: Uuid = sqlx::query_scalar(
            "INSERT INTO data_domain (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
        )
        .bind(format!("Issue domain {}", Uuid::now_v7().simple()))
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO governance_role (domain_ref, user_id, role) VALUES ($1, $2, 'steward')",
        )
        .bind(domain)
        .bind(steward.id)
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query("UPDATE entity_info SET domain_ref = $1 WHERE logicalname = 'account'")
            .bind(domain)
            .execute(app.db())
            .await
            .unwrap();

        let (status, _) = app
            .request(
                Method::PUT,
                "/api/v1/admin/data/quality/targets/account",
                Some(json!({"issue_sla_days": 3})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let ctx = app
            .state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");
        let (account, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            app.admin.id,
            "account",
            json!({"name": "Issue Co"}),
        )
        .await
        .expect("account");
        let issue: Uuid = sqlx::query_scalar(
            "INSERT INTO quality_issue (entity_logicalname, period, dimension, record_id, \
                                        field_logicalname, detail) \
             VALUES ('account', to_char(now(), 'YYYY-MM-DD'), 'completeness', $1, 'phone', \
                     'phone is empty') RETURNING id",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();

        let meta = app.state.entities.load().get("account").cloned().unwrap();
        attome_api::quality::routing::assign_open(app.db(), &meta)
            .await
            .expect("assign");
        let (owner, detected, due): (Option<Uuid>, DateTime<Utc>, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT owner_id, detected_at, due_at FROM quality_issue WHERE id = $1")
                .bind(issue)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(owner, Some(steward.id), "the domain steward owns it");
        assert_eq!(
            due.unwrap() - detected,
            chrono::Duration::days(3),
            "due in the target's days"
        );

        let (status, listed) = app
            .request(
                Method::GET,
                &format!(
                    "/api/v1/admin/data/quality/issues?entity=account&owner_id={}",
                    steward.id
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["id"] == issue.to_string()),
            "{listed}"
        );
        let (status, hidden) = app
            .request_as(
                &outsider.cookie,
                Method::GET,
                "/api/v1/admin/data/quality/issues?entity=account",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{hidden}");
        assert!(
            hidden["items"].as_array().unwrap().is_empty(),
            "a reader who may not read accounts sees none of their issues: {hidden}"
        );

        let path = format!("/api/v1/admin/data/quality/issues/{issue}");
        let (status, _) = app
            .request_as(
                &outsider.cookie,
                Method::PATCH,
                &path,
                Some(json!({"status": "in_progress"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "only its owner works it");
        let (status, _) = app
            .request_as(
                &steward.cookie,
                Method::PATCH,
                &path,
                Some(json!({"status": "accepted"})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "accepting needs a reason"
        );
        let (status, _) = app
            .request_as(
                &steward.cookie,
                Method::PATCH,
                &path,
                Some(json!({"status": "accepted", "accepted_reason": "legacy rows"})),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, reason): (String, Option<String>) =
            sqlx::query_as("SELECT status, accepted_reason FROM quality_issue WHERE id = $1")
                .bind(issue)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "accepted");
        assert_eq!(reason.as_deref(), Some("legacy rows"));
    });
}

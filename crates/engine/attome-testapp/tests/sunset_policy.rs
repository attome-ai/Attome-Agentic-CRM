//! E6-T9: the sunset policy. An unengaged person gets exactly one
//! re-engagement email, is sunset 14 days later if still unengaged, and is
//! back after engaging. The policy switched off is in `sunset_disabled.rs`
//! (the tests of one binary share one app and run at once).

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

const PURPOSE: &str = "newsletter";

async fn install(app: &TestApp) {
    for pack in ["crm", "marketing"] {
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

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}: {created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

/// The policy, switched on, with a re-engagement email (one per binary is
/// enough: the run reads the first live policy).
async fn policy(app: &TestApp) {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM marketing_deliverability_policy WHERE is_active IS NOT FALSE)",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    if exists {
        return;
    }
    let design = json!({ "blocks": [{ "type": "text", "text": "We miss you." }] });
    let design = create(
        app,
        "marketing_email_design",
        json!({ "name": "Come back", "subject": "Still with us?", "locale": "en",
                "design": design.to_string() }),
    )
    .await;
    create(
        app,
        "marketing_deliverability_policy",
        json!({ "name": "Default", "sunset_enabled": true, "sunset_months": 6,
                "reengagement_design_ref": design, "reengagement_purpose": PURPOSE }),
    )
    .await;
}

/// A contact created two years ago who consents to the newsletter.
async fn unengaged(app: &TestApp) -> Uuid {
    let id = create(
        app,
        "contact",
        json!({ "full_name": "Quiet Reader",
                "email": format!("{}@example.com", Uuid::now_v7().simple()) }),
    )
    .await;
    sqlx::query("UPDATE contact SET created_at = now() - interval '2 years' WHERE id = $1")
        .bind(id)
        .execute(app.db())
        .await
        .unwrap();
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    attome_compliance::consent::record(
        &mut tx,
        &attome_compliance::consent::ConsentChange {
            subject_entity: "contact".into(),
            subject_id: id,
            purpose_key: PURPOSE.into(),
            channel: "email".into(),
            grant: true,
            source: "test".into(),
            proof: json!({}),
            occurred_at: chrono::Utc::now(),
            recorded_by: Some(app.admin.id),
        },
    )
    .await
    .unwrap();
    attome_db::tx::commit(tx).await.unwrap();
    id
}

async fn state_of(app: &TestApp, id: Uuid) -> (bool, bool) {
    sqlx::query_as(
        "SELECT reengagement_sent_at IS NOT NULL, marketing_sunset_at IS NOT NULL \
           FROM contact WHERE id = $1",
    )
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn invitations(app: &TestApp, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM email_campaign_recipient WHERE subject_id = $1")
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// Runs the policy, waiting out a run another test holds.
async fn run(app: &TestApp) {
    for _ in 0..100 {
        if attome_marketing::sunset::run(&app.state).await.unwrap().ran {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the sunset run never got its lock");
}

// feature: E6
#[test]
fn reengagement_sent_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        policy(&app).await;
        let person = unengaged(&app).await;
        run(&app).await;
        run(&app).await;
        assert_eq!(state_of(&app, person).await, (true, false));
        assert_eq!(invitations(&app, person).await, 1, "exactly one email");
    });
}

// feature: E6
#[test]
fn excluded_after_no_engagement() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        policy(&app).await;
        let person = unengaged(&app).await;
        run(&app).await;
        sqlx::query(
            "UPDATE contact SET reengagement_sent_at = now() - interval '15 days' WHERE id = $1",
        )
        .bind(person)
        .execute(app.db())
        .await
        .unwrap();
        run(&app).await;
        assert_eq!(state_of(&app, person).await, (true, true), "sunset");
        assert_eq!(invitations(&app, person).await, 1, "no second invitation");
    });
}

// feature: E6
#[test]
fn returns_on_click() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        policy(&app).await;
        let person = unengaged(&app).await;
        sqlx::query(
            "UPDATE contact SET reengagement_sent_at = now() - interval '20 days', \
                    marketing_sunset_at = now() - interval '5 days' WHERE id = $1",
        )
        .bind(person)
        .execute(app.db())
        .await
        .unwrap();
        // What an open or click of a tracked email does for the person.
        let changed = attome_core::engagement::touch(&app.state, "contact", &[person])
            .await
            .unwrap();
        assert_eq!(changed, 1);
        assert_eq!(state_of(&app, person).await, (false, false), "back");
        let engaged: bool = sqlx::query_scalar(
            "SELECT last_marketing_engagement_at > now() - interval '1 minute' \
               FROM contact WHERE id = $1",
        )
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(engaged);
        run(&app).await;
        assert_eq!(
            state_of(&app, person).await,
            (false, false),
            "engaged: left alone"
        );
    });
}

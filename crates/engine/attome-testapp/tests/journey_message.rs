//! E8-T6: the journey email step. One send per person, a replayed step
//! sends nothing more, and a test enrolment goes to the journey's test
//! address.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::workflow_step::{StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_marketing::journey::message_step::SendEmail;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const PURPOSE: &str = "journey-news";

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

async fn design(app: &TestApp) -> Uuid {
    let design = json!({ "blocks": [{ "type": "text", "text": "Welcome aboard." }] });
    create(
        app,
        "marketing_email_design",
        json!({ "name": "Welcome", "subject": "Welcome", "locale": "en",
                "design": design.to_string() }),
    )
    .await
}

/// A contact who consents to email for [`PURPOSE`].
async fn person(app: &TestApp) -> Uuid {
    let id = create(
        app,
        "contact",
        json!({ "full_name": "Journey Reader",
                "email": format!("{}@example.com", Uuid::now_v7().simple()) }),
    )
    .await;
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

fn invocation(instance: Uuid, person: Uuid, design: Uuid, input: Value) -> StepInvocation {
    StepInvocation {
        instance_id: instance,
        node_id: "welcome".into(),
        correlation_entity_id: Some(person),
        config: json!({ "design_id": design, "purpose": PURPOSE, "on_blocked": "skip" }),
        input,
        simulate: false,
        run_as_user: None,
        idempotency_key: Some(format!("{instance}:welcome")),
    }
}

async fn recipients(app: &TestApp, person: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM email_campaign_recipient WHERE subject_id = $1")
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: E8
#[test]
fn email_step_queues_one_send_per_person() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let design = design(&app).await;
        let person = person(&app).await;
        let outcome = SendEmail
            .run(
                &app.state,
                invocation(
                    Uuid::now_v7(),
                    person,
                    design,
                    json!({ "person_entity": "contact" }),
                ),
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, StepOutcome::Done(ref out) if out.get("send_id").is_some()),
            "{outcome:?}"
        );
        assert_eq!(recipients(&app, person).await, 1);
    });
}

// feature: E8
#[test]
fn replayed_step_does_not_double_send() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let design = design(&app).await;
        let person = person(&app).await;
        let instance = Uuid::now_v7();
        for _ in 0..2 {
            SendEmail
                .run(
                    &app.state,
                    invocation(
                        instance,
                        person,
                        design,
                        json!({ "person_entity": "contact" }),
                    ),
                )
                .await
                .unwrap();
        }
        assert_eq!(recipients(&app, person).await, 1, "one send for one step");
    });
}

// feature: E8
#[test]
fn test_mode_redirects_to_test_address() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let design = design(&app).await;
        let person = person(&app).await;
        let journey = create(
            &app,
            "marketing_journey",
            json!({ "workflow_definition_logicalname": format!("journey_{}", Uuid::now_v7().simple()),
                    "test_addresses": "qa@example.com, other@example.com" }),
        )
        .await;
        let outcome = SendEmail
            .run(
                &app.state,
                invocation(
                    Uuid::now_v7(),
                    person,
                    design,
                    json!({ "person_entity": "contact", "journey_id": journey, "is_test": true }),
                ),
            )
            .await
            .unwrap();
        match outcome {
            StepOutcome::Done(out) => assert_eq!(out["sent_to"], "qa@example.com"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            recipients(&app, person).await,
            0,
            "nothing goes to the person on a test run"
        );
    });
}

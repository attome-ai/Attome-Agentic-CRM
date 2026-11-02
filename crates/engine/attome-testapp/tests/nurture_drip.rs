//! E9-T3: the nurture drip. A person in a track gets its emails in order,
//! one per cadence, never one they have already seen, never one twice; and
//! when their state finishes, the journey run waiting on the step goes on.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;
use std::sync::Arc;

use attome_core::EngineState;
use attome_core::workflow_step::{StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_marketing::nurture_run::{self, NurtureRun};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const PURPOSE: &str = "nurture-news";

/// The tick takes every due state in the database, and the tests of this
/// binary share one: they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

async fn design(app: &TestApp, name: &str) -> Uuid {
    let design = json!({ "blocks": [{ "type": "text", "text": format!("{name}.") }] });
    create(
        app,
        "marketing_email_design",
        json!({ "name": name, "subject": name, "locale": "en",
                "design": design.to_string() }),
    )
    .await
}

/// A contact who consents to email for [`PURPOSE`].
async fn person(app: &TestApp) -> Uuid {
    let id = create(
        app,
        "contact",
        json!({ "full_name": "Nurture Reader",
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

/// A journey definition, for a programme's `journey_ref`.
async fn definition(app: &TestApp) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO workflow_definition (logicalname, name, owner_layer, kind) \
         VALUES ($1, $1, 'project', 'journey') RETURNING id",
    )
    .bind(format!("nurture-{}", Uuid::now_v7().simple()))
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// A journey definition with one published version running `graph`:
/// (definition, version).
async fn publish(app: &TestApp, graph: Value) -> (Uuid, Uuid) {
    let definition = definition(app).await;
    let parsed = attome_workflow::graph::Graph::parse(&graph).unwrap();
    let hash = attome_workflow::graph::validate(&parsed).unwrap();
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition_version \
            (definition_id, version_number, graph, status, node_schema_hash) \
         VALUES ($1, 1, $2, 'published', $3) RETURNING id",
    )
    .bind(definition)
    .bind(&graph)
    .bind(&hash)
    .fetch_one(app.db())
    .await
    .unwrap();
    (definition, version)
}

/// A programme on `definition` (one day apart) with one track holding
/// `designs` in order: (programme, track).
async fn programme(app: &TestApp, definition: Uuid, designs: &[Uuid]) -> (Uuid, Uuid) {
    let program = create(
        app,
        "marketing_nurture_program",
        json!({ "name": "Welcome drip", "journey_ref": definition, "cadence_days": 1,
                "status": "active" }),
    )
    .await;
    let track = create(
        app,
        "marketing_nurture_track",
        json!({ "name": "Everyone", "program_ref": program, "lifecycle_stage": "any",
                "language": "any", "position": 1 }),
    )
    .await;
    for (i, design) in designs.iter().enumerate() {
        create(
            app,
            "marketing_nurture_content",
            json!({ "track_ref": track, "content_kind": "email",
                    "content_ref": design.to_string(), "position": i + 1 }),
        )
        .await;
    }
    (program, track)
}

fn invocation(instance: Uuid, person: Uuid, program: Uuid) -> StepInvocation {
    StepInvocation {
        instance_id: instance,
        node_id: "nurture".into(),
        correlation_entity_id: Some(person),
        config: json!({ "purpose": PURPOSE, "program_id": program }),
        input: json!({ "person_entity": "contact" }),
        simulate: false,
        run_as_user: None,
        idempotency_key: Some(format!("{instance}:nurture")),
    }
}

/// Puts the person in the programme through the step.
async fn enter(app: &TestApp, person: Uuid, program: Uuid) -> Uuid {
    let instance = Uuid::now_v7();
    let outcome = NurtureRun
        .run(&app.state, invocation(instance, person, program))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        StepOutcome::Waiting {
            resume_at: None,
            wait_event: Some(nurture_run::done_event(instance)),
        }
    );
    instance
}

/// The designs sent to the person, oldest first.
async fn sent(app: &TestApp, person: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT s.design_id FROM email_campaign_recipient r \
           JOIN email_campaign_send s ON s.id = r.send_id \
          WHERE r.subject_id = $1 ORDER BY s.created_at, s.id",
    )
    .bind(person)
    .fetch_all(app.db())
    .await
    .unwrap()
}

/// Makes the person's state due now, as the cadence passing would.
async fn due_now(app: &TestApp, person: Uuid) {
    sqlx::query(
        "UPDATE marketing_nurture_state SET next_due_at = now() - interval '1 second' \
          WHERE person_id = $1",
    )
    .bind(person)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: E9
#[test]
fn sends_next_unseen_content() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let first = design(&app, "First").await;
        let second = design(&app, "Second").await;
        let third = design(&app, "Third").await;
        let definition = definition(&app).await;
        let (program, _) = programme(&app, definition, &[first, second, third]).await;
        let person = person(&app).await;
        enter(&app, person, program).await;

        nurture_run::tick(&app.state).await.unwrap();
        assert_eq!(sent(&app, person).await, vec![first]);
        let next_due: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT next_due_at FROM marketing_nurture_state WHERE person_id = $1",
        )
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(
            next_due > chrono::Utc::now() + chrono::Duration::hours(23),
            "the next one waits a cadence: {next_due}"
        );

        nurture_run::tick(&app.state).await.unwrap();
        assert_eq!(sent(&app, person).await, vec![first], "not due yet");

        due_now(&app, person).await;
        nurture_run::tick(&app.state).await.unwrap();
        assert_eq!(sent(&app, person).await, vec![first, second]);
    });
}

// feature: E9
#[test]
fn skips_content_already_seen() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let first = design(&app, "First").await;
        let second = design(&app, "Second").await;
        let definition = definition(&app).await;
        let (program, _) = programme(&app, definition, &[first, second]).await;
        let person = person(&app).await;

        // The person opened the first email from another send.
        let other: Uuid = sqlx::query_scalar(
            "INSERT INTO email_campaign_send \
                (list_id, subject, html_body, text_body, purpose_key, design_id) \
             VALUES ($1, 'First', '<p>First.</p>', 'First.', $2, $3) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(PURPOSE)
        .bind(first)
        .fetch_one(app.db())
        .await
        .unwrap();
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO email_campaign_recipient \
                (send_id, subject_entity, subject_id, email, unsubscribe_token, status) \
             VALUES ($1, 'contact', $2, 'reader@example.com', $3, 'sent')",
        )
        .bind(other)
        .bind(person)
        .bind(&token)
        .execute(app.db())
        .await
        .unwrap();
        nurture_run::seen_from_token(app.db(), &token)
            .await
            .unwrap();

        enter(&app, person, program).await;
        nurture_run::tick(&app.state).await.unwrap();
        assert_eq!(
            sent(&app, person).await,
            vec![first, second],
            "the other send, then the second email: the first is not sent again"
        );
    });
}

// feature: E9
#[test]
fn no_double_send_on_retry() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let first = design(&app, "First").await;
        let second = design(&app, "Second").await;
        let definition = definition(&app).await;
        let (program, _) = programme(&app, definition, &[first, second]).await;
        let person = person(&app).await;
        let instance = enter(&app, person, program).await;
        // The step replayed finds its own state and waits again.
        let replay = NurtureRun
            .run(&app.state, invocation(instance, person, program))
            .await
            .unwrap();
        assert!(matches!(replay, StepOutcome::Waiting { .. }), "{replay:?}");

        // Two ticks at once claim the state once.
        let (a, b) = tokio::join!(nurture_run::tick(&app.state), nurture_run::tick(&app.state));
        a.unwrap();
        b.unwrap();
        assert_eq!(sent(&app, person).await, vec![first]);

        // A retried pass after the first send moves on, never back.
        due_now(&app, person).await;
        nurture_run::tick(&app.state).await.unwrap();
        due_now(&app, person).await;
        nurture_run::tick(&app.state).await.unwrap();
        assert_eq!(
            sent(&app, person).await,
            vec![first, second],
            "each email once, and nothing left to send"
        );

        // A second run for a person already in the programme does not wait.
        let other = NurtureRun
            .run(&app.state, invocation(Uuid::now_v7(), person, program))
            .await
            .unwrap();
        assert!(
            matches!(other, StepOutcome::Done(ref out) if out["already_nurtured"] == json!(true)),
            "{other:?}"
        );
    });
}

/// `state` with the marketing steps registered (TestApp registers none).
fn with_nurture_step(app: &TestApp) -> EngineState {
    let mut state = app.state.clone();
    let step: Arc<dyn WorkflowStepHandler> = Arc::new(NurtureRun);
    state.workflow_step_handlers = Arc::new(HashMap::from([(nurture_run::KEY, step)]));
    state
}

async fn run_to_checkpoint(state: &EngineState, instance: Uuid) -> String {
    for _ in 0..50 {
        attome_workflow::scheduler::execute_instance(state, instance)
            .await
            .unwrap();
        let status: String =
            sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
                .bind(instance)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        if status != "running" {
            return status;
        }
    }
    panic!("instance {instance} did not reach a checkpoint");
}

// feature: E9
#[test]
fn done_event_resumes_instance() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let state = with_nurture_step(&app);
        let only = design(&app, "Only").await;
        let (definition, version) = publish(
            &app,
            json!({
                "nodes": [
                    {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
                    {"id": "n", "type": "module_step", "config": {
                        "handler": nurture_run::KEY, "config": { "purpose": PURPOSE }
                    }}
                ],
                "edges": [
                    {"from_node": "t", "from_port": "out", "to_node": "n", "to_port": "input"}
                ]
            }),
        )
        .await;
        // The step finds the programme by its journey.
        let (program, _) = programme(&app, definition, &[only]).await;
        let person = person(&app).await;
        let instance = attome_workflow::instance_admin::start_instance_internal(
            &state,
            version,
            None,
            Some(app.admin.id),
            Some(person),
            json!({}),
        )
        .await
        .unwrap();
        assert_eq!(run_to_checkpoint(&state, instance).await, "waiting");
        let entered: Option<Uuid> = sqlx::query_scalar(
            "SELECT instance_id FROM marketing_nurture_state \
              WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(entered, Some(instance));
        assert!(
            nurture_run::finished(app.db(), 500)
                .await
                .unwrap()
                .is_empty()
        );

        // The person is handed to sales: the state leaves `active`, and the
        // tick job tells the run.
        sqlx::query(
            "UPDATE marketing_nurture_state SET status = 'handed_off' \
              WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .execute(app.db())
        .await
        .unwrap();
        let finished = nurture_run::finished(app.db(), 500).await.unwrap();
        assert_eq!(
            finished,
            vec![(program, person, instance, "handed_off".to_owned())]
        );
        let settled = attome_workflow::scheduler::signal_event(
            &state,
            instance,
            &nurture_run::done_event(instance),
            json!({ "nurture": "handed_off" }),
        )
        .await
        .unwrap();
        assert!(settled);
        nurture_run::mark_signalled(app.db(), program, person, instance)
            .await
            .unwrap();
        assert!(
            nurture_run::finished(app.db(), 500)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(run_to_checkpoint(&state, instance).await, "completed");
    });
}

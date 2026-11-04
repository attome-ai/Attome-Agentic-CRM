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
use attome_marketing::nurture_handoff;
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
/// The workflow engine's execution claim opens a session-pinned runtime
/// connection, which outside `APP_ENV=debug` needs `database.runtime`; the
/// test database has only its bootstrap login, as in `attome-workflow`'s own
/// suite (`tests/execution.rs`).
fn debug_app_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: called first in the test, before its runtime starts; nextest
    // runs each test in its own process, and no test here reads `APP_ENV`
    // concurrently with this write.
    #[allow(
        unsafe_code,
        reason = "the test sets APP_ENV before any thread reads it"
    )]
    ONCE.call_once(|| unsafe { std::env::set_var("APP_ENV", "debug") });
}

#[test]
fn done_event_resumes_instance() {
    debug_app_env();
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

/// E9-T5: a programme that hands people to sales at `threshold` on `model`.
async fn handoff_programme(app: &TestApp, model: &str, threshold: f64) -> Uuid {
    let definition = definition(app).await;
    create(
        app,
        "marketing_nurture_program",
        json!({ "name": "Hand-off drip", "journey_ref": definition, "status": "active",
                "handoff_score_model": model, "handoff_threshold": threshold }),
    )
    .await
}

/// The person's score on `model` (the platform's `points_score`, or a
/// stand-in with its columns where this test app does not provision it).
async fn score(app: &TestApp, model: &str, person: Uuid, value: f64) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS points_score (id uuid PRIMARY KEY DEFAULT uuidv7(), \
            model_id text, record_id text, entity_name text, score numeric, \
            reasons text, computed_at timestamptz, is_active boolean DEFAULT true)",
    )
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query("DELETE FROM points_score WHERE model_id = $1 AND record_id = $2")
        .bind(model)
        .bind(person.to_string())
        .execute(app.db())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO points_score (model_id, record_id, entity_name, score, reasons, computed_at) \
         VALUES ($1, $2, 'contact', $3, '[]', now())",
    )
    .bind(model)
    .bind(person.to_string())
    .bind(value)
    .execute(app.db())
    .await
    .unwrap();
}

async fn handoffs(app: &TestApp, program: Uuid, person: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_handoff WHERE program_id = $1 AND person_id = $2",
    )
    .bind(program)
    .bind(person)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: E9
#[test]
fn handoff_once_per_crossing() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let model = Uuid::now_v7().to_string();
        let program = handoff_programme(&app, &model, 50.0).await;
        let person = person(&app).await;
        enter(&app, person, program).await;

        score(&app, &model, person, 72.0).await;
        let made = nurture_handoff::detect(&app.state).await.unwrap();
        assert_eq!(made.iter().filter(|h| h.person == person).count(), 1);
        assert_eq!(handoffs(&app, program, person).await, 1);
        let status: String = sqlx::query_scalar(
            "SELECT status FROM marketing_nurture_state WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            status, "handed_off",
            "the journey run waiting on it goes on"
        );
        let summary: serde_json::Value = sqlx::query_scalar(
            "SELECT summary FROM marketing_handoff WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(summary["threshold"], json!(50.0));

        // The same crossing, read again, hands nobody off twice.
        nurture_handoff::detect(&app.state).await.unwrap();
        assert_eq!(handoffs(&app, program, person).await, 1);
    });
}

// feature: E9
#[test]
fn below_threshold_no_handoff() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let model = Uuid::now_v7().to_string();
        let program = handoff_programme(&app, &model, 50.0).await;
        let person = person(&app).await;
        enter(&app, person, program).await;
        score(&app, &model, person, 40.0).await;
        nurture_handoff::detect(&app.state).await.unwrap();
        assert_eq!(handoffs(&app, program, person).await, 0);
    });
}

// feature: E9
#[test]
fn open_sequence_pauses_sends() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let first = design(&app, "First").await;
        let journey = definition(&app).await;
        let (program, _) = programme(&app, journey, &[first]).await;
        sqlx::query("UPDATE marketing_nurture_program SET pause_enabled = true WHERE id = $1")
            .bind(program)
            .execute(app.db())
            .await
            .unwrap();
        let person = person(&app).await;
        enter(&app, person, program).await;
        let sequence = definition(&app).await;
        sqlx::query(
            "INSERT INTO workflow_sequence_enrolment \
                (definition_id, definition_version_id, contact_id, status) \
             VALUES ($1, uuidv7(), $2, 'active')",
        )
        .bind(sequence)
        .bind(person)
        .execute(app.db())
        .await
        .unwrap();

        nurture_run::tick(&app.state).await.unwrap();
        assert!(sent(&app, person).await.is_empty(), "sales is working them");
        let paused: Option<String> = sqlx::query_scalar(
            "SELECT paused_reason FROM marketing_nurture_state WHERE person_id = $1",
        )
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(paused.as_deref(), Some("sales_working"));
    });
}

// feature: E9
#[test]
fn recycled_lead_wakes_on_date_and_handoff_is_returned() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let model = Uuid::now_v7().to_string();
        let program = handoff_programme(&app, &model, 50.0).await;
        sqlx::query("UPDATE marketing_nurture_program SET recycling_enabled = true WHERE id = $1")
            .bind(program)
            .execute(app.db())
            .await
            .unwrap();
        let person = person(&app).await;
        enter(&app, person, program).await;
        score(&app, &model, person, 90.0).await;
        let handoff = nurture_handoff::detect(&app.state)
            .await
            .unwrap()
            .into_iter()
            .find(|h| h.person == person)
            .expect("handed off");

        let wake = chrono::Utc::now() + chrono::Duration::days(3);
        let recycled = nurture_handoff::recycle(
            &app.state,
            handoff.id,
            "not ready",
            Some(wake),
            app.admin.id,
        )
        .await
        .unwrap();
        assert!(recycled);
        let (status, due): (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT status, next_due_at FROM marketing_nurture_state \
              WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status, "active");
        assert!((due - wake).num_seconds().abs() < 2, "{due} vs {wake}");
        let (handoff_status, reason): (String, Option<String>) =
            sqlx::query_as("SELECT status, return_reason FROM marketing_handoff WHERE id = $1")
                .bind(handoff.id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(handoff_status, "returned");
        assert_eq!(reason.as_deref(), Some("not ready"));
        assert!(
            nurture_handoff::recycle(&app.state, handoff.id, "again", None, app.admin.id)
                .await
                .is_err(),
            "a hand-off is returned once"
        );
    });
}

/// E9-T8: a hand-off assigned to `assignee`, as the nurture tick makes one.
async fn assigned_handoff(app: &TestApp, assignee: Uuid) -> (Uuid, Uuid, Uuid) {
    let model = Uuid::now_v7().to_string();
    let program = handoff_programme(app, &model, 50.0).await;
    sqlx::query("UPDATE marketing_nurture_program SET recycling_enabled = true WHERE id = $1")
        .bind(program)
        .execute(app.db())
        .await
        .unwrap();
    let person = person(app).await;
    enter(app, person, program).await;
    score(app, &model, person, 90.0).await;
    let handoff = nurture_handoff::detect(&app.state)
        .await
        .unwrap()
        .into_iter()
        .find(|h| h.person == person)
        .expect("handed off");
    sqlx::query("UPDATE marketing_handoff SET assigned_to = $2 WHERE id = $1")
        .bind(handoff.id)
        .bind(assignee)
        .execute(app.db())
        .await
        .unwrap();
    (handoff.id, program, person)
}

// feature: E9
#[test]
fn only_assignee_can_accept() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let assignee = attome_testapp::seed_user(app.db(), "assignee").await;
        let stranger = attome_testapp::seed_user(app.db(), "stranger").await;
        let (handoff, _, _) = assigned_handoff(&app, assignee.id).await;
        let path = format!("/api/v1/marketing/handoffs/{handoff}/accept");
        let (status, _) = app
            .request_as(&stranger.cookie, Method::POST, &path, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, body) = app
            .request_as(&assignee.cookie, Method::POST, &path, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], json!("accepted"));
        let (status, _) = app
            .request_as(&assignee.cookie, Method::POST, &path, None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "decided once");
    });
}

// feature: E9
#[test]
fn return_recycles_lead() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let assignee = attome_testapp::seed_user(app.db(), "assignee").await;
        let (handoff, program, person) = assigned_handoff(&app, assignee.id).await;
        let (status, body) = app
            .request_as(
                &assignee.cookie,
                Method::POST,
                &format!("/api/v1/marketing/handoffs/{handoff}/return"),
                Some(json!({ "reason": "no budget this year" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["recycled"], json!(true));
        let state: String = sqlx::query_scalar(
            "SELECT status FROM marketing_nurture_state WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(state, "active");
    });
}

// feature: E9
#[test]
fn history_forbidden_without_read() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let stranger = attome_testapp::seed_user(app.db(), "stranger").await;
        let person = person(&app).await;
        let path = format!("/api/v1/marketing/people/{person}/nurture-history");
        let (status, _) = app
            .request_as(&stranger.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a person they may not read");
        let (status, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["person_id"], json!(person));
    });
}

// feature: E9
#[test]
fn contact_sales_form_hands_off_now() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let _serial = SERIAL.lock().await;
        install(&app).await;
        let definition = definition(&app).await;
        let (program, _) = programme(&app, definition, &[]).await;
        let person = person(&app).await;
        enter(&app, person, program).await;
        let form = create(
            &app,
            "marketing_form",
            json!({ "name": "Talk to sales", "target_entity": "contact", "field_map": "{}",
                    "is_published": true, "intent": "contact_sales" }),
        )
        .await;
        let submission = create(
            &app,
            "marketing_form_submission",
            json!({ "form_ref": form, "person_entity": "contact", "person_id": person.to_string() }),
        )
        .await;

        let made = nurture_handoff::form_requests(&app.state).await.unwrap();
        assert_eq!(made.iter().filter(|h| h.person == person).count(), 1);
        let crossing: Uuid = sqlx::query_scalar(
            "SELECT crossing_event_id FROM marketing_handoff WHERE program_id = $1 AND person_id = $2",
        )
        .bind(program)
        .bind(person)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(crossing, submission, "the submission is the crossing");
        assert!(
            nurture_handoff::form_requests(&app.state)
                .await
                .unwrap()
                .iter()
                .all(|h| h.person != person),
            "a submission hands off once"
        );
    });
}

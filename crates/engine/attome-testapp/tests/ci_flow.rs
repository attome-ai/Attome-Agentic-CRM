//! D22-T14: a call from transcript to trend. An Arabic and English
//! transcript is analysed (talk patterns, one tracker hit), a stand-in model
//! answers the extraction with a next step and a scorecard answer, the next
//! step becomes a task, the rep's manager confirms the answer, and the
//! nightly job writes the day's aggregate.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_callintel::analysis::coach::{confirm_answer, create_task_from_finding};
use attome_callintel::analysis::job::{JOB, on_transcript_final, run};
use attome_core::EngineState;
use attome_testapp::{TestApp, seed_user};
use axum::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

const MODEL: &str = "stand-in-callintel";

/// A loopback model server that answers every request with `reply`.
async fn stand_in(reply: Value) -> String {
    let app = axum::Router::new().fallback(move || {
        let reply = reply.to_string();
        async move {
            axum::Json(json!({
                "choices": [{ "message": { "content": reply }, "finish_reason": "stop" }],
                "usage": { "prompt_tokens": 40, "completion_tokens": 12 }
            }))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{port}/v1")
}

/// A manager's position above a rep's; returns (manager, rep).
async fn team(app: &TestApp) -> (Uuid, Uuid) {
    let manager = seed_user(app.db(), "ci-flow-manager").await.id;
    let rep = seed_user(app.db(), "ci-flow-rep").await.id;
    let top = Uuid::now_v7();
    let below = Uuid::now_v7();
    for (id, name, parent) in [(top, "Manager", None), (below, "Rep", Some(top))] {
        sqlx::query("INSERT INTO position (id, name, parent_position_ref) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(format!("{name} {}", Uuid::now_v7().simple()))
            .bind(parent)
            .execute(app.db())
            .await
            .unwrap();
    }
    for (user, position) in [(manager, top), (rep, below)] {
        sqlx::query(
            "INSERT INTO user_account_mm_position (id, user_ref, position_ref) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(position)
        .execute(app.db())
        .await
        .unwrap();
    }
    (manager, rep)
}

// feature: D22
#[test]
fn call_analysis_full_flow() {
    attome_testkit::run_shared(async {
        let reply = json!({
            "questions": [{ "text": "What is your budget?", "start_ms": 0, "speaker": "staff" }],
            "objections": [{ "text": "The price is high", "start_ms": 4000, "speaker": "customer" }],
            "next_steps": [{ "text": "Send the proposal tomorrow", "start_ms": 9000, "speaker": "staff" }],
            "price_mentions": [],
            "scorecard": [{ "question_key": "asked_budget", "value": "yes", "start_ms": 0 }]
        });
        let base_url = stand_in(reply).await;
        let Some(app) = TestApp::start_with(|config| {
            config.inference.generation.base_url = base_url;
            config.inference.generation.model = MODEL.to_owned();
            config.inference.generation.request_timeout_secs = 10;
        })
        .await
        else {
            return;
        };
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/callintel.enabled",
                Some(json!({ "scope": "deployment", "value": true })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        // The app registers the job type; this binary stands in for it.
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(JOB, 3),
            |_state: EngineState, _job: attome_jobs::RegisteredJob| async move {
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        );
        let (manager, rep) = team(&app).await;
        sqlx::query(
            "INSERT INTO call_tracker (id, name, exact_terms, enabled, version, is_active, \
                 row_version) \
             VALUES ($1, 'Pricing', 'السعر', true, 1, true, 0)",
        )
        .bind(Uuid::now_v7())
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO call_scorecard (id, name, questions, version, is_active, row_version) \
             VALUES ($1, 'Discovery', 'asked_budget: Did we ask about budget?', 1, true, 0)",
        )
        .bind(Uuid::now_v7())
        .execute(app.db())
        .await
        .unwrap();

        // The call, its recording and its transcript (N22's shape).
        let activity: Uuid = sqlx::query_scalar(
            "INSERT INTO activity (id, owner_ref, created_by, is_active, row_version) \
             VALUES ($1, $2, $2, true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(rep)
        .fetch_one(app.db())
        .await
        .unwrap();
        let file_key = format!("recordings/{}.mp3", Uuid::now_v7().simple());
        let document: Uuid = sqlx::query_scalar(
            "INSERT INTO attome_document (id, name, entity_name, record_id, file, is_active, \
                 row_version) \
             VALUES ($1, 'call.mp3', 'activity', $2, $3, true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(activity.to_string())
        .bind(&file_key)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO recording_transcript (file_key, content_text, segments, model) \
             VALUES ($1, 'call', $2, 'test')",
        )
        .bind(&file_key)
        .bind(json!([
            {"start": 0.0, "end": 4.0, "text": "Hello, what is your budget?", "speaker": "staff"},
            {"start": 4.0, "end": 9.0, "text": "السعر مرتفع جدا بالنسبة لنا", "speaker": "customer"},
            {"start": 9.0, "end": 14.0, "text": "I will send the proposal tomorrow.", "speaker": "staff"},
        ]))
        .execute(app.db())
        .await
        .unwrap();

        // Analysis: talk patterns and the tracker hit, then the extraction.
        let analysis = on_transcript_final(&app.state, document)
            .await
            .unwrap()
            .expect("queued");
        assert_eq!(run(&app.state, analysis).await.unwrap(), "done");
        let share: Option<f64> =
            sqlx::query_scalar("SELECT staff_talk_share::float8 FROM call_analysis WHERE id = $1")
                .bind(analysis)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(share.is_some_and(|s| s > 0.0 && s < 1.0), "{share:?}");
        let kinds: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT kind::text, id FROM call_finding WHERE analysis_ref = $1 ORDER BY kind",
        )
        .bind(analysis)
        .fetch_all(app.db())
        .await
        .unwrap();
        let count = |kind: &str| kinds.iter().filter(|(k, _)| k == kind).count();
        assert_eq!(
            count("tracker_hit"),
            1,
            "the Arabic term was heard once: {kinds:?}"
        );
        assert_eq!(count("next_step"), 1, "{kinds:?}");
        assert_eq!(count("objection"), 1, "{kinds:?}");

        // The next step becomes one task.
        let next_step = kinds
            .iter()
            .find(|(k, _)| k == "next_step")
            .map(|(_, id)| *id)
            .unwrap();
        let admin = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let task = create_task_from_finding(&app.state, &admin, next_step)
            .await
            .unwrap();
        let subject: Option<String> =
            sqlx::query_scalar("SELECT subject FROM activity WHERE id = $1")
                .bind(task)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(subject.as_deref(), Some("Send the proposal tomorrow"));

        // The proposed scorecard answer, confirmed by the rep's manager.
        let (answer, version): (Uuid, i64) = sqlx::query_as(
            "SELECT id, row_version FROM call_scorecard_answer \
              WHERE analysis_ref = $1 AND question_key = 'asked_budget'",
        )
        .bind(analysis)
        .fetch_one(app.db())
        .await
        .unwrap();
        let boss = attome_security::resolve_uncached(app.db(), manager)
            .await
            .unwrap();
        confirm_answer(&app.state, &boss, answer, "yes", version)
            .await
            .unwrap();
        let confirmed: (Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT confirmed_value::text, confirmed_by FROM call_scorecard_answer WHERE id = $1",
        )
        .bind(answer)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(confirmed, (Some("yes".to_owned()), Some(manager)));

        // The nightly job's trend rows for the day.
        let today = chrono::Utc::now().date_naive();
        attome_callintel::analysis::trends::aggregate_day(&app.state, today)
            .await
            .unwrap();
        let calls: Option<f64> = sqlx::query_scalar(
            "SELECT sum(value)::float8 FROM call_daily_aggregate \
              WHERE day::date = $1 AND metric = 'calls'",
        )
        .bind(today)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(calls.is_some_and(|c| c >= 1.0), "{calls:?}");
    });
}

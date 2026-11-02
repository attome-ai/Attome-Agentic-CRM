//! D22-T5: a call's finished transcript is analysed once per transcript
//! version, over its redacted copy, and a call whose speakers are not
//! labelled staff and customer is skipped.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_callintel::analysis::job::{JOB, on_transcript_final, run};
use attome_core::EngineState;
use attome_testapp::TestApp;
use axum::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

async fn analysis_on(app: &TestApp) {
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
}

/// A call activity with a recording document whose transcript has
/// `segments`; returns the document.
async fn call_with_transcript(app: &TestApp, segments: Value) -> Uuid {
    let activity: Uuid = sqlx::query_scalar(
        "INSERT INTO activity (id, is_active, row_version) VALUES ($1, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
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
    .bind(&segments)
    .execute(app.db())
    .await
    .unwrap();
    document
}

// feature: D22
#[test]
fn analysis_runs_once_per_transcript_version() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        analysis_on(&app).await;
        sqlx::query(
            "INSERT INTO call_tracker (id, name, exact_terms, enabled, version, is_active, \
                 row_version) \
             VALUES ($1, 'Pricing', 'price', true, 1, true, 0)",
        )
        .bind(Uuid::now_v7())
        .execute(app.db())
        .await
        .unwrap();
        let document = call_with_transcript(
            &app,
            json!([
                {"start": 0.0, "end": 4.0, "text": "Hello, what is your budget? Email me at ali@example.com", "speaker": "staff"},
                {"start": 4.0, "end": 9.0, "text": "The price matters most to us.", "speaker": "customer"},
            ]),
        )
        .await;

        let first = on_transcript_final(&app.state, document).await.unwrap();
        let again = on_transcript_final(&app.state, document).await.unwrap();
        let analysis = first.expect("queued once");
        assert!(
            again.is_none(),
            "the same transcript version is not analysed twice"
        );

        let copy: String = sqlx::query_scalar(
            "SELECT segments::text FROM call_transcript_redacted WHERE analysis_id = $1",
        )
        .bind(analysis)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(
            !copy.contains("ali@example.com"),
            "the copy is redacted: {copy}"
        );

        assert_eq!(run(&app.state, analysis).await.unwrap(), "done");
        let (status, share): (String, Option<f64>) = sqlx::query_as(
            "SELECT status, staff_talk_share::float8 FROM call_analysis WHERE id = $1",
        )
        .bind(analysis)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status, "done");
        assert!(share.is_some_and(|s| s > 0.0 && s < 1.0), "{share:?}");
        let hits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM call_finding WHERE analysis_ref = $1 AND kind = 'tracker_hit'",
        )
        .bind(analysis)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(hits, 1, "the pricing tracker's term was heard once");
        // A rerun replaces the hits rather than adding to them.
        assert_eq!(run(&app.state, analysis).await.unwrap(), "done");
        let again: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM call_finding WHERE analysis_ref = $1 AND kind = 'tracker_hit'",
        )
        .bind(analysis)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(again, 1);
    });
}

// feature: D22
#[test]
fn unlabelled_speakers_are_skipped() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        analysis_on(&app).await;
        let document = call_with_transcript(
            &app,
            json!([
                {"start": 0.0, "end": 2.0, "text": "Hello", "speaker": "SPEAKER_00"},
                {"start": 2.0, "end": 3.0, "text": "Hi"},
            ]),
        )
        .await;
        let analysis = on_transcript_final(&app.state, document)
            .await
            .unwrap()
            .expect("queued");
        assert_eq!(run(&app.state, analysis).await.unwrap(), "skipped");
    });
}

// feature: D22
#[test]
fn nightly_aggregate_is_rerunnable() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        analysis_on(&app).await;
        let document = call_with_transcript(
            &app,
            json!([
                {"start": 0.0, "end": 3.0, "text": "Any questions?", "speaker": "staff"},
                {"start": 3.0, "end": 6.0, "text": "What does it cost?", "speaker": "customer"},
            ]),
        )
        .await;
        let analysis = on_transcript_final(&app.state, document)
            .await
            .unwrap()
            .expect("queued");
        assert_eq!(run(&app.state, analysis).await.unwrap(), "done");

        let today = chrono::Utc::now().date_naive();
        let first = attome_callintel::analysis::trends::aggregate_day(&app.state, today)
            .await
            .unwrap();
        let rows = |app: &TestApp| {
            let db = app.db().clone();
            async move {
                sqlx::query_as::<_, (Option<String>, String, f64)>(
                    "SELECT team_ref, metric, value::float8 FROM call_daily_aggregate \
                      WHERE day::date = $1 ORDER BY metric, team_ref",
                )
                .bind(today)
                .fetch_all(&db)
                .await
                .unwrap()
            }
        };
        let before = rows(&app).await;
        let second = attome_callintel::analysis::trends::aggregate_day(&app.state, today)
            .await
            .unwrap();
        let after = rows(&app).await;
        assert_eq!(first, second);
        assert_eq!(before, after, "a rerun writes the same rows");
        assert!(
            before
                .iter()
                .any(|(_, metric, value)| metric == "calls" && *value >= 1.0),
            "{before:?}"
        );
        assert!(
            before
                .iter()
                .any(|(_, metric, _)| metric == "question_rate")
        );
    });
}

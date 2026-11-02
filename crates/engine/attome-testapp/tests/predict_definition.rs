//! O1-T3: a model from a definition trains over any entity and scores its
//! rows. Buyers asked not to be called and engineers did not; the model
//! learns that from `job_title`, every contact gets a score with its top
//! factors, and a second run scores nothing new.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_predict::model_def::ModelDef;
use attome_testapp::TestApp;
use serde_json::{Value, json};

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

// feature: O1
#[test]
fn definition_model_trains_and_scores() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let admin = app.admin.id;
        for i in 0..120_u32 {
            let buyer = i % 2 == 0;
            sqlx::query(
                "INSERT INTO contact (full_name, job_title, do_not_email, do_not_call, owner_ref) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(format!("Person {i}"))
            .bind(if buyer { "Buyer" } else { "Engineer" })
            .bind(i % 3 == 0)
            .bind(buyer)
            .bind(admin)
            .execute(app.db())
            .await
            .unwrap();
        }

        let def: ModelDef = serde_json::from_value(json!({
            "entity": "contact", "target": "do_not_call", "algorithm": "logistic_regression",
            "features": [{ "attribute": "job_title" }, { "attribute": "do_not_email" }],
            "min_rows": 100
        }))
        .unwrap();
        let model = attome_predict::train::create_and_enqueue(
            &app.state,
            "Call refusal",
            "",
            "",
            Some(&def),
            admin,
        )
        .await
        .unwrap();
        let target: String =
            sqlx::query_scalar("SELECT target FROM prediction_model WHERE id = $1")
                .bind(model)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(target, "def:do_not_call");

        attome_predict::generic::run(&app.state, model)
            .await
            .unwrap();
        let (status, metrics): (String, Option<Value>) =
            sqlx::query_as("SELECT status, metrics FROM prediction_model WHERE id = $1")
                .bind(model)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "active", "{metrics:?}");

        let scored = attome_predict::generic::score(&app.state, model)
            .await
            .unwrap();
        assert_eq!(scored, 120);
        let (score, explanation): (f64, Value) = sqlx::query_as(
            "SELECT p.score, p.explanation FROM prediction p \
               JOIN contact c ON c.id = p.regarding_id \
              WHERE p.model_ref = $1 AND c.full_name = 'Person 0'",
        )
        .bind(model)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(score > 0.5, "a buyer likely refuses calls: {score}");
        let top = explanation["top_factors"].as_array().unwrap();
        assert!(!top.is_empty() && top.len() <= 3);
        assert!(
            top[0]["feature"]
                .as_str()
                .unwrap()
                .starts_with("job_title="),
            "{top:?}"
        );

        assert_eq!(
            attome_predict::generic::score(&app.state, model)
                .await
                .unwrap(),
            0,
            "a version scores each row once"
        );
        // A bad definition is refused before anything is stored.
        let bad: ModelDef = serde_json::from_value(json!({
            "entity": "contact", "target": "no_such_field", "algorithm": "logistic_regression",
            "features": [{ "attribute": "job_title" }]
        }))
        .unwrap();
        let refused =
            attome_predict::train::create_and_enqueue(&app.state, "Bad", "", "", Some(&bad), admin)
                .await;
        assert!(matches!(
            refused,
            Err(attome_types::AppError::Validation(_))
        ));
    });
}

async fn add_leads(app: &TestApp, from: u32, to: u32, status: Option<&str>) {
    for i in from..to {
        let converts = i % 2 == 0;
        let closed = status.unwrap_or(if converts {
            "converted"
        } else {
            "disqualified"
        });
        sqlx::query(
            "INSERT INTO lead (name, lead_status, authority, source, owner_ref) \
             VALUES ($1, $2, $3, 'web', $4)",
        )
        .bind(format!("Lead {i}"))
        .bind(closed)
        .bind(if converts { "decision_maker" } else { "user" })
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
    }
}

// feature: D18
#[test]
fn lead_conversion_waits_for_history() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let def = attome_predict::generic::lead_conversion();
        let model = attome_predict::train::create_and_enqueue(
            &app.state,
            "Lead conversion",
            "",
            "",
            Some(&def),
            app.admin.id,
        )
        .await
        .unwrap();
        let status = |app: &TestApp| {
            let db = app.db().clone();
            async move {
                sqlx::query_as::<_, (String, Option<Value>)>(
                    "SELECT status, metrics FROM prediction_model WHERE id = $1",
                )
                .bind(model)
                .fetch_one(&db)
                .await
                .unwrap()
            }
        };

        // 300 closed leads: not enough history, no model.
        add_leads(&app, 0, 300, None).await;
        attome_predict::generic::run(&app.state, model)
            .await
            .unwrap();
        let (state, metrics) = status(&app).await;
        assert_eq!(state, "failed_holdout");
        assert_eq!(
            metrics.unwrap()["error"],
            "insufficient labeled training data"
        );

        // 520 closed and 10 open: it trains, and only the open leads are scored.
        add_leads(&app, 300, 520, None).await;
        add_leads(&app, 520, 530, Some("qualified")).await;
        attome_predict::generic::run(&app.state, model)
            .await
            .unwrap();
        let (state, metrics) = status(&app).await;
        assert_eq!(state, "active", "{metrics:?}");
        assert_eq!(
            attome_predict::generic::score(&app.state, model)
                .await
                .unwrap(),
            10
        );
        let (score, explanation): (f64, Value) = sqlx::query_as(
            "SELECT p.score, p.explanation FROM prediction p \
               JOIN lead l ON l.id = p.regarding_id \
              WHERE p.model_ref = $1 AND l.name = 'Lead 520'",
        )
        .bind(model)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(score > 0.5, "a decision maker likely converts: {score}");
        assert!(
            explanation["top_factors"][0]["feature"]
                .as_str()
                .unwrap()
                .starts_with("authority="),
            "{explanation}"
        );

        // A changed lead is rescored when its score moved, and only then.
        let lead = |name: &'static str| {
            let db = app.db().clone();
            async move {
                sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM lead WHERE name = $1")
                    .bind(name)
                    .fetch_one(&db)
                    .await
                    .unwrap()
            }
        };
        let changed = lead("Lead 521").await;
        sqlx::query("UPDATE lead SET authority = 'decision_maker' WHERE id = $1")
            .bind(changed)
            .execute(app.db())
            .await
            .unwrap();
        let rescore = |app: &TestApp| {
            let state = app.state.clone();
            async move {
                attome_predict::generic::rescore(&state, model, &[changed])
                    .await
                    .unwrap()
            }
        };
        assert_eq!(rescore(&app).await, 1, "the score moved");
        assert_eq!(rescore(&app).await, 0, "nothing changed since");

        // A lead that converts records the prediction's outcome (O11).
        let converted = lead("Lead 520").await;
        sqlx::query("UPDATE lead SET lead_status = 'converted' WHERE id = $1")
            .bind(converted)
            .execute(app.db())
            .await
            .unwrap();
        let filled = attome_predict::generic::fill_outcomes(&app.state)
            .await
            .unwrap();
        assert_eq!(filled, 1, "only the closed lead has an outcome");
        let effectiveness: Option<f64> = sqlx::query_scalar(
            "SELECT o.effectiveness FROM outcome o JOIN prediction p ON p.outcome_ref = o.id \
              WHERE p.model_ref = $1 AND p.regarding_id = $2",
        )
        .bind(model)
        .bind(converted)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            effectiveness,
            Some(1.0),
            "a likely conversion that converted"
        );
    });
}

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

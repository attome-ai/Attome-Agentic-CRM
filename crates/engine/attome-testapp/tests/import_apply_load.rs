//! AA5-T1 (measurement first, V2-D1672): how fast the shared mutation path
//! applies a staged import. Stages `IMPORT_LOAD_ROWS` new rows (default
//! 20,000), validates and applies them, and prints the seconds each step took
//! and the rows per second, so the 1-million-row target can be judged before
//! any batch path is designed.
//!
//! Run on purpose, against a throwaway database:
//! `IMPORT_LOAD_ROWS=100000 cargo test -p attome-testapp --test import_apply_load -- --ignored --nocapture`

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "a load measurement prints its numbers; a failed setup step should panic"
)]

use std::time::Instant;

use attome_document::import_stage::{header_names, stage_rows};
use attome_records::{import_apply, import_validate};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

// feature: AA5
#[test]
#[ignore = "load: run on purpose, not with the suite"]
fn import_apply_throughput() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let rows: usize = std::env::var("IMPORT_LOAD_ROWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);

        let entity = format!("ial_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();
        for (field, field_type) in [("title", "text"), ("level", "number")] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/admin/entities/{id}/fields"),
                    Some(json!({ "logicalname": field, "name": field, "field_type": field_type })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let job = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                     mapping, match_mode, match_columns, all_or_nothing, status, \
                                     created_by) \
             VALUES ($1, $2, 'imports/load.csv', 'load.csv', $3, $4, 'upsert', '{title}', false, \
                     'staged', $5)",
        )
        .bind(job)
        .bind(&entity)
        .bind(job.to_string())
        .bind(json!({"columns": [
            {"source": "Name", "target": "title"},
            {"source": "Level", "target": "level"},
        ]}))
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        let names = header_names(&["Name".into(), "Level".into()]);
        let data: Vec<Vec<String>> = (0..rows)
            .map(|i| vec![format!("row {i}"), (i % 100).to_string()])
            .collect();

        let t = Instant::now();
        stage_rows(app.db(), job, &names, &data, 10_000, None)
            .await
            .unwrap();
        let staged = t.elapsed().as_secs_f64();

        let t = Instant::now();
        import_validate::validate(&app.state, job).await.unwrap();
        let validated = t.elapsed().as_secs_f64();

        let t = Instant::now();
        let counts = import_apply::apply(&app.state, job).await.unwrap();
        let applied = t.elapsed().as_secs_f64();

        assert_eq!(counts.applied as usize, rows);
        println!(
            "import_load rows={rows} stage_s={staged:.1} validate_s={validated:.1} \
             apply_s={applied:.1} apply_rows_per_s={:.0}",
            rows as f64 / applied
        );
    });
}

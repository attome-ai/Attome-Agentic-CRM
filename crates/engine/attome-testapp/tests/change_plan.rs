//! Y12-T3: the change plan classifies proposed structure changes and
//! estimates them from measured rates. A small table runs everything
//! inline; over the inline limit a type change is a background run whose
//! estimate comes from the finished runs of its kind. The large table and the
//! measured run are made by hand on the throwaway test database.

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

async fn plan(app: &TestApp, entity_id: Uuid, changes: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/admin/entities/{entity_id}/change-plan"),
        Some(json!({ "changes": changes })),
    )
    .await
}

// feature: Y12
#[test]
fn change_plan_estimates_from_ledger() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let name = format!("cp_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let changes = json!([
            { "kind": "add_field", "field": "note" },
            { "kind": "change_type", "field": "amount", "to": "text" },
        ]);
        let (status, small) = plan(&app, entity_id, changes.clone()).await;
        assert_eq!(status, StatusCode::OK, "{small}");
        assert_eq!(small["changes"][1]["class"], "instant", "{small}");
        assert_eq!(small["total_estimate_secs"], 0);

        // Over the inline limit, analysed, with one measured retype run at
        // 1,000 rows a second.
        sqlx::query(&format!(
            "INSERT INTO \"{name}\" (created_at) SELECT now() FROM generate_series(1, 10001)"
        ))
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(&format!("ANALYZE \"{name}\""))
            .execute(app.db())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO data_step_run \
               (source, entity_logicalname, kind, spec, status, rows_scanned, created_at, finished_at) \
             VALUES ('admin', $1, 'retype', '{}'::jsonb, 'succeeded', 10000, \
                     now() - interval '10 seconds', now())",
        )
        .bind(&name)
        .execute(app.db())
        .await
        .unwrap();

        let (status, large) = plan(&app, entity_id, changes).await;
        assert_eq!(status, StatusCode::OK, "{large}");
        assert_eq!(large["changes"][0]["class"], "instant", "{large}");
        assert_eq!(large["changes"][0]["estimate_secs"], 0);
        assert_eq!(large["changes"][1]["class"], "background", "{large}");
        let secs = large["changes"][1]["estimate_secs"].as_u64().unwrap();
        assert!(
            (10..=12).contains(&secs),
            "about 10,001 rows at 1,000 a second: {large}"
        );

        let (status, _) = plan(&app, entity_id, json!([])).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

//! P10-T1: metric lineage from the L5 graph. A formula metric records the
//! metrics it reads, so the metric it reads lists it downstream, and the
//! impact route previews what a change reaches.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use uuid::Uuid;

async fn insert_metric(app: &TestApp, key: &str, formula: Option<&str>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition \
         (id, name, key, source_kind, formula, direction, period, is_active) \
         VALUES ($1, $2, $2, $3, $4, 'higher_is_better', 'month', true)",
    )
    .bind(id)
    .bind(key)
    .bind(if formula.is_some() {
        "formula"
    } else {
        "manual"
    })
    .bind(formula)
    .execute(app.db())
    .await
    .expect("insert metric definition");
    id
}

/// The impact the route serves (`GET /api/v1/metrics/{id}/impact`, a thin
/// wrapper), as its JSON; `TestApp` does not mount the metric engine.
async fn impact_of(app: &TestApp, metric_id: Uuid) -> serde_json::Value {
    let impact = attome_metric::lineage_graph::impact(app.db(), metric_id)
        .await
        .unwrap();
    serde_json::to_value(impact).unwrap()
}

// feature: P10
#[test]
fn lineage_lists_a_metric_s_inputs_and_consumers() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let suffix = &Uuid::now_v7().simple().to_string()[..10];
        let won = format!("won_{suffix}");
        let lost = format!("lost_{suffix}");
        let won_id = insert_metric(&app, &won, None).await;
        let lost_id = insert_metric(&app, &lost, None).await;
        let rate_id = insert_metric(
            &app,
            &format!("rate_{suffix}"),
            Some(&format!("{won} / ({won} + {lost})")),
        )
        .await;
        for id in [won_id, lost_id, rate_id] {
            attome_metric::lineage_graph::sync_metric_lineage(app.db(), id)
                .await
                .unwrap();
        }

        let body = impact_of(&app, rate_id).await;
        let mut inputs: Vec<String> = body["upstream"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["metric_id"].as_str().unwrap_or_default().to_owned())
            .collect();
        inputs.sort();
        let mut expected = vec![won_id.to_string(), lost_id.to_string()];
        expected.sort();
        assert_eq!(inputs, expected, "{body}");
        assert_eq!(body["downstream"].as_array().unwrap().len(), 0);

        let body = impact_of(&app, won_id).await;
        let downstream = body["downstream"].as_array().unwrap();
        assert_eq!(downstream.len(), 1, "{body}");
        assert_eq!(downstream[0]["kind"], "metric");
        assert_eq!(downstream[0]["id"], rate_id.to_string());
        assert_eq!(body["impact"]["metric"], 1);

        // The formula stops reading `lost`: its consumer list empties.
        sqlx::query("UPDATE dashboard_metric_definition SET formula = $2 WHERE id = $1")
            .bind(rate_id)
            .bind(format!("{won} * 1"))
            .execute(app.db())
            .await
            .unwrap();
        attome_metric::lineage_graph::sync_metric_lineage(app.db(), rate_id)
            .await
            .unwrap();
        let body = impact_of(&app, lost_id).await;
        assert_eq!(body["downstream"].as_array().unwrap().len(), 0, "{body}");

        assert!(matches!(
            attome_metric::lineage_graph::impact(app.db(), Uuid::now_v7()).await,
            Err(attome_types::AppError::NotFound)
        ));
    });
}

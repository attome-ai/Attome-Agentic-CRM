//! I7-T1: a threshold reading posted by device id opens one work order; a
//! second reading inside the rule's quiet period, and a replay of the first,
//! open none, and each reading is counted into its hour once.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_service::iot::{ReadingIn, ReadingsIn, intake, process_reading};
use attome_testapp::TestApp;
use chrono::{Duration, Utc};
use uuid::Uuid;

const PACKS: [&str; 5] = [
    "crm",
    "sales",
    "asset-management",
    "customer-service",
    "field-service",
];

async fn install(app: &TestApp) {
    for pack in PACKS {
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
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn asset(app: &TestApp, device: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO asset (id, name, device_id, owner_ref, is_active) \
         VALUES ($1, $2, $3, $4, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(format!("Chiller {device}"))
    .bind(device)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn rule(app: &TestApp, asset: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO device_rule (id, name, meter, condition, action, asset_ref, priority, \
                                  debounce_minutes, owner_ref, is_active) \
         VALUES ($1, 'Overheat', 'temperature', 'reading > 90', 'work_order', $2, 'urgent', \
                 30, $3, true) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(asset)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

fn posted(device: &str, value: f64, minutes_ago: i64) -> ReadingIn {
    ReadingIn {
        device_id: device.into(),
        meter: "temperature".into(),
        reading: value,
        unit: Some("C".into()),
        read_at: Some(Utc::now() - Duration::minutes(minutes_ago)),
    }
}

// feature: I7
#[test]
fn threshold_reading_opens_one_work_order() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let device = format!("dev-{}", Uuid::now_v7().simple());
        let chiller = asset(&app, &device).await;
        rule(&app, chiller).await;
        let ctx = app
            .state
            .base
            .security
            .resolve_strict(app.admin.id)
            .await
            .unwrap();

        let answer = intake(
            &app.state,
            &ctx,
            ReadingsIn {
                readings: vec![
                    posted(&device, 72.0, 20),
                    posted(&device, 95.5, 10),
                    posted(&device, 97.0, 5),
                    posted("no-such-device", 99.0, 5),
                ],
            },
        )
        .await
        .expect("intake");
        assert_eq!(answer.results[3].error.as_deref(), Some("unknown_device"));
        let ids: Vec<Uuid> = answer.results[..3]
            .iter()
            .map(|r| r.reading_id.expect("a reading for a known device"))
            .collect();

        let mut fired = 0;
        for id in &ids {
            let (counted, made, failed) = process_reading(&app.state, *id).await.expect("process");
            assert!(counted, "a new reading is counted");
            assert_eq!(failed, 0);
            fired += made;
        }
        assert_eq!(
            fired, 1,
            "the second hot reading is inside the quiet period"
        );
        let (counted, made, _) = process_reading(&app.state, ids[1]).await.expect("replay");
        assert!(!counted, "a replay counts nothing");
        assert_eq!(made, 0, "a replay fires nothing");

        let orders: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT title, priority FROM work_order WHERE asset_ref = $1 AND is_active",
        )
        .bind(chiller)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(orders.len(), 1, "one work order: {orders:?}");
        assert!(orders[0].0.starts_with("Overheat: temperature 95.5"));
        assert_eq!(orders[0].1.as_deref(), Some("urgent"));

        let readings: i64 = sqlx::query_scalar(
            "SELECT COALESCE(sum(readings), 0)::bigint FROM device_hourly_summary \
              WHERE asset_id = $1 AND meter = 'temperature'",
        )
        .bind(chiller)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(readings, 3);
        let latest: f64 = sqlx::query_scalar(
            "SELECT reading FROM device_latest_reading WHERE asset_id = $1 AND meter = 'temperature'",
        )
        .bind(chiller)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!((latest - 97.0).abs() < f64::EPSILON);
    });
}

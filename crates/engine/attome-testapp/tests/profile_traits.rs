//! E23-T2: a batch of profile events is kept, events for an unknown contact
//! come back as rejected, and a contact's traits roll up from its events.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_marketing::profile::{EventBatch, IncomingEvent, ingest, traits};
use attome_testapp::TestApp;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

const PACKS: [&str; 1] = ["crm"];

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

fn event(
    contact: Option<Uuid>,
    kind: &str,
    minutes_ago: i64,
    properties: serde_json::Value,
) -> IncomingEvent {
    IncomingEvent {
        contact_id: contact,
        anonymous_id: None,
        kind: kind.to_owned(),
        at: Some(Utc::now() - Duration::minutes(minutes_ago)),
        properties: Some(properties),
    }
}

// feature: E23
#[test]
fn profile_events_roll_up_into_traits() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let contact: Uuid = sqlx::query_scalar(
            "INSERT INTO contact (full_name, email) VALUES ('Huda', 'huda@example.invalid') RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        let ctx = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let batch = EventBatch {
            events: vec![
                event(
                    Some(contact),
                    "page_view",
                    30,
                    json!({ "path": "/pricing" }),
                ),
                event(Some(contact), "visit", 20, json!({})),
                event(Some(contact), "purchase", 10, json!({ "amount": 120.5 })),
                event(Some(contact), "purchase", 5, json!({ "amount": "79.5" })),
                // Unknown contact, and no subject at all.
                event(Some(Uuid::now_v7()), "visit", 5, json!({})),
                event(None, "visit", 5, json!({})),
            ],
        };
        let result = ingest(&app.state, &ctx, &batch, Utc::now()).await.unwrap();
        assert_eq!(result.accepted, 4);
        let rejected: Vec<usize> = result.rejected.iter().map(|r| r.index).collect();
        assert_eq!(rejected, vec![4, 5]);

        let t = traits(&app.state, &ctx, contact).await.unwrap();
        assert_eq!(t.events, 4);
        assert_eq!(t.visits, 2);
        assert_eq!(t.purchases, 2);
        assert!((t.total_purchases - 200.0).abs() < 1e-9, "{t:?}");
        let last = t.last_seen_at.unwrap();
        assert!(Utc::now() - last < Duration::minutes(6), "{last}");
    });
}

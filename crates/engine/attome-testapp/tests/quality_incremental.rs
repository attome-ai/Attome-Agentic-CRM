//! L2-T3: quality scoring follows the change feed. Updating one record
//! rescored that record and no other, and a rescan stopped after its first
//! batch resumes from the cursor it carried.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::quality::incremental;
use attome_testapp::TestApp;
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs")
        .join(pack)
        .join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

async fn scored_at(app: &TestApp, record: Uuid) -> Option<DateTime<Utc>> {
    sqlx::query_scalar(
        "SELECT updated_at FROM quality_record_score WHERE entity = 'account' AND record_id = $1",
    )
    .bind(record)
    .fetch_optional(app.db())
    .await
    .expect("read record score")
}

/// Ticks until `done` holds (the cursor may start behind other tests' events).
async fn tick_until(app: &TestApp, mut done: impl AsyncFnMut() -> bool) {
    for _ in 0..400 {
        incremental::tick(&app.state).await.expect("tick");
        if done().await {
            return;
        }
    }
    panic!("the incremental tick never reached the change");
}

// feature: L2
#[test]
fn only_changed_record_rescored_and_rescan_resumes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        sqlx::query(
            "INSERT INTO quality_target (entity, record_scoring) VALUES ('account', true) \
             ON CONFLICT (entity) DO UPDATE SET record_scoring = true",
        )
        .execute(app.db())
        .await
        .unwrap();
        // One check, so every account gets a record score.
        sqlx::query(
            "INSERT INTO quality_rule (entity, dimension, expression)              SELECT 'account', 'validity', 'name != null'               WHERE NOT EXISTS (SELECT 1 FROM quality_rule                                  WHERE entity = 'account' AND expression = 'name != null')",
        )
        .execute(app.db())
        .await
        .unwrap();
        let owner = attome_testapp::seed_admin(app.db()).await.id;
        let ctx = app.state.base.security.resolve(owner).await.expect("ctx");
        let mut ids = Vec::new();
        for name in ["Quality A", "Quality B"] {
            let (id, _) = attome_records::entity_crud::create_record_for(
                &app.state,
                &ctx,
                owner,
                "account",
                json!({ "name": name }),
            )
            .await
            .expect("account");
            ids.push(id);
        }
        let (a, b) = (ids[0], ids[1]);
        tick_until(&app, async || {
            scored_at(&app, a).await.is_some() && scored_at(&app, b).await.is_some()
        })
        .await;
        let (a_before, b_before) = (scored_at(&app, a).await, scored_at(&app, b).await);

        let version: i64 = sqlx::query_scalar("SELECT row_version FROM account WHERE id = $1")
            .bind(a)
            .fetch_one(app.db())
            .await
            .unwrap();
        attome_records::entity_crud::update_record_for(
            &app.state,
            &ctx,
            owner,
            "account",
            a,
            version,
            json!({ "name": "Quality A renamed" }),
        )
        .await
        .expect("update");
        tick_until(&app, async || scored_at(&app, a).await != a_before).await;
        assert_eq!(
            scored_at(&app, b).await,
            b_before,
            "the record that did not change keeps its score"
        );

        // More accounts than one rescan batch, scored by the rescan only.
        sqlx::query(
            "INSERT INTO account (id, name, is_active) \
             SELECT uuidv7(), 'Quality bulk ' || g, true FROM generate_series(1, $1) g",
        )
        .bind(incremental::RESCAN_BATCH + 10)
        .execute(app.db())
        .await
        .unwrap();
        let first = incremental::rescan_step(&app.state, "account", None)
            .await
            .expect("first batch");
        let cursor = first.expect("more than one batch: the rescan carries a cursor");
        // A restart: the job runs again from the cursor it carried.
        let mut next = Some(cursor);
        let mut batches = 1;
        while let Some(after) = next {
            next = incremental::rescan_step(&app.state, "account", Some(after))
                .await
                .expect("next batch");
            batches += 1;
            assert!(batches < 1_000, "the rescan keeps moving forward");
        }
        let unscored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account t WHERE t.is_active IS NOT FALSE \
               AND NOT EXISTS (SELECT 1 FROM quality_record_score s \
                                WHERE s.entity = 'account' AND s.record_id = t.id)",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            unscored, 0,
            "every live account has a score after the rescan"
        );
    });
}

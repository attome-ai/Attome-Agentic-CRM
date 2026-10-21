//! AK3-T5: the work-share consumer against a throwaway database.
//!
//! A measure is set up on the fixture's test entity (`status` set to
//! `done`); a person and an agent session each complete one record, and the
//! consumer splits the two. Reading the feed again counts nothing twice.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test work_share -- ak3_ --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_core::agent_scope::{AgentScope, scope};
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

use common::{Fixture, fixture};

/// Provisions `ai_work_measure` (a platform-bundle entity, not seeded here)
/// and adds an active measure on the fixture's entity. Returns its key.
async fn measure(f: &Fixture) -> String {
    let entity_id = attome_metadata::provision::ensure_entity(
        f.db(),
        "ai_work_measure",
        "Work Measure",
        None,
        false,
    )
    .await
    .expect("provision ai_work_measure");
    for name in [
        "process_key",
        "label",
        "label_ar",
        "entity_logical_name",
        "completion_attribute",
        "completion_values",
    ] {
        attome_metadata::provision::ensure_attribute(
            f.db(),
            entity_id,
            name,
            name,
            "text",
            false,
            false,
            false,
            false,
            None,
            None,
        )
        .await
        .expect("provision attribute");
    }
    let key = format!("test.{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO ai_work_measure \
             (id, process_key, label, entity_logical_name, completion_attribute, \
              completion_values, is_active, row_version) \
         VALUES ($1, $2, 'Test', $3, 'status', 'done', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(&key)
    .bind(&f.entity)
    .execute(f.db())
    .await
    .expect("a measure");
    key
}

/// Reads the whole feed so far.
async fn drain(f: &Fixture) {
    loop {
        let read = attome_ai::work_share::consume_batch(&f.state)
            .await
            .expect("consume");
        if read == 0 {
            break;
        }
    }
}

/// Sets `status` to `done`, as `session`'s agent when given.
async fn complete(f: &Fixture, session: Option<Uuid>, record: Uuid) {
    let ctx = attome_security::resolve_uncached(f.db(), f.owner)
        .await
        .expect("security");
    let write = attome_records::entity_crud::update_record_for(
        &f.state,
        &ctx,
        f.owner,
        &f.entity,
        record,
        0,
        json!({ "status": "done" }),
    );
    let agent = |session| AgentScope {
        session_id: session,
        action_id: "record.update".into(),
    };
    let written = match session {
        Some(session) => scope(agent(session), write).await,
        None => write.await,
    };
    written.expect("update");
}

/// `(done_by_agent, done_by_person)` summed over every day of `key`.
async fn counts(f: &Fixture, key: &str) -> (i64, i64) {
    sqlx::query_as(
        "SELECT COALESCE(sum(done_by_agent), 0)::bigint, COALESCE(sum(done_by_person), 0)::bigint \
           FROM ai_work_share_daily WHERE process_key = $1",
    )
    .bind(key)
    .fetch_one(f.db())
    .await
    .expect("counts")
}

#[tokio::test]
async fn ak3_agent_and_person_completions_split() {
    let f = skip_if_no_db!(fixture().await);
    let key = measure(&f).await;
    let by_person = f.insert_record("open").await;
    let by_agent = f.insert_record("open").await;
    let untouched = f.insert_record("open").await;
    drain(&f).await;

    complete(&f, None, by_person).await;
    complete(&f, Some(f.session.id), by_agent).await;
    drain(&f).await;

    assert_eq!(counts(&f, &key).await, (1, 1), "agent, person");
    assert_eq!(f.record(untouched).await.0.as_deref(), Some("open"));
}

#[tokio::test]
async fn ak3_consumer_is_exactly_once() {
    let f = skip_if_no_db!(fixture().await);
    let key = measure(&f).await;
    let record = f.insert_record("open").await;
    drain(&f).await;
    complete(&f, None, record).await;
    drain(&f).await;
    let once = counts(&f, &key).await;
    drain(&f).await;
    assert_eq!(counts(&f, &key).await, once, "counted once");
    assert_eq!(once, (0, 1));

    // A rebuild of today recounts the same events to the same numbers.
    let today = chrono::Utc::now().date_naive();
    let range = attome_ai::work_share::RebuildRange {
        from: today,
        to: today,
    };
    attome_ai::work_share::rebuild(&f.state, range)
        .await
        .expect("rebuild");
    assert_eq!(counts(&f, &key).await, once);
}

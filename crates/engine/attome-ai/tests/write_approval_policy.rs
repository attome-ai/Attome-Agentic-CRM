//! Per-write approval policies (roadmap N30-T3, T11): off until a policy
//! names the action, then an agent's write of it waits for a second person.
//! A policy can be narrowed to one entity, and a deactivated one stops
//! applying. The four-eyes rules the request then follows (the requester
//! never approves it, expiry, the record re-check) are the consequential
//! path's, covered by `agent_action_approval_execution.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test write_approval_policy
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::write_policy::requires_approval;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

/// A unique action id per test, so parallel tests and old rows never meet.
fn action(name: &str) -> String {
    format!("test.{name}.{}", Uuid::now_v7().simple())
}

async fn add_policy(db: &sqlx::PgPool, action_id: &str, entity: Option<&str>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO ai_write_approval_policy (action_id, entity, created_by) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(action_id)
    .bind(entity)
    .bind(Uuid::now_v7())
    .fetch_one(db)
    .await
    .expect("insert a policy")
}

#[tokio::test]
async fn policy_on_requires_approval_policy_off_executes() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(2).await);
    let id = action("update");
    let args = json!({ "entity": "invoice", "record_id": Uuid::now_v7() });

    assert!(
        !requires_approval(&db, &id, &args).await.unwrap(),
        "no policy: the write runs once its person confirms it"
    );
    let policy = add_policy(&db, &id, None).await;
    assert!(
        requires_approval(&db, &id, &args).await.unwrap(),
        "an active policy for the action makes it wait for approval"
    );

    sqlx::query(
        "UPDATE ai_write_approval_policy SET is_active = false, deactivated_at = now() WHERE id = $1",
    )
    .bind(policy)
    .execute(&db)
    .await
    .unwrap();
    assert!(
        !requires_approval(&db, &id, &args).await.unwrap(),
        "a deactivated policy no longer applies"
    );
}

#[tokio::test]
async fn an_entity_policy_applies_to_that_entity_only() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(2).await);
    let id = action("delete");
    add_policy(&db, &id, Some("invoice")).await;

    let on_invoice = json!({ "entity": "invoice", "record_id": Uuid::now_v7() });
    let on_contact = json!({ "entity": "contact", "record_id": Uuid::now_v7() });
    let no_entity = json!({ "record_id": Uuid::now_v7() });
    assert!(requires_approval(&db, &id, &on_invoice).await.unwrap());
    assert!(!requires_approval(&db, &id, &on_contact).await.unwrap());
    assert!(
        !requires_approval(&db, &id, &no_entity).await.unwrap(),
        "an entity policy cannot match a write that names no entity"
    );
    // Another action is untouched by this one's policy.
    assert!(
        !requires_approval(&db, &action("other"), &on_invoice)
            .await
            .unwrap()
    );
}

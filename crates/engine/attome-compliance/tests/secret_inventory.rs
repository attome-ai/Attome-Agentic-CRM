//! Z1-T8: the secret inventory records each start's secrets by name and key
//! id, lists their ages without any value, follows a rotation, and claims an
//! age reminder at most once per 30 days.
//!
//! Runs against attome-testkit's migrated throwaway database: set
//! `DATABASE_URL`; without it each test prints SKIP. Key ids are unique per
//! run, so rows a previous run left behind do not interfere.
//!
//! Run: `cargo test -p attome-compliance --test secret_inventory -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_compliance::secret_inventory::{claim_due_reminders, list, record_boot};
use attome_config::secret_inventory::{SecretState, inventory_of};
use attome_types::{PageBase, PageWindow};
use serde_json::json;
use sqlx::PgPool;

async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(3).await
}

fn window() -> PageWindow {
    PageWindow::resolve(Some(1), Some(100), PageBase::One, 100)
}

/// This configuration's states: a JWT ring with `active` first, so it is
/// the active key, and a plain database password.
fn states(active: &str, other: &str) -> Vec<SecretState> {
    inventory_of(&json!({
        "auth": {"jwt_secret": format!("ring:{active}=jwt-value-{active};{other}=jwt-value-{other}")},
        "database": {"runtime": {"password": "runtime-password-value"}}
    }))
}

#[tokio::test]
async fn the_inventory_lists_ages_and_rotations_without_values() {
    let Some(db) = test_pool().await else {
        eprintln!("SKIP: {}", attome_testkit::skip_remedy());
        return;
    };
    let k1 = attome_testkit::unique("k1");
    let k2 = attome_testkit::unique("k2");

    let first = states(&k1, &k2);
    assert!(record_boot(&db, &first).await.expect("record") >= 3);
    let page = list(&db, &first, 365, window()).await.expect("list");
    let jwt = page
        .items
        .iter()
        .find(|row| row.name == "auth.jwt_secret")
        .expect("jwt row");
    assert!(jwt.set);
    assert_eq!(jwt.active_key_id.as_deref(), Some(k1.as_str()));
    assert_eq!(jwt.rotation, "key_ring");
    assert_eq!(jwt.age_days, Some(0));
    assert!(!jwt.over_age);
    assert!(!jwt.used_by.is_empty());
    let unset = page
        .items
        .iter()
        .find(|row| row.name == "storage.s3_secret_key")
        .expect("an unset secret is listed");
    assert!(!unset.set && unset.active_since.is_none());

    let body = serde_json::to_string(&page).expect("serialize");
    for value in ["jwt-value", "runtime-password-value"] {
        assert!(!body.contains(value), "{value} leaked: {body}");
    }

    // Rotation: k2 becomes active. Its row was seen before but never
    // active, so its active_since starts now; k1's is cleared.
    sqlx::query(
        "UPDATE secret_inventory SET first_seen_at = now() - interval '10 days', \
         active_since = now() - interval '10 days' WHERE key_id = $1",
    )
    .bind(&k1)
    .execute(&db)
    .await
    .expect("age k1");
    let rotated = states(&k2, &k1);
    record_boot(&db, &rotated).await.expect("record rotation");
    let page = list(&db, &rotated, 365, window()).await.expect("list");
    let jwt = page
        .items
        .iter()
        .find(|row| row.name == "auth.jwt_secret")
        .expect("jwt row");
    assert_eq!(jwt.active_key_id.as_deref(), Some(k2.as_str()));
    assert_eq!(jwt.age_days, Some(0), "the new active key's age starts now");
    let k1_active: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT active_since FROM secret_inventory WHERE key_id = $1")
            .bind(&k1)
            .fetch_one(&db)
            .await
            .expect("k1 row");
    assert!(
        k1_active.is_none(),
        "a key no longer active has no active_since"
    );
}

#[tokio::test]
async fn an_old_secret_is_reminded_once_per_thirty_days() {
    let Some(db) = test_pool().await else {
        eprintln!("SKIP: {}", attome_testkit::skip_remedy());
        return;
    };
    let k1 = attome_testkit::unique("old");
    let k2 = attome_testkit::unique("spare");
    let configured: Vec<SecretState> = states(&k1, &k2)
        .into_iter()
        .filter(|state| state.name == "auth.jwt_secret")
        .collect();
    record_boot(&db, &configured).await.expect("record");
    assert!(
        claim_due_reminders(&db, &configured, 365)
            .await
            .expect("claim")
            .is_empty(),
        "a new key is not due"
    );

    sqlx::query(
        "UPDATE secret_inventory SET active_since = now() - interval '400 days' WHERE key_id = $1",
    )
    .bind(&k1)
    .execute(&db)
    .await
    .expect("age");
    let page = list(&db, &configured, 365, window()).await.expect("list");
    assert!(page.items[0].over_age);
    assert!(page.items[0].age_days.is_some_and(|days| days >= 400));

    assert!(
        claim_due_reminders(&db, &configured, 0)
            .await
            .expect("claim")
            .is_empty(),
        "0 turns the reminder off"
    );
    let due = claim_due_reminders(&db, &configured, 365)
        .await
        .expect("claim");
    assert_eq!(due.len(), 1, "{due:?}");
    assert_eq!(due[0].name, "auth.jwt_secret");
    assert!(due[0].age_days >= 400);
    assert!(
        claim_due_reminders(&db, &configured, 365)
            .await
            .expect("claim again")
            .is_empty(),
        "reminded at most once per 30 days"
    );
}

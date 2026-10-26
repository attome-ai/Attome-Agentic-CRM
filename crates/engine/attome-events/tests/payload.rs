//! M62 Phase 1 — proves `payload::owner_scoped_record_data`'s central claim
//! (plan §5: "a subscription must never be a permission bypass"): a field
//! the subscription owner cannot read never appears in the projected
//! payload, and an entity the owner cannot read at all yields no payload.
//!
//! Provisions a real throwaway entity (via `attome_metadata::provision`, the same
//! primitive the admin API uses) with one sensitive and one ordinary field,
//! so the assertions run against the actual SQL `attome_core::
//! select_columns_filtered` builds — not a mock of it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-events --test payload -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::{ensure_attribute, ensure_entity};
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

fn ctx(user_id: Uuid, privileges: Vec<String>, field_grants: Vec<String>) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: privileges.into_iter().collect(),
        field_grants: field_grants.into_iter().collect(),
        field_write_grants: Default::default(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: Default::default(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// Provisions `evt_probe_{suffix}` with a `title` (ordinary) and
/// `secret_note` (`is_sensitive = true`) attribute, then inserts one live
/// record. Returns `(entity_logicalname, record_id)`. Short prefix + an
/// 8-hex-char suffix: `valid_identifier` caps logicalnames at 48 chars, and
/// the original `events_payload_probe_{full-uuid}` (58 chars) blew past
/// it.
async fn provision_probe_entity(db: &DbPool) -> (String, Uuid) {
    let suffix = &Uuid::now_v7().simple().to_string()[..8];
    let logicalname = format!("evt_probe_{suffix}");
    let entity_id = ensure_entity(db, &logicalname, "Events Payload Probe", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "title", "Title", "text", false, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute title");
    ensure_attribute(
        db,
        entity_id,
        "secret_note",
        "Secret Note",
        "text",
        false,
        true, // is_sensitive
        false,
        false,
        None,
        None,
    )
    .await
    .expect("ensure_attribute secret_note");

    let record_id: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO \"{logicalname}\" (title, secret_note, is_active) \
         VALUES ('public title', 'do not leak', true) RETURNING id"
    ))
    .fetch_one(db)
    .await
    .expect("insert throwaway record");

    (logicalname, record_id)
}

#[tokio::test]
async fn owner_without_a_field_grant_never_sees_the_sensitive_field() {
    let db = skip_if_no_db!(pool().await);
    let (entity, record_id) = provision_probe_entity(&db).await;
    let owner = ctx(Uuid::now_v7(), vec![format!("{entity}.read")], vec![]);

    let data = attome_events::payload::owner_scoped_record_data(&db, &owner, &entity, record_id)
        .await
        .expect("projection must not error")
        .expect("owner can read the entity, so data must be Some");

    assert_eq!(data["title"], "public title");
    assert!(
        data.get("secret_note").is_none(),
        "an is_sensitive field the owner holds no field-security read grant for \
         must never appear in the payload, got: {data}"
    );
}

#[tokio::test]
async fn owner_with_a_field_grant_sees_the_sensitive_field() {
    let db = skip_if_no_db!(pool().await);
    let (entity, record_id) = provision_probe_entity(&db).await;
    let owner = ctx(
        Uuid::now_v7(),
        vec![format!("{entity}.read")],
        vec![format!("{entity}.secret_note")],
    );

    let data = attome_events::payload::owner_scoped_record_data(&db, &owner, &entity, record_id)
        .await
        .expect("projection must not error")
        .expect("owner can read the entity, so data must be Some");

    assert_eq!(data["title"], "public title");
    assert_eq!(
        data["secret_note"], "do not leak",
        "a field the owner DOES hold a grant for must still be delivered"
    );
}

#[tokio::test]
async fn owner_without_any_entity_read_privilege_gets_no_payload_at_all() {
    let db = skip_if_no_db!(pool().await);
    let (entity, record_id) = provision_probe_entity(&db).await;
    // No `{entity}.read` privilege at all — a subscription owner who cannot
    // read the entity gets nothing, not merely a field-pruned row (M62 plan
    // §5: never a permission bypass).
    let owner = ctx(Uuid::now_v7(), vec![], vec![]);

    let data = attome_events::payload::owner_scoped_record_data(&db, &owner, &entity, record_id)
        .await
        .expect("projection must not error");

    assert!(
        data.is_none(),
        "an owner with no entity-level read privilege must get no data object at all"
    );
}

#[tokio::test]
async fn a_deleted_record_yields_no_data_even_for_a_fully_privileged_owner() {
    let db = skip_if_no_db!(pool().await);
    let (entity, record_id) = provision_probe_entity(&db).await;
    sqlx::query(&format!(
        "UPDATE \"{entity}\" SET is_active = false WHERE id = $1"
    ))
    .bind(record_id)
    .execute(&db)
    .await
    .expect("soft-delete the probe record");

    let owner = ctx(
        Uuid::now_v7(),
        vec![format!("{entity}.read")],
        vec![format!("{entity}.secret_note")],
    );

    let data = attome_events::payload::owner_scoped_record_data(&db, &owner, &entity, record_id)
        .await
        .expect("projection must not error");

    assert!(
        data.is_none(),
        "a delete/purge event's record is not live — the delivery still carries \
         entity/record_id/operation regardless, but no data object"
    );
}

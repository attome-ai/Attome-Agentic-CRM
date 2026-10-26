//! Memory visibility against a real database — scope-leakage negative tests
//! (M35, D-451).
//!
//! The whole point of D-451's "per-principal only" ruling is that
//! `scope_kind`/`scope_ref` never widen who can read a memory row — only
//! `owner_principal` does. These tests exist to catch the failure mode where
//! that stops being true: a memory scoped to one user surfacing in another
//! user's recall, or an entity-scoped memory outliving the record-share that
//! justified it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test memory_visibility
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::corpus::memory::{MemoryScopeKind, NewMemory, RecallQuery, store};
use attome_security::visibility::PolymorphicVisibility;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

async fn seed_user(db: &DbPool, id: Uuid) {
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(id)
        .bind(format!("test-{}", id.simple()))
        .execute(db)
        .await
        .expect("seed user");
}

fn ctx(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        service_principal: false,
    }
}

async fn share(db: &DbPool, record_id: Uuid, entity_ref: Uuid, principal: Uuid) {
    sqlx::query(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0) ON CONFLICT DO NOTHING",
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(principal)
    .execute(db)
    .await
    .expect("share");
}

async fn register_entity(db: &DbPool) -> (Uuid, String) {
    let logicalname = format!("test_mem_{}", Uuid::now_v7().simple());
    let entity_ref: Uuid = sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .fetch_one(db)
    .await
    .expect("register entity");
    (entity_ref, logicalname)
}

async fn cleanup(db: &DbPool, owner: Uuid) {
    let _ = sqlx::query("DELETE FROM memory WHERE owner_principal = $1")
        .bind(owner)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM user_account WHERE id = $1")
        .bind(owner)
        .execute(db)
        .await;
}

/// **The core scope-leakage assertion.** A memory scoped to user A must never
/// surface in a recall performed for user B — even when B asks for exactly
/// A's `scope_ref`.
#[tokio::test]
async fn a_memory_scoped_to_one_user_never_surfaces_for_another_user() {
    let db = skip_if_no_db!(test_db().await);
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    seed_user(&db, user_a).await;
    seed_user(&db, user_b).await;

    store(
        &db,
        NewMemory {
            scope_kind: MemoryScopeKind::User,
            scope_ref: &user_a.to_string(),
            owner_principal: user_a,
            parent_entity: None,
            parent_record_id: None,
            kind: "preference",
            summary: "prefers dark mode",
            facts: &[],
            source_refs: &[],
        },
    )
    .await
    .expect("store memory for user A");

    let empty_access: HashMap<String, (Uuid, AccessLevel)> = HashMap::new();
    let empty_shares = HashSet::new();

    let ctx_b = ctx(user_b);
    let records_b = PolymorphicVisibility::new(&ctx_b, &empty_access, &empty_shares, None);
    let as_b = attome_search::corpus::memory::recall(
        &db,
        RecallQuery {
            owner_principal: user_b,
            scope_kind: None,
            scope_ref: None,
            query_text: None,
            records: &records_b,
            limit: 10,
        },
    )
    .await
    .expect("recall as B");
    assert!(
        as_b.is_empty(),
        "user B must never recall a memory owned by user A: {as_b:?}"
    );

    // Positive control: the same memory IS visible to its owner, or the
    // empty result above proves nothing about permissions.
    let ctx_a = ctx(user_a);
    let records_a = PolymorphicVisibility::new(&ctx_a, &empty_access, &empty_shares, None);
    let as_a = attome_search::corpus::memory::recall(
        &db,
        RecallQuery {
            owner_principal: user_a,
            scope_kind: None,
            scope_ref: None,
            query_text: None,
            records: &records_a,
            limit: 10,
        },
    )
    .await
    .expect("recall as A");
    assert_eq!(
        as_a.len(),
        1,
        "the owner must still recall their own memory, or the empty result \
         for B proves nothing: {as_a:?}"
    );

    cleanup(&db, user_a).await;
    cleanup(&db, user_b).await;
}

/// `organization`-scoped memory is still per-principal (D-451) — it is not an
/// org-wide shared pool. A second user who administers/belongs to the same
/// organization must not recall it.
#[tokio::test]
async fn organization_scoped_memory_does_not_leak_to_another_principal_in_the_same_org() {
    let db = skip_if_no_db!(test_db().await);
    let admin_a = Uuid::now_v7();
    let admin_b = Uuid::now_v7();
    seed_user(&db, admin_a).await;
    seed_user(&db, admin_b).await;
    let org = Uuid::now_v7();

    store(
        &db,
        NewMemory {
            scope_kind: MemoryScopeKind::Organization,
            scope_ref: &org.to_string(),
            owner_principal: admin_a,
            parent_entity: None,
            parent_record_id: None,
            kind: "policy_note",
            summary: "quarterly review happens in January",
            facts: &[],
            source_refs: &[],
        },
    )
    .await
    .expect("store org-scoped memory");

    let empty_access: HashMap<String, (Uuid, AccessLevel)> = HashMap::new();
    let empty_shares = HashSet::new();

    // admin_b's SecurityContext claims the SAME accessible_org_ids as A —
    // membership in the same org must not be enough.
    let mut ctx_b = ctx(admin_b);
    ctx_b.accessible_org_ids = vec![org];
    let records_b = PolymorphicVisibility::new(&ctx_b, &empty_access, &empty_shares, None);
    let as_b = attome_search::corpus::memory::recall(
        &db,
        RecallQuery {
            owner_principal: admin_b,
            scope_kind: Some(MemoryScopeKind::Organization),
            scope_ref: Some(&org.to_string()),
            query_text: None,
            records: &records_b,
            limit: 10,
        },
    )
    .await
    .expect("recall as admin_b");
    assert!(
        as_b.is_empty(),
        "an organization-scoped memory must not be visible to a different \
         principal even when both administer the same organization: {as_b:?}"
    );

    cleanup(&db, admin_a).await;
    cleanup(&db, admin_b).await;
}

/// **Entity-scope respects record visibility, even for the memory's own
/// owner.** A memory about a record the caller can no longer see must not be
/// recalled just because they wrote it while they still could.
#[tokio::test]
async fn entity_scoped_memory_stops_being_recallable_when_the_record_is_no_longer_visible() {
    let db = skip_if_no_db!(test_db().await);
    let user = Uuid::now_v7();
    seed_user(&db, user).await;
    let (entity_ref, entity_name) = register_entity(&db).await;
    let record_id = Uuid::now_v7();

    store(
        &db,
        NewMemory {
            scope_kind: MemoryScopeKind::Entity,
            scope_ref: "",
            owner_principal: user,
            parent_entity: Some(&entity_name),
            parent_record_id: Some(record_id),
            kind: "entity_summary",
            summary: "3 changes recorded; most recent: status set to closed",
            facts: &[],
            source_refs: &[],
        },
    )
    .await
    .expect("store entity-scoped memory");

    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity_name.clone(), (entity_ref, AccessLevel::Team))].into();
    let empty_shares = HashSet::new();
    let c = ctx(user);

    // No share row yet — the record is not visible, so neither is the memory,
    // even though `user` is its owner.
    let records_denied = PolymorphicVisibility::new(&c, &access, &empty_shares, None);
    let denied = attome_search::corpus::memory::recall(
        &db,
        RecallQuery {
            owner_principal: user,
            scope_kind: Some(MemoryScopeKind::Entity),
            scope_ref: None,
            query_text: None,
            records: &records_denied,
            limit: 10,
        },
    )
    .await
    .expect("recall while record is not shared");
    assert!(
        denied.is_empty(),
        "an entity-scoped memory must not be recallable while its parent \
         record is not visible, even to the memory's own owner: {denied:?}"
    );

    // The control: sharing the record makes the memory recallable again — or
    // the empty result above proves nothing about the record predicate.
    share(&db, record_id, entity_ref, user).await;
    let records_allowed = PolymorphicVisibility::new(&c, &access, &empty_shares, None);
    let allowed = attome_search::corpus::memory::recall(
        &db,
        RecallQuery {
            owner_principal: user,
            scope_kind: Some(MemoryScopeKind::Entity),
            scope_ref: None,
            query_text: None,
            records: &records_allowed,
            limit: 10,
        },
    )
    .await
    .expect("recall after sharing the record");
    assert_eq!(
        allowed.len(),
        1,
        "sharing the parent record must make the entity-scoped memory \
         recallable again, or the denial above proves nothing: {allowed:?}"
    );

    cleanup(&db, user).await;
}

/// `memory.forget`'s primitive is scoped to `owner_principal` in the delete
/// itself — a caller must not be able to delete another principal's memory
/// by id.
#[tokio::test]
async fn forget_cannot_delete_another_principals_memory() {
    let db = skip_if_no_db!(test_db().await);
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    seed_user(&db, user_a).await;
    seed_user(&db, user_b).await;

    let id = store(
        &db,
        NewMemory {
            scope_kind: MemoryScopeKind::User,
            scope_ref: &user_a.to_string(),
            owner_principal: user_a,
            parent_entity: None,
            parent_record_id: None,
            kind: "fact",
            summary: "owns a red bicycle",
            facts: &[],
            source_refs: &[],
        },
    )
    .await
    .expect("store");

    let deleted_by_b = attome_search::corpus::memory::forget(&db, user_b, id)
        .await
        .expect("forget call succeeds");
    assert!(
        deleted_by_b.is_none(),
        "user B must not be able to delete user A's memory by id"
    );

    let deleted_by_a = attome_search::corpus::memory::forget(&db, user_a, id)
        .await
        .expect("forget call succeeds");
    assert!(
        deleted_by_a.is_some(),
        "the owner must still be able to forget their own memory, or the \
         refusal above proves nothing"
    );

    cleanup(&db, user_a).await;
    cleanup(&db, user_b).await;
}

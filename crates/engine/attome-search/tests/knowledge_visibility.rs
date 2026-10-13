//! Knowledge-chunk visibility against a real database (TODO-031).
//!
//! The structural tests in `knowledge.rs` assert the fragment's *shape* — that
//! the collection clause is an indexed equality, that the record predicate sits
//! behind the NULL guard. None of that catches a precedence mistake, and there
//! is one waiting: the guard is written as
//! `parent_record_id IS NULL OR TRUE AND EXISTS (...)`, which is correct only
//! because `AND` binds tighter than `OR`. Get that wrong and either every
//! parented chunk becomes visible to everyone, or every unparented chunk
//! disappears — and the fragment reads fine either way.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test knowledge_visibility
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::knowledge::{Audience, KnowledgeVisibility, LifecycleFilter};
use attome_security::visibility::PolymorphicVisibility;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, QueryBuilder};
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

fn ctx(user_id: Uuid, team_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: vec![team_id],
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn seed_chunk(
    db: &DbPool,
    collection: Uuid,
    parent: Option<(&str, Uuid)>,
    lifecycle: &str,
    text: &str,
    ordinal: i32,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO knowledge_chunk \
            (id, collection_ref, source_type, source_id, parent_entity, parent_record_id, \
             lifecycle, ordinal, text_display, text_indexed, tsv) \
         VALUES ($1, $2, 'article', $3, $4, $5, $6, $7, $8, $8, \
                 to_tsvector('attome_search', $8))",
    )
    .bind(id)
    .bind(collection)
    .bind(Uuid::now_v7())
    .bind(parent.map(|(e, _)| e.to_owned()))
    .bind(parent.map(|(_, r)| r))
    .bind(lifecycle)
    .bind(ordinal)
    .bind(text)
    .execute(db)
    .await
    .expect("seed chunk");
    id
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

async fn visible(db: &DbPool, vis: &KnowledgeVisibility<'_>, collection: Uuid) -> Vec<Uuid> {
    let mut qb: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT k.id FROM knowledge_chunk k WHERE k.collection_ref = ");
    qb.push_bind(collection);
    vis.push(&mut qb, "k");

    let mut ids: Vec<Uuid> = qb
        .build_query_scalar()
        .fetch_all(db)
        .await
        .expect("chunk query executes");
    ids.sort();
    ids
}

/// **The precedence assertion, and TODO-031's verify line.**
///
/// Four chunks in one collection: unparented, parented-and-shared,
/// parented-and-not-shared, and a draft. Exactly two must come back, and which
/// two is what the `OR`/`AND` precedence decides.
#[tokio::test]
async fn chunk_visibility_composes_collection_and_record_access() {
    let db = skip_if_no_db!(test_db().await);
    let collection = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let team_id = Uuid::now_v7();

    let entity_ref: Uuid = sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(format!("test_kb_{}", Uuid::now_v7().simple()))
    .fetch_one(&db)
    .await
    .expect("register entity");
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_ref)
            .fetch_one(&db)
            .await
            .expect("read entity name");

    let shared_record = Uuid::now_v7();
    let hidden_record = Uuid::now_v7();
    share(&db, shared_record, entity_ref, user_id).await;

    let standalone = seed_chunk(&db, collection, None, "published", "refund policy", 0).await;
    let parented_visible = seed_chunk(
        &db,
        collection,
        Some((&entity_name, shared_record)),
        "published",
        "contract clause",
        1,
    )
    .await;
    let parented_hidden = seed_chunk(
        &db,
        collection,
        Some((&entity_name, hidden_record)),
        "published",
        "other contract clause",
        2,
    )
    .await;
    let draft = seed_chunk(&db, collection, None, "draft", "unreviewed policy", 3).await;

    let c = ctx(user_id, team_id);
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity_name.clone(), (entity_ref, AccessLevel::Team))].into();
    let empty = HashSet::new();
    let records = PolymorphicVisibility::new(&c, &access, &empty, None);
    let vis = KnowledgeVisibility::new(
        vec![collection],
        &records,
        LifecycleFilter::Published,
        Audience::Internal,
    );

    let mut got = visible(&db, &vis, collection).await;
    got.sort();
    let mut want = vec![standalone, parented_visible];
    want.sort();

    assert_eq!(
        got, want,
        "a chunk with no parent is visible on the collection alone; a parented \
         chunk needs its record too; a draft is never retrieved"
    );
    assert!(
        !got.contains(&parented_hidden),
        "a chunk hanging off a record the caller cannot see must not be \
         readable merely because the collection is"
    );
    assert!(!got.contains(&draft), "a draft must never be retrieved");

    let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE collection_ref = $1")
        .bind(collection)
        .execute(&db)
        .await;
}

/// **TODO-031's verify line, directly.** A caller whose readable-collection
/// list does not contain this collection gets zero chunks from it — with a
/// positive control, because a broken query returning nothing for everybody
/// would pass the security half silently.
#[tokio::test]
async fn a_caller_without_the_collection_gets_zero_chunks_and_the_control_proves_the_query_works() {
    let db = skip_if_no_db!(test_db().await);
    let collection = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let team_id = Uuid::now_v7();

    seed_chunk(&db, collection, None, "published", "visible policy", 0).await;

    let c = ctx(user_id, team_id);
    let access: HashMap<String, (Uuid, AccessLevel)> = HashMap::new();
    let empty = HashSet::new();
    let records = PolymorphicVisibility::new(&c, &access, &empty, None);

    // Without the collection in the readable list.
    let denied = KnowledgeVisibility::new(
        Vec::new(),
        &records,
        LifecycleFilter::Published,
        Audience::Internal,
    );
    assert!(denied.reaches_nothing());
    assert!(
        visible(&db, &denied, collection).await.is_empty(),
        "a caller without read on the collection gets zero chunks from it"
    );

    // The control: with it, the same query returns the chunk.
    let allowed = KnowledgeVisibility::new(
        vec![collection],
        &records,
        LifecycleFilter::Published,
        Audience::Internal,
    );
    assert_eq!(
        visible(&db, &allowed, collection).await.len(),
        1,
        "the same query must return the chunk for a caller who MAY see the \
         collection, or the zero above proves nothing about permissions"
    );

    let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE collection_ref = $1")
        .bind(collection)
        .execute(&db)
        .await;
}

/// `expired` is opt-in and never leaks into the default retrieval.
#[tokio::test]
async fn expired_chunks_are_opt_in() {
    let db = skip_if_no_db!(test_db().await);
    let collection = Uuid::now_v7();
    let c = ctx(Uuid::now_v7(), Uuid::now_v7());
    let access: HashMap<String, (Uuid, AccessLevel)> = HashMap::new();
    let empty = HashSet::new();
    let records = PolymorphicVisibility::new(&c, &access, &empty, None);

    let current = seed_chunk(&db, collection, None, "published", "current policy", 0).await;
    let old = seed_chunk(&db, collection, None, "expired", "superseded policy", 1).await;

    let default = KnowledgeVisibility::new(
        vec![collection],
        &records,
        LifecycleFilter::Published,
        Audience::Internal,
    );
    assert_eq!(visible(&db, &default, collection).await, vec![current]);

    let opted_in = KnowledgeVisibility::new(
        vec![collection],
        &records,
        LifecycleFilter::PublishedAndExpired,
        Audience::Internal,
    );
    let mut got = visible(&db, &opted_in, collection).await;
    got.sort();
    let mut want = vec![current, old];
    want.sort();
    assert_eq!(
        got, want,
        "an expired article is often still the best available answer — the \
         failure is presenting it as current, not returning it"
    );

    let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE collection_ref = $1")
        .bind(collection)
        .execute(&db)
        .await;
}

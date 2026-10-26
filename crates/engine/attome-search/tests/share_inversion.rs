//! The share-driven visibility shape (TODO-053), against a real database.
//!
//! **The only assertion that matters is equivalence.** This is an optimization
//! for a caller who is otherwise §8.1's worst case, and an optimization that
//! changes which rows come back is not an optimization — it is a permission
//! bug wearing a performance costume, and its symptom (a slightly short page)
//! reads as a relevance problem. So every case here runs the *same* query
//! through both shapes and asserts the row sets are identical, including the
//! cases where the answer is "nothing".
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test share_inversion
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::legs::stage1::LexicalLeg;
use attome_search::{SqlLeg, VisibilityShape, legs::push_leg_with_shape};
use attome_security::rls::FastTierColumns;
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

fn ctx(user_id: Uuid, team_ids: Vec<Uuid>, orgs: Vec<Uuid>) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: orgs,
        team_ids,
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

async fn seed_row(db: &DbPool, entity: &str, body: &str) -> Uuid {
    let record_id = Uuid::now_v7();
    let row = attome_search::project("Shared Record", None, body, vec![]);
    attome_search::upsert_row(
        db,
        entity,
        record_id,
        &row,
        Some(Uuid::now_v7()),
        None,
        None,
    )
    .await
    .expect("seed");
    record_id
}

/// Registers an entity so `entity_ref` is a real foreign key, then shares a
/// record with a principal.
async fn seed_entity_info(db: &DbPool, entity: &str) -> Uuid {
    // A plain INSERT: each test mints a fresh logicalname, and
    // `entity_info` carries no unique index on `logicalname` for an
    // `ON CONFLICT` to infer.
    sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(entity)
    .fetch_one(db)
    .await
    .expect("register entity")
}

async fn share(
    db: &DbPool,
    record_id: Uuid,
    entity_ref: Uuid,
    principal_type: i16,
    principal_id: Uuid,
    capability: i16,
) {
    sqlx::query(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .execute(db)
    .await
    .expect("share");
}

/// Runs one leg under a given shape and returns the record ids found.
async fn run(
    db: &DbPool,
    vis: &PolymorphicVisibility<'_>,
    shape: VisibilityShape,
    entity: &str,
    query: &str,
) -> Vec<Uuid> {
    let leg = LexicalLeg {
        stemmed_query: attome_search::index_text(query),
    };
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
    push_leg_with_shape(
        &mut qb,
        &leg as &dyn SqlLeg,
        vis,
        shape,
        "t.entity_logicalname",
        "t.record_id",
    );
    qb.push(" AND t.entity_logicalname = ");
    qb.push_bind(entity.to_string());

    let mut ids: Vec<Uuid> = qb
        .build_query_scalar()
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| panic!("{shape:?} failed to execute: {e}"));
    ids.sort();
    ids
}

/// **The equivalence assertion.** For an eligible caller the two shapes return
/// exactly the same rows — allowed by a direct share, allowed by a team share,
/// denied by a deny row, and absent entirely.
#[tokio::test]
async fn the_two_shapes_agree_on_every_row_for_a_share_only_caller() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_share_{}", Uuid::now_v7().simple());
    let entity_ref = seed_entity_info(&db, &entity).await;

    let user_id = Uuid::now_v7();
    let team_id = Uuid::now_v7();

    let by_user = seed_row(&db, &entity, "quarterly reconciliation notes").await;
    let by_team = seed_row(&db, &entity, "quarterly reconciliation summary").await;
    let denied = seed_row(&db, &entity, "quarterly reconciliation restricted").await;
    let unshared = seed_row(&db, &entity, "quarterly reconciliation private").await;

    share(&db, by_user, entity_ref, 0, user_id, 0).await;
    share(&db, by_team, entity_ref, 1, team_id, 1).await;
    // Shared AND denied. The deny must win under both shapes — a deny row that
    // only the standard shape honours would be a disclosure introduced by an
    // optimization.
    share(&db, denied, entity_ref, 0, user_id, 0).await;
    share(&db, denied, entity_ref, 0, user_id, 2).await;

    let c = ctx(user_id, vec![team_id], Vec::new());
    // Team level, so no fast-tier arm can fire — the share-only shape.
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity.clone(), (entity_ref, AccessLevel::Team))].into();
    let vis = PolymorphicVisibility::new(
        &c,
        &access,
        &HashSet::new(),
        Some(FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );
    assert!(
        vis.share_inversion_eligible(),
        "a Team-level caller with no default share and no accessible orgs is \
         the population this optimization exists for"
    );

    let standard = run(
        &db,
        &vis,
        VisibilityShape::PerRow,
        &entity,
        "quarterly reconciliation",
    )
    .await;
    let inverted = run(
        &db,
        &vis,
        VisibilityShape::ShareSemiJoin,
        &entity,
        "quarterly reconciliation",
    )
    .await;

    assert_eq!(
        standard, inverted,
        "the two shapes must return identical rows; a difference here is a \
         permission bug whose symptom is a short page"
    );
    assert!(standard.contains(&by_user), "the directly-shared record");
    assert!(standard.contains(&by_team), "the team-shared record");
    assert!(
        !standard.contains(&denied),
        "a deny row must win under both shapes"
    );
    assert!(!standard.contains(&unshared), "nothing shares this one");

    let _ = sqlx::query("DELETE FROM search_index WHERE entity_logicalname = $1")
        .bind(&entity)
        .execute(&db)
        .await;
}

/// A caller with a Global grant is **not** eligible.
///
/// Global admits every row of that entity with no share at all, so the inverted
/// shape — which only covers the share arm — would hide everything they are
/// entitled to. The check is structural rather than heuristic for exactly this
/// reason.
#[tokio::test]
async fn a_global_caller_is_not_eligible_for_the_inversion() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_share_{}", Uuid::now_v7().simple());
    let entity_ref = seed_entity_info(&db, &entity).await;
    let c = ctx(Uuid::now_v7(), vec![Uuid::now_v7()], Vec::new());
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity, (entity_ref, AccessLevel::Global))].into();
    let vis = PolymorphicVisibility::new(&c, &access, &HashSet::new(), None);
    assert!(!vis.share_inversion_eligible());
}

/// A BusinessUnit caller with accessible organizations is not eligible: the
/// fast tier admits rows the share table knows nothing about.
#[tokio::test]
async fn a_business_unit_caller_with_orgs_is_not_eligible() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_share_{}", Uuid::now_v7().simple());
    let entity_ref = seed_entity_info(&db, &entity).await;
    let c = ctx(Uuid::now_v7(), vec![Uuid::now_v7()], vec![Uuid::now_v7()]);
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity, (entity_ref, AccessLevel::BusinessUnit))].into();
    let vis = PolymorphicVisibility::new(
        &c,
        &access,
        &HashSet::new(),
        Some(FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    );
    assert!(
        !vis.share_inversion_eligible(),
        "the fast tier admits rows by organization; inverting would hide them"
    );
}

/// An entity-wide default share is not eligible either — it admits every row of
/// the entity without a per-record share row existing at all.
#[tokio::test]
async fn a_default_share_makes_the_caller_ineligible() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_share_{}", Uuid::now_v7().simple());
    let entity_ref = seed_entity_info(&db, &entity).await;
    let c = ctx(Uuid::now_v7(), vec![Uuid::now_v7()], Vec::new());
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity, (entity_ref, AccessLevel::Team))].into();
    let defaults: HashSet<Uuid> = [entity_ref].into();
    let vis = PolymorphicVisibility::new(&c, &access, &defaults, None);
    assert!(
        !vis.share_inversion_eligible(),
        "a default share admits rows with no share row to drive from"
    );
}

/// The planner picks the inversion for an eligible caller under the threshold,
/// and the standard shape otherwise.
#[tokio::test]
async fn the_planner_selects_the_shape_by_eligibility_and_size() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_share_{}", Uuid::now_v7().simple());
    let entity_ref = seed_entity_info(&db, &entity).await;

    let user_id = Uuid::now_v7();
    let c = ctx(user_id, vec![Uuid::now_v7()], Vec::new());
    let access: HashMap<String, (Uuid, AccessLevel)> =
        [(entity, (entity_ref, AccessLevel::Team))].into();
    let vis = PolymorphicVisibility::new(&c, &access, &HashSet::new(), None);

    assert_eq!(
        attome_search::plan_visibility_shape(&db, &vis, user_id, &c.team_ids, &[]).await,
        VisibilityShape::ShareSemiJoin,
        "a share-only caller with few shares is exactly the target"
    );

    // Ineligible callers always get the shape that is correct for everyone.
    let global: HashMap<String, (Uuid, AccessLevel)> =
        [("other".to_string(), (entity_ref, AccessLevel::Global))].into();
    let vis_global = PolymorphicVisibility::new(&c, &global, &HashSet::new(), None);
    assert_eq!(
        attome_search::plan_visibility_shape(&db, &vis_global, user_id, &c.team_ids, &[]).await,
        VisibilityShape::PerRow
    );
}

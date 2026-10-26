//! Every Stage 1 leg's generated SQL must actually **execute** (TODO-012).
//!
//! The unit tests in `legs::stage1` assert the SQL's *shape*: that the fragment
//! is present, that values are bound, that fuzzy matching stays on titles. None
//! of that catches a missing parenthesis, a wrong cast, or a function called
//! with the wrong argument order — a leg can be structurally perfect and still
//! be a syntax error, and a shape-only suite would report green right up until
//! the first real query.
//!
//! So this runs each leg against a real PostgreSQL, with the visibility
//! fragment applied, and asserts it returns rows rather than raising. It also
//! asserts the thing the whole permission design rests on: **a narrowed caller
//! gets zero rows from every leg**, including for a record that plainly matches
//! the query text.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test legs_execute
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::legs::stage1::{ExactKeyLeg, FuzzyLeg, LexicalLeg, PrefixLeg};
use attome_search::{SqlLeg, normalize_ar, push_leg};
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

fn ctx(is_admin: bool, orgs: Vec<Uuid>) -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: orgs,
        team_ids: vec![Uuid::now_v7()],
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// Seeds one indexed row for a throwaway entity name, so assertions can be
/// exact rather than "at least one row somewhere".
async fn seed_row(db: &DbPool, entity: &str, org: Option<Uuid>) -> Uuid {
    let record_id = Uuid::now_v7();
    let title = "ACME Trading LLC";
    sqlx::query(
        "INSERT INTO search_index \
            (corpus, entity_logicalname, record_id, title, title_norm, \
             body_display, body_indexed, exact_keys, tsv, organization_ref) \
         VALUES ('record', $1, $2, $3, $4, $5, $6, $7, \
                 to_tsvector('attome_search', $6), $8)",
    )
    .bind(entity)
    .bind(record_id)
    .bind(title)
    .bind(normalize_ar(title))
    .bind("Invoice for ACME Trading")
    .bind(normalize_ar("Invoice for ACME Trading"))
    .bind(vec!["inv-9001".to_string()])
    .bind(org)
    .execute(db)
    .await
    .expect("seed a search index row");
    record_id
}

fn legs_for(query: &str) -> Vec<Box<dyn SqlLeg>> {
    let norm = normalize_ar(query);
    vec![
        Box::new(ExactKeyLeg {
            normalized_query: norm.clone(),
        }),
        Box::new(PrefixLeg {
            normalized_query: norm.clone(),
        }),
        Box::new(LexicalLeg {
            stemmed_query: norm.clone(),
        }),
        Box::new(FuzzyLeg {
            normalized_query: norm,
            ..FuzzyLeg::default()
        }),
    ]
}

/// Runs one leg and returns the record ids it found for `entity`.
async fn run_leg(
    db: &DbPool,
    leg: &dyn SqlLeg,
    vis: &PolymorphicVisibility<'_>,
    entity: &str,
) -> Vec<Uuid> {
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
    push_leg(&mut qb, leg, vis, "t.entity_logicalname", "t.record_id");
    qb.push(" AND t.entity_logicalname = ");
    qb.push_bind(entity.to_string());

    qb.build_query_scalar::<Uuid>()
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| panic!("leg '{}' failed to execute: {e}", leg.id()))
}

/// Every leg executes without raising, against a real PostgreSQL, with the
/// visibility fragment spliced in. This is the half the shape tests cannot
/// reach.
#[tokio::test]
async fn every_stage_one_leg_executes_as_admin() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legs_{}", Uuid::now_v7().simple());
    let record_id = seed_row(&db, &entity, None).await;

    // Admin: unfiltered, so this measures the leg's own SQL rather than the
    // permission filter.
    let c = ctx(true, Vec::new());
    let vis = PolymorphicVisibility::new(&c, &HashMap::new(), &HashSet::new(), None);
    assert!(vis.is_unfiltered());

    // Each leg is matched with a query it should find the seeded row by.
    let cases: Vec<(Box<dyn SqlLeg>, &str)> = vec![
        (
            Box::new(ExactKeyLeg {
                normalized_query: "inv-9001".into(),
            }),
            "exact key",
        ),
        (
            Box::new(PrefixLeg {
                normalized_query: "acme".into(),
            }),
            "title prefix",
        ),
        (
            Box::new(LexicalLeg {
                stemmed_query: "invoice".into(),
            }),
            "lexical body match",
        ),
        (
            Box::new(FuzzyLeg {
                normalized_query: "acme trading llc".into(),
                ..FuzzyLeg::default()
            }),
            "trigram title similarity",
        ),
    ];

    for (leg, what) in cases {
        let found = run_leg(&db, leg.as_ref(), &vis, &entity).await;
        assert!(
            found.contains(&record_id),
            "leg '{}' ({what}) did not find the seeded row — found {found:?}",
            leg.id()
        );
    }
}

/// **The permission assertion.** A caller with no privilege on the entity gets
/// zero rows from every leg, for a record that plainly matches the query text.
///
/// This is what the whole `push_leg`/census design exists to guarantee, and
/// asserting it against a real database is the only way to know the generated
/// fragment actually filters rather than merely being present in the string.
#[tokio::test]
async fn a_caller_with_no_privilege_gets_nothing_from_any_leg() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legs_{}", Uuid::now_v7().simple());
    seed_row(&db, &entity, None).await;

    // An empty access map means "holds no read privilege on any entity" —
    // `array_position` finds no position, `m.pos` is NULL, the EXISTS is false.
    let c = ctx(false, Vec::new());
    let vis = PolymorphicVisibility::new(&c, &HashMap::new(), &HashSet::new(), None);
    assert!(!vis.is_unfiltered());

    for leg in legs_for("acme") {
        let found = run_leg(&db, leg.as_ref(), &vis, &entity).await;
        assert!(
            found.is_empty(),
            "leg '{}' returned {found:?} to a caller holding no read privilege \
             on the entity — this is the disclosure the fragment exists to \
             prevent",
            leg.id()
        );
    }

    // And the exact-key leg specifically, which is the one a user reaches by
    // pasting an identifier they may have obtained elsewhere.
    let exact = ExactKeyLeg {
        normalized_query: "inv-9001".into(),
    };
    assert!(
        run_leg(&db, &exact, &vis, &entity).await.is_empty(),
        "an exact identifier match must not bypass the permission filter"
    );
}

/// The BusinessUnit fast tier admits an org-matched row — and only when the
/// caller's depth on that entity is actually BusinessUnit.
#[tokio::test]
async fn the_fast_tier_admits_an_org_match_at_business_unit_depth() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_legs_{}", Uuid::now_v7().simple());
    let org = Uuid::now_v7();
    let entity_ref = Uuid::now_v7();
    let record_id = seed_row(&db, &entity, Some(org)).await;

    let tier = attome_security::FastTierColumns {
        organization_ref: "t.organization_ref",
    };
    let leg = PrefixLeg {
        normalized_query: "acme".into(),
    };

    // BusinessUnit depth + the row's own org in the caller's set: admitted.
    let bu = ctx(false, vec![org]);
    let mut map = HashMap::new();
    map.insert(entity.clone(), (entity_ref, AccessLevel::BusinessUnit));
    let vis = PolymorphicVisibility::new(&bu, &map, &HashSet::new(), Some(tier));
    assert!(
        run_leg(&db, &leg, &vis, &entity).await.contains(&record_id),
        "a BU-depth caller whose org matches the row must see it"
    );

    // Same caller, same org, but Team depth: the tier must not fire, and with
    // no share row there is nothing else to admit it.
    let mut team_map = HashMap::new();
    team_map.insert(entity.clone(), (entity_ref, AccessLevel::Team));
    let team_vis = PolymorphicVisibility::new(&bu, &team_map, &HashSet::new(), Some(tier));
    assert!(
        run_leg(&db, &leg, &team_vis, &entity).await.is_empty(),
        "the fast tier is gated on BusinessUnit depth — a Team-depth caller \
         must fall through to the share checks and find nothing"
    );

    // BU depth but a DIFFERENT org: not admitted.
    let other_org = ctx(false, vec![Uuid::now_v7()]);
    let other_vis = PolymorphicVisibility::new(&other_org, &map, &HashSet::new(), Some(tier));
    assert!(
        run_leg(&db, &leg, &other_vis, &entity).await.is_empty(),
        "the tier must match the row's own organization, not merely exist"
    );
}

// ── The fused statement (TODO-012's second half) ─────────────────────────────

/// The fused phase must **execute**, return RRF-ordered rows, and carry its
/// per-leg counts back in one round trip.
///
/// The unit tests assert the statement's shape; only this catches a planner
/// error, a type mismatch in the `jsonb_object_agg`, or a window function used
/// where PostgreSQL will not accept one.
#[tokio::test]
async fn the_fused_phase_executes_and_returns_ranked_rows() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_fuse_{}", Uuid::now_v7().simple());
    let record_id = seed_row(&db, &entity, None).await;

    let c = ctx(true, Vec::new());
    let vis = PolymorphicVisibility::new(&c, &HashMap::new(), &HashSet::new(), None);

    // Queries chosen so several legs match the same row — which is the case
    // RRF exists for, and the case a single-leg test would never exercise.
    let owned: Vec<Box<dyn SqlLeg>> = vec![
        Box::new(ExactKeyLeg {
            normalized_query: "inv-9001".into(),
        }),
        Box::new(PrefixLeg {
            normalized_query: "acme".into(),
        }),
        Box::new(LexicalLeg {
            stemmed_query: "invoice".into(),
        }),
        Box::new(FuzzyLeg {
            normalized_query: "acme trading llc".into(),
            ..FuzzyLeg::default()
        }),
    ];
    let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();

    let mut qb = attome_search::build_phase(
        &refs,
        attome_search::LegPhase::Immediate,
        &vis,
        "t.entity_logicalname",
        "t.record_id",
        50,
    )
    .expect("Stage 1 has immediate legs");

    let rows: Vec<(Uuid, String, f64, Vec<String>, serde_json::Value)> = qb
        .build_query_as()
        .fetch_all(&db)
        .await
        .expect("the fused statement must execute");

    let ours = rows
        .iter()
        .find(|(id, _, _, _, _)| *id == record_id)
        .unwrap_or_else(|| panic!("the seeded row must be found; got {} rows", rows.len()));

    let (_, found_entity, rrf, matched_legs, leg_counts) = ours;
    assert_eq!(found_entity, &entity);
    assert!(*rrf > 0.0, "RRF must be positive");
    assert!(
        matched_legs.len() >= 2,
        "several legs should match this row — that is what RRF fuses: \
         {matched_legs:?}"
    );

    // The per-leg counts survive the grouping and come back in the same round
    // trip, which is what lets a caller report `degraded[]` without a second
    // statement.
    let per_leg =
        attome_search::interpret_counts(&refs, attome_search::LegPhase::Immediate, leg_counts);
    assert_eq!(per_leg.len(), 4, "every leg must be accounted for");
    assert!(
        per_leg
            .values()
            .all(|c| *c == attome_search::Completeness::Complete),
        "one seeded row is nowhere near any ceiling: {per_leg:?}"
    );
}

/// Fusing must not become a way to lose the permission filter. A narrowed
/// caller gets nothing from the fused statement, exactly as from each leg
/// individually — a `UNION ALL` of four unguarded legs would be a disclosure
/// with a very tidy execution plan.
#[tokio::test]
async fn the_fused_phase_returns_nothing_to_a_caller_with_no_privilege() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_fuse_{}", Uuid::now_v7().simple());
    seed_row(&db, &entity, None).await;

    let c = ctx(false, Vec::new());
    let vis = PolymorphicVisibility::new(&c, &HashMap::new(), &HashSet::new(), None);

    let owned = legs_for("acme");
    let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();
    let mut qb = attome_search::build_phase(
        &refs,
        attome_search::LegPhase::Immediate,
        &vis,
        "t.entity_logicalname",
        "t.record_id",
        50,
    )
    .expect("immediate legs exist");

    let rows: Vec<(Uuid, String, f64, Vec<String>, serde_json::Value)> = qb
        .build_query_as()
        .fetch_all(&db)
        .await
        .expect("the fused statement must execute");

    assert!(
        !rows.iter().any(|(_, e, _, _, _)| e == &entity),
        "a caller holding no read privilege must get nothing from the fused \
         statement, not merely from each leg in isolation"
    );
}

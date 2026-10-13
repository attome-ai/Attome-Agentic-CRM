//! Shared seeding and retrieval plumbing for the two evaluation harnesses.
//!
//! `ranking_eval` (TODO-023) and `coverage_eval` (TODO-024) score **the same
//! corpus** through **the same retrieval path** with different metrics. That is
//! the point of TODO-024: two numbers over one pipeline, not two pipelines. A
//! second copy of the seeding or the query construction would let the two
//! measure subtly different systems, and the first symptom would be a coverage
//! result nobody could reconcile with the ranking one.

#![allow(dead_code)]

pub const GOLDEN: &str = include_str!("../fixtures/golden.json");
pub const K: usize = 10;

use attome_db::DbPool;
use attome_search::eval::GoldenSet;
use attome_search::legs::stage1::{ExactKeyLeg, FuzzyLeg, LexicalLeg, PrefixLeg};
use attome_search::{Candidate, LegPhase, LinearRanker, Ranker, SqlLeg, build_phase, extract_all};
use attome_security::rls::FastTierColumns;
use attome_security::visibility::PolymorphicVisibility;
use attome_server::security::{AccessLevel, SecurityContext};
use sqlx::Executor;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Candidates pulled from the fused statement before reranking. Wider than `K`
/// on purpose: a ranker that can only reorder ten results cannot recover a
/// relevant document sitting at fused rank 30, and a harness that fetched only
/// ten would measure the fusion rather than the ranking.
pub const CANDIDATE_DEPTH: i64 = 50;

pub fn golden() -> GoldenSet {
    let set = GoldenSet::parse(GOLDEN).expect("golden.json must parse");
    set.validate()
        .expect("golden.json must be internally valid");
    set
}

/// The pool both harnesses seed through.
///
/// `statement_timeout` is raised per connection because the filler below
/// inserts its whole chaff corpus in one statement, running `to_tsvector` over
/// every row. Migration `0018_role_statement_timeout.sql` leaves every platform
/// role at 500 ms -- the production fast-read bound -- and that batched seed
/// does not fit inside it on a machine that is doing anything else. Verified
/// 2026-08-25: two consecutive `cargo llvm-cov -p attome-search` runs and a plain
/// `cargo test` run all failed every seeding test in `coverage_eval` and
/// `ranking_eval` identically, `57014 canceling statement due to statement
/// timeout` raised by this filler. Instrumentation is not the trigger and the
/// suites are not flaky -- they were simply authored against an idle box.
/// Set via `after_connect` so it survives pool recycling, and bounded rather
/// than `0` so a genuinely wedged seed still fails instead of hanging the
/// suite -- the same argument, and the same value, as `attome-testkit`'s
/// `admin_connection`.
pub async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET statement_timeout = '300s'").await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// The seeded world: which UUID each fixture document got, and the two orgs.
pub struct Seeded {
    pub by_key: HashMap<String, Uuid>,
    pub by_id: HashMap<Uuid, String>,
    pub age_days: HashMap<Uuid, f64>,
    pub entities: Vec<String>,
    pub org_main: Uuid,
    pub org_restricted: Uuid,
}

pub fn ctx(orgs: Vec<Uuid>) -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        // Never an admin. See the module doc.
        is_admin: false,
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
        service_principal: false,
    }
}

/// Every seeded entity at `BusinessUnit`, so the organization fast tier is the
/// arm that decides — the same shape a real deployment's narrowed user hits.
pub fn access_map(seeded: &Seeded) -> HashMap<String, (Uuid, AccessLevel)> {
    seeded
        .entities
        .iter()
        .map(|e| (e.clone(), (Uuid::now_v7(), AccessLevel::BusinessUnit)))
        .collect()
}

pub fn visibility<'a>(
    c: &'a SecurityContext,
    access: &'a HashMap<String, (Uuid, AccessLevel)>,
    empty: &'a HashSet<Uuid>,
) -> PolymorphicVisibility<'a> {
    PolymorphicVisibility::new(
        c,
        access,
        empty,
        Some(FastTierColumns {
            organization_ref: "t.organization_ref",
        }),
    )
}

pub async fn seed(db: &DbPool, set: &GoldenSet) -> Seeded {
    let org_main = Uuid::now_v7();
    let org_restricted = Uuid::now_v7();
    let mut by_key = HashMap::new();
    let mut by_id = HashMap::new();
    let mut age_days = HashMap::new();
    let mut entities: Vec<String> = Vec::new();

    for doc in &set.corpus {
        let id = Uuid::now_v7();
        let org = match doc.org.as_deref() {
            Some("restricted") => org_restricted,
            _ => org_main,
        };
        let row = attome_search::project(&doc.title, None, &doc.body, doc.exact_keys.clone());
        let modified = chrono::Utc::now() - chrono::Duration::days(doc.age_days);
        attome_search::upsert_row(db, &doc.entity, id, &row, Some(org), None, Some(modified))
            .await
            .expect("seed corpus document");
        by_key.insert(doc.key.clone(), id);
        by_id.insert(id, doc.key.clone());
        age_days.insert(id, doc.age_days as f64);
        if !entities.contains(&doc.entity) {
            entities.push(doc.entity.clone());
        }
    }

    // The declared chaff, expanded here. One batched insert rather than 2000
    // round trips — at one statement each this takes minutes, which is the
    // difference between a harness people run and one they skip.
    for spec in &set.filler {
        let mut ids = Vec::with_capacity(spec.count);
        let mut titles = Vec::with_capacity(spec.count);
        let mut norms = Vec::with_capacity(spec.count);
        let mut bodies = Vec::with_capacity(spec.count);
        for n in 0..spec.count {
            let id = Uuid::now_v7();
            let title = spec.title.replace("{n}", &n.to_string());
            ids.push(id);
            norms.push(attome_search::normalize_ar(&title));
            titles.push(title);
            bodies.push(attome_search::index_text(&spec.body));
            age_days.insert(id, spec.age_days as f64);
        }
        let modified = chrono::Utc::now() - chrono::Duration::days(spec.age_days);
        sqlx::query(
            "INSERT INTO search_index \
                (corpus, entity_logicalname, record_id, title, title_norm, \
                 body_display, body_indexed, exact_keys, tsv, organization_ref, \
                 source_modifiedon, indexed_at) \
             SELECT 'record', $1, u.id, u.title, u.norm, u.title, u.body, ARRAY[]::text[], \
                    to_tsvector('attome_search', u.norm || ' ' || u.body), $6, $7, NOW() \
               FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[]) \
                    AS u(id, title, norm, body)",
        )
        .bind(&spec.entity)
        .bind(&ids)
        .bind(&titles)
        .bind(&norms)
        .bind(&bodies)
        .bind(org_main)
        .bind(modified)
        .execute(db)
        .await
        .expect("seed filler");
        if !entities.contains(&spec.entity) {
            entities.push(spec.entity.clone());
        }
    }

    Seeded {
        by_key,
        by_id,
        age_days,
        entities,
        org_main,
        org_restricted,
    }
}

/// The legs, built from one query exactly as the query route builds them.
///
/// Normalization and stemming come from `lang::` and are applied here, not
/// inside a leg — the same functions the drain ran at index time. A leg that
/// normalized its own input would be a second implementation of the one
/// symmetry the whole engine rests on.
pub fn legs_for(query: &str) -> Vec<Box<dyn SqlLeg>> {
    let norm = attome_search::normalize_ar(query);
    vec![
        Box::new(ExactKeyLeg {
            normalized_query: norm.clone(),
        }),
        Box::new(PrefixLeg {
            normalized_query: norm.clone(),
        }),
        Box::new(LexicalLeg {
            stemmed_query: attome_search::index_text(query),
        }),
        Box::new(FuzzyLeg {
            normalized_query: norm,
            ..FuzzyLeg::default()
        }),
    ]
}

/// A context for an explicit user id — the share-only caller's counterpart to
/// [`ctx`], which mints a fresh id each call.
pub fn ctx_for(user_id: Uuid, orgs: Vec<Uuid>) -> SecurityContext {
    SecurityContext {
        user_id,
        ..ctx(orgs)
    }
}

/// [`run_query`] against an already-built visibility, with an explicit shape.
///
/// Takes the visibility rather than building one so a caller can assert its
/// eligibility first — a test that silently built an ineligible one would
/// compare two shapes that are not supposed to agree.
pub async fn run_query_with_shape(
    db: &DbPool,
    seeded: &Seeded,
    vis: &PolymorphicVisibility<'_>,
    shape: attome_search::VisibilityShape,
    query: &str,
) -> Vec<String> {
    let boxed = legs_for(query);
    let legs: Vec<&dyn SqlLeg> = boxed.iter().map(|l| l.as_ref()).collect();
    let Some(mut qb) = attome_search::legs::fuse::build_phase_with_shape(
        &legs,
        LegPhase::Immediate,
        vis,
        shape,
        "t.entity_logicalname",
        "t.record_id",
        CANDIDATE_DEPTH,
    ) else {
        return Vec::new();
    };

    let rows = qb
        .build()
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| panic!("query '{query}' under {shape:?} failed: {e}"));

    rank(seeded, rows)
}

/// Applies the shipped ranker to a fused result set.
fn rank(seeded: &Seeded, rows: Vec<sqlx::postgres::PgRow>) -> Vec<String> {
    let ranker = LinearRanker;
    let mut scored: Vec<(f64, String)> = rows
        .iter()
        .filter_map(|row| {
            let id: Uuid = row.get("record_id");
            let key = seeded.by_id.get(&id)?;
            let matched: Vec<String> = row.get("matched_legs");
            let features = extract_all(&Candidate {
                rrf: row.get::<f64, _>("rrf"),
                matched_legs: &matched,
                age_days: seeded.age_days.get(&id).copied().unwrap_or(0.0),
                caller_owns: false,
                caller_last_viewed_days: None,
            });
            Some((ranker.score(&features), key.clone()))
        })
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, key)| key).collect()
}

/// Runs one query end to end and returns the ranked document keys.
pub async fn run_query(
    db: &DbPool,
    seeded: &Seeded,
    c: &SecurityContext,
    query: &str,
) -> Vec<String> {
    let access = access_map(seeded);
    let empty = HashSet::new();
    let vis = visibility(c, &access, &empty);
    assert!(
        !vis.is_unfiltered(),
        "the harness must never run as an admin — an unfiltered caller skips \
         the visibility fragment entirely and measures a query the product \
         never executes"
    );

    let boxed = legs_for(query);
    let legs: Vec<&dyn SqlLeg> = boxed.iter().map(|l| l.as_ref()).collect();
    let Some(mut qb) = build_phase(
        &legs,
        LegPhase::Immediate,
        &vis,
        "t.entity_logicalname",
        "t.record_id",
        CANDIDATE_DEPTH,
    ) else {
        return Vec::new();
    };

    let rows = qb
        .build()
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| panic!("query '{query}' failed: {e}"));

    // Rerank the fused candidates with the shipped ranker. This is what makes
    // the harness measure ranking rather than fusion.
    let ranker = LinearRanker;
    let mut scored: Vec<(f64, String)> = rows
        .iter()
        .filter_map(|row| {
            let id: Uuid = row.get("record_id");
            let key = seeded.by_id.get(&id)?;
            let matched: Vec<String> = row.get("matched_legs");
            let features = extract_all(&Candidate {
                rrf: row.get::<f64, _>("rrf"),
                matched_legs: &matched,
                age_days: seeded.age_days.get(&id).copied().unwrap_or(0.0),
                caller_owns: false,
                caller_last_viewed_days: None,
            });
            Some((ranker.score(&features), key.clone()))
        })
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, key)| key).collect()
}

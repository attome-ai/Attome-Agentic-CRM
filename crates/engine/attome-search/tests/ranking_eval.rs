//! The retrieval evaluation harness (TODO-023).
//!
//! Seeds the golden corpus into a real PostgreSQL, runs every fixture query
//! through the **shipped** retrieval path — the four Stage 1 legs, RRF fusion,
//! and `LinearRanker` — and scores the result with recall@10, MRR@10 and
//! nDCG@10, broken down by query kind, against a committed baseline.
//!
//! Three properties this harness has that a naive one would not:
//!
//! **It runs as a narrowed caller, never as an admin.** `is_unfiltered()`
//! short-circuits the whole visibility fragment for an admin, so an admin-run
//! harness measures a query the product never executes (the risk TODO-027
//! names). Every scored query here goes through the real `EXISTS` filter.
//!
//! **The forbidden cases are hard assertions, not metrics.** A caller who must
//! see nothing is scored pass/fail and never averaged — an aggregate absorbs a
//! leak, and "the mean dipped" is not how a disclosure should surface. Each
//! one is paired with a **positive control** proving the same query returns the
//! record for a caller who *may* see it. Without that control, a broken query
//! that returns nothing for everybody would pass the security assertion
//! silently.
//!
//! **The baseline is fingerprinted.** Comparing today's mean against one
//! recorded on a different corpus is meaningless, and is the natural thing to
//! do by accident. When the fixture changes, the harness says "re-record",
//! rather than comparing two different things and reporting a number.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test ranking_eval -- --nocapture
//! # to re-record after a deliberate fixture or ranking change:
//! $env:UPDATE_RANKING_BASELINE = "1"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_search::eval::{
    Baseline, CaseResult, EvalReport, QueryCase, QueryKind, check_regression, fixture_fingerprint,
    ndcg_at_k, recall_at_k, reciprocal_rank,
};
use attome_testkit::skip_if_no_db;
use std::collections::{BTreeMap, HashSet};

mod harness;
use harness::{K, ctx, golden, run_query, seed, test_db};

const BASELINE: &str = include_str!("fixtures/ranking_baseline.json");

/// The fixture is well-formed and covers what it claims to. No database.
///
/// A harness whose fixture silently lost its Arabic cases would keep reporting
/// a healthy overall number — Arabic is exactly the group that degrades without
/// an error.
#[test]
fn the_fixture_is_wellformed_and_covers_every_kind() {
    let set = golden();
    assert!(
        set.queries.len() >= 40,
        "TODO-023 starts at 40 queries; 200 before any weight is tuned, because \
         nDCG@10 over 40 has too much variance to tune against"
    );

    let mut by_kind: BTreeMap<QueryKind, usize> = BTreeMap::new();
    for q in &set.queries {
        *by_kind.entry(q.kind).or_default() += 1;
    }
    for kind in [
        QueryKind::ExactKey,
        QueryKind::Lexical,
        QueryKind::Arabic,
        QueryKind::Fuzzy,
        QueryKind::Prefix,
        QueryKind::Recency,
        QueryKind::Forbidden,
    ] {
        assert!(by_kind.contains_key(&kind), "no {kind:?} queries");
    }
    assert!(
        by_kind[&QueryKind::Arabic] >= 8,
        "the Arabic vectors need real coverage, not a token case: F206 names \
         Arabic as the moat and it is the group that fails silently"
    );
    assert!(
        set.queries
            .iter()
            .any(|q| q.kind == QueryKind::Recency && q.judgments.iter().any(|j| j.beyond_ceiling)),
        "the recency-vs-ceiling case must be present and marked, or the \
         harness quietly stops testing the one interaction the plan calls out"
    );
    assert!(
        set.filler.iter().map(|f| f.count).sum::<usize>() >= 1_500,
        "the recency case needs enough chaff to push its target past the \
         per-leg ceiling of {}",
        attome_search::legs::stage1::LEG_CEILING
    );
}

/// The scored evaluation, against the committed baseline.
#[tokio::test]
async fn retrieval_scores_hold_against_the_baseline() {
    let db = skip_if_no_db!(test_db().await);
    let set = golden();
    let seeded = seed(&db, &set).await;

    let primary = ctx(vec![seeded.org_main, seeded.org_restricted]);
    let narrowed = ctx(vec![seeded.org_main]);

    let mut cases = Vec::new();
    for q in &set.queries {
        if q.kind == QueryKind::Forbidden {
            continue; // asserted, never scored — see the module doc.
        }
        let caller = if q.caller == "narrowed" {
            &narrowed
        } else {
            &primary
        };
        let ranked = run_query(&db, &seeded, caller, &q.query).await;

        // Relevant documents that were never candidates at any rank. Reported
        // apart from a low score because the fix is different: rank 40 is a
        // ranking problem, absent is a retrieval problem no weight can touch.
        let returned: HashSet<&String> = ranked.iter().collect();
        let missed_entirely: Vec<String> = q
            .judgments
            .iter()
            .filter(|j| j.grade >= 2 && !returned.contains(&j.doc))
            .map(|j| j.doc.clone())
            .collect();

        cases.push(CaseResult {
            id: q.id.clone(),
            kind: q.kind,
            ndcg: ndcg_at_k(&ranked, &q.judgments, K),
            mrr: reciprocal_rank(&ranked, &q.judgments, K),
            recall: recall_at_k(&ranked, &q.judgments, K),
            missed_entirely,
        });
    }

    let report = EvalReport::build(K, cases);
    println!("{}", report.render());

    let fingerprint = fixture_fingerprint(&set);
    if std::env::var("UPDATE_RANKING_BASELINE").is_ok() {
        let baseline = Baseline {
            fixture_fingerprint: fingerprint,
            k: K,
            overall: report.overall,
            by_kind: report.by_kind.clone(),
        };
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ranking_baseline.json"
        );
        std::fs::write(
            path,
            serde_json::to_string_pretty(&baseline).unwrap() + "\n",
        )
        .expect("write baseline");
        println!("re-recorded {path}");
        return;
    }

    let baseline: Baseline = serde_json::from_str(BASELINE).expect("baseline must parse");
    assert_eq!(
        baseline.fixture_fingerprint, fingerprint,
        "the fixture changed since the baseline was recorded — comparing a \
         score against a baseline from a different corpus is meaningless. \
         Re-record with UPDATE_RANKING_BASELINE=1 and review the diff."
    );
    let failures = check_regression(&report, &baseline);
    assert!(
        failures.is_empty(),
        "retrieval quality regressed:\n  {}\n\n{}",
        failures.join("\n  "),
        report.render()
    );
}

/// A caller who may not see a record gets **zero rows** — and the same query
/// returns it for a caller who may.
///
/// The positive control is not ceremony. "Returns nothing" is also what a
/// query with a typo'd table name, a broken normalization, or an empty corpus
/// returns, and every one of those would pass the security half on its own.
#[tokio::test]
async fn a_narrowed_caller_gets_zero_rows_and_the_control_proves_the_query_works() {
    let db = skip_if_no_db!(test_db().await);
    let set = golden();
    let seeded = seed(&db, &set).await;

    let primary = ctx(vec![seeded.org_main, seeded.org_restricted]);
    let narrowed = ctx(vec![seeded.org_main]);

    // Every restricted document, by key — what must never surface.
    let restricted: HashSet<String> = set
        .corpus
        .iter()
        .filter(|d| d.org.as_deref() == Some("restricted"))
        .map(|d| d.key.clone())
        .collect();
    assert!(
        !restricted.is_empty(),
        "the fixture must seed restricted docs"
    );

    let forbidden: Vec<&QueryCase> = set
        .queries
        .iter()
        .filter(|q| q.kind == QueryKind::Forbidden)
        .collect();
    assert!(forbidden.len() >= 3, "each leg needs its own leak case");

    for q in forbidden {
        let leaked = run_query(&db, &seeded, &narrowed, &q.query).await;
        let leaked_restricted: Vec<&String> =
            leaked.iter().filter(|k| restricted.contains(*k)).collect();
        assert!(
            leaked_restricted.is_empty(),
            "{} leaked {:?} to a caller who may not see it — {}",
            q.id,
            leaked_restricted,
            q.note
        );

        // The control: the identical query, for a caller who may see it.
        let allowed = run_query(&db, &seeded, &primary, &q.query).await;
        assert!(
            allowed.iter().any(|k| restricted.contains(k)),
            "{} returned nothing for a caller who MAY see the record, so its \
             zero-result assertion above proves nothing about permissions",
            q.id
        );
    }
}

/// The one document `beyond_ceiling` marks is genuinely unreachable — and the
/// harness reports it as **never retrieved**, not merely ranked low.
///
/// Two thousand older documents share the query's exact wording, so the record
/// touched today sits past the per-leg ceiling of 500. This asserts the harness
/// can *see* that class of failure; a harness that only reported a mean would
/// show a small dip and no indication that the cause is retrieval rather than
/// ranking, which are fixed in completely different places.
#[tokio::test]
async fn the_recency_case_is_reported_as_never_retrieved_not_as_a_low_score() {
    let db = skip_if_no_db!(test_db().await);
    let set = golden();
    let seeded = seed(&db, &set).await;
    let primary = ctx(vec![seeded.org_main, seeded.org_restricted]);

    let case = set
        .queries
        .iter()
        .find(|q| q.kind == QueryKind::Recency)
        .expect("the fixture carries the recency case");
    let target = &case.judgments[0].doc;
    assert!(
        seeded.by_key.contains_key(target),
        "the target must be seeded"
    );

    let ranked = run_query(&db, &seeded, &primary, &case.query).await;
    let found = ranked.iter().any(|k| k == target);
    let recall = recall_at_k(&ranked, &case.judgments, K).expect("graded");

    println!(
        "recency case: target {} {} in top {K}, recall {recall:.3}, \
         {} chaff documents ahead of it",
        target,
        if found { "IS" } else { "is NOT" },
        set.filler.iter().map(|f| f.count).sum::<usize>(),
    );

    // The assertion is about the *harness*, not about today's ranking: recall
    // and "never retrieved" must agree. If a future recency-ordered leg makes
    // the target reachable, this still passes — what must not happen is the
    // two disagreeing, which would mean the report's per-case diagnosis is
    // wrong and someone would go tune weights for a retrieval problem.
    assert_eq!(
        found,
        recall > 0.0,
        "recall and retrieval must agree, or the report sends whoever reads it \
         to the wrong layer"
    );
}

/// A **share-only caller** scores the same as an equivalently-permitted one
/// (TODO-053).
///
/// The golden set's own share-only case. `share_inversion.rs` proves the two
/// visibility shapes agree at the level of one leg; this proves it survives the
/// whole pipeline — four legs, RRF fusion, the ranker, and paging — because an
/// optimization that changes retrieval *ordering* is as damaging as one that
/// changes membership, and neither shows up as an error.
#[tokio::test]
async fn a_share_only_caller_gets_the_same_ranked_list_under_both_shapes() {
    use attome_search::VisibilityShape;

    let db = skip_if_no_db!(test_db().await);
    let set = golden();
    let seeded = seed(&db, &set).await;

    // Register the entities so `entity_ref` is real, then share every corpus
    // document with one user. The caller reaches the same corpus as `primary`,
    // but reaches it entirely through share rows.
    let user_id = uuid::Uuid::now_v7();
    let mut access = std::collections::HashMap::new();
    for entity in &seeded.entities {
        let entity_ref: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO entity_info (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
        )
        .bind(entity)
        .fetch_one(&db)
        .await
        .expect("register entity");
        access.insert(
            entity.clone(),
            (entity_ref, attome_server::security::AccessLevel::Team),
        );
        for (key, id) in &seeded.by_key {
            if set
                .corpus
                .iter()
                .any(|d| &d.key == key && &d.entity == entity)
            {
                sqlx::query(
                    "INSERT INTO record_share \
                        (record_id, entity_ref, principal_type, principal_id, capability) \
                     VALUES ($1, $2, 0, $3, 0) ON CONFLICT DO NOTHING",
                )
                .bind(id)
                .bind(entity_ref)
                .bind(user_id)
                .execute(&db)
                .await
                .expect("share");
            }
        }
    }

    // No accessible organizations, so no fast-tier arm can fire.
    let c = harness::ctx_for(user_id, Vec::new());
    let empty = std::collections::HashSet::new();
    let vis = harness::visibility(&c, &access, &empty);
    assert!(
        vis.share_inversion_eligible(),
        "the caller must be share-only, or this measures nothing"
    );

    for q in set
        .queries
        .iter()
        .filter(|q| q.kind != QueryKind::Forbidden && q.kind != QueryKind::Recency)
    {
        let standard =
            harness::run_query_with_shape(&db, &seeded, &vis, VisibilityShape::PerRow, &q.query)
                .await;
        let inverted = harness::run_query_with_shape(
            &db,
            &seeded,
            &vis,
            VisibilityShape::ShareSemiJoin,
            &q.query,
        )
        .await;
        assert_eq!(
            standard, inverted,
            "{}: the ranked list must be identical under both shapes",
            q.id
        );
        assert!(
            !standard.is_empty() || q.kind == QueryKind::Fuzzy,
            "{}: a share-only caller reaching the whole corpus must still find \
             results, or this test passes by finding nothing under both shapes",
            q.id
        );
    }
}

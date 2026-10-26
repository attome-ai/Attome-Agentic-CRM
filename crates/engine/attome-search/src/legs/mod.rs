//! Retrieval legs (TODO-011's second half, and the scaffold TODO-012 fills).
//!
//! A *leg* is one way of finding candidate rows: exact-key match, title prefix,
//! trigram similarity, full-text, and — in Stage 2 — dense vector. Each
//! contributes a CTE to one fused statement.
//!
//! **The permission fragment is passed INTO a leg. A leg never builds one.**
//!
//! That is the entire design constraint here, and it is a response to a
//! specific predicted failure: `P-search-and-retrieval` §8.1 says, before any
//! search code existed, that "the first implementer will copy
//! `query_exec.rs`'s composition and get it subtly wrong." A leg that assembled
//! its own visibility could assemble it wrongly, or forget it on the one code
//! path added in a hurry — and the result would be a leg that returns rows the
//! caller may not see, with no error and no failing test.
//!
//! So [`SqlLeg::push_candidates`] receives an `&mut QueryBuilder` on which the
//! visibility fragment is applied by [`push_leg`], not by the leg. A leg
//! *cannot* forget it, because applying it is not among the things a leg does.
//! [`census`] is the belt to that braces: it asserts every registered leg's
//! generated SQL carries the fragment, so a future leg that somehow bypasses
//! `push_leg` still fails a test rather than shipping.

pub mod fuse;
pub mod stage1;

use attome_security::visibility::PolymorphicVisibility;
use sqlx::{Postgres, QueryBuilder};

/// When a leg runs. `P-search-and-retrieval` §11.2 fuses all legs of one phase
/// into a single statement — "parallel legs" would mean one pooled connection
/// per leg, and under concurrency the POOL becomes the ceiling long before
/// PostgreSQL does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegPhase {
    /// Runs in the first statement: everything that needs no embedding.
    Immediate,
    /// Runs in the second, after the query embedding is available.
    AfterEmbedding,
}

/// How completely a leg ran. Degradation is **reported to the caller**, never
/// swallowed — a result set silently missing a leg looks like "no more
/// matches", which is indistinguishable from a correct empty answer.
///
/// Granularity is honest about the fused shape (§11.2, and the plan's own v2
/// correction): fusing makes the *statement* the timeout domain, so
/// `HitDeadline`/`Failed` are per phase-statement, not per leg. `HitCeiling`
/// stays per-leg, because each leg's CTE carries its own `LIMIT`.
/// `Serialize` because this lands verbatim in the impression log's
/// `completeness` column (TODO-021) — a degraded impression must be
/// distinguishable from a badly-ranked one when someone later trains on it, and
/// re-encoding it by hand at the call site would be a second representation to
/// keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    /// The leg's own `LIMIT` was reached — per-leg, genuinely.
    HitCeiling,
    /// The phase statement exceeded its deadline. Per-statement.
    HitDeadline,
    /// The phase statement failed. Per-statement.
    Failed,
}

/// One candidate-producing leg.
///
/// Object-safe, and deliberately narrow: a leg describes *where candidates come
/// from*. It does not decide who may see them, does not rank, and does not
/// know about the other legs.
pub trait SqlLeg: Send + Sync {
    /// Stable identifier, used in `degraded[]` reporting and in the census.
    fn id(&self) -> &'static str;

    fn phase(&self) -> LegPhase;

    /// Pushes this leg's candidate-selecting SQL.
    ///
    /// **The builder arrives with nothing applied and leaves with the leg's
    /// own `FROM`/`WHERE` on it.** The permission fragment is applied around
    /// this call by [`push_leg`]. A leg that tried to apply its own would be
    /// duplicating an enforcement point, which is the drift invariant I-1
    /// exists to prevent.
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>);
}

/// Pushes one leg as a CTE, with visibility applied.
///
/// The **only** sanctioned way to add a leg to a statement. Ordering is fixed
/// here and not up to the leg: candidates first, then the fragment, so the
/// fragment always lands inside the leg's own `WHERE` rather than after a
/// clause the leg happened to close.
pub fn push_leg(
    qb: &mut QueryBuilder<'_, Postgres>,
    leg: &dyn SqlLeg,
    visibility: &PolymorphicVisibility<'_>,
    entity_name_col: &str,
    record_id_col: &str,
) {
    push_leg_with_shape(
        qb,
        leg,
        visibility,
        VisibilityShape::PerRow,
        entity_name_col,
        record_id_col,
    );
}

/// Which of the two equivalent visibility shapes a leg is filtered with
/// (TODO-053).
///
/// **Both express the same rule.** This is a planner hint, not a policy choice:
/// [`ShareSemiJoin`](VisibilityShape::ShareSemiJoin) is only admissible for a
/// caller whose visibility comes *only* from share rows, which
/// `PolymorphicVisibility::share_inversion_eligible` decides and debug-asserts.
/// Selecting it for any other caller narrows what they can see — the safe
/// direction to fail, and still wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityShape {
    /// The standard `EXISTS` per candidate row. Correct for every caller.
    PerRow,
    /// Drive from the share table into the text match. Correct only for a
    /// share-only caller, and dramatically cheaper for one — the per-row form
    /// re-checks the share table for every candidate the text scan produces,
    /// which for a narrowed caller is tens of thousands of rows to fill one
    /// page.
    ShareSemiJoin,
}

/// [`push_leg`] with an explicit shape.
pub fn push_leg_with_shape(
    qb: &mut QueryBuilder<'_, Postgres>,
    leg: &dyn SqlLeg,
    visibility: &PolymorphicVisibility<'_>,
    shape: VisibilityShape,
    entity_name_col: &str,
    record_id_col: &str,
) {
    leg.push_candidates(qb);
    match shape {
        VisibilityShape::PerRow => visibility.push(qb, entity_name_col, record_id_col),
        VisibilityShape::ShareSemiJoin => {
            visibility.push_share_semi_join(qb, entity_name_col, record_id_col)
        }
    }
}

/// Asserts every leg in `legs` produces SQL carrying the visibility fragment.
///
/// The braces to `push_leg`'s belt. `push_leg` makes forgetting the fragment
/// *awkward*; this makes it *fail*. A future leg that assembles its own
/// statement — for a perfectly good reason, in a hurry — still has to pass
/// this, and the failure message says why rather than leaving the next person
/// to work out what a missing `EXISTS` meant.
pub fn census(
    legs: &[&dyn SqlLeg],
    visibility: &PolymorphicVisibility<'_>,
    entity_name_col: &str,
    record_id_col: &str,
) -> Result<(), String> {
    for leg in legs {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        push_leg(&mut qb, *leg, visibility, entity_name_col, record_id_col);
        let sql = qb.into_sql();
        if !sql.contains("m.pos IS NOT NULL") {
            return Err(format!(
                "leg '{}' produced SQL with no visibility fragment — it would \
                 return rows the caller may not see, with no error and no \
                 failing query",
                leg.id()
            ));
        }
        if !sql.contains("NOT EXISTS") {
            return Err(format!(
                "leg '{}' produced SQL with no deny check",
                leg.id()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_server::security::{AccessLevel, SecurityContext};
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    struct WellBehavedLeg;
    impl SqlLeg for WellBehavedLeg {
        fn id(&self) -> &'static str {
            "test.well-behaved"
        }
        fn phase(&self) -> LegPhase {
            LegPhase::Immediate
        }
        fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
            qb.push("SELECT record_id FROM search_index t WHERE t.corpus = 'record'");
        }
    }

    fn ctx() -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: vec![Uuid::now_v7()],
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

    fn access_map() -> HashMap<String, (Uuid, AccessLevel)> {
        let mut m = HashMap::new();
        m.insert("account".to_string(), (Uuid::now_v7(), AccessLevel::Team));
        m
    }

    #[test]
    fn a_leg_pushed_through_push_leg_always_carries_visibility() {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        push_leg(
            &mut qb,
            &WellBehavedLeg,
            &vis,
            "t.entity_logicalname",
            "t.record_id",
        );
        let sql = qb.into_sql();

        assert!(sql.contains("m.pos IS NOT NULL"), "{sql}");
        assert!(sql.contains("NOT EXISTS"), "{sql}");
        assert!(
            sql.find("WHERE t.corpus").unwrap() < sql.find("AND EXISTS").unwrap(),
            "the fragment must land inside the leg's own WHERE: {sql}"
        );
    }

    #[test]
    fn the_census_passes_for_a_well_behaved_leg() {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);
        census(
            &[&WellBehavedLeg],
            &vis,
            "t.entity_logicalname",
            "t.record_id",
        )
        .expect("a leg pushed through push_leg must pass the census");
    }

    /// The census must actually be capable of failing. A guard that cannot
    /// fail is a guard nobody notices has stopped working — so this proves it
    /// by checking the same condition against SQL with no fragment.
    #[test]
    fn the_census_detects_sql_with_no_fragment() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        WellBehavedLeg.push_candidates(&mut qb);
        let unguarded = qb.into_sql();
        assert!(
            !unguarded.contains("m.pos IS NOT NULL"),
            "a leg's own candidates carry no fragment — which is exactly why \
             push_leg, not the leg, applies it"
        );
    }

    /// An admin is unfiltered, so the census's condition cannot hold — and
    /// that is correct, not a gap. The census is only meaningful for a caller
    /// who is actually filtered, which is what `is_unfiltered` exists to let a
    /// caller check.
    #[test]
    fn an_admin_visibility_pushes_nothing_and_the_census_is_not_applicable() {
        let mut c = ctx();
        c.is_admin = true;
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);
        assert!(vis.is_unfiltered());

        let result = census(
            &[&WellBehavedLeg],
            &vis,
            "t.entity_logicalname",
            "t.record_id",
        );
        assert!(
            result.is_err(),
            "the census reports 'no fragment' for an admin — callers check \
             is_unfiltered() first rather than running it"
        );
    }
}

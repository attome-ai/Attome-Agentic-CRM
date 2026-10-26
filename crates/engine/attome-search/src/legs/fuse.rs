//! Fusing a phase's legs into **one** statement (TODO-012's second half).
//!
//! `P-search-and-retrieval` §11.2 is unambiguous about why this is not "run the
//! legs concurrently": parallel legs means one pooled connection per leg, and
//! under concurrency **the pool becomes the ceiling long before PostgreSQL
//! does**. Four legs at four connections apiece turns a busy morning into a
//! connection-starvation incident, and the symptom — everything slow, nothing
//! obviously broken — is among the worst to diagnose.
//!
//! So each leg contributes a CTE, RRF is computed in SQL, and the whole phase
//! is one round trip.
//!
//! **What fusing costs, stated rather than discovered.** The statement becomes
//! the timeout domain. One mis-planned leg cancels every leg sharing its
//! statement, so [`Completeness::HitDeadline`] and [`Completeness::Failed`] are
//! honestly per-*phase*, not per-leg. Only [`Completeness::HitCeiling`] is
//! genuinely per-leg, because each CTE carries its own `LIMIT`. The plan's v2
//! correction says not to promise per-leg deadline isolation this shape cannot
//! deliver, and [`FusedOutcome`] is typed so a caller cannot read one.

use std::collections::BTreeMap;

use attome_security::visibility::PolymorphicVisibility;
use sqlx::{Postgres, QueryBuilder};

use super::{
    Completeness, LegPhase, SqlLeg, VisibilityShape, push_leg_with_shape, stage1::LEG_CEILING,
};

/// Reciprocal Rank Fusion's smoothing constant.
///
/// 60 is the value from the original RRF paper and the one every comparable
/// system uses. It matters less than it looks: RRF's whole appeal is that it
/// fuses *ranks* rather than scores, so legs whose scores are on wildly
/// different scales (a trigram similarity in `[0,1]`, a `ts_rank_cd`, a
/// constant 1.0 for an exact hit) combine sensibly without anyone having to
/// calibrate them against each other.
pub(crate) const RRF_K: f64 = 60.0;

/// What one fused phase produced.
pub struct FusedOutcome {
    /// Per-leg completeness. Keyed by [`SqlLeg::id`].
    ///
    /// A `BTreeMap` so the `degraded[]` a caller reports is ordered and
    /// reproducible — an unordered degradation list makes two identical
    /// queries look different in logs.
    pub per_leg: BTreeMap<&'static str, Completeness>,
    /// Phase-wide outcome. `Complete` unless the statement itself timed out or
    /// failed — see the module doc for why this is not per-leg.
    pub phase: Completeness,
}

impl std::fmt::Debug for FusedOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FusedOutcome").finish_non_exhaustive()
    }
}

impl FusedOutcome {
    /// The legs a caller should report as degraded, in stable order.
    pub fn degraded(&self) -> Vec<&'static str> {
        self.per_leg
            .iter()
            .filter(|(_, c)| **c != Completeness::Complete)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Builds the fused statement for one phase.
///
/// Returns `None` when `legs` is empty — a phase with no legs is not an error
/// (Stage 1 has no `AfterEmbedding` legs at all), and emitting `WITH` followed
/// by nothing would be a syntax error the caller would meet at the database.
pub fn build_phase<'a>(
    legs: &[&dyn SqlLeg],
    phase: LegPhase,
    visibility: &PolymorphicVisibility<'_>,
    entity_name_col: &str,
    record_id_col: &str,
    limit: i64,
) -> Option<QueryBuilder<'a, Postgres>> {
    build_phase_with_shape(
        legs,
        phase,
        visibility,
        VisibilityShape::PerRow,
        entity_name_col,
        record_id_col,
        limit,
    )
}

/// [`build_phase`] with an explicit visibility shape (TODO-053).
#[allow(clippy::too_many_arguments)]
pub fn build_phase_with_shape<'a>(
    legs: &[&dyn SqlLeg],
    phase: LegPhase,
    visibility: &PolymorphicVisibility<'_>,
    shape: VisibilityShape,
    entity_name_col: &str,
    record_id_col: &str,
    limit: i64,
) -> Option<QueryBuilder<'a, Postgres>> {
    let phase_legs: Vec<&&dyn SqlLeg> = legs.iter().filter(|l| l.phase() == phase).collect();
    if phase_legs.is_empty() {
        return None;
    }

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("WITH ");

    for (i, leg) in phase_legs.iter().enumerate() {
        if i > 0 {
            qb.push(", ");
        }
        // CTE names are generated here from an index, never from the leg's own
        // id — an id is a `&'static str` chosen by a developer, but generating
        // the identifier locally means no leg can influence the SQL structure
        // even by accident.
        qb.push(format!(
            "leg_{i} AS ( SELECT record_id, entity_logicalname, "
        ));
        // Rank WITHIN the leg. RRF needs a rank, not a score, and computing it
        // here means a leg never has to know it is being fused.
        qb.push("ROW_NUMBER() OVER (ORDER BY score DESC, record_id) AS rnk FROM ( ");
        push_leg_with_shape(
            &mut qb,
            **leg,
            visibility,
            shape,
            entity_name_col,
            record_id_col,
        );
        // Each leg's own ceiling — the reason HitCeiling stays genuinely
        // per-leg even though the statement shares one timeout.
        qb.push(" ORDER BY score DESC LIMIT ");
        qb.push_bind(LEG_CEILING);
        qb.push(" ) AS candidates )");
    }

    // One `UNION ALL` over every leg, tagged so per-leg counts survive the
    // grouping below.
    qb.push(", unioned AS ( ");
    for (i, leg) in phase_legs.iter().enumerate() {
        if i > 0 {
            qb.push(" UNION ALL ");
        }
        qb.push(format!(
            "SELECT record_id, entity_logicalname, rnk, '{}' AS leg FROM leg_{i}",
            leg.id()
        ));
    }
    qb.push(" )");

    // Per-leg row counts, so the caller can tell HitCeiling from Complete
    // without a second round trip.
    qb.push(", leg_counts AS ( SELECT leg, COUNT(*) AS n FROM unioned GROUP BY leg )");

    // RRF. Summed over the legs that matched each row.
    qb.push(", fused AS ( SELECT record_id, entity_logicalname, SUM(1.0 / (");
    qb.push_bind(RRF_K);
    qb.push(
        " + rnk)) AS rrf, array_agg(DISTINCT leg ORDER BY leg) AS matched_legs \
             FROM unioned GROUP BY record_id, entity_logicalname )",
    );

    // The per-leg counts ride along as one JSONB column, identical on every
    // row. Redundant on the wire and worth it: the alternative is a second
    // statement, which reintroduces exactly the extra round trip fusing exists
    // to remove.
    qb.push(
        " SELECT f.record_id, f.entity_logicalname, f.rrf, f.matched_legs, \
         (SELECT jsonb_object_agg(leg, n) FROM leg_counts) AS leg_counts \
         FROM fused f ORDER BY f.rrf DESC, f.record_id LIMIT ",
    );
    qb.push_bind(limit);

    Some(qb)
}

/// Turns the statement's `leg_counts` column into per-leg completeness.
///
/// A leg that returned exactly its ceiling *probably* had more to give, so it
/// is reported `HitCeiling`. That is deliberately the pessimistic reading: a
/// leg with exactly `LEG_CEILING` matches and no more is indistinguishable
/// from one that was cut off, and telling a caller "possibly incomplete" when
/// it was complete is a far cheaper error than the reverse.
pub fn interpret_counts(
    legs: &[&dyn SqlLeg],
    phase: LegPhase,
    counts: &serde_json::Value,
) -> BTreeMap<&'static str, Completeness> {
    legs.iter()
        .filter(|l| l.phase() == phase)
        .map(|leg| {
            let n = counts.get(leg.id()).and_then(serde_json::Value::as_i64);
            let completeness = match n {
                Some(n) if n >= LEG_CEILING => Completeness::HitCeiling,
                _ => Completeness::Complete,
            };
            (leg.id(), completeness)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legs::stage1::{ExactKeyLeg, FuzzyLeg, LexicalLeg, PrefixLeg};
    use attome_server::security::{AccessLevel, SecurityContext};
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

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

    fn legs() -> Vec<Box<dyn SqlLeg>> {
        vec![
            Box::new(ExactKeyLeg {
                normalized_query: "inv-1".into(),
            }),
            Box::new(PrefixLeg {
                normalized_query: "acme".into(),
            }),
            Box::new(LexicalLeg {
                stemmed_query: "acme".into(),
            }),
            Box::new(FuzzyLeg {
                normalized_query: "acme".into(),
                ..FuzzyLeg::default()
            }),
        ]
    }

    fn build_sql() -> String {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);
        let owned = legs();
        let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();
        build_phase(
            &refs,
            LegPhase::Immediate,
            &vis,
            "t.entity_logicalname",
            "t.record_id",
            50,
        )
        .expect("Stage 1 has immediate legs")
        .into_sql()
    }

    /// The point of the whole file: **one** statement, not one per leg.
    #[test]
    fn all_immediate_legs_fuse_into_a_single_statement() {
        let sql = build_sql();
        assert_eq!(
            sql.matches("WITH ").count(),
            1,
            "a phase must be one statement: {sql}"
        );
        for i in 0..4 {
            assert!(
                sql.contains(&format!("leg_{i} AS (")),
                "leg_{i} missing: {sql}"
            );
        }
    }

    /// Every leg's CTE still carries the visibility fragment. Fusing must not
    /// become a way to lose it — a `UNION ALL` of four unguarded legs would be
    /// a disclosure with a very tidy execution plan.
    #[test]
    fn every_fused_leg_still_carries_visibility() {
        let sql = build_sql();
        assert_eq!(
            sql.matches("m.pos IS NOT NULL").count(),
            4,
            "each of the four legs needs its own fragment: {sql}"
        );
        assert_eq!(sql.matches("AND NOT EXISTS").count(), 4, "{sql}");
    }

    /// Parenthesis balance, mechanically. Same reasoning as the fragment's own
    /// balance test — this string is assembled from far more pieces and a
    /// missing closer surfaces only at the database.
    #[test]
    fn the_fused_statement_is_parenthesis_balanced() {
        let sql = build_sql();
        let mut depth = 0i32;
        for ch in sql.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "closed one paren too many: {sql}");
        }
        assert_eq!(depth, 0, "unbalanced (depth {depth}): {sql}");
    }

    /// Each leg gets its own `LIMIT`, which is what keeps `HitCeiling` a
    /// genuinely per-leg signal.
    #[test]
    fn each_leg_carries_its_own_ceiling() {
        let sql = build_sql();
        assert_eq!(
            sql.matches("ORDER BY score DESC LIMIT").count(),
            4,
            "every leg needs its own ceiling: {sql}"
        );
    }

    /// A phase with no legs produces no statement rather than `WITH` followed
    /// by nothing — Stage 1 has no `AfterEmbedding` legs, so this is the
    /// normal case today, not a defensive edge.
    #[test]
    fn an_empty_phase_produces_no_statement() {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);
        let owned = legs();
        let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();
        assert!(
            build_phase(
                &refs,
                LegPhase::AfterEmbedding,
                &vis,
                "t.entity_logicalname",
                "t.record_id",
                50,
            )
            .is_none()
        );
    }

    /// A leg at its ceiling reads `HitCeiling`; below it, `Complete`. The
    /// pessimistic reading is deliberate — see `interpret_counts`.
    #[test]
    fn counts_at_the_ceiling_report_as_truncated() {
        let owned = legs();
        let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();
        let counts = serde_json::json!({
            "R1.exact": 1,
            "R2.prefix": LEG_CEILING,
            "R3.lexical": 12,
            "R5.fuzzy": LEG_CEILING + 5,
        });
        let per_leg = interpret_counts(&refs, LegPhase::Immediate, &counts);

        assert_eq!(per_leg["R1.exact"], Completeness::Complete);
        assert_eq!(per_leg["R2.prefix"], Completeness::HitCeiling);
        assert_eq!(per_leg["R3.lexical"], Completeness::Complete);
        assert_eq!(per_leg["R5.fuzzy"], Completeness::HitCeiling);

        let outcome = FusedOutcome {
            per_leg,
            phase: Completeness::Complete,
        };
        assert_eq!(outcome.degraded(), vec!["R2.prefix", "R5.fuzzy"]);
    }

    /// A leg absent from the counts (it matched nothing) is `Complete`, not
    /// degraded. "No matches" is a correct answer, and reporting it as
    /// degradation would train callers to ignore the field.
    #[test]
    fn a_leg_that_matched_nothing_is_complete_not_degraded() {
        let owned = legs();
        let refs: Vec<&dyn SqlLeg> = owned.iter().map(|l| l.as_ref()).collect();
        let per_leg = interpret_counts(&refs, LegPhase::Immediate, &serde_json::json!({}));
        assert!(per_leg.values().all(|c| *c == Completeness::Complete));
        let outcome = FusedOutcome {
            per_leg,
            phase: Completeness::Complete,
        };
        assert!(outcome.degraded().is_empty());
    }
}

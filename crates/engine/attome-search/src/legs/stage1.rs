//! Stage 1's immediate legs: R1 exact, R2 prefix, R3 lexical, R5 fuzzy
//! (TODO-012).
//!
//! All four are `LegPhase::Immediate` — none needs an embedding — so they fuse
//! into **one** statement. `P-search-and-retrieval` §11.2 is emphatic about
//! why: "parallel legs" would mean one pooled connection per leg, and under
//! concurrency the POOL becomes the ceiling long before PostgreSQL does. Four
//! legs at four connections apiece is a connection-starvation incident waiting
//! for a busy morning.
//!
//! Every leg here selects `(record_id, entity_logicalname, score)` and nothing
//! else. Ranking fuses them afterwards; a leg that tried to return display
//! columns would make the union wider for no benefit and would have to agree
//! with every other leg about the projection.

use sqlx::{Postgres, QueryBuilder};

use super::{LegPhase, SqlLeg};

/// Per-leg candidate ceiling.
///
/// Each leg's CTE carries its own `LIMIT`, which is what makes
/// `Completeness::HitCeiling` a genuinely per-leg signal even though the
/// fused statement shares one timeout domain.
pub const LEG_CEILING: i64 = 500;

/// R1 — exact key lookup.
///
/// Ranked above everything else, and deliberately: someone who pastes an
/// invoice number wants *that invoice*, not the best textual match for its
/// digits. An exact hit short-circuits ranking rather than competing in it.
pub struct ExactKeyLeg {
    pub normalized_query: String,
}

impl std::fmt::Debug for ExactKeyLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactKeyLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for ExactKeyLeg {
    fn id(&self) -> &'static str {
        "R1.exact"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, 1.0::real AS score \
             FROM search_index t WHERE t.exact_keys @> ARRAY[",
        );
        qb.push_bind(self.normalized_query.clone());
        qb.push("]::text[]");
    }
}

/// R1, phone form (A25-T2): a query that is a phone number written locally
/// (`0501234567`) also looks up its international key (`+966501234567`), the
/// form a record's phone attribute is indexed under.
pub struct PhoneKeyLeg {
    pub phone_key: String,
}

impl std::fmt::Debug for PhoneKeyLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneKeyLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for PhoneKeyLeg {
    fn id(&self) -> &'static str {
        "R1.phone"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, 1.0::real AS score \
             FROM search_index t WHERE t.exact_keys @> ARRAY[",
        );
        qb.push_bind(self.phone_key.clone());
        qb.push("]::text[]");
    }
}

/// R2 — prefix / typeahead.
///
/// `LIKE norm || '%'` against the `text_pattern_ops` btree. The query is bound
/// and the wildcard concatenated **in SQL**, so a query containing `%` or `_`
/// is matched literally rather than becoming a leading-wildcard scan of the
/// whole table — the difference between a 2 ms index probe and a sequential
/// scan a user can trigger by typing a percent sign.
pub struct PrefixLeg {
    pub normalized_query: String,
}

impl std::fmt::Debug for PrefixLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for PrefixLeg {
    fn id(&self) -> &'static str {
        "R2.prefix"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, 0.9::real AS score \
             FROM search_index t WHERE t.title_norm LIKE (replace(replace(replace(",
        );
        qb.push_bind(self.normalized_query.clone());
        qb.push(", '\\', '\\\\'), '%', '\\%'), '_', '\\_') || '%')");
    }
}

/// Appends the platform's one full-text predicate:
/// `plainto_tsquery('attome_search', <stemmed_query>) AS q(query)`.
///
/// Meant to be followed by `WHERE <alias>.tsv @@ q.query` and ranked with
/// `ts_rank_cd(<alias>.tsv, q.query, 32)`. Shared by every caller that ranks
/// against a `tsvector` column — this leg and `knowledge.rs`'s chunk
/// retrieval — so the configuration name and the query itself are bound in
/// exactly one place rather than two copies a future change has to find and
/// keep in sync by hand.
pub fn push_lexical_tsquery(qb: &mut QueryBuilder<'_, Postgres>, stemmed_query: &str) {
    qb.push("plainto_tsquery('attome_search', ");
    qb.push_bind(stemmed_query.to_owned());
    qb.push(") AS q(query)");
}

/// R3 — lexical full-text over the `simple`-configuration tsvector.
///
/// `ts_rank_cd` with normalization flag 32 (`rank / (rank + 1)`), which bounds
/// the score into `[0,1)` so it is commensurable with the other legs' scores
/// when RRF fuses them. Without normalization a long document's raw rank is
/// unbounded and would dominate the fusion for reasons that have nothing to do
/// with relevance.
pub struct LexicalLeg {
    /// Already normalized AND stemmed by the caller, using the same
    /// `lang::` functions the drain used at index time. A leg that stemmed its
    /// own input would be a second stemming implementation — see `lang`'s
    /// module doc for why that is the failure this design exists to avoid.
    pub stemmed_query: String,
}

impl std::fmt::Debug for LexicalLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LexicalLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for LexicalLeg {
    fn id(&self) -> &'static str {
        "R3.lexical"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, \
             ts_rank_cd(t.tsv, q.query, 32)::real AS score \
             FROM search_index t, ",
        );
        push_lexical_tsquery(qb, &self.stemmed_query);
        qb.push(" WHERE t.tsv @@ q.query");
    }
}

/// C10-T1 — the query's glossary synonyms, full-text, as one leg: a record
/// that uses another name for what the query names. Scored a fifth below a
/// literal lexical hit, so the word the person typed still ranks first.
pub struct SynonymLeg {
    /// Each alternative already normalized and stemmed like the query.
    pub stemmed_alternatives: Vec<String>,
}

impl std::fmt::Debug for SynonymLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynonymLeg").finish_non_exhaustive()
    }
}

impl SqlLeg for SynonymLeg {
    fn id(&self) -> &'static str {
        "R3.synonym"
    }
    fn phase(&self) -> LegPhase {
        LegPhase::Immediate
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, \
             (ts_rank_cd(t.tsv, q.query, 32) * 0.8)::real AS score \
             FROM search_index t, (SELECT ",
        );
        for (i, alternative) in self.stemmed_alternatives.iter().enumerate() {
            if i > 0 {
                qb.push(" || ");
            }
            qb.push("plainto_tsquery('attome_search', ");
            qb.push_bind(alternative.clone());
            qb.push(")");
        }
        if self.stemmed_alternatives.is_empty() {
            qb.push("plainto_tsquery('attome_search', '')");
        }
        qb.push(") AS q(query) WHERE t.tsv @@ q.query");
    }
}

/// R5 — fuzzy / typo tolerance.
///
/// **`title_norm` only, never the body.** Trigram similarity over a long body
/// is both slow and meaningless — every sufficiently long text is somewhat
/// similar to every query. Restricting it to titles is what keeps this a typo
/// corrector rather than a random-result generator.
pub struct FuzzyLeg {
    pub normalized_query: String,
    /// Below this, a trigram match is noise. 0.3 is `pg_trgm`'s own default
    /// threshold; it is named here rather than relying on the session GUC,
    /// which a pooled connection may carry over from another caller.
    pub threshold: f32,
    /// AA6-T1: run in the second statement, only when the first found
    /// nothing (a typo is the fallback, not a contender). Off by default, so
    /// a caller that fuses everything at once keeps doing so.
    pub deferred: bool,
}

impl std::fmt::Debug for FuzzyLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzyLeg").finish_non_exhaustive()
    }
}

impl Default for FuzzyLeg {
    fn default() -> Self {
        Self {
            normalized_query: String::new(),
            threshold: 0.3,
            deferred: false,
        }
    }
}

impl SqlLeg for FuzzyLeg {
    fn id(&self) -> &'static str {
        "R5.fuzzy"
    }
    fn phase(&self) -> LegPhase {
        if self.deferred {
            LegPhase::AfterEmbedding
        } else {
            LegPhase::Immediate
        }
    }
    fn push_candidates(&self, qb: &mut QueryBuilder<'_, Postgres>) {
        // AA6-T1: `%` is what the `search_index_title_trgm_idx` GIN index
        // answers (at the session's `pg_trgm.similarity_threshold`, 0.3
        // unless the caller set it); the explicit `similarity > threshold`
        // keeps the bar this leg names whatever the session says.
        qb.push(
            "SELECT t.record_id, t.entity_logicalname, \
             similarity(t.title_norm, ",
        );
        qb.push_bind(self.normalized_query.clone());
        qb.push(")::real AS score FROM search_index t WHERE t.title_norm % ");
        qb.push_bind(self.normalized_query.clone());
        qb.push(" AND similarity(t.title_norm, ");
        qb.push_bind(self.normalized_query.clone());
        qb.push(") > ");
        qb.push_bind(self.threshold);
        qb.push("::real");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legs::{census, push_leg};
    use attome_security::visibility::PolymorphicVisibility;
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

    fn all_legs() -> Vec<Box<dyn SqlLeg>> {
        vec![
            Box::new(ExactKeyLeg {
                normalized_query: "inv-123".into(),
            }),
            Box::new(PrefixLeg {
                normalized_query: "acme".into(),
            }),
            Box::new(LexicalLeg {
                stemmed_query: "acme invoic".into(),
            }),
            Box::new(FuzzyLeg {
                normalized_query: "acme".into(),
                ..FuzzyLeg::default()
            }),
        ]
    }

    /// **The** test for this file. Every Stage 1 leg, pushed the sanctioned
    /// way, carries the visibility fragment and the deny check. A leg added
    /// later that forgets either fails here with a message saying what it
    /// would have leaked.
    #[test]
    fn every_stage_one_leg_passes_the_visibility_census() {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);

        let legs = all_legs();
        let refs: Vec<&dyn SqlLeg> = legs.iter().map(|l| l.as_ref()).collect();
        census(&refs, &vis, "t.entity_logicalname", "t.record_id")
            .expect("every Stage 1 leg must carry visibility");
    }

    /// All four are Immediate, so all four fuse into one statement. A leg
    /// mis-phased as `AfterEmbedding` would silently move to the second round
    /// trip and be absent from the first page of results.
    #[test]
    fn every_stage_one_leg_is_immediate() {
        for leg in all_legs() {
            assert_eq!(
                leg.phase(),
                LegPhase::Immediate,
                "{} needs no embedding and must fuse into the first statement",
                leg.id()
            );
        }
    }

    #[test]
    fn leg_ids_are_unique() {
        let legs = all_legs();
        let mut ids: Vec<&str> = legs.iter().map(|l| l.id()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate leg id: {ids:?}");
    }

    /// The prefix leg escapes LIKE metacharacters. Without this, a query
    /// containing `%` becomes a leading-wildcard scan of the whole table — a
    /// sequential scan any user can trigger by typing a percent sign.
    #[test]
    fn the_prefix_leg_escapes_like_metacharacters() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        PrefixLeg {
            normalized_query: "50%".into(),
        }
        .push_candidates(&mut qb);
        let sql = qb.into_sql();
        assert!(
            sql.contains("replace("),
            "the query must be escaped, not concatenated raw: {sql}"
        );
        assert!(
            !sql.contains("50%"),
            "the query value must be BOUND, never inlined: {sql}"
        );
    }

    /// Fuzzy matching runs on titles only. Trigram similarity over a long body
    /// is slow and meaningless — every long text is somewhat similar to every
    /// query — so this would turn a typo corrector into a random-result
    /// generator.
    /// AA6-T1: the fuzzy leg filters with the indexed `%` operator, and a
    /// deferred one waits for the second statement.
    #[test]
    fn the_fuzzy_leg_uses_the_trigram_index_and_can_wait() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        FuzzyLeg::default().push_candidates(&mut qb);
        assert!(qb.into_sql().contains("t.title_norm % "));
        assert_eq!(FuzzyLeg::default().phase(), LegPhase::Immediate);
        let deferred = FuzzyLeg {
            deferred: true,
            ..FuzzyLeg::default()
        };
        assert_eq!(deferred.phase(), LegPhase::AfterEmbedding);
    }

    #[test]
    fn the_fuzzy_leg_never_touches_the_body() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        FuzzyLeg {
            normalized_query: "acme".into(),
            ..FuzzyLeg::default()
        }
        .push_candidates(&mut qb);
        let sql = qb.into_sql();
        assert!(sql.contains("title_norm"), "{sql}");
        assert!(!sql.contains("body_indexed"), "{sql}");
        assert!(!sql.contains("body_display"), "{sql}");
    }

    /// The lexical leg bounds its score into `[0,1)` with normalization flag
    /// 32. An unbounded raw `ts_rank_cd` would let a long document dominate
    /// RRF fusion for reasons unrelated to relevance.
    #[test]
    fn the_lexical_leg_normalizes_its_rank() {
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
        LexicalLeg {
            stemmed_query: "acme".into(),
        }
        .push_candidates(&mut qb);
        let sql = qb.into_sql();
        assert!(sql.contains("ts_rank_cd"), "{sql}");
        assert!(
            sql.contains(", 32)"),
            "rank must be normalized so scores are commensurable: {sql}"
        );
        assert!(
            sql.contains("'attome_search'"),
            "must use the platform's own configuration, not the default: {sql}"
        );
    }

    /// No leg inlines a query value. Every one goes through `push_bind` —
    /// guidelines §4: bind every runtime value, never interpolate request data
    /// into SQL.
    #[test]
    fn no_leg_inlines_a_query_value() {
        let marker = "'; DROP TABLE search_index; --";
        for leg in [
            Box::new(ExactKeyLeg {
                normalized_query: marker.into(),
            }) as Box<dyn SqlLeg>,
            Box::new(PrefixLeg {
                normalized_query: marker.into(),
            }),
            Box::new(LexicalLeg {
                stemmed_query: marker.into(),
            }),
            Box::new(FuzzyLeg {
                normalized_query: marker.into(),
                ..FuzzyLeg::default()
            }),
        ] {
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
            leg.push_candidates(&mut qb);
            let sql = qb.into_sql();
            assert!(
                !sql.contains("DROP TABLE"),
                "{} inlined a query value: {sql}",
                leg.id()
            );
        }
    }

    /// The fragment lands inside each leg's own `WHERE`, not after a clause the
    /// leg happened to close — which is what `push_leg`'s fixed ordering
    /// guarantees and what a leg assembling its own statement could get wrong.
    #[test]
    fn the_fragment_lands_inside_each_legs_where_clause() {
        let c = ctx();
        let map = access_map();
        let vis = PolymorphicVisibility::new(&c, &map, &HashSet::new(), None);

        for leg in all_legs() {
            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("");
            push_leg(
                &mut qb,
                leg.as_ref(),
                &vis,
                "t.entity_logicalname",
                "t.record_id",
            );
            let sql = qb.into_sql();
            let where_pos = sql.find(" WHERE ").expect("each leg has a WHERE");
            let fragment = sql.find(" AND EXISTS (").expect("fragment present");
            assert!(
                where_pos < fragment,
                "{}: the fragment must extend the leg's WHERE: {sql}",
                leg.id()
            );
        }
    }
}

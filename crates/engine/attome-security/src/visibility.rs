//! The visibility fragment as a *pushed* thing, not a formatted string
//! (TODO-011).
//!
//! **The problem this replaces.** [`crate::rls::polymorphic_audit_predicate`]
//! takes a `first_placeholder: usize`, returns a `String` full of `$7`, `$8`,
//! `$9`, and hands back a bind struct the caller must then splice into its own
//! parameter vector *in exactly the right order*. It works, it is tested, and
//! `P-search-and-retrieval` §8.1 says of it — before any search code existed —
//! that "the first implementer will copy `query_exec.rs`'s composition and get
//! it subtly wrong."
//!
//! That prediction is worth taking literally. Getting it wrong does not
//! produce a type error or a SQL syntax error. It produces a query where one
//! caller's UUID lands in the slot meant for another's, and the result is a
//! *permission filter that filters by the wrong principal*. Silent, plausible,
//! and wrong in the direction that leaks.
//!
//! **The fix is not a better comment.** [`PolymorphicVisibility::push`] writes
//! straight into a `sqlx::QueryBuilder`, where `push_bind` assigns every
//! placeholder itself. There is no offset to pass, no bind vector to keep in
//! step, and no way to interleave two fragments incorrectly — the arithmetic
//! that could be got wrong no longer exists in the caller.
//!
//! **And the fragment is passed INTO each leg, never built by one.** A leg
//! receives an already-pushed builder. It cannot forget to apply visibility,
//! because applying it is not among the things a leg does.

use attome_server::security::{AccessLevel, SecurityContext};
use sqlx::{Postgres, QueryBuilder};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::rls::FastTierColumns;
use crate::rls_fragment::{push_deny_clause, push_principal_disjunction};

/// Everything needed to filter a set of rows by what one caller may see,
/// resolved once per request.
///
/// Built from the same inputs [`crate::rls::polymorphic_audit_predicate`]
/// takes, and generating the same shape — this is a second *interface* to one
/// enforcement rule, not a second rule. `generated_sql_matches_the_string_api`
/// pins that.
pub struct PolymorphicVisibility<'a> {
    ctx: &'a SecurityContext,
    /// Parallel arrays, in one traversal order. Built here rather than by the
    /// caller so the four can never be assembled from different iterations of
    /// the same map — which would mis-index a permission decision.
    logicalnames: Vec<String>,
    entity_refs: Vec<Uuid>,
    access_levels: Vec<i16>,
    default_shares: Vec<bool>,
    fast_tier: Option<FastTierColumns<'a>>,
}

impl std::fmt::Debug for PolymorphicVisibility<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolymorphicVisibility")
            .finish_non_exhaustive()
    }
}

impl<'a> PolymorphicVisibility<'a> {
    pub fn new(
        ctx: &'a SecurityContext,
        access_by_entity: &HashMap<String, (Uuid, AccessLevel)>,
        default_share_entities: &HashSet<Uuid>,
        fast_tier: Option<FastTierColumns<'a>>,
    ) -> Self {
        let mut logicalnames = Vec::with_capacity(access_by_entity.len());
        let mut entity_refs = Vec::with_capacity(access_by_entity.len());
        let mut access_levels = Vec::with_capacity(access_by_entity.len());
        let mut default_shares = Vec::with_capacity(access_by_entity.len());
        for (logicalname, (entity_ref, level)) in access_by_entity {
            logicalnames.push(logicalname.clone());
            entity_refs.push(*entity_ref);
            access_levels.push(crate::rls::polymorphic_level(ctx, *entity_ref, *level));
            default_shares.push(default_share_entities.contains(entity_ref));
        }
        Self {
            ctx,
            logicalnames,
            entity_refs,
            access_levels,
            default_shares,
            fast_tier,
        }
    }

    /// Whether this caller is filtered at all.
    ///
    /// An admin sees everything, so pushing a fragment for one would be dead
    /// SQL the planner still has to consider. Callers check this and skip.
    pub fn is_unfiltered(&self) -> bool {
        self.ctx.is_admin
    }

    /// Pushes `AND EXISTS (...)` into `qb`, binding every value as it goes.
    ///
    /// `entity_name_col` and `record_id_col` are SQL expressions chosen by the
    /// calling code — a column name, or a correlated subquery for a shape that
    /// does not carry them directly. They are **spliced, not bound**, so they
    /// must never come from request data. Every *value* below goes through
    /// `push_bind`.
    pub fn push(
        &self,
        qb: &mut QueryBuilder<'_, Postgres>,
        entity_name_col: &str,
        record_id_col: &str,
    ) {
        if self.is_unfiltered() {
            return;
        }

        qb.push(" AND EXISTS ( SELECT 1 FROM ( SELECT array_position(");
        qb.push_bind(self.logicalnames.clone());
        qb.push("::text[], ");
        qb.push(entity_name_col);
        qb.push("::text) AS pos, ");
        qb.push(record_id_col);
        qb.push(" AS rid ) m WHERE m.pos IS NOT NULL AND ( (");
        qb.push_bind(self.access_levels.clone());
        qb.push("::smallint[])[m.pos] = 3 OR ( (");

        // The opt-in BusinessUnit fast tier (TODO-003), inside the map guard
        // and — see the closing of this arm — inside the deny bound. Outside
        // either, it is the privilege escalation D-357 ruling 2 records.
        if let Some(FastTierColumns { organization_ref }) = self.fast_tier {
            // Wrapped in its own `(...)`, matching `polymorphic_audit_predicate`'s
            // `bu_tier` fragment shape byte-for-byte (redundant with SQL's
            // AND-before-OR precedence either way, but `generated_sql_matches_the_string_api`
            // below pins the two backends to the exact same clause text).
            qb.push("((");
            qb.push_bind(self.access_levels.clone());
            qb.push("::smallint[])[m.pos] = 2 AND ");
            qb.push(organization_ref);
            qb.push(" = ANY(");
            qb.push_bind(self.ctx.accessible_org_ids.clone());
            qb.push("::uuid[])) OR ");
        }

        qb.push(
            "EXISTS ( SELECT 1 FROM record_share s WHERE s.record_id = m.rid AND s.entity_ref = (",
        );
        qb.push_bind(self.entity_refs.clone());
        qb.push("::uuid[])[m.pos] AND s.capability BETWEEN 0 AND 1 AND (");
        push_principal_disjunction(
            qb,
            "s",
            self.ctx.user_id,
            &self.ctx.team_ids,
            Some(&self.ctx.subordinate_user_ids),
        );
        qb.push(") ) OR (");
        qb.push_bind(self.default_shares.clone());
        qb.push("::boolean[])[m.pos] )");

        // The deny check. ANDed with everything above, which is what keeps a
        // deny row authoritative over every allow path including the fast tier.
        // Three closers after it are load-bearing and belong to THIS
        // function's own outer guard/`EXISTS`, not to the deny clause itself
        // (`push_deny_clause` is self-contained and closes only what it
        // opens) — an earlier version was one short here, and the fragment
        // read perfectly while PostgreSQL answered "syntax error at end of
        // input", which `balance::the_pushed_fragment_is_parenthesis_balanced`
        // now catches without a database.
        qb.push(" AND ");
        push_deny_clause(
            qb,
            "s",
            "m.rid",
            |qb| {
                qb.push("(");
                qb.push_bind(self.entity_refs.clone());
                qb.push("::uuid[])[m.pos]");
            },
            self.ctx.user_id,
            &self.ctx.team_ids,
        );
        qb.push(") ) )");
    }

    /// Whether this caller's visibility comes **only** from share rows.
    ///
    /// The precondition for [`push_share_semi_join`](Self::push_share_semi_join),
    /// and it is exact rather than heuristic on purpose. [`push`](Self::push)
    /// admits a row through four independent arms — Global level, the
    /// organization fast tier, a share row, and an entity-wide default share —
    /// and the inverted form covers only the third. Using it for a caller who
    /// also has one of the other three would silently **lose rows**: the query
    /// succeeds, the page is short, and the symptom looks like a relevance
    /// problem rather than a permission one. So this returns true only when the
    /// other three arms provably cannot fire.
    pub fn share_inversion_eligible(&self) -> bool {
        if self.is_unfiltered() {
            return false;
        }
        // Any Global entity admits rows with no share at all.
        if self.access_levels.contains(&3) {
            return false;
        }
        // The fast tier admits BusinessUnit rows by organization. It only fires
        // when a tier is configured AND the caller has organizations to match.
        if self.fast_tier.is_some()
            && !self.ctx.accessible_org_ids.is_empty()
            && self.access_levels.contains(&2)
        {
            return false;
        }
        // An entity-wide default share admits every row of that entity.
        if self.default_shares.iter().any(|d| *d) {
            return false;
        }
        true
    }

    /// The inverted shape: drive **from** `record_share` into the text
    /// match, instead of re-checking the share table once per candidate row
    /// (TODO-053).
    ///
    /// ## Why this exists
    ///
    /// A caller whose visibility comes from share rows gets no fast tier, so
    /// [`push`](Self::push)'s per-row `EXISTS` runs for every candidate the text
    /// scan produces — tens of thousands of rows to fill one page, on typeahead
    /// too, for precisely the narrowed users the whole design exists to protect.
    /// Meanwhile the *answer* is often a few hundred records: the share table is
    /// indexed by principal (`core_record_share_principal_idx`, migration 0051)
    /// and knows exactly which ones they are.
    ///
    /// A semi-join lets the planner build from the small side. The share set is
    /// **not** capped here even though the caller only reaches this path when a
    /// bounded estimate says it is small — a `LIMIT` on the share side would
    /// silently drop reachable records the moment the estimate was stale, which
    /// is the same lost-rows failure the eligibility check above exists to
    /// avoid. The estimate decides *whether* to invert; it never changes *what*
    /// is visible.
    ///
    /// Deny rows are still authoritative: the `NOT EXISTS` rides inside the
    /// subquery, so a denied record never enters the reachable set in the first
    /// place.
    ///
    /// # Panics
    ///
    /// Debug-asserts [`share_inversion_eligible`](Self::share_inversion_eligible).
    /// A caller that skips the check gets a filter that is *narrower* than the
    /// real rule, which is the safe direction to fail but still wrong.
    pub fn push_share_semi_join(
        &self,
        qb: &mut QueryBuilder<'_, Postgres>,
        entity_name_col: &str,
        record_id_col: &str,
    ) {
        debug_assert!(
            self.share_inversion_eligible(),
            "the inverted shape covers only the share arm; see share_inversion_eligible"
        );
        if self.is_unfiltered() {
            return;
        }

        qb.push(" AND (");
        qb.push(entity_name_col);
        qb.push(", ");
        qb.push(record_id_col);
        qb.push(
            ") IN ( SELECT e.logicalname, s.record_id \
                 FROM record_share s \
                 JOIN UNNEST(",
        );
        qb.push_bind(self.logicalnames.clone());
        qb.push("::text[], ");
        qb.push_bind(self.entity_refs.clone());
        qb.push(
            "::uuid[]) AS e(logicalname, entity_ref) ON e.entity_ref = s.entity_ref \
                 WHERE s.capability BETWEEN 0 AND 1 AND (",
        );
        push_principal_disjunction(
            qb,
            "s",
            self.ctx.user_id,
            &self.ctx.team_ids,
            Some(&self.ctx.subordinate_user_ids),
        );
        qb.push(") AND ");
        // `d.entity_ref = s.entity_ref` is a plain join-column reference, not
        // a bind — the share row this deny check must match is the same one
        // the allow arm above already joined to.
        push_deny_clause(
            qb,
            "d",
            "s.record_id",
            |qb| {
                qb.push("s.entity_ref");
            },
            self.ctx.user_id,
            &self.ctx.team_ids,
        );
        // Closes the outer `... IN ( SELECT ... )` opened above — not part
        // of the deny clause itself, which is self-contained.
        qb.push(")");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(is_admin: bool) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
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
            service_principal: false,
        }
    }

    fn map(entries: &[(&str, AccessLevel)]) -> HashMap<String, (Uuid, AccessLevel)> {
        entries
            .iter()
            .map(|(name, level)| (name.to_string(), (Uuid::now_v7(), *level)))
            .collect()
    }

    fn push_sql(
        c: &SecurityContext,
        m: &HashMap<String, (Uuid, AccessLevel)>,
        tier: Option<FastTierColumns<'_>>,
    ) -> String {
        let vis = PolymorphicVisibility::new(c, m, &HashSet::new(), tier);
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT 1 FROM t WHERE true");
        vis.push(&mut qb, "t.entity_name", "t.record_id");
        qb.into_sql()
    }

    /// The whole point: placeholders are assigned by `push_bind`, sequentially,
    /// with no arithmetic anywhere. A gap or a repeat here would mean a bind
    /// landing in the wrong slot — a permission filter keyed on the wrong
    /// principal, which is silent and leaks.
    #[test]
    fn placeholders_are_sequential_with_no_gaps_or_repeats() {
        let c = ctx(false);
        let sql = push_sql(&c, &map(&[("account", AccessLevel::Team)]), None);

        let mut found: Vec<usize> = sql
            .match_indices('$')
            .filter_map(|(i, _)| {
                sql[i + 1..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .ok()
            })
            .collect();
        found.sort_unstable();
        found.dedup();

        assert!(!found.is_empty(), "the fragment must bind something");
        let expected: Vec<usize> = (1..=found.len()).collect();
        assert_eq!(
            found, expected,
            "placeholders must run 1..n with no gaps: {sql}"
        );
    }

    /// An admin pushes nothing at all — not an always-true fragment. Same
    /// guarantee `rls_predicate` gives by returning `None`.
    #[test]
    fn an_admin_pushes_no_fragment() {
        let c = ctx(true);
        let sql = push_sql(&c, &map(&[("account", AccessLevel::Team)]), None);
        assert_eq!(sql, "SELECT 1 FROM t WHERE true");
    }

    /// The same structural guarantees the string API is tested for, restated
    /// here because this is a second interface to the rule and the two must
    /// not drift.
    #[test]
    fn the_pushed_fragment_keeps_the_map_guard_and_the_deny_bound() {
        let c = ctx(false);
        let sql = push_sql(&c, &map(&[("account", AccessLevel::Team)]), None);

        let guard = sql.find("m.pos IS NOT NULL").expect("map guard");
        let deny = sql.find("NOT EXISTS").expect("deny check");
        assert!(
            guard < deny,
            "the deny check must sit inside the guard: {sql}"
        );
        assert!(sql.contains("BETWEEN 0 AND 1"), "{sql}");
        assert!(!sql.contains("owner_id"), "ownership grants nothing: {sql}");
    }

    /// The fast tier lands inside the guard and before the deny bound, exactly
    /// as in the string API.
    #[test]
    fn the_fast_tier_is_bounded_the_same_way_here() {
        let c = ctx(false);
        let sql = push_sql(
            &c,
            &map(&[("account", AccessLevel::BusinessUnit)]),
            Some(FastTierColumns {
                organization_ref: "t.organization_ref",
            }),
        );

        let guard = sql.find("m.pos IS NOT NULL").expect("map guard");
        let tier = sql.find("t.organization_ref").expect("fast tier");
        let deny = sql.find("NOT EXISTS").expect("deny check");
        assert!(guard < tier && tier < deny, "{sql}");
        assert!(sql.contains("= 2"), "the tier must test BU depth: {sql}");
    }

    /// With no tier, the org column never appears — the same byte-identical
    /// guarantee the string API gives its audit callers.
    #[test]
    fn no_tier_emits_no_organization_column() {
        let c = ctx(false);
        let sql = push_sql(&c, &map(&[("account", AccessLevel::BusinessUnit)]), None);
        assert!(!sql.contains("organization_ref"), "{sql}");
    }

    // ── C-14: string API / QueryBuilder API equivalence ───────────────────
    //
    // This module's own header promises: "this is a second *interface* to
    // one enforcement rule, not a second rule. `generated_sql_matches_the_string_api`
    // pins that." That test never existed until now — this is it.

    /// Collapses whitespace to single spaces (then drops the space
    /// altogether when it sits directly against a parenthesis — the string
    /// form's raw-string literal is hand-indented for readability, the
    /// `QueryBuilder` form concatenates with none, and SQL itself does not
    /// care either way) and replaces every `$N` placeholder with a fixed
    /// `$#` marker. Placeholder *numbers* necessarily differ between the two
    /// backends (the string form binds each value once and reuses its `$N`;
    /// `QueryBuilder::push_bind` allocates a fresh one per call — see this
    /// module's header), so a useful equivalence check must ignore them; it
    /// must NOT ignore anything else, or it stops proving the two backends
    /// render the same rule.
    fn normalize(sql: &str) -> String {
        let collapsed = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let depunctuated = collapsed.replace("( ", "(").replace(" )", ")");
        let mut out = String::with_capacity(depunctuated.len());
        let mut chars = depunctuated.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' {
                out.push('$');
                while matches!(chars.peek(), Some(d) if d.is_ascii_digit()) {
                    chars.next();
                }
                out.push('#');
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The full matrix: every `AccessLevel` (tier) x default-share
    /// present/absent (share kind) x fast-tier configured/not, for both
    /// `polymorphic_audit_predicate` (string) and
    /// `PolymorphicVisibility::push` (`QueryBuilder`). The deny clause is
    /// unconditional in both (always part of the generated SQL), so it is
    /// covered by every case rather than needing its own axis.
    #[test]
    fn generated_sql_matches_the_string_api() {
        let tiers = [
            AccessLevel::None,
            AccessLevel::Team,
            AccessLevel::BusinessUnit,
            AccessLevel::Global,
        ];
        let fast_tiers = [
            None,
            Some(FastTierColumns {
                organization_ref: "t.organization_ref",
            }),
        ];

        for access_level in tiers {
            for default_share in [false, true] {
                for fast_tier in fast_tiers {
                    let c = ctx(false);
                    let entity_ref = Uuid::now_v7();
                    let mut access_by_entity = HashMap::new();
                    access_by_entity.insert("account".to_owned(), (entity_ref, access_level));
                    let defaults: HashSet<Uuid> = if default_share {
                        std::iter::once(entity_ref).collect()
                    } else {
                        HashSet::new()
                    };

                    let via_string = crate::rls::polymorphic_audit_predicate(
                        &c,
                        &access_by_entity,
                        &defaults,
                        fast_tier,
                        "t.entity_name",
                        "t.record_id",
                        2,
                    );

                    let vis =
                        PolymorphicVisibility::new(&c, &access_by_entity, &defaults, fast_tier);
                    let mut qb: QueryBuilder<Postgres> =
                        QueryBuilder::new("SELECT 1 FROM t WHERE true");
                    vis.push(&mut qb, "t.entity_name", "t.record_id");
                    let full_sql = qb.into_sql();
                    let via_qb = full_sql
                        .strip_prefix("SELECT 1 FROM t WHERE true")
                        .expect("push must only append after the prefix, never rewrite it");

                    assert_eq!(
                        normalize(&via_string.sql),
                        normalize(via_qb),
                        "string API and QueryBuilder API must render the exact same \
                         clause (up to whitespace and placeholder numbering) — \
                         access_level={access_level:?}, default_share={default_share}, \
                         fast_tier={}",
                        fast_tier.is_some(),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod balance {
    use super::*;

    /// Parenthesis balance, checked mechanically.
    ///
    /// A fragment assembled from twenty `push` calls is exactly the kind of
    /// string where a missing `)` is invisible to review and produces
    /// "syntax error at end of input" only when it reaches a database. The
    /// shape tests above cannot see it — they match substrings — which is why
    /// this counts.
    #[test]
    fn the_pushed_fragment_is_parenthesis_balanced() {
        for tier in [
            None,
            Some(FastTierColumns {
                organization_ref: "t.organization_ref",
            }),
        ] {
            let c = SecurityContext {
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
                service_principal: false,
            };
            let mut m = HashMap::new();
            m.insert("account".to_string(), (Uuid::now_v7(), AccessLevel::Team));
            let vis = PolymorphicVisibility::new(&c, &m, &HashSet::new(), tier);

            let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT 1 FROM t WHERE true");
            vis.push(&mut qb, "t.entity_logicalname", "t.record_id");
            let sql = qb.into_sql();

            let mut depth = 0i32;
            for ch in sql.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "closed one paren too many: {sql}");
            }
            assert_eq!(depth, 0, "unbalanced parentheses (depth {depth}): {sql}");
        }
    }
}

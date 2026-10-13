//! C-14: one shared writer for D-133's RLS predicate, instead of four
//! independent hand-copies of the same rule.
//!
//! Before this module, the share-principal disjunction
//! (`principal_type = 0 AND principal_id = caller) OR (principal_type = 1
//! AND principal_id = ANY(teams)) [OR (... subordinates)]`) was hand-copied
//! at every allow/deny check across [`crate::rls::build_predicate`],
//! [`crate::rls::polymorphic_audit_predicate`], and
//! [`crate::visibility::PolymorphicVisibility::push`]/
//! [`crate::visibility::PolymorphicVisibility::push_share_semi_join`], and
//! the deny clause that wraps it was hand-copied once per function (4x).
//! Two of those four functions render into a `String` with hand-numbered
//! `$N` placeholders; the other two push straight into a
//! `sqlx::QueryBuilder`, which assigns placeholders itself via `push_bind`.
//!
//! There is no single representation that serves both without changing the
//! placeholder economy either backend already commits to: the string form
//! binds each value once and references the same `$N` as many times as the
//! shape needs (sqlx's native placeholder reuse — required so
//! [`crate::rls::RlsBinds`] stays a fixed [`RLS_BIND_COUNT`]-tuple every
//! caller binds the same way); `QueryBuilder::push_bind` allocates a fresh
//! placeholder on every call with no way to reference an earlier one, so
//! re-binding the same value per occurrence is that backend's own correct
//! shape. This module therefore writes the shared clause **twice** — once
//! for each backend — but only once *per backend*, so every caller of
//! either form gets the exact same clause text/shape and the exact same
//! argument order. That is what "one fragment writer" means here: one
//! module that owns the rule, not one function that ignores which backend
//! is asking.
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

/// `record_share`/`entity_default_share.principal_type`
/// values — named so the disjunction below reads as what it means rather
/// than repeating bare integers at every call site.
const PRINCIPAL_USER: i16 = 0;
const PRINCIPAL_TEAM: i16 = 1;

/// `record_share.capability`/`entity_default_share.capability`
/// value that always denies, regardless of `required` (see
/// [`crate::rls::Capability`]'s doc comment on the allow-side range check
/// this deliberately sits outside of).
pub(crate) const DENY_CAPABILITY: i16 = 2;

/// The fixed number of bind values [`crate::rls::RlsBinds`] always carries,
/// in the fixed order its fields are declared. Every caller of
/// [`bind_rls_predicate`], and every arithmetic offset past a tier fragment
/// (`rls_predicate_with_conditions`'s own condition placeholders start
/// here), must use this constant rather than a bare `6`.
pub const RLS_BIND_COUNT: usize = 6;

/// A monotonic `$N` counter. Replaces the hand-added-per-field arithmetic
/// (`first_placeholder + 1`, `+ 2`, ...) a placeholder layout used to need —
/// one call per placeholder, so adding, removing, or reordering a field can
/// never silently skip or repeat a number.
pub(crate) struct PlaceholderAllocator {
    next: usize,
}

impl PlaceholderAllocator {
    pub(crate) fn new(first_placeholder: usize) -> Self {
        Self {
            next: first_placeholder,
        }
    }

    /// Returns the next `$N` number and advances past it.
    pub(crate) fn next(&mut self) -> usize {
        let n = self.next;
        self.next += 1;
        n
    }
}

// ── String form ──────────────────────────────────────────────────────────
//
// Used by `crate::rls::build_predicate` and
// `crate::rls::polymorphic_audit_predicate`. `caller_ph`/`teams_ph`/
// `subordinates_ph` are already-rendered SQL expressions (a cached
// `$N::uuid`/`$N::uuid[]` placeholder) — these functions only assemble the
// boolean shape and never bind anything themselves, which is what lets the
// same shape be reused unchanged by the `QueryBuilder` form below.

/// `({alias}.principal_type = 0 AND {alias}.principal_id = {caller_ph}) OR
/// ({alias}.principal_type = 1 AND {alias}.principal_id = ANY({teams_ph}))
/// [OR ({alias}.principal_type = 0 AND {alias}.principal_id =
/// ANY({subordinates_ph}))]` — F138 only ever extends an individual
/// *share* grant (D-133 (2), ownership-as-share-row), never an entity-wide
/// default share and never a deny, so `subordinates_ph` is `None` at every
/// call site except the share-allow check.
pub(crate) fn principal_disjunction_sql(
    alias: &str,
    caller_ph: &str,
    teams_ph: &str,
    subordinates_ph: Option<&str>,
) -> String {
    let mut sql = format!(
        "({alias}.principal_type = {PRINCIPAL_USER} AND {alias}.principal_id = {caller_ph}) OR \
         ({alias}.principal_type = {PRINCIPAL_TEAM} AND {alias}.principal_id = ANY({teams_ph}))"
    );
    if let Some(sub_ph) = subordinates_ph {
        sql.push_str(&format!(
            " OR ({alias}.principal_type = {PRINCIPAL_USER} AND {alias}.principal_id = ANY({sub_ph}))"
        ));
    }
    sql
}

/// `NOT EXISTS ( SELECT 1 FROM record_share {alias} WHERE
/// {alias}.record_id = {record_id_expr} AND {alias}.entity_ref =
/// {entity_ref_expr} AND {alias}.capability = {DENY_CAPABILITY} AND
/// (<principal_disjunction_sql, no subordinate arm>) )` — the deny check,
/// authoritative over every allow arm a caller ANDs this onto.
pub(crate) fn deny_clause_sql(
    alias: &str,
    record_id_expr: &str,
    entity_ref_expr: &str,
    caller_ph: &str,
    teams_ph: &str,
) -> String {
    format!(
        "NOT EXISTS ( SELECT 1 FROM record_share {alias} WHERE {alias}.record_id = {record_id_expr} AND {alias}.entity_ref = {entity_ref_expr} AND {alias}.capability = {DENY_CAPABILITY} AND ({disjunction}) )",
        disjunction = principal_disjunction_sql(alias, caller_ph, teams_ph, None),
    )
}

// ── QueryBuilder form ────────────────────────────────────────────────────
//
// Used by `crate::visibility::PolymorphicVisibility::push`/
// `push_share_semi_join`. Same clause shape as the string form above, but
// every value is freshly `push_bind`ed — `QueryBuilder` has no way to
// reference an earlier placeholder, so re-binding per occurrence is this
// backend's native shape, not a second, drifted copy of the string form's
// bind economy.

/// `QueryBuilder` form of [`principal_disjunction_sql`].
pub(crate) fn push_principal_disjunction(
    qb: &mut QueryBuilder<'_, Postgres>,
    alias: &str,
    caller: Uuid,
    teams: &[Uuid],
    subordinates: Option<&[Uuid]>,
) {
    qb.push(format!(
        "({alias}.principal_type = {PRINCIPAL_USER} AND {alias}.principal_id = "
    ));
    qb.push_bind(caller);
    qb.push(format!(
        "::uuid) OR ({alias}.principal_type = {PRINCIPAL_TEAM} AND {alias}.principal_id = ANY("
    ));
    qb.push_bind(teams.to_vec());
    qb.push("::uuid[]))");
    if let Some(subs) = subordinates {
        qb.push(format!(
            " OR ({alias}.principal_type = {PRINCIPAL_USER} AND {alias}.principal_id = ANY("
        ));
        qb.push_bind(subs.to_vec());
        qb.push("::uuid[]))");
    }
}

/// `QueryBuilder` form of [`deny_clause_sql`]. `push_entity_ref` renders
/// whatever the caller's entity-ref expression is — a fresh bind for a
/// single-entity caller, or a literal array-subscript referencing a
/// placeholder already pushed for the allow arm in a map-based caller. That
/// is the one piece that genuinely differs by shape between `push`'s
/// per-row map lookup and `push_share_semi_join`'s share-table join, so it
/// stays a caller-supplied closure rather than a fixed literal.
pub(crate) fn push_deny_clause(
    qb: &mut QueryBuilder<'_, Postgres>,
    alias: &str,
    record_id_expr: &str,
    push_entity_ref: impl FnOnce(&mut QueryBuilder<'_, Postgres>),
    caller: Uuid,
    teams: &[Uuid],
) {
    qb.push(format!(
        "NOT EXISTS ( SELECT 1 FROM record_share {alias} WHERE {alias}.record_id = {record_id_expr} AND {alias}.entity_ref = "
    ));
    push_entity_ref(qb);
    qb.push(format!(" AND {alias}.capability = {DENY_CAPABILITY} AND ("));
    push_principal_disjunction(qb, alias, caller, teams, None);
    qb.push("))");
}

/// Postgres text-array literal, double-quoted/escaped elements — one
/// canonical implementation for every caller that stringifies a
/// `Vec<String>` as a bind-able array literal
/// ([`crate::rls::PolymorphicAuditBinds::to_text_params`], `crate::conditions`'s
/// `In`-operator rendering). Previously duplicated verbatim in both modules.
pub(crate) fn text_array_literal(values: &[String]) -> String {
    format!(
        "{{{}}}",
        values
            .iter()
            .map(|v| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Binds [`crate::rls::RlsBinds`]'s fixed [`RLS_BIND_COUNT`] values onto a
/// `sqlx::query_scalar` query, in the exact order `RlsBinds`' fields
/// promise — one place, instead of the same six `.bind(...)` calls
/// hand-copied at every `tier_binds` consumer (`entity_crud/access.rs`,
/// `merge.rs`, `related.rs`, `hierarchy.rs`).
pub fn bind_rls_predicate<'q, O>(
    q: sqlx::query::QueryScalar<'q, Postgres, O, sqlx::postgres::PgArguments>,
    binds: &'q crate::rls::RlsBinds,
) -> sqlx::query::QueryScalar<'q, Postgres, O, sqlx::postgres::PgArguments> {
    q.bind(binds.entity_ref)
        .bind(binds.caller_id)
        .bind(&binds.team_ids)
        .bind(binds.capability)
        .bind(&binds.accessible_org_ids)
        .bind(&binds.subordinate_user_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_allocator_is_sequential_with_no_gaps() {
        let mut alloc = PlaceholderAllocator::new(3);
        let got: Vec<usize> = (0..6).map(|_| alloc.next()).collect();
        assert_eq!(got, vec![3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn principal_disjunction_omits_subordinate_arm_by_default() {
        let sql = principal_disjunction_sql("s", "$3::uuid", "$4::uuid[]", None);
        assert!(!sql.contains("$5"));
        assert!(sql.contains("principal_type = 0"));
        assert!(sql.contains("principal_type = 1"));
    }

    #[test]
    fn principal_disjunction_includes_subordinate_arm_when_given() {
        let sql = principal_disjunction_sql("s", "$3::uuid", "$4::uuid[]", Some("$5::uuid[]"));
        assert_eq!(sql.matches("OR").count(), 2);
        assert!(sql.contains("$5::uuid[]"));
    }

    #[test]
    fn deny_clause_never_takes_the_subordinate_arm() {
        let sql = deny_clause_sql("s", "t.id", "$2::uuid", "$3::uuid", "$4::uuid[]");
        assert!(sql.contains("NOT EXISTS"));
        assert!(sql.contains(&format!("capability = {DENY_CAPABILITY}")));
        assert!(
            sql.matches("OR").count() == 1,
            "deny must be 2-arm only: {sql}"
        );
    }

    #[test]
    fn text_array_literal_escapes_quotes_and_backslashes() {
        let literal = text_array_literal(&["a\"b".to_owned(), "c\\d".to_owned()]);
        assert_eq!(literal, r#"{"a\"b","c\\d"}"#);
    }
}

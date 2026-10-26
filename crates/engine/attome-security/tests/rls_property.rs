//! Property-based coverage for `attome_security::rls` (`rls_predicate`,
//! `rls_predicate_by_column`, `polymorphic_audit_predicate`) — the single
//! generic predicate-generation boundary every record-level check in this
//! workspace goes through (`entity_crud.rs`, `bulk.rs`, `files.rs`,
//! `query_exec.rs`; see D-133/D-146/D-149/D-140 in DECISIONS.md).
//!
//! `rls.rs` already has a thorough hand-written unit-test matrix (in its own
//! `#[cfg(test)] mod tests`) pinning specific cases: admin bypass, each
//! `AccessLevel` tier, the capability-range check, the deny clause, the
//! position-hierarchy subordinate bind, `rls_predicate` vs
//! `rls_predicate_by_column`. This file generalizes those same invariants
//! across the *combinatorial* input space (arbitrary UUIDs, team/org/
//! subordinate set sizes, every `AccessLevel` x `Capability` x table-alias
//! combination) rather than the hand-picked examples the unit tests use —
//! the gap a hand-written matrix reliably misses is the corner of the space
//! nobody thought to write an example for.
//!
//! Deliberately pure: every function under test builds a SQL string plus
//! typed bind values with zero I/O, so this suite needs no `DATABASE_URL`,
//! no Redis, no running server — unlike every `#[tokio::test]` suite
//! elsewhere in this workspace. Run with:
//!
//! ```powershell
//! cargo test -p attome-security --test rls_property
//! ```
//!
//! NOT a substitute for `record_level_security.rs`'s HTTP/bulk-level
//! coverage — this file only proves the generated SQL TEXT has the structural
//! properties its doc comments promise, never that Postgres accepts or
//! evaluates it as expected. That half now exists for
//! `polymorphic_audit_predicate` too (it was an open TODO here when this
//! header was written): `record_level_security.rs`'s `polymorphic_audit_*`
//! and `query_execute_*_audit_*` tests run the generated SQL against a live
//! Postgres, including the volume case that F-002/TODO-007 fixed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_security::{
    Capability, polymorphic_audit_predicate, rls_predicate, rls_predicate_by_column,
};
use attome_server::security::{AccessLevel, SecurityContext};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ── Strategies ─────────────────────────────────────────────────────────────

fn arb_uuid() -> impl Strategy<Value = Uuid> {
    any::<u128>().prop_map(Uuid::from_u128)
}

fn arb_uuid_vec(max_len: usize) -> impl Strategy<Value = Vec<Uuid>> {
    prop::collection::vec(arb_uuid(), 0..=max_len)
}

fn arb_access_level() -> impl Strategy<Value = AccessLevel> {
    prop_oneof![
        Just(AccessLevel::None),
        Just(AccessLevel::Team),
        Just(AccessLevel::BusinessUnit),
        Just(AccessLevel::Global),
    ]
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![Just(Capability::View), Just(Capability::Action)]
}

/// A small fixed pool of realistic identifier-shaped column names, rather
/// than arbitrary strings — `id_column` is always an admin-declared,
/// validated identifier in real callers (D-146), never free text.
fn arb_id_column() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("id"),
        Just("contact_id"),
        Just("account_id"),
        Just("record_ref"),
    ]
}

fn arb_table_alias() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(""), Just("t"), Just("acct")]
}

fn capability_i16(cap: Capability) -> i16 {
    match cap {
        Capability::View => 0,
        Capability::Action => 1,
    }
}

fn make_ctx(
    is_admin: bool,
    team_ids: Vec<Uuid>,
    accessible_org_ids: Vec<Uuid>,
    subordinate_user_ids: Vec<Uuid>,
) -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids,
        team_ids,
        position_hierarchy_enabled: false,
        subordinate_user_ids,
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// Every placeholder in `build_predicate`'s generated SQL is immediately
/// followed by an explicit `::type` cast (rls.rs's own doc comment on
/// `build_predicate`) — so `"$N::"` is an unambiguous marker for "placeholder
/// N is referenced here", safe from false hits against unrelated numbers
/// like the literal `1` in `BETWEEN ... AND 1` or the literal `2` in
/// `capability = 2`.
fn references_placeholder(sql: &str, n: usize) -> bool {
    sql.contains(&format!("${n}::"))
}

proptest! {
    /// D-133's central guarantee: `is_admin` or `Global` access means NO
    /// filtering at all (`None`, not an always-true fragment) — regardless
    /// of every other input (alias, capability, placeholder offset, team/org/
    /// subordinate sets). This must hold for both entry points.
    #[test]
    fn admin_or_global_is_always_unfiltered(
        is_admin in any::<bool>(),
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        id_column in arb_id_column(),
        capability in arb_capability(),
        first_placeholder in 1usize..8,
        team_ids in arb_uuid_vec(3),
        org_ids in arb_uuid_vec(3),
        subordinates in arb_uuid_vec(3),
    ) {
        let level = if is_admin { AccessLevel::Team } else { AccessLevel::Global };
        let ctx = make_ctx(is_admin, team_ids, org_ids, subordinates);

        prop_assert!(
            rls_predicate(&ctx, entity_ref, alias, level, capability, first_placeholder).is_none()
        );
        prop_assert!(
            rls_predicate_by_column(&ctx, entity_ref, alias, id_column, level, capability, first_placeholder)
                .is_none()
        );
    }

    /// Whenever filtering DOES apply (not admin, not Global), the deny
    /// clause and the bounded capability range must always be present, and
    /// exact-equality capability checks must never appear — across every
    /// non-bypassing access level, both entry points.
    #[test]
    fn narrowed_access_always_carries_deny_and_bounded_capability(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        id_column in arb_id_column(),
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team), Just(AccessLevel::BusinessUnit)],
        capability in arb_capability(),
        first_placeholder in 1usize..8,
        team_ids in arb_uuid_vec(3),
        org_ids in arb_uuid_vec(3),
        subordinates in arb_uuid_vec(3),
    ) {
        let ctx = make_ctx(false, team_ids, org_ids, subordinates);

        let via_rls = rls_predicate(&ctx, entity_ref, alias, access_level, capability, first_placeholder)
            .expect("non-admin, non-Global must always produce a predicate");
        prop_assert!(via_rls.sql.contains("NOT EXISTS"));
        prop_assert!(via_rls.sql.contains("BETWEEN") && via_rls.sql.contains("AND 1"));
        prop_assert!(!via_rls.sql.contains("capability = $"));
        prop_assert!(via_rls.sql.contains("record_share"));
        prop_assert!(via_rls.sql.contains("entity_default_share"));

        let via_by_column = rls_predicate_by_column(
            &ctx, entity_ref, alias, id_column, access_level, capability, first_placeholder,
        )
        .expect("non-admin, non-Global must always produce a predicate");
        prop_assert!(via_by_column.sql.contains("NOT EXISTS"));
        prop_assert!(via_by_column.sql.contains("BETWEEN") && via_by_column.sql.contains("AND 1"));
        prop_assert!(!via_by_column.sql.contains("capability = $"));
    }

    /// D-146: `rls_predicate_by_column` must never expose the BusinessUnit
    /// organization fast path, at ANY access level — it degrades BU-tier to
    /// share-only, strictly more restrictive than `rls_predicate`, never
    /// less. This is the exact claim the doc comment makes; check it holds
    /// across the whole input space, not just the one hand-picked case the
    /// unit test covers.
    #[test]
    fn by_column_never_exposes_the_organization_fast_path(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        id_column in arb_id_column(),
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team), Just(AccessLevel::BusinessUnit)],
        capability in arb_capability(),
        first_placeholder in 1usize..8,
    ) {
        let ctx = make_ctx(false, vec![], vec![], vec![]);
        let pred = rls_predicate_by_column(
            &ctx, entity_ref, alias, id_column, access_level, capability, first_placeholder,
        )
        .unwrap();
        prop_assert!(!pred.sql.contains("organization_ref"));
    }

    /// The organization fast path appears via `rls_predicate` if and only if
    /// access_level is exactly `BusinessUnit` — never at `None`/`Team`, and
    /// (per the admin/Global test above) never at all once bypassed.
    #[test]
    fn rls_predicate_organization_fast_path_appears_iff_business_unit_tier(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        capability in arb_capability(),
        first_placeholder in 1usize..8,
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team), Just(AccessLevel::BusinessUnit)],
    ) {
        let ctx = make_ctx(false, vec![], vec![], vec![]);
        let pred = rls_predicate(&ctx, entity_ref, alias, access_level, capability, first_placeholder).unwrap();
        prop_assert_eq!(
            pred.sql.contains("organization_ref"),
            access_level == AccessLevel::BusinessUnit
        );
    }

    /// Placeholder-numbering contract (rls.rs's `build_predicate` comment):
    /// entity/caller/teams/capability/subordinates placeholders
    /// (`first_placeholder`, `+1`, `+2`, `+3`, `+5`) are always referenced in
    /// the generated SQL once filtering applies at all; the org placeholder
    /// (`+4`) is referenced only when the BusinessUnit fast path is actually
    /// taken (`rls_predicate` at BusinessUnit tier — never via
    /// `rls_predicate_by_column`, which hardcodes `allow_bu_tier = false`).
    /// A caller composing this fragment into a larger query relies on this
    /// exact contract to renumber correctly; a silent shift here would
    /// desync every downstream bind.
    #[test]
    fn placeholder_numbering_matches_the_documented_contract(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        id_column in arb_id_column(),
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team), Just(AccessLevel::BusinessUnit)],
        capability in arb_capability(),
        first_placeholder in 1usize..6,
    ) {
        let ctx = make_ctx(false, vec![], vec![], vec![]);
        let fp = first_placeholder;

        let via_rls = rls_predicate(&ctx, entity_ref, alias, access_level, capability, fp).unwrap();
        for offset in [0, 1, 2, 3, 5] {
            prop_assert!(
                references_placeholder(&via_rls.sql, fp + offset),
                "expected ${}:: in generated SQL: {}", fp + offset, via_rls.sql
            );
        }
        prop_assert_eq!(
            references_placeholder(&via_rls.sql, fp + 4),
            access_level == AccessLevel::BusinessUnit
        );

        let via_by_column = rls_predicate_by_column(
            &ctx, entity_ref, alias, id_column, access_level, capability, fp,
        )
        .unwrap();
        for offset in [0, 1, 2, 3, 5] {
            prop_assert!(references_placeholder(&via_by_column.sql, fp + offset));
        }
        prop_assert!(!references_placeholder(&via_by_column.sql, fp + 4));
    }

    /// `rls_predicate` and `rls_predicate_by_column("id", ...)` must agree
    /// byte-for-byte at every access level EXCEPT BusinessUnit (where
    /// `rls_predicate` alone takes the org fast path) — the externally
    /// observable half of the same claim rls.rs's own
    /// `rls_predicate_and_by_column_generate_byte_identical_sql_for_the_implicit_id_case`
    /// unit test pins via the private `build_predicate` function directly.
    #[test]
    fn rls_predicate_and_by_column_agree_outside_business_unit_tier(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        capability in arb_capability(),
        first_placeholder in 1usize..8,
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team)],
        team_ids in arb_uuid_vec(3),
        org_ids in arb_uuid_vec(3),
        subordinates in arb_uuid_vec(3),
    ) {
        let ctx = make_ctx(false, team_ids, org_ids, subordinates);
        let via_rls = rls_predicate(&ctx, entity_ref, alias, access_level, capability, first_placeholder).unwrap();
        let via_by_column = rls_predicate_by_column(
            &ctx, entity_ref, alias, "id", access_level, capability, first_placeholder,
        )
        .unwrap();
        prop_assert_eq!(via_rls.sql, via_by_column.sql);

        prop_assert_eq!(&via_rls.binds.team_ids, &via_by_column.binds.team_ids);
        prop_assert_eq!(&via_rls.binds.accessible_org_ids, &via_by_column.binds.accessible_org_ids);
        prop_assert_eq!(&via_rls.binds.subordinate_user_ids, &via_by_column.binds.subordinate_user_ids);
    }

    /// `RlsBinds` always echoes its inputs verbatim, regardless of what
    /// combination produced them — the caller's bind step must never
    /// transpose or drop a value.
    #[test]
    fn rls_binds_echo_their_inputs(
        entity_ref in arb_uuid(),
        alias in arb_table_alias(),
        access_level in prop_oneof![Just(AccessLevel::None), Just(AccessLevel::Team), Just(AccessLevel::BusinessUnit)],
        capability in arb_capability(),
        first_placeholder in 1usize..8,
        team_ids in arb_uuid_vec(3),
        org_ids in arb_uuid_vec(3),
        subordinates in arb_uuid_vec(3),
    ) {
        let ctx = make_ctx(false, team_ids.clone(), org_ids.clone(), subordinates.clone());
        let pred = rls_predicate(&ctx, entity_ref, alias, access_level, capability, first_placeholder).unwrap();

        prop_assert_eq!(pred.binds.entity_ref, entity_ref);
        prop_assert_eq!(pred.binds.caller_id, ctx.user_id);
        prop_assert_eq!(&pred.binds.team_ids, &team_ids);
        prop_assert_eq!(&pred.binds.accessible_org_ids, &org_ids);
        prop_assert_eq!(&pred.binds.subordinate_user_ids, &subordinates);
        prop_assert_eq!(pred.binds.capability, capability_i16(capability));
    }

    /// `to_text_params` must always produce exactly 6 Postgres array/scalar
    /// literals, with every array-typed field wrapped in `{}` (never blank,
    /// never NULL, even when the source `Vec` is empty) and every uuid
    /// value's string form present inside its array literal.
    #[test]
    fn to_text_params_always_produces_six_valid_literals(
        entity_ref in arb_uuid(),
        capability in arb_capability(),
        team_ids in arb_uuid_vec(3),
        org_ids in arb_uuid_vec(3),
        subordinates in arb_uuid_vec(3),
    ) {
        let ctx = make_ctx(false, team_ids.clone(), org_ids.clone(), subordinates.clone());
        let pred = rls_predicate(&ctx, entity_ref, "t", AccessLevel::None, capability, 2).unwrap();
        let params = pred.binds.to_text_params();

        prop_assert_eq!(params.len(), 6);
        for idx in [2usize, 4, 5] {
            let is_pg_array_literal = params[idx].starts_with('{') && params[idx].ends_with('}');
            prop_assert!(is_pg_array_literal, "expected a Postgres array literal at params[{idx}]: {:?}", params[idx]);
        }
        for team_id in &team_ids {
            prop_assert!(params[2].contains(&team_id.to_string()));
        }
        for org_id in &org_ids {
            prop_assert!(params[4].contains(&org_id.to_string()));
        }
        for sub_id in &subordinates {
            prop_assert!(params[5].contains(&sub_id.to_string()));
        }
        if team_ids.is_empty() {
            prop_assert_eq!(&params[2], "{}");
        }
    }

    // ── polymorphic_audit_predicate (D-140 follow-up) ───────────────────────

    /// D-146 precedent generalized: the polymorphic-audit predicate must
    /// never expose the organization fast path, for any map of
    /// (logicalname -> access level) — it structurally cannot join to a
    /// dynamically-named per-row target table (see the function's own doc
    /// comment).
    #[test]
    fn polymorphic_predicate_never_exposes_organization_fast_path(
        levels in prop::collection::vec(arb_access_level(), 0..5),
    ) {
        let ctx = make_ctx(false, vec![], vec![], vec![]);
        let map: HashMap<String, (Uuid, AccessLevel)> = levels
            .into_iter()
            .enumerate()
            .map(|(i, level)| (format!("entity_{i}"), (Uuid::now_v7(), level)))
            .collect();
        let pred = polymorphic_audit_predicate(
            &ctx, &map, &HashSet::new(), None, "h.entity_name", "h.record_id", 2,
        );
        prop_assert!(!pred.sql.contains("organization_ref"));
        prop_assert!(pred.sql.contains("BETWEEN 0 AND 1"));
        prop_assert!(pred.sql.contains("NOT EXISTS"));
    }

    /// Bind arrays are always four parallel arrays in the same order as the
    /// map traversal, for any map shape (including the empty map, which must
    /// still produce valid `{}` literals rather than panicking or producing
    /// mismatched lengths). D-357 added the fourth (`default_shares`); a
    /// caller that built it from a *different* traversal than the other three
    /// would mis-index a permission decision, which is why this asserts
    /// position agreement rather than just length.
    #[test]
    fn polymorphic_predicate_binds_stay_parallel_for_any_map_shape(
        levels in prop::collection::vec(arb_access_level(), 0..6),
        default_flags in prop::collection::vec(any::<bool>(), 0..6),
    ) {
        let ctx = make_ctx(false, vec![], vec![], vec![]);
        let map: HashMap<String, (Uuid, AccessLevel)> = levels
            .into_iter()
            .enumerate()
            .map(|(i, level)| (format!("entity_{i}"), (Uuid::now_v7(), level)))
            .collect();

        // Mark an arbitrary subset of the map's entities as default-shared.
        let mut names: Vec<&String> = map.keys().collect();
        names.sort();
        let defaults: HashSet<Uuid> = names
            .iter()
            .enumerate()
            .filter(|(i, _)| default_flags.get(*i).copied().unwrap_or(false))
            .map(|(_, name)| map[*name].0)
            .collect();

        let pred = polymorphic_audit_predicate(
            &ctx, &map, &defaults, None, "h.entity_name", "h.record_id", 2,
        );

        prop_assert_eq!(pred.binds.logicalnames.len(), map.len());
        prop_assert_eq!(pred.binds.entity_refs.len(), map.len());
        prop_assert_eq!(pred.binds.access_levels.len(), map.len());
        prop_assert_eq!(pred.binds.default_shares.len(), map.len());
        for (name, (entity_ref, level)) in &map {
            let idx = pred
                .binds
                .logicalnames
                .iter()
                .position(|n| n == name)
                .expect("every map key must appear in the bound logicalname array");
            prop_assert_eq!(pred.binds.entity_refs[idx], *entity_ref);
            prop_assert_eq!(pred.binds.access_levels[idx], *level as i16);
            prop_assert_eq!(pred.binds.default_shares[idx], defaults.contains(entity_ref));
        }

        let params = pred.binds.to_text_params();
        prop_assert_eq!(params.len(), 8);
        if map.is_empty() {
            prop_assert_eq!(&params[0], "{}");
            prop_assert_eq!(&params[1], "{}");
            prop_assert_eq!(&params[2], "{}");
            prop_assert_eq!(&params[3], "{}");
        }
        // The fast tier's org array is ALWAYS bound, tier or no tier — an
        // empty array makes `= ANY(...)` correctly match nothing rather than
        // needing a second SQL shape.
        // `prop_assert!` stringifies its argument into a format string, so a
        // literal brace anywhere in the expression is parsed as a placeholder.
        // Comparing a precomputed bool sidesteps that.
        let orgs = &params[7];
        let is_array_literal = orgs.starts_with('{') && orgs.ends_with('}');
        prop_assert!(is_array_literal);
    }
}

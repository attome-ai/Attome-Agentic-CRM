//! D-133: record-level access predicate — the generic, entity-agnostic SQL
//! fragment `entity_crud.rs`'s four handlers splice into their existing
//! WHERE/CTE construction. One function, reused everywhere a record-level
//! check is needed (guidelines §9: generic dispatch only, no per-entity
//! code).

use attome_core::AttrInfo;
use attome_server::security::{AccessLevel, SecurityContext};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::rls_fragment::{
    PlaceholderAllocator, RLS_BIND_COUNT, SHARE_ROWS, deny_clause_sql, principal_disjunction_sql,
    text_array_literal,
};

/// `record_share.capability`/`entity_default_share.capability`
/// values (D-133 migration `0051`: 0=view 1=action 2=deny). Ordered:
/// `action` satisfies a `view` requirement (D-133 (4): "view OR action
/// grants both satisfy a read") but never the reverse, and `deny` (2) must
/// never satisfy either as an allow — the generated SQL below expresses
/// this as `capability BETWEEN required AND 1`, not equality, specifically
/// to cap the range below `deny` while still accepting the more-permissive
/// tier.
///
/// Deliberately orthogonal to `db::RecordAction` (`Read`/`Update`/`Delete`,
/// 3-valued): that type selects which `role_mm_entity_access` column
/// resolves the *role-ladder depth* (None/Team/BusinessUnit/Global) for a
/// caller's `(entity, action)`; this type gates only the coarser
/// view-vs-mutate check against an explicit `record_share`/
/// `entity_default_share` row, which has never distinguished update
/// from delete. An update and a delete on the same record both need
/// `Action` here even though they resolve independent depths via
/// `RecordAction::Update`/`RecordAction::Delete`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    View,
    Action,
}

impl Capability {
    /// The `capability` value this requirement binds as — the lower bound of
    /// the `capability BETWEEN required AND 1` range every allow-check uses.
    /// Public so callers that resolve part of the check outside the generated
    /// SQL (`db::resolve_default_share_entities`) express the same bound
    /// rather than hardcoding a literal.
    pub fn as_i16(self) -> i16 {
        match self {
            Capability::View => 0,
            Capability::Action => 1,
        }
    }
}

/// A generated predicate fragment plus its bind values, in the exact order
/// they must be bound after whatever positional parameters the caller's own
/// query already uses (the fragment's placeholders start at
/// `first_placeholder`, chosen by the caller so this composes with an
/// existing `WHERE id = $1 AND is_active = true`-shaped clause without
/// renumbering).
pub struct RlsPredicate {
    /// SQL fragment beginning with `AND (...)`. `rls_predicate` returns
    /// `Option::None` (not an empty-string variant of this struct) for
    /// `Global`/`is_admin` — a caller who never narrows a grant gets no
    /// `RlsPredicate` at all, so the generated SQL is byte-identical to
    /// pre-D-133 code, not "an always-true fragment appended."
    pub sql: String,
    pub binds: RlsBinds,
}

impl std::fmt::Debug for RlsPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlsPredicate").finish_non_exhaustive()
    }
}

/// Bind values for [`RlsPredicate::sql`], in the fixed placeholder order
/// `rls_predicate` numbers them (`$first_placeholder` = `entity_ref`,
/// `+1` = `caller_id`, `+2` = `team_ids`, `+3` = `capability`, `+4` =
/// `accessible_org_ids`, `+5` = `subordinate_user_ids`). Kept as a struct,
/// not a positional tuple/`Vec`, so a caller binds by field name — harder to
/// accidentally transpose two `Vec<Uuid>`s of the same type in the wrong
/// order.
pub struct RlsBinds {
    pub entity_ref: Uuid,
    pub caller_id: Uuid,
    pub team_ids: Vec<Uuid>,
    pub capability: i16,
    pub accessible_org_ids: Vec<Uuid>,
    /// F138: every user in the caller's position subtree — empty unless
    /// `SecurityContext::position_hierarchy_enabled` is true. Always bound
    /// (never conditionally omitted), same as `team_ids`: an empty array
    /// makes the generated `= ANY(...)` clause correctly evaluate to no
    /// match rather than needing a separate SQL branch.
    pub subordinate_user_ids: Vec<Uuid>,
}

impl std::fmt::Debug for RlsBinds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlsBinds").finish_non_exhaustive()
    }
}

impl RlsBinds {
    /// Stringifies every bind value in placeholder order, for a caller
    /// whose own param-binding convention is a flat `Vec<String>` with
    /// in-SQL `::type` casts (`query_exec.rs`) rather than typed
    /// `.bind(Uuid)`/`.bind(Vec<Uuid>)` calls (`entity_crud.rs`) —
    /// `rls_predicate`'s generated SQL casts every placeholder explicitly
    /// (`$N::uuid`, `$N::uuid[]`, `$N::smallint`), so a plain Postgres text
    /// representation binds correctly either way. `Vec<Uuid>` becomes a
    /// Postgres array literal (`{u1,u2}` — empty `Vec` becomes `{}`, a
    /// valid empty array, not NULL, so `= ANY('{}')` correctly evaluates to
    /// no match rather than NULL/error).
    pub fn to_text_params(&self) -> Vec<String> {
        vec![
            self.entity_ref.to_string(),
            self.caller_id.to_string(),
            uuid_array_literal(&self.team_ids),
            self.capability.to_string(),
            uuid_array_literal(&self.accessible_org_ids),
            uuid_array_literal(&self.subordinate_user_ids),
        ]
    }
}

fn uuid_array_literal(ids: &[Uuid]) -> String {
    format!(
        "{{{}}}",
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Postgres boolean-array literal (`{t,f}`) — the single-letter form
/// Postgres itself emits, accepted by `::boolean[]` on input.
fn bool_array_literal(values: &[bool]) -> String {
    format!(
        "{{{}}}",
        values
            .iter()
            .map(|v| if *v { "t" } else { "f" })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn smallint_array_literal(values: &[i16]) -> String {
    format!(
        "{{{}}}",
        values
            .iter()
            .map(i16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Builds the record-level predicate for one entity/action check.
///
/// `table_alias` is the caller's already-quoted alias for the entity table
/// (or `""` for an unaliased single-table query — the fragment omits the
/// `alias.` prefix in that case). `entity_ref` is the entity's
/// `entity_info.id` (resolved once per request by every handler via
/// `resolve_entity`, not re-queried here). `access_level` is the caller's
/// resolved depth for this exact `(entity_ref, action)` —
/// `db::resolve_entity_access_level`'s result, passed in rather than read
/// off `ctx` directly; record-level scope is no longer a single flat field
/// on `SecurityContext` (that was the cross-entity leak — see
/// `resolve_entity_access_level`'s doc comment). `first_placeholder` is the
/// next free `$N` — the fragment's placeholders are numbered starting there.
///
/// Returns `None` when no filtering applies at all: `is_admin`, or
/// `access_level == Global`. This is the same "zero behavior change until a
/// grant is narrowed" guarantee D-133 originally required — a caller whose
/// resolved depth for this entity/action is still `Global` (every role's
/// default) gets byte-identical generated SQL to pre-D-133 code.
pub fn rls_predicate(
    ctx: &SecurityContext,
    entity_ref: Uuid,
    table_alias: &str,
    access_level: AccessLevel,
    required: Capability,
    first_placeholder: usize,
) -> Option<RlsPredicate> {
    build_predicate(
        ctx,
        entity_ref,
        table_alias,
        "id",
        true,
        false,
        access_level,
        required,
        first_placeholder,
    )
}

/// P-stored-query-containment Phase 3 (D-146) — same predicate shape as
/// [`rls_predicate`], but keyed on an admin-declared output column instead of
/// the implicit `"id"`. Used when RLS is applied to the *outer* wrapper of a
/// custom/multi-entity stored query (`query_exec.rs`'s `FROM ({base_sql}) AS
/// t`) rather than a real `FROM`-clause table — the query's own author
/// declares, per entity the report should be row-filtered on, which output
/// column carries that entity's row id (`sql_query_entity_mapping`).
///
/// The BusinessUnit-tier organization fast path is deliberately unavailable
/// here (no admin-declared org column in v1): a BusinessUnit-scoped caller is
/// treated the same as Team-tier for this entity — an explicit
/// `record_share`/`entity_default_share` row is required, org
/// membership alone does not grant visibility. This is strictly more
/// restrictive than [`rls_predicate`], never less — see D-146 for why the
/// org-column case is deferred rather than guessed at.
pub fn rls_predicate_by_column(
    ctx: &SecurityContext,
    entity_ref: Uuid,
    table_alias: &str,
    id_column: &str,
    access_level: AccessLevel,
    required: Capability,
    first_placeholder: usize,
) -> Option<RlsPredicate> {
    build_predicate(
        ctx,
        entity_ref,
        table_alias,
        id_column,
        false,
        false,
        access_level,
        required,
        first_placeholder,
    )
}

/// A [`RlsPredicate`]-shaped fragment that may additionally carry a D-369
/// condition narrowing, returned by [`rls_predicate_with_conditions`].
/// `tier_binds` is `None` exactly when the tier/share/deny logic contributed
/// nothing to `sql` (the caller's tier is `Global`, or there is no tier
/// fragment at all) — mirrors [`RlsPredicate`]'s own "no fragment, not an
/// empty one" convention, just split across the two independent halves this
/// function can combine.
pub struct ConditionAwarePredicate {
    /// Already-combined `AND (...) [AND (...)]` fragment, ready to splice
    /// into a caller's WHERE clause exactly like [`RlsPredicate::sql`].
    pub sql: String,
    /// Present iff the tier/share/deny fragment is part of `sql` — bind in
    /// the same fixed order [`RlsBinds::to_text_params`]/its field order
    /// already documents.
    pub tier_binds: Option<RlsBinds>,
    /// Present iff a condition fragment is part of `sql` — bind as plain
    /// text in order after `tier_binds`' six placeholders (or starting at
    /// `first_placeholder` when `tier_binds` is `None`); every placeholder
    /// carries its own explicit `::type` cast in `sql`, same convention as
    /// [`RlsBinds::to_text_params`].
    pub condition_binds: Vec<String>,
}

impl std::fmt::Debug for ConditionAwarePredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConditionAwarePredicate")
            .finish_non_exhaustive()
    }
}

/// D-369 v1: same behavior as [`rls_predicate`], but additionally ANDs in
/// any active [`SecurityContext::condition_grants`] entry for
/// `privilege_key`. Only `entity_crud.rs`'s direct paths call this function
/// — every other `rls_predicate`/`rls_predicate_by_column` caller is
/// unaffected by D-369 entirely (see `condition_grants`' doc comment on
/// `SecurityContext`).
///
/// `ctx.is_admin` still fully bypasses, condition or not — admin is the
/// system's existing "God mode" bypass used pervasively elsewhere (audit,
/// field security, `ctx.require`), a stronger and orthogonal concept from a
/// role's own access-level ladder, and D-369 does not touch it.
///
/// **The `Global`-tier short-circuit does not bypass an active condition —
/// this is the load-bearing difference from a naive "AND a fragment onto
/// `build_predicate`'s `allow`" patch.** `build_predicate` alone returns
/// `None` for `Global` (as it must — the tier/share/deny logic genuinely has
/// nothing left to check at that point), but a condition is an orthogonal
/// narrowing layer: a `Global`-tier role holding a conditional grant on this
/// exact privilege must still be filtered by it. This function computes the
/// condition fragment independently of `build_predicate`'s tier
/// short-circuit and ANDs it on regardless of tier, closing the fail-open
/// gap a naive patch (checking conditions only inside the already-narrowed
/// branch) would have left — `build_predicate` returns before its `allow`
/// fragment is even built for `Global`, so nothing appended there would ever
/// run for exactly the tier where D-369's own example (a `Global`-tier role
/// with a conditional grant) lives.
/// `owner_visible` (D-371, amends D-357 ruling 2) is resolved by the caller
/// via `db::resolve_owner_visible` and threaded straight into
/// `build_predicate` — unlike conditions, ownership visibility only ever
/// *widens* what a caller sees, so it needs no special handling around the
/// `Global`/`is_admin` short-circuit the way conditions did: `Global`
/// already grants everything, so the short-circuit losing the owner arm at
/// that tier is correct, not a gap.
#[allow(clippy::too_many_arguments)]
pub fn rls_predicate_with_conditions(
    ctx: &SecurityContext,
    entity_ref: Uuid,
    table_alias: &str,
    access_level: AccessLevel,
    required: Capability,
    privilege_key: &str,
    attrs: &[AttrInfo],
    owner_visible: bool,
    first_placeholder: usize,
) -> Option<ConditionAwarePredicate> {
    if ctx.is_admin {
        return None;
    }

    let tier = build_predicate(
        ctx,
        entity_ref,
        table_alias,
        "id",
        true,
        owner_visible,
        access_level,
        required,
        first_placeholder,
    );

    let next_placeholder = first_placeholder + if tier.is_some() { RLS_BIND_COUNT } else { 0 };
    let condition = crate::conditions::condition_predicate(
        ctx,
        privilege_key,
        attrs,
        table_alias,
        next_placeholder,
    );

    match (tier, condition) {
        (None, None) => None,
        (Some(t), None) => Some(ConditionAwarePredicate {
            sql: t.sql,
            tier_binds: Some(t.binds),
            condition_binds: Vec::new(),
        }),
        (None, Some(c)) => Some(ConditionAwarePredicate {
            sql: format!("AND ({})", c.sql),
            tier_binds: None,
            condition_binds: c.binds,
        }),
        (Some(t), Some(c)) => Some(ConditionAwarePredicate {
            sql: format!("{} AND ({})", t.sql, c.sql),
            tier_binds: Some(t.binds),
            condition_binds: c.binds,
        }),
    }
}

/// Shared predicate builder behind [`rls_predicate`]/[`rls_predicate_by_column`]/
/// [`rls_predicate_with_conditions`]. `id_column` names the column carrying
/// the entity's row id (`"id"` for a real FROM-clause table; an
/// admin-declared alias for a wrapped custom-query output column).
/// `allow_bu_tier` gates whether the BusinessUnit-tier organization fast path
/// may fire at all — `false` forces it to `FALSE` regardless of
/// `access_level`, the same shape `access_level == Team`/`None` already
/// produce, so a caller that doesn't support an org-column mapping degrades
/// to share-only enforcement rather than guessing at an organization column
/// that might not exist in its output.
///
/// `owner_visible` (D-371, amends D-357 ruling 2) adds one more OR arm —
/// `owner_ref = caller AND owner_type = 0` (user ownership) — **inside** this
/// same deny-guarded `allow` fragment, in the same position the
/// BusinessUnit-tier fast path already occupies. `false` (the only value
/// [`rls_predicate`]/[`rls_predicate_by_column`] ever pass) produces
/// byte-identical output to before this parameter existed — only
/// [`rls_predicate_with_conditions`] ever passes a resolved `true`. Reuses
/// the `$p_caller` placeholder already bound for the share checks; no new
/// bind parameter.
#[allow(clippy::too_many_arguments)]
fn build_predicate(
    ctx: &SecurityContext,
    entity_ref: Uuid,
    table_alias: &str,
    id_column: &str,
    allow_bu_tier: bool,
    owner_visible: bool,
    access_level: AccessLevel,
    required: Capability,
    first_placeholder: usize,
) -> Option<RlsPredicate> {
    if ctx.is_admin || access_level == AccessLevel::Global {
        return None;
    }

    let col = |name: &str| -> String {
        if table_alias.is_empty() {
            name.to_owned()
        } else {
            format!("{table_alias}.{name}")
        }
    };

    // Placeholder layout (fixed order, matches RlsBinds field order) —
    // allocated one at a time so a layout change can never silently skip or
    // repeat a number:
    //   $N   = entity_ref (share/deny subqueries)
    //   $N+1 = caller_id (user-principal match)
    //   $N+2 = team_ids (team-principal match)
    //   $N+3 = required capability (share allow-check)
    //   $N+4 = accessible_org_ids (BusinessUnit tier; empty vec if unused)
    //   $N+5 = subordinate_user_ids (F138 position hierarchy; empty vec if unused)
    let mut alloc = PlaceholderAllocator::new(first_placeholder);
    let p_entity = alloc.next();
    let p_caller = alloc.next();
    let p_teams = alloc.next();
    let p_cap = alloc.next();
    let p_orgs = alloc.next();
    let p_subordinates = alloc.next();

    let record_id_col = col(id_column);
    let org_col = col("organization_ref");
    let owner_col = col("owner_ref");
    let owner_type_col = col("owner_type");

    // Every placeholder carries an explicit `::type` cast — a no-op for a
    // caller (e.g. `entity_crud.rs`) that binds real typed values via
    // sqlx's `.bind(Uuid)`/`.bind(Vec<Uuid>)`/`.bind(i16)` (Postgres accepts
    // `$1::uuid` whether or not the driver already typed `$1` as uuid), but
    // load-bearing for a caller (e.g. `query_exec.rs`) whose existing
    // param-binding convention is a flat `Vec<String>` with in-SQL casts —
    // that caller can splice this same fragment in and stringify its binds
    // (`Uuid::to_string()`, a Postgres `{u1,u2}` array literal) rather than
    // this module needing a second, duplicated fragment-builder.
    let caller_ph = format!("${p_caller}::uuid");
    let teams_ph = format!("${p_teams}::uuid[]");
    let subordinates_ph = format!("${p_subordinates}::uuid[]");

    let allow = format!(
        r#"(
            ({bu_tier})
            OR ({owner_arm})
            OR EXISTS (
                SELECT 1 FROM {SHARE_ROWS} s
                WHERE s.record_id = {record_id_col} AND s.entity_ref = ${p_entity}::uuid
                  AND s.capability BETWEEN ${p_cap}::smallint AND 1
                  AND ({share_disjunction})
            )
            OR EXISTS (
                SELECT 1 FROM entity_default_share d
                WHERE d.entity_ref = ${p_entity}::uuid
                  AND d.capability BETWEEN ${p_cap}::smallint AND 1
                  AND ({default_share_disjunction})
            )
        )"#,
        bu_tier = if allow_bu_tier && access_level == AccessLevel::BusinessUnit {
            format!("{org_col} = ANY(${p_orgs}::uuid[])")
        } else {
            // Team tier (or None, which never reaches here — see below), or
            // a caller that doesn't support the org fast path at all
            // (`allow_bu_tier = false`): BU comparison is never true, so the
            // allow-chain falls through to the share/default-share EXISTS
            // checks, which already cover the Team tier via principal_type
            // = 1 team matches.
            "FALSE".to_owned()
        },
        owner_arm = if owner_visible {
            format!("{owner_col} = ${p_caller}::uuid AND {owner_type_col} = 0")
        } else {
            "FALSE".to_owned()
        },
        share_disjunction =
            principal_disjunction_sql("s", &caller_ph, &teams_ph, Some(&subordinates_ph)),
        default_share_disjunction = principal_disjunction_sql("d", &caller_ph, &teams_ph, None),
    );

    // `AccessLevel::None` holds no role at all — no BU/Team tier match is
    // possible, but an explicit share can still grant access (D-133: share
    // rows are independent of the ladder, not gated behind holding a role).
    // The `allow` fragment above already expresses that correctly for
    // `None` too (BU tier is `FALSE`, share/default-share EXISTS still run).

    let deny = deny_clause_sql(
        "s",
        &record_id_col,
        &format!("${p_entity}::uuid"),
        &caller_ph,
        &teams_ph,
    );

    let sql = format!("AND {allow} AND {deny}");

    Some(RlsPredicate {
        sql,
        binds: RlsBinds {
            entity_ref,
            caller_id: ctx.user_id,
            team_ids: ctx.team_ids.clone(),
            capability: required.as_i16(),
            accessible_org_ids: ctx.accessible_org_ids.clone(),
            subordinate_user_ids: ctx.subordinate_user_ids.clone(),
        },
    })
}

/// Opt-in BusinessUnit fast tier for [`polymorphic_audit_predicate`]
/// (TODO-003).
///
/// **Why this is opt-in and not simply always on.** D-146 and the polymorphic
/// predicate's own doc comment record that a BU-tier organization fast path is
/// *structurally unavailable* there: the predicate cannot reach the target
/// entity's own row, because that is a differently-named physical table per
/// row which one static statement cannot join to. That reasoning is unchanged
/// and still correct for the audit call sites.
///
/// It stops applying when the rows being filtered carry `organization_ref`
/// **themselves**. `search_index` does: every indexed row copies the
/// source record's organization at index time, precisely so this tier becomes
/// possible. So the caller declares the column it can offer, and a caller that
/// has none passes `None` and gets byte-identical SQL to before.
///
/// **There is no owner tier, and there will not be one.** The search plan's v1
/// described a second tier ORing an `owner_id` match — that admits rows of
/// entities the caller holds no read privilege on at all, and it escapes the
/// deny check. Ownership grants nothing in this platform (`rls.rs`'s
/// `build_predicate`, D-357 ruling 2); `owner_id` on the index is a ranking
/// signal and nothing else.
#[derive(Clone, Copy, Debug)]
pub struct FastTierColumns<'a> {
    /// The filtered row's own organization column, already qualified for the
    /// caller's alias (e.g. `"s.organization_ref"`). Must be a literal chosen
    /// by the calling code, never request data — it is spliced into SQL.
    pub organization_ref: &'a str,
}

/// Bind values for [`polymorphic_audit_predicate`]'s generated SQL, in the
/// fixed placeholder order it numbers them (`$first_placeholder` =
/// `logicalnames`, `+1` = `entity_refs`, `+2` = `access_levels`, `+3` =
/// `default_shares`, `+4` = `caller_id`, `+5` = `team_ids`, `+6` =
/// `subordinate_user_ids`). The first four arrays are parallel (same length,
/// same index maps to one entity) — callers must build them from the same
/// iteration order, which `polymorphic_audit_predicate` itself guarantees
/// since it builds all four from one map traversal.
pub struct PolymorphicAuditBinds {
    pub logicalnames: Vec<String>,
    pub entity_refs: Vec<Uuid>,
    pub access_levels: Vec<i16>,
    /// Whether the caller holds an allow `entity_default_share` row
    /// on the entity at the same index — resolved once per request by
    /// [`crate::db::resolve_default_share_entities`] instead of per candidate
    /// row, since that table carries no `record_id` and so returns the same
    /// answer for every row of an entity.
    pub default_shares: Vec<bool>,
    pub caller_id: Uuid,
    pub team_ids: Vec<Uuid>,
    pub subordinate_user_ids: Vec<Uuid>,
    /// The caller's organizations, for the opt-in fast tier. **Always bound**,
    /// even when the tier is unused — an empty array makes the generated
    /// `= ANY(...)` correctly match nothing rather than needing a second SQL
    /// shape, the same convention `team_ids` already follows.
    pub accessible_org_ids: Vec<Uuid>,
}

impl std::fmt::Debug for PolymorphicAuditBinds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolymorphicAuditBinds")
            .finish_non_exhaustive()
    }
}

impl PolymorphicAuditBinds {
    /// Same text-param convention as [`RlsBinds::to_text_params`] —
    /// `query_exec.rs`'s existing flat `Vec<String>` binding shape, every
    /// placeholder cast explicitly in the generated SQL so this binds
    /// correctly as plain Postgres text regardless.
    pub fn to_text_params(&self) -> Vec<String> {
        vec![
            text_array_literal(&self.logicalnames),
            uuid_array_literal(&self.entity_refs),
            smallint_array_literal(&self.access_levels),
            bool_array_literal(&self.default_shares),
            self.caller_id.to_string(),
            uuid_array_literal(&self.team_ids),
            uuid_array_literal(&self.subordinate_user_ids),
            uuid_array_literal(&self.accessible_org_ids),
        ]
    }
}

pub struct PolymorphicAuditPredicate {
    pub sql: String,
    pub binds: PolymorphicAuditBinds,
}

impl std::fmt::Debug for PolymorphicAuditPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolymorphicAuditPredicate")
            .finish_non_exhaustive()
    }
}

/// D-140's named follow-up: a genuine per-row RLS predicate for the
/// polymorphic-audit list path (`audit_header`/`audit_snapshot`/
/// `audit_detail`), meant to replace the fail-closed `Forbidden`
/// stopgap `query_exec.rs` currently returns for any caller whose own access
/// level on one of these three entities is narrowed below `Global`.
///
/// Unlike [`rls_predicate`], the entity a row is "about" varies per row (the
/// audited business record's own entity, resolved from the row's own
/// `entity_name`/`record_id` columns — see `entity_crud.rs`'s
/// `polymorphic_audit_target` for the two column shapes: `audit_header`/
/// `audit_snapshot` carry them directly, `audit_detail` needs them
/// joined in from `audit_header` via `audit_ref`), so the caller's
/// access level can't be resolved once for the whole query the way every
/// other RLS-scoped entity can. It's precomputed in bulk
/// (`db::resolve_all_entity_access_levels`, one query for the whole request
/// instead of one per row) and spliced in here as three parallel bind arrays,
/// looked up per row by `array_position` on the row's own `entity_name_col`
/// (see the comment on the SQL below for why that, and not `UNNEST`).
///
/// BusinessUnit-tier's `organization_ref` fast path is unavailable here, for
/// the same reason [`rls_predicate_by_column`] (D-146) already accepted:
/// this predicate has no access to the *target* entity's own row — a
/// different, dynamically-named physical table per row, which a single
/// static SQL statement cannot join to by name — only to
/// `record_share`/`entity_default_share`, which are keyed
/// abstractly by `(entity_ref, record_id)` and never require touching the
/// target table at all. A BusinessUnit- or Team-tier caller is therefore
/// evaluated via the explicit-share path only, exactly like the
/// stored-query containment case — strictly more restrictive than
/// `rls_predicate`'s ordinary BusinessUnit handling, never less.
///
/// A row whose `entity_name_col`/`record_id_col` is `NULL` (an audit event
/// not "about" any business record — e.g. a login/logout audit entry)
/// evaluates to `false` under this predicate alone: the map lookup keyed on a
/// `NULL` `entity_name_col` never matches, so there is no position to
/// subscript with and the `EXISTS` is false. This is deliberate, not an
/// oversight —
/// **the caller is responsible for OR-ing in a fallback keyed on the audit
/// row's own scope** (`rls_predicate` against the audit entity itself) for
/// exactly those rows, the way `entity_crud.rs::get_record`'s `None` arm
/// falls back to `require_record_access` when `polymorphic_audit_target`
/// resolves no target. Both call sites in `query_exec.rs` do this. (An
/// earlier version of this predicate instead passed target-less rows through
/// unconditionally and relied on the caller ANDing this fragment with
/// `rls_predicate` unconditionally — see 9ec8c7a. That composition made
/// every target-bearing row's referenced-record share unsatisfiable for a
/// narrowed caller, defeating D-147's purpose. Removing the unconditional
/// passthrough here, so the caller can OR in the audit-scope fallback
/// per-row instead of ANDing it globally, fixes both problems at once —
/// verified against a real Postgres, see the regression test.)
///
/// An entity with no entry in `access_by_entity` at all (caller holds no
/// `"{entity}.read"` privilege whatsoever) excludes the row outright — the
/// list-path equivalent of `require_referenced_record_access` failing closed
/// to `NotFound` when its own `ctx.require` check fails.
///
/// Live-verified against a real Postgres/Redis: the three-array mapping
/// lookup, the target-less-row exclusion above, and the capability/deny logic
/// all confirmed correct for a caller whose access on the *referenced* (not
/// the audit) entity is None/Team/BusinessUnit/Global. See
/// `record_level_security.rs`'s `polymorphic_audit_*`-named tests.
///
/// The cost rewrite below is pinned by shape, not by wall clock, in
/// `polymorphic_predicate_reads_the_map_without_re_expanding_it_per_row`. A
/// timing regression driven through `/api/v1/query/execute` was tried and
/// deliberately abandoned, originally because the seeded default query for
/// these entities carried `ORDER BY created_at DESC` inside its own `base_sql`:
/// that made the handler sort every matching row (all 25 selected columns,
/// spilling to disk past ~55k rows) before this predicate was even applied, and
/// again by `id` afterwards, so the sort rather than this predicate set the
/// ceiling on that path. D-350 removed that inner sort, and this predicate is
/// now the dominant per-row cost there — but the shape assertion is still the
/// right regression, because a wall-clock one on a shared local database is
/// exactly the volume/load-sensitive test `entity_crud/access.rs`'s
/// `POLYMORPHIC_AUDIT_ENTITIES` note warns against. A timing assertion belongs
/// in a seeded, isolated load environment, not in the unit suite.
pub fn polymorphic_audit_predicate(
    ctx: &SecurityContext,
    access_by_entity: &HashMap<String, (Uuid, AccessLevel)>,
    default_share_entities: &HashSet<Uuid>,
    fast_tier: Option<FastTierColumns<'_>>,
    entity_name_col: &str,
    record_id_col: &str,
    first_placeholder: usize,
) -> PolymorphicAuditPredicate {
    let mut logicalnames = Vec::with_capacity(access_by_entity.len());
    let mut entity_refs = Vec::with_capacity(access_by_entity.len());
    let mut access_levels = Vec::with_capacity(access_by_entity.len());
    let mut default_shares = Vec::with_capacity(access_by_entity.len());
    for (logicalname, (entity_ref, level)) in access_by_entity {
        logicalnames.push(logicalname.clone());
        entity_refs.push(*entity_ref);
        access_levels.push(*level as i16);
        default_shares.push(default_share_entities.contains(entity_ref));
    }

    let mut alloc = PlaceholderAllocator::new(first_placeholder);
    let p_names = alloc.next();
    let p_refs = alloc.next();
    let p_levels = alloc.next();
    let p_defaults = alloc.next();
    let p_caller = alloc.next();
    let p_teams = alloc.next();
    let p_subordinates = alloc.next();
    let p_orgs = alloc.next();

    let caller_ph = format!("${p_caller}::uuid");
    let teams_ph = format!("${p_teams}::uuid[]");
    let subordinates_ph = format!("${p_subordinates}::uuid[]");
    let entity_ref_expr = format!("(${p_refs}::uuid[])[m.pos]");

    // The four parallel arrays stay bind parameters rather than a join
    // against a real table: the mapping is request-scoped, precomputed data,
    // not something to persist — this keeps the predicate entirely inside the
    // WHERE-clause splice convention `query_exec.rs` already uses (no
    // FROM-clause or CTE change needed at either call site).
    //
    // They are read with `array_position` + array subscripting rather than
    // `UNNEST(...)`, and the whole predicate hangs off ONE `EXISTS` over a
    // single-row derived table, for a measured reason (F-002/TODO-007). The
    // earlier shape spliced four separate correlated `SELECT ... FROM
    // UNNEST(...)` scalar subqueries into the filter; because each is its own
    // SubPlan, Postgres re-expanded all three arrays into a fresh function
    // scan *per candidate row per occurrence* and then linearly scanned it —
    // O(rows x map x occurrences) — and on a populated audit table that blew
    // through the read pool's 500ms `statement_timeout` and returned 500
    // instead of the filtered list. Hoisting `pos` into the derived table
    // evaluates `entity_name_col` (a correlated `audit_header` lookup on
    // the `audit_detail` shape, not a plain column) and `record_id_col`
    // exactly once per row, and turns the four function scans into one
    // trivial `Result` node.
    //
    // Measured with EXPLAIN ANALYZE on a seeded local Postgres 18, worst case
    // (full scan, no matching rows, 40-entity map): `audit_header`
    // (10,500 rows) 267.7ms -> 43.3ms; `audit_detail` (6,099 rows)
    // 318.9ms -> 87.7ms. All four `Function Scan on m` nodes at `loops=10500`
    // are gone from both plans.
    //
    // `array_position` matches the old `UNNEST` lookup's semantics exactly,
    // including the cases the doc comment above depends on: the arrays never
    // contain NULL (they are built from `access_by_entity`'s keys just
    // above), so a `NULL` `entity_name_col` and an entity absent from the map
    // both yield `pos IS NULL`, which makes the `EXISTS` false — the
    // target-less exclusion and the no-privilege exclusion. It is also
    // strictly safer than the scalar subquery it replaces, which would have
    // raised "more than one row returned by a subquery" on a duplicate
    // logicalname; `array_position` takes the first.
    //
    // The `default_shares` array is the same idea applied to a second
    // constant: `entity_default_share` has no `record_id` column, so
    // the correlated `EXISTS` that used to sit in the allow-chain returned the
    // same answer for every row of an entity and was re-planned per row for
    // nothing. It is now resolved once per request
    // (`db::resolve_default_share_entities`) into a `boolean[]` read by the
    // same `m.pos` subscript — one fewer SubPlan in the filter, and the
    // remaining two (`record_share` allow, `record_share`
    // deny) are the genuinely per-record ones that cannot be hoisted.
    // `(${p_defaults}::boolean[])[m.pos]` is only ever evaluated under the
    // `m.pos IS NOT NULL` guard, so it can never subscript with NULL; a
    // `false` element behaves exactly as the old non-matching `EXISTS` did.
    // TODO-003's opt-in fast tier. Placed INSIDE the `m.pos IS NOT NULL`
    // guard and INSIDE the deny-bounded arm, which is the whole correctness
    // argument: as an outer `OR` it would admit rows of entities the caller
    // holds no read privilege on (the map guard is what establishes privilege)
    // AND escape the deny check. That is the privilege escalation the search
    // plan's v1 contained, and it is why this is a formatted fragment rather
    // than a line someone appends later.
    //
    // `= 2` is `AccessLevel::BusinessUnit`. A Team-tier or None-tier caller
    // gets no tier and falls through to the share checks, exactly as before —
    // the tier is a shortcut for callers who already hold BU-wide read on the
    // entity, not a new grant.
    let bu_tier = match fast_tier {
        Some(FastTierColumns { organization_ref }) => format!(
            "((${p_levels}::smallint[])[m.pos] = 2              AND {organization_ref} = ANY(${p_orgs}::uuid[]))
                        OR "
        ),
        // `None` produces the empty string, so the generated SQL is
        // byte-identical to before this parameter existed. The audit call
        // sites depend on that.
        None => String::new(),
    };

    let sql = format!(
        r#"AND EXISTS (
            SELECT 1 FROM (
                SELECT array_position(${p_names}::text[], {entity_name_col}::text) AS pos,
                       {record_id_col} AS rid
            ) m
            WHERE m.pos IS NOT NULL
              AND (
                (${p_levels}::smallint[])[m.pos] = 3
                OR (
                    (
                        {bu_tier}EXISTS (
                            SELECT 1 FROM record_share s
                            WHERE s.record_id = m.rid AND s.entity_ref = {entity_ref_expr}
                              AND s.capability BETWEEN 0 AND 1
                              AND ({share_disjunction})
                        )
                        OR (${p_defaults}::boolean[])[m.pos]
                    )
                    AND {deny_clause}
                )
              )
        )"#,
        share_disjunction =
            principal_disjunction_sql("s", &caller_ph, &teams_ph, Some(&subordinates_ph)),
        deny_clause = deny_clause_sql("s", "m.rid", &entity_ref_expr, &caller_ph, &teams_ph),
    );

    PolymorphicAuditPredicate {
        sql,
        binds: PolymorphicAuditBinds {
            logicalnames,
            entity_refs,
            access_levels,
            default_shares,
            caller_id: ctx.user_id,
            team_ids: ctx.team_ids.clone(),
            subordinate_user_ids: ctx.subordinate_user_ids.clone(),
            accessible_org_ids: ctx.accessible_org_ids.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rls_fragment::DENY_CAPABILITY;
    use std::collections::HashSet;

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
            service_principal: false,
        }
    }

    /// Same as `ctx`, but with F138 position hierarchy turned on and a given
    /// subordinate set — the shape every position-hierarchy-specific test
    /// below needs instead of `ctx`'s default (disabled, empty).
    fn ctx_with_subordinates(subordinate_user_ids: Vec<Uuid>) -> SecurityContext {
        SecurityContext {
            position_hierarchy_enabled: true,
            subordinate_user_ids,
            ..ctx(false)
        }
    }

    #[test]
    fn none_for_admin_regardless_of_access_level() {
        let c = ctx(true);
        assert!(
            rls_predicate(
                &c,
                Uuid::now_v7(),
                "t",
                AccessLevel::Team,
                Capability::View,
                2
            )
            .is_none()
        );
    }

    #[test]
    fn none_for_global_access_level() {
        let c = ctx(false);
        assert!(
            rls_predicate(
                &c,
                Uuid::now_v7(),
                "t",
                AccessLevel::Global,
                Capability::View,
                2
            )
            .is_none()
        );
    }

    #[test]
    fn some_for_business_unit_includes_org_filter() {
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(pred.sql.contains("organization_ref"));
        assert!(pred.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn some_for_team_omits_org_filter_but_keeps_share_checks() {
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(pred.sql.contains("FALSE"));
        assert!(pred.sql.contains("record_share"));
        assert!(pred.sql.contains("entity_default_share"));
    }

    /// Regression test for a real bug caught by integration testing: the
    /// capability check must accept a MORE permissive share than what's
    /// required (an `action` share satisfies a `view` requirement per
    /// D-133 (4)), via a bounded range — not exact equality, which would
    /// wrongly reject an action-holder's read, and not a bare `>=`, which
    /// would wrongly let a `deny` row (2) satisfy an allow-check.
    #[test]
    fn capability_check_uses_a_bounded_range_not_equality() {
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(
            pred.sql.contains("BETWEEN") && pred.sql.contains("AND 1"),
            "capability check must be a bounded range (required..=1), not \
             equality — otherwise a caller with only an action-capability \
             share would incorrectly fail a view-capability check: {}",
            pred.sql
        );
        assert!(
            !pred.sql.contains("capability = $"),
            "capability must never be checked via exact equality: {}",
            pred.sql
        );
    }

    #[test]
    fn some_for_none_access_level_still_allows_explicit_share() {
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::None,
            Capability::View,
            2,
        )
        .unwrap();
        // No BU/Team tier possible, but the share EXISTS checks still run —
        // a caller with no role can still be explicitly shared a record.
        assert!(pred.sql.contains("record_share"));
    }

    #[test]
    fn deny_clause_always_present_when_filtering_at_all() {
        for level in [
            AccessLevel::None,
            AccessLevel::Team,
            AccessLevel::BusinessUnit,
        ] {
            let c = ctx(false);
            let pred =
                rls_predicate(&c, Uuid::now_v7(), "t", level, Capability::Action, 2).unwrap();
            assert!(
                pred.sql.contains("NOT EXISTS"),
                "deny check missing for {level:?}"
            );
        }
    }

    #[test]
    fn to_text_params_produces_valid_postgres_array_literals() {
        let binds = RlsBinds {
            entity_ref: Uuid::nil(),
            caller_id: Uuid::nil(),
            team_ids: vec![],
            capability: 0,
            accessible_org_ids: vec![Uuid::nil()],
            subordinate_user_ids: vec![Uuid::nil()],
        };
        let params = binds.to_text_params();
        assert_eq!(params.len(), 6);
        assert_eq!(
            params[2], "{}",
            "empty Vec<Uuid> must be a valid empty array literal, not blank/NULL"
        );
        assert!(params[4].starts_with('{') && params[4].ends_with('}'));
        assert!(params[5].starts_with('{') && params[5].ends_with('}'));
    }

    #[test]
    fn position_hierarchy_adds_a_subordinate_check_to_the_share_exists_clause() {
        let subordinate = Uuid::now_v7();
        let c = ctx_with_subordinates(vec![subordinate]);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::None,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(
            pred.sql.contains("principal_id = ANY($7::uuid[])"),
            "expected the subordinate placeholder ($first_placeholder+5 = $7 here) \
             in the generated SQL: {}",
            pred.sql
        );
        assert_eq!(pred.binds.subordinate_user_ids, vec![subordinate]);
    }

    #[test]
    fn position_hierarchy_never_extends_entity_default_shares() {
        // Position hierarchy answers "did my subordinate get individually
        // granted this record" (D-133 (2)'s ownership-as-share-row), not
        // "does my subordinate benefit from some entity-wide blanket grant" —
        // the default-share EXISTS clause must stay untouched by the new bind.
        let c = ctx_with_subordinates(vec![Uuid::now_v7()]);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::None,
            Capability::View,
            2,
        )
        .unwrap();
        let default_share_clause = pred
            .sql
            .split("entity_default_share")
            .nth(1)
            .expect("default-share clause must be present");
        assert!(
            !default_share_clause.contains("$7"),
            "default-share EXISTS must not reference the subordinate placeholder ($7): {}",
            pred.sql
        );
    }

    #[test]
    fn disabled_position_hierarchy_still_binds_an_empty_subordinate_array() {
        // ctx() (not ctx_with_subordinates) defaults position_hierarchy_enabled
        // to false — the generated SQL is unconditional (no text branch, unlike
        // BU-tier's), so an empty array must still be a valid bind, never a
        // missing placeholder.
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert_eq!(pred.binds.subordinate_user_ids, Vec::<Uuid>::new());
        assert_eq!(pred.binds.to_text_params()[5], "{}");
    }

    #[test]
    fn empty_table_alias_omits_prefix() {
        let c = ctx(false);
        let with_alias = rls_predicate(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        let without_alias = rls_predicate(
            &c,
            Uuid::now_v7(),
            "",
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(with_alias.sql.contains("t.organization_ref"));
        assert!(!without_alias.sql.contains(".organization_ref"));
        assert!(without_alias.sql.contains("organization_ref"));
    }

    /// Without an alias the record column is a bare `id`. The share and deny
    /// sub-queries read `record_share` through a derived table with no `id`
    /// of its own, so that `id` can only be the outer record's.
    #[test]
    fn share_subqueries_cannot_capture_a_bare_record_id() {
        let c = ctx(false);
        let pred = rls_predicate(
            &c,
            Uuid::now_v7(),
            "",
            AccessLevel::None,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(pred.sql.contains("s.record_id = id"));
        assert!(!pred.sql.contains("FROM record_share s"));
        assert_eq!(pred.sql.matches(SHARE_ROWS).count(), 2, "{}", pred.sql);
    }

    // ── rls_predicate_by_column (P-stored-query-containment Phase 3, D-146) ──

    #[test]
    fn by_column_uses_the_declared_id_column_not_the_implicit_id() {
        let c = ctx(false);
        let pred = rls_predicate_by_column(
            &c,
            Uuid::now_v7(),
            "t",
            "contact_id",
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(
            pred.sql.contains("t.contact_id"),
            "expected the declared column, not the implicit \"id\": {}",
            pred.sql
        );
        assert!(
            !pred.sql.contains("t.id "),
            "must not fall back to t.id: {}",
            pred.sql
        );
    }

    #[test]
    fn by_column_forces_business_unit_tier_to_the_share_only_path() {
        let c = ctx(false);
        let pred = rls_predicate_by_column(
            &c,
            Uuid::now_v7(),
            "t",
            "account_id",
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(
            !pred.sql.contains("organization_ref"),
            "the org fast path must never appear for rls_predicate_by_column, \
             even at BusinessUnit tier (v1 scope cut, D-146): {}",
            pred.sql
        );
        assert!(pred.sql.contains("record_share"));
        assert!(pred.sql.contains("entity_default_share"));
    }

    #[test]
    fn by_column_none_for_admin_or_global() {
        let admin = ctx(true);
        assert!(
            rls_predicate_by_column(
                &admin,
                Uuid::now_v7(),
                "t",
                "contact_id",
                AccessLevel::Team,
                Capability::View,
                2
            )
            .is_none()
        );
        let non_admin = ctx(false);
        assert!(
            rls_predicate_by_column(
                &non_admin,
                Uuid::now_v7(),
                "t",
                "contact_id",
                AccessLevel::Global,
                Capability::View,
                2
            )
            .is_none()
        );
    }

    #[test]
    fn by_column_keeps_the_same_capability_bound_and_deny_clause_as_rls_predicate() {
        let c = ctx(false);
        let pred = rls_predicate_by_column(
            &c,
            Uuid::now_v7(),
            "t",
            "account_id",
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert!(pred.sql.contains("BETWEEN") && pred.sql.contains("AND 1"));
        assert!(!pred.sql.contains("capability = $"));
        assert!(pred.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn rls_predicate_and_by_column_generate_byte_identical_sql_for_the_implicit_id_case() {
        // The whole point of extracting `build_predicate` is that
        // `rls_predicate` itself is unchanged — pin that its output is
        // identical to calling the new function with id_column="id" and
        // allow_bu_tier=true.
        let c = ctx(false);
        let entity_ref = Uuid::now_v7();
        let via_rls_predicate = rls_predicate(
            &c,
            entity_ref,
            "t",
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        let via_build = build_predicate(
            &c,
            entity_ref,
            "t",
            "id",
            true,
            false,
            AccessLevel::BusinessUnit,
            Capability::View,
            2,
        )
        .unwrap();
        assert_eq!(via_rls_predicate.sql, via_build.sql);
    }

    // ── rls_predicate_with_conditions (D-369) ─────────────────────────────

    fn account_industry_attr() -> Vec<AttrInfo> {
        vec![AttrInfo {
            logicalname: "industry".to_owned(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options: None,
        }]
    }

    fn ctx_with_condition(
        privilege_key: &str,
        condition: attome_server::security::GrantCondition,
    ) -> SecurityContext {
        let mut condition_grants = HashMap::new();
        condition_grants.insert(privilege_key.to_owned(), vec![vec![condition]]);
        SecurityContext {
            condition_grants,
            ..ctx(false)
        }
    }

    /// THE regression test for the fail-open gap this function exists to
    /// close: `build_predicate` alone returns `None` for `Global` — a naive
    /// "AND a fragment onto `allow`" patch would never even run for this
    /// tier, since `allow` is never built. A `Global`-tier role holding a
    /// conditional grant on this exact privilege must still be filtered.
    #[test]
    fn global_tier_with_an_active_condition_is_still_filtered() {
        let c = ctx_with_condition(
            "account.read",
            attome_server::security::GrantCondition {
                field_logicalname: "industry".to_owned(),
                operator: attome_server::security::ConditionOperator::Eq,
                value: serde_json::json!("Active"),
            },
        );
        let pred = rls_predicate_with_conditions(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::Global,
            Capability::View,
            "account.read",
            &account_industry_attr(),
            false,
            2,
        );
        assert!(
            pred.is_some(),
            "a Global-tier role with an active condition must still produce a filtering predicate"
        );
        let pred = pred.unwrap();
        assert!(
            pred.tier_binds.is_none(),
            "no tier fragment at Global — only the condition narrows"
        );
        assert!(pred.sql.contains("t.industry ="));
        assert_eq!(pred.condition_binds, vec!["Active".to_owned()]);
    }

    /// `is_admin` still fully bypasses, condition or not — a stronger,
    /// orthogonal bypass than any role's own grant (D-369 does not touch it).
    #[test]
    fn admin_bypasses_even_an_active_condition() {
        let c = ctx_with_condition(
            "account.read",
            attome_server::security::GrantCondition {
                field_logicalname: "industry".to_owned(),
                operator: attome_server::security::ConditionOperator::Eq,
                value: serde_json::json!("Active"),
            },
        );
        let c = SecurityContext {
            is_admin: true,
            ..c
        };
        assert!(
            rls_predicate_with_conditions(
                &c,
                Uuid::now_v7(),
                "t",
                AccessLevel::Global,
                Capability::View,
                "account.read",
                &account_industry_attr(),
                false,
                2,
            )
            .is_none()
        );
    }

    /// No condition grant for this privilege key at all — behavior must be
    /// byte-identical to plain `rls_predicate`/`build_predicate` (D-369's own
    /// "zero behavior change" guarantee).
    #[test]
    fn no_condition_grant_is_byte_identical_to_build_predicate() {
        let c = ctx(false);
        let entity_ref = Uuid::now_v7();
        let via_conditions = rls_predicate_with_conditions(
            &c,
            entity_ref,
            "t",
            AccessLevel::Team,
            Capability::View,
            "account.read",
            &account_industry_attr(),
            false,
            2,
        )
        .unwrap();
        let via_build = build_predicate(
            &c,
            entity_ref,
            "t",
            "id",
            true,
            false,
            AccessLevel::Team,
            Capability::View,
            2,
        )
        .unwrap();
        assert_eq!(via_conditions.sql, via_build.sql);
        assert!(via_conditions.condition_binds.is_empty());
    }

    /// A non-Global tier's tier/share/deny fragment and the condition
    /// fragment must both be present, ANDed together, not one replacing the
    /// other.
    #[test]
    fn team_tier_with_a_condition_ands_both_fragments() {
        let c = ctx_with_condition(
            "account.read",
            attome_server::security::GrantCondition {
                field_logicalname: "industry".to_owned(),
                operator: attome_server::security::ConditionOperator::Eq,
                value: serde_json::json!("Active"),
            },
        );
        let pred = rls_predicate_with_conditions(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::Team,
            Capability::View,
            "account.read",
            &account_industry_attr(),
            false,
            2,
        )
        .unwrap();
        assert!(
            pred.tier_binds.is_some(),
            "the tier/share/deny fragment must still be present"
        );
        assert!(pred.sql.contains("record_share"));
        assert!(pred.sql.contains("t.industry ="));
        // The condition placeholder must be numbered after the tier
        // fragment's fixed 6 (first_placeholder=2 -> tier uses 2..=7, so the
        // condition's own placeholder is 8).
        assert!(pred.sql.contains("$8::TEXT"));
    }

    // ── owner_visible (D-371, amends D-357 ruling 2) ──────────────────────

    #[test]
    fn owner_visible_adds_an_owner_arm_at_none_tier() {
        let c = ctx(false);
        let pred = rls_predicate_with_conditions(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::None,
            Capability::View,
            "account.read",
            &[],
            true,
            2,
        )
        .unwrap();
        assert!(
            pred.sql
                .contains("t.owner_ref = $3::uuid AND t.owner_type = 0"),
            "expected an owner-match arm reusing the caller placeholder ($first_placeholder+1 = $3 here): {}",
            pred.sql
        );
    }

    #[test]
    fn owner_visible_false_is_byte_identical_to_before_the_parameter_existed() {
        let c = ctx(false);
        let entity_ref = Uuid::now_v7();
        let with_owner_false = rls_predicate_with_conditions(
            &c,
            entity_ref,
            "t",
            AccessLevel::None,
            Capability::View,
            "account.read",
            &[],
            false,
            2,
        )
        .unwrap();
        let via_rls_predicate =
            rls_predicate(&c, entity_ref, "t", AccessLevel::None, Capability::View, 2).unwrap();
        assert_eq!(with_owner_false.sql, via_rls_predicate.sql);
    }

    /// The load-bearing safety property D-371 amends D-357 to preserve: the
    /// owner arm sits INSIDE the same `allow` fragment the deny check below
    /// still ANDs against — an explicit deny row must still win over
    /// ownership, exactly like it already wins over a team/BU/global share.
    #[test]
    fn owner_arm_never_escapes_the_deny_check() {
        let c = ctx(false);
        let pred = rls_predicate_with_conditions(
            &c,
            Uuid::now_v7(),
            "t",
            AccessLevel::None,
            Capability::View,
            "account.read",
            &[],
            true,
            2,
        )
        .unwrap();
        let owner_pos = pred
            .sql
            .find("t.owner_ref")
            .expect("owner arm must be present");
        let deny_pos = pred
            .sql
            .find("NOT EXISTS")
            .expect("deny check must be present");
        assert!(
            owner_pos < deny_pos,
            "the owner arm must precede — and therefore be ANDed with — the deny check: {}",
            pred.sql
        );
    }

    /// `Global`-tier short-circuits to `None` regardless of `owner_visible` —
    /// correct, not a gap: `Global` already grants everything, so there is
    /// nothing left for the owner arm to add.
    #[test]
    fn owner_visible_at_global_tier_still_short_circuits() {
        let c = ctx(false);
        assert!(
            rls_predicate_with_conditions(
                &c,
                Uuid::now_v7(),
                "t",
                AccessLevel::Global,
                Capability::View,
                "account.read",
                &[],
                true,
                2,
            )
            .is_none()
        );
    }

    // ── polymorphic_audit_predicate (D-140 follow-up) ─────────────────────
    //
    // Structural/shape tests only — pinning that the generated SQL text has
    // the properties the doc comment promises. Nothing here executes this SQL
    // against a real `record_share`/`entity_default_share`
    // table; that is `record_level_security.rs`'s `polymorphic_audit_*` and
    // `query_execute_*_audit_*` tests, which run against a live Postgres.

    fn access_map(entries: &[(&str, AccessLevel)]) -> HashMap<String, (Uuid, AccessLevel)> {
        entries
            .iter()
            .map(|(name, level)| (name.to_string(), (Uuid::now_v7(), *level)))
            .collect()
    }

    /// The caller holds no entity-default share anywhere — the input
    /// `db::resolve_default_share_entities` returns for the common case, and
    /// the shape every pre-existing test below was written against (when the
    /// default-share check was still a correlated subquery in the SQL).
    fn no_defaults() -> HashSet<Uuid> {
        HashSet::new()
    }

    #[test]
    fn polymorphic_predicate_does_not_pass_through_null_targets() {
        // A target-less row (login/logout, no resolvable business record)
        // must NOT be unconditionally admitted by this predicate alone — an
        // earlier version did exactly that and relied on the caller ANDing
        // in `rls_predicate` globally to compensate, which instead made
        // every target-bearing row's referenced-record share unsatisfiable
        // for a narrowed caller (9ec8c7a). The caller is now responsible for
        // OR-ing in a scope fallback for target-less rows specifically; this
        // predicate must evaluate `false` for them on its own so that OR
        // composes correctly.
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            !pred.sql.contains("h.record_id IS NULL"),
            "target-less rows must not be unconditionally admitted: {}",
            pred.sql
        );
        assert!(
            !pred.sql.contains("h.entity_name IS NULL"),
            "target-less rows must not be unconditionally admitted: {}",
            pred.sql
        );
    }

    #[test]
    fn polymorphic_predicate_admits_global_tier_targets_unconditionally() {
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Global)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            pred.sql.contains("= 3"),
            "must special-case Global (3): {}",
            pred.sql
        );
    }

    #[test]
    fn polymorphic_predicate_never_uses_the_organization_ref_fast_path() {
        // D-146 precedent: the BU-tier org fast path requires reading the
        // *target* entity's own row, which this predicate structurally
        // cannot do (dynamic per-row table). Must never appear here, at any
        // access level.
        let c = ctx(false);
        let map = access_map(&[
            ("account", AccessLevel::BusinessUnit),
            ("contact", AccessLevel::Team),
            ("lead", AccessLevel::None),
        ]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(!pred.sql.contains("organization_ref"), "{}", pred.sql);
    }

    #[test]
    fn polymorphic_predicate_keeps_the_bounded_capability_range_and_deny_clause() {
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(pred.sql.contains("BETWEEN 0 AND 1"));
        assert!(pred.sql.contains("NOT EXISTS"));
        assert!(
            pred.sql
                .contains(&format!("capability = {DENY_CAPABILITY}"))
        );
    }

    #[test]
    fn polymorphic_predicate_binds_are_parallel_arrays_in_map_order() {
        let c = ctx(false);
        let entries = [
            ("account", AccessLevel::Team),
            ("contact", AccessLevel::Global),
        ];
        let map = access_map(&entries);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert_eq!(pred.binds.logicalnames.len(), map.len());
        assert_eq!(pred.binds.entity_refs.len(), map.len());
        assert_eq!(pred.binds.access_levels.len(), map.len());
        for (name, level) in &entries {
            let idx = pred
                .binds
                .logicalnames
                .iter()
                .position(|n| n == name)
                .expect("every map key must appear in the bound logicalname array");
            assert_eq!(pred.binds.access_levels[idx], *level as i16);
            assert_eq!(pred.binds.entity_refs[idx], map[*name].0);
        }
    }

    #[test]
    fn polymorphic_predicate_reads_the_map_without_re_expanding_it_per_row() {
        // F-002/TODO-007 regression, at the shape level: the map must be read
        // by subscript, not by splicing correlated `SELECT ... FROM UNNEST()`
        // scalar subqueries that Postgres re-expands once per candidate row
        // per occurrence (measured: 267.7ms -> 43.3ms on a 10,500-row
        // `audit_header`, against a 500ms `statement_timeout`). The
        // volume-representative half of this regression lives in
        // `record_level_security.rs`; this half stops the old shape from
        // being reintroduced without one.
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team), ("lead", AccessLevel::None)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            !pred.sql.contains("UNNEST"),
            "the map must not be re-expanded per row: {}",
            pred.sql
        );
        assert_eq!(
            pred.sql.matches("array_position").count(),
            1,
            "the map position must be computed once per row, not per reference: {}",
            pred.sql
        );
        // `entity_name_col` is a correlated `audit_header` subquery on the
        // `audit_detail` shape, so evaluating it more than once per row is
        // itself a per-row cost — it must appear only inside `array_position`.
        assert_eq!(
            pred.sql.matches("h.entity_name").count(),
            1,
            "entity_name_col must be evaluated once per row: {}",
            pred.sql
        );
        assert_eq!(
            pred.sql.matches("h.record_id").count(),
            1,
            "record_id_col must be evaluated once per row: {}",
            pred.sql
        );
    }

    #[test]
    fn polymorphic_predicate_empty_map_still_produces_valid_array_literals() {
        let c = ctx(false);
        let map = HashMap::new();
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        let params = pred.binds.to_text_params();
        assert_eq!(params[0], "{}");
        assert_eq!(params[1], "{}");
        assert_eq!(params[2], "{}");
        assert_eq!(
            params[3], "{}",
            "the boolean array must be a valid empty literal too"
        );
    }

    // ── D-357: entity-default-share hoist ─────────────────────────────────

    #[test]
    fn polymorphic_predicate_no_longer_subqueries_the_default_share_table_per_row() {
        // D-357. `entity_default_share` carries no `record_id`, so
        // its answer is constant per entity — as a correlated subquery it was
        // re-evaluated once per candidate row for nothing. It must now be read
        // by the same `m.pos` subscript the access-level array uses.
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            !pred.sql.contains("entity_default_share"),
            "the default-share check must be hoisted out of the per-row \
             predicate, not spliced in as a correlated subquery: {}",
            pred.sql
        );
        assert!(
            pred.sql.contains("::boolean[])[m.pos]"),
            "the hoisted answer must be read by the same map subscript: {}",
            pred.sql
        );
        // The two remaining SubPlans are the genuinely per-record ones: the
        // record-share allow and the record-share deny. Neither can be
        // hoisted — both are keyed on `m.rid`.
        assert_eq!(
            pred.sql.matches("record_share").count(),
            2,
            "only the two per-record share checks may remain: {}",
            pred.sql
        );
    }

    #[test]
    fn polymorphic_predicate_default_share_array_is_parallel_to_the_other_three() {
        let c = ctx(false);
        let entries = [
            ("account", AccessLevel::Team),
            ("contact", AccessLevel::Team),
            ("lead", AccessLevel::None),
        ];
        let map = access_map(&entries);
        // Only `contact` carries a default share for this caller.
        let shared = map["contact"].0;
        let defaults: HashSet<Uuid> = std::iter::once(shared).collect();

        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &defaults,
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert_eq!(pred.binds.default_shares.len(), map.len());
        for (name, _) in &entries {
            let idx = pred
                .binds
                .logicalnames
                .iter()
                .position(|n| n == name)
                .expect("every map key must appear in the bound logicalname array");
            assert_eq!(
                pred.binds.default_shares[idx],
                *name == "contact",
                "default_shares must be indexed by the same position as \
                 logicalnames/entity_refs/access_levels"
            );
        }

        let params = pred.binds.to_text_params();
        assert_eq!(
            params.len(),
            8,
            "the placeholder layout carries the boolean array (D-357) and the fast tier's org array (TODO-003): {params:?}"
        );
        // Postgres boolean-array literal, elements in bind order.
        assert!(
            params[3].starts_with('{') && params[3].ends_with('}'),
            "not a Postgres array literal: {}",
            params[3]
        );
        assert_eq!(params[3].matches(',').count(), entries.len() - 1);
        assert_eq!(params[3].matches('t').count(), 1);
    }

    // ── TODO-003 / D-357 ruling 2: the opt-in BusinessUnit fast tier ─────

    /// `None` must generate SQL byte-identical to before the parameter
    /// existed. The audit call sites pass `None` and their behaviour must not
    /// have moved by a character.
    #[test]
    fn no_fast_tier_generates_the_same_sql_as_before_the_parameter_existed() {
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::BusinessUnit)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            !pred.sql.contains("organization_ref"),
            "with no fast tier the org column must not appear at all: {}",
            pred.sql
        );
    }

    /// THE test for this feature. The tier must sit INSIDE the map guard and
    /// INSIDE the deny-bounded arm.
    ///
    /// As an outer `OR` it would do two things at once: admit rows of entities
    /// the caller holds no read privilege on (the `m.pos` guard is what
    /// establishes privilege at all), and escape the deny check. That is the
    /// privilege escalation the search plan's v1 contained, and it is the
    /// reason this function grew a parameter instead of a caller appending a
    /// clause.
    #[test]
    fn the_fast_tier_sits_inside_the_map_guard_and_inside_the_deny_bound() {
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::BusinessUnit)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            Some(FastTierColumns {
                organization_ref: "s.organization_ref",
            }),
            "h.entity_name",
            "h.record_id",
            2,
        );

        let guard = pred
            .sql
            .find("m.pos IS NOT NULL")
            .expect("the map guard must be present");
        let tier = pred
            .sql
            .find("s.organization_ref")
            .expect("the fast tier must be present");
        let deny = pred
            .sql
            .find("NOT EXISTS")
            .expect("the deny check must be present");

        assert!(
            guard < tier,
            "the tier must be INSIDE the map guard — outside it, a caller with no read privilege on an entity would see its rows: {}",
            pred.sql
        );
        assert!(
            tier < deny,
            "the tier must precede — and therefore be ANDed with — the deny check, not sit outside it: {}",
            pred.sql
        );
    }

    /// The tier is gated on BusinessUnit depth (`= 2`) specifically. A
    /// Team-tier or None-tier caller must fall through to the share checks:
    /// the tier is a shortcut for callers who already hold BU-wide read on the
    /// entity, never a new grant.
    #[test]
    fn the_fast_tier_is_gated_on_business_unit_depth() {
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team)]);
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &no_defaults(),
            Some(FastTierColumns {
                organization_ref: "s.organization_ref",
            }),
            "h.entity_name",
            "h.record_id",
            2,
        );
        assert!(
            pred.sql.contains("= 2"),
            "the tier must test the BusinessUnit level explicitly, so a Team-tier caller does not get it: {}",
            pred.sql
        );
    }

    /// There is no owner tier, in either mode. `owner_id` is a ranking signal
    /// and never an access grant (D-357 ruling 2) — this is the assertion that
    /// makes reintroducing it a failing test rather than a review comment.
    #[test]
    fn no_mode_ever_emits_an_owner_tier() {
        let c = ctx(false);
        let map = access_map(&[
            ("account", AccessLevel::BusinessUnit),
            ("contact", AccessLevel::Team),
        ]);
        for tier in [
            None,
            Some(FastTierColumns {
                organization_ref: "s.organization_ref",
            }),
        ] {
            let pred = polymorphic_audit_predicate(
                &c,
                &map,
                &no_defaults(),
                tier,
                "h.entity_name",
                "h.record_id",
                2,
            );
            assert!(
                !pred.sql.contains("owner_id"),
                "ownership grants nothing in this platform; owner_id must never appear in a permission predicate: {}",
                pred.sql
            );
        }
    }

    #[test]
    fn polymorphic_predicate_default_share_never_escapes_the_deny_check() {
        // The hoisted term replaces one arm of the ALLOW chain only. It must
        // stay inside the `AND NOT EXISTS (...deny...)` bound — a default
        // share must never make a denied record visible (I-6/D-133).
        let c = ctx(false);
        let map = access_map(&[("account", AccessLevel::Team)]);
        let entity_ref = map["account"].0;
        let defaults: HashSet<Uuid> = std::iter::once(entity_ref).collect();
        let pred = polymorphic_audit_predicate(
            &c,
            &map,
            &defaults,
            None,
            "h.entity_name",
            "h.record_id",
            2,
        );

        let subscript = pred
            .sql
            .find("::boolean[])[m.pos]")
            .expect("the hoisted term must be present");
        let deny = pred
            .sql
            .find("NOT EXISTS")
            .expect("the deny check must be present");
        assert!(
            subscript < deny,
            "the hoisted allow term must precede — and therefore be ANDed \
             with — the deny check, not sit outside it: {}",
            pred.sql
        );
    }
}

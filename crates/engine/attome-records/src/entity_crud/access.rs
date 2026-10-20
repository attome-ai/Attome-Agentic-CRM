use attome_core::{AttrInfo, EngineState, OnTargetDelete, quote_ident};
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use super::resolve::resolve_entity;

// â”€â”€ Audit helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Moved to `attome_audit::fetch_audit_ctx` (ARCH-5): the compliance route
/// bundles that call it now live in `attome-compliance`, which cannot reach
/// this crate. Re-exported so every `entity_crud::fetch_audit_ctx` call
/// site in this crate is unchanged.
pub use attome_audit::fetch_audit_ctx;

/// Post-commit hook for `update_record`/`delete_record`: when the mutated
/// entity is `user_account` itself, `record_id` IS an `audit_users`
/// cache key (a user's own row), so a display-name/email edit or account
/// deactivation must drop that entry everywhere, not just self-heal after
/// the 60s TTL. Called only after `attome_db::tx::commit` returns `Ok` (never
/// inside the mutation's own transaction, guidelines §4). Same hook is
/// needed at `bulk.rs`'s two other real commit sites (`process_bulk_item`,
/// the staged-import equivalent) since both call
/// `entity_mutation::update_one`/`delete_one` directly rather than through
/// this handler.
///
/// The same edit also drops the user's cached `SecurityContext`, because
/// `user_account.organization_ref` is one of the columns a generic
/// update can change and it now feeds `resolve_accessible_org_ids`'s
/// home-org seed — i.e. it determines BusinessUnit-tier reach. Membership
/// edits already invalidate (`admin::organizations::add_organization_member`);
/// without this, moving a user between orgs through generic CRUD would leave
/// the old org set live until the resolver's own TTL expired. The failure is
/// logged rather than propagated: this runs after the transaction has already
/// committed, so there is nothing left to roll back, and the resolver's TTL
/// still heals it — the same degrade-don't-fail posture the audit-user
/// invalidation above takes.
pub(crate) async fn invalidate_audit_user_if_systemuser(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
) {
    if entity_name == AUDIT_USER_CACHE_ENTITY {
        state.invalidate_audit_user(record_id).await;
        if let Err(e) = state.base.security.invalidate_sync(record_id).await {
            tracing::warn!(
                user_id = %record_id,
                error = %e,
                "failed to invalidate cached security context after a systemuser \
                 update; BusinessUnit-tier org reach may be stale until the \
                 resolver TTL expires"
            );
        }
    }
}

/// Same post-commit-invalidation need as `invalidate_audit_user_if_systemuser`
/// above, for the other table whose generic-CRUD writes must not wait out the
/// resolver's TTL: `user_account_mm_privilege`, the direct user-privilege
/// grant junction (registered as an entity so the User form's Privileges tab
/// can be an ordinary `xrm-related-grid` m2m subgrid, same pattern as Teams,
/// instead of a bespoke panel). The bespoke `/api/v1/admin/security/grants`
/// endpoints this replaces call `invalidate_sync` synchronously
/// (`admin/grants.rs`) precisely because a delayed revoke of `system.admin` -
/// the single most sensitive privilege in the system - is not an acceptable
/// staleness window; this hook preserves that guarantee on the generic path.
///
/// `row` is the mutation's own `new_row` when the caller already has it
/// (create/update); pass `None` for a soft delete, whose `MutationResult`
/// carries no row, and this falls back to reading `user_ref` straight from
/// the table (the row still exists - only `is_active` flipped). A hard
/// delete's physical row is gone by the time this would run - use
/// [`invalidate_privilege_grant_user`] directly with a `user_ref` pulled from
/// the pre-delete snapshot instead of calling this function.
pub(crate) async fn invalidate_privilege_grant_target(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
    row: Option<&Value>,
) {
    if entity_name != PRIVILEGE_GRANT_ENTITY {
        return;
    }

    let from_row = row
        .and_then(|r| r.get("user_ref"))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());

    let user_id = match from_row {
        Some(id) => Some(id),
        None => sqlx::query_scalar::<_, Option<Uuid>>(attome_db::tagged_sql!(
            "entity.access",
            "SELECT user_ref FROM user_account_mm_privilege WHERE id = $1"
        ))
        .bind(record_id)
        .fetch_optional(&state.base.db)
        .await
        .ok()
        .flatten()
        .flatten(),
    };

    invalidate_privilege_grant_user(state, user_id).await;
}

/// The actual invalidation, factored out so a caller that has already
/// resolved `user_ref` some other way (`hard_delete_record`, whose snapshot
/// is taken before the row is physically removed) doesn't have to round-trip
/// it back through a fake row `Value` just to reach the same effect.
pub(crate) async fn invalidate_privilege_grant_user(state: &EngineState, user_id: Option<Uuid>) {
    let Some(user_id) = user_id else { return };
    if let Err(e) = state.base.security.invalidate_sync(user_id).await {
        tracing::warn!(
            user_id = %user_id,
            error = %e,
            "failed to invalidate cached security context after a direct privilege \
             grant edit made through the generic entity API; the change may be stale \
             until the resolver TTL expires"
        );
    }
}

// â”€â”€ D-133: record-level access gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Pre-check gate for `get_record`/`update_record`/`delete_record`: does
/// `ctx` have `required` capability on `record_id`? Runs as a standalone
/// `SELECT EXISTS` against the target table before the real read/mutation,
/// rather than splicing `rls_predicate`'s fragment into
/// `entity_mutation.rs`'s already-parameterized multi-CTE queries — keeps
/// the placeholder numbering in both places simple and independently
/// correct, at the cost of one extra round-trip on a narrowed grant (never
/// paid at all when `access_level == Global`/`is_admin`, since
/// `rls_predicate` returns `None` and this function short-circuits to
/// `Ok(())`). Returns `NotFound`, not `Forbidden`, on a miss — matches the
/// existing soft-delete-style not-found convention (`entity_crud.rs`'s
/// `get_record`), so a `Team`-level caller can't distinguish "doesn't
/// exist" from "exists but I can't see it."
pub async fn require_record_access(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    require_record_access_any_active_state(
        state,
        ctx,
        entity_id,
        entity_name,
        record_id,
        action,
        true,
    )
    .await
}

/// `require_record_access`'s primitive, generalized to optionally skip the
/// `is_active = true` filter — every caller except `restore_record` wants
/// that filter (you can't act on an already-deleted record through get/
/// update/delete/merge/hierarchy), but restore's entire purpose is to act on
/// a record that is currently inactive, so gating it the same way would make
/// every restore 404 regardless of the caller's actual record-level grant.
///
/// Resolves the caller's depth for this exact `(entity_id, action)` first
/// (`resolve_entity_access_level` — the fix for the cross-entity leak the
/// old single-scalar `ctx.access_level` had), then derives the
/// `rls_predicate` capability check from the same `action` — see
/// `RecordAction::share_capability`.
///
/// M01 Core C-12: split into [`resolve_record_access_inputs`] (the pool-based
/// depth/owner-visible resolution, which depends only on `(user, entity,
/// action)`, never on `record_id`) and [`check_record_access`] (the per-record
/// `EXISTS` probe, generic over the executor it runs on) — see
/// [`require_record_access_in_tx`]'s doc comment for why a caller with an
/// already-open transaction needs that split.
pub(super) async fn require_record_access_any_active_state(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
    require_active: bool,
) -> Result<(), AppError> {
    let (access_level, owner_visible) =
        resolve_record_access_inputs(state, ctx, entity_id, entity_name, action).await?;
    check_record_access(
        &state.base.db,
        state,
        ctx,
        entity_id,
        entity_name,
        record_id,
        action,
        require_active,
        access_level,
        owner_visible,
        None,
    )
    .await
}

/// The pool-based half of [`require_record_access_any_active_state`]: resolves
/// the caller's depth ladder and owner-visible flag for `(entity_id, action)`
/// alone. Deliberately has no `record_id` parameter — this result does not
/// depend on which record is being checked, only on who is asking and what
/// they're asking to do, so a caller that will need it from inside an
/// already-open transaction (e.g. `upsert_record`, after its `FOR UPDATE`
/// conflict precheck) can resolve it here, on the pool, before `begin()`
/// (M01-core C-12) rather than paying for a second pool connection while the
/// first is still checked out.
pub async fn resolve_record_access_inputs(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    action: RecordAction,
) -> Result<(AccessLevel, bool), AppError> {
    let access_level =
        resolve_entity_access_level(&state.base.db, ctx.user_id, entity_id, entity_name, action)
            .await?;
    let owner_visible =
        resolve_owner_visible(&state.base.db, ctx.user_id, entity_id, entity_name, action).await?;
    Ok((access_level, owner_visible))
}

/// The per-record `EXISTS` probe, generic over its executor so it can run
/// against either the ordinary pool (`require_record_access_any_active_state`)
/// or an already-open transaction's own connection
/// (`require_record_access_in_tx`) — never a second pool connection acquired
/// while a caller's transaction is open (M01-core C-12).
#[allow(clippy::too_many_arguments)]
async fn check_record_access<'e, E>(
    executor: E,
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
    require_active: bool,
    access_level: AccessLevel,
    owner_visible: bool,
    known_attrs: Option<&[AttrInfo]>,
) -> Result<(), AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let table = quote_ident(entity_name);
    // D-369: attrs are needed only to render an active condition's column
    // cast, if any. A caller inside a transaction passes its own: resolving
    // them here could read `entity_info` through the pool on a registry miss
    // while the transaction holds a connection (M01 Core C-12).
    let resolved;
    let attrs: &[AttrInfo] = match known_attrs {
        Some(attrs) => attrs,
        None => {
            resolved = resolve_entity(state, entity_name).await?.2;
            &resolved
        }
    };
    let privilege_key = format!("{entity_name}.{}", action.as_str());
    let Some(pred) = rls_predicate_with_conditions(
        ctx,
        entity_id,
        "t",
        access_level,
        action.share_capability(),
        &privilege_key,
        attrs,
        owner_visible,
        2,
    ) else {
        return Ok(());
    };

    let active_predicate = if require_active {
        "AND t.is_active = true"
    } else {
        ""
    };
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {table} t WHERE t.id = $1 {active_predicate} {predicate})",
        predicate = pred.sql,
    );

    let sql = attome_db::tag_dynamic("entity.access", &sql);
    let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(record_id);
    if let Some(tb) = &pred.tier_binds {
        q = bind_rls_predicate(q, tb);
    }
    for bind in &pred.condition_binds {
        q = q.bind(bind);
    }
    let allowed: bool = q.fetch_one(executor).await.map_err(AppError::internal)?;

    if allowed {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// M01 Core C-12 — `require_record_access`'s counterpart for a caller that has
/// already opened a transaction and located `record_id` under a `FOR UPDATE`
/// lock (`upsert_record`'s conflict precheck): calling the ordinary
/// `require_record_access` there would acquire a SECOND pool connection while
/// the first is still checked out for that open transaction, which
/// self-deadlocks every such request once the pool saturates. `access_level`/
/// `owner_visible` depend only on `(user, entity, action)`, never on which
/// record matched, so the caller resolves them from the pool BEFORE `begin()`
/// via [`resolve_record_access_inputs`] and this only runs the final
/// per-record `EXISTS` probe, on the transaction's own connection. Always
/// checks `is_active = true` (`require_active: true`) — every existing
/// tx-scoped call site acts on a live row, same as `require_record_access`
/// itself.
#[allow(clippy::too_many_arguments)]
pub async fn require_record_access_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
    access_level: AccessLevel,
    owner_visible: bool,
    attrs: &[AttrInfo],
) -> Result<(), AppError> {
    check_record_access(
        &mut **tx,
        state,
        ctx,
        entity_id,
        entity_name,
        record_id,
        action,
        true,
        access_level,
        owner_visible,
        Some(attrs),
    )
    .await
}

/// C-13 — `require_record_access`'s counterpart for a caller that already
/// resolved this exact `(entity_id, action)`'s depth and owner-visibility
/// itself, typically once for a whole batch rather than once per row: see
/// `bulk.rs`'s `process_ledger`/`apply_ledgered_item`, where `action` derives
/// from `operation`, a parameter of the enclosing `process_ledger` call and
/// therefore invariant across every item in one batch. Resolving
/// `(access_level, owner_visible)` once via [`resolve_record_access_inputs`]
/// and reusing it for every row is exactly as correct as resolving it fresh
/// per row, at a fraction of the query cost — same values, same result.
/// Always checks `is_active = true` (`require_active: true`), matching
/// `require_record_access`'s own default; no current caller of this wrapper
/// needs the inactive-record path `require_record_access_any_active_state`
/// exists for.
#[allow(clippy::too_many_arguments)]
pub async fn require_record_access_with(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
    access_level: AccessLevel,
    owner_visible: bool,
) -> Result<(), AppError> {
    check_record_access(
        &state.base.db,
        state,
        ctx,
        entity_id,
        entity_name,
        record_id,
        action,
        true,
        access_level,
        owner_visible,
        None,
    )
    .await
}

/// `audit_header`/`audit_snapshot` (and, via their `audit_ref`
/// join, `audit_detail`) are ordinary seeded XRM entities
/// (`attome-audit`'s `seed.rs`) whose own row-level RLS
/// (`record_share`/`entity_default_share` keyed on the *audit*
/// entity's own `entity_ref`) says nothing about whether the caller can see
/// the *business* record the audit trail is actually about — the row's own
/// `entity_name`/`record_id` columns (`audit_detail` has neither
/// directly; it points at its own `audit_header` row instead). Left
/// unguarded, a caller whose grant on `audit_header.read` is broader
/// than their grant on the audited entity could read another team's change
/// history — including field old/new values in `audit_detail` — purely
/// through the audit trail. `record_id` is a polymorphic reference (any
/// entity, no `lookup_entity_ref` FK enforced — see `seed.rs`'s comment on
/// that column), so the generic hierarchy/lookup machinery has no metadata
/// shape for it; this is a narrow, explicitly-named exception to "generic
/// dispatch only, no per-entity code" (guidelines Â§9), not a template for
/// other entities. Covers single-record reads (`get_record`) directly, and
/// `query_exec.rs`'s single-entity list/search path via the same
/// `attome_security::polymorphic_audit_predicate` (D-140 follow-up, resolves the
/// per-distinct-target-entity access level in bulk instead of per row —
/// `attome_security::resolve_all_entity_access_levels` — to avoid the N+1 this
/// comment used to flag as the blocker). `query_exec.rs`'s *multi-entity*
/// stored-query path is still fail-closed (`Forbidden`) for these three
/// entities — that path wraps admin-authored SQL with no declared
/// `entity_name`/`record_id` output-column mapping to hook the same fix into;
/// see that call site's own comment.
///
/// This carried a `TODO(needs a live Postgres)` until 2026-08-11 saying none
/// of it had been run against a database. It now is:
/// `record_level_security.rs`'s `get_record_*_audit_header_*` and
/// `query_execute_*_audit_*` tests drive both `polymorphic_audit_target` SQL
/// shapes (the direct select, and the `audit_detail` join through
/// `audit_ref`) and `polymorphic_audit_predicate`'s generated SQL against
/// seeded `audit_header`/`record_share` fixtures, over a caller
/// whose access on the *referenced* entity is None/Team/BusinessUnit/Global.
///
/// `attome_document` (the Documents feature's generic per-record file library)
/// joined this list rather than getting a parallel mechanism: its
/// `entity_name`/`record_id` columns are the same direct-select shape as
/// `audit_header`/`audit_snapshot` (no `audit_ref`-style indirection),
/// so it shares that match arm below, and it never grants its own independent
/// `record_share` rows — a Document row's visibility is purely
/// inherited from the record it's attached to, exactly like the audit case.
/// Unlike an audit event, a Document row's `entity_name`/`record_id` are
/// never null (every Document is attached to something), so the target-less
/// own-scope fallback the call sites below OR in for audit rows simply never
/// triggers for `attome_document` — harmless, not dead code worth special-casing
/// out.
///
/// One caveat worth keeping, since it is a property of the endpoint rather
/// than of this guard: those tests are sensitive to how many rows the audit
/// table holds, and the read pool allows only 500ms. They were seen to fail
/// intermittently against a shared local database of ~15.6k audit rows on a
/// loaded machine, and to pass on a quiet one. Treat an isolated failure there
/// as a volume/load signal to measure, not as an automatic
/// record-level-security regression.
///
/// The largest contributor to that was fixed by D-350 (finding H-9): the seeded
/// default query for these entities used to carry its own
/// `ORDER BY created_at DESC`, which stopped PostgreSQL flattening the subquery
/// `query_exec.rs` wraps it in, so the whole relation was sorted before the
/// outer `ORDER BY id … LIMIT` could stop early on an index. It no longer does.
/// What remains is inherent to the polymorphic case: this per-row predicate
/// still has to be evaluated over rows the index cannot pre-filter, so the
/// volume sensitivity is reduced, not eliminated.
pub const POLYMORPHIC_AUDIT_ENTITIES: &[&str] = &[
    "audit_header",
    "audit_snapshot",
    "audit_detail",
    "attome_document",
];

/// The audit ledger itself: the three entities only the audit writers may
/// create rows in (D-516 ruling 5, audit 10/10 plan item 1.1).
///
/// **Deliberately not `POLYMORPHIC_AUDIT_ENTITIES`**, which also lists
/// `attome_document` — an ordinary, creatable entity that merely shares the
/// polymorphic access predicate. D-516 excludes it by name.
///
/// **Deliberately not "every append-only entity" either.** `is_append_only`
/// is a metadata flag several ordinary entities carry: `integration_event`
/// is append-only *and* is created through `entity_crud::create_record_for`
/// by the inbound webhook (`attome-integration::webhook`), and
/// `s2s_access_log` is append-only traffic. Refusing on the flag would
/// break those; the ledger is a fixed platform invariant, the same reasoning
/// D-386 applies to the constants below.
///
/// Rows here are written only by `attome_audit`'s own writers, which use
/// `attome_core::crud::append_only_insert`/`append_only_insert_many` and
/// the chainer's batch append — never `entity_mutation::create_one`, where
/// the refusal lives.
pub const LEDGER_ENTITIES: &[&str] = &["audit_header", "audit_detail", "audit_snapshot"];

// ── Platform-invariant entity names (D-386) ──────────────────────────────────
//
// Generic entity CRUD names four specific entities in code. D-386 rejected
// ARCH-8's proposal to resolve them from a `requires_sync_invalidation`
// metadata flag — two of them trigger D-116's fail-closed authz invalidation,
// and making that trigger administrator-editable would let clearing a metadata
// field silently stop privilege revocations propagating. These names are
// platform invariants, not per-deployment data: there is no deployment in
// which the correct answer differs, which is the test for whether something
// belongs in metadata at all.
//
// What D-386 *did* sanction — and what the constants below are — is naming
// them as compile-time `const`s beside `POLYMORPHIC_AUDIT_ENTITIES`, so the
// coupling is declared in one greppable place. Readability only: no
// behavioural surface, no security surface, no metadata involvement.
//
// **They are deliberately three separate constants, not one list.** The four
// original literal sites are three unrelated concerns, and D-386 is explicit
// that merging them under a single predicate is the thing to avoid — a
// recursion guard and a cache invalidation trigger share a spelling, not a
// meaning. Adding an entity here is therefore never a one-line change: it
// requires knowing *which* of these three properties it has.

/// The entity whose own rows are also `audit_users` cache keys.
///
/// A write to `user_account` through generic CRUD must drop that user's
/// L1 audit-user entry *and* their cached `SecurityContext`, because
/// `organization_ref` is a column a generic update can change and it seeds
/// `resolve_accessible_org_ids` — i.e. it determines BusinessUnit-tier reach.
/// See [`invalidate_audit_user_if_systemuser`] for the full reasoning and for
/// why the failure is logged rather than propagated.
const AUDIT_USER_CACHE_ENTITY: &str = "user_account";

/// The direct user-privilege grant junction.
///
/// Registered as an entity so the User form's Privileges tab can be an
/// ordinary m2m subgrid, which means grants and revokes reach it through
/// generic CRUD as well as through the bespoke `/api/v1/admin/security/grants`
/// endpoints. Both paths must invalidate synchronously: a delayed revoke of
/// `system.admin` is not an acceptable staleness window (D-116).
///
/// Named here rather than at its use sites because it is consulted from two
/// files for two different reasons — [`invalidate_privilege_grant_target`]
/// after a create/update/soft-delete commit, and `mutations.rs`'s hard-delete
/// path, which must capture `user_ref` from the pre-delete snapshot *before*
/// the physical row disappears and makes it unrecoverable.
pub(super) const PRIVILEGE_GRANT_ENTITY: &str = "user_account_mm_privilege";

/// The entity that mirrors other entities' `file`-typed fields (D-36x).
///
/// Used by `mutations.rs`'s `sync_file_field_documents` as a **recursion
/// guard** — mirroring Document's own `file` field into Document is infinite
/// regress — and then as the mirror target itself. This is not an
/// invalidation concern in any sense; it shares this block only because it is
/// the fourth hardcoded entity name ARCH-8 swept together.
///
/// Note this name also appears in `POLYMORPHIC_AUDIT_ENTITIES` above, for an
/// unrelated third reason: a Document row's visibility is inherited from the
/// record it is attached to rather than granted independently. Same entity,
/// three separate properties — which is exactly why these are not one list.
///
/// One literal remains unreplaced by design: the static `UPDATE attome_document
/// SET is_active = false …` statement in `sync_file_field_documents`. Folding
/// a `const` into it would mean `format!`-ing what is currently a compile-time
/// string, trading a real allocation for a cosmetic gain.
pub(super) const FILE_MIRROR_ENTITY: &str = "attome_document";

/// Looks up the business `(entity_name, record_id)` a polymorphic-reference
/// row is about, for the entities in `POLYMORPHIC_AUDIT_ENTITIES`. `Ok(None)`
/// both for every other entity (zero extra query on the hot path â€” matched
/// away before any SQL runs) and for an audit row that legitimately has no
/// business-record reference (`entity_name`/`record_id` are nullable there â€”
/// e.g. a login/logout or admin-action audit event isn't "about" any entity
/// record, so there's nothing to scope against). `attome_document` rows are
/// required-non-null on both columns (D-36x), so this only ever returns
/// `None` for them via the same `WHERE ... IS NOT NULL` guard finding no row
/// at all (e.g. a stale/deleted id) â€” not a target-less-by-design case.
pub(super) async fn polymorphic_audit_target(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
) -> Result<Option<(String, Uuid)>, AppError> {
    let row: Option<(String, Uuid)> = match entity_name {
        "audit_header" | "audit_snapshot" | "attome_document" => {
            let table = quote_ident(entity_name);
            // `record_id::uuid` — redundant-but-harmless for
            // `audit_header`/`audit_snapshot` (already a native
            // `uuid` column), load-bearing for `attome_document` (a plain
            // `text` column: its polymorphic `record_id` can't be
            // provisioned as a `lookup`-typed field the way audit's is,
            // because `entity_mutation::lock_lookup_targets` rejects any
            // `lookup` field with no configured target the moment a value
            // is written through `create_one`/`update_one` — fine for audit
            // rows, which never go through that path (`AuditService::write_in_tx`
            // writes them directly), fatal for Document, which does for both
            // the file-field mirror sync and the folder browser's ordinary
            // generic-entity writes).
            sqlx::query_as(&attome_db::tag_dynamic(
                "entity.access",
                &format!(
                    "SELECT entity_name, record_id::uuid FROM {table} \
                 WHERE id = $1 AND entity_name IS NOT NULL AND record_id IS NOT NULL"
                ),
            ))
            .bind(record_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
        }
        "audit_detail" => sqlx::query_as(attome_db::tagged_sql!(
            "entity.access",
            "SELECT h.entity_name, h.record_id FROM audit_detail d \
             JOIN audit_header h ON h.id = d.audit_ref \
             WHERE d.id = $1 AND h.entity_name IS NOT NULL AND h.record_id IS NOT NULL"
        ))
        .bind(record_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        _ => None,
    };
    Ok(row)
}

/// Gate for the `(entity_name, record_id)` `polymorphic_audit_target`
/// resolves: does `ctx` hold entity-level read privilege on the audited
/// entity AND pass its record-level RLS? Fails closed to `NotFound` (not
/// `Forbidden`, matching `require_record_access`'s existing
/// can't-distinguish-missing-from-hidden convention) on either a missing
/// privilege or an entity name that no longer resolves (e.g. the audited
/// entity was later renamed/removed) â€” an audit row referencing a target
/// the caller can't independently read must not be readable just because
/// the audit entity itself was.
pub(super) async fn require_referenced_record_access(
    state: &EngineState,
    ctx: &SecurityContext,
    audited_entity_name: &str,
    audited_record_id: Uuid,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }
    let Ok((target_entity_id, target_entity_name, _, _)) =
        resolve_entity(state, audited_entity_name).await
    else {
        return Err(AppError::NotFound);
    };
    if ctx.require(&target_entity_name, "read").is_err() {
        return Err(AppError::NotFound);
    }
    require_record_access(
        state,
        ctx,
        target_entity_id,
        &target_entity_name,
        audited_record_id,
        RecordAction::Read,
    )
    .await
}

/// The whole record-level read decision a single-record read makes, minus the
/// row fetch: the polymorphic-audit carve-out (an audit/document row is gated
/// by the record it is about, D-147), otherwise the row's own
/// `require_record_access`, and then the polymorphic-child parent check
/// (D-593). `get_record`, `read_record` and the record timeline/history routes
/// (D-601) all call this, so they cannot drift apart.
///
/// Does not check the entity-level `{entity}.read` privilege (the HTTP
/// extractor does, and a non-HTTP caller does it itself) and does not prove the
/// row exists for a Global-tier caller — `require_record_access` short-circuits
/// there, and the caller's own fetch answers `NotFound`.
///
/// S1-T15: a record the caller cannot read answers `NotFound`, never
/// `Forbidden`, so a read cannot tell a hidden record from a missing one;
/// any `Forbidden` from the checks below is answered as `NotFound`.
pub(crate) async fn require_record_read(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
) -> Result<(), AppError> {
    record_read_checks(state, ctx, entity_id, entity_name, record_id)
        .await
        .map_err(|error| match error {
            AppError::Forbidden => AppError::NotFound,
            other => other,
        })
}

async fn record_read_checks(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
) -> Result<(), AppError> {
    match polymorphic_audit_target(state, entity_name, record_id).await? {
        Some((audited_entity, audited_record_id)) => {
            require_referenced_record_access(state, ctx, &audited_entity, audited_record_id)
                .await?;
        }
        None => {
            require_record_access(
                state,
                ctx,
                entity_id,
                entity_name,
                record_id,
                RecordAction::Read,
            )
            .await?;
        }
    }
    require_child_parent_access(state, ctx, entity_name, record_id).await
}

/// Entities whose rows hang off another record through a text `entity_name` +
/// `record_id` pair: a note, a communication, a tag or a follow *on* some
/// record (basic-units plan B-R1, U1).
///
/// Unlike [`POLYMORPHIC_AUDIT_ENTITIES`], these rows carry real row-level
/// security of their own (owners, the creator share), so the parent check is
/// **added to** the row's own check, never substituted for it. A row is
/// readable only when the caller passes its own record scope **and** can read
/// the record it is attached to. Substituting would widen a role limited to its
/// own notes to every note on every record it can see.
///
/// The parent half applies at every access level short of admin: a caller with
/// Global read on `note` still cannot read the notes of a record hidden from
/// them, which is the gap this closes.
///
/// `attome-search` (`corpus`, `routes`, `aggregate`) keeps its own copy of this
/// list because it cannot depend on this crate; change both together.
pub const POLYMORPHIC_CHILD_ENTITIES: &[&str] = &[
    "note",
    // C1-T1: a note's replies, on the note's own parent record.
    "note_reply",
    "communication",
    "tag_item",
    "follow",
    "reminder",
    // U2 activities (D-600), added to D-593's list 2026-09-23.
    "activity",
];

/// Whether `ctx` can read the record `(entity_name, record_id)` names, as the
/// parent check of [`POLYMORPHIC_CHILD_ENTITIES`] decides it: entity read
/// privilege plus record-level security, admins always. `Ok(false)` covers
/// "hidden", "gone" and "unknown entity" alike; any other failure is an error.
///
/// For callers outside a request that act on a user's behalf — the reminder
/// delivery sweep (D-602) asks it for the reminder's recipient.
pub async fn referenced_record_visible(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    record_id: Uuid,
) -> Result<bool, AppError> {
    match require_referenced_record_access(state, ctx, entity_name, record_id).await {
        Ok(()) => Ok(true),
        Err(AppError::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A child row's stored parent reference. `record_id` is a plain `text`
/// column on every one of these entities, so it is parsed here rather than cast in SQL:
/// a malformed value must fail closed, not raise a cast error.
async fn child_parent_ref(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
) -> Result<Option<(Option<String>, Option<String>)>, AppError> {
    let table = quote_ident(entity_name);
    sqlx::query_as(&attome_db::tag_dynamic(
        "entity.access",
        &format!("SELECT entity_name, record_id FROM {table} WHERE id = $1"),
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Read gate on the record an existing polymorphic child row is attached to.
/// A no-op for admins and for every entity outside
/// [`POLYMORPHIC_CHILD_ENTITIES`]. Every call site runs the row's own
/// `require_record_access` first; this is the second, additional half.
///
/// A parent reference that is missing or not a UUID fails closed to
/// `NotFound`, the same can't-tell-missing-from-hidden answer
/// [`require_referenced_record_access`] gives for a hidden parent.
pub(crate) async fn require_child_parent_access(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    record_id: Uuid,
) -> Result<(), AppError> {
    if ctx.is_admin || !POLYMORPHIC_CHILD_ENTITIES.contains(&entity_name) {
        return Ok(());
    }
    match child_parent_ref(state, entity_name, record_id).await? {
        // No such row: the row's own check has already answered for it.
        None => Ok(()),
        Some((Some(parent_entity), Some(parent_id))) => match Uuid::parse_str(parent_id.trim()) {
            Ok(parent_id) => {
                require_referenced_record_access(state, ctx, &parent_entity, parent_id).await
            }
            Err(_) => Err(AppError::NotFound),
        },
        Some(_) => Err(AppError::NotFound),
    }
}

/// Write-side gate: the parent a create names, or the parent an update moves
/// the row to. You cannot attach a note to a record you cannot read.
///
/// `existing` is `None` for a create. For an update whose body touches neither
/// `entity_name` nor `record_id` the parent is unchanged, and
/// [`require_child_parent_access`] (which the caller runs on the existing row)
/// already covers it. A partial update that changes only one of the pair is
/// resolved against the stored value of the other.
pub(crate) async fn require_child_parent_access_for_write(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    existing: Option<Uuid>,
    body: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if ctx.is_admin || !POLYMORPHIC_CHILD_ENTITIES.contains(&entity_name) {
        return Ok(());
    }
    let touches_parent = body.contains_key("entity_name") || body.contains_key("record_id");
    if existing.is_some() && !touches_parent {
        return Ok(());
    }
    let (stored_entity, stored_id) = match existing {
        Some(id) => child_parent_ref(state, entity_name, id)
            .await?
            .unwrap_or((None, None)),
        None => (None, None),
    };
    let named = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let parent_entity = named("entity_name").or(stored_entity);
    let parent_id = named("record_id").or(stored_id);
    let invalid = || {
        AppError::Validation(format!(
            "{entity_name} must name the record it belongs to: entity_name and a record_id UUID"
        ))
    };
    let parent_entity = parent_entity.ok_or_else(invalid)?;
    let parent_id = parent_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id.trim()).ok())
        .ok_or_else(invalid)?;
    require_referenced_record_access(state, ctx, &parent_entity, parent_id).await
}

/// Writes the implicit `action`-capability share row `create_record` grants
/// its caller (D-133 (2)) — this row is what *authorizes* the creator, and
/// `rls_predicate` reads only this table, never the `owner_ref` column below.
/// D-137 added `owner_ref`/`owner_type` as a denormalized, always-in-sync
/// pointer alongside this row (set by `entity_mutation::create_one`, in the
/// same transaction) purely for query/report/grid/queue purposes — it is a
/// second, narrower answer to "who owns this," not a second mechanism for
/// "who can act on this." Runs in the same transaction as the insert so a
/// failure rolls the whole create back rather than leaving an unowned,
/// inaccessible-to-its-own-creator record behind.
pub async fn grant_creator_share(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    record_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    grant_user_share_in_tx(tx, entity_id, record_id, user_id, 1, user_id).await?;
    Ok(())
}

/// Gives one user a share of one record: `capability` 0 to view, 1 to act
/// (`rls::Capability`). Idempotent; the share's id, existing or new. The
/// record-rule predicate reads `record_share` live, so there is no cache to
/// invalidate (D7-T2's deal team members are granted this way).
pub async fn grant_user_share_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    record_id: Uuid,
    user_id: Uuid,
    capability: i16,
    granted_by: Uuid,
) -> Result<Uuid, AppError> {
    if !(0..=1).contains(&capability) {
        return Err(AppError::internal(
            "a share capability is 0 (view) or 1 (act)",
        ));
    }
    sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.access",
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
         VALUES ($1, $2, 0, $3, $4, $5) \
         ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) \
         DO UPDATE SET granted_by = record_share.granted_by \
         RETURNING id"
    ))
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .bind(capability)
    .bind(granted_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Removes one share by id; whether a row went.
pub async fn revoke_share_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    share_id: Uuid,
) -> Result<bool, AppError> {
    Ok(sqlx::query(attome_db::tagged_sql!(
        "entity.access",
        "DELETE FROM record_share WHERE id = $1"
    ))
    .bind(share_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected()
        > 0)
}

/// M01 Core C-12: resolves the `(AccessLevel, owner_visible)` pair
/// [`guard_cascade_dependent_access`] needs for every dependent in
/// `dependents`, before any transaction is open. These depend only on
/// `(user, dep_entity, Delete)` — never on `record_id`, which dependent rows
/// actually exist, or anything else the caller's own transaction would lock —
/// so there is no reason to wait until that transaction is open, and every
/// reason not to: `guard_cascade_dependent_access` always receives an
/// already-open transaction, and resolving these on the pool from inside it
/// would check out a second connection while the first is still held,
/// self-deadlocking under pool saturation (M01-core C-12). Returns one entry
/// per element of `dependents`, in order; a non-`CascadeDeactivate`
/// dependent's entry is `(None, false)` and unused.
pub async fn resolve_cascade_dependent_access(
    state: &EngineState,
    ctx: &SecurityContext,
    dependents: &[(String, String, OnTargetDelete)],
) -> Result<Vec<(Option<AccessLevel>, bool)>, AppError> {
    let mut out = Vec::with_capacity(dependents.len());
    for (dep_entity, _dep_field, mode) in dependents {
        if *mode != OnTargetDelete::CascadeDeactivate {
            out.push((None, false));
            continue;
        }
        // D-369: an arc-swap registry read, not a DB round trip.
        let dep_entity_id = state.entities.load().get(dep_entity).map(|m| m.entity_id);
        let access_level = match dep_entity_id {
            Some(id) => Some(
                resolve_entity_access_level(
                    &state.base.db,
                    ctx.user_id,
                    id,
                    dep_entity,
                    RecordAction::Delete,
                )
                .await?,
            ),
            None => None,
        };
        let owner_visible = match dep_entity_id {
            Some(id) => {
                resolve_owner_visible(
                    &state.base.db,
                    ctx.user_id,
                    id,
                    dep_entity,
                    RecordAction::Delete,
                )
                .await?
            }
            None => false,
        };
        out.push((access_level, owner_visible));
    }
    Ok(out)
}

/// D-133 follow-up / cascade-delete-authz: `apply_dependents_on_delete`'s
/// `CascadeDeactivate` policy silently deactivates rows on *other* entities
/// the caller may hold no privilege on at all â€” entity-level `delete` on the
/// target entity (checked by every call site before this) says nothing about
/// `dep_entity`. This mirrors `merge_records`'s dependent-redirect guard
/// exactly: require entity-level `delete` on every cascade-dependent entity,
/// then lock (`FOR UPDATE`) every currently-active row referencing
/// `record_id` on that entity and reject the whole delete unless every one of
/// them falls inside the caller's record-level scope. Must run inside the
/// same transaction whose later `apply_dependents_on_delete` call performs
/// the actual cascade `UPDATE`, so the locks taken here are still held when
/// that statement executes â€” same reasoning merge gives for why this isn't a
/// TOCTOU race against a concurrent write to these rows.
///
/// Restrict/orphan dependents need no check here: `Restrict` only ever blocks
/// the delete (no write to the dependent table), and plain orphan (no policy
/// entry at all) leaves the dependent row's lookup field untouched.
///
/// M01 Core C-12: `access_by_dep` is the per-dependent `(AccessLevel,
/// owner_visible)` pair [`resolve_cascade_dependent_access`] resolves —
/// parallel to `dependents`, one entry per element, `(None, false)` for a
/// non-`CascadeDeactivate` dependent (never consulted for those; the `mode`
/// check below still short-circuits first). Resolving it used to happen right
/// here, against the pool, every call — but every call site already has this
/// same transaction open by the time it calls this function (the whole point
/// is to lock dependent rows under it), so that pool call was a second
/// connection checked out from the same pool the transaction's own connection
/// already holds, which self-deadlocks under pool saturation (M01-core C-12).
/// `dependents` is known before any transaction opens (an arc-swap registry
/// read), so the caller now resolves `access_by_dep` there too, on the pool,
/// before `begin()`.
pub async fn guard_cascade_dependent_access(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    access_by_dep: &[(Option<AccessLevel>, bool)],
) -> Result<(), AppError> {
    for ((dep_entity, dep_field, mode), (access_level, dep_owner_visible)) in
        dependents.iter().zip(access_by_dep.iter())
    {
        if *mode != OnTargetDelete::CascadeDeactivate {
            continue;
        }

        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);
        // D-369: attrs come along with the same registry read entity_id
        // already needed — an arc-swap read, not an extra DB round trip.
        let dep_meta = state.entities.load().get(dep_entity).cloned();
        let dep_entity_id = dep_meta.as_ref().map(|meta| meta.entity_id);
        let dep_attrs = dep_meta.as_ref().map(|m| m.attrs.as_slice()).unwrap_or(&[]);
        let access_level = *access_level;
        let dep_owner_visible = *dep_owner_visible;
        let dep_privilege_key = format!("{dep_entity}.delete");
        let rls = match (dep_entity_id, access_level) {
            (Some(id), Some(access_level)) => rls_predicate_with_conditions(
                ctx,
                id,
                "d",
                access_level,
                RecordAction::Delete.share_capability(),
                &dep_privilege_key,
                dep_attrs,
                dep_owner_visible,
                2,
            ),
            _ => None,
        };
        let predicate = rls.as_ref().map_or("", |p| p.sql.as_str());

        let total_count: i64 = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.access",
            &format!(
                "SELECT COUNT(*) FROM {dep_table} WHERE {dep_field_ident} = $1 AND is_active = TRUE"
            ),
        ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        if total_count == 0 {
            continue;
        }

        ctx.require(dep_entity, "delete")?;

        let lock_sql = format!(
            "SELECT d.id FROM {dep_table} d WHERE d.{dep_field_ident} = $1 \
             AND d.is_active = TRUE {predicate} FOR UPDATE"
        );
        let lock_sql = attome_db::tag_dynamic("entity.access", &lock_sql);
        let mut lq = sqlx::query_scalar::<_, Uuid>(&lock_sql).bind(record_id);
        if let Some(pred) = &rls {
            if let Some(tb) = &pred.tier_binds {
                lq = bind_rls_predicate(lq, tb);
            }
            for bind in &pred.condition_binds {
                lq = lq.bind(bind);
            }
        }
        let authorized_ids: Vec<Uuid> =
            lq.fetch_all(&mut **tx).await.map_err(AppError::internal)?;

        if authorized_ids.len() as i64 != total_count {
            // At least one dependent row referencing `record_id` falls
            // outside the caller's record-level access on `dep_entity`.
            // Reject the whole delete rather than cascade only the rows the
            // caller happens to be authorized on â€” a partially-cascaded
            // delete leaves the rest pointing at a retired parent, same
            // failure mode merge's own comment calls out.
            return Err(AppError::Forbidden);
        }
    }
    Ok(())
}

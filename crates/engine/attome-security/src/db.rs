//! Privilege resolution against the existing (legacy, shared) privilege
//! tables plus the D-111 `role` model (supersedes D-011/D-012's
//! `core_job`-based grant path — see DECISIONS.md).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use attome_db::DbPool;
use attome_server::security::{AccessLevel, ConditionOperator, GrantCondition};
use attome_types::AppError;
use uuid::Uuid;

/// P1.15 §4(c): every node falls through to this query simultaneously during
/// a Redis (L2 cache) outage, since it's the L3 fallback behind `attome-security`'s
/// L1 moka + L2 Redis layering (D-012) — bounding it (guidelines §14.1's
/// fast-read class) keeps that fallback a latency hit, not an unbounded stall
/// stacked on top of an already-degraded cache path.
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// Guards every privilege resolution against a missing/disabled account
/// (P-account-state-enforcement, audit finding #2) — without this, a
/// disabled user with a still-live session (or a warm 60s authz cache entry,
/// D-012) kept every privilege it held at disable time. Runs on the same
/// `QUERY_TIMEOUT` budget as the privilege query itself, since it's on the
/// exact same request-path hot loop (`SecurityCache::resolve`'s cache-miss
/// path, `attome-server`'s worker-startup `resolve_uncached`). `is_active IS
/// NULL` is legacy-active (D-005, matches
/// `0024_partial_unique_soft_delete.sql`'s index predicate).
async fn require_active_user(db: &DbPool, user_id: Uuid) -> Result<(), AppError> {
    let row: Option<Option<bool>> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db),
    )
    .await
    .map_err(|_| AppError::internal("account-state check timed out"))?
    .map_err(AppError::internal)?;

    match row {
        None => Err(AppError::Forbidden),              // no such user
        Some(Some(false)) => Err(AppError::Forbidden), // explicitly disabled
        Some(_) => Ok(()),                             // active, or legacy NULL = active
    }
}

/// Resolves every `privilege.key` held by `user_id`, via direct grants
/// (`user_account_mm_privilege`) and role-mediated grants
/// (`role_mm_privilege` joined through either
/// `user_account_mm_role` or team membership, D-111/D-133). One
/// bound-parameter query, no N+1. Guarded by `require_active_user` first —
/// see that function's doc comment.
pub async fn resolve_privileges(db: &DbPool, user_id: Uuid) -> Result<HashSet<String>, AppError> {
    require_active_user(db, user_id).await?;

    let keys: Vec<String> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT p.key
            FROM privilege p
            JOIN user_account_mm_privilege up ON up.privilege_ref = p.id
            WHERE up.user_ref = $1 AND up.is_active = true AND p.is_active = true

            UNION

            SELECT DISTINCT p.key
            FROM privilege p
            JOIN role_mm_privilege rp ON rp.privilege_ref = p.id
            JOIN user_account_mm_role ur ON ur.role_ref = rp.role_ref
            WHERE ur.user_ref = $1 AND ur.is_deleted = false
              AND rp.is_deleted = false AND p.is_active = true

            UNION

            SELECT DISTINCT p.key
            FROM privilege p
            JOIN role_mm_privilege rp ON rp.privilege_ref = p.id
            JOIN role_mm_team rt ON rt.role_ref = rp.role_ref
            JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref
            WHERE ut.user_ref = $1 AND ut.is_deleted = false
              AND rt.is_deleted = false AND rp.is_deleted = false
              AND p.is_active = true
            "#,
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("privilege resolution query timed out"))?
    .map_err(AppError::internal)?;

    Ok(keys.into_iter().collect())
}

/// Resolves both grant dimensions of every `"{entity_logicalname}.{field_logicalname}"`
/// pair reachable through one of `user_id`'s roles' `field_security_profile`
/// assignments (`role_mm_field_security_profile` joined through
/// `user_account_mm_role`) — `can_read` (D-111/F013/F135) and `can_update`
/// (P-field-write-security, D-141), returned as two independent sets rather
/// than a single set with a value, matching `has_field_read_grant`/
/// `has_field_write_grant`'s pure-membership check shape. One query pass, not
/// two, since both dimensions live on the same `field_security_profile_field`
/// row — no reason to hit Postgres twice for one table's two columns. No
/// direct-user assignment path — field-security profiles attach to roles
/// only, unlike privileges (which also support a direct user grant) —
/// keeping one assignment shape for this grant type rather than mirroring
/// privileges' two paths before there's a demonstrated need for the direct
/// one.
pub async fn resolve_field_grants(
    db: &DbPool,
    user_id: Uuid,
) -> Result<(HashSet<String>, HashSet<String>), AppError> {
    let rows: Vec<(String, String, bool, bool)> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(
            r#"
            SELECT DISTINCT f.entity_logicalname, f.field_logicalname, f.can_read, f.can_update
            FROM field_security_profile_field f
            JOIN role_mm_field_security_profile rp ON rp.profile_ref = f.profile_ref
            JOIN user_account_mm_role ur ON ur.role_ref = rp.role_ref
            WHERE ur.user_ref = $1 AND ur.is_deleted = false
              AND rp.is_deleted = false AND (f.can_read = true OR f.can_update = true)
            "#,
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("field-grant resolution query timed out"))?
    .map_err(AppError::internal)?;

    let mut read_grants = HashSet::new();
    let mut write_grants = HashSet::new();
    for (entity, field, can_read, can_update) in rows {
        let key = format!("{entity}.{field}");
        if can_read {
            read_grants.insert(key.clone());
        }
        if can_update {
            write_grants.insert(key);
        }
    }
    Ok((read_grants, write_grants))
}

/// D-589: the caller's bulk-surface field exposure. `Legacy` (today's
/// behaviour) while any role the caller holds, directly or through a team, is
/// still `legacy`, or while the caller holds a direct privilege grant (which
/// predates roles and has no bulk list of its own), or holds no role at all.
/// Otherwise `Listed` with the union of every held role's listed fields.
pub async fn resolve_bulk_fields(
    db: &DbPool,
    user_id: Uuid,
) -> Result<attome_server::security::BulkFields, AppError> {
    let row: (i64, bool, bool, Vec<String>) = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(
            r#"
            WITH held AS (
                SELECT ur.role_ref FROM user_account_mm_role ur
                WHERE ur.user_ref = $1 AND ur.is_deleted = false
                UNION
                SELECT rt.role_ref FROM role_mm_team rt
                JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref
                WHERE ut.user_ref = $1 AND ut.is_deleted = false AND rt.is_deleted = false
            ), roles AS (
                SELECT r.id, r.bulk_field_mode FROM role r
                JOIN held h ON h.role_ref = r.id
                WHERE r.is_deleted = false
            )
            SELECT
                (SELECT COUNT(*) FROM roles),
                COALESCE((SELECT bool_or(bulk_field_mode = 0) FROM roles), false),
                EXISTS (SELECT 1 FROM user_account_mm_privilege up
                        WHERE up.user_ref = $1 AND up.is_active = true),
                COALESCE((SELECT array_agg(DISTINCT bf.entity_logicalname || '.' || bf.attribute_logicalname)
                          FROM role_bulk_field bf JOIN roles ON roles.id = bf.role_ref),
                         ARRAY[]::text[])
            "#,
        )
        .bind(user_id)
        .fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("bulk-field resolution query timed out"))?
    .map_err(AppError::internal)?;
    let (role_count, any_legacy, has_direct_privilege, fields) = row;
    Ok(if role_count == 0 || any_legacy || has_direct_privilege {
        attome_server::security::BulkFields::Legacy
    } else {
        attome_server::security::BulkFields::Listed(fields.into_iter().collect())
    })
}

/// Finds a `privilege` row by unique `key`, creating it if missing.
/// Shared by `seed::seed` (bootstrap admin) and `admin::create_grant` (the
/// privilege-grants admin page) — both need "find or create privilege by key".
///
/// `owner_layer` (Solution 7, D-785) stamps a newly created row only; an
/// existing row keeps its layer.
pub async fn ensure_privilege(
    db: &DbPool,
    key: &str,
    name: &str,
    description: &str,
    owner_layer: attome_core::changeset::Layer,
) -> Result<Uuid, AppError> {
    ensure_privilege_with_id(db, key, name, description, None, owner_layer).await
}

/// Same as [`ensure_privilege`], but on the create path binds `desired_id`
/// verbatim instead of a random `Uuid::now_v7()` — the bundle engine's
/// deterministic-id path (D-374 amendment), used only by
/// `reconcile_privilege`. `None` reproduces [`ensure_privilege`]'s random-id
/// behavior exactly; ignored when the row already exists (`ON CONFLICT`).
pub async fn ensure_privilege_with_id(
    db: &DbPool,
    key: &str,
    name: &str,
    description: &str,
    desired_id: Option<Uuid>,
    owner_layer: attome_core::changeset::Layer,
) -> Result<Uuid, AppError> {
    // Race-safe find-or-create, not check-then-insert. The previous shape was
    // SELECT-then-INSERT with no guard between them: two callers seeding the
    // same key concurrently — two engines' `seed::seed` runs, or a seed racing
    // `admin::create_grant` — both missed the SELECT, both INSERTed, and the
    // loser surfaced a raw `uq_core_privilege_key` violation as an opaque
    // `Internal` error out of what is documented as an idempotent helper
    // (guidelines §2: every mutation needs an explicit concurrency story).
    // `ON CONFLICT (key) DO NOTHING` closes the window against
    // `uq_core_privilege_key`'s plain `UNIQUE (key)` index; `RETURNING id`
    // yields `None` on the losing side, which the follow-up read resolves to
    // whichever id the winner committed.
    //
    // privilege.id has no column default (legacy table) — bind explicitly.
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer)
         VALUES ($1, $2, $3, $4, true, NOW(), $5)
         ON CONFLICT (key) DO NOTHING
         RETURNING id",
    )
    .bind(desired_id.unwrap_or_else(Uuid::now_v7))
    .bind(key)
    .bind(name)
    .bind(description)
    .bind(owner_layer.as_str())
    .fetch_optional(db)
    .await
    // M01 Core C-23: this INSERT's own `ON CONFLICT (key) DO NOTHING`
    // already closes the unique-key race documented above, so `classify`'s
    // 23505 branch is not expected to fire here — it is adopted for the
    // other SQLSTATEs it recognizes (an FK violation, a serialization
    // conflict) instead of a blanket `AppError::internal`.
    .map_err(attome_db::classify)?
    {
        return Ok(id);
    }

    // Either the row already existed or we lost the insert race — both resolve
    // to "read the committed row". `fetch_one`, not `fetch_optional`: a miss
    // here would mean the conflicting row vanished between the two statements,
    // which no code path does (privileges are never hard-deleted), so it is a
    // genuine internal error rather than a `None` for the caller to interpret.
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Solution 7 (D-785): [`ensure_privilege`] inside the caller's transaction,
/// stamping a newly created row with `owner_layer`, and reporting whether it
/// created one (the admin role-grant route records `ensure_privilege` only
/// then). An existing row is returned untouched, whatever its layer: minting
/// is idempotent and changes nothing on a privilege that already exists.
pub async fn ensure_privilege_in_tx(
    conn: &mut sqlx::PgConnection,
    key: &str,
    name: &str,
    description: &str,
    owner_layer: attome_core::changeset::Layer,
) -> Result<(Uuid, bool), AppError> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, \
             owner_layer) \
         VALUES ($1, $2, $3, $4, true, NOW(), $5) \
         ON CONFLICT (key) DO NOTHING \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(key)
    .bind(name)
    .bind(description)
    .bind(owner_layer.as_str())
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?
    {
        return Ok((id, true));
    }
    let id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok((id, false))
}

/// Idempotent direct-grant insert: `user_id` holds `privilege_id` after this
/// call, no duplicate row on repeat calls (checks the `uq_user_priv`
/// constraint's shape before inserting). Shared by `seed::seed` and
/// `admin::create_grant`.
pub async fn ensure_user_privilege_grant(
    db: &DbPool,
    user_id: Uuid,
    privilege_id: Uuid,
) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_privilege WHERE user_ref = $1 AND privilege_ref = $2)",
    )
    .bind(user_id)
    .bind(privilege_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    if exists {
        return Ok(());
    }

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at)
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(id)
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    // M01 Core C-23: a bad `user_id`/`privilege_id` FK, or a lost race
    // against a concurrent grant of the same pair, is now classified
    // (409/422) instead of a blanket masked 500.
    .map_err(attome_db::classify)?;

    Ok(())
}

/// Idempotent role-grant insert (D-111): every current + future member of
/// `role_id` holds `privilege_id` after this call, no duplicate row on
/// repeat calls (mirrors `ensure_user_privilege_grant`, targeting
/// `role_mm_privilege`). Reactivates a previously soft-deleted grant
/// rather than inserting a second row for the same pair.
///
/// A thin wrapper over [`upsert_role_privilege_grant`] (C-19): this used to
/// be its own check-then-write (SELECT, then branch to UPDATE or INSERT) —
/// racy under two concurrent callers of the same pair, and a second,
/// independent restatement of `reconcile_role`'s own reactivate-or-insert
/// block in `attome-security/src/reconcile.rs`. Kept as a separate name (rather
/// than switching `admin::role_grants::create_role_grant` to call the
/// `upsert_*` function directly) purely so that call site's `Result<(),
/// AppError>` shape doesn't need to change too.
pub async fn ensure_role_privilege_grant(
    db: &DbPool,
    role_id: Uuid,
    privilege_id: Uuid,
) -> Result<(), AppError> {
    // Not a recorded path (tests and tooling): a new row gets `project`,
    // the layer every row had before D-785.
    upsert_role_privilege_grant(
        db,
        role_id,
        privilege_id,
        attome_core::changeset::Layer::Project,
    )
    .await
    .map(|_id| ())
}

/// Atomic role <-> privilege grant upsert (C-19): one `ON CONFLICT` statement
/// for the table `reconcile_role`, `ensure_role_privilege_grant` and (through
/// that wrapper) `admin::role_grants::create_role_grant` all write. Reactivates
/// a soft-deleted grant or creates a fresh one, bumping `row_version` in both
/// cases — the previous check-then-write shape never bumped it on reactivate,
/// unlike `reconcile_role`'s own hand-rolled version of this same upsert.
/// Generic over the executor so a caller inside an open transaction (`&mut
/// *tx`) and a caller holding only the pool (`&state.base.db`) share the one
/// implementation.
///
/// `owner_layer` (Solution 7, D-785) stamps a newly inserted row only; a
/// reactivated or re-granted row keeps its layer (the caller checks it).
pub async fn upsert_role_privilege_grant<'c, E>(
    db: E,
    role_id: Uuid,
    privilege_id: Uuid,
    owner_layer: attome_core::changeset::Layer,
) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    sqlx::query_scalar(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (role_ref, privilege_ref) DO UPDATE SET \
             is_deleted = false, updated_at = NOW(), \
             row_version = role_mm_privilege.row_version + 1 \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .bind(owner_layer.as_str())
    .fetch_one(db)
    .await
    // M01 Core C-23: a bad `role_id`/`privilege_id` FK is now `Validation`
    // (422) instead of a masked 500 — the `ON CONFLICT` target above only
    // covers the (role_ref, privilege_ref) unique key, not the FK columns.
    .map_err(attome_db::classify)
}

/// Atomic role x entity access-level grant upsert (C-19): the one `ON
/// CONFLICT` statement `reconcile_role` and
/// `admin::role_entity_access::upsert_entity_access_grant` both write against
/// `role_mm_entity_access`. Before this collapse the two had drifted:
/// the admin handler's copy never bumped `row_version` on an update, while
/// `reconcile_role`'s did. Always bumps it now, matching every other mutable
/// table's write path.
///
/// `owner_layer` (Solution 7, D-785) stamps a newly inserted row only.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_role_entity_access<'c, E>(
    db: E,
    role_id: Uuid,
    entity_ref: Uuid,
    read_access_level: i16,
    write_access_level: i16,
    delete_access_level: i16,
    read_owner_visible: bool,
    write_owner_visible: bool,
    delete_owner_visible: bool,
    owner_layer: attome_core::changeset::Layer,
) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    sqlx::query_scalar(
        "INSERT INTO role_mm_entity_access \
             (id, role_ref, entity_ref, read_access_level, write_access_level, \
              delete_access_level, read_owner_visible, write_owner_visible, \
              delete_owner_visible, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (role_ref, entity_ref) DO UPDATE SET \
             read_access_level = EXCLUDED.read_access_level, \
             write_access_level = EXCLUDED.write_access_level, \
             delete_access_level = EXCLUDED.delete_access_level, \
             read_owner_visible = EXCLUDED.read_owner_visible, \
             write_owner_visible = EXCLUDED.write_owner_visible, \
             delete_owner_visible = EXCLUDED.delete_owner_visible, \
             is_deleted = false, updated_at = NOW(), \
             row_version = role_mm_entity_access.row_version + 1 \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_ref)
    .bind(read_access_level)
    .bind(write_access_level)
    .bind(delete_access_level)
    .bind(read_owner_visible)
    .bind(write_owner_visible)
    .bind(delete_owner_visible)
    .bind(owner_layer.as_str())
    .fetch_one(db)
    .await
    // M01 Core C-23: a bad `role_id`/`entity_ref` FK is now `Validation`
    // (422) instead of a masked 500.
    .map_err(attome_db::classify)
}

/// Atomic field-security profile field upsert (C-19): the one `ON CONFLICT`
/// statement `reconcile_field_security_profile` and
/// `admin::field_security::set_field_profile_field` both wrote out
/// identically against `field_security_profile_field` — same SQL,
/// two copies. No soft-delete flag on this table (migration 0040); a member
/// that should stop being granted is a `DELETE`, not a write this function
/// makes.
///
/// `owner_layer` (Solution 7, D-785) stamps a newly inserted row only.
pub async fn upsert_profile_field<'c, E>(
    db: E,
    profile_id: Uuid,
    entity: &str,
    field: &str,
    can_read: bool,
    can_update: bool,
    owner_layer: attome_core::changeset::Layer,
) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    sqlx::query_scalar(
        "INSERT INTO field_security_profile_field \
             (id, profile_ref, entity_logicalname, field_logicalname, can_read, can_update, \
              owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (profile_ref, entity_logicalname, field_logicalname) \
         DO UPDATE SET can_read = EXCLUDED.can_read, can_update = EXCLUDED.can_update, \
             updated_at = NOW(), \
             row_version = field_security_profile_field.row_version + 1 \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(profile_id)
    .bind(entity)
    .bind(field)
    .bind(can_read)
    .bind(can_update)
    .bind(owner_layer.as_str())
    .fetch_one(db)
    .await
    // M01 Core C-23: a bad `profile_id` FK is now `Validation` (422)
    // instead of a masked 500.
    .map_err(attome_db::classify)
}

/// D-133: every currently-active user who effectively holds `role_id` —
/// direct (`user_account_mm_role`) OR team-mediated
/// (`role_mm_team` joined through `user_account_mm_team`).
/// Used to fan out cache invalidation (a loop of in-memory/Redis key
/// deletes, not a query-per-user N+1) on any role-privilege,
/// role-grant-condition, role-field-profile, or `access_level` change — a
/// team-mediated holder's cached `SecurityContext`/privileges are exactly as
/// stale as a direct holder's after any of those change. (C-03: this
/// replaced the direct-only `users_in_role`, which predated D-133's team
/// path and let team-mediated holders keep stale privileges until the cache
/// TTL expired.)
pub async fn users_holding_role(db: &DbPool, role_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        r#"
        SELECT user_ref FROM user_account_mm_role
        WHERE role_ref = $1 AND is_deleted = false

        UNION

        SELECT ut.user_ref
        FROM role_mm_team rt
        JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref
        WHERE rt.role_ref = $1 AND rt.is_deleted = false AND ut.is_deleted = false
        "#,
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

// ── P-record-level-security (post-D-133/D-134): entity-scoped resolution ──
//
// Supersedes the old `resolve_access_level` (single `role.access_level`
// scalar, MAX-aggregated across every role a user holds regardless of
// entity). That design let a role's scope for one entity leak into every
// other entity a user could touch — a role granting Global scope for
// Employee widened a user's Customer access to Global too, if that same
// user also held a role scoped only Team for Customer, since the bare
// cross-role MAX had no entity boundary. See D-136 in DECISIONS.md.

/// Which action's depth to resolve — mirrors `role_mm_entity_access`'s
/// three scoped columns exactly. `create` is deliberately not a variant
/// here: a create has no existing row for `rls_predicate` to filter
/// against, so there is nothing for a depth to scope — create stays gated
/// purely by the boolean `role_mm_privilege` grant via
/// `SecurityContextExt::require`, same as today. Distinct from
/// `rls::Capability` (`View`/`Action`, 2-valued) on purpose: `Capability`
/// gates only the `record_share`/`entity_default_share`
/// capability check inside `rls_predicate`, an orthogonal, coarser axis
/// that doesn't distinguish update from delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordAction {
    Read,
    Update,
    Delete,
}

impl RecordAction {
    /// The suffix `SecurityContextExt::require`'s privilege-key convention
    /// (`"{entity}.{action}"`) already uses at every existing call site.
    /// `pub` (not `pub(crate)`) so `entity_crud.rs`'s D-369 condition call
    /// sites can build the same `"{entity}.{action}"` privilege key without
    /// a second, duplicated verb table.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordAction::Read => "read",
            RecordAction::Update => "update",
            RecordAction::Delete => "delete",
        }
    }

    /// The `rls::Capability` (View/Action, 2-valued) that gates the
    /// `record_share`/`entity_default_share` capability check for
    /// this action — a deterministic mapping (`Read` needs only `View`;
    /// `Update` and `Delete` both need `Action`, since sharing has never
    /// distinguished the two), kept here so every call site only ever has to
    /// think in terms of one action type, not both.
    pub fn share_capability(self) -> crate::rls::Capability {
        match self {
            RecordAction::Read => crate::rls::Capability::View,
            RecordAction::Update | RecordAction::Delete => crate::rls::Capability::Action,
        }
    }
}

/// The "which roles does this user effectively hold" CTE — direct
/// (`user_account_mm_role`) OR team-mediated (`role_mm_team`
/// joined through `user_account_mm_team`), always keyed on `$1` =
/// `user_id`. C-19: this exact shape used to be hand-copied into six
/// functions below (`resolve_entity_access_level`, `resolve_owner_visible`,
/// `resolve_condition_grants`, `resolve_all_entity_access_levels`,
/// `any_role_uses_business_unit_scope`, and — inlined slightly differently,
/// selecting `position_hierarchy_enabled` directly instead of projecting
/// `role_id` — `resolve_position_hierarchy_enabled`) — one drifting typo
/// away from a silent authorization gap between them. Spliced in via `format!`, not a
/// bind parameter: this is a fixed literal SQL fragment (no request data),
/// so string composition here carries none of the interpolation risk
/// guidelines §4 warns against — every actual value is still bound
/// positionally by the query that wraps this constant.
pub(crate) const HELD_ROLES_CTE: &str = r#"
    WITH held_roles AS (
        SELECT r.id AS role_id
        FROM role r
        JOIN user_account_mm_role ur ON ur.role_ref = r.id
        WHERE ur.user_ref = $1 AND ur.is_deleted = false AND r.is_deleted = false

        UNION

        SELECT r.id AS role_id
        FROM role r
        JOIN role_mm_team rt ON rt.role_ref = r.id
        JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref
        WHERE ut.user_ref = $1 AND ut.is_deleted = false
          AND rt.is_deleted = false AND r.is_deleted = false
    )"#;

/// Resolves the record-level `AccessLevel` for exactly one `(user_id,
/// entity_ref, action)` key — the fix for the cross-entity leak
/// `resolve_access_level` had. Combines, via `MAX`, only:
///
/// 1. `Global`, if `user_id` holds the `"{entity_name}.{action}"` privilege
///    via a **direct** grant (`user_account_mm_privilege`) — a direct
///    grant carries no role to look up a depth from, so it gets the
///    pre-D-133 unscoped default, exactly like `resolve_access_level` used
///    to give every legacy (role-less) deployment.
/// 2. For every role `user_id` holds (direct via `user_account_mm_role`,
///    or team-mediated via `role_mm_team`/`user_account_mm_team`)
///    that **also** grants `"{entity_name}.{action}"` via
///    `role_mm_privilege`/`privilege` — that role's
///    `{action}_access_level` from `role_mm_entity_access` for this
///    exact `entity_ref`, defaulting to `Global` when the role holds the
///    privilege but has no row there yet (D-133's own zero-behavior-change
///    guarantee, carried forward).
///
/// A role's depth for an entity it does NOT grant this privilege for is
/// never consulted — this is what keeps an Employee-scoped `Global` role
/// from ever contributing to a Customer resolution. No applicable grant at
/// all (neither path matches) resolves to `None`, not `Global` — safe by
/// construction, since every real caller reaches this function only after
/// `ctx.require(entity, action)` already confirmed the privilege exists.
pub async fn resolve_entity_access_level(
    db: &DbPool,
    user_id: Uuid,
    entity_ref: Uuid,
    entity_name: &str,
    action: RecordAction,
) -> Result<AccessLevel, AppError> {
    // C-13: no-op unless a subscriber is installed (tracing's whole design,
    // same convention as `attome-metadata/src/provision/ddl.rs`'s DDL-statement
    // event) — purely so a counting test can observe how many times this
    // 3-CTE query actually runs across a batch, without `pg_stat_statements`
    // (unavailable against this repo's CI Postgres image, see that file's
    // comment). Never gated behind `cfg(test)`.
    tracing::debug!(
        %user_id,
        %entity_ref,
        entity_name,
        action = action.as_str(),
        "attome-security: resolving entity access level"
    );
    let privilege_key = format!("{entity_name}.{}", action.as_str());

    // U12-T1: the same statement answers whether the caller is confined to
    // their companies (`crate::company_walls`), so a wall costs no extra
    // round trip on the request path. `WITH RECURSIVE` covers the walk up
    // the organisation tree; `held_roles` itself does not recurse.
    let held_roles = HELD_ROLES_CTE.replacen("WITH held_roles", "WITH RECURSIVE held_roles", 1);
    let walls = crate::company_walls::confined_ctes("$5", "$6");
    let sql = format!(
        r#"
            {held_roles},
            {walls},
            role_depth AS (
                SELECT COALESCE(
                    CASE $4::text
                        WHEN 'read'   THEN ea.read_access_level
                        WHEN 'update' THEN ea.write_access_level
                        WHEN 'delete' THEN ea.delete_access_level
                    END,
                    3::smallint
                ) AS depth
                FROM held_roles hr
                JOIN role_mm_privilege rp ON rp.role_ref = hr.role_id AND rp.is_deleted = false
                JOIN privilege p ON p.id = rp.privilege_ref
                  AND p.is_active = true AND p.key = $3
                LEFT JOIN role_mm_entity_access ea
                    ON ea.role_ref = hr.role_id AND ea.entity_ref = $2 AND ea.is_deleted = false
            ),
            direct_depth AS (
                SELECT 3::smallint AS depth
                FROM user_account_mm_privilege up
                JOIN privilege p ON p.id = up.privilege_ref
                  AND p.is_active = true AND p.key = $3
                WHERE up.user_ref = $1 AND up.is_active = true
            )
            SELECT
                (SELECT MAX(depth) FROM (
                    SELECT depth FROM role_depth
                    UNION ALL
                    SELECT depth FROM direct_depth
                ) combined),
                (SELECT confined FROM wall_confined)
            "#
    );
    let (max_level, confined): (Option<i16>, Option<bool>) = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(&sql)
            .bind(user_id)
            .bind(entity_ref)
            .bind(&privilege_key)
            .bind(action.as_str())
            .bind(crate::company_walls::CROSS_COMPANY)
            .bind(crate::company_walls::MAX_DEPTH)
            .fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("entity-access-level resolution query timed out"))?
    .map_err(AppError::internal)?;

    let level = max_level
        .map(AccessLevel::from_i16)
        .unwrap_or(AccessLevel::None);
    // U12-T1: a person confined to their companies never reads, changes or
    // deletes at `Global` depth; the `BusinessUnit` filter then compares the
    // record's organisation with the companies' organisations.
    Ok(crate::company_walls::wall_level(
        level,
        confined.unwrap_or(false),
    ))
}

/// D-371 (amends D-357 ruling 2): resolves whether `user_id`'s held roles
/// (the same `held_roles` shape [`resolve_entity_access_level`] uses, direct
/// or team-mediated) grant "I own this record" visibility for one
/// `(entity_ref, action)` — `bool_or`-aggregated across every role holding
/// the entity's privilege, since one role opting in is enough (same
/// most-permissive-wins posture the ladder's `MAX` already uses, applied to
/// a boolean). Defaults to `false` on no matching row — the opposite default
/// from the ladder (an absent depth row still resolves to `Global`); silence
/// here means "no widening," matching `read_owner_visible`'s own
/// `DEFAULT FALSE`.
pub async fn resolve_owner_visible(
    db: &DbPool,
    user_id: Uuid,
    entity_ref: Uuid,
    entity_name: &str,
    action: RecordAction,
) -> Result<bool, AppError> {
    // C-13: see `resolve_entity_access_level`'s identical debug event for why
    // this exists — the counting test greps for both.
    tracing::debug!(
        %user_id,
        %entity_ref,
        entity_name,
        action = action.as_str(),
        "attome-security: resolving owner visibility"
    );
    let privilege_key = format!("{entity_name}.{}", action.as_str());

    let sql = format!(
        r#"
            {HELD_ROLES_CTE}
            SELECT bool_or(
                CASE $4::text
                    WHEN 'read'   THEN ea.read_owner_visible
                    WHEN 'update' THEN ea.write_owner_visible
                    WHEN 'delete' THEN ea.delete_owner_visible
                    ELSE false
                END
            )
            FROM held_roles hr
            JOIN role_mm_privilege rp ON rp.role_ref = hr.role_id AND rp.is_deleted = false
            JOIN privilege p ON p.id = rp.privilege_ref
              AND p.is_active = true AND p.key = $3
            LEFT JOIN role_mm_entity_access ea
                ON ea.role_ref = hr.role_id AND ea.entity_ref = $2 AND ea.is_deleted = false
            "#
    );
    let owner_visible: Option<bool> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(&sql)
            .bind(user_id)
            .bind(entity_ref)
            .bind(&privilege_key)
            .bind(action.as_str())
            .fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("owner-visibility resolution query timed out"))?
    .map_err(AppError::internal)?;

    Ok(owner_visible.unwrap_or(false))
}

/// D-369: resolves every privilege key `user_id`'s held roles (direct via
/// `user_account_mm_role`, or team-mediated via
/// `role_mm_team`/`user_account_mm_team` — the same
/// `held_roles` shape [`resolve_entity_access_level`] already uses) carry a
/// *conditional* grant for, into [`SecurityContext::condition_grants`]'s
/// shape. Whole-context, not per-`(entity, action)` — resolved once
/// alongside `privileges`/`field_grants`, consulted per request by privilege
/// key.
///
/// A privilege key is present in the result only when **no** role holding it
/// grants it unconditionally: the same most-permissive-role-wins posture
/// `resolve_entity_access_level`'s `MAX`-across-roles rule already applies to
/// the access-level ladder, applied here to "does any held role's grant
/// carry zero condition rows" instead of a numeric depth.
pub async fn resolve_condition_grants(
    db: &DbPool,
    user_id: Uuid,
) -> Result<HashMap<String, Vec<Vec<GrantCondition>>>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        privilege_key: String,
        role_privilege_ref: Uuid,
        field_logicalname: Option<String>,
        operator: Option<i16>,
        value: Option<serde_json::Value>,
    }

    let sql = format!(
        r#"
            {HELD_ROLES_CTE}
            SELECT p.key AS privilege_key, rp.id AS role_privilege_ref,
                   c.field_logicalname, c.operator, c.value
            FROM held_roles hr
            JOIN role_mm_privilege rp ON rp.role_ref = hr.role_id AND rp.is_deleted = false
            JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active = true
            LEFT JOIN role_privilege_condition c
                ON c.role_privilege_ref = rp.id AND c.is_deleted = false
            "#
    );
    let rows: Vec<Row> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(&sql).bind(user_id).fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("condition-grant resolution query timed out"))?
    .map_err(AppError::internal)?;

    // Pass 1: group by the individual (privilege_key, role_privilege_ref)
    // grant — an empty Vec means that specific grant is unconditional.
    let mut by_grant: HashMap<(String, Uuid), Vec<GrantCondition>> = HashMap::new();
    for row in rows {
        let entry = by_grant
            .entry((row.privilege_key, row.role_privilege_ref))
            .or_default();
        if let (Some(field_logicalname), Some(op), Some(value)) =
            (row.field_logicalname, row.operator, row.value)
        {
            // An out-of-range operator can't happen through the admin write
            // path (validated there), but a stray/corrupted row must not
            // panic resolution for every other grant — drop just this
            // condition, narrowing the grant rather than widening it.
            if let Some(operator) = ConditionOperator::from_i16(op) {
                entry.push(GrantCondition {
                    field_logicalname,
                    operator,
                    value,
                });
            }
        }
    }

    // Pass 2: fold per privilege_key — any unconditional grant removes the
    // key entirely (checked via a separate set so iteration order over the
    // unordered `by_grant` map can never matter).
    let mut by_key: HashMap<String, Vec<Vec<GrantCondition>>> = HashMap::new();
    let mut unconditional_keys: HashSet<String> = HashSet::new();
    for ((key, _role_privilege_ref), conditions) in by_grant {
        if conditions.is_empty() {
            unconditional_keys.insert(key);
        } else {
            by_key.entry(key).or_default().push(conditions);
        }
    }
    for key in &unconditional_keys {
        by_key.remove(key);
    }

    Ok(by_key)
}

/// Bulk variant of [`resolve_entity_access_level`] — resolves `user_id`'s
/// record-level depth for `action` across **every** entity the caller holds
/// `"{entity}.{action}"` on, in one query, keyed by `entity_info.
/// logicalname` (not `entity_ref` — the one caller this exists for,
/// [`crate::rls::polymorphic_audit_predicate`], only ever has the
/// polymorphic `entity_name` text column to join against, never the target's
/// `entity_ref`). Same two sources of truth as the single-entity function
/// (direct grant / role grant + `role_mm_entity_access` depth,
/// `MAX`-combined) — generalized by joining `entity_info` and grouping
/// by entity instead of filtering to one, not a second implementation.
///
/// Built for D-140's named follow-up (`query_exec.rs`'s polymorphic-audit
/// list path): a `audit_header`/`audit_snapshot`/`audit_detail`
/// row's *target* entity varies row-to-row, so resolving access per row via
/// [`resolve_entity_access_level`] would be a per-distinct-target-entity N+1
/// against Postgres. Entity counts are small (dozens per deployment, not
/// per-row), so resolving every entity's depth once per request and joining
/// the result in-query is the bounded alternative D-140 named.
///
/// An entity absent from the returned map means `user_id` holds no
/// `"{entity}.{action}"` privilege on it at all — callers must treat that the
/// same as [`AccessLevel::None`] plus "no privilege" (i.e. exclude the row
/// entirely unless an explicit `record_share` grants it), matching
/// `require_referenced_record_access`'s single-record behavior of failing
/// closed to `NotFound` when the entity-level `ctx.require` check fails.
///
/// Mechanically derived from `resolve_entity_access_level`'s query by joining
/// `entity_info` and grouping instead of filtering. That derivation
/// carried a `TODO(needs a live Postgres)` until 2026-08-11; it is now run
/// against a real database by `resolver.rs`'s
/// `bulk_entity_access_levels_agree_with_the_single_entity_resolver` and
/// `bulk_entity_access_levels_is_empty_for_a_user_with_no_grants`, which cover
/// the three things that TODO named:
///
/// - the `privilege.key = logicalname || '.' || action` join, pinned
///   from both sides — an entity granted only `.update` must not appear in a
///   `Read` resolve (the suffix half), and an entity whose `.read` this user
///   was never granted must not appear either (the grant half);
/// - the `GROUP BY logicalname, entity_ref` + `MAX(depth)` shape, via one
///   entity reachable through two roles at different depths resolving to the
///   more permissive one;
/// - the empty-result case, via a user with zero role and zero direct grants,
///   asserted while an ungranted entity does exist in the table — so it proves
///   the grant join filters rather than that the table was empty.
///
/// Each entity is also cross-checked against [`resolve_entity_access_level`]
/// itself, with absolute values asserted alongside, so a matching pair of
/// wrong answers still fails.
pub async fn resolve_all_entity_access_levels(
    db: &DbPool,
    user_id: Uuid,
    action: RecordAction,
) -> Result<HashMap<String, (Uuid, AccessLevel)>, AppError> {
    let suffix = format!(".{}", action.as_str());

    let sql = format!(
        r#"
            {HELD_ROLES_CTE},
            role_depth AS (
                SELECT ei.logicalname, ei.id AS entity_ref,
                       COALESCE(
                           CASE $3::text
                               WHEN 'read'   THEN ea.read_access_level
                               WHEN 'update' THEN ea.write_access_level
                               WHEN 'delete' THEN ea.delete_access_level
                           END,
                           3::smallint
                       ) AS depth
                FROM held_roles hr
                JOIN role_mm_privilege rp ON rp.role_ref = hr.role_id AND rp.is_deleted = false
                JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active = true
                JOIN entity_info ei
                    ON p.key = ei.logicalname || $2::text
                   AND (ei.is_active IS NULL OR ei.is_active = true)
                LEFT JOIN role_mm_entity_access ea
                    ON ea.role_ref = hr.role_id AND ea.entity_ref = ei.id AND ea.is_deleted = false
            ),
            direct_depth AS (
                SELECT ei.logicalname, ei.id AS entity_ref, 3::smallint AS depth
                FROM user_account_mm_privilege up
                JOIN privilege p ON p.id = up.privilege_ref AND p.is_active = true
                JOIN entity_info ei
                    ON p.key = ei.logicalname || $2::text
                   AND (ei.is_active IS NULL OR ei.is_active = true)
                WHERE up.user_ref = $1 AND up.is_active = true
            )
            SELECT logicalname, entity_ref, MAX(depth) AS depth
            FROM (
                SELECT logicalname, entity_ref, depth FROM role_depth
                UNION ALL
                SELECT logicalname, entity_ref, depth FROM direct_depth
            ) combined
            GROUP BY logicalname, entity_ref
            "#
    );
    let rows: Vec<(String, Uuid, Option<i16>)> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(&sql)
            .bind(user_id)
            .bind(&suffix)
            .bind(action.as_str())
            .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("bulk entity-access-level resolution query timed out"))?
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|(logicalname, entity_ref, depth)| {
            (
                logicalname,
                (
                    entity_ref,
                    depth
                        .map(AccessLevel::from_i16)
                        .unwrap_or(AccessLevel::None),
                ),
            )
        })
        .collect())
}

/// Resolves, in one query, the set of `entity_ref`s on which `user_id` (or
/// one of `team_ids`) holds an **allow** `entity_default_share` row
/// at or above `required_capability` — the request-scoped input
/// [`crate::rls::polymorphic_audit_predicate`] needs to stop re-evaluating
/// that same question once per candidate row.
///
/// `entity_default_share` is keyed on `(entity_ref, principal_type,
/// principal_id, capability)` and has **no `record_id` column at all**, so its
/// answer is identical for every row of a given entity. Inside a per-row
/// predicate it was therefore a correlated subquery returning a constant —
/// paid once per candidate row for nothing. Hoisting it here turns it into a
/// `boolean[]` bind array indexed by the same `pos` the access-level array
/// already uses (see `polymorphic_audit_predicate`'s SQL).
///
/// The capability range matches the in-SQL check it replaces exactly:
/// `capability BETWEEN required AND 1` — an `action` (1) share satisfies a
/// `view` (0) requirement, and `deny` (2) never satisfies either (D-133 (4),
/// see [`crate::rls::Capability`]). Principals are the user and their teams
/// only; `subordinate_user_ids` is deliberately absent, matching the
/// default-share leg of both `build_predicate` and the polymorphic predicate
/// (F138's position hierarchy expands *record* shares, never entity defaults).
///
/// Deny is **not** resolved here. Deny rows live in `record_share`
/// and are inherently per-record, so the `NOT EXISTS` deny check stays in the
/// per-row predicate where it belongs — this hoist removes one of the three
/// correlated subqueries, never the deny guard.
pub async fn resolve_default_share_entities(
    db: &DbPool,
    user_id: Uuid,
    team_ids: &[Uuid],
    required_capability: i16,
) -> Result<HashSet<Uuid>, AppError> {
    let rows: Vec<(Uuid,)> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_as(
            r#"
            SELECT DISTINCT d.entity_ref
            FROM entity_default_share d
            WHERE d.capability BETWEEN $3::smallint AND 1
              AND (
                    (d.principal_type = 0 AND d.principal_id = $1::uuid)
                 OR (d.principal_type = 1 AND d.principal_id = ANY($2::uuid[]))
              )
            "#,
        )
        .bind(user_id)
        .bind(team_ids)
        .bind(required_capability)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("default-share resolution query timed out"))?
    .map_err(AppError::internal)?;

    Ok(rows.into_iter().map(|(entity_ref,)| entity_ref).collect())
}

/// True iff any role `user_id` holds (direct or team-mediated) has an
/// entity-access row anywhere at `BusinessUnit` depth on any of the three
/// scoped actions — a cheap existence check gating whether
/// `resolve_accessible_org_ids`'s recursive-CTE walk is worth paying for at
/// all this resolve cycle. Mirrors the "don't pay for a tier this caller
/// doesn't use" discipline `resolve_record_level_context` already applies;
/// unlike the old single-scalar `access_level`, depth is now per-entity, so
/// this can only ever be a conservative "might need it somewhere" existence
/// check, not a precise per-entity gate — a caller for whom this is true but
/// whose actual request never touches a `BusinessUnit`-scoped entity simply
/// paid for `accessible_org_ids` it won't end up using this cycle, same cost
/// class as any other cache-refresh-time speculation.
pub async fn any_role_uses_business_unit_scope(
    db: &DbPool,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let sql = format!(
        r#"
            {HELD_ROLES_CTE}
            SELECT EXISTS(
                SELECT 1 FROM role_mm_entity_access ea
                JOIN held_roles hr ON hr.role_id = ea.role_ref
                WHERE ea.is_deleted = false
                  AND 2 IN (ea.read_access_level, ea.write_access_level, ea.delete_access_level)
            )
            "#
    );
    let found: Option<bool> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(&sql).bind(user_id).fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("business-unit-scope existence check timed out"))?
    .map_err(AppError::internal)?;

    Ok(found.unwrap_or(false))
}

/// Every `team.id` `user_id` is a member of, via
/// `user_account_mm_team`. Consulted by `rls_predicate`'s `Team` tier and
/// by explicit share rows targeting a team.
pub async fn resolve_team_ids(db: &DbPool, user_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            "SELECT team_ref FROM user_account_mm_team \
             WHERE user_ref = $1 AND is_deleted = false",
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("team-membership resolution query timed out"))?
    .map_err(AppError::internal)
}

/// D-789 §4.3: every live `role.id` `user_id` holds — directly
/// (`user_account_mm_role`) or through a team (`role_mm_team`
/// joined through `user_account_mm_team`), the same two paths
/// [`resolve_privileges`] walks — sorted and de-duplicated. The audience of
/// role-scoped business rules (`SecurityContext::role_ids`).
pub async fn resolve_role_ids(db: &DbPool, user_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            r#"
            SELECT r.id
            FROM role r
            JOIN user_account_mm_role ur ON ur.role_ref = r.id
            WHERE ur.user_ref = $1 AND ur.is_deleted = false AND r.is_deleted = false

            UNION

            SELECT r.id
            FROM role r
            JOIN role_mm_team rt ON rt.role_ref = r.id
            JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref
            WHERE ut.user_ref = $1 AND ut.is_deleted = false
              AND rt.is_deleted = false AND r.is_deleted = false

            ORDER BY 1
            "#,
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("role-membership resolution query timed out"))?
    .map_err(AppError::internal)
}

/// Every `organization.id` reachable for `BusinessUnit`-tier scoping:
/// the caller's own org(s), plus every descendant of each via
/// `organization.organization_ref`'s self-reference (D-133 §4's
/// recursive-CTE design) — "my org(s) plus every sub-org," matching the
/// manager-sees-subordinates requirement. Only worth calling when the
/// caller's resolved `access_level` is `BusinessUnit` or lower doesn't need
/// it (`Global` skips filtering entirely; `None`/`Team` never consult this
/// set) — callers should gate on that before paying this query.
///
/// The recursive walk is seeded from **two** sources, not one:
///
///   1. explicit multi-org membership (`user_account_mm_organization`),
///      D-133 §4's original and only seed; and
///   2. the caller's *home org* — the single-valued
///      `user_account.organization_ref` that D-133 kept "unchanged as
///      the user's primary/home org" for audit stamping and notification
///      targeting.
///
/// Adding (2) is what makes the BusinessUnit tier work out of the box. With
/// only (1), a deployment whose admin set a role to `BusinessUnit` depth
/// without *also* hand-inserting membership rows resolved an empty org set,
/// and `organization_ref = ANY('{}')` matched nothing — the caller saw zero
/// records, which reads as a permissions bug rather than as the deliberate
/// fail-closed it technically was. Every user has a home org since migration
/// `0102_default_root_organization.sql` backfilled one, so BusinessUnit depth
/// now means "my business unit and everything under it" from the first boot,
/// and an admin narrows from there by creating sub-orgs.
///
/// This widens BusinessUnit-tier reach relative to pre-`0102` behavior. It
/// cannot widen `Global` (unfiltered already), `Team`, or `None` — those tiers
/// never consult this set at all — and it grants nothing to a caller holding
/// no `BusinessUnit`-depth role, since `rls_predicate` only emits the org
/// comparison at that exact depth.
pub async fn resolve_accessible_org_ids(db: &DbPool, user_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            // One non-recursive term (the UNION of both seeds, collapsed into
            // an IN-subquery) and one recursive term, rather than three
            // top-level UNION branches — PostgreSQL's WITH RECURSIVE grammar
            // is specified as `non_recursive_term UNION recursive_term`, so
            // keeping the seeds inside a subquery leaves no ambiguity about
            // where that split falls.
            r#"
            WITH RECURSIVE org_tree AS (
                SELECT o.id
                FROM organization o
                WHERE o.id IN (
                    SELECT m.organization_ref
                    FROM user_account_mm_organization m
                    WHERE m.user_ref = $1 AND m.is_deleted = false

                    UNION

                    SELECT u.organization_ref
                    FROM user_account u
                    WHERE u.id = $1 AND u.organization_ref IS NOT NULL
                )

                UNION

                SELECT o.id
                FROM organization o
                JOIN org_tree t ON o.organization_ref = t.id
            )
            SELECT id FROM org_tree
            "#,
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("accessible-org resolution query timed out"))?
    .map_err(AppError::internal)
}

// ── F138: position hierarchy resolution ────────────────────────────────

/// The most permissive `role.position_hierarchy_enabled` across every
/// role `user_id` holds — direct or team-mediated, same two-path UNION shape
/// `resolve_access_level` already uses, `bool_or` instead of `MAX`. A caller
/// holding zero roles (or every held role has this flag false) resolves to
/// `false` — there is no "flag absent means enabled" case to mirror
/// `resolve_access_level`'s NULL->Global special case, since a disabled flag
/// is already the safe, zero-behavior-change default (unlike `access_level`,
/// where NULL had to map to the *permissive* end for backward compatibility).
pub async fn resolve_position_hierarchy_enabled(
    db: &DbPool,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let sql = format!(
        r#"
            {HELD_ROLES_CTE}
            SELECT bool_or(r.position_hierarchy_enabled)
            FROM held_roles hr
            JOIN role r ON r.id = hr.role_id
            "#
    );
    let enabled: Option<bool> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(&sql).bind(user_id).fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("position-hierarchy-flag resolution query timed out"))?
    .map_err(AppError::internal)?;

    Ok(enabled.unwrap_or(false))
}

/// Every `user_account.id` in `user_id`'s position subtree: every user
/// assigned to a position that descends from a position `user_id` holds —
/// never `user_id`'s own position's other members (peers), only strict
/// descendants, matching hierarchy security's "never sideways" rule.
///
/// Bounded to 100 levels and guarded against a cycle in `parent_position_ref`
/// via the accumulated `path` array — the same defensive posture F019's
/// hierarchical self-reference entities use for their own recursive walk,
/// applied here too since `position` is a fresh admin-editable tree
/// (unlike `organization`'s equivalent walk in
/// `resolve_accessible_org_ids`, which has no admin-facing mutation endpoint
/// in this codebase and so has never needed one). A cycle should already be
/// impossible by construction — `assign_position_parent` rejects one at
/// write time — this is defense in depth, not the primary guard.
pub async fn resolve_subordinate_user_ids(
    db: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            r#"
            WITH RECURSIVE held_positions AS (
                SELECT position_ref
                FROM user_account_mm_position
                WHERE user_ref = $1 AND is_deleted = false
            ),
            descendants AS (
                SELECT p.id, 1 AS depth, ARRAY[p.id] AS path
                FROM position p
                WHERE p.parent_position_ref IN (SELECT position_ref FROM held_positions)
                  AND p.is_deleted = false

                UNION ALL

                SELECT p.id, d.depth + 1, d.path || p.id
                FROM position p
                JOIN descendants d ON p.parent_position_ref = d.id
                WHERE p.is_deleted = false
                  AND d.depth < 100
                  AND NOT p.id = ANY(d.path)
            )
            SELECT DISTINCT m.user_ref
            FROM user_account_mm_position m
            JOIN descendants d ON m.position_ref = d.id
            WHERE m.is_deleted = false
            "#,
        )
        .bind(user_id)
        .fetch_all(db),
    )
    .await
    .map_err(|_| AppError::internal("position-subordinate resolution query timed out"))?
    .map_err(AppError::internal)
}

/// Walks up from `proposed_parent_id` via `parent_position_ref` and returns
/// `true` if `position_id` appears in that ancestor chain — meaning setting
/// `position_id`'s parent to `proposed_parent_id` would create a cycle.
/// Called by the admin reparent endpoint before writing, bounded to 100
/// levels (same bound `resolve_subordinate_user_ids` uses) so a pre-existing
/// data anomaly can't turn this check itself into a runaway query.
pub async fn would_create_position_cycle(
    db: &DbPool,
    position_id: Uuid,
    proposed_parent_id: Uuid,
) -> Result<bool, AppError> {
    if position_id == proposed_parent_id {
        return Ok(true);
    }

    let found: Option<bool> = tokio::time::timeout(
        QUERY_TIMEOUT,
        sqlx::query_scalar(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_position_ref, 1 AS depth, ARRAY[id] AS path
                FROM position
                WHERE id = $2 AND is_deleted = false

                UNION ALL

                SELECT p.id, p.parent_position_ref, a.depth + 1, a.path || p.id
                FROM position p
                JOIN ancestors a ON p.id = a.parent_position_ref
                WHERE p.is_deleted = false
                  AND a.depth < 100
                  AND NOT p.id = ANY(a.path)
            )
            SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $1)
            "#,
        )
        .bind(position_id)
        .bind(proposed_parent_id)
        .fetch_one(db),
    )
    .await
    .map_err(|_| AppError::internal("position-cycle-check query timed out"))?
    .map_err(AppError::internal)?;

    Ok(found.unwrap_or(false))
}

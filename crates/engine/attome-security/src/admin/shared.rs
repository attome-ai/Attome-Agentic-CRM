//! Helpers used by more than one admin submodule — everything else lives
//! next to the single submodule that owns it.

use attome_core::changeset::{Layer, Op, RecordedOp};
use attome_server::security::SecurityResolverHandle;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A privilege-grant row: (grant id, subject ref [user or role], subject label,
/// privilege key, privilege name, granted-on). Shared by `grants::list_grants`
/// (subject = user) and `role_grants::list_role_grants` (subject = role,
/// D-111) — both query shapes match.
pub(super) type GrantRow = (
    Uuid,
    Uuid,
    Option<String>,
    String,
    String,
    Option<DateTime<Utc>>,
);

/// P-authz-revocation-epoch (D-116) goal (b): the concurrent, acknowledged
/// counterpart to looping a best-effort `invalidate(user_id).await` over a
/// role/profile's membership — every member's epoch bump + L1/L2 purge must
/// succeed before the handler returns 200 (a failed bump/purge is a 500,
/// never a silent partial success), and members are invalidated concurrently
/// rather than one sequential round-trip per member (guidelines §10/§14.4) —
/// bounded to `reconcile::AUTHZ_INVALIDATION_MAX_IN_FLIGHT` in flight at
/// once (PLATFORM-REVIEW-2026-08-24 §3.7). One implementation, shared with
/// the reconcile helpers: see [`crate::reconcile::invalidate_all`].
pub(super) async fn invalidate_sync_all(
    security: &SecurityResolverHandle,
    user_ids: Vec<Uuid>,
) -> Result<(), AppError> {
    crate::reconcile::invalidate_all(security, user_ids).await
}

/// Resolves an entity logicalname to `entity_info.id` — the FK
/// `record_share.entity_ref`/`entity_default_share.entity_ref`/
/// `role_mm_entity_access.entity_ref` require (D-133: real FK, matching
/// `attribute_info.lookup_entity_ref`'s convention, never a bare stored
/// logicalname). Shared by `shares` (record/entity-default shares) and
/// `role_entity_access` (role × entity access-level grants) — both resolve
/// the same entity-ref FK.
pub(super) async fn resolve_entity_ref(
    db: &attome_db::DbPool,
    logicalname: &str,
) -> Result<Uuid, AppError> {
    let entity_ref: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
            .bind(logicalname)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    entity_ref.ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{logicalname}'"
        ))
    })
}

/// Same lookup as [`resolve_entity_ref`], but also hands back the DB's own
/// stored `logicalname` rather than the caller's raw request string. Use this
/// (not `resolve_entity_ref`) at any call site that goes on to splice the
/// entity name into dynamic SQL (e.g. `quote_ident` on a physical table name)
/// — the same "fetch by logicalname, then use the *returned*, DB-trusted
/// value, never the request string" discipline
/// `entity_crud::resolve`'s doc comment states for the generic CRUD path.
/// Today the two strings are always byte-identical (the lookup below is an
/// exact match), but resolving through the DB's own copy is what makes that
/// true by construction rather than by the caller re-deriving the same
/// invariant at every dynamic-SQL site.
pub(super) async fn resolve_entity_ref_and_name(
    db: &attome_db::DbPool,
    logicalname: &str,
) -> Result<(Uuid, String), AppError> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, logicalname FROM entity_info WHERE logicalname = $1")
            .bind(logicalname)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    row.ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{logicalname}'"
        ))
    })
}

/// A unique-key violation (SQLSTATE 23505) on an admin create/rename is a
/// client-actionable 409 (the name is taken by a live row), never a masked
/// 500 — same classification `attome_server::entity_mutation::classify_db_error`
/// gives the generic CRUD path.
pub(super) fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("an active object with this name already exists")
    } else {
        AppError::internal(error)
    }
}

/// P-environment-promotion §5 step 5: an admin write that touches a role's
/// grants, conditions, entity access or profile links marks the *role* row
/// `is_customized` (those child tables carry no marker of their own), so a
/// boot seed leaves the whole role alone and a promotion bundle carries the
/// flag. Runs on the pool after the child write — a marker that lags a
/// crashed request by one write is the documented, harmless direction (the
/// seed skips one row too few, never one too many, on the next write).
pub(super) async fn mark_role_customized<'c, E>(db: E, role_id: Uuid) -> Result<(), AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    sqlx::query(
        "UPDATE role SET is_customized = true, updated_at = NOW() \
         WHERE id = $1 AND is_customized = false",
    )
    .bind(role_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Same as [`mark_role_customized`], for a field-security profile whose
/// member rows were written by an admin.
pub(super) async fn mark_profile_customized<'c, E>(db: E, profile_id: Uuid) -> Result<(), AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    sqlx::query(
        "UPDATE field_security_profile SET is_customized = true, updated_at = NOW() \
         WHERE id = $1 AND is_customized = false",
    )
    .bind(profile_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Opens the audited transaction an admin mutation of an `Access`-category
/// security table runs in (audit plan 3.3, D-541 rule 7): the mutation and
/// its mandatory event commit together, and the event cannot be omitted.
pub(super) async fn access_tx<'a>(
    state: &'a attome_core::EngineState,
    operation: attome_audit::AuditOperation,
    actor_user_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
) -> Result<attome_audit::security::SecurityTx<'a>, AppError> {
    attome_audit::security::SecurityTx::begin(
        state,
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Access,
            operation,
            actor_user_id,
            entity_name,
            record_id,
        ),
    )
    .await
}

// ── Solution 7 Phase 1 (D-785): changeset recording helpers ────────────────
//
// Every recorded security write follows one shape (design §1, §4.2):
// `recording.preflight` before the transaction; inside it, the live row's
// `owner_layer` checked with `recording.check_owner` before an update, retire
// or removal (a new row is stamped with `recording.stamp()`); then the
// operation — a logical-key target and a post-write snapshot — recorded as
// the last statement before commit.

/// A stored `owner_layer`, parsed. The column's CHECK admits only the four
/// layers, so an unknown value is a defect, not client input.
pub(super) fn parse_owner_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?}")))
}

/// Builds the operation a security write records.
pub(super) fn security_op(
    op: Op,
    object_kind: &'static str,
    object_ref: Uuid,
    target: serde_json::Value,
    snapshot: serde_json::Value,
) -> RecordedOp {
    RecordedOp {
        op,
        object_kind,
        object_ref: Some(object_ref),
        target,
        snapshot,
        changed: Vec::new(),
    }
}

/// The post-write snapshot of one row: `select` is a code-literal `SELECT`
/// of enumerated columns filtered by `$1` (never request text), wrapped in
/// `to_jsonb`. Runs in the write's transaction, so it sees the write.
pub(super) async fn snapshot_row(
    conn: &mut sqlx::PgConnection,
    select: &'static str,
    id: Uuid,
) -> Result<serde_json::Value, AppError> {
    let sql = format!("SELECT to_jsonb(t) FROM ({select}) t");
    sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_one(conn)
        .await
        .map_err(AppError::internal)
}

/// `role`'s snapshot columns.
pub(super) const ROLE_SNAPSHOT: &str = "SELECT id, name, description, access_level, \
     position_hierarchy_enabled, ip_allowlist, bulk_field_mode, is_customized, is_deleted, \
     row_version, owner_layer FROM role WHERE id = $1";

/// A live role's `(name, owner_layer)`, row-locked for the write that
/// follows; `None` when there is no live role.
pub(super) async fn lock_live_role(
    conn: &mut sqlx::PgConnection,
    role_id: Uuid,
) -> Result<Option<(String, Layer)>, AppError> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT name, owner_layer FROM role \
         WHERE id = $1 AND is_deleted = false FOR UPDATE",
    )
    .bind(role_id)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)?;
    row.map(|(name, layer)| Ok((name, parse_owner_layer(&layer)?)))
        .transpose()
}

/// The logical key of a grant condition (design §3 `add_role_grant_condition`
/// target `condition`): a condition row has no name, so its identity is its
/// content — `"<field>|<operator code>|<canonical JSON value>"`. Two live
/// conditions with the same content on one grant are the same condition.
pub(super) fn condition_key(field: &str, operator: i16, value: &serde_json::Value) -> String {
    format!("{field}|{operator}|{value}")
}

/// The logical key of an entity default share (design §3
/// `set_entity_default_share` target `share`). `entity_default_share`
/// is unique on `(entity_ref, principal_type, principal_id, capability)`; the
/// principal's UUID is replaced by the natural key the create route accepts
/// for it (a team's name, a user's email, lower-cased) so the key names no
/// UUID: `"team:<name>:<capability>"` / `"user:<email>:<capability>"`.
pub(super) fn default_share_key(principal_type: i16, principal: &str, capability: &str) -> String {
    let kind = if principal_type == 0 { "user" } else { "team" };
    format!("{kind}:{principal}:{capability}")
}

/// The natural key of a share principal: a user's lower-cased email or a
/// team's name. Soft-deleted teams still resolve (the share row outlives
/// them); a principal with no row is an internal error (FK-less column, but
/// never written without a resolved principal).
pub(super) async fn principal_natural_key(
    conn: &mut sqlx::PgConnection,
    principal_type: i16,
    principal_id: Uuid,
) -> Result<String, AppError> {
    let sql = if principal_type == 0 {
        "SELECT lower(email) FROM user_account WHERE id = $1"
    } else {
        "SELECT name FROM team WHERE id = $1"
    };
    let key: Option<Option<String>> = sqlx::query_scalar(sql)
        .bind(principal_id)
        .fetch_optional(conn)
        .await
        .map_err(AppError::internal)?;
    key.flatten()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| AppError::internal("share principal has no natural key"))
}

#[cfg(test)]
mod changeset_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn condition_and_share_keys_are_logical_and_pass_the_recorder_check() {
        let condition = condition_key("statuscode", 0, &json!("open"));
        assert_eq!(condition, "statuscode|0|\"open\"");
        let op = security_op(
            Op::AddRoleGrantCondition,
            "role_grant_condition",
            Uuid::now_v7(),
            json!({ "role": "Sales", "privilege": "account.read", "condition": condition }),
            json!({ "field_logicalname": "statuscode" }),
        );
        op.check().expect("well-formed condition op");

        let share = default_share_key(1, "Sales EMEA", "read");
        assert_eq!(share, "team:Sales EMEA:read");
        assert_eq!(
            default_share_key(0, "a@b.test", "write"),
            "user:a@b.test:write"
        );
        let op = security_op(
            Op::SetEntityDefaultShare,
            "entity_default_share",
            Uuid::now_v7(),
            json!({ "entity": "account", "share": share }),
            json!({}),
        );
        op.check().expect("well-formed share op");
    }

    #[test]
    fn stored_layers_parse_and_unknown_ones_are_internal() {
        assert_eq!(parse_owner_layer("project").ok(), Some(Layer::Project));
        assert!(matches!(parse_owner_layer("x"), Err(AppError::Internal(_))));
    }
}

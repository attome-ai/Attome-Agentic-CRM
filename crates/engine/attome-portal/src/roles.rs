//! Portal roles and grants (D-574, D-575, D-576 item 4, D-579). Business
//! logic only; the `Admin` handlers are in [`crate::admin`].
//!
//! A portal role belongs to one portal. A grant gives one role actions on one
//! entity, scoped by **1 to 3 row conditions** (ANDed; an unconditioned grant
//! is refused, D-574), with a **field profile** that is default-deny (D-575).
//! A portal user holds exactly one role (D-579).
//!
//! Everything a grant says is validated here, at admin-write time, against
//! live metadata, so the request path ([`crate::context`]) only ever resolves
//! grants that were valid when written.
//!
//! Two rules from the 2026-09-23 code review (plan §9.5):
//!
//! - **G-3.** A grant that can create, update or delete needs at least one
//!   condition bound to the caller (`value_ref`). A literal such as
//!   `status ne 99` is not a boundary between customers, so a grant with only
//!   literal conditions is read-only reference data, reported as `public`.
//! - **I-8.** A readable or writable lookup needs a read grant, in the same
//!   role, on the lookup's target. The request path enforces the target's
//!   scope on every value either way; this check stops an admin configuring a
//!   lookup that could never show anything.

use std::collections::HashSet;

use attome_core::{AttrInfo, EntityMetaRegistry, FieldType};
use attome_server::security::{ConditionOperator, GrantCondition};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

pub const MAX_CONDITIONS: usize = 3;

/// Entities a portal grant may never name: staff identity and security,
/// audit, AI, S2S, notifications, integrations, and the portal's own identity
/// entities.
pub const DENIED_ENTITY_PREFIXES: &[&str] = &[
    "",
    "attome_audit",
    "ai_",
    "attome_s2s",
    "attome_notification",
    "attome_integration",
    "webportal",
];

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ConditionSpec {
    pub field: String,
    /// `eq`, `ne`, `gt`, `lt`, `gte`, `lte` or `in`.
    pub operator: String,
    /// A literal (an array for `in`). Exactly one of `value` and `value_ref`.
    #[serde(default)]
    pub value: Option<Value>,
    /// `@portal_user.id`, or `@portal_user.<lookup field>` (e.g.
    /// `@portal_user.account_ref`). Only with `eq`. Resolved per request; a
    /// null or missing value matches no row.
    ///
    /// `field` may be `id`, the record's own key, with `eq` only: that is how
    /// a role reaches the portal user's own parent record
    /// (`id = @portal_user.company_ref`).
    #[serde(default)]
    pub value_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct FieldSpec {
    pub field: String,
    #[serde(default)]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
    /// Filter and sort. Requires `can_read`.
    #[serde(default)]
    pub can_filter: bool,
    /// Required to list an `is_sensitive` field at all.
    #[serde(default)]
    pub allow_sensitive: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct GrantSpec {
    #[serde(default)]
    pub can_read: bool,
    #[serde(default)]
    pub can_create: bool,
    #[serde(default)]
    pub can_update: bool,
    #[serde(default)]
    pub can_delete: bool,
    /// 1 to 3, ANDed. Never empty.
    pub conditions: Vec<ConditionSpec>,
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleDetail {
    pub id: Uuid,
    pub webportal_id: Uuid,
    pub name: String,
}

pub fn parse_operator(op: &str) -> Option<ConditionOperator> {
    Some(match op {
        "eq" => ConditionOperator::Eq,
        "ne" => ConditionOperator::Ne,
        "gt" => ConditionOperator::Gt,
        "lt" => ConditionOperator::Lt,
        "gte" => ConditionOperator::Gte,
        "lte" => ConditionOperator::Lte,
        "in" => ConditionOperator::In,
        _ => return None,
    })
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::Validation(msg.into())
}

/// The lookup fields of `webportal_user` a `value_ref` may name.
fn portal_user_lookups(registry: &EntityMetaRegistry) -> HashSet<String> {
    registry
        .get("webportal_user")
        .map(|meta| {
            meta.attrs
                .iter()
                .filter(|a| FieldType::from_int(a.field_type_int) == Some(FieldType::Lookup))
                .map(|a| a.logicalname.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Validates a `value_ref`. `Ok` for `@portal_user.id` and for
/// `@portal_user.<f>` where `f` is a lookup on `webportal_user`.
pub fn validate_value_ref(registry: &EntityMetaRegistry, value_ref: &str) -> Result<(), AppError> {
    match value_ref.strip_prefix("@portal_user.") {
        Some("id") => Ok(()),
        Some(field) if portal_user_lookups(registry).contains(field) => Ok(()),
        _ => Err(invalid(format!(
            "value_ref '{value_ref}' must be @portal_user.id or @portal_user.<a lookup field of webportal_user>"
        ))),
    }
}

fn entity_allowed(logicalname: &str) -> bool {
    !DENIED_ENTITY_PREFIXES
        .iter()
        .any(|prefix| logicalname.starts_with(prefix))
}

/// Whether a lookup pointing at `target` may be shown to a portal. A lookup to
/// `webportal_user` (an opaque portal user id, e.g. the portal user field)
/// may; a lookup into staff identity, security, audit or the other denied
/// entities may not (D-575 item 4: no staff id ever reaches a portal).
pub fn lookup_target_allowed(target: &str) -> bool {
    target == "webportal_user" || entity_allowed(target)
}

/// True when no condition is bound to the caller: every portal user of the
/// role sees the same rows. Only a read-only grant may be public (G-3).
pub fn is_public(spec: &GrantSpec) -> bool {
    !spec.conditions.iter().any(|c| c.value_ref.is_some())
}

/// Validates a grant against live metadata. `portal_user_field` is the
/// portal's configured stamp field for this entity, if any.
pub fn validate_grant(
    registry: &EntityMetaRegistry,
    engine_owned: &HashSet<String>,
    entity: &str,
    spec: &GrantSpec,
    portal_user_field: Option<&str>,
) -> Result<(), AppError> {
    if !entity_allowed(entity) || engine_owned.contains(entity) {
        return Err(invalid(format!(
            "'{entity}' cannot be exposed to a web portal"
        )));
    }
    let meta = registry
        .get(entity)
        .ok_or_else(|| invalid(format!("'{entity}' is not a registered entity")))?;
    if meta.is_append_only {
        return Err(invalid(format!("'{entity}' is append-only")));
    }
    let attrs: &[AttrInfo] = &meta.attrs;

    if spec.conditions.is_empty() {
        return Err(invalid(
            "a portal grant needs at least one row condition; an unconditioned grant would expose every record",
        ));
    }
    if spec.conditions.len() > MAX_CONDITIONS {
        return Err(invalid(format!(
            "a portal grant has at most {MAX_CONDITIONS} row conditions"
        )));
    }
    if (spec.can_create || spec.can_update || spec.can_delete) && is_public(spec) {
        return Err(invalid(
            "a grant that can create, update or delete needs a condition bound to the portal user \
             (value_ref); a grant with only literal conditions is read-only reference data",
        ));
    }
    for c in &spec.conditions {
        let op = parse_operator(&c.operator)
            .ok_or_else(|| invalid(format!("unknown operator '{}'", c.operator)))?;
        if c.field == "id" {
            if op != ConditionOperator::Eq {
                return Err(invalid("a condition on `id` must use `eq`"));
            }
            match (&c.value, &c.value_ref) {
                (Some(v), None) if v.as_str().and_then(|s| s.parse::<Uuid>().ok()).is_some() => {}
                (None, Some(r)) => validate_value_ref(registry, r)?,
                _ => {
                    return Err(invalid(
                        "a condition on `id` needs a UUID `value` or a `value_ref`",
                    ));
                }
            }
            continue;
        }
        let probe_value = match (&c.value, &c.value_ref) {
            (Some(v), None) => v.clone(),
            (None, Some(r)) => {
                validate_value_ref(registry, r)?;
                if op != ConditionOperator::Eq {
                    return Err(invalid("a value_ref condition must use `eq`"));
                }
                // A syntactically valid stand-in, so the render check below
                // proves the field and operator combination.
                Value::String(Uuid::nil().to_string())
            }
            _ => return Err(invalid("give exactly one of `value` and `value_ref`")),
        };
        let probe = GrantCondition {
            field_logicalname: c.field.clone(),
            operator: op,
            value: probe_value,
        };
        if c.value_ref.is_some() {
            // Only the field's eligibility matters for a reference.
            attome_security::conditions::eligible_condition_field(attrs, &c.field)
                .map_err(|e| invalid(format!("condition on '{}': {e}", c.field)))?;
        } else {
            attome_security::conditions::render_condition(&probe, attrs, "t", 1)
                .map_err(|e| invalid(format!("condition on '{}': {e}", c.field)))?;
        }
    }

    let mut seen = HashSet::new();
    for f in &spec.fields {
        if !seen.insert(f.field.as_str()) {
            return Err(invalid(format!("'{}' is listed twice", f.field)));
        }
        let attr = attrs
            .iter()
            .find(|a| a.logicalname == f.field)
            .ok_or_else(|| invalid(format!("'{}' is not a field of '{entity}'", f.field)))?;
        if attr.is_sensitive && !f.allow_sensitive {
            return Err(invalid(format!(
                "'{}' is sensitive; set allow_sensitive to expose it to a portal",
                f.field
            )));
        }
        let field_type = FieldType::from_int(attr.field_type_int);
        // A portal downloads (read) and uploads (write, D-774) a file field's
        // files, but never filters or sorts on one.
        if attr.is_file_backed() && f.can_filter {
            return Err(invalid(format!(
                "'{}' is a file field; portals can't filter or sort on it",
                f.field
            )));
        }
        if field_type == Some(FieldType::Lookup)
            && let Some(target) = attr.lookup_entity_ref.and_then(|id| registry.get_by_id(id))
        {
            if !lookup_target_allowed(&target.logicalname) {
                return Err(invalid(format!(
                    "'{}' points at '{}', which a portal may never see",
                    f.field, target.logicalname
                )));
            }
            // Only the engine sets a portal user reference (the stamp).
            if target.logicalname == "webportal_user" && f.can_write {
                return Err(invalid(format!(
                    "'{}' points at a portal user and cannot be writable",
                    f.field
                )));
            }
        }
        if f.can_filter {
            if !f.can_read {
                return Err(invalid(format!(
                    "'{}': filtering on a field that cannot be read leaks its value",
                    f.field
                )));
            }
            attome_security::conditions::eligible_condition_field(attrs, &f.field)
                .map_err(|e| invalid(format!("'{}' cannot be filtered: {e}", f.field)))?;
        }
        if f.can_write && portal_user_field == Some(f.field.as_str()) {
            return Err(invalid(format!(
                "'{}' records the portal user and is set by the engine; it cannot be writable",
                f.field
            )));
        }
    }
    Ok(())
}

async fn lock(conn: &mut PgConnection, key: String) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another request is changing this portal role; retry",
        ))
    }
}

/// A portal that has users (roles are meaningless on an anonymous one).
async fn ensure_portal_with_users(
    conn: &mut PgConnection,
    portal_id: Uuid,
) -> Result<(), AppError> {
    let portal = crate::provision::load_portal(conn, portal_id).await?;
    if !portal.portal_type.has_users() {
        return Err(invalid("an anonymous web portal has no users or roles"));
    }
    Ok(())
}

async fn ensure_role_in_portal(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_role WHERE id = $1 AND webportal_id = $2)",
    )
    .bind(role_id)
    .bind(portal_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

pub async fn create_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    name: &str,
) -> Result<RoleDetail, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(invalid("name is required (at most 200 characters)"));
    }
    ensure_portal_with_users(conn, portal_id).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO webportal_role (webportal_id, name) VALUES ($1, $2) \
         ON CONFLICT (webportal_id, name) DO NOTHING RETURNING id",
    )
    .bind(portal_id)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let id = id.ok_or(AppError::Conflict(
        "this portal already has a role with this name",
    ))?;
    Ok(RoleDetail {
        id,
        webportal_id: portal_id,
        name: name.to_owned(),
    })
}

async fn portal_user_field(
    conn: &mut PgConnection,
    portal_id: Uuid,
    entity: &str,
) -> Result<Option<String>, AppError> {
    let field: Option<Option<String>> = sqlx::query_scalar(
        "SELECT portal_user_field FROM webportal_entity \
         WHERE webportal_id = $1 AND entity_logicalname = $2",
    )
    .bind(portal_id)
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(field.flatten())
}

/// Replaces the role's grant on `entity` (validated first).
pub async fn put_grant(
    conn: &mut PgConnection,
    registry: &EntityMetaRegistry,
    engine_owned: &HashSet<String>,
    portal_id: Uuid,
    role_id: Uuid,
    entity: &str,
    spec: &GrantSpec,
) -> Result<(), AppError> {
    ensure_role_in_portal(conn, portal_id, role_id).await?;
    lock(conn, format!("attome-portal/role:{role_id}")).await?;
    let stamp_field = portal_user_field(conn, portal_id, entity).await?;
    validate_grant(registry, engine_owned, entity, spec, stamp_field.as_deref())?;
    require_lookup_target_grants(conn, registry, role_id, entity, spec).await?;

    sqlx::query("DELETE FROM webportal_grant WHERE role_id = $1 AND entity_logicalname = $2")
        .bind(role_id)
        .bind(entity)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let grant_id: Uuid = sqlx::query_scalar(
        "INSERT INTO webportal_grant \
           (role_id, entity_logicalname, can_read, can_create, can_update, can_delete) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(role_id)
    .bind(entity)
    .bind(spec.can_read)
    .bind(spec.can_create)
    .bind(spec.can_update)
    .bind(spec.can_delete)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for (ordinal, c) in spec.conditions.iter().enumerate() {
        let op = parse_operator(&c.operator).ok_or_else(|| invalid("unknown operator"))?;
        sqlx::query(
            "INSERT INTO webportal_grant_condition \
               (grant_id, ordinal, field_logicalname, operator, value, value_ref) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(grant_id)
        .bind(i16::try_from(ordinal).map_err(AppError::internal)?)
        .bind(&c.field)
        .bind(op as i16)
        .bind(&c.value)
        .bind(&c.value_ref)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    for f in &spec.fields {
        sqlx::query(
            "INSERT INTO webportal_grant_field \
               (grant_id, field_logicalname, can_read, can_write, can_filter, allow_sensitive) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(grant_id)
        .bind(&f.field)
        .bind(f.can_read)
        .bind(f.can_write)
        .bind(f.can_filter)
        .bind(f.allow_sensitive)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// I-8 at write time: every readable or writable lookup (other than one to
/// the portal user) needs a read grant on its target in the same role.
async fn require_lookup_target_grants(
    conn: &mut PgConnection,
    registry: &EntityMetaRegistry,
    role_id: Uuid,
    entity: &str,
    spec: &GrantSpec,
) -> Result<(), AppError> {
    let Some(meta) = registry.get(entity) else {
        return Ok(());
    };
    for f in spec.fields.iter().filter(|f| f.can_read || f.can_write) {
        let Some(target) = meta
            .attrs
            .iter()
            .find(|a| a.logicalname == f.field)
            .filter(|a| FieldType::from_int(a.field_type_int) == Some(FieldType::Lookup))
            .and_then(|a| a.lookup_entity_ref)
            .and_then(|id| registry.get_by_id(id))
            .map(|t| t.logicalname.clone())
        else {
            continue;
        };
        if target == "webportal_user" {
            continue;
        }
        let readable = if target == entity {
            spec.can_read
        } else {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM webportal_grant \
                 WHERE role_id = $1 AND entity_logicalname = $2 AND can_read)",
            )
            .bind(role_id)
            .bind(&target)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?
        };
        if !readable {
            return Err(invalid(format!(
                "'{}' points at '{target}'; give this role a read grant on '{target}' first, \
                 or its values could never be shown or written",
                f.field
            )));
        }
    }
    Ok(())
}

pub async fn delete_grant(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
    entity: &str,
) -> Result<(), AppError> {
    ensure_role_in_portal(conn, portal_id, role_id).await?;
    lock(conn, format!("attome-portal/role:{role_id}")).await?;
    let deleted =
        sqlx::query("DELETE FROM webportal_grant WHERE role_id = $1 AND entity_logicalname = $2")
            .bind(role_id)
            .bind(entity)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Gives a portal user their one role (replacing any previous one).
pub async fn assign_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    ensure_role_in_portal(conn, portal_id, role_id).await?;
    let in_portal: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_user \
         WHERE id = $1 AND webportal_ref = $2 AND is_active IS NOT FALSE)",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if !in_portal {
        return Err(AppError::NotFound);
    }
    sqlx::query(
        "INSERT INTO webportal_user_role (webportal_user_id, role_id) VALUES ($1, $2) \
         ON CONFLICT (webportal_user_id) DO UPDATE SET role_id = EXCLUDED.role_id, assigned_at = NOW()",
    )
    .bind(user_id)
    .bind(role_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Sets the portal's configuration for `entity`: the lookup to
/// `webportal_user` that records the portal user on create. Refused if
/// any grant of this portal makes that field writable.
pub async fn put_entity_config(
    conn: &mut PgConnection,
    registry: &EntityMetaRegistry,
    portal_id: Uuid,
    entity: &str,
    portal_user_field: Option<&str>,
) -> Result<(), AppError> {
    ensure_portal_with_users(conn, portal_id).await?;
    if !entity_allowed(entity) {
        return Err(invalid(format!(
            "'{entity}' cannot be exposed to a web portal"
        )));
    }
    let meta = registry
        .get(entity)
        .ok_or_else(|| invalid(format!("'{entity}' is not a registered entity")))?;
    if let Some(field) = portal_user_field {
        let portal_user_entity = registry
            .get("webportal_user")
            .ok_or_else(|| AppError::internal("webportal_user is not registered"))?;
        let ok = meta.attrs.iter().any(|a| {
            a.logicalname == field
                && FieldType::from_int(a.field_type_int) == Some(FieldType::Lookup)
                && a.lookup_entity_ref == Some(portal_user_entity.entity_id)
        });
        if !ok {
            return Err(invalid(format!(
                "'{field}' must be a lookup on '{entity}' to webportal_user"
            )));
        }
        let writable: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM webportal_grant_field f \
             JOIN webportal_grant g ON g.id = f.grant_id \
             JOIN webportal_role r ON r.id = g.role_id \
             WHERE r.webportal_id = $1 AND g.entity_logicalname = $2 \
               AND f.field_logicalname = $3 AND f.can_write)",
        )
        .bind(portal_id)
        .bind(entity)
        .bind(field)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if writable {
            return Err(invalid(format!(
                "a grant makes '{field}' writable; remove that before using it to record the portal user"
            )));
        }
    }
    sqlx::query(
        "INSERT INTO webportal_entity (webportal_id, entity_logicalname, portal_user_field) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (webportal_id, entity_logicalname) DO UPDATE SET portal_user_field = EXCLUDED.portal_user_field",
    )
    .bind(portal_id)
    .bind(entity)
    .bind(portal_user_field)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Admin reads and role lifecycle (plan §9.5 G-8) ──────────────────────────

/// The inverse of [`parse_operator`].
pub fn operator_name(op: ConditionOperator) -> &'static str {
    match op {
        ConditionOperator::Eq => "eq",
        ConditionOperator::Ne => "ne",
        ConditionOperator::Gt => "gt",
        ConditionOperator::Lt => "lt",
        ConditionOperator::Gte => "gte",
        ConditionOperator::Lte => "lte",
        ConditionOperator::In => "in",
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleSummary {
    pub id: Uuid,
    pub name: String,
    /// Portal users holding this role.
    pub user_count: i64,
}

/// A grant as stored, with the G-3 label: `public` when no condition is bound
/// to the portal user, which only a read-only grant may be.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantView {
    pub entity: String,
    pub can_read: bool,
    pub can_create: bool,
    pub can_update: bool,
    pub can_delete: bool,
    pub public: bool,
    pub conditions: Vec<ConditionSpec>,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleView {
    pub id: Uuid,
    pub webportal_id: Uuid,
    pub name: String,
    pub user_count: i64,
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EntityConfigView {
    pub entity: String,
    pub portal_user_field: Option<String>,
}

/// Every role of a portal, by name.
pub async fn list_roles(
    conn: &mut PgConnection,
    portal_id: Uuid,
) -> Result<Vec<RoleSummary>, AppError> {
    ensure_portal_with_users(conn, portal_id).await?;
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT r.id, r.name, count(ur.webportal_user_id) \
         FROM webportal_role r \
         LEFT JOIN webportal_user_role ur ON ur.role_id = r.id \
         WHERE r.webportal_id = $1 GROUP BY r.id, r.name ORDER BY r.name",
    )
    .bind(portal_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, user_count)| RoleSummary {
            id,
            name,
            user_count,
        })
        .collect())
}

type GrantRowView = (Uuid, String, bool, bool, bool, bool);
type ConditionRowView = (String, i16, Option<Value>, Option<String>);
type FieldRowView = (String, bool, bool, bool, bool);

/// The entities `role_id` has a grant on, if the role belongs to
/// `portal_id`, by name (the portal metadata index).
pub async fn granted_entities(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT g.entity_logicalname FROM webportal_grant g \
         JOIN webportal_role r ON r.id = g.role_id AND r.webportal_id = $2 \
         WHERE g.role_id = $1 ORDER BY g.entity_logicalname",
    )
    .bind(role_id)
    .bind(portal_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// One role with every grant, condition and field row.
pub async fn get_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
) -> Result<RoleView, AppError> {
    let role: Option<(String, i64)> = sqlx::query_as(
        "SELECT r.name, \
                (SELECT count(*) FROM webportal_user_role ur WHERE ur.role_id = r.id) \
         FROM webportal_role r WHERE r.id = $1 AND r.webportal_id = $2",
    )
    .bind(role_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((name, user_count)) = role else {
        return Err(AppError::NotFound);
    };
    let grants: Vec<GrantRowView> = sqlx::query_as(
        "SELECT id, entity_logicalname, can_read, can_create, can_update, can_delete \
         FROM webportal_grant WHERE role_id = $1 ORDER BY entity_logicalname",
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let mut views = Vec::with_capacity(grants.len());
    for (grant_id, entity, can_read, can_create, can_update, can_delete) in grants {
        let condition_rows: Vec<ConditionRowView> = sqlx::query_as(
            "SELECT field_logicalname, operator, value, value_ref \
             FROM webportal_grant_condition WHERE grant_id = $1 ORDER BY ordinal",
        )
        .bind(grant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let conditions: Vec<ConditionSpec> = condition_rows
            .into_iter()
            .map(|(field, op, value, value_ref)| ConditionSpec {
                field,
                operator: ConditionOperator::from_i16(op)
                    .map_or("invalid", operator_name)
                    .to_owned(),
                value,
                value_ref,
            })
            .collect();
        let field_rows: Vec<FieldRowView> = sqlx::query_as(
            "SELECT field_logicalname, can_read, can_write, can_filter, allow_sensitive \
             FROM webportal_grant_field WHERE grant_id = $1 ORDER BY field_logicalname",
        )
        .bind(grant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let fields = field_rows
            .into_iter()
            .map(
                |(field, can_read, can_write, can_filter, allow_sensitive)| FieldSpec {
                    field,
                    can_read,
                    can_write,
                    can_filter,
                    allow_sensitive,
                },
            )
            .collect();
        let public = !conditions.iter().any(|c| c.value_ref.is_some());
        views.push(GrantView {
            entity,
            can_read,
            can_create,
            can_update,
            can_delete,
            public,
            conditions,
            fields,
        });
    }
    Ok(RoleView {
        id: role_id,
        webportal_id: portal_id,
        name,
        user_count,
        grants: views,
    })
}

/// Renames a role.
pub async fn rename_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
    name: &str,
) -> Result<(), AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(invalid("name is required (at most 200 characters)"));
    }
    ensure_role_in_portal(conn, portal_id, role_id).await?;
    lock(conn, format!("attome-portal/role:{role_id}")).await?;
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_role \
         WHERE webportal_id = $1 AND name = $2 AND id <> $3)",
    )
    .bind(portal_id)
    .bind(name)
    .bind(role_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if taken {
        return Err(AppError::Conflict(
            "this portal already has a role with this name",
        ));
    }
    sqlx::query(
        "UPDATE webportal_role SET name = $3, updated_at = NOW() \
         WHERE id = $1 AND webportal_id = $2",
    )
    .bind(role_id)
    .bind(portal_id)
    .bind(name)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Deletes a role and its grants. Refused while any user holds it or the
/// portal's signup policy hands it out, so no one loses access by accident.
pub async fn delete_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    ensure_role_in_portal(conn, portal_id, role_id).await?;
    lock(conn, format!("attome-portal/role:{role_id}")).await?;
    let (held, signup): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM webportal_user_role WHERE role_id = $1), \
                EXISTS (SELECT 1 FROM webportal_auth_policy WHERE signup_role_ref = $1)",
    )
    .bind(role_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if held {
        return Err(AppError::Conflict(
            "users still hold this role; reassign or unassign them first",
        ));
    }
    if signup {
        return Err(AppError::Conflict(
            "the portal's signup policy gives this role to new users; change it first",
        ));
    }
    sqlx::query("DELETE FROM webportal_role WHERE id = $1 AND webportal_id = $2")
        .bind(role_id)
        .bind(portal_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Takes a user's role away: they keep their account and reach no records.
pub async fn unassign_role(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let removed = sqlx::query(
        "DELETE FROM webportal_user_role ur USING webportal_role r \
         WHERE ur.webportal_user_id = $1 AND ur.role_id = r.id AND r.webportal_id = $2",
    )
    .bind(user_id)
    .bind(portal_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// The portal's per-entity configuration rows.
pub async fn list_entity_configs(
    conn: &mut PgConnection,
    portal_id: Uuid,
) -> Result<Vec<EntityConfigView>, AppError> {
    ensure_portal_with_users(conn, portal_id).await?;
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT entity_logicalname, portal_user_field FROM webportal_entity \
         WHERE webportal_id = $1 ORDER BY entity_logicalname",
    )
    .bind(portal_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(entity, portal_user_field)| EntityConfigView {
            entity,
            portal_user_field,
        })
        .collect())
}

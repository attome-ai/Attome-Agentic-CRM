//! `PortalSession → PortalContext → AccessPlan` (D-576 items 4 and 5).
//!
//! A portal request never carries a staff `SecurityContext`, and nothing in
//! this crate builds one. The session resolves to a [`PortalPrincipal`]
//! (router authn); this module turns the principal's **one** role (D-579)
//! into an engine [`AccessPlan`] for one entity:
//!
//! - actions from the grant;
//! - the row scope from the grant's conditions only, each `value_ref`
//!   resolved from the principal's own `webportal_user` row (a null or
//!   missing value becomes `MatchNothing`, never "match everything");
//! - the field profile, default-deny;
//! - for every readable or writable lookup, the principal's own read scope on
//!   the lookup's target entity (plan §9.6 I-8): no read grant there means the
//!   lookup's values are never shown and can't be written;
//! - the portal's owning team (writes only), and the entity's portal user
//!   field.
//!
//! Built in two halves (G-9, plan §4.2). The role's [`PlanTemplate`] (grant,
//! raw conditions, field profile, portal user field, each lookup target's
//! grant) depends only on portal-admin data and metadata, so
//! [`crate::cache::PortalCache`] may hold it. Everything about the user —
//! the `value_ref` sources and the label, read in one statement — is applied
//! per request and never cached.
//!
//! **Fails closed** (plan §9.6 I-10). A condition that no longer renders
//! against today's metadata (G-6), an unresolvable `value_ref`, or a lookup
//! target with no grant all match nothing; an owning team that is gone
//! refuses creation (G-15). None of them widens access, and none of them turns
//! into a 500 on every request.
//!
//! `None` when the principal has no role or the role has no grant for the
//! entity: the router answers 404, the same as for a missing record.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};

use attome_core::{AttrInfo, EntityMetaRegistry, FieldType, quote_ident};
use attome_records::access_plan::{AccessPlan, LookupScope, PlanCondition, condition_renders};
use attome_server::security::{ConditionOperator, GrantCondition};
use attome_types::AppError;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::auth::PortalPrincipal;
use crate::cache::PortalCache;
use crate::provision::PortalDetail;
use crate::roles::validate_value_ref;
use crate::telemetry;

/// `(grant id, read, create, update, delete)`.
type GrantRow = (Uuid, bool, bool, bool, bool);
type ConditionRow = (String, i16, Option<Value>, Option<String>);
type FieldRow = (String, bool, bool, bool);

/// The portal principal's own identity entity.
const PORTAL_USER_ENTITY: &str = "webportal_user";

/// One stored grant condition, not yet resolved for a user.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RawCondition {
    field: String,
    operator: i16,
    value: Option<Value>,
    value_ref: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum LookupTemplate {
    SelfOnly,
    /// The role's read grant on the target (its id and raw conditions), or
    /// `None`: no read there, so the lookup matches nothing.
    Target {
        entity: String,
        grant: Option<(Uuid, Vec<RawCondition>)>,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct GrantTemplate {
    grant_id: Uuid,
    can_read: bool,
    can_create: bool,
    can_update: bool,
    can_delete: bool,
    conditions: Vec<RawCondition>,
    readable: BTreeSet<String>,
    writable: BTreeSet<String>,
    filterable: BTreeSet<String>,
    portal_user_field: Option<String>,
    /// Readable or writable lookup field → its target's scope template.
    lookups: Vec<(String, LookupTemplate)>,
}

/// A role's grant on one entity with nothing user-specific applied: what the
/// G-9 cache holds. `grant` is `None` when the role has no grant there.
/// (De)serializable only because a `TieredCache` value must be; the portal
/// cache keeps it in process memory, and a decoded copy has no snapshot, so
/// it is never [`built_against`](Self::built_against) one.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PlanTemplate {
    /// The metadata snapshot this was checked against. A `Weak` keeps the
    /// snapshot's address from being reused while this entry lives, so a
    /// pointer comparison is an exact "same snapshot" test.
    #[serde(skip)]
    registry: Weak<EntityMetaRegistry>,
    role_id: Uuid,
    grant: Option<GrantTemplate>,
}

impl PlanTemplate {
    /// Whether this template was built against `registry` (today's snapshot).
    pub(crate) fn built_against(&self, registry: &Arc<EntityMetaRegistry>) -> bool {
        std::ptr::eq(self.registry.as_ptr(), Arc::as_ptr(registry))
    }
}

/// The role's grant on `entity`, if the role belongs to `portal_id`.
async fn load_grant(
    conn: &mut PgConnection,
    portal_id: Uuid,
    role_id: Uuid,
    entity: &str,
) -> Result<Option<GrantRow>, AppError> {
    sqlx::query_as(
        "SELECT g.id, g.can_read, g.can_create, g.can_update, g.can_delete \
         FROM webportal_grant g \
         JOIN webportal_role r ON r.id = g.role_id AND r.webportal_id = $2 \
         WHERE g.role_id = $1 AND g.entity_logicalname = $3",
    )
    .bind(role_id)
    .bind(portal_id)
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

async fn load_raw_conditions(
    conn: &mut PgConnection,
    grant_id: Uuid,
) -> Result<Vec<RawCondition>, AppError> {
    let rows: Vec<ConditionRow> = sqlx::query_as(
        "SELECT field_logicalname, operator, value, value_ref FROM webportal_grant_condition \
         WHERE grant_id = $1 ORDER BY ordinal",
    )
    .bind(grant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(field, operator, value, value_ref)| RawCondition {
            field,
            operator,
            value,
            value_ref,
        })
        .collect())
}

/// Builds the role's template for `entity` from PostgreSQL, checked against
/// `registry`.
async fn build_template(
    conn: &mut PgConnection,
    registry: &Arc<EntityMetaRegistry>,
    portal_id: Uuid,
    role_id: Uuid,
    entity: &str,
) -> Result<PlanTemplate, AppError> {
    let template = |grant| PlanTemplate {
        registry: Arc::downgrade(registry),
        role_id,
        grant,
    };
    let Some((grant_id, can_read, can_create, can_update, can_delete)) =
        load_grant(conn, portal_id, role_id, entity).await?
    else {
        return Ok(template(None));
    };
    let attrs: &[AttrInfo] = registry.get(entity).map_or(&[], |m| m.attrs.as_slice());
    let conditions = load_raw_conditions(conn, grant_id).await?;

    let field_rows: Vec<FieldRow> = sqlx::query_as(
        "SELECT field_logicalname, can_read, can_write, can_filter \
         FROM webportal_grant_field WHERE grant_id = $1",
    )
    .bind(grant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // Defence in depth against metadata drift since the grant was written: a
    // lookup into a denied entity, or a field that is gone, is dropped rather
    // than served; a field that is (now) a file is never filterable below.
    let still_ok = |name: &str| {
        attrs.iter().any(|a| {
            a.logicalname == name
                && !(FieldType::from_int(a.field_type_int) == Some(FieldType::Lookup)
                    && a.lookup_entity_ref
                        .and_then(|id| registry.get_by_id(id))
                        .is_some_and(|t| !crate::roles::lookup_target_allowed(&t.logicalname)))
        })
    };
    let (mut readable, mut writable, mut filterable) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (field, r, w, f) in field_rows {
        if !still_ok(&field) {
            continue;
        }
        // A file is never filterable or sortable to a portal, whatever a stale
        // grant says; it is downloaded (read) and uploaded (write, D-774).
        let file = attrs
            .iter()
            .any(|a| a.logicalname == field && a.is_file_backed());
        if r {
            readable.insert(field.clone());
        }
        if w {
            writable.insert(field.clone());
        }
        if f && r && !file {
            filterable.insert(field);
        }
    }

    let portal_user_field: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT portal_user_field FROM webportal_entity \
         WHERE webportal_id = $1 AND entity_logicalname = $2",
    )
    .bind(portal_id)
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .flatten();
    if let Some(field) = &portal_user_field {
        // Never client-writable, whatever a stale grant says.
        writable.remove(field);
    }

    // I-8: every lookup the plan can read or write gets the principal's own
    // scope on its target. A lookup with no configured target matches nothing
    // (it has no entry).
    let mut lookups = Vec::new();
    for attr in attrs.iter().filter(|a| {
        FieldType::from_int(a.field_type_int) == Some(FieldType::Lookup)
            && (readable.contains(&a.logicalname) || writable.contains(&a.logicalname))
    }) {
        let Some(target) = attr
            .lookup_entity_ref
            .and_then(|id| registry.get_by_id(id))
            .map(|t| t.logicalname.clone())
        else {
            continue;
        };
        let scope = if target == PORTAL_USER_ENTITY {
            LookupTemplate::SelfOnly
        } else {
            let grant = match load_grant(conn, portal_id, role_id, &target).await? {
                Some((target_grant, true, ..)) => {
                    Some((target_grant, load_raw_conditions(conn, target_grant).await?))
                }
                // No grant, or no read on it: the lookup's values stay invisible.
                _ => None,
            };
            LookupTemplate::Target {
                entity: target,
                grant,
            }
        };
        lookups.push((attr.logicalname.clone(), scope));
    }

    Ok(template(Some(GrantTemplate {
        grant_id,
        can_read,
        can_create,
        can_update,
        can_delete,
        conditions,
        readable,
        writable,
        filterable,
        portal_user_field,
        lookups,
    })))
}

/// Every `value_ref` the template's conditions (its own and its lookups')
/// name.
fn value_refs(grant: &GrantTemplate) -> BTreeSet<&str> {
    let lookup_conditions = grant.lookups.iter().filter_map(|(_, l)| match l {
        LookupTemplate::Target {
            grant: Some((_, conditions)),
            ..
        } => Some(conditions.iter()),
        _ => None,
    });
    grant
        .conditions
        .iter()
        .chain(lookup_conditions.flatten())
        .filter_map(|c| c.value_ref.as_deref())
        .collect()
}

/// What the user's own row supplies: the label and each `value_ref`'s value.
struct UserValues {
    label: String,
    /// `value_ref` → its value; a missing key or `None` resolves to nothing.
    values: HashMap<String, Option<String>>,
}

/// The portal user's label and the lookup fields the `value_ref`s name, in
/// one statement. Each `value_ref` is re-validated against today's metadata:
/// a lookup dropped since the grant was written resolves to nothing rather
/// than erroring every request.
async fn load_user_values(
    conn: &mut PgConnection,
    registry: &EntityMetaRegistry,
    user_id: Uuid,
    refs: &BTreeSet<&str>,
) -> Result<UserValues, AppError> {
    let mut values = HashMap::new();
    let mut columns: Vec<(&str, &str)> = Vec::new();
    for &value_ref in refs {
        if validate_value_ref(registry, value_ref).is_err() {
            continue;
        }
        match value_ref.trim_start_matches("@portal_user.") {
            "id" => {
                values.insert(value_ref.to_owned(), Some(user_id.to_string()));
            }
            field => columns.push((value_ref, field)),
        }
    }
    // Each `field` is a validated lookup attribute of webportal_user.
    let projection: String = columns
        .iter()
        .map(|(_, field)| format!(", {}::text", quote_ident(field)))
        .collect();
    let row = sqlx::query(&format!(
        "SELECT name, is_active IS NOT FALSE{projection} FROM {PORTAL_USER_ENTITY} WHERE id = $1"
    ))
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(UserValues {
            label: String::new(),
            values,
        });
    };
    let label: Option<String> = row.try_get(0).map_err(AppError::internal)?;
    let live: bool = row.try_get(1).map_err(AppError::internal)?;
    for (i, (value_ref, _)) in columns.iter().enumerate() {
        let value: Option<String> = row.try_get(i + 2).map_err(AppError::internal)?;
        // An inactive row resolves nothing (match nothing, never widen).
        values.insert((*value_ref).to_owned(), value.filter(|_| live));
    }
    Ok(UserValues {
        label: label.unwrap_or_default(),
        values,
    })
}

/// A grant's raw conditions, resolved for this user and re-checked against
/// today's `attrs` of `entity`.
fn render_conditions(
    raw: &[RawCondition],
    user: &UserValues,
    (grant_id, role_id): (Uuid, Uuid),
    entity: &str,
    attrs: &[AttrInfo],
) -> Vec<PlanCondition> {
    let mut conditions = Vec::with_capacity(raw.len());
    for c in raw {
        let Some(operator) = ConditionOperator::from_i16(c.operator) else {
            // Drift of the stored grant itself (an operator this build does
            // not know): match nothing, loudly.
            tracing::warn!(
                role_id = %role_id,
                grant_id = %grant_id,
                entity = %entity,
                field = %c.field,
                operator = c.operator,
                "portal grant condition has an unknown operator; it matches nothing"
            );
            telemetry::plan_match_nothing();
            conditions.push(PlanCondition::MatchNothing);
            continue;
        };
        let value = match (&c.value, &c.value_ref) {
            (Some(v), None) => Some(v.clone()),
            (None, Some(r)) => user.values.get(r).cloned().flatten().map(Value::String),
            _ => None,
        };
        let Some(value) = value else {
            conditions.push(PlanCondition::MatchNothing);
            continue;
        };
        let condition = GrantCondition {
            field_logicalname: c.field.clone(),
            operator,
            value,
        };
        if condition_renders(&condition, attrs) {
            conditions.push(PlanCondition::Match(condition));
        } else {
            // G-6: the field was dropped or changed type since the grant was
            // written. Match nothing, and tell the operator which grant.
            // The enclosing `portal_request` span carries `webportal_id`.
            tracing::warn!(
                role_id = %role_id,
                grant_id = %grant_id,
                entity = %entity,
                field = %condition.field_logicalname,
                "portal grant condition no longer renders against current metadata; it matches nothing"
            );
            telemetry::plan_match_nothing();
            conditions.push(PlanCondition::MatchNothing);
        }
    }
    conditions
}

/// The access plan for `principal` on `entity`, or `None` (no role, or no
/// grant for this entity).
///
/// `cache` and `version` come from the portal router (G-9): with both, the
/// role's template is served from the L1; with either missing, it is read from
/// PostgreSQL. `write` is true for create, update and delete: only they
/// resolve the owning team (reads never use it, and a read plan can't
/// create).
pub async fn access_plan(
    conn: &mut PgConnection,
    registry: &Arc<EntityMetaRegistry>,
    portal: &PortalDetail,
    principal: &PortalPrincipal,
    entity: &str,
    write: bool,
    cache: Option<(&PortalCache, Option<&str>)>,
) -> Result<Option<AccessPlan>, AppError> {
    let Some(role_id) = principal.role_id else {
        return Ok(None);
    };
    let build = build_template(&mut *conn, registry, portal.id, role_id, entity);
    let template = match cache {
        // An entity today's metadata doesn't know is never cached: a request
        // naming arbitrary entities can't fill the L1.
        Some((cache, version)) => {
            let version = version.filter(|_| registry.get(entity).is_some());
            cache
                .plan((portal.id, role_id, entity), version, registry, build)
                .await?
        }
        None => Arc::new(build.await?),
    };
    let Some(grant) = &template.grant else {
        return Ok(None);
    };
    let attrs: &[AttrInfo] = registry.get(entity).map_or(&[], |m| m.attrs.as_slice());

    let user = load_user_values(conn, registry, principal.user_id, &value_refs(grant)).await?;
    let conditions = render_conditions(
        &grant.conditions,
        &user,
        (grant.grant_id, template.role_id),
        entity,
        attrs,
    );
    let mut lookup_scopes = BTreeMap::new();
    for (field, lookup) in &grant.lookups {
        let scope = match lookup {
            LookupTemplate::SelfOnly => LookupScope::SelfOnly,
            LookupTemplate::Target {
                entity: target,
                grant: target_grant,
            } => LookupScope::Target {
                entity: target.clone(),
                conditions: match target_grant {
                    Some((target_grant, raw)) => render_conditions(
                        raw,
                        &user,
                        (*target_grant, template.role_id),
                        target,
                        registry.get(target).map_or(&[], |m| m.attrs.as_slice()),
                    ),
                    None => Vec::new(),
                },
            },
        };
        lookup_scopes.insert(field.clone(), scope);
    }

    // Creating needs a live staff team to own the record (G-15). A team that
    // is gone refuses creation; it never falls back to another owner. Read
    // live, and only for writes (the team also stamps write audit rows).
    let team = if write {
        owning_team(&mut *conn, portal).await?
    } else {
        None
    };
    if write && team.is_none() && portal.owning_team_ref.is_some() && grant.can_create {
        tracing::warn!(
            webportal_id = %portal.id,
            "portal owning team is missing or deleted; portal creates are refused"
        );
    }
    let (owner_team_ref, owner_org_ref) =
        team.unwrap_or((Uuid::nil(), attome_core::ROOT_ORGANIZATION_ID));

    Ok(Some(AccessPlan {
        portal_user_id: principal.user_id,
        portal_user_label: user.label,
        webportal_id: portal.id,
        entity: entity.to_owned(),
        can_read: grant.can_read,
        can_create: grant.can_create && team.is_some(),
        can_update: grant.can_update,
        can_delete: grant.can_delete,
        conditions,
        readable: grant.readable.clone(),
        writable: grant.writable.clone(),
        filterable: grant.filterable.clone(),
        owner_team_ref,
        owner_org_ref,
        portal_user_field: grant.portal_user_field.clone(),
        lookup_scopes,
        request_context: Default::default(),
        // D-789 ruling 6: portal-role business rules apply to this plan's
        // writes (D-579: one role per portal user).
        role_id: Some(role_id),
    }))
}

/// The portal's live owning team and that team's organisation, or `None`
/// when the portal has none or it is deleted (G-15: never a fallback owner).
async fn owning_team(
    conn: &mut PgConnection,
    portal: &PortalDetail,
) -> Result<Option<(Uuid, Uuid)>, AppError> {
    let Some(team) = portal.owning_team_ref else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT organization_ref FROM team WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(team)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .map(|org| (team, org.unwrap_or(attome_core::ROOT_ORGANIZATION_ID))))
}

/// The organisation a portal write outside a grant (the profile, `PATCH /me`)
/// is audited under: the owning team's, like a record write, or the root
/// organisation when the portal has no live owning team.
pub async fn owning_org(conn: &mut PgConnection, portal: &PortalDetail) -> Result<Uuid, AppError> {
    Ok(owning_team(conn, portal)
        .await?
        .map_or(attome_core::ROOT_ORGANIZATION_ID, |(_, org)| org))
}

/// The plan for the principal's **own** `webportal_user` row (`GET` and
/// `PATCH /{keyword}/api/v1/me`, D-588): so a profile edit goes through the
/// same engine update as every other portal write (validation, record
/// guards, row version, change events, audit), not a second write path
/// (I-18).
///
/// The row scope is the principal's own id and nothing else. Readable and
/// writable are the policy's `editable` fields that exist today and pass
/// [`crate::policy::self_editable`] (checked again here, so a policy saved
/// before that check existed can't make a lookup self-editable). No lookup
/// scopes: a lookup could never be written anyway. Only read and update.
/// `owner_org_ref` is the organisation its audit rows carry (`owning_org`).
pub fn self_plan(
    registry: &EntityMetaRegistry,
    principal: &PortalPrincipal,
    label: String,
    editable: &[String],
    owner_org_ref: Uuid,
) -> AccessPlan {
    let attrs: &[AttrInfo] = registry
        .get(PORTAL_USER_ENTITY)
        .map_or(&[], |m| m.attrs.as_slice());
    let fields: BTreeSet<String> = editable
        .iter()
        .filter(|f| {
            attrs
                .iter()
                .any(|a| &a.logicalname == *f && crate::policy::self_editable(a))
        })
        .cloned()
        .collect();
    AccessPlan {
        portal_user_id: principal.user_id,
        portal_user_label: label,
        webportal_id: principal.webportal_id,
        entity: PORTAL_USER_ENTITY.to_owned(),
        can_read: true,
        can_create: false,
        can_update: !fields.is_empty(),
        can_delete: false,
        conditions: vec![PlanCondition::Match(GrantCondition {
            field_logicalname: "id".to_owned(),
            operator: ConditionOperator::Eq,
            value: Value::String(principal.user_id.to_string()),
        })],
        readable: fields.clone(),
        writable: fields,
        filterable: BTreeSet::new(),
        owner_team_ref: Uuid::nil(),
        owner_org_ref,
        portal_user_field: None,
        lookup_scopes: BTreeMap::new(),
        request_context: Default::default(),
        // D-789 ruling 6: the own-profile write runs the same business
        // rules, scoped by the principal's role when it holds one.
        role_id: principal.role_id,
    }
}

/// T-37 (web-portal plan §6.1), the resolver's half: [`render_conditions`]
/// turns a grant's stored conditions into plan conditions for one user. Its
/// output must be one plan condition per stored one, each either a condition
/// that renders against today's metadata or `MatchNothing`; and a
/// restriction (an unknown operator, a `value_ref` whose source is now null
/// or missing, a field dropped from metadata) only ever turns a condition
/// into `MatchNothing`, never the reverse or into a different condition. The
/// engine's half (`attome_records::access_plan::t37_property`) proves that
/// `MatchNothing` then matches no row. Run with:
/// `cargo test -p attome-portal --lib context::t37_property`
#[cfg(test)]
mod t37_property {
    use super::*;
    use proptest::prelude::*;

    static FIELDS: [&str; 4] = ["title", "status", "ghost", "id"];
    static REFS: [&str; 3] = [
        "@portal_user.id",
        "@portal_user.company_ref",
        "@portal_user.gone_ref",
    ];

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
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
            sensitivity_confirmed: false,
            options: None,
        }
    }

    fn attrs() -> Vec<AttrInfo> {
        vec![attr("title", 3), attr("status", 1)]
    }

    fn value() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::String(Uuid::from_u128(7).to_string())),
            "[a-z]{0,4}".prop_map(Value::String),
            (-3i64..3).prop_map(Value::from),
            Just(Value::Null),
            prop::collection::vec("[a-z]{0,3}".prop_map(Value::String), 0..3)
                .prop_map(Value::Array),
        ]
    }

    fn raw() -> impl Strategy<Value = RawCondition> {
        (
            prop::sample::select(&FIELDS[..]),
            -1i16..=8,
            prop::option::of(value()),
            prop::option::of(prop::sample::select(&REFS[..])),
        )
            .prop_map(|(field, operator, value, value_ref)| RawCondition {
                field: field.to_owned(),
                operator,
                value,
                value_ref: value_ref.map(str::to_owned),
            })
    }

    /// Each `value_ref`'s source on the user's row: absent, null, or a value.
    fn user() -> impl Strategy<Value = HashMap<String, Option<String>>> {
        prop::collection::vec(
            prop::option::of(prop::option::of(prop_oneof![
                Just(Uuid::from_u128(5).to_string()),
                "[a-z]{0,4}"
            ])),
            REFS.len(),
        )
        .prop_map(|slots| {
            REFS.iter()
                .zip(slots)
                .filter_map(|(r, s)| s.map(|v| ((*r).to_owned(), v)))
                .collect()
        })
    }

    #[derive(Clone, Debug)]
    enum Restriction {
        UnknownOperator(usize),
        NullSource(usize),
        MissingSource(usize),
        DropAttr(usize),
    }

    fn restriction() -> impl Strategy<Value = Restriction> {
        prop_oneof![
            any::<usize>().prop_map(Restriction::UnknownOperator),
            any::<usize>().prop_map(Restriction::NullSource),
            any::<usize>().prop_map(Restriction::MissingSource),
            any::<usize>().prop_map(Restriction::DropAttr),
        ]
    }

    fn render(
        raw: &[RawCondition],
        values: &HashMap<String, Option<String>>,
        attrs: &[AttrInfo],
    ) -> Vec<PlanCondition> {
        let user = UserValues {
            label: String::new(),
            values: values.clone(),
        };
        render_conditions(
            raw,
            &user,
            (Uuid::from_u128(1), Uuid::from_u128(2)),
            "t37_case",
            attrs,
        )
    }

    fn is_nothing(c: &PlanCondition) -> bool {
        matches!(c, PlanCondition::MatchNothing)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn t37_resolved_conditions_render_or_match_nothing(
            raw in prop::collection::vec(raw(), 0..5),
            values in user(),
        ) {
            let attrs = attrs();
            let out = render(&raw, &values, &attrs);
            prop_assert_eq!(out.len(), raw.len());
            for (c, r) in out.iter().zip(&raw) {
                match c {
                    PlanCondition::Match(g) => {
                        prop_assert!(condition_renders(g, &attrs), "{:?} does not render", g);
                        prop_assert!(ConditionOperator::from_i16(r.operator).is_some());
                        prop_assert!(r.value.is_some() != r.value_ref.is_some(),
                            "a condition with both or neither of value and value_ref matched");
                        if let Some(source) = &r.value_ref {
                            prop_assert!(values.get(source).is_some_and(Option::is_some),
                                "{} resolved without a source value", source);
                        }
                    }
                    PlanCondition::MatchNothing => {}
                }
            }
        }

        #[test]
        fn t37_a_restriction_only_turns_conditions_into_match_nothing(
            raw in prop::collection::vec(raw(), 1..5),
            values in user(),
            r in restriction(),
        ) {
            let attrs = attrs();
            let wide = render(&raw, &values, &attrs);
            let (mut raw2, mut values2, mut attrs2) = (
                raw.iter()
                    .map(|c| RawCondition {
                        field: c.field.clone(),
                        operator: c.operator,
                        value: c.value.clone(),
                        value_ref: c.value_ref.clone(),
                    })
                    .collect::<Vec<_>>(),
                values.clone(),
                attrs.clone(),
            );
            match r {
                Restriction::UnknownOperator(i) => {
                    let n = i % raw2.len();
                    raw2[n].operator = 99;
                }
                Restriction::NullSource(i) => {
                    values2.insert(REFS[i % REFS.len()].to_owned(), None);
                }
                Restriction::MissingSource(i) => {
                    values2.remove(REFS[i % REFS.len()]);
                }
                Restriction::DropAttr(i) => {
                    let n = i % attrs2.len();
                    attrs2.remove(n);
                }
            }
            let narrow = render(&raw2, &values2, &attrs2);
            prop_assert_eq!(narrow.len(), wide.len());
            for (n, w) in narrow.iter().zip(&wide) {
                prop_assert!(
                    is_nothing(n) || format!("{n:?}") == format!("{w:?}"),
                    "{:?} changed {:?} into {:?}", r, w, n
                );
            }
        }
    }
}

/// [`self_plan`]: the user's own row only, only plain editable fields, and a
/// write only when the policy allows one.
#[cfg(test)]
mod self_plan_tests {
    use super::*;
    use attome_core::EntityMeta;

    const ROOT: Uuid = attome_core::ROOT_ORGANIZATION_ID;

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    fn registry() -> EntityMetaRegistry {
        EntityMetaRegistry::from_entities(vec![EntityMeta {
            entity_id: Uuid::from_u128(1),
            logicalname: PORTAL_USER_ENTITY.to_owned(),
            attrs: vec![
                attr("name", 3),
                attr("phone", 3),
                attr("email", 3),
                attr("status", 1),
                attr("company_ref", 11),
                attr("avatar", 12),
                attr("score", 16),
                AttrInfo {
                    is_sensitive: true,
                    ..attr("staff_note", 3)
                },
                AttrInfo {
                    is_write_restricted: true,
                    ..attr("tier", 3)
                },
            ],
            is_append_only: false,
            primary_name_attribute: Some("name".to_owned()),
        }])
    }

    fn principal() -> PortalPrincipal {
        PortalPrincipal {
            webportal_id: Uuid::from_u128(2),
            user_id: Uuid::from_u128(3),
            family_id: Uuid::from_u128(4),
            mfa_enabled: false,
            mfa_enrollment_required: false,
            role_id: None,
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_stale_policy_still_cannot_make_identity_lookup_or_file_fields_editable() {
        // As if saved before the policy refused them.
        let editable = names(&[
            "phone",
            "name",
            "email",
            "status",
            "company_ref",
            "avatar",
            "score",
            "staff_note",
            "tier",
            "ghost",
        ]);
        let plan = self_plan(&registry(), &principal(), "Pat".to_owned(), &editable, ROOT);
        let only_phone: BTreeSet<String> = names(&["phone"]).into_iter().collect();
        assert_eq!(plan.writable, only_phone);
        assert_eq!(plan.readable, only_phone);
        assert!(plan.filterable.is_empty());
        assert!(plan.lookup_scopes.is_empty());
        assert!(plan.portal_user_field.is_none());
        assert!(plan.can_read && plan.can_update);
        assert!(!plan.can_create && !plan.can_delete);
        assert_eq!(plan.entity, PORTAL_USER_ENTITY);
        assert_eq!(plan.portal_user_id, principal().user_id);
    }

    #[test]
    fn the_scope_is_the_users_own_row_and_nothing_else() {
        let registry = registry();
        let plan = self_plan(
            &registry,
            &principal(),
            String::new(),
            &names(&["phone"]),
            ROOT,
        );
        let [PlanCondition::Match(c)] = plan.conditions.as_slice() else {
            panic!("one condition: {:?}", plan.conditions);
        };
        assert_eq!(c.field_logicalname, "id");
        assert_eq!(c.operator, ConditionOperator::Eq);
        assert_eq!(c.value, Value::String(principal().user_id.to_string()));
        let attrs = &registry.get(PORTAL_USER_ENTITY).unwrap().attrs;
        assert!(condition_renders(c, attrs), "the own-row condition renders");
    }

    #[test]
    fn with_nothing_editable_the_profile_is_read_only() {
        let plan = self_plan(&registry(), &principal(), String::new(), &[], ROOT);
        assert!(plan.can_read);
        assert!(!plan.can_update);
        assert!(plan.writable.is_empty() && plan.readable.is_empty());
    }
}

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use arc_swap::ArcSwap;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Record-level access-scoping tier. Originally (D-133) resolved once per
/// request as a single scalar — the most-permissive `xrm_core_role.access_level`
/// across every role a caller held, regardless of entity. That design let one
/// role's scope leak into every other entity a caller could touch; it has
/// been superseded by per-`(entity, action)` resolution
/// (`xrm_security::db::resolve_entity_access_level`) — see
/// `document/decisions/security/D-136.md`. This enum itself (the four-value
/// ladder) is unchanged, only *where*
/// a value gets resolved and cached changed. Ord is derived in declaration
/// order — `None < Team < BusinessUnit < Global` — so `MAX()` within one
/// `(entity, action)` key picks the most permissive contributing role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(i16)]
pub enum AccessLevel {
    None = 0,
    Team = 1,
    BusinessUnit = 2,
    Global = 3,
}

impl AccessLevel {
    /// Maps `xrm_core_role.access_level`'s `SMALLINT` (0-3, DB CHECK-constrained)
    /// to the enum. Any out-of-range value (should be unreachable given the
    /// constraint) fails closed to `None` rather than panicking or silently
    /// granting `Global`.
    pub fn from_i16(value: i16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Team,
            2 => Self::BusinessUnit,
            3 => Self::Global,
            _ => Self::None,
        }
    }
}

impl Default for AccessLevel {
    /// Only meaningful as "no role held" — every seeded/admin-created role
    /// row defaults to `Global` at the DB layer (D-133), not here.
    fn default() -> Self {
        Self::None
    }
}

/// D-369: `xrm_core_role_privilege_condition.operator`'s `SMALLINT` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i16)]
pub enum ConditionOperator {
    Eq = 0,
    Ne = 1,
    Gt = 2,
    Lt = 3,
    Gte = 4,
    Lte = 5,
    In = 6,
}

impl ConditionOperator {
    /// Fails closed to `None` (never a silent default operator) on an
    /// out-of-range value — same posture as `AccessLevel::from_i16`.
    pub fn from_i16(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Eq),
            1 => Some(Self::Ne),
            2 => Some(Self::Gt),
            3 => Some(Self::Lt),
            4 => Some(Self::Gte),
            5 => Some(Self::Lte),
            6 => Some(Self::In),
            _ => None,
        }
    }

    /// The SQL comparison operator text — `In` has no single-token operator
    /// and is rendered separately by its caller (`xrm_security::rls`).
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "<>",
            Self::Gt => ">",
            Self::Lt => "<",
            Self::Gte => ">=",
            Self::Lte => "<=",
            Self::In => "IN",
        }
    }
}

/// D-369: one already-validated row from `xrm_core_role_privilege_condition`
/// — field eligibility (belongs to the grant's entity, carries a supporting
/// B-tree index, not `is_sensitive`) is enforced once, at admin-write time
/// (`xrm-security`'s admin condition endpoints); this struct carries only
/// what's needed to render a WHERE-clause comparison at request time, not to
/// re-validate it. Defined here (not `xrm-security`) because it hangs off
/// `SecurityContext`, which attome-server owns for the same dependency-direction
/// reason as every other field on this struct — see the struct's own doc
/// comment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantCondition {
    pub field_logicalname: String,
    pub operator: ConditionOperator,
    /// Scalar for every operator except `In`, where this is a JSON array.
    pub value: serde_json::Value,
}

/// Resolved authorization decision for one request's `SessionClaims.sub`.
///
/// Deliberately owned by attome-server (not xrm-security): the `authz`
/// middleware below inserts it as an `Extension<T>`, and attome-server cannot
/// name a type from `xrm-security` (dependency direction, guidelines §1).
/// `xrm-security` resolves this type's fields and extends it with ergonomic
/// `.require_admin()`/`.require(entity, action)` methods via an extension
/// trait defined on its side — see `xrm_security::SecurityContextExt`.
/// Deliberately **not** `Clone`. `axum::Extension<T>` implements
/// `FromRequestParts` for any `T: Clone`, so as long as this type were
/// cloneable a handler could keep writing `Extension(ctx):
/// Extension<SecurityContext>` and receive an unauthorized context — the exact
/// opt-in-authorization hazard `crate::authz` exists to remove. Without `Clone`
/// that signature does not compile, so forgetting to name a policy is a build
/// failure rather than a silent privilege escalation.
///
/// Shared ownership is expressed with `Arc<SecurityContext>` instead: the
/// resolver, its L1 cache, and `AuthorizedContext` all carry the `Arc`, which
/// is also strictly cheaper than the deep `HashSet`/`Vec` clone this derive
/// used to perform on every cache hit and every request.
/// Q10-T2: where a role's `BusinessUnit` depth stops at the caller's own
/// units instead of reaching their child units too
/// (`role_mm_entity_access.{action}_bu_children = false`).
///
/// Resolved with the rest of the context. An `(entity, action)` is listed
/// only when every held role that grants it at `BusinessUnit` depth excludes
/// child units, the same most-permissive-role-wins rule the depth `MAX`
/// already applies. `xrm_security::rls` reads it when it builds the
/// `BusinessUnit` tier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitScope {
    /// The caller's own units (memberships and home unit), without the units
    /// under them. Empty unless some `(entity, action)` is listed below.
    pub own_org_ids: Vec<Uuid>,
    /// `"{entity_ref}.{action}"` keys (`action` as
    /// `RecordAction::as_str`) whose `BusinessUnit` tier is
    /// [`Self::own_org_ids`] rather than
    /// [`SecurityContext::accessible_org_ids`].
    pub own_units_only: HashSet<String>,
}

impl UnitScope {
    /// True when `entity_ref`'s `BusinessUnit` tier for `action` excludes
    /// child units.
    pub fn excludes_children(&self, entity_ref: Uuid, action: &str) -> bool {
        !self.own_units_only.is_empty()
            && self
                .own_units_only
                .contains(&format!("{entity_ref}.{action}"))
    }
}

/// D-589: which non-sensitive fields a *bulk* surface (export, query/execute,
/// reports, document generation, dashboards, AI context and tools, search
/// aggregates and graph, webhook payloads) may return to this caller.
/// Interactive record reads never consult it (D-111 unchanged there), and a
/// sensitive field always needs its field-security grant on every surface.
///
/// Decide visibility through `xrm_security::field_gate`, never by matching on
/// this directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkFields {
    /// Every non-sensitive field: behaviour before D-589, and what a caller
    /// gets while any role it holds is still `legacy`
    /// (`xrm_core_role.bulk_field_mode = 0`). Also the serde default, so a
    /// cached context written before this type existed behaves as it did.
    #[default]
    Legacy,
    /// Only these `"{entity}.{field}"` pairs (plus the entity's id, system
    /// columns and primary name, which bulk surfaces always return).
    Listed(HashSet<String>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityContext {
    pub user_id: Uuid,
    /// True iff `privileges` contains the reserved key `"system.admin"`.
    pub is_admin: bool,
    /// Flat privilege.key strings held (direct grants + role-mediated grants).
    pub privileges: HashSet<String>,
    /// `"{entity_logicalname}.{field_logicalname}"` pairs this user may read,
    /// via a `xrm_core_field_security_profile` assigned (directly or through a
    /// role) with `can_read = true` for that pair (D-111/F013/F135). Only
    /// meaningful for `is_sensitive` attributes — a non-sensitive field is
    /// never gated by this set in the first place.
    #[serde(default)]
    pub field_grants: HashSet<String>,
    /// Same shape as `field_grants`, gated on `can_update = true` instead of
    /// `can_read` (P-field-write-security, D-141) — a caller can hold one of
    /// these two grants for a given `(entity, field)` pair without the other
    /// (e.g. read-only visibility into a sensitive field with no permission
    /// to change it). `#[serde(default)]` is the same stale-cache safety net
    /// every other post-launch `SecurityContext` field uses: an L2 cache
    /// entry written before this field existed deserializes to an empty set,
    /// i.e. fails closed (no write grant), never a silently-inferred true.
    #[serde(default)]
    pub field_write_grants: HashSet<String>,
    /// Q15-T1: `"{entity}.{field}"` -> mask format (`last4`, `email`, `phone`,
    /// `full`) for each sensitive field this caller may see only masked: a
    /// profile grants it with a `mask_format` and none grants it in full. A
    /// masked field is in neither `field_grants` nor `field_write_grants`,
    /// so every surface that does not project masks keeps hiding it.
    #[serde(default)]
    pub field_masks: HashMap<String, String>,
    /// D-589: bulk-surface field exposure. See [`BulkFields`].
    #[serde(default)]
    pub bulk_fields: BulkFields,
    /// P-authz-revocation-epoch (D-116): the value of the per-user Redis
    /// counter `xrm:authz_epoch:{user_id}` this context was resolved under.
    /// `0` means "resolved before/without ever consulting the counter" — the
    /// same value an absent key GETs as, so a cold-Redis restart doesn't
    /// manufacture a false mismatch. Only meaningful to `resolve_strict`'s
    /// compare; the ordinary D-012 cache path ignores it entirely.
    #[serde(default)]
    pub epoch: i64,
    /// P-record-level-security (post-D-133/D-134): every `xrm_core_organization.id`
    /// this caller can reach for `BusinessUnit`-tier scoping — every org the
    /// caller is a direct member of (`xrm_core_systemuser_mm_organization`) plus
    /// every descendant of each, walked via
    /// `xrm_core_organization.organization_ref`'s self-reference. Populated
    /// speculatively whenever `xrm_security::db::any_role_uses_business_unit_scope`
    /// says at least one held role *might* need it somewhere this resolve
    /// cycle — the actual per-request depth (and therefore whether this set
    /// is consulted at all for a given entity/action) is resolved separately,
    /// per `(entity, action)`, by `xrm_security::db::resolve_entity_access_level`
    /// — record-level scope is no longer a single flat field on this struct
    /// (see that function's doc comment for why the old
    /// `xrm_core_role.access_level` single-scalar design leaked scope across
    /// entities, and `document/decisions/security/D-136.md` for the full
    /// writeup).
    #[serde(default)]
    pub accessible_org_ids: Vec<Uuid>,
    /// D-133: every `xrm_core_team.id` this caller belongs to
    /// (`xrm_core_systemuser_mm_team`) — consulted by `rls_predicate`'s `Team`
    /// tier and by explicit `xrm_core_record_share`/`xrm_core_entity_default_share`
    /// rows targeting a team rather than the caller directly.
    #[serde(default)]
    pub team_ids: Vec<Uuid>,
    /// F138 (position hierarchy): the most permissive
    /// `xrm_core_role.position_hierarchy_enabled` across every role this caller
    /// holds (direct or team-mediated) — `bool_or`, same aggregation shape as
    /// `access_level`'s `MAX`. Deliberately not a rung on `AccessLevel`'s
    /// ladder: this is an orthogonal, additive flag (a role's existing
    /// `access_level` extends downward through the caller's position
    /// subtree when this is true), not a fifth tier. `#[serde(default)]` is
    /// the same stale-cache safety net as every other D-133 field — an old
    /// cache entry predating this field must fail closed to `false`.
    #[serde(default)]
    pub position_hierarchy_enabled: bool,
    /// F138: every `user_account.id` in the caller's position subtree
    /// (every user assigned, directly or transitively, to a position that
    /// descends from a position the caller holds — never the caller's own
    /// position peers, see `xrm_security::db::resolve_subordinate_user_ids`).
    /// Only ever non-empty when `position_hierarchy_enabled` is true — left
    /// unresolved (empty) otherwise as wasted work, same optimization
    /// `accessible_org_ids` already applies for non-`BusinessUnit` callers.
    /// Consulted by `rls_predicate` exactly like `team_ids` is: a
    /// `principal_id = ANY(...)` match against `xrm_core_record_share`'s
    /// user-principal rows, since a subordinate's "ownership" of a record is
    /// itself just a user-principal `action`-capability share row (D-133 §2)
    /// — there is no separate owner column to compare against.
    #[serde(default)]
    pub subordinate_user_ids: Vec<Uuid>,
    /// D-369: bounded per-grant record conditions, keyed by `"{entity}.{action}"`
    /// privilege key. Every inner `Vec<GrantCondition>` is one role's AND-set
    /// (≤3 rows, enforced at admin-write time); a privilege key present in
    /// this map means no role holding it granted it unconditionally — a role
    /// whose own grant carries zero conditions makes the whole key ABSENT
    /// here rather than present with an empty outer `Vec`, so "no entry" and
    /// "no restriction" are the same state a caller checks with one
    /// `.get()` (most-permissive-role-wins, same posture as `AccessLevel`'s
    /// per-entity `MAX` — D-133/D-136). `#[serde(default)]` is the same
    /// stale-cache safety net every other post-launch field on this struct
    /// uses: an L2 entry written before this field existed deserializes to
    /// an empty map, i.e. fails closed to "no conditions cached" — callers
    /// must not treat an empty map as proof no condition exists server-side;
    /// only `resolve_strict`'s fresh re-resolution is authoritative for that.
    /// Only consulted by `xrm_security::rls::rls_predicate_with_conditions`,
    /// which only `entity_crud.rs`'s direct paths call (D-369 v1 scope) —
    /// every other `rls_predicate`/`rls_predicate_by_column` caller ignores
    /// this field entirely, unchanged.
    #[serde(default)]
    pub condition_grants: HashMap<String, Vec<Vec<GrantCondition>>>,
    /// D-789 §4.3: every live `xrm_core_role.id` this caller holds, directly
    /// or through a team — the audience business rules are scoped by.
    /// `Some(..)` for a context the resolver built for a user (cached with the
    /// rest of the context and refreshed by the same security epoch on a
    /// membership change); `None` for a context built in code (workflow
    /// scheduler, bundle record sets, jobs): a **system** writer, which
    /// business-rule locks never refuse and role-scoped rules never match.
    /// `#[serde(default)]` would read a pre-D-789 cache entry as `None` (a
    /// system writer, skipping locks), which is why the resolver's L2 key
    /// version was bumped with this field (`xrm_security::cache`): no such
    /// entry is ever read.
    #[serde(default)]
    pub role_ids: Option<Vec<Uuid>>,
    /// Q10-T2: `(entity, action)` pairs whose `BusinessUnit` depth excludes
    /// child units, and the caller's own units for them. Empty, the default,
    /// keeps every `BusinessUnit` tier on `accessible_org_ids`; the
    /// resolver's L2 key version was bumped with this field so no entry
    /// written before it is read as "children included".
    #[serde(default)]
    pub unit_scope: UnitScope,
    /// D-791 rule 3: true when this request authenticated with an API key or
    /// as an S2S client (anything but a cookie session). Such a caller is
    /// exempt from business-rule `hidden`/`disabled` policies; `error` and
    /// `set_value` still apply. Set per request by
    /// [`AuthorizedContext::for_request`](crate::authz::AuthorizedContext::for_request),
    /// never cached and never serialized: a resolved (cached) context is
    /// `false`, which is the restrictive default (subject to locks).
    #[serde(skip)]
    pub service_principal: bool,
}

impl SecurityContext {
    /// Z3-T4: one string for everything this context is allowed, the same
    /// for two readers with the same effective permissions in any order:
    /// SHA-256 hex over the admin flag, privileges, field read and write
    /// grants, bulk fields, record conditions, reachable organisations,
    /// teams, the position hierarchy and its subordinates, roles and the
    /// service-principal flag. A cache partitioned `PerPermissionSet` keys
    /// on it.
    ///
    /// The user id and the authorisation epoch are left out. The epoch is a
    /// per-user counter, so including it would make every fingerprint
    /// personal; a permission change it marks changes the fields above. The
    /// user id is what a record-level owner check reads, so rows filtered by
    /// ownership must live in a `PerUser` cache, never a `PerPermissionSet`
    /// one.
    pub fn permission_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        fn sorted<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
            let mut out: Vec<String> = items.into_iter().map(|i| i.to_string()).collect();
            out.sort();
            out.dedup();
            out
        }

        let mut lines = vec![format!("admin:{}", self.is_admin)];
        lines.extend(
            sorted(&self.privileges)
                .into_iter()
                .map(|p| format!("privilege:{p}")),
        );
        lines.extend(
            sorted(&self.field_grants)
                .into_iter()
                .map(|f| format!("read:{f}")),
        );
        lines.extend(
            sorted(
                self.field_masks
                    .iter()
                    .map(|(field, format)| format!("{field}={format}")),
            )
            .into_iter()
            .map(|m| format!("mask:{m}")),
        );
        lines.extend(
            sorted(&self.field_write_grants)
                .into_iter()
                .map(|f| format!("write:{f}")),
        );
        match &self.bulk_fields {
            BulkFields::Legacy => lines.push("bulk:legacy".into()),
            BulkFields::Listed(fields) => {
                lines.push("bulk:listed".into());
                lines.extend(sorted(fields).into_iter().map(|f| format!("bulk:{f}")));
            }
        }
        for key in sorted(self.condition_grants.keys()) {
            let sets = sorted(
                self.condition_grants[&key]
                    .iter()
                    .map(|set| serde_json::to_string(set).unwrap_or_default()),
            );
            lines.push(format!("condition:{key}={}", sets.join("|")));
        }
        lines.extend(
            sorted(&self.accessible_org_ids)
                .into_iter()
                .map(|o| format!("org:{o}")),
        );
        lines.extend(
            sorted(&self.team_ids)
                .into_iter()
                .map(|t| format!("team:{t}")),
        );
        lines.push(format!("hierarchy:{}", self.position_hierarchy_enabled));
        lines.extend(
            sorted(&self.subordinate_user_ids)
                .into_iter()
                .map(|u| format!("subordinate:{u}")),
        );
        lines.extend(
            sorted(&self.unit_scope.own_org_ids)
                .into_iter()
                .map(|o| format!("own_org:{o}")),
        );
        lines.extend(
            sorted(&self.unit_scope.own_units_only)
                .into_iter()
                .map(|k| format!("own_units_only:{k}")),
        );
        match &self.role_ids {
            Some(roles) => lines.extend(sorted(roles).into_iter().map(|r| format!("role:{r}"))),
            None => lines.push("role:system".into()),
        }
        lines.push(format!("service:{}", self.service_principal));

        Sha256::digest(lines.join("\n").as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A copy of this context marked as a service principal (D-791 rule 3).
    /// Deep-copies, as [`EntityCeiling::apply`] does; only API-key and S2S
    /// requests pay it.
    pub fn as_service_principal(&self) -> SecurityContext {
        SecurityContext {
            user_id: self.user_id,
            is_admin: self.is_admin,
            privileges: self.privileges.clone(),
            field_grants: self.field_grants.clone(),
            field_write_grants: self.field_write_grants.clone(),
            field_masks: self.field_masks.clone(),
            bulk_fields: self.bulk_fields.clone(),
            epoch: self.epoch,
            accessible_org_ids: self.accessible_org_ids.clone(),
            team_ids: self.team_ids.clone(),
            position_hierarchy_enabled: self.position_hierarchy_enabled,
            subordinate_user_ids: self.subordinate_user_ids.clone(),
            condition_grants: self.condition_grants.clone(),
            role_ids: self.role_ids.clone(),
            unit_scope: self.unit_scope.clone(),
            service_principal: true,
        }
    }
}

/// The reserved privilege key a resolver maps to [`SecurityContext::is_admin`].
pub const ADMIN_PRIVILEGE_KEY: &str = "system.admin";

/// The per-entity verbs an [`EntityCeiling`] governs: a privilege key
/// `"{entity}.{verb}"` whose verb is one of these is an entity privilege.
pub(crate) const CEILING_ACTIONS: [&str; 5] = ["read", "create", "update", "delete", "bulk"];

/// D-766: an upper bound on the entity privileges of a delegated caller (an
/// S2S client acting as its service user). A middleware that authenticates
/// such a caller inserts one as a request extension;
/// [`AuthorizedContext::for_request`](crate::authz::AuthorizedContext::for_request),
/// which `authz` and `strict_authz` use, applies it before attaching the
/// context, so every check that reads `is_admin` / `privileges` sees the
/// narrowed set.
///
/// It only ever narrows. A governed key (see [`CEILING_ACTIONS`]) survives
/// only if the ceiling also allows it; a non-entity key (`sidebar.manage`)
/// is untouched. An admin context loses `is_admin` and
/// [`ADMIN_PRIVILEGE_KEY`] and gets exactly the ceiling's keys instead:
/// admin implies every entity privilege, so there is no narrower way to
/// express "admin, but only these entities" — it fails closed.
#[derive(Clone, Debug, Default)]
pub struct EntityCeiling {
    allowed: HashSet<String>,
}

impl EntityCeiling {
    /// `allowed` holds `"{entity}.{verb}"` keys; keys whose verb is not a
    /// [`CEILING_ACTIONS`] verb are ignored.
    pub fn new(allowed: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: allowed.into_iter().filter(|k| governs(k)).collect(),
        }
    }

    pub fn allows(&self, key: &str) -> bool {
        !governs(key) || self.allowed.contains(key)
    }

    /// The narrowed copy of `ctx`.
    pub fn apply(&self, ctx: &SecurityContext) -> SecurityContext {
        let privileges = if ctx.is_admin {
            ctx.privileges
                .iter()
                .filter(|k| k.as_str() != ADMIN_PRIVILEGE_KEY && !governs(k))
                .chain(self.allowed.iter())
                .cloned()
                .collect()
        } else {
            ctx.privileges
                .iter()
                .filter(|k| self.allows(k))
                .cloned()
                .collect()
        };
        SecurityContext {
            user_id: ctx.user_id,
            is_admin: false,
            privileges,
            field_grants: ctx.field_grants.clone(),
            field_write_grants: ctx.field_write_grants.clone(),
            field_masks: ctx.field_masks.clone(),
            bulk_fields: ctx.bulk_fields.clone(),
            epoch: ctx.epoch,
            accessible_org_ids: ctx.accessible_org_ids.clone(),
            team_ids: ctx.team_ids.clone(),
            position_hierarchy_enabled: ctx.position_hierarchy_enabled,
            subordinate_user_ids: ctx.subordinate_user_ids.clone(),
            condition_grants: ctx.condition_grants.clone(),
            role_ids: ctx.role_ids.clone(),
            unit_scope: ctx.unit_scope.clone(),
            service_principal: ctx.service_principal,
        }
    }
}

fn governs(key: &str) -> bool {
    key.rsplit_once('.')
        .is_some_and(|(entity, verb)| !entity.is_empty() && CEILING_ACTIONS.contains(&verb))
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a `SessionClaims.sub` user id into a `SecurityContext`.
/// `xrm-security` provides the real implementation (Postgres + moka/Redis
/// cache); attome-server only depends on this trait, never on xrm-security
/// itself.
pub trait SecurityResolver: Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        user_id: Uuid,
    ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>>;

    /// Drops any cached `SecurityContext` for `user_id` (L1 + L2, where the
    /// concrete resolver has them) — call after any privilege/job-grant
    /// write so the change takes effect immediately instead of waiting out
    /// the cache TTL. Best-effort: internal failures (Redis DEL/publish) are
    /// logged, never propagated — see `invalidate_sync` for the
    /// acknowledged counterpart.
    fn invalidate<'a>(&'a self, user_id: Uuid) -> BoxFuture<'a, ()>;

    /// P-authz-revocation-epoch (D-116) goal (a): synchronous, fail-closed
    /// re-check against the live `xrm:authz_epoch:{user_id}` counter —
    /// re-resolves fresh from Postgres on a mismatch, returns `Err` on a
    /// Redis error/timeout rather than trusting a possibly-stale cached
    /// value (same posture as `attome_auth::revocation::is_revoked`). Used by
    /// the `strict_authz` middleware ahead of the privileged/admin-gated
    /// route bundles, and by every resolve when `security.strict_revocation`
    /// is on.
    fn resolve_strict<'a>(
        &'a self,
        user_id: Uuid,
    ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>>;

    /// P-authz-revocation-epoch (D-116) goal (b): the acknowledged
    /// counterpart to `invalidate` — propagates an epoch-bump or L2-purge
    /// failure as `Err` instead of a swallowed `warn!`, so a grant/revoke
    /// handler can turn it into a 500-with-request-id rather than returning
    /// 200/204 while the cache never actually converged.
    fn invalidate_sync<'a>(&'a self, user_id: Uuid) -> BoxFuture<'a, Result<(), AppError>>;

    /// The IP allow-lists of every *restrictive* role `user_id` holds (roles
    /// without one are left out), read fresh on every call so an edit applies
    /// to the next request. The cookie-session branch of the auth middleware
    /// allows the request only from an address in at least one of them.
    /// Required, with no default: a resolver that forgot it would silently
    /// lift every role's network restriction.
    fn session_ip_allowlists<'a>(
        &'a self,
        user_id: Uuid,
    ) -> BoxFuture<'a, Result<Vec<Vec<String>>, AppError>>;
}

/// Fail-closed default until `XrmSystem::builder` injects the real resolver.
/// Absence of a resolver MUST deny, never silently allow.
#[derive(Debug)]
pub struct DenyAllResolver;

impl SecurityResolver for DenyAllResolver {
    fn resolve<'a>(
        &'a self,
        _user_id: Uuid,
    ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>> {
        Box::pin(async move { Err(AppError::Forbidden) })
    }

    fn invalidate<'a>(&'a self, _user_id: Uuid) -> BoxFuture<'a, ()> {
        Box::pin(async move {})
    }

    fn resolve_strict<'a>(
        &'a self,
        _user_id: Uuid,
    ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>> {
        Box::pin(async move { Err(AppError::Forbidden) })
    }

    fn invalidate_sync<'a>(&'a self, _user_id: Uuid) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move { Ok(()) })
    }

    fn session_ip_allowlists<'a>(
        &'a self,
        _user_id: Uuid,
    ) -> BoxFuture<'a, Result<Vec<Vec<String>>, AppError>> {
        Box::pin(async move { Err(AppError::Forbidden) })
    }
}

/// Swappable holder for the active resolver — mirrors `XrmState.license`'s
/// `ArcSwap` pattern, since `AppState` is constructed before `XrmSystem`
/// (and therefore before `xrm-security`) exists.
#[derive(Clone)]
pub struct SecurityResolverHandle(Arc<ArcSwap<Arc<dyn SecurityResolver>>>);

impl std::fmt::Debug for SecurityResolverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityResolverHandle")
            .finish_non_exhaustive()
    }
}

impl SecurityResolverHandle {
    pub fn new(resolver: Arc<dyn SecurityResolver>) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(resolver)))
    }

    pub(crate) fn default_deny() -> Self {
        Self::new(Arc::new(DenyAllResolver))
    }

    /// Atomically replace the resolver — call once from `XrmSystemBuilder::build()`
    /// after `xrm-security`'s seed has run.
    pub fn store(&self, resolver: Arc<dyn SecurityResolver>) {
        self.0.store(Arc::new(resolver));
    }

    pub async fn resolve(&self, user_id: Uuid) -> Result<Arc<SecurityContext>, AppError> {
        let resolver = self.0.load_full();
        resolver.resolve(user_id).await
    }

    /// See `SecurityResolver::invalidate`.
    pub async fn invalidate(&self, user_id: Uuid) {
        let resolver = self.0.load_full();
        resolver.invalidate(user_id).await
    }

    /// See `SecurityResolver::resolve_strict`.
    pub async fn resolve_strict(&self, user_id: Uuid) -> Result<Arc<SecurityContext>, AppError> {
        let resolver = self.0.load_full();
        resolver.resolve_strict(user_id).await
    }

    /// See `SecurityResolver::invalidate_sync`.
    pub async fn invalidate_sync(&self, user_id: Uuid) -> Result<(), AppError> {
        let resolver = self.0.load_full();
        resolver.invalidate_sync(user_id).await
    }

    /// See `SecurityResolver::session_ip_allowlists`.
    pub async fn session_ip_allowlists(&self, user_id: Uuid) -> Result<Vec<Vec<String>>, AppError> {
        let resolver = self.0.load_full();
        resolver.session_ip_allowlists(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(privileges: &[&str], field_grants: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::new_v4(),
            is_admin: false,
            privileges: privileges.iter().map(|p| p.to_string()).collect(),
            field_grants: field_grants.iter().map(|f| f.to_string()).collect(),
            field_write_grants: HashSet::new(),
            bulk_fields: BulkFields::Legacy,
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: Some(Vec::new()),
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    #[test]
    fn fingerprint_stable_under_set_order() {
        let mut a = reader(
            &["deal.read", "deal.update", "account.read"],
            &["deal.margin"],
        );
        let mut b = reader(
            &["account.read", "deal.update", "deal.read"],
            &["deal.margin"],
        );
        b.epoch = 41;
        let team_a = Uuid::new_v4();
        let team_b = Uuid::new_v4();
        a.team_ids = vec![team_a, team_b];
        b.team_ids = vec![team_b, team_a];
        assert_eq!(
            a.permission_fingerprint(),
            b.permission_fingerprint(),
            "same permissions, different users, order and epoch"
        );
        assert_eq!(a.permission_fingerprint().len(), 64);
    }

    #[test]
    fn fingerprint_changes_with_field_grant() {
        let a = reader(&["deal.read"], &[]);
        let b = reader(&["deal.read"], &["deal.margin"]);
        assert_ne!(a.permission_fingerprint(), b.permission_fingerprint());
        let mut c = reader(&["deal.read"], &[]);
        c.field_write_grants.insert("deal.margin".into());
        assert_ne!(a.permission_fingerprint(), c.permission_fingerprint());
        let mut d = reader(&["deal.read"], &[]);
        d.team_ids.push(Uuid::new_v4());
        assert_ne!(
            a.permission_fingerprint(),
            d.permission_fingerprint(),
            "record-level reach counts"
        );
        let mut e = reader(&["deal.read"], &[]);
        e.role_ids = None;
        assert_ne!(a.permission_fingerprint(), e.permission_fingerprint());
    }

    struct AllowAllResolver;

    impl SecurityResolver for AllowAllResolver {
        fn resolve<'a>(
            &'a self,
            user_id: Uuid,
        ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>> {
            Box::pin(async move {
                Ok(Arc::new(SecurityContext {
                    user_id,
                    is_admin: true,
                    privileges: HashSet::from(["system.admin".to_owned()]),
                    field_grants: HashSet::new(),
                    field_write_grants: HashSet::new(),
                    bulk_fields: Default::default(),
                    epoch: 0,
                    accessible_org_ids: Vec::new(),
                    team_ids: Vec::new(),
                    position_hierarchy_enabled: false,
                    subordinate_user_ids: Vec::new(),
                    condition_grants: HashMap::new(),
                    role_ids: None,
                    unit_scope: Default::default(),
                    field_masks: Default::default(),
                    service_principal: false,
                }))
            })
        }

        fn invalidate<'a>(&'a self, _user_id: Uuid) -> BoxFuture<'a, ()> {
            Box::pin(async move {})
        }

        fn resolve_strict<'a>(
            &'a self,
            user_id: Uuid,
        ) -> BoxFuture<'a, Result<Arc<SecurityContext>, AppError>> {
            self.resolve(user_id)
        }

        fn invalidate_sync<'a>(&'a self, _user_id: Uuid) -> BoxFuture<'a, Result<(), AppError>> {
            Box::pin(async move { Ok(()) })
        }

        fn session_ip_allowlists<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> BoxFuture<'a, Result<Vec<Vec<String>>, AppError>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    fn ctx_with(is_admin: bool, privileges: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: privileges.iter().map(|p| (*p).to_owned()).collect(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    fn ceiling(keys: &[&str]) -> EntityCeiling {
        EntityCeiling::new(keys.iter().map(|k| (*k).to_owned()))
    }

    #[test]
    fn ceiling_drops_entity_privileges_it_does_not_allow() {
        let ctx = ctx_with(
            false,
            &[
                "account.read",
                "account.delete",
                "contact.update",
                "sidebar.manage",
            ],
        );
        let out = ceiling(&["account.read", "contact.read"]).apply(&ctx);
        assert!(!out.is_admin);
        assert_eq!(
            out.privileges,
            HashSet::from(["account.read".to_owned(), "sidebar.manage".to_owned()]),
            "the ceiling never grants contact.read the user lacked, and keeps non-entity keys"
        );
    }

    #[test]
    fn ceiling_turns_an_admin_into_exactly_the_ceiling() {
        let ctx = ctx_with(
            true,
            &[ADMIN_PRIVILEGE_KEY, "account.delete", "sidebar.manage"],
        );
        let out = ceiling(&["account.read"]).apply(&ctx);
        assert!(!out.is_admin);
        assert_eq!(
            out.privileges,
            HashSet::from(["account.read".to_owned(), "sidebar.manage".to_owned()]),
        );
    }

    #[test]
    fn empty_ceiling_allows_no_entity_privilege() {
        let out = ceiling(&[]).apply(&ctx_with(false, &["account.read", "report.run"]));
        assert_eq!(out.privileges, HashSet::from(["report.run".to_owned()]));
    }

    #[test]
    fn only_entity_verbs_are_governed() {
        let c = ceiling(&["system.admin", "account.bulk"]);
        assert!(c.allows("sidebar.manage"));
        assert!(c.allows("account.bulk"));
        assert!(!c.allows("account.read"));
        assert!(
            c.allows(".read"),
            "no entity part, so not an entity privilege"
        );
        assert!(
            !c.allowed.contains("system.admin"),
            "a non-entity key in the input is ignored, never granted"
        );
    }

    #[tokio::test]
    async fn default_deny_rejects_before_any_resolver_is_injected() {
        let handle = SecurityResolverHandle::default_deny();
        let result = handle.resolve(Uuid::now_v7()).await;
        assert!(matches!(result, Err(AppError::Forbidden)));
    }

    #[tokio::test]
    async fn default_deny_invalidate_is_a_harmless_no_op() {
        let handle = SecurityResolverHandle::default_deny();
        handle.invalidate(Uuid::now_v7()).await; // must not panic
    }

    #[tokio::test]
    async fn store_atomically_swaps_in_the_real_resolver() {
        let handle = SecurityResolverHandle::default_deny();
        let user_id = Uuid::now_v7();
        assert!(handle.resolve(user_id).await.is_err());

        handle.store(Arc::new(AllowAllResolver));

        let ctx = handle.resolve(user_id).await.unwrap();
        assert_eq!(ctx.user_id, user_id);
        assert!(ctx.is_admin);
    }

    // ── P-authz-revocation-epoch (D-116) ────────────────────────────────────

    #[tokio::test]
    async fn default_deny_resolve_strict_fails_closed() {
        let handle = SecurityResolverHandle::default_deny();
        let result = handle.resolve_strict(Uuid::now_v7()).await;
        assert!(matches!(result, Err(AppError::Forbidden)));
    }

    #[tokio::test]
    async fn default_deny_invalidate_sync_is_a_harmless_no_op() {
        let handle = SecurityResolverHandle::default_deny();
        let result = handle.invalidate_sync(Uuid::now_v7()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn resolve_strict_delegates_to_the_stored_resolver() {
        let handle = SecurityResolverHandle::default_deny();
        let user_id = Uuid::now_v7();
        handle.store(Arc::new(AllowAllResolver));

        let ctx = handle.resolve_strict(user_id).await.unwrap();
        assert_eq!(ctx.user_id, user_id);
        assert!(ctx.is_admin);
    }

    #[tokio::test]
    async fn invalidate_sync_delegates_to_the_stored_resolver() {
        let handle = SecurityResolverHandle::default_deny();
        handle.store(Arc::new(AllowAllResolver));
        assert!(handle.invalidate_sync(Uuid::now_v7()).await.is_ok());
    }
}

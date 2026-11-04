use std::future::Future;
use std::pin::Pin;

use attome_cache::Store;
use attome_db::DbPool;
use std::sync::Arc;

use attome_server::security::{SecurityContext, SecurityResolver};
use attome_types::AppError;
use uuid::Uuid;

use crate::cache::SecurityCache;

/// Return type for [`resolve_record_level_context`] — a named struct rather
/// than a positional tuple because this now carries three `Vec<Uuid>`-shaped
/// fields (`accessible_org_ids`, `team_ids`, `subordinate_user_ids`); a tuple
/// that size invites exactly the silent-transposition risk `rls::RlsBinds`
/// was already deliberately made a struct to avoid.
pub(crate) struct RecordLevelContext {
    pub accessible_org_ids: Vec<Uuid>,
    pub team_ids: Vec<Uuid>,
    pub position_hierarchy_enabled: bool,
    pub subordinate_user_ids: Vec<Uuid>,
    /// D-789 §4.3: the live roles held directly or through a team
    /// (`SecurityContext::role_ids`).
    pub role_ids: Vec<Uuid>,
    /// Q10-T2: where `BusinessUnit` depth excludes child units.
    pub unit_scope: attome_server::security::UnitScope,
}

/// F138 (and, historically, D-133): resolves `accessible_org_ids`/`team_ids`/
/// `position_hierarchy_enabled`/`subordinate_user_ids` (and, D-789, the
/// business-rule audience `role_ids`) — shared by
/// `resolve_uncached` and `SecurityCache::resolve_fresh` so both construction
/// sites stay in lockstep. Record-level depth itself is no longer resolved
/// here at all — it moved to per-`(entity, action)` resolution
/// (`crate::db::resolve_entity_access_level`), called directly by the
/// handlers that need it, since it can't be collapsed into one cached
/// scalar without reintroducing the cross-entity leak that motivated the
/// change (see that function's doc comment). `accessible_org_ids` is only
/// queried when `crate::db::any_role_uses_business_unit_scope` says at least
/// one held role might need it somewhere this cycle — a conservative,
/// existence-only gate now that depth is per-entity, but still cheaper than
/// unconditionally paying the recursive-CTE query for every caller.
/// `subordinate_user_ids` is likewise only queried when
/// `position_hierarchy_enabled` is true, same "don't pay for a tier this
/// caller doesn't use" reasoning.
pub(crate) async fn resolve_record_level_context(
    db: &DbPool,
    user_id: Uuid,
) -> Result<RecordLevelContext, AppError> {
    let team_ids = crate::db::resolve_team_ids(db, user_id).await?;
    let role_ids = crate::db::resolve_role_ids(db, user_id).await?;
    let uses_business_units = crate::db::any_role_uses_business_unit_scope(db, user_id).await?;
    let business_units = if uses_business_units {
        Some(crate::db::resolve_accessible_org_ids(db, user_id).await?)
    } else {
        None
    };
    // Q10-T2: the own units are only needed where some role turns child
    // units off.
    let own_units_only = if uses_business_units {
        crate::db::resolve_own_units_only(db, user_id).await?
    } else {
        Default::default()
    };
    // Q14-T2: a sharing rule may share with a unit's members. A31-T1: a
    // unit-owned entity's user and team levels reach the own units.
    let own_units = if own_units_only.is_empty()
        && !crate::sharing_rules::targets_units()
        && !crate::ownership::any_unit()
    {
        Vec::new()
    } else {
        crate::db::resolve_own_org_ids(db, user_id).await?
    };
    // U12-T1: a person confined to their companies filters on the
    // companies' organisations (their own business units inside them, when
    // a role already scopes them that way).
    let (accessible_org_ids, own_org_ids) =
        match crate::company_walls::confinement(db, user_id).await? {
            Some(companies) => {
                let company = crate::company_walls::company_org_ids(db, &companies).await?;
                (
                    crate::company_walls::walled_org_ids(business_units.as_deref(), &company),
                    crate::company_walls::walled_org_ids(Some(&own_units), &company),
                )
            }
            None => (business_units.unwrap_or_default(), own_units),
        };
    let position_hierarchy_enabled =
        crate::db::resolve_position_hierarchy_enabled(db, user_id).await?;
    let subordinate_user_ids = if position_hierarchy_enabled {
        crate::db::resolve_subordinate_user_ids(db, user_id).await?
    } else {
        Vec::new()
    };
    // A17-T3: the subtree a role's owner arm reaches, only when some role
    // turns it on. Kept apart from `subordinate_user_ids`, which also widens
    // shares (F138) and stays tied to `position_hierarchy_enabled`.
    let owner_subtree = crate::db::resolve_owner_subtree(db, user_id).await?;
    let subtree_user_ids = if owner_subtree.is_empty() {
        Vec::new()
    } else if position_hierarchy_enabled {
        subordinate_user_ids.clone()
    } else {
        crate::db::resolve_subordinate_user_ids(db, user_id).await?
    };
    Ok(RecordLevelContext {
        accessible_org_ids,
        team_ids,
        position_hierarchy_enabled,
        subordinate_user_ids,
        role_ids,
        unit_scope: attome_server::security::UnitScope {
            own_org_ids,
            own_units_only,
            owner_subtree,
            subtree_user_ids,
        },
    })
}

/// Resolves authorization directly from PostgreSQL without either the local
/// moka cache or Redis.  Long-running workers use this at the start of a job
/// so a recently revoked privilege cannot remain effective on a warm app
/// node (the normal request path continues to use `EngineSecurityResolver`).
pub async fn resolve_uncached(db: &DbPool, user_id: Uuid) -> Result<SecurityContext, AppError> {
    let privileges = crate::db::resolve_privileges(db, user_id).await?;
    let (field_grants, field_write_grants, field_masks) =
        crate::db::resolve_field_access(db, user_id).await?;
    let bulk_fields = crate::db::resolve_bulk_fields(db, user_id).await?;
    let rlc = resolve_record_level_context(db, user_id).await?;
    let condition_grants = crate::db::resolve_condition_grants(db, user_id).await?;
    // `human` sets `is_admin` from the reserved admin key, as the cached
    // path does. The epoch stays 0: this path bypasses every cache layer
    // (L1/L2 and the epoch check alike) and always reads Postgres directly,
    // so it's already maximally fresh — the epoch is only meaningful as a
    // staleness marker for a *cached* value, which this never is.
    let mut ctx = SecurityContext::human(user_id, privileges);
    ctx.field_grants = field_grants;
    ctx.field_write_grants = field_write_grants;
    ctx.field_masks = field_masks;
    ctx.field_read_conditions =
        crate::db::resolve_field_read_conditions(db, user_id, &ctx.field_grants).await?;
    ctx.bulk_fields = bulk_fields;
    ctx.accessible_org_ids = rlc.accessible_org_ids;
    ctx.team_ids = rlc.team_ids;
    ctx.position_hierarchy_enabled = rlc.position_hierarchy_enabled;
    ctx.subordinate_user_ids = rlc.subordinate_user_ids;
    ctx.condition_grants = condition_grants;
    // D-789 §4.3: a resolved user is never a system writer.
    ctx.role_ids = Some(rlc.role_ids);
    ctx.unit_scope = rlc.unit_scope;
    // AH3-T5: an agent holds no more than its sponsor.
    if let Some(facts) = crate::agent_scope::agent_facts(db, user_id).await? {
        crate::agent_scope::narrow(db, &mut ctx, &facts).await?;
    }
    Ok(ctx)
}

/// The real `SecurityResolver` — injected into `attome_server::AppState` by
/// `EngineSystemBuilder::build()` once the bootstrap-admin seed has run.
pub struct EngineSecurityResolver {
    cache: SecurityCache,
    /// P-record-level-security item (b), implemented as a mode of this
    /// plan's epoch mechanism rather than a second implementation
    /// (`security.strict_revocation`, default true, and required true under
    /// `app.deployment_profile = "production"` per D-233):
    /// when true, every `resolve()` — not just the privileged-bundle class
    /// `resolve_strict` otherwise reserves this for — pays the fail-closed
    /// epoch re-check.
    strict_revocation: bool,
}

impl std::fmt::Debug for EngineSecurityResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineSecurityResolver")
            .finish_non_exhaustive()
    }
}

impl EngineSecurityResolver {
    pub fn new(
        db: DbPool,
        redis: Store,
        redis_coordination: Store,
        strict_revocation: bool,
    ) -> Self {
        Self {
            cache: SecurityCache::new(db, redis, redis_coordination),
            strict_revocation,
        }
    }

    /// L1-only invalidation for a REMOTE node's revoke, delivered via the
    /// `security_version` pub/sub doorbell (D-051) — see
    /// `attome-server/src/system.rs`'s subscriber and `SecurityCache::invalidate_local`.
    pub async fn invalidate_local(&self, user_id: Uuid) {
        self.cache.invalidate_local(user_id).await;
    }
}

impl SecurityResolver for EngineSecurityResolver {
    fn resolve<'a>(
        &'a self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<SecurityContext>, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if self.strict_revocation {
                self.cache.resolve_strict(user_id).await
            } else {
                self.cache.resolve(user_id).await
            }
        })
    }

    fn invalidate<'a>(&'a self, user_id: Uuid) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move { self.cache.invalidate(user_id).await })
    }

    fn resolve_strict<'a>(
        &'a self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<SecurityContext>, AppError>> + Send + 'a>> {
        Box::pin(async move { self.cache.resolve_strict(user_id).await })
    }

    fn invalidate_sync<'a>(
        &'a self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move { self.cache.invalidate_sync(user_id).await })
    }

    /// The IP allow-lists of the restrictive roles `user_id` holds, uncached
    /// so a role edit applies to the next request.
    fn session_ip_allowlists<'a>(
        &'a self,
        user_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<String>>, AppError>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query_scalar(
                "SELECT r.ip_allowlist
                 FROM user_account_mm_role ur
                 JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false
                 WHERE ur.user_ref = $1 AND ur.is_deleted = false
                   AND r.ip_allowlist IS NOT NULL AND array_length(r.ip_allowlist, 1) > 0",
            )
            .bind(user_id)
            .fetch_all(self.cache.db())
            .await
            .map_err(AppError::internal)
        })
    }
}

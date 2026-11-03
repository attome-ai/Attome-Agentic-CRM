//! AH3-T5: what an agent principal may do — never more than its sponsor.
//!
//! An agent account (`principal_kind` 2) resolves its own grants as anyone
//! does; then [`narrow`] keeps only what its sponsor also holds (privileges,
//! field read and write grants: an intersection, never a union), adds the
//! sponsor's field masks, drops `system.admin`, and, when the agent has an
//! entity scope, every privilege and field grant of an entity outside it.
//! The resolution fails closed (`Forbidden`) unless the agent is `active`
//! and its sponsor an active person. Record-level narrowing waits for the
//! staff-identity work (D-590): the agent's own record scope applies.
//!
//! The resolved context names the sponsor and the sponsor's epoch in its
//! `chain`, so a cached agent context is re-resolved when the sponsor's
//! grants or account change ([`crate::cache::SecurityCache::resolve_strict`]).

use std::collections::{HashMap, HashSet};

use attome_db::DbPool;
use attome_server::security::{ADMIN_PRIVILEGE_KEY, SecurityContext};
use attome_types::AppError;
use uuid::Uuid;

/// `user_account.principal_kind` of an agent.
const AGENT_KIND: i16 = 2;

/// What narrowing an agent reads about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentFacts {
    pub sponsor: Uuid,
    pub entity_scope: Option<Vec<String>>,
}

/// The agent facts of `user_id`: `None` for anyone who is not an agent,
/// `Forbidden` for an agent that may not act now (not active, no principal
/// row, or a sponsor who is not an active person).
pub async fn agent_facts(db: &DbPool, user_id: Uuid) -> Result<Option<AgentFacts>, AppError> {
    type Row = (
        i16,
        Option<String>,
        Option<Uuid>,
        Option<Vec<String>>,
        Option<bool>,
        Option<i16>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT u.principal_kind, a.lifecycle_state, a.sponsor_user_ref, a.entity_scope, \
                s.is_active, s.principal_kind \
           FROM user_account u \
           LEFT JOIN agent_principal a ON a.user_ref = u.id \
           LEFT JOIN user_account s ON s.id = a.sponsor_user_ref \
          WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((kind, state, sponsor, scope, sponsor_active, sponsor_kind)) = row else {
        return Ok(None);
    };
    if kind != AGENT_KIND {
        return Ok(None);
    }
    match (state.as_deref(), sponsor, sponsor_active, sponsor_kind) {
        (Some("active"), Some(sponsor), Some(true), Some(0)) => Ok(Some(AgentFacts {
            sponsor,
            entity_scope: scope,
        })),
        _ => {
            tracing::warn!(
                %user_id,
                state = state.as_deref().unwrap_or("none"),
                "an agent principal that may not act now was refused"
            );
            Err(AppError::Forbidden)
        }
    }
}

/// The entity a privilege or field-grant key names (`account.read`,
/// `account.credit_limit` → `account`). Pure.
fn entity_of(key: &str) -> &str {
    key.split_once('.').map_or(key, |(entity, _)| entity)
}

/// `own` ∩ `sponsor`, then only the entities in `scope` when given. Pure.
pub fn intersect(
    own: &HashSet<String>,
    sponsor: &HashSet<String>,
    scope: Option<&[String]>,
) -> HashSet<String> {
    own.iter()
        .filter(|k| sponsor.contains(*k))
        .filter(|k| k.as_str() != ADMIN_PRIVILEGE_KEY)
        .filter(|k| scope.is_none_or(|s| s.iter().any(|e| e == entity_of(k))))
        .cloned()
        .collect()
}

/// The sponsor's grants, as the agent's narrowing needs them.
pub struct SponsorGrants {
    pub privileges: HashSet<String>,
    pub field_grants: HashSet<String>,
    pub field_write_grants: HashSet<String>,
    pub field_masks: HashMap<String, String>,
}

/// Narrows `ctx` (an agent's own resolution) to `sponsor`. Pure.
pub fn apply(ctx: &mut SecurityContext, sponsor: &SponsorGrants, scope: Option<&[String]>) {
    ctx.privileges = intersect(&ctx.privileges, &sponsor.privileges, scope);
    ctx.field_grants = intersect(&ctx.field_grants, &sponsor.field_grants, scope);
    ctx.field_write_grants = intersect(&ctx.field_write_grants, &sponsor.field_write_grants, scope);
    // A field masked for the sponsor stays masked for its agent.
    for (field, mask) in &sponsor.field_masks {
        ctx.field_masks
            .entry(field.clone())
            .or_insert_with(|| mask.clone());
    }
    ctx.is_admin = false;
}

/// Narrows `ctx`, an agent's own resolution, to its sponsor's grants and
/// its scope (`facts` from [`agent_facts`]).
pub async fn narrow(
    db: &DbPool,
    ctx: &mut SecurityContext,
    facts: &AgentFacts,
) -> Result<(), AppError> {
    let privileges = crate::db::resolve_privileges(db, facts.sponsor).await?;
    let (field_grants, field_write_grants, field_masks) =
        crate::db::resolve_field_access(db, facts.sponsor).await?;
    apply(
        ctx,
        &SponsorGrants {
            privileges,
            field_grants,
            field_write_grants,
            field_masks,
        },
        facts.entity_scope.as_deref(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|k| (*k).to_owned()).collect()
    }

    fn agent(privileges: &[&str]) -> SecurityContext {
        SecurityContext::human(Uuid::now_v7(), set(privileges))
    }

    fn sponsor(privileges: &[&str]) -> SponsorGrants {
        SponsorGrants {
            privileges: set(privileges),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            field_masks: HashMap::new(),
        }
    }

    #[test]
    fn agent_principal_holds_only_what_both_hold() {
        let mut ctx = agent(&["account.read", "invoice.read"]);
        apply(&mut ctx, &sponsor(&["account.read", "contact.read"]), None);
        // Both: allowed. Agent only (invoice) and sponsor only (contact): refused.
        assert_eq!(ctx.privileges, set(&["account.read"]));
    }

    #[test]
    fn agent_principal_outside_its_scope_is_refused() {
        let mut ctx = agent(&["account.read", "contact.read"]);
        ctx.field_grants = set(&["account.credit_limit", "contact.phone"]);
        let mut sp = sponsor(&["account.read", "contact.read"]);
        sp.field_grants = set(&["account.credit_limit", "contact.phone"]);
        apply(&mut ctx, &sp, Some(&["account".to_owned()]));
        assert_eq!(ctx.privileges, set(&["account.read"]));
        assert_eq!(ctx.field_grants, set(&["account.credit_limit"]));
    }

    #[test]
    fn agent_principal_is_never_admin_and_keeps_its_sponsors_masks() {
        let mut ctx = agent(&["system.admin", "account.read"]);
        assert!(ctx.is_admin);
        let mut sp = sponsor(&["system.admin", "account.read"]);
        sp.field_masks
            .insert("contact.national_id".into(), "last4".into());
        apply(&mut ctx, &sp, None);
        assert!(!ctx.is_admin);
        assert_eq!(ctx.privileges, set(&["account.read"]));
        assert_eq!(
            ctx.field_masks
                .get("contact.national_id")
                .map(String::as_str),
            Some("last4")
        );
    }
}

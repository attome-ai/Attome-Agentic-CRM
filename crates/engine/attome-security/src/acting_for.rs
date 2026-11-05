//! Z4-T8 (V2-D1812): an agent acting for a user (the RFC 8693 `act` claim
//! of an agent session token) gets only what both of them may do.
//!
//! The owner's rule (2026-11-05): the records are reached through the
//! user's own teams, units, subordinates and ownership; privileges, field
//! read and write grants are the intersection of both principals' (AH3-T5's
//! [`crate::agent_scope::apply`]), the field masks of either apply, a grant
//! condition of either must hold, each entity's record access level is the
//! lower of the two, and the result is never an administrator. Never a
//! union.
//!
//! Levels are read per request from a user id
//! ([`crate::db::resolve_entity_access_level`] and
//! [`crate::db::resolve_all_entity_access_levels`]), so the agent's cap is
//! ambient: a request served for an agent acting for a user runs inside
//! [`scope`], and those two lower each level to the agent's own while it is
//! set.

use std::collections::HashMap;
use std::future::Future;

use attome_db::DbPool;
use attome_server::security::{AccessLevel, GrantCondition, SecurityContext};
use attome_types::AppError;
use uuid::Uuid;

tokio::task_local! {
    static ACTING_AGENT: Uuid;
}

/// Runs `f` as `agent` acting for the request's user: every record access
/// level resolved inside is capped at the agent's own.
pub async fn scope<F: Future>(agent: Uuid, f: F) -> F::Output {
    ACTING_AGENT.scope(agent, f).await
}

/// The agent the current task acts as, when inside [`scope`].
pub fn acting_agent() -> Option<Uuid> {
    ACTING_AGENT.try_with(|agent| *agent).ok()
}

/// The lower of two access levels: an agent never reaches further than the
/// user it acts for, nor further than itself. Pure.
pub fn lower(a: AccessLevel, b: AccessLevel) -> AccessLevel {
    std::cmp::min(a, b)
}

/// `user`'s grant conditions with `agent`'s added: for a privilege both
/// condition, every pairing of an AND-set of each (so both hold); for a
/// privilege only one conditions, that one's. A privilege neither
/// conditions stays unconditional. Pure.
pub fn both_conditions(
    user: &HashMap<String, Vec<Vec<GrantCondition>>>,
    agent: &HashMap<String, Vec<Vec<GrantCondition>>>,
) -> HashMap<String, Vec<Vec<GrantCondition>>> {
    let mut out = user.clone();
    for (key, agent_sets) in agent {
        match out.get(key) {
            Some(user_sets) => {
                let paired: Vec<Vec<GrantCondition>> = user_sets
                    .iter()
                    .flat_map(|u| {
                        agent_sets
                            .iter()
                            .map(move |a| u.iter().chain(a.iter()).cloned().collect::<Vec<_>>())
                    })
                    .collect();
                out.insert(key.clone(), paired);
            }
            None => {
                out.insert(key.clone(), agent_sets.clone());
            }
        }
    }
    out
}

/// Narrows `user_ctx` (the user's own resolution) to `agent_ctx` (the
/// agent's): the user's record reach, the intersection of grants, both
/// principals' masks and conditions, never admin. Pure.
pub fn narrow_to_agent(user_ctx: &mut SecurityContext, agent_ctx: &SecurityContext) {
    crate::agent_scope::apply(
        user_ctx,
        &crate::agent_scope::SponsorGrants {
            privileges: agent_ctx.privileges.clone(),
            field_grants: agent_ctx.field_grants.clone(),
            field_write_grants: agent_ctx.field_write_grants.clone(),
            field_masks: agent_ctx.field_masks.clone(),
            field_read_conditions: agent_ctx.field_read_conditions.clone(),
        },
        None,
    );
    user_ctx.condition_grants =
        both_conditions(&user_ctx.condition_grants, &agent_ctx.condition_grants);
}

/// The context of `agent` acting for `on_behalf_of`, resolved from
/// PostgreSQL. The request then runs inside [`scope`]`(agent, ..)` so its
/// record access levels are capped too.
pub async fn resolve_for_agent(
    db: &DbPool,
    agent: Uuid,
    on_behalf_of: Uuid,
) -> Result<SecurityContext, AppError> {
    let mut ctx = crate::resolver::resolve_uncached(db, on_behalf_of).await?;
    let agent_ctx = crate::resolver::resolve_uncached(db, agent).await?;
    narrow_to_agent(&mut ctx, &agent_ctx);
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn ctx(user: Uuid, privileges: &[&str], fields: &[&str]) -> SecurityContext {
        let mut ctx =
            SecurityContext::human(user, privileges.iter().map(|p| (*p).to_owned()).collect());
        ctx.field_grants = fields.iter().map(|f| (*f).to_owned()).collect();
        ctx
    }

    #[test]
    fn agent_context_is_intersection_of_levels() {
        assert_eq!(
            lower(AccessLevel::Global, AccessLevel::Team),
            AccessLevel::Team
        );
        assert_eq!(
            lower(AccessLevel::None, AccessLevel::BusinessUnit),
            AccessLevel::None
        );
        let user = Uuid::now_v7();
        let mut user_ctx = ctx(
            user,
            &["account.read", "account.update", "lead.read"],
            &["account.credit_limit", "lead.score"],
        );
        user_ctx.team_ids = vec![Uuid::now_v7()];
        let agent_ctx = ctx(
            Uuid::now_v7(),
            &["account.read", "lead.read", "opportunity.read"],
            &["account.credit_limit"],
        );
        let teams = user_ctx.team_ids.clone();
        narrow_to_agent(&mut user_ctx, &agent_ctx);
        let want: HashSet<String> = ["account.read", "lead.read"]
            .iter()
            .map(|p| (*p).to_owned())
            .collect();
        assert_eq!(user_ctx.privileges, want);
        assert_eq!(
            user_ctx.field_grants,
            HashSet::from(["account.credit_limit".to_owned()])
        );
        // The records are still the user's to reach.
        assert_eq!(user_ctx.user_id, user);
        assert_eq!(user_ctx.team_ids, teams);
    }

    #[test]
    fn agent_never_gains_admin_from_user() {
        let admin = attome_server::security::ADMIN_PRIVILEGE_KEY;
        let mut user_ctx = ctx(Uuid::now_v7(), &[admin, "account.read"], &[]);
        assert!(user_ctx.is_admin);
        let agent_ctx = ctx(Uuid::now_v7(), &["account.read"], &[]);
        narrow_to_agent(&mut user_ctx, &agent_ctx);
        assert!(!user_ctx.is_admin);
        assert!(!user_ctx.privileges.contains(admin));
        // Not even when both are administrators.
        let mut both = ctx(Uuid::now_v7(), &[admin], &[]);
        narrow_to_agent(&mut both, &ctx(Uuid::now_v7(), &[admin], &[]));
        assert!(!both.is_admin);
    }

    #[test]
    fn the_agent_scope_is_ambient_only_inside() {
        let agent = Uuid::now_v7();
        assert_eq!(acting_agent(), None);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let seen = rt.block_on(scope(agent, async { acting_agent() }));
        assert_eq!(seen, Some(agent));
        assert_eq!(acting_agent(), None);
    }
}

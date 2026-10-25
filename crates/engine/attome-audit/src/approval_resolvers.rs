//! Z10-T6: approver tokens resolve through a registry of resolvers, one per
//! token prefix, instead of hard-coded parsing.
//!
//! A token is `<prefix>` or `<prefix>:<rest>`. Built in:
//!
//! - `user:<uuid>`, `role:<uuid>`, `team:<uuid>`: that user, or every active
//!   member of the role or team.
//! - `position:manager_of_requester`: whoever holds the parent position of a
//!   position the requester holds.
//! - `owner`: the owner of the record the request is about.
//! - `owner_manager`, `manager_chain:<n>` (n in 1..=5): whoever holds the
//!   position 1 (or n) levels above a position the record's owner holds.
//! - `attribute:<logical_name>`: the user a lookup field of the record names;
//!   the field must be a lookup to `user_account`.
//!
//! Another engine adds a resolver with [`install_extra`] at boot (the
//! `queue:<uuid>` resolver lives in attome-api, so this crate never depends
//! on attome-service). The registry is built once and never changes after,
//! so every node holds the same one.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use attome_approval::ApprovalRequest;
use attome_core::{EngineState, FieldType, quote_ident};
use attome_types::AppError;
use uuid::Uuid;

/// What a resolver may read about the request being decided.
#[derive(Debug, Clone, Copy)]
pub struct ResolveCtx<'a> {
    pub requested_by: Uuid,
    pub regarding_entity: Option<&'a str>,
    pub regarding_id: Option<Uuid>,
    pub action_type: &'a str,
}

impl<'a> ResolveCtx<'a> {
    /// The context of `request`.
    pub fn of(request: &'a ApprovalRequest) -> Self {
        Self {
            requested_by: request.requested_by,
            regarding_entity: request.regarding_entity.as_deref(),
            regarding_id: request.regarding_id,
            action_type: &request.action_type,
        }
    }
}

/// The future a resolver returns.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Uuid>, AppError>> + Send + 'a>>;

/// Turns one kind of approver token into user ids.
pub trait ApproverResolver: Send + Sync {
    /// The token's prefix: `"user"` matches `user:<rest>`, `"owner"` matches
    /// the bare token `owner`.
    fn prefix(&self) -> &'static str;
    /// Whether `rest` (the text after `prefix:`, empty for a bare token) is
    /// a token this resolver can resolve. Checked when a plan is saved.
    fn validate(&self, rest: &str) -> Result<(), AppError>;
    /// The users `rest` names for this request.
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a>;
}

/// The resolvers, looked up by token prefix.
#[derive(Default, Clone)]
pub struct ResolverRegistry(Vec<Arc<dyn ApproverResolver>>);

impl std::fmt::Debug for ResolverRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolverRegistry")
            .field("resolvers", &self.0.len())
            .finish()
    }
}

impl ResolverRegistry {
    /// The built-in resolvers.
    pub fn builtin() -> Self {
        let mut registry = Self::default();
        registry.register(Arc::new(UserResolver));
        registry.register(Arc::new(MembershipResolver::ROLE));
        registry.register(Arc::new(MembershipResolver::TEAM));
        registry.register(Arc::new(PositionResolver));
        registry.register(Arc::new(OwnerResolver));
        registry.register(Arc::new(OwnerManagerResolver));
        registry.register(Arc::new(ManagerChainResolver));
        registry.register(Arc::new(AttributeResolver));
        registry
    }

    /// Add `resolver`; a later one with the same prefix wins.
    pub fn register(&mut self, resolver: Arc<dyn ApproverResolver>) {
        self.0.retain(|r| r.prefix() != resolver.prefix());
        self.0.push(resolver);
    }

    /// The resolver for `token` and the rest of the token after its prefix.
    pub fn lookup<'t>(&self, token: &'t str) -> Option<(&Arc<dyn ApproverResolver>, &'t str)> {
        let (prefix, rest) = token.split_once(':').unwrap_or((token, ""));
        self.0
            .iter()
            .find(|r| r.prefix() == prefix)
            .map(|r| (r, rest))
    }

    /// Every prefix, for error messages.
    pub fn prefixes(&self) -> Vec<&'static str> {
        self.0.iter().map(|r| r.prefix()).collect()
    }
}

static REGISTRY: OnceLock<ResolverRegistry> = OnceLock::new();

/// Add resolvers from another engine to the registry. Call at boot, before
/// the first approval is resolved: the registry is fixed on first use, so a
/// later call changes nothing. Returns whether every prefix in `extra` is
/// in the registry afterwards (a repeat of the same boot call is `true`).
pub fn install_extra(extra: Vec<Arc<dyn ApproverResolver>>) -> bool {
    let prefixes: Vec<&'static str> = extra.iter().map(|r| r.prefix()).collect();
    let mut registry = ResolverRegistry::builtin();
    for resolver in extra {
        registry.register(resolver);
    }
    let _ = REGISTRY.set(registry);
    let installed = self::registry().prefixes();
    prefixes.iter().all(|p| installed.contains(p))
}

/// The process's registry: the built-ins plus whatever [`install_extra`]
/// added.
pub fn registry() -> &'static ResolverRegistry {
    REGISTRY.get_or_init(ResolverRegistry::builtin)
}

fn uuid_rest(prefix: &str, rest: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(rest).map_err(|_| {
        AppError::Validation(format!(
            "invalid approver token \"{prefix}:{rest}\": {prefix}: must be followed by a uuid"
        ))
    })
}

fn bare(prefix: &str, rest: &str) -> Result<(), AppError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "invalid approver token \"{prefix}:{rest}\": {prefix} takes nothing after it"
        )))
    }
}

async fn user_ids(state: &EngineState, sql: &str, bind: Uuid) -> Result<Vec<Uuid>, AppError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(sql)
        .bind(bind)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

struct UserResolver;

impl ApproverResolver for UserResolver {
    fn prefix(&self) -> &'static str {
        "user"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        uuid_rest("user", rest).map(|_| ())
    }
    fn resolve<'a>(
        &'a self,
        _state: &'a EngineState,
        rest: &'a str,
        _ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(Uuid::parse_str(rest).into_iter().collect()) })
    }
}

/// `role:` and `team:`: every active member.
struct MembershipResolver {
    prefix: &'static str,
    sql: &'static str,
}

impl MembershipResolver {
    const ROLE: Self = Self {
        prefix: "role",
        sql: "SELECT ur.user_ref FROM user_account_mm_role ur \
                  JOIN user_account u ON u.id = ur.user_ref \
                  WHERE ur.role_ref = $1 AND ur.is_deleted = false \
                    AND (u.is_active IS NULL OR u.is_active = TRUE)",
    };
    const TEAM: Self = Self {
        prefix: "team",
        sql: "SELECT tm.user_ref FROM user_account_mm_team tm \
                  JOIN user_account u ON u.id = tm.user_ref \
                  WHERE tm.team_ref = $1 AND tm.is_deleted = false \
                    AND (u.is_active IS NULL OR u.is_active = TRUE)",
    };
}

impl ApproverResolver for MembershipResolver {
    fn prefix(&self) -> &'static str {
        self.prefix
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        uuid_rest(self.prefix, rest).map(|_| ())
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        _ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            match Uuid::parse_str(rest) {
                Ok(id) => user_ids(state, self.sql, id).await,
                Err(_) => Ok(Vec::new()),
            }
        })
    }
}

/// Users holding a position `levels` above any position `user` holds.
/// Dual-hatting means more than one such user is possible; a user holding
/// no position, or only positions too near the root, resolves to no one.
async fn managers_of(state: &EngineState, user: Uuid, levels: i32) -> Result<Vec<Uuid>, AppError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "WITH RECURSIVE up(position_ref, depth) AS ( \
             SELECT pos.parent_position_ref, 1 \
               FROM user_account_mm_position held \
               JOIN position pos ON pos.id = held.position_ref AND pos.is_deleted = false \
              WHERE held.user_ref = $1 AND held.is_deleted = false \
                AND pos.parent_position_ref IS NOT NULL \
             UNION \
             SELECT pos.parent_position_ref, up.depth + 1 \
               FROM up JOIN position pos ON pos.id = up.position_ref AND pos.is_deleted = false \
              WHERE up.depth < $2 AND pos.parent_position_ref IS NOT NULL \
         ) \
         SELECT DISTINCT mgr.user_ref \
           FROM up \
           JOIN user_account_mm_position mgr \
             ON mgr.position_ref = up.position_ref AND mgr.is_deleted = false \
           JOIN user_account u ON u.id = mgr.user_ref \
          WHERE up.depth = $2 AND (u.is_active IS NULL OR u.is_active = TRUE)",
    )
    .bind(user)
    .bind(levels)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

struct PositionResolver;

impl ApproverResolver for PositionResolver {
    fn prefix(&self) -> &'static str {
        "position"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        if rest == "manager_of_requester" {
            Ok(())
        } else {
            Err(AppError::Validation(format!(
                "unsupported approver token \"position:{rest}\": the one position token is \
                 \"{}\"",
                crate::approval::POSITION_MANAGER_OF_REQUESTER
            )))
        }
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            if rest != "manager_of_requester" {
                return Ok(Vec::new());
            }
            managers_of(state, ctx.requested_by, 1).await
        })
    }
}

/// The value of user-lookup column `column` on the request's record, or
/// `None` when the request is about no record or the record is gone. The
/// entity is looked up in the metadata registry and its name quoted.
async fn record_user(
    state: &EngineState,
    ctx: &ResolveCtx<'_>,
    column: &str,
) -> Result<Option<Uuid>, AppError> {
    let (Some(entity), Some(id)) = (ctx.regarding_entity, ctx.regarding_id) else {
        return Ok(None);
    };
    // Checked and dropped before the query: the registry guard is not held
    // across an await.
    if state.entities.load().get(entity).is_none() {
        return Ok(None);
    }
    let sql = format!(
        "SELECT {} FROM {} WHERE id = $1",
        quote_ident(column),
        quote_ident(entity)
    );
    let value: Option<Option<Uuid>> = sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(value.flatten())
}

struct OwnerResolver;

impl ApproverResolver for OwnerResolver {
    fn prefix(&self) -> &'static str {
        "owner"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        bare("owner", rest)
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        _rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            Ok(record_user(state, ctx, "owner_ref")
                .await?
                .into_iter()
                .collect())
        })
    }
}

struct OwnerManagerResolver;

impl ApproverResolver for OwnerManagerResolver {
    fn prefix(&self) -> &'static str {
        "owner_manager"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        bare("owner_manager", rest)
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        _rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            match record_user(state, ctx, "owner_ref").await? {
                Some(owner) => managers_of(state, owner, 1).await,
                None => Ok(Vec::new()),
            }
        })
    }
}

/// The most levels `manager_chain:<n>` may climb.
pub const MAX_MANAGER_CHAIN: i32 = 5;

struct ManagerChainResolver;

fn chain_levels(rest: &str) -> Result<i32, AppError> {
    rest.parse::<i32>()
        .ok()
        .filter(|n| (1..=MAX_MANAGER_CHAIN).contains(n))
        .ok_or_else(|| {
            AppError::Validation(format!(
                "invalid approver token \"manager_chain:{rest}\": the level is 1 to \
                 {MAX_MANAGER_CHAIN}"
            ))
        })
}

impl ApproverResolver for ManagerChainResolver {
    fn prefix(&self) -> &'static str {
        "manager_chain"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        chain_levels(rest).map(|_| ())
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let Ok(levels) = chain_levels(rest) else {
                return Ok(Vec::new());
            };
            match record_user(state, ctx, "owner_ref").await? {
                Some(owner) => managers_of(state, owner, levels).await,
                None => Ok(Vec::new()),
            }
        })
    }
}

struct AttributeResolver;

/// Whether `field` of `entity` is a lookup to `user_account`.
pub fn is_user_lookup(state: &EngineState, entity: &str, field: &str) -> bool {
    let registry = state.entities.load();
    let Some(users) = registry.get("user_account").map(|m| m.entity_id) else {
        return false;
    };
    registry.get(entity).is_some_and(|meta| {
        meta.attrs.iter().any(|a| {
            a.logicalname == field
                && a.field_type() == FieldType::Lookup
                && a.lookup_entity_ref == Some(users)
        })
    })
}

fn valid_field_name(rest: &str) -> bool {
    !rest.is_empty()
        && rest.len() <= 63
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl ApproverResolver for AttributeResolver {
    fn prefix(&self) -> &'static str {
        "attribute"
    }
    fn validate(&self, rest: &str) -> Result<(), AppError> {
        if valid_field_name(rest) {
            Ok(())
        } else {
            Err(AppError::Validation(format!(
                "invalid approver token \"attribute:{rest}\": attribute: must be followed by a \
                 field's logical name"
            )))
        }
    }
    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            // The field must exist in the metadata and name a user; anything
            // else resolves to no one rather than reading an arbitrary column.
            let Some(entity) = ctx.regarding_entity else {
                return Ok(Vec::new());
            };
            if !is_user_lookup(state, entity, rest) {
                return Ok(Vec::new());
            }
            Ok(record_user(state, ctx, rest).await?.into_iter().collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_splits_on_the_first_colon() {
        let registry = ResolverRegistry::builtin();
        let (r, rest) = registry.lookup("manager_chain:2").unwrap();
        assert_eq!((r.prefix(), rest), ("manager_chain", "2"));
        let (r, rest) = registry.lookup("owner").unwrap();
        assert_eq!((r.prefix(), rest), ("owner", ""));
        assert!(registry.lookup("queue:x").is_none());
    }

    #[test]
    fn builtin_tokens_validate() {
        let registry = ResolverRegistry::builtin();
        let check = |token: &str| {
            let (r, rest) = registry.lookup(token).expect("known prefix");
            r.validate(rest)
        };
        assert!(check(&format!("user:{}", Uuid::now_v7())).is_ok());
        assert!(check("user:nope").is_err());
        assert!(check("position:manager_of_requester").is_ok());
        assert!(check("position:ceo").is_err());
        assert!(check("owner").is_ok());
        assert!(check("owner:x").is_err());
        assert!(check("owner_manager").is_ok());
        assert!(check("manager_chain:5").is_ok());
        assert!(check("manager_chain:6").is_err());
        assert!(check("manager_chain:0").is_err());
        assert!(check("attribute:account_manager_ref").is_ok());
        assert!(check("attribute:x;drop").is_err());
    }
}

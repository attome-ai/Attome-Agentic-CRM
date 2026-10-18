//! The caller's record scope on an entity, for billing's own reads: the
//! same condition-aware predicate the generic record reads apply (tier,
//! shares, the owner arm of D-371 and the conditional grants of D-369),
//! never the plain tier predicate, which drops the last two.

use attome_core::EngineState;
use attome_security::{
    ConditionAwarePredicate, RecordAction, SecurityContextExt, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::security::SecurityContext;
use attome_types::AppError;

/// The read scope of `entity` on `alias`, with placeholders from
/// `first_placeholder`. `None` reads every row; the caller must hold
/// `{entity}.read` (`403` otherwise).
pub(crate) async fn read_scope(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    alias: &str,
    first_placeholder: usize,
) -> Result<Option<ConditionAwarePredicate>, AppError> {
    ctx.require(entity, "read")?;
    let meta = state
        .entities
        .load()
        .get(entity)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let db = &state.base.db;
    let level =
        resolve_entity_access_level(db, ctx.user_id, meta.entity_id, entity, RecordAction::Read)
            .await?;
    let owner_visible =
        resolve_owner_visible(db, ctx.user_id, meta.entity_id, entity, RecordAction::Read).await?;
    Ok(rls_predicate_with_conditions(
        ctx,
        meta.entity_id,
        alias,
        level,
        RecordAction::Read.share_capability(),
        &format!("{entity}.read"),
        &meta.attrs,
        owner_visible,
        first_placeholder,
    ))
}

/// Binds a scope's values after the query's own.
pub(crate) fn bind_scope<'q, O>(
    mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    scope: &'q Option<ConditionAwarePredicate>,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
    let Some(scope) = scope else {
        return q;
    };
    if let Some(tier) = &scope.tier_binds {
        q = attome_security::bind_rls_predicate_as(q, tier);
    }
    for value in &scope.condition_binds {
        q = q.bind(value);
    }
    q
}

/// The number of placeholders a scope takes, so a query can bind after it.
pub(crate) fn scope_binds(scope: &Option<ConditionAwarePredicate>) -> usize {
    scope.as_ref().map_or(0, |s| {
        s.tier_binds
            .as_ref()
            .map_or(0, |_| attome_security::RLS_BIND_COUNT)
            + s.condition_binds.len()
    })
}

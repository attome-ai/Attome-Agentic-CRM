//! D-369/D-371: the read scope one record read takes, for any path that reads
//! records for a caller — the record rules (tier, shares, denies), owner
//! visibility and every grant condition on `{entity}.read`. A list, a join,
//! a count or an id check that takes this never shows a row the record
//! itself would refuse.

use attome_core::AttrInfo;
use attome_db::DbPool;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use sqlx::Postgres;
use sqlx::postgres::PgArguments;
use uuid::Uuid;

use crate::db::{RecordAction, resolve_owner_visible};
use crate::rls::{ConditionAwarePredicate, rls_predicate_with_conditions};
use crate::rls_fragment::{RLS_BIND_COUNT, bind_rls_predicate, bind_rls_predicate_as};

/// The read scope over `alias` (empty for an unqualified table), its
/// placeholders from `first`. `None` for an administrator, or when nothing
/// narrows.
#[allow(clippy::too_many_arguments)]
pub async fn read_scope(
    db: &DbPool,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    access_level: AccessLevel,
    attrs: &[AttrInfo],
    alias: &str,
    first: usize,
) -> Result<Option<ConditionAwarePredicate>, AppError> {
    if ctx.is_admin {
        return Ok(None);
    }
    let owner_visible = access_level != AccessLevel::Global
        && resolve_owner_visible(db, ctx.user_id, entity_id, entity_name, RecordAction::Read)
            .await?;
    Ok(rls_predicate_with_conditions(
        ctx,
        entity_id,
        alias,
        access_level,
        RecordAction::Read.share_capability(),
        &format!("{entity_name}.read"),
        attrs,
        owner_visible,
        first,
    ))
}

impl ConditionAwarePredicate {
    /// How many placeholders this predicate takes.
    pub fn bind_count(&self) -> usize {
        self.tier_binds.as_ref().map_or(0, |_| RLS_BIND_COUNT) + self.condition_binds.len()
    }
}

/// How many placeholders an optional scope takes (0 for none).
pub fn scope_bind_count(scope: Option<&ConditionAwarePredicate>) -> usize {
    scope.map_or(0, ConditionAwarePredicate::bind_count)
}

/// Binds a scope's values onto a scalar query, in order.
pub fn bind_read_scope<'q, O>(
    mut q: sqlx::query::QueryScalar<'q, Postgres, O, PgArguments>,
    scope: &'q ConditionAwarePredicate,
) -> sqlx::query::QueryScalar<'q, Postgres, O, PgArguments> {
    if let Some(tier) = &scope.tier_binds {
        q = bind_rls_predicate(q, tier);
    }
    for bind in &scope.condition_binds {
        q = q.bind(bind);
    }
    q
}

/// [`bind_read_scope`] for a row query.
pub fn bind_read_scope_as<'q, O>(
    mut q: sqlx::query::QueryAs<'q, Postgres, O, PgArguments>,
    scope: &'q ConditionAwarePredicate,
) -> sqlx::query::QueryAs<'q, Postgres, O, PgArguments> {
    if let Some(tier) = &scope.tier_binds {
        q = bind_rls_predicate_as(q, tier);
    }
    for bind in &scope.condition_binds {
        q = q.bind(bind);
    }
    q
}

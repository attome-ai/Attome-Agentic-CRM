//! AB5-T5: search while the index is down.
//!
//! When the `search_index` capability is confirmed unavailable (its drain has
//! stopped or fallen far behind), the search route answers from the entity
//! tables instead: a prefix match on each readable entity's title attribute,
//! five rows per entity, marked `limited` with the route `fallback` and
//! `search_index` in `degraded`.
//!
//! **The same visibility as the index.** The entities are the caller's read
//! access map (every entity for an admin, who is unfiltered in the index route
//! too) with the polymorphic children removed;
//! each table is filtered by `attome_security::rls_predicate` at the caller's
//! depth; and the matched attribute is the one the index itself titles a
//! record by ([`crate::corpus::title_attribute`] over
//! [`crate::corpus::indexable_attributes`]), so a sensitive field is never
//! searched. An entity with no indexable title is skipped.
//!
//! **Bounded.** At most [`MAX_ENTITIES`] tables, [`PER_ENTITY`] rows each; at
//! most [`PERMITS`] fallback searches run at once on a node (a caller waits up
//! to [`PERMIT_WAIT`], then gets `overloaded`); and each person may run
//! [`PER_USER_PER_MINUTE`] a minute (`search:fallback:<user>` in the rate
//! limiter, failing closed like every limiter).

use std::time::Duration;

use attome_core::EngineState;
use attome_core::sql_ident::quote_ident;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::routes::{SearchHit, SearchResponse, Total};

/// Rows taken from each entity.
pub const PER_ENTITY: i64 = 5;
/// Entities searched at most, in name order.
pub const MAX_ENTITIES: usize = 50;
/// Fallback searches running at once on this node.
pub const PERMITS: usize = 2;
/// How long a fallback search waits for a permit before answering overloaded.
pub const PERMIT_WAIT: Duration = Duration::from_secs(2);
/// Fallback searches one person may run a minute (one a second).
pub const PER_USER_PER_MINUTE: i32 = 60;

/// The route name a fallback answer carries.
pub const ROUTE: &str = "fallback";

static SLOTS: Semaphore = Semaphore::const_new(PERMITS);

/// `q` as a case-insensitive prefix pattern, its `%`, `_` and `\` escaped.
pub fn prefix_pattern(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 1);
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// The database search; see the module doc. Only page 1 has rows: the answer
/// is a short list per entity, not a ranked corpus to page through.
pub async fn fallback_search(
    state: &EngineState,
    ctx: &SecurityContext,
    q: &str,
    page: i64,
    page_size: i64,
) -> Result<SearchResponse, AppError> {
    let limit = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &format!("search:fallback:{}", ctx.user_id),
        PER_USER_PER_MINUTE,
    )
    .await?;
    if !limit.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: Some(limit.retry_after_secs),
        });
    }
    let _permit = tokio::time::timeout(PERMIT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| AppError::Overloaded("search fallback"))?
        .map_err(|_| AppError::Overloaded("search fallback"))?;

    let registry = state.entities.load();
    // An admin sees every entity, as in the index route (`is_unfiltered`);
    // anyone else the entities their read grants reach.
    let mut entities: Vec<(String, (Uuid, AccessLevel))> = if ctx.is_admin {
        registry
            .iter()
            .map(|meta| {
                (
                    meta.logicalname.clone(),
                    (meta.entity_id, AccessLevel::Global),
                )
            })
            .collect()
    } else {
        attome_security::resolve_all_entity_access_levels(
            &state.base.db,
            ctx.user_id,
            attome_security::RecordAction::Read,
        )
        .await?
        .into_iter()
        .collect()
    };
    entities.retain(|(entity, (_, level))| {
        *level != AccessLevel::None
            && !crate::corpus::POLYMORPHIC_CHILD_ENTITIES.contains(&entity.as_str())
    });
    entities.sort_by(|a, b| a.0.cmp(&b.0));

    let pattern = prefix_pattern(q);
    let mut items = Vec::new();
    if page == 1 {
        for (entity, (entity_id, level)) in entities.into_iter().take(MAX_ENTITIES) {
            let Some(meta) = registry.get(&entity) else {
                continue;
            };
            let indexable = crate::corpus::indexable_attributes(&meta.attrs);
            let Some(title) =
                crate::corpus::title_attribute(meta.primary_name_attribute.as_deref(), &indexable)
            else {
                continue;
            };
            let column = quote_ident(&title.logicalname);
            let mut sql = format!(
                "SELECT t.id, t.{col}::text FROM {} t WHERE t.{col} ILIKE $1 ESCAPE '\\'",
                quote_ident(&entity),
                col = quote_ident(&title.logicalname),
            );
            if !meta.is_append_only {
                sql.push_str(" AND t.is_active = true");
            }
            let predicate = attome_security::rls_predicate(
                ctx,
                entity_id,
                "t",
                level,
                attome_security::RecordAction::Read.share_capability(),
                2,
            );
            let mut binds = Vec::new();
            if let Some(predicate) = predicate {
                sql.push(' ');
                sql.push_str(&predicate.sql);
                binds = predicate.binds.to_text_params();
            }
            sql.push_str(&format!(" ORDER BY t.{column}, t.id LIMIT {PER_ENTITY}"));
            let mut query = sqlx::query_as::<_, (Uuid, Option<String>)>(&sql).bind(&pattern);
            for bind in &binds {
                query = query.bind(bind);
            }
            match query.fetch_all(&state.base.db).await {
                Ok(rows) => items.extend(rows.into_iter().map(|(record_id, name)| SearchHit {
                    entity_logicalname: entity.clone(),
                    record_id,
                    title: name,
                    subtitle: None,
                    score: 0.0,
                    matched_legs: vec![ROUTE.to_owned()],
                    explain: None,
                })),
                // One table that cannot be read (a timeout, a dropped column)
                // must not lose the others' rows; it is logged, not hidden.
                Err(error) => {
                    tracing::warn!(entity = %entity, %error, "search fallback: an entity was skipped");
                }
            }
        }
    }
    let found = items.len() as u64;
    let has_more = found > page_size.unsigned_abs();
    items.truncate(usize::try_from(page_size).unwrap_or(0));
    Ok(SearchResponse {
        facets: None,
        items,
        total: Total::Exact { value: found },
        page,
        page_size,
        has_more,
        route: ROUTE.to_owned(),
        degraded: vec!["search_index".to_owned()],
        route_hint: None,
        impression_id: None,
        limited: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pattern_is_a_prefix_with_wildcards_escaped() {
        assert_eq!(prefix_pattern("acme"), "acme%");
        assert_eq!(prefix_pattern("50%_off\\"), "50\\%\\_off\\\\%");
    }
}

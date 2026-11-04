//! D-369 in search: the index carries no record's fields, so a grant
//! condition on `{entity}.read` cannot narrow a search leg. A page of hits is
//! checked against the records themselves instead: a hit on an entity whose
//! read grant carries a condition stays only when its record meets it. A
//! check that cannot run drops that entity's hits (fails closed). Search
//! checks its whole candidate list (bounded by the search ceiling) before it
//! counts, so the total and facets agree with what is shown.

use std::collections::{HashMap, HashSet};

use attome_core::{EngineState, quote_ident};
use attome_server::security::SecurityContext;
use uuid::Uuid;

/// `items` without the hits a grant condition hides from `ctx`; `key` names
/// each item's entity and record. Order is kept.
pub async fn retain_admitted<T>(
    state: &EngineState,
    ctx: &SecurityContext,
    items: Vec<T>,
    key: impl Fn(&T) -> (&str, Uuid),
) -> Vec<T> {
    if ctx.is_admin || ctx.condition_grants.is_empty() {
        return items;
    }
    let mut by_entity: HashMap<String, Vec<Uuid>> = HashMap::new();
    for item in &items {
        let (entity, id) = key(item);
        if ctx.condition_grants.contains_key(&format!("{entity}.read")) {
            by_entity.entry(entity.to_owned()).or_default().push(id);
        }
    }
    if by_entity.is_empty() {
        return items;
    }
    let mut checked: HashSet<String> = HashSet::new();
    let mut admitted: HashSet<(String, Uuid)> = HashSet::new();
    for (entity, ids) in by_entity {
        checked.insert(entity.clone());
        let attrs = state
            .entities
            .load()
            .get(&entity)
            .map(|meta| meta.attrs.clone());
        let Some(attrs) = attrs else {
            continue;
        };
        let Some(condition) = attome_security::conditions::condition_predicate(
            ctx,
            &format!("{entity}.read"),
            &attrs,
            "t",
            2,
        ) else {
            admitted.extend(ids.into_iter().map(|id| (entity.clone(), id)));
            continue;
        };
        let sql = format!(
            "SELECT t.id FROM {} t WHERE t.id = ANY($1) AND ({})",
            quote_ident(&entity),
            condition.sql
        );
        let mut query = sqlx::query_scalar::<_, Uuid>(&sql).bind(&ids);
        for bind in &condition.binds {
            query = query.bind(bind);
        }
        match query.fetch_all(&state.base.db).await {
            Ok(rows) => admitted.extend(rows.into_iter().map(|id| (entity.clone(), id))),
            Err(error) => {
                tracing::warn!(
                    entity = %entity,
                    %error,
                    "search: a grant-condition check failed; the entity's hits are left out"
                );
            }
        }
    }
    items
        .into_iter()
        .filter(|item| {
            let (entity, id) = key(item);
            !checked.contains(entity) || admitted.contains(&(entity.to_owned(), id))
        })
        .collect()
}

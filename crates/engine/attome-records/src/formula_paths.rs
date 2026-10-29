//! A9-T2: the values a `read_time` formula reads through lookups
//! (`account.owner.manager.region`, up to
//! [`attome_core::formula::MAX_FORMULA_HOPS`] lookups), loaded when the
//! record is read and handed to the evaluator as the rules context's
//! related fields (one hop) and paths (more).
//!
//! Each hop follows the lookup's stored id to a live record; a null,
//! dangling or soft-deleted link reads as null, as in business rules
//! (A11-T2). A path that ends at another entity's `read_time` formula
//! computes it on that record in turn, one level deeper; the save-time
//! cycle check ([`attome_core::formula::formula_cycle`]) keeps the chain
//! finite, and [`MAX_DEPTH`] stops it regardless. Like a business rule's
//! related values, a formula reads only fields that are not read-gated
//! (`attome_core::business_rules::related_refs_within` leaves sensitive and
//! field-secured attributes out).

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;

use attome_core::business_rules::RelatedRef;
use attome_core::{AttrInfo, EngineState, EntityMetaRegistry};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// How many formulas deep one read follows `read_time` formulas on other
/// records.
pub const MAX_DEPTH: usize = attome_core::formula::MAX_FORMULA_HOPS;

/// The registry a read resolves paths in: the loaded one, or (metadata
/// cache off, so it is empty) one built from the database for this read.
pub(crate) async fn registry_for(
    state: &EngineState,
    entity: &str,
) -> Result<std::sync::Arc<EntityMetaRegistry>, AppError> {
    let loaded = std::sync::Arc::clone(&state.entities.load());
    if loaded.get(entity).is_some() {
        return Ok(loaded);
    }
    Ok(std::sync::Arc::new(
        attome_core::build_registry(&state.base.db).await?,
    ))
}

/// Reads one live record's row as JSON.
async fn live_row(state: &EngineState, entity: &str, id: Uuid) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE t.id = $1 AND (t.is_active IS NULL OR t.is_active = true)",
        attome_core::quote_ident(entity)
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The value at the end of `r` for `record`, following its lookups.
fn follow<'a>(
    state: &'a EngineState,
    registry: &'a EntityMetaRegistry,
    record: &'a Map<String, Value>,
    r: &'a RelatedRef,
    depth: usize,
    rows: &'a mut HashMap<(String, Uuid), Option<Value>>,
) -> Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>> {
    Box::pin(async move {
        let mut id = uuid_of(record.get(&r.segments[0]));
        for (i, entity) in r.entities.iter().enumerate() {
            let Some(current) = id else {
                return Ok(Value::Null);
            };
            let key = (entity.clone(), current);
            let row = match rows.get(&key) {
                Some(row) => row.clone(),
                None => {
                    let row = live_row(state, entity, current).await?;
                    rows.insert(key, row.clone());
                    row
                }
            };
            let Some(Value::Object(mut row)) = row else {
                return Ok(Value::Null);
            };
            let column = &r.segments[i + 1];
            if i + 1 < r.entities.len() {
                id = uuid_of(row.get(column));
                continue;
            }
            // The last hop: a formula computed when read is computed on this
            // record now (its column is empty).
            if let Some(meta) = registry.get(entity)
                && meta.attrs.iter().any(|a| {
                    &a.logicalname == column
                        && a.is_formula()
                        && attome_core::formula::is_read_time(a.options.as_ref())
                })
            {
                if depth >= MAX_DEPTH {
                    return Ok(Value::Null);
                }
                let mut one = [Value::Object(std::mem::take(&mut row))];
                crate::entity_mutation::fill_read_time_formulas_at(
                    state,
                    registry,
                    entity,
                    &meta.attrs,
                    &mut one,
                    depth + 1,
                )
                .await;
                return Ok(one[0].get(column).cloned().unwrap_or(Value::Null));
            }
            return Ok(row.get(column).cloned().unwrap_or(Value::Null));
        }
        Ok(Value::Null)
    })
}

fn uuid_of(value: Option<&Value>) -> Option<Uuid> {
    value
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// `ctx` with the values `refs` name, read for `record`. Each related
/// record is read once per call.
pub(crate) async fn with_paths(
    state: &EngineState,
    registry: &EntityMetaRegistry,
    record: &Map<String, Value>,
    refs: &[RelatedRef],
    mut ctx: attome_rules::Context,
    depth: usize,
) -> Result<attome_rules::Context, AppError> {
    let mut one_hop: BTreeMap<String, HashMap<String, attome_rules::Value>> = BTreeMap::new();
    let mut rows = HashMap::new();
    for r in refs {
        let value = follow(state, registry, record, r, depth, &mut rows).await?;
        let rules_value = attome_core::business_rules::condition_value(r.kind, Some(&value));
        if r.segments.len() == 2 {
            one_hop
                .entry(r.segments[0].clone())
                .or_default()
                .insert(r.segments[1].clone(), rules_value);
        } else {
            let path: Vec<&str> = r.segments.iter().map(String::as_str).collect();
            ctx = ctx.with_path(&path, rules_value);
        }
    }
    for (lookup, fields) in one_hop {
        ctx = ctx.with_related(lookup, fields);
    }
    Ok(ctx)
}

/// The lookup paths each formula in `formulas` reads (empty for one that
/// reads only its own record).
pub(crate) fn paths_of(
    registry: &EntityMetaRegistry,
    attrs: &[AttrInfo],
    expressions: &[&str],
) -> Vec<Vec<RelatedRef>> {
    expressions
        .iter()
        .map(|e| {
            if attome_core::formula::reads_through_lookup(e) {
                attome_core::formula::formula_paths(e, attrs, registry)
            } else {
                Vec::new()
            }
        })
        .collect()
}

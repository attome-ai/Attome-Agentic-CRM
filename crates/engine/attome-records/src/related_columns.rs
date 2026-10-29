//! A13-T1: columns from related records. A list or view may name a column
//! through lookups, `account_ref.industry` or `account_ref.owner_ref.name`
//! (at most [`MAX_RELATED_HOPS`] lookups), in a `select` list or in a view's
//! `table_definition`.
//!
//! [`resolve`] checks a path against the metadata as the caller sees it:
//! every lookup on the way and the last field must be readable in full by
//! the caller (a masked or hidden field reads as unknown, like a missing
//! one). [`fill`] then reads the values for a page of records, one
//! `WHERE id = ANY($1)` per hop, with the caller's record rules on each
//! related entity spliced in (`attome_security::rls_predicate`, as lookup
//! display names do): a related record the caller may not read, a deleted
//! one or an empty lookup reads as null. A related column is shown, not
//! filtered, sorted or searched on.

use std::collections::HashMap;

use attome_core::field_mask::ColumnAccess;
use attome_core::{EngineState, EntityMeta, FieldType, quote_ident};
use attome_security::RecordAction;
use attome_security::field_gate::{Surface, projection};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// How many lookups a related column may follow.
pub const MAX_RELATED_HOPS: usize = 2;

/// Whether `name` names a related column.
pub fn is_path(name: &str) -> bool {
    name.contains('.')
}

/// One lookup on a related column's way: the field and the entity it
/// points at.
#[derive(Debug, Clone)]
struct Hop {
    lookup: String,
    target_id: Uuid,
    target_table: String,
}

/// A related column checked against the metadata.
#[derive(Debug, Clone)]
pub struct RelatedColumn {
    /// The path as named (`account_ref.industry`).
    pub path: String,
    hops: Vec<Hop>,
    field: String,
    /// The last field's presentation type, for the column's `data_type`.
    pub data_type: String,
    /// The entity a lookup at the end of the path points at.
    pub lookup_target_entity: Option<String>,
}

fn readable_in_full(ctx: &SecurityContext, meta: &EntityMeta, name: &str) -> bool {
    meta.attrs.iter().any(|attr| {
        attr.logicalname == name
            && matches!(
                projection(
                    ctx,
                    &meta.logicalname,
                    attr,
                    meta.primary_name_attribute.as_deref(),
                    Surface::Interactive,
                ),
                ColumnAccess::Full
            )
    })
}

/// Checks `path` on the entity `entity_id`. A path the caller may not
/// follow is refused exactly like an unknown attribute.
pub fn resolve(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    path: &str,
) -> Result<RelatedColumn, AppError> {
    let unknown = || AppError::Validation(format!("unknown attribute: {path}"));
    let segments: Vec<&str> = path.split('.').collect();
    if segments.len() < 2
        || segments.len() > MAX_RELATED_HOPS + 1
        || segments.iter().any(|s| s.is_empty())
    {
        return Err(AppError::Validation(format!(
            "a related column follows 1 to {MAX_RELATED_HOPS} lookups: {path}"
        )));
    }
    let registry = state.entities.load();
    let mut meta = registry.get_by_id(entity_id).ok_or_else(unknown)?;
    let mut hops = Vec::with_capacity(segments.len() - 1);
    for lookup in &segments[..segments.len() - 1] {
        let attr = meta
            .attrs
            .iter()
            .find(|a| a.logicalname == *lookup && a.field_type() == FieldType::Lookup)
            .ok_or_else(unknown)?;
        if !readable_in_full(ctx, meta, lookup) {
            return Err(unknown());
        }
        let target = attr
            .lookup_entity_ref
            .and_then(|id| registry.get_by_id(id))
            .ok_or_else(unknown)?;
        hops.push(Hop {
            lookup: (*lookup).to_owned(),
            target_id: target.entity_id,
            target_table: target.logicalname.clone(),
        });
        meta = target;
    }
    let field = segments[segments.len() - 1];
    let attr = meta
        .attrs
        .iter()
        .find(|a| a.logicalname == field)
        .ok_or_else(unknown)?;
    if !readable_in_full(ctx, meta, field) {
        return Err(unknown());
    }
    let lookup_target_entity = if attr.field_type() == FieldType::Lookup {
        attr.lookup_entity_ref
            .and_then(|id| registry.get_by_id(id))
            .map(|m| m.logicalname.clone())
    } else {
        None
    };
    Ok(RelatedColumn {
        path: path.to_owned(),
        hops,
        field: field.to_owned(),
        data_type: attr.presentation_type().as_str().to_owned(),
        lookup_target_entity,
    })
}

/// The distinct ids the records reach. Pure.
fn distinct(reached: &[Option<Uuid>]) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = reached.iter().flatten().copied().collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// `column` of the live records `ids` of `table` the caller may read.
async fn visible_values(
    state: &EngineState,
    ctx: &SecurityContext,
    hop: &Hop,
    ids: &[Uuid],
    column: &str,
) -> Result<HashMap<Uuid, Value>, AppError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        hop.target_id,
        &hop.target_table,
        RecordAction::Read,
    )
    .await?;
    let pred = attome_security::rls_predicate(
        ctx,
        hop.target_id,
        "",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let predicate = pred.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT id, to_jsonb({}) FROM {} \
         WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true) {predicate}",
        quote_ident(column),
        quote_ident(&hop.target_table),
    );
    let sql = attome_db::tag_dynamic("query.related_columns", &sql);
    let mut query = sqlx::query_as::<_, (Uuid, Option<Value>)>(&sql).bind(ids);
    if let Some(p) = &pred {
        query = query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let rows = query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, value)| (id, value.unwrap_or(Value::Null)))
        .collect())
}

/// Sets each column of `columns` on every record of `records`: the value
/// at the end of its path, or null.
pub async fn fill(
    state: &EngineState,
    ctx: &SecurityContext,
    columns: &[RelatedColumn],
    records: &mut [Value],
) -> Result<(), AppError> {
    for column in columns {
        // For each record, the id it reaches at each hop.
        let mut reached: Vec<Option<Uuid>> = records
            .iter()
            .map(|r| {
                r.get(&column.hops[0].lookup)
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
            .collect();
        for (i, hop) in column.hops.iter().enumerate() {
            let ids = distinct(&reached);
            let next = column.hops.get(i + 1);
            let wanted = next.map_or(column.field.as_str(), |n| n.lookup.as_str());
            let values = visible_values(state, ctx, hop, &ids, wanted).await?;
            if next.is_some() {
                reached = reached
                    .iter()
                    .map(|id| {
                        id.and_then(|id| values.get(&id))
                            .and_then(Value::as_str)
                            .and_then(|s| Uuid::parse_str(s).ok())
                    })
                    .collect();
            } else {
                for (record, id) in records.iter_mut().zip(&reached) {
                    let value = id
                        .and_then(|id| values.get(&id))
                        .cloned()
                        .unwrap_or(Value::Null);
                    if let Some(obj) = record.as_object_mut() {
                        obj.insert(column.path.clone(), value);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_related_column_is_a_dotted_name() {
        assert!(is_path("account_ref.industry"));
        assert!(!is_path("industry"));
    }

    #[test]
    fn ids_are_read_once() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert_eq!(distinct(&[Some(b), None, Some(a), Some(b)]).len(), 2);
        assert!(distinct(&[None, None]).is_empty());
    }
}

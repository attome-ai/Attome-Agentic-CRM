//! AA3-T1: the index advisor.
//!
//! Views and the definitions that read records say which attributes are
//! filtered and sorted on: a view's sort and filter settings (its
//! `table_definition` and `view_metadata`), and every attribute-level
//! lineage edge (`metadata_reference`) a stored query, metric, dashboard or
//! flow reads. [`propose`] counts those uses per attribute of a table
//! larger than [`MIN_ROWS`], leaves out attributes already indexed
//! (filterable, sortable, a lookup, or advised before), and keeps the most
//! used ones within the table's budget: at most [`MAX_PER_TABLE`] indexes
//! on a table, counting the ones it has.
//!
//! [`advise`] records each choice in `index_advice` (migration 0232); the
//! attribute-index job counts an advised attribute as wanted, so the index
//! is built online (`CREATE INDEX CONCURRENTLY`, the size-gated job) by the
//! same worker as every other attribute index, and kept while it is
//! advised. The daily trigram sweep runs the advisor and queues the builds.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;

/// The most indexes a table gets, its existing ones included.
pub const MAX_PER_TABLE: usize = 15;
/// Tables smaller than this are left alone (a scan is cheap).
pub const MIN_ROWS: f64 = 10_000.0;

/// The attributes a view's settings sort or filter on.
pub fn view_fields(definition: &Value) -> Vec<String> {
    fn walk(v: &Value, inside: bool, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (key, value) in map {
                    let k = key.to_ascii_lowercase();
                    let relevant = inside
                        || k.contains("sort")
                        || k.contains("order")
                        || k.contains("filter")
                        || k.contains("where")
                        || k.contains("condition");
                    if relevant
                        && matches!(k.as_str(), "field" | "attribute" | "column")
                        && let Some(name) = value.as_str()
                    {
                        out.push(name.to_owned());
                    }
                    // `"order_by": ["priority"]`: bare names under a sort key
                    // (never the values a filter compares with).
                    if (k.contains("sort") || k.contains("order"))
                        && let Some(names) = value.as_array()
                    {
                        out.extend(names.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                    walk(value, relevant, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, inside, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(definition, false, &mut out);
    out
}

/// One table as the advisor sees it.
#[derive(Debug, Clone, Default)]
pub struct Table {
    pub rows: f64,
    /// Indexes the table has now.
    pub index_count: usize,
    /// Live attributes, with whether each is already indexed.
    pub attributes: HashMap<String, bool>,
}

/// The `(entity, attribute)` pairs to index, most used first per table.
pub fn propose(
    tables: &BTreeMap<String, Table>,
    uses: &HashMap<(String, String), u32>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (entity, table) in tables {
        if table.rows < MIN_ROWS {
            continue;
        }
        let budget = MAX_PER_TABLE.saturating_sub(table.index_count);
        let mut candidates: Vec<(&String, u32)> = table
            .attributes
            .iter()
            .filter(|(_, indexed)| !**indexed)
            .filter_map(|(attr, _)| {
                uses.get(&(entity.clone(), attr.clone()))
                    .map(|n| (attr, *n))
            })
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out.extend(
            candidates
                .into_iter()
                .take(budget)
                .map(|(attr, _)| (entity.clone(), attr.clone())),
        );
    }
    out
}

/// Reads the uses and tables, records the advice; the pairs to build.
pub async fn advise(db: &DbPool) -> Result<Vec<(String, String)>, AppError> {
    let views: Vec<(Option<String>, Option<Value>, Option<Value>)> = sqlx::query_as(
        "SELECT entity_logical_name, table_definition, view_metadata FROM view \
          WHERE is_active IS NULL OR is_active",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut uses: HashMap<(String, String), u32> = HashMap::new();
    for (entity, table_definition, view_metadata) in views {
        let Some(entity) = entity else { continue };
        let mut seen = HashSet::new();
        for def in [table_definition, view_metadata].into_iter().flatten() {
            for field in view_fields(&def) {
                if seen.insert(field.clone()) {
                    *uses.entry((entity.clone(), field)).or_default() += 1;
                }
            }
        }
    }
    let reads: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT to_entity, to_attribute, count(*) FROM metadata_reference \
          WHERE to_kind = 'entity' AND to_attribute <> '' AND confidence <> 'entity_only' \
            AND edge_kind IN ('reads', 'derives') \
          GROUP BY to_entity, to_attribute",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (entity, attribute, n) in reads {
        *uses.entry((entity, attribute)).or_default() += u32::try_from(n).unwrap_or(u32::MAX);
    }

    let columns: Vec<(String, String, bool, f64, i64)> = sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text, \
                (COALESCE(a.is_sortable, false) OR COALESCE(a.is_filterable, false) \
                 OR a.type = 11 OR EXISTS (SELECT 1 FROM index_advice x \
                                            WHERE x.entity_logicalname = e.logicalname \
                                              AND x.attribute = a.logicalname)), \
                t.reltuples::float8, \
                (SELECT count(*) FROM pg_index i WHERE i.indrelid = t.oid) \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
           JOIN pg_class t ON t.relname::text = e.logicalname::text \
                          AND t.relnamespace = current_schema()::regnamespace AND t.relkind = 'r' \
          WHERE COALESCE(a.is_active, true) AND COALESCE(e.is_active, true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut tables: BTreeMap<String, Table> = BTreeMap::new();
    for (entity, attribute, indexed, rows, indexes) in columns {
        let table = tables.entry(entity).or_default();
        table.rows = rows;
        table.index_count = usize::try_from(indexes).unwrap_or(MAX_PER_TABLE);
        table.attributes.insert(attribute, indexed);
    }
    let proposals = propose(&tables, &uses);
    for (entity, attribute) in &proposals {
        let n = uses
            .get(&(entity.clone(), attribute.clone()))
            .copied()
            .unwrap_or(0);
        sqlx::query(
            "INSERT INTO index_advice (entity_logicalname, attribute, uses) VALUES ($1, $2, $3) \
             ON CONFLICT (entity_logicalname, attribute) DO UPDATE SET uses = EXCLUDED.uses, \
                 advised_at = now()",
        )
        .bind(entity)
        .bind(attribute)
        .bind(i32::try_from(n).unwrap_or(i32::MAX))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(proposals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn index_advisor_reads_view_sorts_and_filters() {
        let def = json!({
            "columns": [{ "field": "name" }, { "field": "owner" }],
            "sort": [{ "field": "created_at", "desc": true }],
            "filters": { "and": [{ "field": "status", "op": "eq", "value": "open" },
                                 { "field": "region", "op": "in", "value": ["riyadh"] }] },
            "order_by": ["priority"]
        });
        let mut fields = view_fields(&def);
        fields.sort();
        assert_eq!(
            fields,
            vec!["created_at", "priority", "region", "status"],
            "columns alone are not uses"
        );
    }

    fn table(rows: f64, index_count: usize, attrs: &[(&str, bool)]) -> Table {
        Table {
            rows,
            index_count,
            attributes: attrs.iter().map(|(a, i)| ((*a).to_owned(), *i)).collect(),
        }
    }

    #[test]
    fn index_advisor_keeps_to_the_table_budget() {
        let mut tables = BTreeMap::new();
        tables.insert(
            "ticket".to_owned(),
            table(
                50_000.0,
                13,
                &[
                    ("status", false),
                    ("region", false),
                    ("owner", true),
                    ("tag", false),
                ],
            ),
        );
        tables.insert("small".to_owned(), table(100.0, 1, &[("status", false)]));
        let uses = HashMap::from([
            (("ticket".to_owned(), "status".to_owned()), 9),
            (("ticket".to_owned(), "region".to_owned()), 4),
            (("ticket".to_owned(), "owner".to_owned()), 20),
            (("ticket".to_owned(), "tag".to_owned()), 1),
            (("small".to_owned(), "status".to_owned()), 50),
        ]);
        let proposals = propose(&tables, &uses);
        assert_eq!(
            proposals,
            vec![
                ("ticket".to_owned(), "status".to_owned()),
                ("ticket".to_owned(), "region".to_owned()),
            ],
            "the most used unindexed attributes, 15 indexes at most, none on a small table"
        );
        let mut full = tables.clone();
        full.get_mut("ticket").unwrap().index_count = MAX_PER_TABLE;
        assert!(propose(&full, &uses).is_empty());
    }
}

//! Whole-batch integrity preflight for bulk mutations and staged imports.
//!
//! P-bulk-batch-integrity Gaps A/C (`document/detailed-plans/P-bulk-batch-integrity.md`):
//! validates a batch's *combined* effect — intra-batch hierarchy cycles and
//! intra-batch unique-key collisions — before any item's own transaction
//! begins, rather than relying on the incidental, undesigned protection that
//! sequential, eager-commit processing happens to provide today (D-095/D-096's
//! "accepted gap" language). The graph/collision logic below is pure and
//! unit-testable without a database; the two DB reads it needs (committed
//! hierarchy pointers, the target table's unique-index key-column tuples) are
//! thin, bound, read-only queries kept in this module alongside the logic
//! that consumes their results.
//!
//! Scope boundary, stated explicitly rather than silently overclaimed: cycle
//! detection here fetches the committed parent pointer for every id the
//! batch's own records touch (their own ids) or directly reference (a
//! record's proposed new parent value) — one hop of committed context beyond
//! the batch's own edges, matching the plan's own "one batched, bound query"
//! design. A cycle assembled from two or more batch edits joined by *two or
//! more hops* of pre-existing, non-batch-touched committed ancestry remains
//! outside this pass's coverage (same as it always has been); a batch edit
//! combined with at most one pre-existing hop is caught, and every hop of a
//! cycle formed entirely from the batch's own edits is caught regardless of
//! chain length (bounded by `MAX_HIERARCHY_DEPTH`, matching
//! `entity_mutation::guard_hierarchy_cycles`). `guard_hierarchy_cycles`
//! itself still runs, unconditionally, against the live table at each item's
//! own apply time — this preflight is additive defense-in-depth for the
//! window before any item has committed, not a replacement for it.

use std::collections::HashMap;

use attome_core::{AttrInfo, quote_ident};
use attome_types::AppError;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::bulk::BulkRecordEnvelope;
use crate::entity_mutation::{self, MAX_HIERARCHY_DEPTH};

/// One preflight finding: the offending batch item's index and a
/// human-readable reason, in the same shape `bulk.rs` already uses for
/// per-item errors.
pub(crate) type Finding = (usize, String);

/// Every id the batch's own records touch (their own `id`) or directly
/// reference (a non-null value set on `hierarchy_field`) — the set
/// `fetch_committed_hierarchy` needs to read one hop of committed context.
fn hierarchy_ids_to_fetch(records: &[BulkRecordEnvelope], hierarchy_field: &str) -> Vec<Uuid> {
    let mut ids = std::collections::HashSet::new();
    for record in records {
        if let Some(id) = record.id {
            ids.insert(id);
        }
        if let Some(obj) = record.data.as_object()
            && let Some(value) = obj.get(hierarchy_field)
            && let Some(parent) = value.as_str().and_then(|s| Uuid::parse_str(s).ok())
        {
            ids.insert(parent);
        }
    }
    ids.into_iter().collect()
}

/// Reads the currently-committed parent pointer for every id
/// `hierarchy_ids_to_fetch` names, via one bound `WHERE id = ANY($1)` read.
/// `entity_name` is validated metadata (already resolved by the caller's
/// `resolve_entity`), quoted through `quote_ident` — not request data.
pub(crate) async fn fetch_committed_hierarchy(
    tx: &mut PgConnection,
    entity_name: &str,
    hierarchy_field: &str,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Option<Uuid>>, AppError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let table = quote_ident(entity_name);
    let field_ident = quote_ident(hierarchy_field);
    let rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(&format!(
        "SELECT id, {field_ident} FROM {table} WHERE id = ANY($1)"
    ))
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// Detects intra-batch hierarchy cycles for one self-referencing hierarchy
/// field. Only meaningful for `operation == "update"` batches — a "create"
/// record has no client-known id (`entity_mutation::build_insert_binds`
/// never accepts `id` as an attribute) and so can never itself be a cycle
/// participant; calling this for a create/delete batch is harmless (nothing
/// in `records` will carry the field in a way that builds a cycle edge) but
/// wasted work, so callers should skip it for those operations.
///
/// `committed` is `fetch_committed_hierarchy`'s snapshot; the batch's own
/// proposed values are overlaid on top of it before walking each touched
/// record's chain, so this reflects "the graph as it would exist after
/// applying the whole batch together" — see this module's top doc comment
/// for the one-hop scope boundary.
pub(crate) fn detect_cycles(
    records: &[BulkRecordEnvelope],
    hierarchy_field: &str,
    committed: &HashMap<Uuid, Option<Uuid>>,
) -> Vec<Finding> {
    let mut graph = committed.clone();
    let mut touched: Vec<(usize, Uuid)> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let Some(id) = record.id else { continue };
        touched.push((index, id));
        let Some(obj) = record.data.as_object() else {
            continue;
        };
        if let Some(value) = obj.get(hierarchy_field) {
            let parent = if value.is_null() {
                None
            } else {
                value.as_str().and_then(|s| Uuid::parse_str(s).ok())
            };
            graph.insert(id, parent);
        }
    }

    let mut findings = Vec::new();
    for (index, id) in touched {
        let Some(direct_parent) = graph.get(&id).copied() else {
            continue;
        };
        if direct_parent == Some(id) {
            findings.push((
                index,
                format!("{hierarchy_field}: a record cannot be its own parent"),
            ));
            continue;
        }
        let mut current = direct_parent;
        let mut depth = 0u32;
        let mut cycle = false;
        while let Some(next) = current {
            depth += 1;
            if next == id {
                cycle = true;
                break;
            }
            if depth >= MAX_HIERARCHY_DEPTH {
                break;
            }
            current = graph.get(&next).copied().flatten();
        }
        if cycle {
            findings.push((
                index,
                format!("{hierarchy_field}: this batch would create a cycle in the hierarchy"),
            ));
        }
    }
    findings.sort_by_key(|(index, _)| *index);
    findings
}

/// Introspects `entity_name`'s own unique indexes (the lazily-created upsert
/// match-key index, `entity_crud.rs`'s `ux_{entity}_upsert_{digest}`, and/or
/// any customer-added unique index) and returns each one's key-column tuple,
/// in index-column order. Bound only by the table's own OID (`$1::regclass`
/// — a bound text parameter, same pattern `metrics.rs`'s own `pg_partition_
/// tree($1::regclass)` documents: `::regclass` resolves a *string value*
/// against `pg_class`, so a double-quoted `quote_ident` identifier here
/// would be parsed as a *column* reference instead and fail with "column ...
/// does not exist" for any name that isn't also a column in scope — bind,
/// don't quote-and-interpolate, for this specific cast). An index with any
/// expression column (`indkey` containing `0`) is excluded, since it has no
/// fixed column tuple this batch-payload-based check can compare against.
pub(crate) async fn fetch_unique_key_columns(
    tx: &mut PgConnection,
    entity_name: &str,
) -> Result<Vec<Vec<String>>, AppError> {
    // `i.indkey` (`int2vector`) is walked via `unnest(...) WITH ORDINALITY`
    // twice: once (correlated subquery) to build the ordered column-name
    // array, once (`NOT EXISTS`) to exclude an index with any expression
    // column (an expression column's `attnum` entry is `0`, which has no
    // corresponding `pg_attribute` row to join against) — avoids relying on
    // `= ANY(int2vector)`, which is not a supported comparison, by reusing
    // the same documented `unnest(int2vector)` system function both times.
    let rows: Vec<Option<Vec<String>>> = sqlx::query_scalar(
        "SELECT (
             SELECT array_agg(a.attname::text ORDER BY k.ord)
             FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
         )
         FROM pg_index i
         WHERE i.indrelid = $1::regclass
           AND i.indisunique = TRUE
           AND NOT EXISTS (
               SELECT 1 FROM unnest(i.indkey) WITH ORDINALITY AS k2(attnum, ord2)
               WHERE k2.attnum = 0
           )",
    )
    .bind(entity_name)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().flatten().collect())
}

/// Detects intra-batch collisions against any of `unique_key_columns`'
/// key-column tuples. Only a record whose payload sets *every* column in a
/// given tuple is considered for that tuple (a record leaving one of the key
/// columns unset cannot be shown to collide from the batch's own payload
/// alone); a tuple where any participating value is JSON `null` is skipped
/// entirely for that record, since a standard btree unique index never
/// treats two `NULL`s as equal. A collision against a row *outside* the
/// batch is not, and cannot be, caught here — that is what Gap B's
/// `entity_mutation::classify_db_error` fix (SQLSTATE `23505` ->
/// `AppError::Conflict`) closes instead, at apply time.
pub(crate) fn detect_unique_collisions(
    records: &[BulkRecordEnvelope],
    unique_key_columns: &[Vec<String>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for key_columns in unique_key_columns {
        if key_columns.is_empty() {
            continue;
        }
        let mut groups: HashMap<Vec<String>, Vec<usize>> = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            let Some(obj) = record.data.as_object() else {
                continue;
            };
            if !key_columns.iter().all(|c| obj.contains_key(c)) {
                continue;
            }
            if key_columns
                .iter()
                .any(|c| obj.get(c).is_some_and(serde_json::Value::is_null))
            {
                continue;
            }
            let key_value: Vec<String> = key_columns
                .iter()
                .map(|c| {
                    obj.get(c)
                        .map(serde_json::Value::to_string)
                        .unwrap_or_default()
                })
                .collect();
            groups.entry(key_value).or_default().push(index);
        }
        for indices in groups.into_values() {
            if indices.len() <= 1 {
                continue;
            }
            let column_list = key_columns.join(", ");
            for &index in &indices {
                let others = indices
                    .iter()
                    .filter(|&&other| other != index)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push((
                    index,
                    format!(
                        "duplicate value for unique key ({column_list}) also set by item(s) {others}"
                    ),
                ));
            }
        }
    }
    findings.sort_by_key(|(index, _)| *index);
    findings
}

/// Runs both checks for one batch and returns every finding, sorted by item
/// index. Shared by `bulk.rs`'s `enqueue`, `staged_import`, and
/// `approve_staged_import` so the three call sites can't drift apart on
/// which checks run or in what order.
///
/// Hierarchy-cycle detection only runs for `operation == "update"` batches
/// against an entity that actually has a self-referencing hierarchy field
/// (a "create" record has no client-known id and cannot be a cycle
/// participant; "delete" never sets the field) — and only takes
/// `entity_mutation::lock_hierarchy_entity_unconditional` (the same
/// entity-level advisory lock `update_one` already takes for every
/// hierarchy-touching write, D-138/P-hierarchy-mutation-locking) when that
/// condition holds, per this plan's own coordination note against
/// reinventing a second, differently-scoped lock over the same resource.
/// Unique-collision detection runs for `create`/`update` batches (a
/// `delete` record's payload is never applied to any column).
pub(crate) async fn run_preflight(
    tx: &mut PgConnection,
    entity_name: &str,
    entity_id: Uuid,
    attrs: &[AttrInfo],
    operation: &str,
    records: &[BulkRecordEnvelope],
) -> Result<Vec<Finding>, AppError> {
    let mut findings = Vec::new();

    if operation == "update" {
        let hierarchy_fields: Vec<&str> = attrs
            .iter()
            .filter(|a| a.field_type_int == 11 && a.lookup_entity_ref == Some(entity_id))
            .map(|a| a.logicalname.as_str())
            .collect();
        if !hierarchy_fields.is_empty() {
            entity_mutation::lock_hierarchy_entity_unconditional(tx, entity_name).await?;
            for field in hierarchy_fields {
                let ids = hierarchy_ids_to_fetch(records, field);
                let committed = fetch_committed_hierarchy(tx, entity_name, field, &ids).await?;
                findings.extend(detect_cycles(records, field, &committed));
            }
        }
    }

    if matches!(operation, "create" | "update") {
        let unique_key_columns = fetch_unique_key_columns(tx, entity_name).await?;
        findings.extend(detect_unique_collisions(records, &unique_key_columns));
    }

    findings.sort_by_key(|(index, _)| *index);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(id: Option<Uuid>, data: serde_json::Value) -> BulkRecordEnvelope {
        BulkRecordEnvelope {
            id,
            expected_row_version: id.map(|_| 0),
            data,
            skip_defaults: false,
        }
    }

    #[test]
    fn detect_cycles_finds_direct_mutual_reference() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let records = vec![
            record(Some(a), json!({ "parent_id": b.to_string() })),
            record(Some(b), json!({ "parent_id": a.to_string() })),
        ];
        let committed = HashMap::new();
        let findings = detect_cycles(&records, "parent_id", &committed);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].0, 0);
        assert_eq!(findings[1].0, 1);
    }

    #[test]
    fn detect_cycles_finds_longer_indirect_chain_closed_by_last_item() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        let records = vec![
            record(Some(a), json!({ "parent_id": b.to_string() })),
            record(Some(b), json!({ "parent_id": c.to_string() })),
            record(Some(c), json!({ "parent_id": a.to_string() })),
        ];
        let committed = HashMap::new();
        let findings = detect_cycles(&records, "parent_id", &committed);
        let indices: Vec<usize> = findings.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn detect_cycles_negative_case_no_cycle() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let root = Uuid::now_v7();
        let records = vec![
            record(Some(a), json!({ "parent_id": b.to_string() })),
            record(Some(b), json!({ "parent_id": root.to_string() })),
        ];
        let mut committed = HashMap::new();
        committed.insert(root, None);
        let findings = detect_cycles(&records, "parent_id", &committed);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_cycles_self_parent() {
        let a = Uuid::now_v7();
        let records = vec![record(Some(a), json!({ "parent_id": a.to_string() }))];
        let committed = HashMap::new();
        let findings = detect_cycles(&records, "parent_id", &committed);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, 0);
    }

    #[test]
    fn detect_cycles_respects_max_hierarchy_depth_boundary() {
        // A chain of MAX_HIERARCHY_DEPTH + 2 batch records that never
        // actually closes a cycle must not be misreported as one merely for
        // running up against the depth cap.
        let ids: Vec<Uuid> = (0..(MAX_HIERARCHY_DEPTH + 2))
            .map(|_| Uuid::now_v7())
            .collect();
        let records: Vec<BulkRecordEnvelope> = ids
            .windows(2)
            .map(|pair| record(Some(pair[0]), json!({ "parent_id": pair[1].to_string() })))
            .collect();
        let committed = HashMap::new();
        let findings = detect_cycles(&records, "parent_id", &committed);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_cycles_ignores_records_without_id() {
        // A "create" record never has a client-known id and cannot itself
        // be a cycle participant.
        let records = vec![record(
            None,
            json!({ "parent_id": Uuid::now_v7().to_string() }),
        )];
        let committed = HashMap::new();
        let findings = detect_cycles(&records, "parent_id", &committed);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_unique_collisions_flags_matching_create_pair() {
        let records = vec![
            record(None, json!({ "email": "a@example.com" })),
            record(None, json!({ "email": "b@example.com" })),
            record(None, json!({ "email": "a@example.com" })),
        ];
        let findings = detect_unique_collisions(&records, &[vec!["email".to_owned()]]);
        let indices: Vec<usize> = findings.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn detect_unique_collisions_negative_case_no_collision() {
        let records = vec![
            record(None, json!({ "email": "a@example.com" })),
            record(None, json!({ "email": "b@example.com" })),
        ];
        let findings = detect_unique_collisions(&records, &[vec!["email".to_owned()]]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_unique_collisions_ignores_null_participants() {
        let records = vec![
            record(None, json!({ "email": null })),
            record(None, json!({ "email": null })),
        ];
        let findings = detect_unique_collisions(&records, &[vec!["email".to_owned()]]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_unique_collisions_ignores_records_missing_a_key_column() {
        let records = vec![
            record(None, json!({ "email": "a@example.com" })),
            record(None, json!({ "name": "no email set here" })),
        ];
        let findings = detect_unique_collisions(&records, &[vec!["email".to_owned()]]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_unique_collisions_handles_composite_key() {
        let records = vec![
            record(None, json!({ "tenant": "acme", "code": "X1" })),
            record(None, json!({ "tenant": "acme", "code": "X1" })),
            record(None, json!({ "tenant": "other", "code": "X1" })),
        ];
        let findings =
            detect_unique_collisions(&records, &[vec!["tenant".to_owned(), "code".to_owned()]]);
        let indices: Vec<usize> = findings.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 1]);
    }
}

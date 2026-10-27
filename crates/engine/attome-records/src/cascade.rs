//! A7-T1: a delete's rule applied at every depth, not only to the records
//! that point at the deleted one.
//!
//! [`crate::entity_mutation::apply_dependents_on_delete`] handles the first
//! level as before (restrict refuses, cascade deactivates, a group over
//! `CASCADE_INLINE_ROW_LIMIT` goes to a job). [`cascade_below`] then walks
//! on from each first-level group, level by level: a restrict-mode lookup
//! referencing a record about to be deactivated refuses the whole delete
//! with the blocking path ([`AppError::CascadeRestricted`]), since it runs
//! in the delete's own transaction; a cascade-mode lookup deactivates its
//! live records and the walk continues from them. Small trees finish in
//! the transaction; once [`CASCADE_TREE_LIMIT`] records below the first
//! level have been deactivated, each remaining group is queued as the same
//! durable job the first level uses, one per parent record, and that job
//! continues the walk below each batch it deactivates.
//!
//! Every batch is written to the `cascade_deactivation` ledger under its
//! own parent record, so [`restore_below`] can bring a restored record's
//! whole subtree back, level by level, and only the records the delete
//! took. The dependents of an entity are read from the metadata tables in
//! the same transaction ([`dependents_of`]).

use attome_core::{OnTargetDelete, quote_ident};
use attome_types::AppError;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::entity_mutation::record_cascade_batch;

/// Records below the first level one delete deactivates in its own
/// transaction; past this, the rest goes to jobs.
pub const CASCADE_TREE_LIMIT: usize = 1_000;
/// Levels below the first a walk follows (a guard against a cycle of
/// cascade lookups, which the `is_active` filter already ends).
pub const MAX_CASCADE_DEPTH: usize = 16;

/// The (dependent entity, lookup field, rule) triples whose live lookup
/// attribute targets `entity`, sorted, from the metadata tables.
pub(crate) async fn dependents_of(
    conn: &mut PgConnection,
    entity: &str,
) -> Result<Vec<(String, String, OnTargetDelete)>, AppError> {
    let rows: Vec<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT de.logicalname, a.logicalname, a.on_target_delete \
           FROM attribute_info a \
           JOIN entity_info de ON de.id = a.entity_ref \
           JOIN entity_info te ON te.id = a.lookup_entity_ref \
          WHERE te.logicalname = $1 \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND (de.is_active IS NULL OR de.is_active = true) \
          ORDER BY de.logicalname, a.logicalname",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(e, f, mode)| {
            Some((
                e?,
                f?,
                OnTargetDelete::from_db_str(mode.as_deref().unwrap_or("orphan")),
            ))
        })
        .collect())
}

/// One level of the walk: records of `entity` just deactivated, reached by
/// `path` from the deleted record.
struct Level {
    entity: String,
    ids: Vec<Uuid>,
    path: String,
}

/// Walks below the first level from `ids` (records of `entity` the delete
/// just deactivated, reached by `path`). Returns the summary lines.
/// `budget` is what is left of [`CASCADE_TREE_LIMIT`]; groups past it are
/// queued as jobs per parent record.
pub(crate) async fn cascade_below(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    ids: Vec<Uuid>,
    user_id: Uuid,
    path: String,
    budget: &mut usize,
) -> Result<Vec<String>, AppError> {
    let mut summary = Vec::new();
    let mut frontier = vec![Level {
        entity: entity.to_owned(),
        ids,
        path,
    }];
    for _ in 0..MAX_CASCADE_DEPTH {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for level in frontier.drain(..) {
            if level.ids.is_empty() {
                continue;
            }
            let dependents = dependents_of(&mut **tx, &level.entity).await?;
            for (dep_entity, dep_field, mode) in dependents {
                let dep_table = quote_ident(&dep_entity);
                let dep_field_ident = quote_ident(&dep_field);
                let step = format!("{} -> {dep_entity}.{dep_field}", level.path);
                match mode {
                    OnTargetDelete::Orphan => {}
                    OnTargetDelete::Restrict => {
                        let blocked: bool = sqlx::query_scalar(&format!(
                            "SELECT EXISTS(SELECT 1 FROM {dep_table} \
                              WHERE {dep_field_ident} = ANY($1) AND is_active = TRUE)"
                        ))
                        .bind(&level.ids)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(AppError::internal)?;
                        if blocked {
                            return Err(AppError::CascadeRestricted(step));
                        }
                    }
                    OnTargetDelete::CascadeDeactivate => {
                        // A bounded probe: more than the budget left goes to jobs.
                        let probe = i64::try_from(*budget).unwrap_or(i64::MAX);
                        let over: bool = sqlx::query_scalar(&format!(
                            "SELECT EXISTS (SELECT 1 FROM {dep_table} \
                              WHERE {dep_field_ident} = ANY($1) AND is_active = TRUE OFFSET {probe})"
                        ))
                        .bind(&level.ids)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(AppError::internal)?;
                        if over {
                            queue_groups(tx, &level, &dep_entity, &dep_field, user_id).await?;
                            *budget = 0;
                            summary.push(format!("{step}: queued for async processing"));
                            continue;
                        }
                        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
                            "UPDATE {dep_table} SET is_active = false, modified_at = NOW(), modified_by = $2, \
                                    row_version = row_version + 1 \
                              WHERE {dep_field_ident} = ANY($1) AND is_active = TRUE \
                              RETURNING id, {dep_field_ident}"
                        ))
                        .bind(&level.ids)
                        .bind(user_id)
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(AppError::internal)?;
                        if rows.is_empty() {
                            continue;
                        }
                        let child_ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();
                        attome_core::change_feed::emit_many(
                            tx,
                            &dep_entity,
                            &child_ids,
                            attome_core::ChangeOperation::Delete,
                        )
                        .await?;
                        // The ledger, per parent record, so restore walks back.
                        let mut by_parent: std::collections::BTreeMap<Uuid, Vec<Uuid>> =
                            std::collections::BTreeMap::new();
                        for (id, parent) in &rows {
                            by_parent.entry(*parent).or_default().push(*id);
                        }
                        for (parent, children) in &by_parent {
                            record_cascade_batch(
                                tx,
                                &level.entity,
                                *parent,
                                &dep_entity,
                                &dep_field,
                                children,
                            )
                            .await?;
                        }
                        *budget = budget.saturating_sub(child_ids.len());
                        summary.push(format!("{step}: {}", child_ids.len()));
                        next.push(Level {
                            entity: dep_entity,
                            ids: child_ids,
                            path: step,
                        });
                    }
                }
            }
        }
        frontier = next;
    }
    if !frontier.is_empty() {
        tracing::warn!(
            entity,
            depth = MAX_CASCADE_DEPTH,
            "cascade stopped at its depth limit; deeper records stay live"
        );
    }
    Ok(summary)
}

/// Queues one cascade job per parent record of `level` for the
/// `dep_entity.dep_field` group.
async fn queue_groups(
    tx: &mut Transaction<'_, Postgres>,
    level: &Level,
    dep_entity: &str,
    dep_field: &str,
    user_id: Uuid,
) -> Result<(), AppError> {
    for parent in &level.ids {
        attome_jobs::enqueue_in_tx_dedup(
            tx,
            attome_core::jobs::EngineJob::CascadeDeactivateDependents {
                target_entity: level.entity.clone(),
                target_record_id: *parent,
                dependent_entity: dep_entity.to_owned(),
                dependent_field: dep_field.to_owned(),
                deactivated_by: user_id,
            },
            &format!(
                "attome-server/cascade-deactivate:{}:{parent}:{dep_entity}:{dep_field}",
                level.entity
            ),
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Brings back, level by level, the records the ledger says a delete took
/// below `parents` (records just restored), and spends those ledger rows.
/// Returns the summary lines.
pub(crate) async fn restore_below(
    conn: &mut PgConnection,
    parents: Vec<Uuid>,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let mut summary = Vec::new();
    let mut frontier = parents;
    for _ in 0..MAX_CASCADE_DEPTH {
        if frontier.is_empty() {
            break;
        }
        let groups: Vec<(String, String)> = sqlx::query_as(
            "SELECT DISTINCT dependent_entity, dependent_field FROM cascade_deactivation \
              WHERE parent_record_id = ANY($1) ORDER BY 1, 2",
        )
        .bind(&frontier)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let mut next = Vec::new();
        for (dep_entity, dep_field) in groups {
            let dep_table = quote_ident(&dep_entity);
            let dep_field_ident = quote_ident(&dep_field);
            let back: Vec<(Uuid,)> = sqlx::query_as(&format!(
                "UPDATE {dep_table} SET is_active = true, modified_at = NOW(), modified_by = $2, \
                        row_version = row_version + 1 \
                  WHERE {dep_field_ident} = ANY($1) AND is_active = FALSE \
                    AND id IN ( \
                        SELECT dependent_record_id FROM cascade_deactivation \
                         WHERE parent_record_id = ANY($1) AND dependent_entity = $3 AND dependent_field = $4 \
                    ) \
                  RETURNING id"
            ))
            .bind(&frontier)
            .bind(user_id)
            .bind(&dep_entity)
            .bind(&dep_field)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "DELETE FROM cascade_deactivation \
                  WHERE parent_record_id = ANY($1) AND dependent_entity = $2 AND dependent_field = $3",
            )
            .bind(&frontier)
            .bind(&dep_entity)
            .bind(&dep_field)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            if back.is_empty() {
                continue;
            }
            let ids: Vec<Uuid> = back.into_iter().map(|(id,)| id).collect();
            attome_core::change_feed::emit_many(
                &mut *conn,
                &dep_entity,
                &ids,
                attome_core::ChangeOperation::Restore,
            )
            .await?;
            summary.push(format!("{dep_entity}.{dep_field}: {}", ids.len()));
            next.extend(ids);
        }
        frontier = next;
    }
    Ok(summary)
}

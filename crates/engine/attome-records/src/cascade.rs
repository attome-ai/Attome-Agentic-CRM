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

use attome_core::relationship_registry::RelationshipCascade;
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

/// A8-T2: the polymorphic pairs that may point at `entity` and carry a
/// delete rule for it other than orphan: (dependent entity, id attribute,
/// entity attribute, rule), from the metadata tables.
pub(crate) async fn polymorphic_dependents_of(
    conn: &mut PgConnection,
    entity: &str,
) -> Result<Vec<(String, String, String, OnTargetDelete)>, AppError> {
    let rows: Vec<(Option<String>, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT de.logicalname, a.logicalname, a.options \
           FROM attribute_info a \
           JOIN entity_info de ON de.id = a.entity_ref \
          WHERE a.options ? 'polymorphic' \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND (de.is_active IS NULL OR de.is_active = true) \
          ORDER BY de.logicalname, a.logicalname",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(dep, attr, options)| {
            let options: crate::polymorphic::PolymorphicOptions =
                serde_json::from_value(options?.get("polymorphic")?.clone()).ok()?;
            if !crate::polymorphic::allowed(&options, entity, None) {
                return None;
            }
            let (dep, attr) = (dep?, attr?);
            let rule = options.delete_rule(entity);
            (rule != OnTargetDelete::Orphan).then(|| (dep, attr, options.pair.clone(), rule))
        })
        .collect())
}

/// A8-T2: the delete rule of every polymorphic pair that may point at
/// records of `entity` being deleted (`ids`, reached by `path`): `restrict`
/// refuses while a live record points at one of them, `cascade-deactivate`
/// deactivates the records pointing at them (recorded in the
/// `cascade_deactivation` ledger, so a restore brings them back); the walk
/// does not continue below them. Returns the summary lines.
pub(crate) async fn polymorphic_on_delete(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    ids: &[Uuid],
    path: &str,
) -> Result<Vec<String>, AppError> {
    let mut summary = Vec::new();
    let texts: Vec<String> = ids.iter().map(Uuid::to_string).collect();
    for (dep_entity, id_attr, pair_attr, rule) in polymorphic_dependents_of(tx, entity).await? {
        let table = quote_ident(&dep_entity);
        let id_col = quote_ident(&id_attr);
        let pair_col = quote_ident(&pair_attr);
        let step = format!("{path} -> {dep_entity}.{id_attr}");
        match rule {
            OnTargetDelete::Orphan => {}
            OnTargetDelete::Restrict => {
                let blocked: bool = sqlx::query_scalar(&format!(
                    "SELECT EXISTS(SELECT 1 FROM {table} \
                      WHERE {pair_col} = $1 AND {id_col} = ANY($2) \
                        AND (is_active IS NULL OR is_active = true))"
                ))
                .bind(entity)
                .bind(&texts)
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?;
                if blocked {
                    return Err(AppError::CascadeRestricted(step));
                }
            }
            OnTargetDelete::CascadeDeactivate => {
                let mut total = 0usize;
                for (parent, text) in ids.iter().zip(&texts) {
                    let taken: Vec<Uuid> = sqlx::query_scalar(&format!(
                        "UPDATE {table} SET is_active = false, modified_at = NOW(), \
                                row_version = row_version + 1 \
                          WHERE {pair_col} = $1 AND {id_col} = $2 \
                            AND (is_active IS NULL OR is_active = true) \
                          RETURNING id"
                    ))
                    .bind(entity)
                    .bind(text)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(AppError::internal)?;
                    record_cascade_batch(&mut **tx, entity, *parent, &dep_entity, &id_attr, &taken)
                        .await?;
                    total += taken.len();
                }
                if total > 0 {
                    summary.push(format!("{step}: {total} deactivated"));
                }
            }
        }
    }
    Ok(summary)
}

/// A7-T1: the many-to-many relationships' rule for records of `entity`
/// being deleted (`ids`, reached by `path`): `restrict` refuses while a
/// live link to a live record still holds one of them, `cascade-deactivate`
/// deactivates their links, `orphan` leaves the links as they are (an
/// inactive endpoint drops out of every related read). Returns the summary
/// lines. A restored record's links are not brought back: no ledger records
/// which links a delete took.
pub(crate) async fn links_on_delete(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    ids: &[Uuid],
    path: &str,
) -> Result<Vec<String>, AppError> {
    let relationships: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT name, entity_a, entity_b, join_table, cascade FROM relationship_info \
          WHERE (entity_a = $1 OR entity_b = $1) AND is_active = TRUE AND is_deleted IS NOT TRUE \
          ORDER BY name",
    )
    .bind(entity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut summary = Vec::new();
    for (name, entity_a, entity_b, join_table, cascade) in relationships {
        let join = quote_ident(&join_table);
        // Each side the deleted records sit on, with the other side's table.
        let mut sides = Vec::new();
        if entity_a == entity {
            sides.push(("a_id", "b_id", entity_b.clone()));
        }
        if entity_b == entity {
            sides.push(("b_id", "a_id", entity_a.clone()));
        }
        for (mine, other, other_entity) in sides {
            match RelationshipCascade::from_db_str(&cascade) {
                RelationshipCascade::Orphan => {}
                RelationshipCascade::Restrict => {
                    let other_table = quote_ident(&other_entity);
                    let blocked: bool = sqlx::query_scalar(&format!(
                        "SELECT EXISTS(SELECT 1 FROM {join} j JOIN {other_table} o ON o.id = j.{other} \
                          WHERE j.{mine} = ANY($1) AND j.is_active = TRUE AND o.is_active = TRUE)"
                    ))
                    .bind(ids)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(AppError::internal)?;
                    if blocked {
                        return Err(AppError::CascadeRestricted(format!(
                            "{path} -> {name} ({other_entity})"
                        )));
                    }
                }
                RelationshipCascade::CascadeDeactivate => {
                    let done = sqlx::query(&format!(
                        "UPDATE {join} SET is_active = false, row_version = row_version + 1 \
                          WHERE {mine} = ANY($1) AND is_active = TRUE"
                    ))
                    .bind(ids)
                    .execute(&mut **tx)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
                    if done > 0 {
                        summary.push(format!("{path} -> {name}: {done} links"));
                    }
                }
            }
        }
    }
    Ok(summary)
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
            summary.extend(links_on_delete(tx, &level.entity, &level.ids, &level.path).await?);
            summary
                .extend(polymorphic_on_delete(tx, &level.entity, &level.ids, &level.path).await?);
            let dependents = dependents_of(tx, &level.entity).await?;
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
                  WHERE {dep_field_ident}::text = ANY($5::text[]) AND is_active = FALSE \
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
            // A8-T2: a polymorphic id is text; a lookup compares as text too.
            .bind(frontier.iter().map(Uuid::to_string).collect::<Vec<_>>())
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

// ── A7-T2: the impact of an action, before it runs ──────────────────────────

/// Records listed per group.
pub const IMPACT_FIRST: i64 = 20;

/// One group of records an action would touch.
#[derive(Debug, Clone, PartialEq, serde::Serialize, utoipa::ToSchema)]
pub struct ImpactGroup {
    /// The entity the records are in.
    pub entity: String,
    /// The lookup field through which they point at the record above them;
    /// `null` for a many-to-many group.
    pub field: Option<String>,
    /// The many-to-many relationship, for a link group.
    pub relationship: Option<String>,
    /// How they are reached from the record (`account -> contact.account_ref`).
    pub path: String,
    /// `deactivated`, `blocks`, `orphaned`, `repointed`, `unlinked` or `reassigned`.
    pub effect: String,
    pub count: i64,
    /// The first records (at most 20); none for a link group.
    pub first: Vec<Uuid>,
}

/// What an action on one record would touch.
#[derive(Debug, Clone, PartialEq, serde::Serialize, utoipa::ToSchema)]
pub struct Impact {
    /// `delete`, `merge` or `reassign`.
    pub action: String,
    pub groups: Vec<ImpactGroup>,
    /// A restrict rule would refuse the action.
    pub blocked: bool,
    /// The walk stopped at [`CASCADE_TREE_LIMIT`] records or
    /// [`MAX_CASCADE_DEPTH`] levels; deeper records are not counted.
    pub truncated: bool,
    /// Entities the caller cannot read hold records the action touches; they
    /// are not listed (a restrict rule there still sets `blocked`).
    pub hidden_dependents: bool,
}

/// The live records of `dep_entity` pointing at `ids` through `field`:
/// their count and up to `limit` ids.
async fn pointing(
    conn: &mut PgConnection,
    dep_entity: &str,
    field: &str,
    ids: &[Uuid],
    limit: i64,
) -> Result<(i64, Vec<Uuid>), AppError> {
    let table = quote_ident(dep_entity);
    let field = quote_ident(field);
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} WHERE {field} = ANY($1) AND is_active = TRUE"
    ))
    .bind(ids)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if count == 0 {
        return Ok((0, Vec::new()));
    }
    let found: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE {field} = ANY($1) AND is_active = TRUE ORDER BY id LIMIT {limit}"
    ))
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((count, found))
}

/// The many-to-many link groups of records of `entity` (`ids`): their
/// count per relationship, with `effect` naming what the action does; for a
/// delete, the relationship's own rule decides (restrict blocks, cascade
/// unlinks, orphan leaves them, not listed).
async fn link_groups(
    conn: &mut PgConnection,
    entity: &str,
    ids: &[Uuid],
    path: &str,
    effect: Option<&str>,
) -> Result<(Vec<ImpactGroup>, bool), AppError> {
    let relationships: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT name, entity_a, entity_b, join_table, cascade FROM relationship_info \
          WHERE (entity_a = $1 OR entity_b = $1) AND is_active = TRUE AND is_deleted IS NOT TRUE \
          ORDER BY name",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let mut groups = Vec::new();
    let mut blocked = false;
    for (name, entity_a, entity_b, join_table, cascade) in relationships {
        let join = quote_ident(&join_table);
        let mut sides = Vec::new();
        if entity_a == entity {
            sides.push(("a_id", "b_id", entity_b.clone()));
        }
        if entity_b == entity {
            sides.push(("b_id", "a_id", entity_a.clone()));
        }
        for (mine, other, other_entity) in sides {
            let rule = RelationshipCascade::from_db_str(&cascade);
            let effect = match (effect, rule) {
                (Some(e), _) => e,
                (None, RelationshipCascade::Restrict) => "blocks",
                (None, RelationshipCascade::CascadeDeactivate) => "unlinked",
                (None, RelationshipCascade::Orphan) => continue,
            };
            let other_table = quote_ident(&other_entity);
            let count: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {join} j JOIN {other_table} o ON o.id = j.{other} \
                  WHERE j.{mine} = ANY($1) AND j.is_active = TRUE AND o.is_active = TRUE"
            ))
            .bind(ids)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            if count == 0 {
                continue;
            }
            blocked |= effect == "blocks";
            groups.push(ImpactGroup {
                entity: other_entity,
                field: None,
                relationship: Some(name.clone()),
                path: format!("{path} -> {name}"),
                effect: effect.to_owned(),
                count,
                first: Vec::new(),
            });
        }
    }
    Ok((groups, blocked))
}

/// What `action` (`delete`, `merge` or `reassign`) on record `id` of
/// `entity` would touch, without changing anything. A delete walks every
/// depth as [`cascade_below`] would; a merge repoints every live record and
/// link that points at the record; a reassignment changes the record alone.
/// `can_read` says whether the caller may read an entity's records.
pub async fn impact(
    conn: &mut PgConnection,
    entity: &str,
    id: Uuid,
    action: &str,
    can_read: &(dyn Fn(&str) -> bool + Sync),
) -> Result<Impact, AppError> {
    let mut out = Impact {
        action: action.to_owned(),
        groups: Vec::new(),
        blocked: false,
        truncated: false,
        hidden_dependents: false,
    };
    match action {
        "reassign" => {
            out.groups.push(ImpactGroup {
                entity: entity.to_owned(),
                field: None,
                relationship: None,
                path: entity.to_owned(),
                effect: "reassigned".into(),
                count: 1,
                first: vec![id],
            });
        }
        "merge" => {
            for (dep_entity, field, _) in dependents_of(conn, entity).await? {
                let (count, first) =
                    pointing(conn, &dep_entity, &field, &[id], IMPACT_FIRST).await?;
                if count == 0 {
                    continue;
                }
                if !can_read(&dep_entity) {
                    out.hidden_dependents = true;
                    continue;
                }
                out.groups.push(ImpactGroup {
                    path: format!("{entity} -> {dep_entity}.{field}"),
                    entity: dep_entity,
                    field: Some(field),
                    relationship: None,
                    effect: "repointed".into(),
                    count,
                    first,
                });
            }
            let (links, _) = link_groups(conn, entity, &[id], entity, Some("repointed")).await?;
            out.groups.extend(links);
        }
        "delete" => {
            let mut budget = i64::try_from(CASCADE_TREE_LIMIT).unwrap_or(i64::MAX);
            let mut frontier = vec![(entity.to_owned(), vec![id], entity.to_owned())];
            for depth in 0..=MAX_CASCADE_DEPTH {
                if frontier.is_empty() {
                    break;
                }
                if depth == MAX_CASCADE_DEPTH {
                    out.truncated = true;
                    break;
                }
                let mut next = Vec::new();
                for (level_entity, ids, path) in frontier {
                    let (links, blocked) =
                        link_groups(conn, &level_entity, &ids, &path, None).await?;
                    out.blocked |= blocked;
                    out.groups.extend(links);
                    for (dep_entity, field, mode) in dependents_of(conn, &level_entity).await? {
                        let step = format!("{path} -> {dep_entity}.{field}");
                        let (count, first) =
                            pointing(conn, &dep_entity, &field, &ids, IMPACT_FIRST).await?;
                        if count == 0 {
                            continue;
                        }
                        let effect = match mode {
                            OnTargetDelete::Restrict => {
                                out.blocked = true;
                                "blocks"
                            }
                            OnTargetDelete::Orphan => "orphaned",
                            OnTargetDelete::CascadeDeactivate => "deactivated",
                        };
                        if mode == OnTargetDelete::CascadeDeactivate {
                            // The next level walks from every record this
                            // one deactivates, within the budget.
                            let take = budget.min(count);
                            if count > budget {
                                out.truncated = true;
                            }
                            budget -= take;
                            if take > 0 {
                                let (_, all) =
                                    pointing(conn, &dep_entity, &field, &ids, take).await?;
                                next.push((dep_entity.clone(), all, step.clone()));
                            }
                        }
                        if !can_read(&dep_entity) {
                            out.hidden_dependents = true;
                            continue;
                        }
                        out.groups.push(ImpactGroup {
                            entity: dep_entity,
                            field: Some(field),
                            relationship: None,
                            path: step,
                            effect: effect.into(),
                            count,
                            first,
                        });
                    }
                }
                frontier = next;
            }
        }
        _ => {
            return Err(AppError::Validation(
                "action is delete, merge or reassign".into(),
            ));
        }
    }
    Ok(out)
}

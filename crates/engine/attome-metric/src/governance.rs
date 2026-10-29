//! P9-T11: who sees which metric, which breakdown members, and who may enter
//! values and certify.
//!
//! - **Role-limited metrics.** A metric whose `visible_role_keys` names roles
//!   (a JSON list or a comma-separated list of role names) is listed, and its
//!   snapshots read, only by a holder of one of them, or an administrator.
//!   Its totals are company-wide values, so this is the only gate on them.
//! - **Breakdown members.** A member of a lookup dimension (an owner, an
//!   account) is a record: a member row is shown only when the viewer may
//!   read every record it names, checked in one batched query per target
//!   entity per page (`attome_records::changes::readable_ids`). A value that
//!   cannot be read as record ids, or a metric whose entity is unknown, hides
//!   the row from all but administrators: the check fails closed.
//! - **Manual values** need [`ENTER_VALUE`]; **certification** needs
//!   [`CERTIFY`] and goes through `POST /api/v1/metrics/{id}/certify`, the
//!   only writer of `certified` and `certified_at` (engine-managed fields).
//! - A snapshot under a new definition version clears the certification
//!   ([`uncertify_if_new_version`]).

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

use crate::metric::SnapshotRow;

/// A dimension list's shape: its dimension count, and each lookup position
/// with its target entity's id and name.
type DimensionShape = (usize, Vec<(usize, Uuid, String)>);

/// The privilege a manual value needs.
pub const ENTER_VALUE: &str = "attome_metric.enter_value";
/// The privilege certification needs.
pub const CERTIFY: &str = "attome_metric.certify";

/// Whether a metric limited to `keys` (empty: not limited) shows to a
/// caller holding `roles`. Role names compare exactly. Pure.
pub fn visible_to(keys: &[String], roles: &[String], is_admin: bool) -> bool {
    is_admin || keys.is_empty() || keys.iter().any(|k| roles.iter().any(|r| r == k))
}

/// The SQL condition, over `dashboard_metric_definition d`, that a metric
/// shows to the caller: `$admin` a boolean, `$roles` the caller's role
/// names (`text[]`). The roles column is read through `to_jsonb(d)` so a
/// deployment without the governance fields still lists every metric.
pub fn visible_clause(admin: usize, roles: usize) -> String {
    let keys = "unnest(string_to_array(regexp_replace(\
                coalesce(to_jsonb(d)->>'visible_role_keys', ''), '[\\[\\]\"]', '', 'g'), ','))";
    format!(
        "(${admin}::boolean \
          OR NOT EXISTS (SELECT 1 FROM {keys} k WHERE btrim(k) <> '') \
          OR EXISTS (SELECT 1 FROM {keys} k WHERE btrim(k) = ANY(${roles}::text[])))"
    )
}

/// The names of the caller's live roles.
pub async fn role_names(db: &DbPool, user_id: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT r.name FROM user_account_mm_role ur JOIN role r ON r.id = ur.role_ref \
          WHERE ur.user_ref = $1 AND NOT ur.is_deleted AND NOT r.is_deleted AND r.is_active",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// 404 unless the metric shows to `ctx` (a hidden metric is not revealed).
pub async fn require_visible(
    db: &DbPool,
    ctx: &SecurityContext,
    metric_id: Uuid,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }
    let raw: Option<Option<String>> = sqlx::query_scalar(
        "SELECT to_jsonb(d)->>'visible_role_keys' FROM dashboard_metric_definition d WHERE d.id = $1",
    )
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let keys = crate::metric::parse_dimensions(raw.flatten().as_deref());
    if keys.is_empty() {
        return Ok(());
    }
    let roles = role_names(db, ctx.user_id).await?;
    if visible_to(&keys, &roles, false) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The record ids a member value names at the lookup positions, or `None`
/// when the value cannot be split into one part per dimension or a lookup
/// part is not an id (the caller then hides the row). An empty part is the
/// member with no record and names none. Pure.
pub fn lookup_ids(value: &str, dimensions: usize, lookups: &[usize]) -> Option<Vec<(usize, Uuid)>> {
    let parts: Vec<&str> = if dimensions == 1 {
        vec![value]
    } else {
        value.split(',').collect()
    };
    if parts.len() != dimensions {
        return None;
    }
    let mut ids = Vec::new();
    for &at in lookups {
        let part = parts.get(at)?.trim();
        if part.is_empty() {
            continue;
        }
        ids.push((at, Uuid::parse_str(part).ok()?));
    }
    Some(ids)
}

/// The metric's entity: its governance `entity_logicalname`, else its
/// builder spec's.
async fn metric_entity(db: &DbPool, metric_id: Uuid) -> Result<Option<String>, AppError> {
    let entity: Option<Option<String>> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(to_jsonb(d)->>'entity_logicalname', ''), \
                         s.spec->>'entity_logicalname') \
           FROM dashboard_metric_definition d \
           LEFT JOIN metric_builder_spec s ON s.metric_ref = d.id \
          WHERE d.id = $1",
    )
    .bind(metric_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(entity.flatten())
}

/// The member rows of `rows` the caller may see, and how many were hidden.
/// Total rows (no dimension) always pass; see the module doc.
pub async fn visible_members(
    state: &EngineState,
    ctx: &SecurityContext,
    metric_id: Uuid,
    rows: Vec<SnapshotRow>,
) -> Result<(Vec<SnapshotRow>, usize), AppError> {
    if ctx.is_admin || rows.iter().all(|r| r.dimension_attribute.is_none()) {
        return Ok((rows, 0));
    }
    let entity = metric_entity(&state.base.db, metric_id).await?;
    let registry = std::sync::Arc::clone(&state.entities.load());
    let meta = entity.as_deref().and_then(|e| registry.get(e));
    // Per dimension list: (dimension count, lookup positions with their
    // target entity), or None when the metric's fields are unknown.
    let mut shapes: HashMap<String, Option<DimensionShape>> = HashMap::new();
    for row in &rows {
        let Some(attrs) = &row.dimension_attribute else {
            continue;
        };
        shapes.entry(attrs.clone()).or_insert_with(|| {
            let meta = meta?;
            let names: Vec<&str> = attrs.split(',').map(str::trim).collect();
            let mut lookups = Vec::new();
            for (at, name) in names.iter().enumerate() {
                let attr = meta.attrs.iter().find(|a| a.logicalname == *name)?;
                if attr.field_type() == attome_core::FieldType::Lookup {
                    let target = registry.get_by_id(attr.lookup_entity_ref?)?;
                    lookups.push((at, target.entity_id, target.logicalname.clone()));
                }
            }
            Some((names.len(), lookups))
        });
    }

    // Every id per target entity on this page, read in one batch each.
    let mut wanted: HashMap<(Uuid, String), Vec<Uuid>> = HashMap::new();
    let mut parsed: Vec<Option<Vec<(Uuid, Uuid)>>> = Vec::with_capacity(rows.len());
    for row in &rows {
        let Some(attrs) = &row.dimension_attribute else {
            parsed.push(Some(Vec::new()));
            continue;
        };
        let ids = match shapes.get(attrs).cloned().flatten() {
            Some((count, lookups)) => {
                let positions: Vec<usize> = lookups.iter().map(|l| l.0).collect();
                lookup_ids(
                    row.dimension_value.as_deref().unwrap_or(""),
                    count,
                    &positions,
                )
                .map(|found| {
                    found
                        .into_iter()
                        .filter_map(|(at, id)| {
                            let (_, entity_id, name) = lookups.iter().find(|l| l.0 == at)?;
                            wanted
                                .entry((*entity_id, name.clone()))
                                .or_default()
                                .push(id);
                            Some((*entity_id, id))
                        })
                        .collect()
                })
            }
            None => None,
        };
        parsed.push(ids);
    }
    let mut readable: HashSet<(Uuid, Uuid)> = HashSet::new();
    for ((entity_id, name), ids) in wanted {
        for id in attome_records::changes::readable_ids(state, ctx, entity_id, &name, &ids).await? {
            readable.insert((entity_id, id));
        }
    }
    let mut kept = Vec::with_capacity(rows.len());
    let mut hidden = 0;
    for (row, ids) in rows.into_iter().zip(parsed) {
        match ids {
            Some(ids) if ids.iter().all(|key| readable.contains(key)) => kept.push(row),
            _ => hidden += 1,
        }
    }
    Ok((kept, hidden))
}

/// A snapshot written under a definition version above the last one clears
/// the metric's certification: what was certified is not what is measured
/// now. Read without assuming the governance fields exist.
pub async fn uncertify_if_new_version(
    db: &DbPool,
    metric_id: Uuid,
    last_version: Option<i32>,
    version: i32,
) -> Result<(), AppError> {
    if !last_version.is_some_and(|last| version > last) {
        return Ok(());
    }
    let has_field: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'dashboard_metric_definition' \
            AND column_name = 'certified')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !has_field {
        return Ok(());
    }
    let cleared = sqlx::query(
        "UPDATE dashboard_metric_definition \
            SET certified = false, certified_at = NULL, \
                row_version = row_version + 1, modified_at = now() \
          WHERE id = $1 AND certified = true",
    )
    .bind(metric_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if cleared > 0 {
        tracing::info!(%metric_id, version, "metric certification cleared: new definition version");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn a_role_limited_metric_shows_only_to_its_roles_and_admins() {
        assert!(visible_to(&[], &[], false), "not limited");
        assert!(visible_to(
            &s(&["Finance"]),
            &s(&["Sales", "Finance"]),
            false
        ));
        assert!(!visible_to(&s(&["Finance"]), &s(&["Sales"]), false));
        assert!(
            visible_to(&s(&["Finance"]), &[], true),
            "an administrator sees all"
        );
    }

    #[test]
    fn breakdown_member_ids_are_read_at_lookup_positions_and_fail_closed() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_eq!(lookup_ids(&a.to_string(), 1, &[0]), Some(vec![(0, a)]));
        assert_eq!(
            lookup_ids(&format!("east,{b}"), 2, &[1]),
            Some(vec![(1, b)])
        );
        assert_eq!(
            lookup_ids(",", 2, &[1]),
            Some(vec![]),
            "no record, nothing to hide"
        );
        assert_eq!(lookup_ids("not-an-id", 1, &[0]), None);
        assert_eq!(
            lookup_ids("a,b,c", 2, &[1]),
            None,
            "a value that does not split cleanly"
        );
    }

    #[test]
    fn the_visibility_clause_numbers_its_parameters() {
        let sql = visible_clause(3, 4);
        assert!(sql.contains("$3::boolean"), "{sql}");
        assert!(sql.contains("ANY($4::text[])"), "{sql}");
        assert!(sql.contains("to_jsonb(d)->>'visible_role_keys'"), "{sql}");
    }
}

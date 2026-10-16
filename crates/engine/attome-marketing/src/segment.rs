//! Segment refresh (roadmap E7-T4): a marketing list's members are worked
//! out and the member table brought in line, with an entered/left event per
//! change.
//!
//! A `segment` list's people are the ids its stored query returns to the
//! list's owner (`attome_records::query_exec::execute_stored_query_ids`, so
//! the owner's record access applies); a `static` list's are its current
//! members. Combinations then apply in position order: `include` adds the
//! operand list's people, `intersect` keeps only those also in it,
//! `exclude` removes them; operand lists are evaluated the same way, at
//! most [`MAX_DEPTH`] deep, and a list met twice on one path is a cycle.
//! An account list expands to its accounts' contacts (all of them, or the
//! decision makers and economic buyers named on their opportunities).
//!
//! [`refresh`] takes the list's advisory lock, diffs against
//! `marketing_list_member`, writes the changes in batches and one
//! `marketing_list_membership_event` per change, and updates the list's
//! count and refresh time, in one transaction.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// How deep combinations may nest.
pub const MAX_DEPTH: usize = 5;

/// Most people a segment may hold.
pub const MAX_MEMBERS: i64 = 1_000_000;

/// Rows written per statement.
const WRITE_BATCH: usize = 5_000;

/// A combination step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Include,
    Intersect,
    Exclude,
}

impl Operation {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "include" => Some(Self::Include),
            "intersect" => Some(Self::Intersect),
            "exclude" => Some(Self::Exclude),
            _ => None,
        }
    }
}

/// Applies combination steps, in order, to a base set (pure).
pub fn combine(mut base: HashSet<Uuid>, steps: Vec<(Operation, HashSet<Uuid>)>) -> HashSet<Uuid> {
    for (operation, operand) in steps {
        match operation {
            Operation::Include => base.extend(operand),
            Operation::Intersect => base.retain(|id| operand.contains(id)),
            Operation::Exclude => base.retain(|id| !operand.contains(id)),
        }
    }
    base
}

/// Who joins and who leaves (pure).
pub fn diff(current: &HashSet<Uuid>, wanted: &HashSet<Uuid>) -> (Vec<Uuid>, Vec<Uuid>) {
    let mut added: Vec<Uuid> = wanted.difference(current).copied().collect();
    let mut removed: Vec<Uuid> = current.difference(wanted).copied().collect();
    added.sort();
    removed.sort();
    (added, removed)
}

type ListRow = (String, String, String, Option<String>, Option<Uuid>);

async fn load_list(state: &EngineState, list: Uuid) -> Result<ListRow, AppError> {
    sqlx::query_as::<_, ListRow>(
        "SELECT COALESCE(kind, 'static'), COALESCE(target_entity, 'contact'), \
                COALESCE(account_expand, 'none'), query_id, owner_ref \
         FROM marketing_list WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The people of a list, as `ctx` may see them.
pub fn evaluate<'a>(
    state: &'a EngineState,
    ctx: &'a SecurityContext,
    list: Uuid,
    path: Vec<Uuid>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<HashSet<Uuid>, AppError>> + Send + 'a>>
{
    Box::pin(async move {
        if path.contains(&list) {
            return Err(AppError::Validation("segment.cycle".into()));
        }
        if path.len() >= MAX_DEPTH {
            return Err(AppError::Validation("segment.too_deep".into()));
        }
        let (kind, target, expand, query, _) = load_list(state, list).await?;
        let mut people: HashSet<Uuid> = match (kind.as_str(), query.as_deref()) {
            ("segment", Some(query)) => {
                let query_id = Uuid::parse_str(query.trim())
                    .map_err(|_| AppError::Validation("segment.query_id_invalid".into()))?;
                attome_records::query_exec::execute_stored_query_ids(
                    state,
                    ctx,
                    query_id,
                    None,
                    Some(MAX_MEMBERS),
                )
                .await?
                .into_iter()
                .collect()
            }
            ("segment", None) => {
                return Err(AppError::Validation("segment.query_missing".into()));
            }
            _ => sqlx::query_scalar::<_, Uuid>(
                "SELECT person_id FROM marketing_list_member WHERE list_id = $1",
            )
            .bind(list)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect(),
        };
        if target == "account" && expand != "none" && kind == "segment" {
            people = expand_accounts(state, &people, &expand).await?;
        }
        let steps: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT operand_list_ref, operation FROM marketing_list_combination \
             WHERE list_ref = $1 AND operand_list_ref IS NOT NULL \
               AND (is_active IS NULL OR is_active = true) ORDER BY position NULLS LAST, id",
        )
        .bind(list)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let mut child_path = path.clone();
        child_path.push(list);
        let mut evaluated = Vec::with_capacity(steps.len());
        for (operand, operation) in steps {
            let Some(operation) = Operation::parse(&operation) else {
                continue;
            };
            let set = evaluate(state, ctx, operand, child_path.clone()).await?;
            evaluated.push((operation, set));
        }
        Ok(combine(people, evaluated))
    })
}

async fn expand_accounts(
    state: &EngineState,
    accounts: &HashSet<Uuid>,
    expand: &str,
) -> Result<HashSet<Uuid>, AppError> {
    let ids: Vec<Uuid> = accounts.iter().copied().collect();
    let rows: Vec<Uuid> = if expand == "decision_makers" {
        let available: bool =
            sqlx::query_scalar("SELECT to_regclass('opportunity_contact_role') IS NOT NULL")
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        if !available {
            return Err(AppError::Validation(
                "segment.decision_makers_unavailable".into(),
            ));
        }
        sqlx::query_scalar(
            "SELECT DISTINCT c.id FROM contact c JOIN opportunity_contact_role r ON r.contact_ref = c.id \
             WHERE c.account_ref = ANY($1) AND r.role IN ('decision_maker', 'economic_buyer') \
               AND (c.is_active IS NULL OR c.is_active = true) \
               AND (r.is_active IS NULL OR r.is_active = true)",
        )
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
    } else {
        sqlx::query_scalar(
            "SELECT id FROM contact WHERE account_ref = ANY($1) \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
    };
    Ok(rows.into_iter().collect())
}

/// What a refresh changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct RefreshResult {
    pub added: usize,
    pub removed: usize,
    pub members: usize,
}

/// Refreshes a list's members as its owner sees them.
pub async fn refresh(
    state: &EngineState,
    list: Uuid,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<RefreshResult, AppError> {
    let (_, target, expand, _, owner) = load_list(state, list).await?;
    let owner = owner.ok_or_else(|| AppError::Validation("segment.owner_missing".into()))?;
    let ctx = attome_security::resolve_uncached(&state.base.db, owner).await?;
    let wanted = evaluate(state, &ctx, list, Vec::new()).await?;
    let person_entity = if target == "account" && expand != "none" {
        "contact".to_owned()
    } else {
        target
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-marketing/segment_refresh:{list}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this list is already being refreshed"));
    }
    let current: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT person_id FROM marketing_list_member WHERE list_id = $1",
    )
    .bind(list)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let (added, removed) = diff(&current, &wanted);
    for chunk in added.chunks(WRITE_BATCH) {
        sqlx::query(
            "INSERT INTO marketing_list_member (list_id, person_id, person_entity, source, added_at) \
             SELECT $1, p, $2, 'segment', $3 FROM unnest($4::uuid[]) AS p \
             ON CONFLICT (list_id, person_id) DO NOTHING",
        )
        .bind(list)
        .bind(&person_entity)
        .bind(now)
        .bind(chunk)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason, at) \
             SELECT $1, p, 'entered', $2, $3 FROM unnest($4::uuid[]) AS p",
        )
        .bind(list)
        .bind(reason)
        .bind(now)
        .bind(chunk)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    for chunk in removed.chunks(WRITE_BATCH) {
        sqlx::query("DELETE FROM marketing_list_member WHERE list_id = $1 AND person_id = ANY($2)")
            .bind(list)
            .bind(chunk)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason, at) \
             SELECT $1, p, 'left', $2, $3 FROM unnest($4::uuid[]) AS p",
        )
        .bind(list)
        .bind(reason)
        .bind(now)
        .bind(chunk)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if !added.is_empty() || !removed.is_empty() {
        attome_core::change_feed::emit_named(
            &mut tx,
            "marketing_list",
            list,
            attome_core::change_feed::ChangeOperation::Update,
            "marketing.list.refreshed",
        )
        .await?;
    }
    sqlx::query(
        "UPDATE marketing_list SET member_count = $2, last_refreshed_at = $3, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(list)
    .bind(wanted.len() as f64)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(RefreshResult {
        added: added.len(),
        removed: removed.len(),
        members: wanted.len(),
    })
}

/// Refreshes every scheduled list whose interval has passed; the number
/// refreshed. A list that fails is logged and skipped.
pub async fn refresh_due(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('marketing_list') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM marketing_list          WHERE (is_active IS NULL OR is_active = true) AND refresh_mode = 'scheduled'            AND COALESCE(is_paused, false) = false            AND (last_refreshed_at IS NULL OR last_refreshed_at <= $1 -                 CASE WHEN refresh_interval = 'hourly' THEN INTERVAL '1 hour' ELSE INTERVAL '1 day' END)          ORDER BY id LIMIT 200",
    )
    .bind(now)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut done = 0;
    for list in due {
        match refresh(state, list, "scheduled", now).await {
            Ok(_) => done += 1,
            Err(e) => {
                tracing::warn!(%list, error = %e, "segment refresh failed; the list is skipped")
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[u128]) -> HashSet<Uuid> {
        ids.iter().map(|i| Uuid::from_u128(*i)).collect()
    }

    #[test]
    fn combinations_apply_in_order() {
        let base = set(&[1, 2, 3]);
        let out = combine(
            base,
            vec![
                (Operation::Include, set(&[4])),
                (Operation::Intersect, set(&[2, 3, 4, 9])),
                (Operation::Exclude, set(&[3])),
            ],
        );
        assert_eq!(out, set(&[2, 4]));
    }

    #[test]
    fn diff_lists_who_joins_and_who_leaves() {
        let (added, removed) = diff(&set(&[1, 2, 3]), &set(&[2, 3, 4]));
        assert_eq!(added, vec![Uuid::from_u128(4)]);
        assert_eq!(removed, vec![Uuid::from_u128(1)]);
        assert_eq!(Operation::parse("exclude"), Some(Operation::Exclude));
    }
}

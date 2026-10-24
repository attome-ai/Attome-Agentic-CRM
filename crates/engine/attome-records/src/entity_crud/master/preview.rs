//! L1-T10: what a trust ranking would change, before anyone sets it.
//!
//! [`preview_ranking`] reads every attached contribution of a master entity
//! (at most [`MAX_PREVIEW_CONTRIBUTIONS`]), chooses each attribute's value
//! under the proposed `source_system_rank` config with the same
//! [`SourceSystemRank::choose`] a rebuild uses, and counts, per attribute,
//! the golden records whose value would change. Pinned values are left out,
//! as a rebuild leaves them. It only reads: nothing is written, no rebuild is
//! queued, and no value is returned, only counts.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_core::{EngineState, quote_ident};
use attome_metadata::provision::master::{contribution_table, provenance_table};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_crud::survivorship::{Contribution, SourceSystemRank};

/// The most contributions one preview reads; a larger entity is refused.
pub const MAX_PREVIEW_CONTRIBUTIONS: i64 = 100_000;

/// What a proposed ranking would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RankingPreview {
    /// The attached contributions read.
    pub contributions: usize,
    /// The golden records they belong to.
    pub golden_records: usize,
    /// Per attribute, the golden records whose value would change.
    pub changes: BTreeMap<String, u64>,
}

/// One golden record's attached contributions, oldest first.
type Grouped = HashMap<Uuid, Vec<Contribution>>;

/// Counts what `config` (a `source_system_rank` rule's config) would change
/// on `entity`'s golden records, for `attributes` (each the config ranks).
/// `attributes` must already be readable by the caller.
pub async fn preview_ranking(
    state: &EngineState,
    entity: &str,
    config: &Value,
    attributes: &[String],
) -> Result<RankingPreview, AppError> {
    let rank = SourceSystemRank::from_config(config).map_err(AppError::Validation)?;
    let db = &state.base.db;
    let rows: Vec<(Uuid, Uuid, String, DateTime<Utc>, Value)> = sqlx::query_as(&format!(
        "SELECT id, golden_id, source_system, received_at, payload FROM {} \
          WHERE status = 'attached' AND golden_id IS NOT NULL \
          ORDER BY golden_id, received_at, id LIMIT $1",
        quote_ident(&contribution_table(entity))
    ))
    .bind(MAX_PREVIEW_CONTRIBUTIONS + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if rows.len() as i64 > MAX_PREVIEW_CONTRIBUTIONS {
        return Err(AppError::Validation(format!(
            "{entity} has more than {MAX_PREVIEW_CONTRIBUTIONS} attached contributions: \
             too many to preview at once"
        )));
    }
    let contributions = rows.len();
    let mut grouped: Grouped = HashMap::new();
    for (id, golden, system, received_at, payload) in rows {
        grouped.entry(golden).or_default().push(Contribution {
            id,
            system,
            received_at,
            payload: payload.as_object().cloned().unwrap_or_default(),
            validated: true,
        });
    }
    let goldens: Vec<Uuid> = grouped.keys().copied().collect();
    let pinned: HashSet<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(&format!(
        "SELECT golden_id, attribute FROM {} \
          WHERE golden_id = ANY($1) AND pinned_by IS NOT NULL",
        quote_ident(&provenance_table(entity))
    ))
    .bind(&goldens)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let current: HashMap<Uuid, Map<String, Value>> = sqlx::query_as::<_, (Uuid, Value)>(&format!(
        "SELECT t.id, to_jsonb(t) FROM {} t WHERE t.id = ANY($1) AND t.is_active",
        quote_ident(entity)
    ))
    .bind(&goldens)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(id, row)| (id, row.as_object().cloned().unwrap_or_default()))
    .collect();
    Ok(count_changes(
        &rank,
        attributes,
        &grouped,
        &current,
        &pinned,
        contributions,
    ))
}

/// The counting itself, apart from the reads. Pure.
pub fn count_changes(
    rank: &SourceSystemRank,
    attributes: &[String],
    grouped: &HashMap<Uuid, Vec<Contribution>>,
    current: &HashMap<Uuid, Map<String, Value>>,
    pinned: &HashSet<(Uuid, String)>,
    contributions: usize,
) -> RankingPreview {
    let mut out = RankingPreview {
        contributions,
        golden_records: current.len(),
        changes: attributes.iter().map(|a| (a.clone(), 0)).collect(),
    };
    for (golden, values) in current {
        let Some(list) = grouped.get(golden) else {
            continue;
        };
        for attribute in attributes {
            if pinned.contains(&(*golden, attribute.clone())) {
                continue;
            }
            let Some((chosen, _, _)) = rank.choose(attribute, list) else {
                continue;
            };
            if values.get(attribute) != Some(chosen)
                && let Some(n) = out.changes.get_mut(attribute)
            {
                *n += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contribution(system: &str, minutes: i64, payload: Value) -> Contribution {
        Contribution {
            id: Uuid::now_v7(),
            system: system.into(),
            received_at: DateTime::<Utc>::from_timestamp(1_800_000_000 + minutes * 60, 0).unwrap(),
            payload: payload.as_object().cloned().unwrap(),
            validated: true,
        }
    }

    #[test]
    fn a_new_ranking_counts_the_values_it_would_change() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let grouped: HashMap<Uuid, Vec<Contribution>> = [
            (
                a,
                vec![
                    contribution("crm", 0, json!({"phone": "1"})),
                    contribution("erp", 1, json!({"phone": "2"})),
                ],
            ),
            (b, vec![contribution("crm", 0, json!({"phone": "3"}))]),
            (
                c,
                vec![
                    contribution("crm", 0, json!({"phone": "4"})),
                    contribution("erp", 1, json!({"phone": "5"})),
                ],
            ),
        ]
        .into_iter()
        .collect();
        // Today crm wins everywhere.
        let current: HashMap<Uuid, Map<String, Value>> = [
            (a, json!({"phone": "1"})),
            (b, json!({"phone": "3"})),
            (c, json!({"phone": "4"})),
        ]
        .into_iter()
        .map(|(id, v)| (id, v.as_object().cloned().unwrap()))
        .collect();
        let erp_first =
            SourceSystemRank::from_config(&json!({"ranks": {"phone": ["erp", "crm"]}})).unwrap();
        let attrs = ["phone".to_owned()];
        let none = HashSet::new();
        let preview = count_changes(&erp_first, &attrs, &grouped, &current, &none, 5);
        // a and c take erp's value; b has no erp version.
        assert_eq!(preview.changes["phone"], 2);
        assert_eq!(preview.golden_records, 3);
        // A pinned value is left alone.
        let pinned: HashSet<(Uuid, String)> = [(a, "phone".to_owned())].into_iter().collect();
        let preview = count_changes(&erp_first, &attrs, &grouped, &current, &pinned, 5);
        assert_eq!(preview.changes["phone"], 1);
    }
}

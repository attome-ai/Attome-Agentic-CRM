//! L1-T4: recomputing a golden record from its contributions.

use std::collections::HashSet;

use attome_core::{EngineState, quote_ident};
use attome_metadata::provision::master::{contribution_table, provenance_table};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_crud::survivorship::{Contribution, Strategy, load_survivorship_rules};

/// The rule name an attribute without a rank takes its newest value under.
pub const MOST_RECENT: &str = "most_recent";

/// What a rebuild did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rebuilt {
    /// The attributes whose golden value changed.
    pub changed: Vec<String>,
    /// The attributes whose source was recorded.
    pub provenance: usize,
    /// The attributes left as a person pinned them.
    pub pinned: usize,
}

fn filled(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
}

/// The newest filled value of `attribute`. Pure.
pub fn newest<'a>(
    attribute: &str,
    contributions: &'a [Contribution],
) -> Option<(&'a Value, Uuid, &'static str)> {
    contributions
        .iter()
        .filter_map(|c| {
            c.payload
                .get(attribute)
                .filter(|v| filled(v))
                .map(|v| (c, v))
        })
        .max_by(|(a, _), (b, _)| a.received_at.cmp(&b.received_at).then(a.id.cmp(&b.id)))
        .map(|(c, v)| (v, c.id, MOST_RECENT))
}

/// Recomputes golden record `golden` of `entity` as `actor`.
pub async fn rebuild(
    state: &EngineState,
    entity: &str,
    golden: Uuid,
    actor: Uuid,
) -> Result<Rebuilt, AppError> {
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::NotFound)?;
    let db = &state.base.db;

    // One rebuild of a golden record at a time; a second waits for its own
    // retry rather than racing this one.
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(super::rebuild_lock_key(golden))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this golden record is being rebuilt; retry",
        ));
    }

    let rows: Vec<(Uuid, String, DateTime<Utc>, Value)> = sqlx::query_as(&format!(
        "SELECT id, source_system, received_at, payload FROM {contributions_t} \
          WHERE golden_id = $1 AND status = 'attached' ORDER BY received_at, id",
        contributions_t = quote_ident(&contribution_table(entity))
    ))
    .bind(golden)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let contributions: Vec<Contribution> = rows
        .into_iter()
        .map(|(id, system, received_at, payload)| Contribution {
            id,
            system,
            received_at,
            payload: payload.as_object().cloned().unwrap_or_default(),
            // Only attached contributions are read: each passed validation.
            validated: true,
        })
        .collect();
    let pinned: HashSet<String> = sqlx::query_scalar(&format!(
        "SELECT attribute FROM {provenance_t} WHERE golden_id = $1 AND pinned_by IS NOT NULL",
        provenance_t = quote_ident(&provenance_table(entity))
    ))
    .bind(golden)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let current: Option<(Value, i64)> = sqlx::query_as(&format!(
        "SELECT row_to_json(t)::jsonb, t.row_version FROM {} t WHERE t.id = $1",
        quote_ident(entity)
    ))
    .bind(golden)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((current, row_version)) = current else {
        return Err(AppError::NotFound);
    };
    let rules = load_survivorship_rules(db, entity).await?;

    let mut out = Rebuilt::default();
    let mut patch = Map::new();
    let mut chosen: Vec<(String, Uuid, &'static str)> = Vec::new();
    for attr in attrs.iter().filter(|a| !a.is_computed()) {
        let name = &attr.logicalname;
        if pinned.contains(name) {
            out.pinned += 1;
            continue;
        }
        let rule = rules.get(name);
        let pick = match rule {
            Some(r) if r.strategy == Strategy::SourceSystemRank => r
                .source_system_rank
                .as_ref()
                .and_then(|rank| rank.choose(name, &contributions)),
            // A manual attribute is a person's to set.
            Some(r) if r.strategy == Strategy::Manual => None,
            _ => newest(name, &contributions),
        };
        let Some((value, from, rule_name)) = pick else {
            continue;
        };
        if current.get(name) != Some(value) {
            patch.insert(name.clone(), value.clone());
            out.changed.push(name.clone());
        }
        chosen.push((name.clone(), from, rule_name));
    }

    if !patch.is_empty() {
        let ctx = state.base.security.resolve(actor).await?;
        // The generic update path: validation, audit, row version and the
        // change feed, as for any other edit.
        super::super::update_record_for(
            state,
            &ctx,
            actor,
            entity,
            golden,
            row_version,
            Value::Object(patch),
        )
        .await?;
    }
    for (attribute, contribution, rule) in &chosen {
        sqlx::query(&format!(
            "INSERT INTO {provenance_t} (golden_id, attribute, contribution_id, rule, chosen_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (golden_id, attribute) DO UPDATE \
                SET contribution_id = EXCLUDED.contribution_id, rule = EXCLUDED.rule, \
                    chosen_at = now() \
              WHERE {provenance_t}.pinned_by IS NULL",
            provenance_t = quote_ident(&provenance_table(entity))
        ))
        .bind(golden)
        .bind(attribute)
        .bind(contribution)
        .bind(rule)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        out.provenance += 1;
    }
    if !out.changed.is_empty() {
        distribute(state, &mut tx, entity, golden, &out.changed).await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(out)
}

/// L1-T7: the event name of a golden record's change.
pub const GOLDEN_CHANGED: &str = "master.golden_changed";
/// L1-T7: the setting naming the entities sent only while certified.
pub const CERTIFIED_ONLY: &str = "master.certified_only";

/// Whether `entity`'s golden-record changes wait for certification. Pure.
pub fn certified_only(setting: &Value, entity: &str) -> bool {
    setting
        .as_array()
        .is_some_and(|list| list.iter().any(|e| e.as_str() == Some(entity)))
}

/// L1-T7: queues `master.golden_changed` for subscribers in the rebuild's
/// transaction, naming the attributes that changed; skipped for a golden
/// record that is not certified when the entity is sent only certified.
/// Each webhook subscriber resolves its own external id when the event is
/// delivered (`attome_events::delivery`).
async fn distribute(
    state: &EngineState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity: &str,
    golden: Uuid,
    changed: &[String],
) -> Result<(), AppError> {
    let setting = attome_core::setting_registry()
        .get(CERTIFIED_ONLY)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .unwrap_or(Value::Null);
    if certified_only(&setting, entity)
        && super::steward::certification(tx, entity, golden).await?
            != super::steward::Certification::Certified
    {
        return Ok(());
    }
    attome_core::change_feed::emit_with(
        tx,
        entity,
        golden,
        attome_core::change_feed::ChangeOperation::Update,
        Some(GOLDEN_CHANGED),
        &attome_core::change_feed::ChangePayload {
            changed_attributes: changed.to_vec(),
            ..Default::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_certified_only_names_entities() {
        let setting = serde_json::json!(["account", "product"]);
        assert!(certified_only(&setting, "account"));
        assert!(!certified_only(&setting, "contact"));
        assert!(!certified_only(&Value::Null, "account"));
    }

    #[test]
    fn master_newest_takes_the_latest_filled_value() {
        let at = |m: i64| Utc::now() - chrono::Duration::minutes(m);
        let c = |m, v: Value| Contribution {
            id: Uuid::now_v7(),
            system: "crm".into(),
            received_at: at(m),
            payload: serde_json::json!({ "city": v })
                .as_object()
                .cloned()
                .unwrap(),
            validated: true,
        };
        let all = vec![
            c(30, "Jeddah".into()),
            c(5, "Riyadh".into()),
            c(1, Value::Null),
        ];
        assert_eq!(newest("city", &all).unwrap().0, "Riyadh");
        assert!(newest("zip", &all).is_none());
    }
}

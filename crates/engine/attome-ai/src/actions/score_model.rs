//! `model.score` (roadmap AD7-T1): scores a built entity's model and
//! proposes fixes with evidence. It reads, read-only:
//!
//! - the newest data profile (fill rates, distinct values, the most common
//!   values per attribute);
//! - where each attribute is used: the entity's forms (the model store's
//!   newest version of each) and its views;
//! - slow statements filtering on its attributes (the index advisor,
//!   `pg_stat_statements` when installed);
//!
//! and scores them with [`crate::builder::review::score_model`]. Every fix
//! is a draft: the route and body a builder sends in their Develop
//! workspace, where nothing publishes without the owner's review (V2-D27).
//! Nothing here writes.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_metadata::index_advisor::{self, Advice};
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::builder::review::{AttributeEvidence, SlowFilter, score_model};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MODEL_SCORE: &str = "model.score";

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["entity"],
  "properties": {
    "entity": { "type": "string", "description": "The entity's logical name" }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MODEL_SCORE,
            "Score an entity's data model from evidence (fill rates, repeated identifier values, \
             text attributes holding a handful of values, attributes on no form or view, slow \
             statements filtering without an index) and propose a draft fix for each issue. \
             Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ScoreModel)]
}

/// Each attribute's evidence from a profile's per-attribute summaries.
/// Attributes the profile does not hold keep `rows: None`. Pure.
pub fn from_profile(evidence: &mut [AttributeEvidence], fields: &Value) {
    for f in fields.as_array().into_iter().flatten() {
        let Some(a) = evidence
            .iter_mut()
            .find(|a| Some(a.name.as_str()) == f["field"].as_str())
        else {
            continue;
        };
        let rows = f["rows"].as_i64().unwrap_or(0);
        let empty = f["nulls"].as_i64().unwrap_or(0) + f["blanks"].as_i64().unwrap_or(0);
        a.rows = Some(rows);
        a.filled = (rows - empty).max(0);
        a.distinct = f["distinct_count"].as_i64().unwrap_or(0);
        a.distinct_capped = f["distinct_is_lower_bound"].as_bool().unwrap_or(false);
        a.text = f["length"].is_object();
        a.top_values = f["top_values"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["value"].as_str().map(str::to_owned))
            .take(12)
            .collect();
    }
}

/// How many of `docs` name `attribute` as a quoted JSON string. Pure.
pub fn used_in(docs: &[String], attribute: &str) -> i64 {
    let quoted = format!("\"{attribute}\"");
    i64::try_from(docs.iter().filter(|d| d.contains(&quoted)).count()).unwrap_or(i64::MAX)
}

#[derive(Debug)]
pub struct ScoreModel;

impl Action for ScoreModel {
    fn id(&self) -> ActionId {
        ActionId(MODEL_SCORE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?
                .to_owned();
            let (entity_id, names, filterable): (Uuid, Vec<String>, HashMap<String, bool>) = {
                let registry = state.entities.load();
                let meta = registry
                    .get(&entity)
                    .ok_or_else(|| AppError::Validation(format!("no entity {entity}")))?;
                let own: Vec<_> = meta
                    .attrs
                    .iter()
                    .filter(|a| !attome_core::ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
                    .collect();
                (
                    meta.entity_id,
                    own.iter().map(|a| a.logicalname.clone()).collect(),
                    own.iter()
                        .map(|a| (a.logicalname.clone(), a.is_filterable))
                        .collect(),
                )
            };
            let db = &state.base.db;
            let ids: HashMap<String, Uuid> = sqlx::query_as::<_, (String, Uuid)>(
                "SELECT logicalname, id FROM attribute_info \
                  WHERE entity_ref = $1 AND is_active IS NOT FALSE",
            )
            .bind(entity_id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
            let forms: Vec<String> = sqlx::query_scalar(
                "SELECT v.doc::text FROM metadata_object o \
                   JOIN LATERAL (SELECT doc FROM metadata_object_version \
                                  WHERE object_id = o.id ORDER BY version_no DESC LIMIT 1) v ON true \
                  WHERE o.kind = 'form' AND o.is_active AND v.doc->>'entity' = $1",
            )
            .bind(&entity)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            let views: Vec<String> = sqlx::query_scalar(
                "SELECT table_definition::text FROM view \
                  WHERE entity_logical_name = $1 AND is_active",
            )
            .bind(entity_id)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;

            let mut evidence: Vec<AttributeEvidence> = names
                .iter()
                .map(|name| AttributeEvidence {
                    name: name.clone(),
                    id: ids.get(name).copied(),
                    filterable: filterable.get(name).copied().unwrap_or(false),
                    on_forms: used_in(&forms, name),
                    on_views: used_in(&views, name),
                    ..AttributeEvidence::default()
                })
                .collect();
            let profile = attome_core::data_profile::latest(db, &entity).await?;
            if let Some(p) = &profile {
                from_profile(&mut evidence, &p.fields);
            }
            let set: BTreeSet<String> = names.iter().cloned().collect();
            let (slow, slow_note) = match index_advisor::proposals(db, &entity, &set).await? {
                Advice::Proposals(found) => (
                    found
                        .into_iter()
                        .map(|p| SlowFilter {
                            attribute: p.attribute,
                            statements: p.statements,
                            calls: p.calls,
                            worst_mean_ms: p.worst_mean_ms,
                        })
                        .collect(),
                    None,
                ),
                Advice::Unavailable(reason) => (Vec::new(), Some(reason)),
            };
            let scored = score_model(&entity, Some(entity_id), &evidence, &slow);
            Ok(ActionResult::plain(json!({
                "entity": scored.entity,
                "score": scored.score,
                "issues": scored.issues,
                "profile_id": profile.as_ref().map(|p| p.id),
                "profiled": scored.profiled,
                "slow_statements": slow_note.map_or_else(|| json!("read"), |r| json!(r)),
                "note": "drafts only: make the fixes you want in a Develop workspace; nothing publishes without the owner's review",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_review_reads_the_profile_and_usage() {
        let mut evidence = vec![
            AttributeEvidence {
                name: "status_text".into(),
                ..AttributeEvidence::default()
            },
            AttributeEvidence {
                name: "amount".into(),
                ..AttributeEvidence::default()
            },
            AttributeEvidence {
                name: "never_profiled".into(),
                ..AttributeEvidence::default()
            },
        ];
        let fields = json!([
            { "field": "status_text", "rows": 100, "nulls": 5, "blanks": 5, "distinct_count": 3,
              "distinct_is_lower_bound": false, "length": { "min": 4 },
              "top_values": [{ "value": "open", "count": 50 }, { "value": "closed", "count": 40 }] },
            { "field": "amount", "rows": 100, "nulls": 0, "blanks": 0, "distinct_count": 99,
              "distinct_is_lower_bound": true, "number": { "min": 0 } },
        ]);
        from_profile(&mut evidence, &fields);
        assert_eq!(evidence[0].rows, Some(100));
        assert_eq!(evidence[0].filled, 90);
        assert!(evidence[0].text);
        assert_eq!(evidence[0].top_values, vec!["open", "closed"]);
        assert!(!evidence[1].text && evidence[1].distinct_capped);
        assert_eq!(evidence[2].rows, None);

        let docs = vec![
            r#"{"fields":["status_text","amount"]}"#.to_owned(),
            r#"{"columns":[{"name":"amount"}]}"#.to_owned(),
        ];
        assert_eq!(used_in(&docs, "amount"), 2);
        assert_eq!(used_in(&docs, "status_text"), 1);
        assert_eq!(used_in(&docs, "status"), 0);
    }

    #[test]
    fn descriptor_is_a_read_tool() {
        let d = &descriptors()[0];
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.effect, Effect::Read);
    }
}

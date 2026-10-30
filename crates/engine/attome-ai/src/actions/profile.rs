//! L6-T8: the data profile tools.
//!
//! - `profile.summary`: the newest completed profile of an entity
//!   (`attome_core::data_profile::latest`), as masked statistics only: per
//!   attribute its row, null, blank and distinct counts, and for an
//!   attribute that is neither sensitive nor masked its number, length and
//!   date ranges. No value of a record ever leaves: top values, the
//!   smallest and largest texts and pattern examples are dropped for every
//!   attribute, and a sensitive attribute the person may not read is left
//!   out and counted.
//! - `profile.explain`: the same summary, and one model call (within the
//!   person's AI budget) that explains it in words: what is complete, what
//!   is mostly empty, what looks inconsistent.
//!
//! Both read and change nothing, as the person the agent acts for: an
//! entity they may not read has no profile for them.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::{MODULE_AI, MODULE_CORE};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const PROFILE_SUMMARY: &str = "profile.summary";
pub const PROFILE_EXPLAIN: &str = "profile.explain";
const EXPLAIN_PROMPT_VERSION: &str = "profile.explain/v1";

/// The statistics a summary keeps for every attribute.
const COUNTS: &[&str] = &[
    "rows",
    "null_pct",
    "nulls",
    "blanks",
    "distinct_count",
    "distinct_is_lower_bound",
];
/// Ranges kept only for an attribute that is neither sensitive nor masked.
const RANGES: &[&str] = &["number", "length", "date_range"];

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": {"type": "string", "description": "The entity whose newest data profile to summarise"}
  },
  "required": ["entity"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            PROFILE_SUMMARY,
            "Summarise the newest data profile of an entity: per attribute how many rows are \
             empty, blank or distinct, and number, length and date ranges for attributes that \
             are not sensitive. Never returns a record's value. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(INPUT),
        ActionDescriptor::new(
            PROFILE_EXPLAIN,
            "Explain the newest data profile of an entity in words (what is complete, what is \
             mostly empty, what looks inconsistent), with the same masked summary. One model \
             call; changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ProfileTool { explain: false }),
        Box::new(ProfileTool { explain: true }),
    ]
}

/// The masked summary of a profile's `fields`. `sensitive` are the
/// entity's sensitive attributes; `hidden` the ones the person may not
/// read, which are left out and counted. Pure.
pub fn summarize(fields: &Value, sensitive: &HashSet<String>, hidden: &HashSet<String>) -> Value {
    let mut out = Vec::new();
    let mut left_out = 0usize;
    for field in fields.as_array().into_iter().flatten() {
        let Some(name) = field["field"].as_str() else {
            continue;
        };
        if hidden.contains(name) {
            left_out += 1;
            continue;
        }
        let is_sensitive = sensitive.contains(name);
        let masked = field["masked"].as_bool().unwrap_or(false);
        let mut kept = Map::new();
        kept.insert("field".into(), Value::String(name.to_owned()));
        kept.insert("sensitive".into(), Value::Bool(is_sensitive));
        for key in COUNTS {
            if let Some(v) = field.get(*key) {
                kept.insert((*key).into(), v.clone());
            }
        }
        if !is_sensitive && !masked {
            for key in RANGES {
                if let Some(v) = field.get(*key).filter(|v| !v.is_null()) {
                    kept.insert((*key).into(), v.clone());
                }
            }
        }
        out.push(Value::Object(kept));
    }
    json!({ "fields": out, "hidden": left_out })
}

struct ProfileTool {
    explain: bool,
}

impl Action for ProfileTool {
    fn id(&self) -> ActionId {
        ActionId(if self.explain {
            PROFILE_EXPLAIN
        } else {
            PROFILE_SUMMARY
        })
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("name the entity".into()))?;
            // An entity the person may not read has no profile for them.
            if ctx.security.require(entity, "read").is_err() {
                return Err(AppError::NotFound);
            }
            let (sensitive, hidden) = {
                let registry = state.entities.load();
                let meta = registry.get(entity).ok_or(AppError::NotFound)?;
                let sensitive: HashSet<String> = meta
                    .attrs
                    .iter()
                    .filter(|a| a.is_sensitive)
                    .map(|a| a.logicalname.clone())
                    .collect();
                // D-589: a profile summarises a field across every record, so
                // the bulk field gate decides what this person sees of it.
                let hidden: HashSet<String> = meta
                    .attrs
                    .iter()
                    .filter(|a| {
                        !attome_security::field_gate::readable(
                            &ctx.security,
                            entity,
                            a,
                            meta.primary_name_attribute.as_deref(),
                            attome_security::field_gate::Surface::Bulk,
                        )
                    })
                    .map(|a| a.logicalname.clone())
                    .collect();
                (sensitive, hidden)
            };
            let Some(profile) = attome_core::data_profile::latest(&state.base.db, entity).await?
            else {
                return Ok(ActionResult::plain(json!({
                    "entity": entity,
                    "profiled": false,
                    "message": "this entity has no completed profile yet",
                })));
            };
            let mut summary = summarize(&profile.fields, &sensitive, &hidden);
            summary["entity"] = Value::String(entity.to_owned());
            summary["profiled"] = Value::Bool(true);
            summary["row_count"] = profile.row_count.into();
            summary["sample_size"] = profile.sample_size.into();
            summary["full_scan"] = Value::Bool(profile.full_scan);
            summary["profiled_at"] = profile.completed_at.map(|t| t.to_rfc3339()).into();
            if !self.explain {
                return Ok(ActionResult::plain(summary));
            }

            let client = crate::inference_client::client_for(state, PROFILE_EXPLAIN).await?;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                PROFILE_EXPLAIN,
            )
            .await?;
            let data = serde_json::to_string(&summary).map_err(AppError::internal)?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(
                    "You explain a data profile of one business entity to its data steward, \
                     in at most eight short sentences: which attributes are complete, which are \
                     mostly empty or blank, which have few distinct values, and anything that \
                     looks inconsistent. The profile is in the data block; it holds statistics \
                     only. Do not guess values."
                        .to_owned(),
                ),
                Segment::untrusted(entity, &data),
            ]));
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                PROFILE_EXPLAIN,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "profile.explain generation failed");
                AppError::internal("profile explanation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            summary["explanation"] = Value::String(generated.text.trim().to_owned());
            summary["truncated"] = Value::Bool(generated.truncated);
            Ok(ActionResult {
                value: summary,
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: EXPLAIN_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_has_no_raw_sensitive_values() {
        let fields = json!([
            {
                "field": "national_id", "rows": 100, "null_pct": 0.0, "nulls": 0, "blanks": 0,
                "distinct_count": 100, "distinct_is_lower_bound": false, "masked": true,
                "top_values": [{"value": "1012345678", "count": 1}],
                "min": "1012345678", "max": "1099999999",
                "length": {"min": 10, "max": 10, "mean": 10.0, "median": 10},
                "patterns": {"top": [{"shape": "9999999999", "example": "1012345678"}]}
            },
            {
                "field": "salary", "rows": 100, "null_pct": 5.0, "nulls": 5, "blanks": 0,
                "distinct_count": 40, "distinct_is_lower_bound": false, "masked": false,
                "number": {"min": 4000, "max": 95000, "mean": 20000.0},
                "top_values": [{"value": "95000", "count": 1}]
            },
            {
                "field": "status", "rows": 100, "null_pct": 0.0, "nulls": 0, "blanks": 2,
                "distinct_count": 3, "distinct_is_lower_bound": false, "masked": false,
                "top_values": [{"value": "open", "count": 60}],
                "min": "closed", "max": "open",
                "length": {"min": 4, "max": 6, "mean": 4.6, "median": 4}
            },
            {
                "field": "iban", "rows": 100, "masked": true,
                "top_values": [{"value": "SA0380000000608010167519", "count": 1}]
            }
        ]);
        let sensitive: HashSet<String> = ["national_id", "salary", "iban"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let hidden: HashSet<String> = ["iban".to_owned()].into_iter().collect();
        let out = summarize(&fields, &sensitive, &hidden);
        let text = out.to_string();
        for raw in [
            "1012345678",
            "1099999999",
            "95000",
            "4000",
            "SA0380000000608010167519",
            "open",
            "closed",
        ] {
            assert!(!text.contains(raw), "{raw} leaked: {text}");
        }
        assert_eq!(
            out["hidden"], 1,
            "the unreadable sensitive field is counted"
        );
        let kept = out["fields"].as_array().unwrap();
        assert_eq!(kept.len(), 3);
        assert_eq!(kept[0]["distinct_count"], 100);
        assert_eq!(kept[0]["sensitive"], true);
        assert!(
            kept[0].get("length").is_none(),
            "no ranges on a sensitive field"
        );
        assert!(kept[1].get("number").is_none());
        assert_eq!(kept[2]["blanks"], 2);
        assert_eq!(kept[2]["length"]["max"], 6, "ranges stay on a plain field");
        assert!(kept[2].get("top_values").is_none());
    }

    #[test]
    fn profile_tools_are_read_only() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
        assert_eq!(executors().len(), descriptors().len());
    }
}

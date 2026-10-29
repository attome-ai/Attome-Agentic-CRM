//! `metric.draft_definition` and `metric.draft_commentary` (roadmap P9-T13):
//! drafts for a person, never writes.
//!
//! - `metric.draft_definition` turns a sentence ("won deal amount per month
//!   by owner") into a metric builder spec (`attome_metric::builder::
//!   MetricSpec`), checked with `validate_spec` against the deployment's
//!   entities before it is returned. Nothing is saved: a person builds the
//!   metric from it (`POST /api/v1/metrics/{id}/builder`).
//! - `metric.draft_commentary` drafts a period's commentary from the
//!   metric's stored values the caller may see, and returns it with the
//!   `record.create` call that would save it as a `metric_comment`. The
//!   save is that ordinary guarded write (write caps, approval, the acting
//!   person's permissions), made by the person or by an agent through it.
//!
//! Neither can certify, set a target or name a steward: the only fields a
//! proposed comment carries are [`COMMENT_FIELDS`].

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_metric::builder::MetricSpec;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const METRIC_DRAFT_DEFINITION: &str = "metric.draft_definition";
pub const METRIC_DRAFT_COMMENTARY: &str = "metric.draft_commentary";
/// Bumped whenever a prompt changes in a way that could move results.
pub const DRAFT_PROMPT_VERSION: &str = "metric.draft/v1";

/// The fields a drafted comment may carry.
pub const COMMENT_FIELDS: [&str; 4] = ["metric_ref", "period_start", "body", "dimension_value"];

/// Periods of history a commentary draft reads.
const HISTORY: i64 = 6;

const DEFINITION_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "sentence": { "type": "string", "description": "What the metric should measure, in the person's words." },
    "entity": { "type": "string", "description": "The entity to measure, when known." }
  },
  "required": ["sentence"],
  "additionalProperties": false
}"#;

const COMMENTARY_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "metric_id": { "type": "string", "format": "uuid" },
    "period_start": { "type": "string", "format": "date", "description": "The period commented on; the newest when omitted." },
    "language": { "type": "string", "description": "The language to write in; the person's own when omitted." }
  },
  "required": ["metric_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            METRIC_DRAFT_DEFINITION,
            "Draft a metric from a sentence: the entity, the aggregate, the measured field, the \
             date that places a record in a period, filters and dimensions, as a builder spec \
             checked against the deployment's entities. Saves nothing; a person builds the metric.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(DEFINITION_SCHEMA),
        ActionDescriptor::new(
            METRIC_DRAFT_COMMENTARY,
            "Draft commentary on a metric's period from its stored values, and return the \
             record.create call that would save it as a comment. Saves nothing itself.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(COMMENTARY_SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(DraftDefinition), Box::new(DraftCommentary)]
}

/// The model's answer without a Markdown code fence around it. Pure.
pub fn strip_fence(text: &str) -> &str {
    let t = text.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t);
    t.strip_suffix("```").unwrap_or(t).trim()
}

/// The `record.create` call that saves a drafted comment: only
/// [`COMMENT_FIELDS`]. Pure.
pub fn comment_call(metric_id: Uuid, period_start: &str, body: &str) -> Value {
    json!({
        "action": crate::actions::record_write::RECORD_CREATE,
        "args": {
            "entity": "metric_comment",
            "values": {
                "metric_ref": metric_id,
                "period_start": period_start,
                "body": body,
            }
        }
    })
}

/// One model call with the shared admission, budget and approval rules.
async fn generate(
    state: &EngineState,
    ctx: &ActionContext,
    action: &str,
    system: String,
    facts: String,
) -> Result<(String, Option<Provenance>), AppError> {
    let client = crate::inference_client::client_for(state, action).await?;
    let mut request = GenerationRequest::new(crate::prompt::assemble(&[
        Segment::trusted(system),
        Segment::untrusted("facts", facts),
    ]));
    request.temperature = 0.0;
    crate::model_registry::require_approved_model(&state.base.db, client.model_id(), action)
        .await?;
    let grant = crate::budget_guard::admit(
        state,
        ctx,
        attome_inference::budget::Priority::Chat,
        action,
        &mut request,
    )
    .await?;
    let generated = client.generate(request).await.map_err(|e| {
        tracing::warn!(error = %e, "{action} generation failed");
        AppError::internal("the draft could not be written")
    })?;
    grant.settle(state, &generated.usage).await;
    let provenance = Some(Provenance {
        model_id: generated.usage.model_id.clone(),
        prompt_version: DRAFT_PROMPT_VERSION.to_owned(),
        suggestion_id: None,
    });
    Ok((generated.text, provenance))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefinitionArgs {
    sentence: String,
    #[serde(default)]
    entity: Option<String>,
}

pub(crate) struct DraftDefinition;

impl Action for DraftDefinition {
    fn id(&self) -> ActionId {
        ActionId(METRIC_DRAFT_DEFINITION)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: DefinitionArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {METRIC_DRAFT_DEFINITION} arguments: {e}"))
            })?;
            // The entities and fields the caller may read, as the model's
            // vocabulary.
            let catalogue: Vec<Value> = {
                let registry = state.entities.load();
                registry
                    .iter()
                    .filter(|m| args.entity.as_deref().is_none_or(|e| e == m.logicalname))
                    .filter(|m| {
                        ctx.security.is_admin
                            || ctx
                                .security
                                .privileges
                                .contains(&format!("{}.read", m.logicalname))
                    })
                    .take(40)
                    .map(|m| {
                        json!({
                            "entity": m.logicalname,
                            "fields": m.attrs.iter()
                                .filter(|a| !a.is_read_gated())
                                .map(|a| json!({ "name": a.logicalname, "type": a.field_type().as_str() }))
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect()
            };
            let system = "You draft a metric definition. Answer with one JSON object and nothing \
                else: {\"entity_logicalname\", \"aggregate\" (count, sum, avg, median, min or max), \
                \"measure_attribute\" (a number field, omitted for count), \"date_attribute\" (a \
                date field, created_at or modified_at), \"filters\": [{\"attribute\", \"op\" (eq, \
                neq, gt, gte, lt, lte, in, is_null, is_not_null), \"value\"}], \
                \"dimension_attributes\": [at most three fields]}. Use only the entities and \
                fields given."
                .to_owned();
            let facts = json!({ "sentence": args.sentence, "entities": catalogue }).to_string();
            let (text, provenance) =
                generate(state, ctx, METRIC_DRAFT_DEFINITION, system, facts).await?;
            let spec: MetricSpec = serde_json::from_str(strip_fence(&text)).map_err(|e| {
                AppError::Validation(format!("the drafted metric is not a builder spec: {e}"))
            })?;
            let issue = {
                let registry = state.entities.load();
                attome_metric::builder::validate_spec(&spec, &registry)
                    .err()
                    .map(|e| e.to_string())
            };
            Ok(ActionResult {
                value: json!({
                    "spec": spec,
                    "valid": issue.is_none(),
                    "issue": issue,
                    "saved": false,
                }),
                provenance,
            })
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentaryArgs {
    metric_id: Uuid,
    #[serde(default)]
    period_start: Option<chrono::NaiveDate>,
    #[serde(default)]
    language: Option<String>,
}

pub(crate) struct DraftCommentary;

impl Action for DraftCommentary {
    fn id(&self) -> ActionId {
        ActionId(METRIC_DRAFT_COMMENTARY)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: CommentaryArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {METRIC_DRAFT_COMMENTARY} arguments: {e}"))
            })?;
            if !(ctx.security.is_admin
                || ctx
                    .security
                    .privileges
                    .contains("dashboard_metric_definition.read"))
            {
                return Err(AppError::Forbidden);
            }
            let db = &state.base.db;
            let metric = attome_metric::metric::fetch_metric(db, args.metric_id).await?;
            attome_metric::governance::require_visible(db, &ctx.security, args.metric_id).await?;
            let history: Vec<(chrono::NaiveDate, Option<f64>, String)> = sqlx::query_as(
                "SELECT period_start, actual, status FROM metric_snapshot \
                  WHERE metric_ref = $1 AND dimension_attribute IS NULL \
                    AND ($2::date IS NULL OR period_start <= $2) \
                  ORDER BY period_start DESC, computed_at DESC LIMIT $3",
            )
            .bind(args.metric_id)
            .bind(args.period_start)
            .bind(HISTORY * 3)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            // One row per period, newest computation first.
            let mut seen = std::collections::BTreeSet::new();
            let history: Vec<Value> = history
                .into_iter()
                .filter(|(period, ..)| seen.insert(*period))
                .take(usize::try_from(HISTORY).unwrap_or(6))
                .map(|(period, actual, status)| {
                    json!({ "period_start": period, "actual": actual, "status": status })
                })
                .collect();
            let Some(period) = history
                .first()
                .and_then(|h| h["period_start"].as_str())
                .map(str::to_owned)
            else {
                return Err(AppError::Validation(
                    "the metric has no stored value to comment on".into(),
                ));
            };
            let language = args
                .language
                .as_deref()
                .unwrap_or("the language the person wrote in");
            let system = format!(
                "You draft a short commentary on a business metric's latest period for a \
                 person to review. Write in {language}, two to four sentences: the value, how \
                 it moved against the previous periods and its status. Use only the facts \
                 given; do not guess causes or give advice."
            );
            let facts = json!({
                "metric": { "period": metric.period, "direction": metric.direction },
                "periods_newest_first": history,
            })
            .to_string();
            let (text, provenance) =
                generate(state, ctx, METRIC_DRAFT_COMMENTARY, system, facts).await?;
            let body = text.trim().to_owned();
            Ok(ActionResult {
                value: json!({
                    "metric_id": args.metric_id,
                    "period_start": period,
                    "draft": body,
                    "saved": false,
                    "save_with": comment_call(args.metric_id, &period, &body),
                }),
                provenance,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_definition_never_writes() {
        for d in descriptors() {
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        }
        assert_eq!(
            strip_fence("```json\n{\"aggregate\": \"count\"}\n```"),
            "{\"aggregate\": \"count\"}"
        );
    }

    #[test]
    fn commentary_goes_through_write_guard() {
        let id = Uuid::from_u128(7);
        let call = comment_call(id, "2026-09-01", "Up 4% on August.");
        assert_eq!(call["action"], crate::actions::record_write::RECORD_CREATE);
        assert_eq!(call["args"]["entity"], "metric_comment");
        let values = call["args"]["values"].as_object().unwrap();
        for key in values.keys() {
            assert!(COMMENT_FIELDS.contains(&key.as_str()), "{key}");
        }
        for forbidden in ["certified", "certified_at", "steward_ref", "target_value"] {
            assert!(!values.contains_key(forbidden));
        }
    }
}

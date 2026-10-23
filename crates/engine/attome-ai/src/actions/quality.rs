//! L2-T9: the data quality tools.
//!
//! - `quality.explain_drop(entity, day?)`: what changed between a day's
//!   quality snapshot and the day before, dimension by dimension, which
//!   dimension fell most, and where the open issues come from (channel,
//!   import, person) and which attributes hold most of them.
//! - `quality.record_score(entity, record_id)`: one record's quality score
//!   and failed checks (`quality_record_score`, kept when the entity's record
//!   scoring is on), and whether it is below the entity's target, so an
//!   agent knows before it relies on the record.
//! - `quality.propose_rules(entity)`: measure-only rule drafts from the
//!   newest data profile (an attribute almost always filled, a number never
//!   negative), each with how many profiled rows it would fail. Drafts
//!   only: a builder adds the ones they want, through publish; the tool
//!   writes nothing.
//!
//! All three read and change nothing, as the person the agent acts for:
//! they need read access to the entity, and `record_score` to the record.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use chrono::NaiveDate;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const QUALITY_EXPLAIN_DROP: &str = "quality.explain_drop";
pub const QUALITY_RECORD_SCORE: &str = "quality.record_score";
pub const QUALITY_PROPOSE_RULES: &str = "quality.propose_rules";

/// The target score when an entity sets none.
const DEFAULT_THRESHOLD: f64 = 70.0;
/// An attribute filled in at least this share of profiled rows gets a
/// "filled" rule draft.
const FILLED_SHARE: f64 = 0.99;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            QUALITY_EXPLAIN_DROP,
            "Explain a change in an entity's data quality score: each dimension's score on the \
             day and the day before, the dimension that fell most, and where the open issues \
             come from (channel, import, person) and which attributes hold them. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "entity": {"type": "string"},
    "day": {"type": "string", "format": "date", "description": "YYYY-MM-DD; today when absent"}
  },
  "required": ["entity"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            QUALITY_RECORD_SCORE,
            "Tell whether a record's data quality is below its entity's target before relying \
             on it: its score and failed checks. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "entity": {"type": "string"},
    "record_id": {"type": "string", "format": "uuid"}
  },
  "required": ["entity", "record_id"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            QUALITY_PROPOSE_RULES,
            "Propose measure-only data quality rules for an entity from its newest data \
             profile, each with how many profiled rows it would fail. Returns drafts for a \
             builder to add through publish; writes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {"entity": {"type": "string"}},
  "required": ["entity"],
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Tool(QUALITY_EXPLAIN_DROP)),
        Box::new(Tool(QUALITY_RECORD_SCORE)),
        Box::new(Tool(QUALITY_PROPOSE_RULES)),
    ]
}

/// Each dimension's change between two days, largest fall first. Pure.
pub fn changes(today: &[(String, f64)], before: &[(String, f64)]) -> Vec<Value> {
    let mut out: Vec<(String, f64, Option<f64>)> = today
        .iter()
        .map(|(d, s)| {
            let prev = before.iter().find(|(p, _)| p == d).map(|(_, s)| *s);
            (d.clone(), *s, prev)
        })
        .collect();
    out.sort_by(|a, b| {
        let fall = |x: &(String, f64, Option<f64>)| x.2.map_or(0.0, |p| p - x.1);
        fall(b)
            .partial_cmp(&fall(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    out.into_iter()
        .map(|(dimension, score, before)| {
            json!({
                "dimension": dimension,
                "score": score,
                "before": before,
                "change": before.map(|b| score - b),
            })
        })
        .collect()
}

/// Rule drafts from a profile's per-attribute summaries. Pure: it reads the
/// summaries it is given and returns drafts.
pub fn propose(fields: &Value) -> Vec<Value> {
    let mut drafts = Vec::new();
    for f in fields.as_array().into_iter().flatten() {
        let Some(name) = f["field"].as_str() else {
            continue;
        };
        let rows = f["rows"].as_i64().unwrap_or(0);
        if rows <= 0 {
            continue;
        }
        let empty = f["nulls"].as_i64().unwrap_or(0) + f["blanks"].as_i64().unwrap_or(0);
        if empty > 0 && (rows - empty) as f64 / rows as f64 >= FILLED_SHARE {
            drafts.push(json!({
                "attribute": name,
                "dimension": "validity",
                "expression": format!("{name} != null"),
                "why": format!("{name} is filled in {} of {rows} profiled rows", rows - empty),
                "would_fail": empty,
            }));
        }
        if let Some(min) = f["number"]["min"].as_f64()
            && min >= 0.0
        {
            drafts.push(json!({
                "attribute": name,
                "dimension": "validity",
                "expression": format!("{name} >= 0"),
                "why": format!("{name} is never negative in the profiled rows"),
                "would_fail": 0,
            }));
        }
    }
    drafts
}

fn entity_of(args: &Value) -> Result<&str, AppError> {
    args["entity"]
        .as_str()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| AppError::Validation("name the entity".into()))
}

/// An entity's snapshot scores on `day`, by dimension.
async fn snapshot(
    db: &attome_db::DbPool,
    entity: &str,
    day: NaiveDate,
) -> Result<Vec<(String, f64)>, AppError> {
    sqlx::query_as(
        "SELECT dimension, score::float8 FROM quality_snapshot           WHERE entity = $1 AND day = $2 ORDER BY dimension",
    )
    .bind(entity)
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

struct Tool(&'static str);

impl Action for Tool {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = entity_of(args)?;
            if ctx.security.require(entity, "read").is_err() {
                return Err(AppError::NotFound);
            }
            let db = &state.base.db;
            let value = match self.0 {
                QUALITY_EXPLAIN_DROP => {
                    let day = match args["day"].as_str() {
                        Some(d) => NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| {
                            AppError::Validation("day is a date, YYYY-MM-DD".into())
                        })?,
                        None => chrono::Utc::now().date_naive(),
                    };
                    let today = snapshot(db, entity, day).await?;
                    let before = snapshot(db, entity, day - chrono::Duration::days(1)).await?;
                    let sources: Vec<(String, Option<String>, i64)> = sqlx::query_as(
                        "SELECT kind, value, n FROM ( \
                             SELECT 'channel' AS kind, source_channel AS value, count(*) AS n \
                               FROM quality_issue WHERE entity_logicalname = $1 AND status = 'open' \
                              GROUP BY source_channel \
                             UNION ALL \
                             SELECT 'import', source_import_id::text, count(*) FROM quality_issue \
                              WHERE entity_logicalname = $1 AND status = 'open' \
                                AND source_import_id IS NOT NULL GROUP BY source_import_id \
                             UNION ALL \
                             SELECT 'person', source_actor::text, count(*) FROM quality_issue \
                              WHERE entity_logicalname = $1 AND status = 'open' \
                                AND source_actor IS NOT NULL GROUP BY source_actor \
                         ) s ORDER BY n DESC LIMIT 5",
                    )
                    .bind(entity)
                    .fetch_all(db)
                    .await
                    .map_err(AppError::internal)?;
                    let attributes: Vec<(String, String, i64)> = sqlx::query_as(
                        "SELECT field_logicalname, dimension, count(*) FROM quality_issue \
                          WHERE entity_logicalname = $1 AND status = 'open' \
                          GROUP BY field_logicalname, dimension ORDER BY count(*) DESC LIMIT 5",
                    )
                    .bind(entity)
                    .fetch_all(db)
                    .await
                    .map_err(AppError::internal)?;
                    let dimensions = changes(&today, &before);
                    json!({
                        "entity": entity,
                        "day": day.to_string(),
                        "snapshot": !today.is_empty(),
                        "biggest_fall": dimensions.first()
                            .filter(|d| d["change"].as_f64().is_some_and(|c| c < 0.0))
                            .map(|d| d["dimension"].clone()),
                        "dimensions": dimensions,
                        "issue_sources": sources.into_iter().map(|(kind, value, n)| json!({
                            "kind": kind, "value": value.unwrap_or_else(|| "unknown".into()), "open_issues": n,
                        })).collect::<Vec<_>>(),
                        "issue_attributes": attributes.into_iter().map(|(field, dimension, n)| json!({
                            "attribute": if field.is_empty() { Value::Null } else { Value::String(field) },
                            "dimension": dimension, "open_issues": n,
                        })).collect::<Vec<_>>(),
                    })
                }
                QUALITY_RECORD_SCORE => {
                    let record: Uuid = args["record_id"]
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .ok_or_else(|| AppError::Validation("record_id is a uuid".into()))?;
                    let entity_id = state
                        .entities
                        .load()
                        .get(entity)
                        .map(|m| m.entity_id)
                        .ok_or(AppError::NotFound)?;
                    attome_records::entity_crud::require_record_access(
                        state,
                        &ctx.security,
                        entity_id,
                        entity,
                        record,
                        RecordAction::Read,
                    )
                    .await?;
                    let row: Option<(f64, Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                        "SELECT score::float8, findings, updated_at FROM quality_record_score \
                          WHERE entity = $1 AND record_id = $2",
                    )
                    .bind(entity)
                    .bind(record)
                    .fetch_optional(db)
                    .await
                    .map_err(AppError::internal)?;
                    let threshold: f64 = sqlx::query_scalar(
                        "SELECT threshold::float8 FROM quality_target WHERE entity = $1",
                    )
                    .bind(entity)
                    .fetch_optional(db)
                    .await
                    .map_err(AppError::internal)?
                    .unwrap_or(DEFAULT_THRESHOLD);
                    match row {
                        Some((score, findings, at)) => json!({
                            "entity": entity, "record_id": record, "scored": true,
                            "score": score, "threshold": threshold,
                            "below_threshold": score < threshold,
                            "findings": findings, "scored_at": at.to_rfc3339(),
                        }),
                        None => json!({
                            "entity": entity, "record_id": record, "scored": false,
                            "message": "this record has no quality score (record scoring is off for the entity, or it has not been scored yet)",
                        }),
                    }
                }
                _ => match attome_core::data_profile::latest(db, entity).await? {
                    Some(profile) => {
                        let drafts = propose(&profile.fields);
                        json!({
                            "entity": entity, "profile_id": profile.id,
                            "drafts": drafts,
                            "note": "drafts only: add the ones you want as quality rules through publish",
                        })
                    }
                    None => json!({
                        "entity": entity, "drafts": [],
                        "message": "this entity has no completed profile yet; profile it first",
                    }),
                },
            };
            Ok(ActionResult::plain(value))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_valid() {
        let ds = descriptors();
        assert_eq!(ds.len(), 3);
        assert_eq!(executors().len(), ds.len());
        for d in &ds {
            assert!(d.id.0.starts_with("quality."), "{}", d.id.0);
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
    }

    #[test]
    fn propose_rules_writes_nothing() {
        let fields = json!([
            {"field": "email", "rows": 1000, "nulls": 3, "blanks": 0},
            {"field": "notes", "rows": 1000, "nulls": 600, "blanks": 0},
            {"field": "amount", "rows": 1000, "nulls": 0, "blanks": 0, "number": {"min": 0.0, "max": 9.0}},
            {"field": "balance", "rows": 1000, "nulls": 0, "blanks": 0, "number": {"min": -5.0}}
        ]);
        let before = fields.clone();
        let drafts = propose(&fields);
        assert_eq!(fields, before, "the profile is only read");
        let expressions: Vec<&str> = drafts
            .iter()
            .filter_map(|d| d["expression"].as_str())
            .collect();
        assert_eq!(expressions, vec!["email != null", "amount >= 0"]);
        assert_eq!(drafts[0]["would_fail"], 3);
        // The tool's only effect is reading.
        for d in descriptors() {
            assert_eq!(d.effect, Effect::Read);
        }
    }

    #[test]
    fn quality_changes_put_the_biggest_fall_first() {
        let today = vec![
            ("completeness".to_owned(), 80.0),
            ("overall".to_owned(), 70.0),
            ("validity".to_owned(), 50.0),
        ];
        let before = vec![
            ("completeness".to_owned(), 82.0),
            ("overall".to_owned(), 85.0),
            ("validity".to_owned(), 90.0),
        ];
        let out = changes(&today, &before);
        assert_eq!(out[0]["dimension"], "validity");
        assert_eq!(out[0]["change"], -40.0);
        assert_eq!(out[2]["dimension"], "completeness");
    }
}

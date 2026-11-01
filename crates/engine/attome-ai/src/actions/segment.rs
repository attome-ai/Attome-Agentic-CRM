//! Segment actions (roadmap E7-T11), read-only:
//!
//! - `segment.explain_change` explains why a marketing list's size changed
//!   between two dates: how many people entered and left, grouped by the
//!   reason the membership event recorded (`scheduled`, `live`, `manual`,
//!   an import, a form, a flow).
//! - `segment.lookalike` suggests conditions for a look-alike segment: the
//!   choice values that are clearly more common among the list's members
//!   than among all records of its entity.
//!
//! Both need the caller's `marketing_list.read` and a list they may read,
//! and are hidden without the marketing module. Only counts and choice
//! values reach the model, never a person: look-alike reads only the members
//! the caller may read, and only filterable, ungated, general-classification
//! single-choice fields (a lookup value would name a record).

use std::future::Future;
use std::pin::Pin;

use attome_core::business_rules::ConditionFieldKind;
use attome_core::{EngineState, quote_ident};
use attome_modules::MODULE_MARKETING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXPLAIN_CHANGE: &str = "segment.explain_change";
pub const LOOKALIKE: &str = "segment.lookalike";

/// The longest window one explanation reads.
const MAX_DAYS: i64 = 366;
/// Members one look-alike reads, newest first.
const MAX_MEMBERS: i64 = 5_000;
/// Fewer readable members than this suggest nothing.
const MIN_MEMBERS: usize = 5;
/// Fields one look-alike compares.
const MAX_FIELDS: usize = 12;
/// Values compared per field.
const PER_FIELD: i64 = 3;
/// Suggestions returned.
const TOP: usize = 10;

const EXPLAIN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "list_id": { "type": "string", "format": "uuid" },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date", "description": "inclusive" }
  },
  "required": ["list_id", "from", "to"],
  "additionalProperties": false
}"#;

const LOOKALIKE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "list_id": { "type": "string", "format": "uuid" }
  },
  "required": ["list_id"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_MARKETING,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            EXPLAIN_CHANGE,
            "Explain a change in a marketing list's size between two dates: how many people \
             entered and left, grouped by why (a scheduled or live refresh, a manual change, \
             an import, a form or a flow).",
            EXPLAIN_SCHEMA,
        ),
        read(
            LOOKALIKE,
            "Suggest conditions for a look-alike segment of a marketing list: the choice values \
             clearly more common among its members than among all records. Nothing is saved.",
            LOOKALIKE_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Segment(EXPLAIN_CHANGE)),
        Box::new(Segment(LOOKALIKE)),
    ]
}

/// One reason's movement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    pub reason: String,
    pub entered: i64,
    pub left: i64,
}

/// `(change, reason, count)` rows grouped by reason, the biggest movement
/// first. Pure.
pub fn group_by_reason(rows: &[(String, String, i64)]) -> Vec<ReasonCount> {
    let mut out: Vec<ReasonCount> = Vec::new();
    for (change, reason, n) in rows {
        let at = match out.iter().position(|r| &r.reason == reason) {
            Some(at) => at,
            None => {
                out.push(ReasonCount {
                    reason: reason.clone(),
                    entered: 0,
                    left: 0,
                });
                out.len() - 1
            }
        };
        match change.as_str() {
            "entered" => out[at].entered += n,
            "left" => out[at].left += n,
            _ => {}
        }
    }
    out.sort_by(|a, b| {
        (b.entered + b.left)
            .cmp(&(a.entered + a.left))
            .then_with(|| a.reason.cmp(&b.reason))
    });
    out
}

/// One suggested condition.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub field: String,
    pub op: &'static str,
    pub value: String,
    /// Share of the list's readable members with this value.
    pub member_share: f64,
    /// Share of all live records of the entity with it.
    pub overall_share: f64,
    /// `member_share / overall_share`.
    pub lift: f64,
}

/// One value's counts: field, value, members with it, all records with it.
pub type ValueCount = (String, String, i64, i64);

/// The values at least a fifth of the members share and at least half as
/// common again among them as overall, the highest lift first. Pure.
pub fn suggest(members: i64, total: i64, values: &[ValueCount]) -> Vec<Suggestion> {
    if members <= 0 || total <= 0 {
        return Vec::new();
    }
    let mut out: Vec<Suggestion> = values
        .iter()
        .filter_map(|(field, value, in_list, overall)| {
            let member_share = *in_list as f64 / members as f64;
            let overall_share = (*overall).max(1) as f64 / total as f64;
            let lift = member_share / overall_share;
            (member_share >= 0.2 && lift >= 1.5).then(|| Suggestion {
                field: field.clone(),
                op: "eq",
                value: value.clone(),
                member_share,
                overall_share,
                lift,
            })
        })
        .collect();
    out.sort_by(|a, b| b.lift.total_cmp(&a.lift));
    out.truncate(TOP);
    out
}

fn date_arg(args: &Value, key: &str) -> Result<NaiveDate, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a date, YYYY-MM-DD")))
}

fn list_arg(args: &Value) -> Result<Uuid, AppError> {
    args.get("list_id")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::Validation("list_id must be an id".into()))
}

fn day_start(d: NaiveDate) -> DateTime<Utc> {
    d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc()
}

async fn require_list(
    state: &EngineState,
    ctx: &ActionContext,
    list: Uuid,
) -> Result<(), AppError> {
    if attome_records::entity_crud::referenced_record_visible(
        state,
        &ctx.security,
        "marketing_list",
        list,
    )
    .await?
    {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

async fn explain_change(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let list = list_arg(args)?;
    let (from, to) = (date_arg(args, "from")?, date_arg(args, "to")?);
    let days = (to - from).num_days() + 1;
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(AppError::Validation(format!(
            "to is on or after from, at most {MAX_DAYS} days later"
        )));
    }
    require_list(state, ctx, list).await?;
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT change, reason, COUNT(*) FROM marketing_list_membership_event \
          WHERE list_id = $1 AND at >= $2 AND at < $3 \
          GROUP BY change, reason",
    )
    .bind(list)
    .bind(day_start(from))
    .bind(day_start(to + Duration::days(1)))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let reasons = group_by_reason(&rows);
    let entered: i64 = reasons.iter().map(|r| r.entered).sum();
    let left: i64 = reasons.iter().map(|r| r.left).sum();
    Ok(json!({
        "list_id": list,
        "window": { "from": from, "to": to },
        "entered": entered,
        "left": left,
        "net": entered - left,
        "by_reason": reasons,
    }))
}

async fn lookalike(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<Value, AppError> {
    let list = list_arg(args)?;
    require_list(state, ctx, list).await?;
    let db = &state.base.db;
    let members: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT person_id, person_entity FROM marketing_list_member \
          WHERE list_id = $1 ORDER BY added_at DESC LIMIT $2",
    )
    .bind(list)
    .bind(MAX_MEMBERS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let Some(entity) = members.first().map(|(_, e)| e.clone()) else {
        return Ok(json!({ "list_id": list, "saved": false, "suggestions": [] }));
    };
    let ids: Vec<Uuid> = members
        .iter()
        .filter(|(_, e)| *e == entity)
        .map(|(id, _)| *id)
        .collect();
    let visible: Vec<Uuid> =
        attome_marketing::segment_insight::readable(state, &ctx.security, &entity, &ids)
            .await?
            .into_iter()
            .collect();
    if visible.len() < MIN_MEMBERS {
        return Ok(json!({
            "list_id": list,
            "saved": false,
            "suggestions": [],
            "note": "too few members you may read to compare",
        }));
    }
    let fields: Vec<String> = state
        .entities
        .load()
        .get(&entity)
        .map(|meta| {
            meta.attrs
                .iter()
                .filter(|a| {
                    a.is_filterable
                        && !a.is_sensitive
                        && !a.is_read_gated()
                        && matches!(
                            a.data_classification,
                            attome_core::meta_registry::DataClassification::General
                        )
                        && matches!(
                            ConditionFieldKind::of_attr(a),
                            Some(ConditionFieldKind::Choice)
                        )
                })
                .take(MAX_FIELDS)
                .map(|a| a.logicalname.clone())
                .collect()
        })
        .unwrap_or_default();
    let table = quote_ident(&entity);
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} t WHERE t.is_active IS NOT FALSE"
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let mut values: Vec<ValueCount> = Vec::new();
    for field in &fields {
        let col = quote_ident(field);
        let top: Vec<(String, i64)> = sqlx::query_as(&format!(
            "SELECT t.{col}::text, COUNT(*) FROM {table} t \
              WHERE t.id = ANY($1) AND t.{col} IS NOT NULL \
              GROUP BY 1 ORDER BY 2 DESC LIMIT $2"
        ))
        .bind(&visible)
        .bind(PER_FIELD)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (value, in_list) in top {
            let overall: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} t \
                  WHERE t.is_active IS NOT FALSE AND t.{col}::text = $1"
            ))
            .bind(&value)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            values.push((field.clone(), value, in_list, overall));
        }
    }
    Ok(json!({
        "list_id": list,
        "saved": false,
        "target_entity": entity,
        "members_compared": visible.len(),
        "suggestions": suggest(visible.len() as i64, total, &values),
    }))
}

struct Segment(&'static str);

impl Action for Segment {
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
            ctx.security.require("marketing_list", "read")?;
            let out = match self.0 {
                EXPLAIN_CHANGE => explain_change(state, ctx, args).await?,
                LOOKALIKE => lookalike(state, ctx, args).await?,
                _ => return Err(AppError::NotFound),
            };
            Ok(ActionResult::plain(out))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_change_groups_by_reason() {
        let rows = vec![
            ("entered".to_owned(), "scheduled".to_owned(), 40),
            ("left".to_owned(), "scheduled".to_owned(), 5),
            ("entered".to_owned(), "manual".to_owned(), 3),
            ("left".to_owned(), "live".to_owned(), 12),
        ];
        let grouped = group_by_reason(&rows);
        assert_eq!(grouped[0].reason, "scheduled");
        assert_eq!((grouped[0].entered, grouped[0].left), (40, 5));
        assert_eq!(grouped[1].reason, "live");
        assert_eq!(grouped.len(), 3);
    }

    #[test]
    fn lookalike_keeps_values_clearly_more_common_in_the_list() {
        let values = vec![
            ("industry".to_owned(), "retail".to_owned(), 60, 1_000),
            ("industry".to_owned(), "banking".to_owned(), 30, 4_000),
            ("region".to_owned(), "riyadh".to_owned(), 10, 100),
        ];
        // 100 members, 10,000 records: retail 60% vs 10% (lift 6), banking
        // 30% vs 40% (no lift), riyadh 10% of members (too few).
        let got = suggest(100, 10_000, &values);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "retail");
        assert!((got[0].lift - 6.0).abs() < 1e-9);
        assert!(suggest(0, 10, &values).is_empty());
    }

    #[test]
    fn hidden_without_module() {
        for d in descriptors() {
            assert_eq!(d.module, MODULE_MARKETING, "{}", d.id.0);
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        }
        assert_eq!(executors().len(), descriptors().len());
    }
}

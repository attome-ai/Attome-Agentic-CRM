//! Segment actions (roadmap E7-T11), read-only:
//!
//! - `segment.draft` drafts a segment from a description: the model writes
//!   one SELECT over a contact, lead or account table (alias `t`, returning
//!   `t.id`, only the fields given), which passes the checks a stored-query
//!   publish runs (`attome_records::query_admin::check_draft_query`: plan,
//!   no function scans, registered entity tables only, describe) and must
//!   read that one table; a failing draft goes back to the model once with
//!   the error, then the action gives up. It returns the query, the
//!   planner's row estimate and the two calls that would save it (publish
//!   the stored query, then `record.create` the list), and saves nothing.
//!   Administrators only, since publishing a stored query is theirs and the
//!   draft is planned on the read-only pool as the describe route does.
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
pub const DRAFT: &str = "segment.draft";
/// Bumped whenever the draft prompt changes in a way that could move results.
pub const DRAFT_PROMPT_VERSION: &str = "segment.draft/v1";

/// The entities a segment can be drafted over.
pub const DRAFT_TARGETS: [&str; 3] = ["contact", "lead", "account"];
/// Fields of the target offered to the model.
const DRAFT_FIELDS: usize = 60;
/// Model answers one draft may take: the first and one retry.
const DRAFT_ATTEMPTS: usize = 2;

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

const DRAFT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "description": { "type": "string", "description": "Who should be in the segment, in Arabic or English." },
    "entity": { "type": "string", "enum": ["contact", "lead", "account"], "description": "Whose records; contact by default." }
  },
  "required": ["description"],
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
        ActionDescriptor::new(
            DRAFT,
            "Draft a marketing segment from a description: returns a checked query over contacts, \
             leads or accounts, an estimate of how many it holds, and the calls that would save it \
             as a stored query and a list. Nothing is saved. Administrators only.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_MARKETING,
            &["system.admin"],
        )
        .input_schema(DRAFT_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Segment(EXPLAIN_CHANGE)),
        Box::new(Segment(LOOKALIKE)),
        Box::new(Segment(DRAFT)),
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

/// Why a checked draft over `entity` cannot be a segment, if it cannot: it
/// must read that one table and return `id`. Pure.
pub fn draft_problem(
    entity: &str,
    check: &attome_records::query_admin::DraftQueryCheck,
) -> Option<String> {
    if check.relations.len() != 1 || check.relations[0] != entity {
        return Some(format!(
            "the query must read only the {entity} table, as t; it reads {:?}",
            check.relations
        ));
    }
    if !check.columns.iter().any(|c| c == "id") {
        return Some("the query must return the records' id (t.id)".into());
    }
    None
}

/// The calls that save a checked draft: the stored query (`POST
/// /api/v1/admin/queries`, an administrator's), then the list over it
/// through `record.create`. Pure.
pub fn draft_save_calls(
    entity: &str,
    entity_id: Uuid,
    name: &str,
    sql: &str,
    title: &str,
) -> Value {
    json!([
        {
            "method": "POST",
            "path": "/api/v1/admin/queries",
            "body": { "name": name, "sql_query": sql, "entity_logical_name": entity_id },
        },
        {
            "action": crate::actions::record_write::RECORD_CREATE,
            "args": {
                "entity": "marketing_list",
                "values": {
                    "name": title,
                    "kind": "segment",
                    "target_entity": entity,
                    "query_id": format!("{entity}/{name}"),
                    "refresh_mode": "manual",
                }
            }
        }
    ])
}

const DRAFT_SYSTEM: &str = "You write one PostgreSQL SELECT for a marketing segment. Answer with \
    one JSON object and nothing else: {\"sql\": \"...\"}. The query reads only the table named \
    in the facts, with alias t, returns t.id, filters only on the fields given, leaves out \
    deleted records with t.is_active IS NOT FALSE, and has no joins, functions, comments or \
    semicolons.";

async fn draft(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
) -> Result<ActionResult, AppError> {
    if !ctx.security.is_admin {
        return Err(AppError::Forbidden);
    }
    let description = args
        .get("description")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| {
            AppError::Validation("description says who should be in the segment".into())
        })?;
    let entity = args
        .get("entity")
        .and_then(Value::as_str)
        .unwrap_or("contact");
    if !DRAFT_TARGETS.contains(&entity) {
        return Err(AppError::Validation(
            "entity is contact, lead or account".into(),
        ));
    }
    let (entity_id, fields) = {
        let registry = state.entities.load();
        let meta = registry.get(entity).ok_or(AppError::NotFound)?;
        let fields: Vec<Value> = meta
            .attrs
            .iter()
            .filter(|a| {
                !a.is_sensitive
                    && !a.is_read_gated()
                    && matches!(
                        a.data_classification,
                        attome_core::meta_registry::DataClassification::General
                    )
            })
            .take(DRAFT_FIELDS)
            .map(|a| json!({ "name": a.logicalname, "type": a.field_type().as_str() }))
            .collect();
        (meta.entity_id, fields)
    };
    let pool = state.base.readonly_query_pool(ctx.security.user_id).await;
    let mut problem: Option<String> = None;
    let mut provenance = None;
    for _ in 0..DRAFT_ATTEMPTS {
        let facts = json!({
            "description": description,
            "table": entity,
            "fields": fields,
            "previous_problem": problem,
        })
        .to_string();
        let (text, prov) = crate::actions::metric_draft::generate(
            state,
            ctx,
            DRAFT,
            DRAFT_PROMPT_VERSION,
            DRAFT_SYSTEM.to_owned(),
            facts,
        )
        .await?;
        provenance = prov;
        let sql = serde_json::from_str::<Value>(crate::actions::metric_draft::strip_fence(&text))
            .ok()
            .and_then(|v| v.get("sql").and_then(Value::as_str).map(str::to_owned));
        let Some(sql) = sql else {
            problem =
                Some("the answer held no query; answer with {\"sql\": \"SELECT ...\"}".into());
            continue;
        };
        let check = match attome_records::query_admin::check_draft_query(pool, &sql).await {
            Ok(check) => check,
            Err(AppError::Validation(p)) => {
                problem = Some(p);
                continue;
            }
            Err(e) => return Err(e),
        };
        if let Some(p) = draft_problem(entity, &check) {
            problem = Some(p);
            continue;
        }
        let name = format!("segment_{}", &Uuid::now_v7().simple().to_string()[20..]);
        let title: String = description.chars().take(200).collect();
        return Ok(ActionResult {
            value: json!({
                "entity": entity,
                "sql": sql,
                "estimated_rows": check.estimated_rows,
                "valid": true,
                "saved": false,
                "save": draft_save_calls(entity, entity_id, &name, &sql, &title),
            }),
            provenance,
        });
    }
    Ok(ActionResult {
        value: json!({ "entity": entity, "valid": false, "problem": problem, "saved": false }),
        provenance,
    })
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
            if self.0 == DRAFT {
                return draft(state, ctx, args).await;
            }
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
    fn draft_does_not_save() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.0 == DRAFT)
            .expect("registered");
        assert_eq!(d.effect, Effect::Read, "a draft writes nothing");
        assert_eq!(d.required_privileges, &["system.admin"]);
        let calls = draft_save_calls(
            "contact",
            Uuid::nil(),
            "segment_x",
            "SELECT t.id FROM contact t",
            "Engaged",
        );
        assert_eq!(calls[0]["path"], json!("/api/v1/admin/queries"));
        assert_eq!(calls[1]["action"], json!("record.create"));
        assert_eq!(
            calls[1]["args"]["values"]["query_id"],
            json!("contact/segment_x")
        );
        assert_eq!(calls[1]["args"]["values"]["kind"], json!("segment"));
    }

    #[test]
    fn a_draft_reads_its_one_table_and_returns_ids() {
        let check =
            |relations: &[&str], columns: &[&str]| attome_records::query_admin::DraftQueryCheck {
                relations: relations.iter().map(|r| (*r).to_owned()).collect(),
                columns: columns.iter().map(|c| (*c).to_owned()).collect(),
                estimated_rows: 10,
            };
        assert_eq!(
            draft_problem("contact", &check(&["contact"], &["id"])),
            None
        );
        assert!(draft_problem("contact", &check(&["contact", "account"], &["id"])).is_some());
        assert!(draft_problem("contact", &check(&["lead"], &["id"])).is_some());
        assert!(draft_problem("contact", &check(&["contact"], &["email"])).is_some());
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

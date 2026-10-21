//! Bulk actions (roadmap N6-T3): change or delete many records in one step,
//! with a preview first and per-record results after.
//!
//! - `record.bulk.preview` (read): how many records, a sample of what each
//!   change does (current value, new value), and every problem the values
//!   have, before anything runs.
//! - `record.bulk.update` / `record.bulk.delete` (consequential): submit the
//!   change to the bulk engine (`attome_records::bulk::submit_bulk`), the
//!   same durable path as `POST /api/v1/{entity}/bulk`: per-record access
//!   checks, row versions, the item ledger, one audit event per record. For
//!   an agent each is confirmed by a person and approved by a second one.
//! - `record.bulk.status` (read): the operation's progress and each record's
//!   result.
//!
//! **Large changes preview first** (roadmap N1-T2). A change to more than
//! [`PREVIEW_REQUIRED_OVER`] records runs only with the `preview_token` the
//! preview of exactly that change returned, so the agent (and the person who
//! confirms it) has seen the sample diff before anything is written. The
//! change itself runs in the background; `record.bulk.status` reports its
//! progress.
//!
//! **Never applied twice.** An agent's call carries its tool-call id, and
//! the action ledger claims it before the executor runs (`execute::claim_write`):
//! a retried or replayed call returns the first call's result instead of
//! submitting a second operation. Inside one operation the item ledger makes
//! every record apply at most once.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::{EngineState, EntityMeta};
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const BULK_PREVIEW: &str = "record.bulk.preview";
pub const BULK_UPDATE: &str = "record.bulk.update";
pub const BULK_DELETE: &str = "record.bulk.delete";
pub const BULK_STATUS: &str = "record.bulk.status";
/// The most records one bulk action takes (the bulk engine's own cap).
pub const MAX_RECORDS: usize = 500;
/// Records a preview reads to show what the change does.
pub const SAMPLE_SIZE: usize = 5;
/// A change to more records than this needs its preview's token.
pub const PREVIEW_REQUIRED_OVER: usize = 20;

const BULK_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 500, "description": "The records to change, e.g. from query.execute." },
    "values": { "type": "object", "description": "For an update: the fields to set on every record." },
    "preview_token": { "type": "string", "description": "The preview_token record.bulk.preview returned for this exact change; required above 20 records." }
  },
  "required": ["entity", "record_ids"],
  "additionalProperties": false
}"#;

const PREVIEW_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "operation": { "type": "string", "enum": ["update", "delete"] },
    "record_ids": { "type": "array", "items": { "type": "string", "format": "uuid" }, "minItems": 1, "maxItems": 500 },
    "values": { "type": "object", "description": "For an update: the fields to set on every record." }
  },
  "required": ["entity", "operation", "record_ids"],
  "additionalProperties": false
}"#;

const STATUS_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "operation_id": { "type": "string", "format": "uuid", "description": "The id record.bulk.update or record.bulk.delete returned." }
  },
  "required": ["entity", "operation_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            BULK_PREVIEW,
            "Before changing or deleting many records: how many, what the change \
             does to a sample of them, and any problem with the values. Changes \
             nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(PREVIEW_INPUT),
        ActionDescriptor::new(
            BULK_UPDATE,
            "Set the same values on many records (up to 500), after record.bulk.preview. \
             Runs in the background; follow it with record.bulk.status.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(BULK_INPUT)
        .agent_must_confirm(),
        ActionDescriptor::new(
            BULK_DELETE,
            "Delete many records (up to 500), after record.bulk.preview. Runs in the \
             background; follow it with record.bulk.status.",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(BULK_INPUT)
        .agent_must_confirm(),
        ActionDescriptor::new(
            BULK_STATUS,
            "Progress of a bulk change and each record's result.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(STATUS_INPUT),
    ]
}

/// A bulk request as the actions take it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkArgs {
    pub entity: String,
    #[serde(default)]
    pub operation: Option<String>,
    pub record_ids: Vec<Uuid>,
    #[serde(default)]
    pub values: Option<Map<String, Value>>,
    #[serde(default)]
    pub preview_token: Option<String>,
}

/// A checked bulk request.
#[derive(Debug, Clone, PartialEq)]
pub struct BulkPlan {
    pub entity: String,
    pub operation: &'static str,
    /// Distinct ids, in the order given.
    pub record_ids: Vec<Uuid>,
    /// For an update: the values; empty for a delete.
    pub values: Map<String, Value>,
}

/// Checks a bulk request against the entity's fields: ids present, at most
/// [`MAX_RECORDS`] after duplicates are dropped, an update has values and
/// every value names a field the caller may write (system columns and
/// computed fields are not), a delete has none. Every problem is returned.
pub fn check(
    args: &BulkArgs,
    operation: &str,
    meta: &EntityMeta,
    writable: impl Fn(&str) -> bool,
) -> Result<BulkPlan, Vec<String>> {
    let mut issues = Vec::new();
    let operation = match operation {
        "update" => "update",
        "delete" => "delete",
        other => {
            issues.push(format!("operation must be update or delete, not {other}"));
            "update"
        }
    };
    let mut seen = HashSet::new();
    let record_ids: Vec<Uuid> = args
        .record_ids
        .iter()
        .copied()
        .filter(|id| seen.insert(*id))
        .collect();
    if record_ids.is_empty() {
        issues.push("record_ids must not be empty".to_owned());
    }
    if record_ids.len() > MAX_RECORDS {
        issues.push(format!(
            "at most {MAX_RECORDS} records at once, got {}",
            record_ids.len()
        ));
    }
    let values = args.values.clone().unwrap_or_default();
    match operation {
        "update" if values.is_empty() => {
            issues.push("an update needs values".to_owned());
        }
        "delete" if !values.is_empty() => {
            issues.push("a delete takes no values".to_owned());
        }
        _ => {}
    }
    for field in values.keys() {
        let known = meta.attrs.iter().find(|a| &a.logicalname == field);
        let computed = known.is_some_and(|a| a.field_type() == attome_core::FieldType::Formula);
        if attome_core::ALL_SYSTEM_COLS.contains(&field.as_str())
            || known.is_none()
            || computed
            || !writable(field)
        {
            issues.push(format!(
                "{} has no field {field} you can set",
                meta.logicalname
            ));
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(BulkPlan {
        entity: meta.logicalname.clone(),
        operation,
        record_ids,
        values,
    })
}

/// The token naming one exact change: entity, operation, the set of records
/// and the values. Order and duplicates do not change it.
pub fn preview_token(plan: &BulkPlan) -> String {
    use sha2::{Digest, Sha256};
    let mut ids: Vec<String> = plan.record_ids.iter().map(Uuid::to_string).collect();
    ids.sort();
    let values: std::collections::BTreeMap<&String, &Value> = plan.values.iter().collect();
    let text = json!({
        "entity": plan.entity,
        "operation": plan.operation,
        "ids": ids,
        "values": values,
    })
    .to_string();
    format!("{:x}", Sha256::digest(text.as_bytes()))[..32].to_owned()
}

/// Whether `plan` may run with `token`: small changes always, large ones only
/// with the token of their own preview.
pub fn preview_satisfied(plan: &BulkPlan, token: Option<&str>) -> bool {
    plan.record_ids.len() <= PREVIEW_REQUIRED_OVER || token == Some(preview_token(plan).as_str())
}

/// Parses and checks a request in `ctx`'s name: the entity's `bulk` and
/// operation privileges, then [`check`].
fn plan_for(
    state: &EngineState,
    ctx: &ActionContext,
    args: &Value,
    operation: Option<&str>,
) -> Result<Result<BulkPlan, Vec<String>>, AppError> {
    let parsed: BulkArgs = serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid bulk arguments: {e}")))?;
    let entity = parsed.entity.trim().to_owned();
    let operation = operation
        .map(str::to_owned)
        .or_else(|| parsed.operation.clone())
        .ok_or_else(|| AppError::Validation("operation is required".into()))?;
    ctx.security.require(&entity, "bulk")?;
    ctx.security.require(&entity, &operation)?;
    let registry = state.entities.load();
    let meta = registry.get(&entity).ok_or(AppError::NotFound)?;
    let writable = |field: &str| {
        meta.attrs
            .iter()
            .find(|a| a.logicalname == field)
            .is_none_or(|a| {
                !a.requires_field_write_grant()
                    || ctx.security.has_field_write_grant(&entity, field)
            })
    };
    Ok(check(&parsed, &operation, meta, writable))
}

fn issues_result(issues: Vec<String>) -> ActionResult {
    ActionResult::plain(json!({ "valid": false, "issues": issues }))
}

pub(crate) struct BulkPreview;

impl Action for BulkPreview {
    fn id(&self) -> ActionId {
        ActionId(BULK_PREVIEW)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let plan = match plan_for(state, ctx, args, None)? {
                Ok(plan) => plan,
                Err(issues) => return Ok(issues_result(issues)),
            };
            // A sample, read the way the caller reads a record: a record the
            // caller cannot see is reported as not found, like a missing one.
            let mut sample = Vec::new();
            let mut not_found = 0usize;
            for id in plan.record_ids.iter().take(SAMPLE_SIZE) {
                match attome_records::entity_crud::read_record_bulk(
                    state,
                    &ctx.security,
                    &plan.entity,
                    *id,
                )
                .await
                {
                    Ok(record) => {
                        let data = record.data();
                        let current: Map<String, Value> = if plan.operation == "update" {
                            plan.values
                                .keys()
                                .map(|k| (k.clone(), data.get(k).cloned().unwrap_or(Value::Null)))
                                .collect()
                        } else {
                            data.as_object().cloned().unwrap_or_default()
                        };
                        sample.push(json!({
                            "id": id,
                            "current": current,
                            "after": if plan.operation == "update" { json!(plan.values) } else { json!("deleted") },
                        }));
                    }
                    Err(AppError::NotFound | AppError::Forbidden) => {
                        not_found += 1;
                        sample.push(json!({ "id": id, "not_found": true }));
                    }
                    Err(other) => return Err(other),
                }
            }
            let token = preview_token(&plan);
            Ok(ActionResult::plain(json!({
                "valid": true,
                "preview_token": token,
                "entity": plan.entity,
                "operation": plan.operation,
                "count": plan.record_ids.len(),
                "sample": sample,
                "sample_not_found": not_found,
                "detail": "Nothing was changed. Each record's own access and row version are checked again when the change runs.",
            })))
        })
    }
}

/// `record.bulk.update` and `record.bulk.delete`.
pub(crate) struct BulkApply {
    id: &'static str,
    operation: &'static str,
}

impl Action for BulkApply {
    fn id(&self) -> ActionId {
        ActionId(self.id)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let plan = match plan_for(state, ctx, args, Some(self.operation))? {
                Ok(plan) => plan,
                Err(issues) => return Ok(issues_result(issues)),
            };
            if !preview_satisfied(&plan, args["preview_token"].as_str()) {
                return Ok(issues_result(vec![format!(
                    "a change to more than {PREVIEW_REQUIRED_OVER} records needs a preview first: \
                     call {BULK_PREVIEW} with the same records and values and pass its preview_token"
                )]));
            }
            let items = plan
                .record_ids
                .iter()
                .map(|id| attome_records::bulk::BulkItem {
                    id: Some(*id),
                    expected_row_version: None,
                    data: if plan.operation == "update" {
                        Value::Object(plan.values.clone())
                    } else {
                        json!({})
                    },
                })
                .collect();
            let submitted = attome_records::bulk::submit_bulk(
                state,
                &ctx.security,
                &plan.entity,
                plan.operation,
                items,
                false,
                false,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "operation_id": submitted.id,
                "total": submitted.total,
                "status": "pending",
                "detail": "Running in the background; record.bulk.status shows each record's result.",
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let parsed: BulkArgs = serde_json::from_value(args.clone()).ok()?;
        Some(json!({
            "action": self.id,
            "entity": parsed.entity,
            "records": parsed.record_ids.len(),
            "values": parsed.values,
            "previewed": parsed.preview_token.is_some(),
        }))
    }
}

pub(crate) struct BulkStatus;

impl Action for BulkStatus {
    fn id(&self) -> ActionId {
        ActionId(BULK_STATUS)
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
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            let id = args["operation_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("operation_id must be a UUID".into()))?;
            let status =
                attome_records::bulk::bulk_status(state, &ctx.security, entity, id, true).await?;
            Ok(ActionResult::plain(status))
        })
    }
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(BulkPreview),
        Box::new(BulkApply {
            id: BULK_UPDATE,
            operation: "update",
        }),
        Box::new(BulkApply {
            id: BULK_DELETE,
            operation: "delete",
        }),
        Box::new(BulkStatus),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::LimitClass;

    fn meta() -> EntityMeta {
        serde_json::from_value(json!({
            "entity_id": Uuid::now_v7(),
            "logicalname": "lead",
            "is_append_only": false,
            "attrs": [
                { "logicalname": "status", "field_type_int": 7, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false },
                { "logicalname": "score", "field_type_int": 16, "is_sensitive": false,
                  "is_sortable": false, "is_filterable": false },
            ],
        }))
        .unwrap()
    }

    fn args(value: Value) -> BulkArgs {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn large_change_preview_is_required_above_the_threshold() {
        let meta = meta();
        let many: Vec<Uuid> = (0..=PREVIEW_REQUIRED_OVER)
            .map(|_| Uuid::now_v7())
            .collect();
        let request =
            args(json!({ "entity": "lead", "record_ids": many, "values": { "status": "x" } }));
        let plan = check(&request, "update", &meta, |_| true).unwrap();
        assert!(!preview_satisfied(&plan, None), "no preview");
        assert!(!preview_satisfied(&plan, Some("guess")), "a wrong token");
        let token = preview_token(&plan);
        assert!(preview_satisfied(&plan, Some(&token)));
        // The token names the change: other values need their own preview.
        let other = args(
            json!({ "entity": "lead", "record_ids": plan.record_ids, "values": { "status": "y" } }),
        );
        let other = check(&other, "update", &meta, |_| true).unwrap();
        assert!(!preview_satisfied(&other, Some(&token)));
        // Order does not change it.
        let mut reversed = plan.clone();
        reversed.record_ids.reverse();
        assert_eq!(preview_token(&reversed), token);
        // A small change needs no preview.
        let small = args(
            json!({ "entity": "lead", "record_ids": [Uuid::now_v7()], "values": { "status": "x" } }),
        );
        let small = check(&small, "update", &meta, |_| true).unwrap();
        assert!(preview_satisfied(&small, None));
    }

    #[test]
    fn a_bulk_update_is_checked_and_deduplicated() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let plan = check(
            &args(
                json!({ "entity": "lead", "record_ids": [a, b, a], "values": { "status": "won" } }),
            ),
            "update",
            &meta(),
            |_| true,
        )
        .unwrap();
        assert_eq!(plan.record_ids, [a, b]);
        assert_eq!(plan.operation, "update");
    }

    #[test]
    fn every_problem_with_a_bulk_request_is_reported() {
        let issues = check(
            &args(json!({ "entity": "lead", "record_ids": [], "values": { "score": 1, "nope": 2, "id": 3 } })),
            "update",
            &meta(),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(issues.len(), 4, "{issues:?}");
        let delete = check(
            &args(json!({ "entity": "lead", "record_ids": [Uuid::now_v7()], "values": { "status": "x" } })),
            "delete",
            &meta(),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(delete, ["a delete takes no values"]);
        let ungranted = check(
            &args(json!({ "entity": "lead", "record_ids": [Uuid::now_v7()], "values": { "status": "x" } })),
            "update",
            &meta(),
            |_| false,
        )
        .unwrap_err();
        assert_eq!(ungranted, ["lead has no field status you can set"]);
        let many: Vec<Uuid> = (0..=MAX_RECORDS).map(|_| Uuid::now_v7()).collect();
        let too_many = check(
            &args(json!({ "entity": "lead", "record_ids": many })),
            "delete",
            &meta(),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(too_many.len(), 1);
    }

    #[test]
    fn bulk_writes_are_consequential_and_count_in_their_limit_class() {
        let all = descriptors();
        let find = |id: &str| all.iter().find(|d| d.id.as_str() == id).unwrap();
        assert_eq!(find(BULK_UPDATE).risk, RiskTier::Consequential);
        assert_eq!(find(BULK_DELETE).risk, RiskTier::Consequential);
        assert_eq!(find(BULK_UPDATE).limit_class(), LimitClass::RecordChange);
        assert_eq!(find(BULK_DELETE).limit_class(), LimitClass::Delete);
        assert_eq!(find(BULK_PREVIEW).limit_class(), LimitClass::None);
        assert_eq!(find(BULK_UPDATE).retry, RetryClass::RequiresKey);
    }
}

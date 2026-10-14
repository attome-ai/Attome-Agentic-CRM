//! `record.deleted` (roadmap A18-T8): an entity's deleted records the caller
//! may see, newest deletion first, so an agent can find what was removed and
//! offer to bring it back with `record.restore`. Reads only.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::{AppError, OnePageQuery};
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RECORD_DELETED: &str = "record.deleted";

/// Deleted records one call returns.
const PAGE_SIZE: i64 = 20;

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "page": { "type": "integer", "minimum": 1, "description": "1 for the newest 20 deletions, 2 for the next 20." }
  },
  "required": ["entity"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        RECORD_DELETED,
        "List an entity's deleted records you may see, newest deletion first, 20 at a \
         time: id, name, when and by whom. Use record.restore to bring one back. Does \
         NOT list live records; use search.records or query.execute for those.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(INPUT)
}

pub(crate) struct RecordDeleted;

impl Action for RecordDeleted {
    fn id(&self) -> ActionId {
        ActionId(RECORD_DELETED)
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
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            let page = args["page"].as_i64().unwrap_or(1);
            let found = attome_records::entity_crud::recycle_bin::deleted_records(
                state,
                &ctx.security,
                entity,
                &OnePageQuery {
                    page: Some(page),
                    page_size: Some(PAGE_SIZE),
                },
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": entity,
                "total": found.total,
                "page": found.page,
                "records": found.items.iter().map(|r| json!({
                    "id": r.id,
                    "name": r.label,
                    "deleted_at": r.deleted_at,
                    "deleted_by": r.deleted_by,
                })).collect::<Vec<_>>(),
            })))
        })
    }
}

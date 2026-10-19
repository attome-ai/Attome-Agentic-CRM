//! `scan.lookup` and `code.generate` (roadmap B16-T13): an agent's side of
//! scanning.
//!
//! - `scan.lookup` resolves a scanned value to the records holding it in a
//!   scan-enabled field, through the very function `GET /api/v1/scan/find`
//!   uses (B16-T5), as the agent's acting user: a record that user may not
//!   read never appears. Hidden while the `scan.enabled` flag is off.
//! - `code.generate` gives the deep link a code for a record should carry,
//!   for the client to render as a QR or barcode; only for a record the
//!   acting user may read, so it never confirms one they may not see.
//!
//! Both read and change nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_security::RecordAction;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SCAN_LOOKUP: &str = "scan.lookup";
pub const CODE_GENERATE: &str = "code.generate";

const SCAN_FLAG: &str = "scan.enabled";

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            SCAN_LOOKUP,
            "Find the records a scanned barcode or QR value belongs to, in the \
             fields set up for scanning. Pass the value exactly as read; name an \
             entity to search only its fields. Returns only records you may read.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "properties": {
                "value": {"type": "string", "minLength": 1, "maxLength": 512},
                "entity": {"type": "string"}
            }, "required": ["value"], "additionalProperties": false}"#,
        ),
        ActionDescriptor::new(
            CODE_GENERATE,
            "Give the link a printed code for a record should carry, so a scan \
             opens that record. Render it as a QR code or barcode yourself.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "properties": {
                "entity": {"type": "string", "minLength": 1},
                "record_id": {"type": "string", "format": "uuid"}
            }, "required": ["entity", "record_id"], "additionalProperties": false}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ScanLookup), Box::new(CodeGenerate)]
}

/// The deep link a code for `entity`/`id` carries. Pure.
pub fn record_link(entity: &str, id: Uuid) -> String {
    format!("/xrm/entity/{entity}/form?id={id}")
}

fn text_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

pub(crate) struct ScanLookup;

impl Action for ScanLookup {
    fn id(&self) -> ActionId {
        ActionId(SCAN_LOOKUP)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !state.feature_flags().is_on(SCAN_FLAG, &ctx.security).await {
                return Err(AppError::NotFound);
            }
            // Read raw: the scanned value is matched exactly as read.
            let value = args
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("value: required".into()))?;
            let hits = attome_records::entity_crud::scan::find_scanned(
                state,
                &ctx.security,
                value,
                text_arg(args, "entity"),
            )
            .await?;
            Ok(ActionResult::plain(json!({ "items": hits })))
        })
    }
}

pub(crate) struct CodeGenerate;

impl Action for CodeGenerate {
    fn id(&self) -> ActionId {
        ActionId(CODE_GENERATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let entity = text_arg(args, "entity")
                .ok_or_else(|| AppError::Validation("entity: required".into()))?;
            let id = text_arg(args, "record_id")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("record_id: a UUID is required".into()))?;
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
                id,
                RecordAction::Read,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "entity": entity,
                "record_id": id,
                "link": record_link(entity, id),
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_lookup_descriptor_is_read_only() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
        let ids: Vec<&str> = descriptors().iter().map(|d| d.id.0).collect();
        assert_eq!(ids, vec![SCAN_LOOKUP, CODE_GENERATE]);
        assert_eq!(executors().len(), 2);
    }

    #[test]
    fn scan_lookup_respects_acting_user() {
        // The lookup is `find_scanned` under `ctx.security` (the acting
        // user), the same function `scan/find` gates per record; this pins
        // that the action passes the caller's context, not a system one.
        let source = include_str!("scan.rs");
        let body = &source[source.find("impl Action for ScanLookup").unwrap()..];
        let body = &body[..body.find("pub(crate) struct CodeGenerate").unwrap()];
        assert!(body.contains("find_scanned("));
        assert!(body.contains("&ctx.security"));
        assert_eq!(
            record_link("asset", Uuid::nil()),
            "/xrm/entity/asset/form?id=00000000-0000-0000-0000-000000000000"
        );
    }
}

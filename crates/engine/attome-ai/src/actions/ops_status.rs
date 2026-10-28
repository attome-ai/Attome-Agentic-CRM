//! AB11-T10: an agent reads the status page and drafts incident text; it
//! never publishes.
//!
//! - `ops.status` (Read) — each component's state, open incidents and
//!   maintenance, as `GET /api/v1/ops/status` answers the caller (internal
//!   items only with `ops.read`).
//! - `ops.draft_incident_update` (Read, `ops.read`) — suggested English and
//!   Arabic text for the next update of an open incident, from the
//!   components that are down now. It writes nothing: a person with
//!   `ops.incident.publish` publishes it through the incidents route, which
//!   no action reaches.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_OPS;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const OPS_STATUS: &str = "ops.status";
pub const OPS_DRAFT_INCIDENT_UPDATE: &str = "ops.draft_incident_update";

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            OPS_STATUS,
            "Read the platform's status page: each component (sign-in, records, search, email, \
             AI, portal, integrations) with its state, the open incidents and the planned \
             maintenance not yet over.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &[],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
        ActionDescriptor::new(
            OPS_DRAFT_INCIDENT_UPDATE,
            "Draft the next update of an open incident in English and Arabic from the components \
             that are down now. Returns suggested text only; a person publishes it.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_OPS,
            &["ops.read"],
        )
        .input_schema(
            r#"{"type": "object", "required": ["incident_id"], "properties": {"incident_id": {"type": "string", "format": "uuid"}, "stage": {"enum": ["investigating", "identified", "monitoring", "resolved", "note"]}}, "additionalProperties": false}"#,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(OpsStatus), Box::new(OpsDraftIncidentUpdate)]
}

/// One component as a draft names it: key, English name, Arabic name, state.
pub type Named<'a> = (&'a str, &'a str, &'a str, &'a str);

/// Suggested update text for an incident's `components` at `stage`, from
/// the current component states: names the affected components still down,
/// or says they are back. Pure.
pub fn draft_text(current: &[Named<'_>], components: &[String], stage: &str) -> (String, String) {
    let affected: Vec<&Named<'_>> = current
        .iter()
        .filter(|(key, ..)| components.is_empty() || components.iter().any(|c| c == key))
        .collect();
    let down: Vec<&Named<'_>> = affected
        .iter()
        .copied()
        .filter(|(.., state)| *state == "down" || *state == "degraded")
        .collect();
    let list_en = |items: &[&Named<'_>]| items.iter().map(|c| c.1).collect::<Vec<_>>().join(", ");
    let list_ar = |items: &[&Named<'_>]| items.iter().map(|c| c.2).collect::<Vec<_>>().join("، ");
    if stage == "resolved" || down.is_empty() {
        let (en, ar) = if affected.is_empty() {
            ("Every component".to_owned(), "جميع المكونات".to_owned())
        } else {
            (list_en(&affected), list_ar(&affected))
        };
        return (
            format!(
                "{en} is working normally again. We are monitoring to make sure it stays that way."
            ),
            format!("عاد {ar} إلى العمل بشكل طبيعي. نواصل المراقبة للتأكد من استقراره."),
        );
    }
    let (en, ar) = (list_en(&down), list_ar(&down));
    match stage {
        "identified" => (
            format!("We have found the cause of the problem with {en} and are working on a fix."),
            format!("حددنا سبب المشكلة في {ar} ونعمل على إصلاحها."),
        ),
        "monitoring" => (
            format!("A fix for {en} is in place. We are monitoring the results."),
            format!("طُبّق إصلاح لـ {ar}، ونراقب النتائج."),
        ),
        _ => (
            format!(
                "{en} is not working normally. We are investigating and will post updates here."
            ),
            format!("لا يعمل {ar} بشكل طبيعي. نعمل على التحقق وسننشر التحديثات هنا."),
        ),
    }
}

pub(crate) struct OpsStatus;

impl Action for OpsStatus {
    fn id(&self) -> ActionId {
        ActionId(OPS_STATUS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let status = attome_ops::public_status::status_for(state, &ctx.security).await?;
            Ok(ActionResult::plain(
                serde_json::to_value(status).map_err(AppError::internal)?,
            ))
        })
    }
}

pub(crate) struct OpsDraftIncidentUpdate;

impl Action for OpsDraftIncidentUpdate {
    fn id(&self) -> ActionId {
        ActionId(OPS_DRAFT_INCIDENT_UPDATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = args["incident_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("incident_id must be a uuid".into()))?;
            let stage = args["stage"].as_str().unwrap_or("investigating");
            let incident: Option<(Vec<String>, String, Option<chrono::DateTime<chrono::Utc>>)> =
                sqlx::query_as(
                    "SELECT components, state, resolved_at FROM ops_incident WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            let (components, incident_state, resolved_at) = incident.ok_or(AppError::NotFound)?;
            if resolved_at.is_some() {
                return Err(AppError::Conflict("this incident is resolved"));
            }
            let snapshot = attome_ops::public_status::status_for(state, &ctx.security).await?;
            let current: Vec<Named<'_>> = snapshot
                .components
                .iter()
                .map(|c| {
                    (
                        c.key.as_str(),
                        c.name_en.as_str(),
                        c.name_ar.as_str(),
                        c.state.as_str(),
                    )
                })
                .collect();
            let (body_en, body_ar) = draft_text(&current, &components, stage);
            Ok(ActionResult::plain(json!({
                "incident_id": id,
                "incident_state": incident_state,
                "stage": stage,
                "body_en": body_en,
                "body_ar": body_ar,
                "note": "Suggested text only. A person with ops.incident.publish publishes it.",
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> ActionDescriptor {
        descriptors().into_iter().find(|d| d.id.0 == id).unwrap()
    }

    #[test]
    fn both_actions_only_read() {
        for id in [OPS_STATUS, OPS_DRAFT_INCIDENT_UPDATE] {
            let d = descriptor(id);
            assert_eq!(d.risk, RiskTier::Read);
            assert_eq!(d.module, MODULE_OPS);
        }
        assert_eq!(
            descriptor(OPS_DRAFT_INCIDENT_UPDATE).required_privileges,
            &["ops.read"]
        );
    }

    #[test]
    fn draft_names_the_components_still_down() {
        let current = [
            ("search", "Search", "البحث", "down"),
            ("email", "Email", "البريد", "operational"),
        ];
        let (en, ar) = draft_text(
            &current,
            &["search".into(), "email".into()],
            "investigating",
        );
        assert!(
            en.starts_with("Search is not working") && !en.contains("Email"),
            "{en}"
        );
        assert!(ar.contains("البحث"), "{ar}");
        let (en, _) = draft_text(&current, &["email".into()], "investigating");
        assert!(en.contains("working normally again"), "{en}");
    }
}

//! Competitor actions (roadmap D25-T8), all read only.
//!
//! - `sales.competitors.on_deal` lists the competitors on a deal with their
//!   status, threat and battle card id (`attome_sales::competitor_routes::
//!   battlecards`, the battle card route's own function).
//! - `sales.battlecard.get` reads a competitor and, when it points at one, its
//!   knowledge article.
//! - `sales.winloss.draft_review` drafts a deal's win-loss review from the
//!   deal and the notes, emails and call findings about it. It never saves:
//!   the person creates the `win_loss_review` from the draft.
//! - `sales.battlecard.draft_update` drafts a battle card update from the
//!   last loss reviews against a competitor. It never publishes: the card's
//!   owner edits and publishes the article.
//!
//! Every read is the caller's own (`attome_sales::competitor_drafts`).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const ON_DEAL: &str = "sales.competitors.on_deal";
pub const BATTLECARD_GET: &str = "sales.battlecard.get";
pub const DRAFT_REVIEW: &str = "sales.winloss.draft_review";
pub const DRAFT_UPDATE: &str = "sales.battlecard.draft_update";

const DEAL_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "opportunity_id": { "type": "string", "format": "uuid" } },
  "required": ["opportunity_id"],
  "additionalProperties": false
}"#;

const COMPETITOR_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "competitor_id": { "type": "string", "format": "uuid" } },
  "required": ["competitor_id"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_SALES,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            ON_DEAL,
            "List the competitors on a deal: status (suspected, confirmed, primary), threat \
             and the battle card article id.",
            DEAL_SCHEMA,
        ),
        read(
            BATTLECARD_GET,
            "Read a competitor's battle card: strengths, weaknesses, price position and, when \
             set, the knowledge article holding the card.",
            COMPETITOR_SCHEMA,
        ),
        read(
            DRAFT_REVIEW,
            "Draft a deal's win-loss review: outcome, main reason, competitors and quotes from \
             the deal's notes, emails and call findings. Nothing is saved; write the review's \
             text from the quotes and show it to the person, who creates the review.",
            DEAL_SCHEMA,
        ),
        read(
            DRAFT_UPDATE,
            "Draft an update to a competitor's battle card from the last 20 loss reviews \
             against it. Nothing is published; the card's owner edits and publishes it.",
            COMPETITOR_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Read(ON_DEAL)),
        Box::new(Read(BATTLECARD_GET)),
        Box::new(Read(DRAFT_REVIEW)),
        Box::new(Read(DRAFT_UPDATE)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

fn plain(value: impl serde::Serialize) -> Result<ActionResult, AppError> {
    Ok(ActionResult::plain(
        serde_json::to_value(value).map_err(AppError::internal)?,
    ))
}

struct Read(&'static str);

impl Action for Read {
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
            use attome_sales::{competitor_drafts as drafts, competitor_routes as routes};
            let security = &ctx.security;
            match self.0 {
                ON_DEAL => plain(
                    routes::battlecards(state, security, uuid_arg(args, "opportunity_id")?).await?,
                ),
                BATTLECARD_GET => plain(
                    drafts::battlecard(state, security, uuid_arg(args, "competitor_id")?).await?,
                ),
                DRAFT_REVIEW => plain(
                    drafts::review_draft(state, security, uuid_arg(args, "opportunity_id")?)
                        .await?,
                ),
                DRAFT_UPDATE => plain(
                    drafts::battlecard_update_draft(
                        state,
                        security,
                        uuid_arg(args, "competitor_id")?,
                    )
                    .await?,
                ),
                other => Err(AppError::internal(format!("unknown action {other}"))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn competitor_actions_are_reads_with_an_executor_each() {
        let all = descriptors();
        let executors = executors();
        for id in [ON_DEAL, BATTLECARD_GET, DRAFT_REVIEW, DRAFT_UPDATE] {
            let d = all
                .iter()
                .find(|d| d.id.as_str() == id)
                .unwrap_or_else(|| panic!("{id} is described"));
            assert_eq!(d.effect, Effect::Read, "{id} only reads");
            assert!(executors.iter().any(|e| e.id().0 == id), "{id} executes");
        }
        for schema in [DEAL_SCHEMA, COMPETITOR_SCHEMA] {
            assert!(serde_json::from_str::<Value>(schema).is_ok());
        }
    }

    /// The draft-review action does not save: it is a read, and the function
    /// it calls never writes (`competitor_drafts::tests::drafts_never_write`).
    #[test]
    fn draft_review_does_not_save() {
        let d = descriptors()
            .into_iter()
            .find(|d| d.id.as_str() == DRAFT_REVIEW)
            .expect("described");
        assert!(matches!(d.risk, RiskTier::Read));
        assert!(!d.agent_must_confirm);
    }
}

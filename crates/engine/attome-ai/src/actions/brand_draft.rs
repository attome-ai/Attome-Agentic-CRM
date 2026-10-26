//! A theme drafted from a brand guidelines PDF (roadmap B13-T11).
//!
//! `brand.draft_from_document` reads a theme's `guidelines_pdf` brand asset
//! (B13-T4), takes its text with the document extractor
//! (`attome_document::text_extract`, PDF literal strings) capped at
//! [`MAX_TEXT_CHARS`], and asks the model for the theme tokens as JSON. The
//! reply is parsed into `ThemeTokens` (colours checked as `#RRGGBB`); a
//! reply that does not parse is the typed refusal [`BrandDraftError`], and
//! nothing is saved.
//!
//! **Draft only.** The tokens are saved as a new draft of the asset's theme
//! scope through `theme_store::save_draft`, never published: publishing
//! stays a person's step behind the contrast gate. Saving a theme is an
//! administrator's change, so the action needs an administrator and writes
//! the same Configuration audit event (`theme.draft_saved`) as the themes
//! route, in the draft's own transaction.

use std::future::Future;
use std::pin::Pin;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_core::theme_tokens::ThemeTokens;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const BRAND_DRAFT: &str = "brand.draft_from_document";
/// Bumped whenever the prompt changes in a way that could move output.
pub const BRAND_DRAFT_PROMPT_VERSION: &str = "brand.draft_from_document/v1";
/// The most guideline text the model reads.
pub const MAX_TEXT_CHARS: usize = 20_000;
/// The asset kind the action reads.
pub const GUIDELINES_KIND: &str = "guidelines_pdf";

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "asset_id": { "type": "string", "format": "uuid", "description": "A brand asset of kind guidelines_pdf." }
  },
  "required": ["asset_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            BRAND_DRAFT,
            "Draft a theme (colours, fonts, density) from a brand guidelines PDF and save it as a \
             new draft of that theme's scope. Never publishes. Administrators only.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(BrandDraft)]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    asset_id: Uuid,
}

/// Why a reply gave no theme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrandDraftError {
    /// The model's reply is not a theme.
    NotATheme(String),
    /// The guidelines hold no readable text.
    NoText,
}

impl std::fmt::Display for BrandDraftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATheme(why) => write!(f, "the model's reply is not a theme: {why}"),
            Self::NoText => f.write_str("the guidelines hold no readable text"),
        }
    }
}

impl From<BrandDraftError> for AppError {
    fn from(error: BrandDraftError) -> Self {
        AppError::Validation(error.to_string())
    }
}

/// The prompt.
pub fn system_prompt() -> String {
    "You read a company's brand guidelines and propose a theme for its business application. \
     Reply with exactly one JSON object and nothing else, using only these keys, each \
     optional: primary, accent, surface, surface_dark, text, text_dark, success, warning, \
     danger, info (colours as #RRGGBB), font_latin, font_arabic (font family names), \
     radius_px (0 to 24), density (\"comfortable\" or \"compact\"), app_name (at most 60 \
     characters). Take colours and fonts only from the guidelines; leave out a key the \
     guidelines do not settle. Text colours must read clearly on their surfaces."
        .to_owned()
}

/// The guidelines text the model reads: whitespace folded, capped. Pure.
pub fn prepared_text(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_TEXT_CHARS)
        .collect()
}

/// The model's reply as theme tokens: the first JSON object in it, parsed
/// strictly. Pure.
pub fn parse_tokens(reply: &str) -> Result<ThemeTokens, BrandDraftError> {
    let start = reply.find('{');
    let end = reply.rfind('}');
    let (Some(start), Some(end)) = (start, end) else {
        return Err(BrandDraftError::NotATheme("no JSON object".into()));
    };
    if end < start {
        return Err(BrandDraftError::NotATheme("no JSON object".into()));
    }
    serde_json::from_str::<ThemeTokens>(&reply[start..=end])
        .map_err(|e| BrandDraftError::NotATheme(e.to_string()))
}

pub(crate) struct BrandDraft;

impl Action for BrandDraft {
    fn id(&self) -> ActionId {
        ActionId(BRAND_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {BRAND_DRAFT} arguments: {e}"))
            })?;
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let asset: Option<(String, Uuid, String, String)> = sqlx::query_as(
                "SELECT a.storage_key, a.theme_id, t.scope_kind, t.scope_ref \
                   FROM brand_asset a JOIN theme t ON t.id = a.theme_id \
                  WHERE a.id = $1 AND a.kind = $2",
            )
            .bind(args.asset_id)
            .bind(GUIDELINES_KIND)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let (key, theme_id, scope_kind, scope_ref) = asset.ok_or(AppError::NotFound)?;
            let bytes = attome_storage::mirror::read_object(&state.base.storage, &key)
                .await
                .map_err(AppError::internal)?;
            let raw = tokio::task::spawn_blocking(move || {
                attome_document::text_extract::extract(
                    attome_document::text_extract::TextFormat::Pdf,
                    &bytes,
                )
            })
            .await
            .map_err(AppError::internal)?
            .unwrap_or_default();
            let text = prepared_text(&raw);
            if text.is_empty() {
                return Err(BrandDraftError::NoText.into());
            }

            let client = crate::inference_client::client_for(state, BRAND_DRAFT).await?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(system_prompt()),
                Segment::untrusted("guidelines", text),
            ]));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                BRAND_DRAFT,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                BRAND_DRAFT,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "brand draft generation failed");
                AppError::internal("brand draft generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let tokens = parse_tokens(&generated.text)?;

            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let row = attome_core::theme_store::save_draft(
                &mut tx,
                &scope_kind,
                &scope_ref,
                &tokens,
                ctx.security.user_id,
            )
            .await?;
            write_security_event(
                &mut tx,
                &audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Create,
                    ctx.security.user_id,
                    "theme",
                    Some(row.id),
                )
                .named("theme.draft_saved"),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(ActionResult {
                value: json!({
                    "theme_id": row.id,
                    "version": row.version,
                    "status": row.status,
                    "from_theme": theme_id,
                    "tokens": row.tokens.0,
                }),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: BRAND_DRAFT_PROMPT_VERSION.to_owned(),
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
    fn brand_draft_parses_tokens_only() {
        let reply = "Here you are: {\"primary\": \"#0A4D8C\", \"font_latin\": \"Inter\", \
                     \"density\": \"compact\"} done";
        let tokens = parse_tokens(reply).unwrap();
        assert_eq!(tokens.primary.as_ref().map(|c| c.as_str()), Some("#0a4d8c"));
        assert_eq!(tokens.font_latin.as_deref(), Some("Inter"));
        assert!(tokens.accent.is_none());
        // A bad colour or no object is a typed refusal; nothing to save.
        assert!(matches!(
            parse_tokens("{\"primary\": \"blue\"}"),
            Err(BrandDraftError::NotATheme(_))
        ));
        assert!(matches!(
            parse_tokens("no theme here"),
            Err(BrandDraftError::NotATheme(_))
        ));
    }

    #[test]
    fn brand_draft_text_is_capped() {
        let long = "word ".repeat(10_000);
        assert_eq!(prepared_text(&long).chars().count(), MAX_TEXT_CHARS);
        assert_eq!(prepared_text("  a \n\n b  "), "a b");
    }
}

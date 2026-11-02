//! Commerce actions (roadmap F8-T11, V2-D1595 (2)).
//!
//! - `commerce.product_answer(search)`: the orderable products whose name or
//!   SKU matches, each read through the record engine with the caller's own
//!   access (a product the caller cannot read is left out).
//! - `commerce.order_track(order_number, phone | email)`: an order's status,
//!   only when the phone or email given is the order's contact's. Shopper
//!   bots pass what the shopper told them; the caller also needs
//!   `order.read`. Anything that does not match answers as not found, the
//!   same as an unknown number, so the action cannot be used to probe.
//! - `commerce.draft_product_description(product_id, notes?)`: an Arabic and
//!   an English description drafted by the model for a person to review.
//!   Nothing is saved.
//!
//! There is deliberately no tool that changes a price, a promotion, a
//! refund, or releases or cancels an order.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_SALES;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const PRODUCT_ANSWER: &str = "commerce.product_answer";
pub const ORDER_TRACK: &str = "commerce.order_track";
pub const DRAFT_DESCRIPTION: &str = "commerce.draft_product_description";
/// Bumped whenever the prompt changes in a way that could move output.
pub const DRAFT_PROMPT_VERSION: &str = "commerce.draft_product_description/v1";
/// Products answered at most.
const MAX_PRODUCTS: i64 = 5;
/// Digits of a phone compared (the subscriber number, whatever the prefix).
const PHONE_DIGITS: usize = 9;

const ANSWER_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "search": { "type": "string", "minLength": 2, "maxLength": 100 } },
  "required": ["search"],
  "additionalProperties": false
}"#;

const TRACK_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "order_number": { "type": "string", "minLength": 1, "maxLength": 100 },
    "phone": { "type": "string", "maxLength": 40 },
    "email": { "type": "string", "maxLength": 200 }
  },
  "required": ["order_number"],
  "additionalProperties": false
}"#;

const DRAFT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "product_id": { "type": "string", "format": "uuid" },
    "notes": { "type": "string", "maxLength": 2000 }
  },
  "required": ["product_id"],
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
            PRODUCT_ANSWER,
            "Find orderable products by name or SKU and answer with their names (English and \
             Arabic), SKU and description, read with the caller's own access.",
            ANSWER_SCHEMA,
        ),
        read(
            ORDER_TRACK,
            "Tell a shopper where their order stands: give the order number and the phone or \
             email they ordered with; answers only when they match the order's contact.",
            TRACK_SCHEMA,
        ),
        read(
            DRAFT_DESCRIPTION,
            "Draft an Arabic and an English description of a product for a person to review. \
             Nothing is saved.",
            DRAFT_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ProductAnswer),
        Box::new(OrderTrack),
        Box::new(DraftDescription),
    ]
}

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>>;

/// The last [`PHONE_DIGITS`] digits of a phone; `None` with fewer. Pure.
pub fn phone_key(raw: &str) -> Option<String> {
    let digits: Vec<char> = raw.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= PHONE_DIGITS).then(|| digits[digits.len() - PHONE_DIGITS..].iter().collect())
}

/// Whether what the shopper gave matches the contact's phones or email.
/// Pure.
pub fn shopper_matches(
    phone: Option<&str>,
    email: Option<&str>,
    contact_phones: &[Option<String>],
    contact_email: Option<&str>,
) -> bool {
    let by_phone = phone.and_then(phone_key).is_some_and(|given| {
        contact_phones
            .iter()
            .flatten()
            .filter_map(|p| phone_key(p))
            .any(|known| known == given)
    });
    let by_email = email
        .map(|e| e.trim().to_lowercase())
        .filter(|e| e.contains('@'))
        .is_some_and(|given| {
            contact_email.is_some_and(|known| known.trim().to_lowercase() == given)
        });
    by_phone || by_email
}

fn text_arg<'v>(args: &'v Value, key: &str) -> Option<&'v str> {
    args[key].as_str().map(str::trim).filter(|s| !s.is_empty())
}

struct ProductAnswer;

impl Action for ProductAnswer {
    fn id(&self) -> ActionId {
        ActionId(PRODUCT_ANSWER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let search = text_arg(args, "search")
                .ok_or_else(|| AppError::Validation("search is required".into()))?;
            ctx.security.require("product", "read")?;
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM product \
                  WHERE COALESCE(is_orderable, false) \
                    AND (is_active IS NULL OR is_active = true) \
                    AND (name ILIKE '%' || $1 || '%' OR sku ILIKE '%' || $1 || '%') \
                  ORDER BY name, id LIMIT $2",
            )
            .bind(search)
            .bind(MAX_PRODUCTS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let mut products = Vec::with_capacity(ids.len());
            for id in ids {
                // The record engine applies record access and field grants.
                let record = match attome_records::entity_crud::read_record(
                    state,
                    &ctx.security,
                    "product",
                    id,
                )
                .await
                {
                    Ok(record) => record,
                    Err(AppError::Forbidden | AppError::NotFound) => continue,
                    Err(error) => return Err(error),
                };
                let data = record.data();
                products.push(json!({
                    "product_id": id,
                    "name": data.get("name"),
                    "name_ar": data.get("name_ar"),
                    "sku": data.get("sku"),
                    "description": data.get("description"),
                }));
            }
            Ok(ActionResult::plain(json!({ "products": products })))
        })
    }
}

struct OrderTrack;

type TrackRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl Action for OrderTrack {
    fn id(&self) -> ActionId {
        ActionId(ORDER_TRACK)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let number = text_arg(args, "order_number")
                .ok_or_else(|| AppError::Validation("order_number is required".into()))?;
            let (phone, email) = (text_arg(args, "phone"), text_arg(args, "email"));
            if phone.is_none() && email.is_none() {
                return Err(AppError::Validation(
                    "give the phone or email the order was placed with".into(),
                ));
            }
            ctx.security.require("order", "read")?;
            let row: Option<TrackRow> = sqlx::query_as(
                "SELECT o.status::text, to_jsonb(o) ->> 'payment_status', o.ordered_on::text, \
                        k.mobile_phone, k.phone, k.email \
                   FROM \"order\" o JOIN contact k ON k.id = o.updates_contact_ref \
                  WHERE (o.order_number = $1 OR to_jsonb(o) ->> 'source_order_number' = $1) \
                    AND (o.is_active IS NULL OR o.is_active = true) \
                  ORDER BY o.created_at DESC LIMIT 1",
            )
            .bind(number)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some((status, payment, ordered_on, mobile, landline, contact_email)) = row else {
                return Err(AppError::NotFound);
            };
            if !shopper_matches(phone, email, &[mobile, landline], contact_email.as_deref()) {
                // The same answer as an unknown number.
                return Err(AppError::NotFound);
            }
            Ok(ActionResult::plain(json!({
                "order_number": number,
                "status": status,
                "payment_status": payment,
                "ordered_on": ordered_on,
            })))
        })
    }
}

/// The drafting instructions.
pub fn draft_system_prompt() -> String {
    "You write product descriptions for an online shop. From the product facts and the \
     merchant's notes, write one short description in English and one in Modern Standard \
     Arabic (not a translation word for word; natural in each). State only what the facts \
     say: no prices, discounts, guarantees or claims they do not support. Answer with JSON \
     only: {\"en\": \"...\", \"ar\": \"...\"}."
        .to_owned()
}

/// The two descriptions from the model's reply. Pure.
pub fn parse_draft(reply: &str) -> Result<(String, String), AppError> {
    let start = reply.find('{');
    let end = reply.rfind('}');
    let value: Value = match (start, end) {
        (Some(s), Some(e)) if s < e => serde_json::from_str(&reply[s..=e])
            .map_err(|_| AppError::Validation("the draft could not be read".into()))?,
        _ => return Err(AppError::Validation("the draft could not be read".into())),
    };
    let text = |key: &str| {
        value[key]
            .as_str()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
    };
    match (text("en"), text("ar")) {
        (Some(en), Some(ar)) => Ok((en, ar)),
        _ => Err(AppError::Validation("the draft lacks a language".into())),
    }
}

struct DraftDescription;

impl Action for DraftDescription {
    fn id(&self) -> ActionId {
        ActionId(DRAFT_DESCRIPTION)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            let product = args["product_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("product_id must be a UUID".into()))?;
            let record =
                attome_records::entity_crud::read_record(state, &ctx.security, "product", product)
                    .await?;
            let data = record.data();
            let facts = json!({
                "name": data.get("name"),
                "name_ar": data.get("name_ar"),
                "sku": data.get("sku"),
                "description": data.get("description"),
            })
            .to_string();
            let notes = text_arg(args, "notes").unwrap_or("").to_owned();

            let client = crate::inference_client::client_for(state, DRAFT_DESCRIPTION).await?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(draft_system_prompt()),
                Segment::untrusted("product", facts),
                Segment::untrusted("notes", notes),
            ]));
            request.temperature = 0.3;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                DRAFT_DESCRIPTION,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                DRAFT_DESCRIPTION,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "product description draft failed");
                AppError::internal("product description draft failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let (en, ar) = parse_draft(&generated.text)?;
            Ok(ActionResult {
                value: json!({ "product_id": product, "en": en, "ar": ar, "saved": false }),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: DRAFT_PROMPT_VERSION.to_owned(),
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
    fn commerce_tools_are_read_only() {
        let all = descriptors();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|d| d.risk == RiskTier::Read));
    }

    #[test]
    fn order_track_refuses_other_shoppers_order() {
        let phones = [Some("+966501234567".to_owned()), None];
        assert!(shopper_matches(Some("0501234567"), None, &phones, None));
        assert!(!shopper_matches(Some("0509999999"), None, &phones, None));
        assert!(shopper_matches(
            None,
            Some(" Sara@Example.com"),
            &[],
            Some("sara@example.com")
        ));
        assert!(!shopper_matches(
            None,
            Some("other@example.com"),
            &[],
            Some("sara@example.com")
        ));
        assert!(
            !shopper_matches(Some("123"), None, &phones, None),
            "too short to compare"
        );
    }

    #[test]
    fn product_draft_needs_both_languages() {
        let (en, ar) = parse_draft("Sure: {\"en\": \"A lamp.\", \"ar\": \"مصباح.\"}").unwrap();
        assert_eq!((en.as_str(), ar.as_str()), ("A lamp.", "مصباح."));
        assert!(parse_draft("{\"en\": \"A lamp.\"}").is_err());
        assert!(parse_draft("no json").is_err());
    }
}

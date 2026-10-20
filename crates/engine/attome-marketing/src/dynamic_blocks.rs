//! Dynamic blocks (roadmap E25-T1): a `dynamic` block in an email design
//! holds variants, each with a rule-language (Z11) condition over the
//! recipient's record or a marketing list the recipient must be in, and a
//! default. [`resolve`] picks, per recipient, the first variant that
//! matches (in order), replaces the block with its content and reports
//! which variant each block chose, so the send can record it. The renderer
//! (E2-T2) refuses a design that still holds a dynamic block, so nothing
//! is ever sent unresolved.
//!
//! A condition that does not compile against the recipient's entity, or
//! that does not evaluate to true, does not match: the default wins. List
//! membership is read from `marketing_list_member` (the stored membership),
//! not by re-running a segment. [`preview`] resolves and renders a design
//! for one contact or lead, for the designer's "preview as" panel.

use std::collections::{BTreeMap, HashSet};

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::email_render::{DynamicVariant, EmailBlock, EmailDesign};

/// What one recipient matches against.
#[derive(Debug, Clone, Default)]
pub struct Recipient {
    /// The recipient's record, as attribute values.
    pub record: Map<String, Value>,
    /// The lists the recipient is in.
    pub lists: HashSet<Uuid>,
}

/// Which variant a dynamic block chose for a recipient (`None`: the
/// default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    pub block_id: String,
    pub variant_id: Option<String>,
}

fn matches(
    variant: &DynamicVariant,
    recipient: &Recipient,
    schema: &attome_rules::Schema,
    ctx: &attome_rules::Context,
) -> bool {
    if let Some(list) = variant.in_list
        && !recipient.lists.contains(&list)
    {
        return false;
    }
    match variant
        .condition
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        None => variant.in_list.is_some(),
        Some(source) => attome_rules::compile(source, schema)
            .ok()
            .and_then(|c| c.eval(ctx).ok())
            .is_some_and(|v| matches!(v, attome_rules::Value::Bool(true))),
    }
}

fn resolve_blocks(
    blocks: &[EmailBlock],
    recipient: &Recipient,
    schema: &attome_rules::Schema,
    ctx: &attome_rules::Context,
    choices: &mut Vec<Choice>,
) -> Vec<EmailBlock> {
    let mut out = Vec::new();
    for block in blocks {
        match block {
            EmailBlock::Dynamic {
                id,
                variants,
                default,
            } => {
                let chosen = variants.iter().find(|v| matches(v, recipient, schema, ctx));
                choices.push(Choice {
                    block_id: id.clone(),
                    variant_id: chosen.map(|v| v.id.clone()),
                });
                let content = chosen.map_or(default, |v| &v.blocks);
                out.extend(resolve_blocks(content, recipient, schema, ctx, choices));
            }
            EmailBlock::Columns { columns } => out.push(EmailBlock::Columns {
                columns: columns
                    .iter()
                    .map(|c| resolve_blocks(c, recipient, schema, ctx, choices))
                    .collect(),
            }),
            other => out.push(other.clone()),
        }
    }
    out
}

/// The design for one recipient, with every dynamic block replaced by its
/// chosen content, and the choices made. Pure given the schema.
pub fn resolve(
    design: &EmailDesign,
    attrs: &[attome_core::AttrInfo],
    recipient: &Recipient,
    now: DateTime<Utc>,
) -> (EmailDesign, Vec<Choice>) {
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    let ctx = attome_records::rule_engine::context_for_record(now, attrs, &recipient.record);
    let mut choices = Vec::new();
    let blocks = resolve_blocks(&design.blocks, recipient, &schema, &ctx, &mut choices);
    (
        EmailDesign {
            blocks,
            ..design.clone()
        },
        choices,
    )
}

/// Every list a dynamic block of `design` names. Pure.
pub fn named_lists(blocks: &[EmailBlock]) -> HashSet<Uuid> {
    let mut out = HashSet::new();
    for block in blocks {
        match block {
            EmailBlock::Dynamic {
                variants, default, ..
            } => {
                for v in variants {
                    out.extend(v.in_list);
                    out.extend(named_lists(&v.blocks));
                }
                out.extend(named_lists(default));
            }
            EmailBlock::Columns { columns } => {
                for c in columns {
                    out.extend(named_lists(c));
                }
            }
            _ => {}
        }
    }
    out
}

/// A preview of a design as one contact or lead sees it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DynamicPreview {
    pub html: String,
    pub text: String,
    /// Block id to the chosen variant id (absent: the default).
    pub choices: BTreeMap<String, Option<String>>,
}

/// Resolves and renders `design` for `person` of `entity` as `ctx` may read
/// them. `NotFound` for a person the caller cannot read.
pub async fn preview(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity: &str,
    person: Uuid,
    design: &EmailDesign,
) -> Result<DynamicPreview, AppError> {
    if !matches!(entity, "contact" | "lead") {
        return Err(AppError::Validation(
            "preview as a contact or a lead".into(),
        ));
    }
    let read = attome_records::entity_crud::read_record(state, ctx, entity, person).await?;
    let read = serde_json::to_value(&read).map_err(AppError::internal)?;
    let record = read
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let lists_named: Vec<Uuid> = named_lists(&design.blocks).into_iter().collect();
    let lists: HashSet<Uuid> = if lists_named.is_empty() {
        HashSet::new()
    } else {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT list_id FROM marketing_list_member WHERE person_id = $1 AND list_id = ANY($2)",
        )
        .bind(person)
        .bind(&lists_named)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect()
    };
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .unwrap_or_default();
    let (resolved, choices) = resolve(design, &attrs, &Recipient { record, lists }, Utc::now());
    let rendered =
        crate::email_render::render(&resolved).map_err(|e| AppError::Validation(e.to_string()))?;
    Ok(DynamicPreview {
        html: rendered.html,
        text: rendered.text,
        choices: choices
            .into_iter()
            .map(|c| (c.block_id, c.variant_id))
            .collect(),
    })
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewBody {
    /// `contact` or `lead`.
    pub entity: String,
    pub person_id: Uuid,
    /// The email design (blocks, direction, width, colour).
    #[schema(value_type = Object)]
    pub design: EmailDesign,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/emails/preview",
    operation_id = "preview_marketing_email",
    tag = "marketing",
    request_body = PreviewBody,
    responses(
        (status = 200, description = "The design as the person would receive it", body = DynamicPreview),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = attome_types::ErrorResponse),
        (status = 404, description = "No such person, or the caller cannot read them", body = attome_types::ErrorResponse),
        (status = 422, description = "The design does not render", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "renders a preview; sends and writes nothing",
    )))),
)]
/// Preview an email as one contact or lead.
///
/// Resolves each dynamic block for the person (their record and lists) and
/// renders the design, naming the variant each block chose.
async fn post_preview(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<crate::segment_insight::ListRead>,
    >,
    axum::Json(body): axum::Json<PreviewBody>,
) -> Result<axum::Json<DynamicPreview>, AppError> {
    preview(&state, &ctx, &body.entity, body.person_id, &body.design)
        .await
        .map(axum::Json)
}

pub fn routes() -> axum::Router<EngineState> {
    axum::Router::new().route(
        "/api/v1/marketing/emails/preview",
        axum::routing::post(post_preview),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_preview), components(schemas(PreviewBody, DynamicPreview)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{AttrInfo, DataClassification, OnTargetDelete};
    use serde_json::json;

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    fn design(list: Uuid) -> EmailDesign {
        serde_json::from_value(json!({
            "blocks": [
                { "type": "heading", "text": "Hello" },
                { "type": "dynamic", "id": "offer", "variants": [
                    { "id": "riyadh", "condition": "city == \"Riyadh\"", "blocks": [ { "type": "text", "text": "Riyadh offer" } ] },
                    { "id": "vip", "in_list": list, "blocks": [ { "type": "text", "text": "VIP offer" } ] }
                ], "default": [ { "type": "text", "text": "Standard offer" } ] }
            ]
        }))
        .unwrap()
    }

    fn texts(design: &EmailDesign) -> Vec<String> {
        design
            .blocks
            .iter()
            .filter_map(|b| match b {
                EmailBlock::Text { text } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_first_matching_variant_wins_else_the_default() {
        // 3: text.
        let attrs = vec![attr("city", 3)];
        let vip = Uuid::now_v7();
        let d = design(vip);
        let now = Utc::now();

        let mut riyadh = Recipient::default();
        riyadh.record.insert("city".into(), json!("Riyadh"));
        riyadh.lists.insert(vip);
        let (resolved, choices) = resolve(&d, &attrs, &riyadh, now);
        assert_eq!(texts(&resolved), vec!["Riyadh offer"]);
        assert_eq!(choices[0].variant_id.as_deref(), Some("riyadh"));

        let mut member = Recipient::default();
        member.record.insert("city".into(), json!("Jeddah"));
        member.lists.insert(vip);
        assert_eq!(
            texts(&resolve(&d, &attrs, &member, now).0),
            vec!["VIP offer"]
        );

        let mut other = Recipient::default();
        other.record.insert("city".into(), json!("Dammam"));
        let (resolved, choices) = resolve(&d, &attrs, &other, now);
        assert_eq!(texts(&resolved), vec!["Standard offer"]);
        assert_eq!(choices[0].variant_id, None);
    }

    #[test]
    fn an_unresolved_design_does_not_render() {
        let d = design(Uuid::now_v7());
        assert!(crate::email_render::render(&d).is_err());
        assert_eq!(named_lists(&d.blocks).len(), 1);
    }
}

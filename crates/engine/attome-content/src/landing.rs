//! Marketing spaces (roadmap E11-T1). A content space of kind `marketing`
//! holds landing pages: it starts with the landing page templates below,
//! and its form blocks name a marketing form (`marketing_form_id`), whose
//! submissions from the page are the page's conversions
//! (`attome_marketing::landing` counts them against the unique visitors
//! the website tracking saw).

use attome_db::Tx;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// The kinds a space may have.
pub const SPACE_KINDS: &[&str] = &["standard", "marketing"];

/// The landing page templates a marketing space starts with: (name,
/// description, blocks). The form block is left for the author to point at
/// a marketing form; the page cannot be saved until it does. Pure.
pub fn templates() -> Vec<(&'static str, &'static str, Value)> {
    let block =
        |kind: &str, props: Value| json!({ "id": Uuid::now_v7(), "kind": kind, "props": props });
    vec![
        (
            "Landing page: offer and form",
            "A headline, the offer and a sign-up form.",
            json!([
                block("heading", json!({ "text": "Your headline", "level": 1 })),
                block(
                    "rich_text",
                    json!({ "html": "<p>What the visitor gets, in two or three sentences.</p>" })
                ),
                block("form", json!({ "marketing_form_id": "" })),
            ]),
        ),
        (
            "Landing page: event registration",
            "The event, its agenda and a registration form.",
            json!([
                block("heading", json!({ "text": "Event name", "level": 1 })),
                block(
                    "rich_text",
                    json!({ "html": "<p>When, where and who it is for.</p>" })
                ),
                block(
                    "rich_text",
                    json!({ "html": "<ul><li>Agenda item</li></ul>" })
                ),
                block("form", json!({ "marketing_form_id": "" })),
            ]),
        ),
        (
            "Landing page: download",
            "A guide or report offered for an email address.",
            json!([
                block("heading", json!({ "text": "Get the guide", "level": 1 })),
                block(
                    "rich_text",
                    json!({ "html": "<p>What is inside and why it helps.</p>" })
                ),
                block("form", json!({ "marketing_form_id": "" })),
                block("component", json!({ "component_key": "testimonial-grid" })),
            ]),
        ),
    ]
}

/// Adds the landing templates and allows them in `space`, in the space's
/// own create transaction.
pub async fn add_templates(
    tx: &mut Tx<'_>,
    space: Uuid,
    actor: Uuid,
    owner_layer: &str,
) -> Result<(), AppError> {
    for (name, description, blocks) in templates() {
        let template: Uuid = sqlx::query_scalar(
            "INSERT INTO content_template (name, description, blocks, created_by, updated_by, owner_layer) \
             VALUES ($1, $2, $3, $4, $4, $5) RETURNING id",
        )
        .bind(name)
        .bind(description)
        .bind(&blocks)
        .bind(actor)
        .bind(owner_layer)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO content_space_template (content_space_id, template_id) VALUES ($1, $2)",
        )
        .bind(space)
        .bind(template)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Block;

    #[test]
    fn landing_conversion_templates_end_in_a_marketing_form() {
        for (name, _, blocks) in templates() {
            let blocks: Vec<Block> = serde_json::from_value(blocks).expect(name);
            assert!(
                blocks
                    .iter()
                    .any(|b| b.props.get("marketing_form_id").is_some()),
                "{name} has a form block"
            );
            // Only the form is left to choose: every other block is valid.
            let others: Vec<Block> = blocks
                .into_iter()
                .filter(|b| b.props.get("marketing_form_id").is_none())
                .collect();
            crate::blocks::validate_blocks(&others).expect(name);
        }
    }

    #[test]
    fn landing_conversion_form_block_needs_a_marketing_form_id() {
        let block = |props: Value| -> Block {
            serde_json::from_value(json!({ "id": Uuid::now_v7(), "kind": "form", "props": props }))
                .unwrap()
        };
        assert!(
            crate::blocks::validate_blocks(&[block(json!({ "marketing_form_id": "" }))]).is_err()
        );
        assert!(
            crate::blocks::validate_blocks(&[block(
                json!({ "marketing_form_id": Uuid::now_v7() })
            )])
            .is_ok()
        );
        assert!(crate::blocks::validate_blocks(&[block(json!({ "entity": "lead" }))]).is_ok());
    }
}

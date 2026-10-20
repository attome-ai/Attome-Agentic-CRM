//! Server-side block validation. A block's `props` is opaque JSON on the
//! wire, but is never trusted as-is: this module checks each block's shape
//! against its declared `kind` before a draft save or publish is accepted,
//! which is what keeps a "custom content" page from becoming a place to
//! hide business logic in a configuration blob (coding-guidelines §8) — in
//! particular, the Component block can only ever reference a name in
//! `ALLOWED_COMPONENTS`, never arbitrary code or markup.

use uuid::Uuid;

use crate::model::{Block, BlockKind};

/// Generous but real — a page this large is almost certainly a mistake, and
/// an unbounded block count is an easy way to make the editor and the
/// public render path both slow.
pub const MAX_BLOCKS_PER_PAGE: usize = 300;
pub const MAX_COLUMNS_PER_ROW: usize = 4;

/// The Component block's curated allow-list — the editor's picker only ever
/// offers these keys; there is no free-text/arbitrary-component path. Add a
/// new key here only alongside the matching Angular component registered in
/// `@attome/xrm/content`'s own allow-list map.
pub const ALLOWED_COMPONENTS: &[&str] = &[
    "cta-banner",
    "pricing-table",
    "testimonial-grid",
    "newsletter-signup",
];

#[derive(Debug, thiserror::Error)]
pub enum BlockValidationError {
    #[error("page has {0} blocks, exceeding the {MAX_BLOCKS_PER_PAGE} limit")]
    TooManyBlocks(usize),
    #[error("block {id}: {message}")]
    InvalidBlock { id: Uuid, message: String },
}

pub fn validate_blocks(blocks: &[Block]) -> Result<(), BlockValidationError> {
    if blocks.len() > MAX_BLOCKS_PER_PAGE {
        return Err(BlockValidationError::TooManyBlocks(blocks.len()));
    }
    for block in blocks {
        validate_block(block).map_err(|message| BlockValidationError::InvalidBlock {
            id: block.id,
            message,
        })?;
    }
    Ok(())
}

fn validate_block(block: &Block) -> Result<(), String> {
    match block.kind {
        BlockKind::Heading => require_nonempty_str(&block.props, "text"),
        BlockKind::RichText => require_nonempty_str(&block.props, "html"),
        BlockKind::Alert => require_nonempty_str(&block.props, "message"),
        BlockKind::Image => require_nonempty_str(&block.props, "src"),
        BlockKind::Columns => {
            let columns = block
                .props
                .get("columns")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "columns block requires a \"columns\" array".to_string())?;
            if columns.is_empty() || columns.len() > MAX_COLUMNS_PER_ROW {
                Err(format!(
                    "columns block must have between 1 and {MAX_COLUMNS_PER_ROW} columns"
                ))
            } else {
                Ok(())
            }
        }
        BlockKind::DataTable | BlockKind::Chart => require_uuid(&block.props, "query_id"),
        // E11-T1: a landing page's form block names a marketing form;
        // any other form block names the entity it captures.
        BlockKind::Form => {
            if block.props.get("marketing_form_id").is_some() {
                require_uuid(&block.props, "marketing_form_id")
            } else {
                require_nonempty_str(&block.props, "entity")
            }
        }
        BlockKind::Component => {
            let key = block
                .props
                .get("component_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "component block requires \"component_key\"".to_string())?;
            if ALLOWED_COMPONENTS.contains(&key) {
                Ok(())
            } else {
                Err(format!("\"{key}\" is not a registered component"))
            }
        }
    }
}

fn require_nonempty_str(props: &serde_json::Value, field: &str) -> Result<(), String> {
    match props.get(field).and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => Ok(()),
        _ => Err(format!("missing or empty \"{field}\"")),
    }
}

fn require_uuid(props: &serde_json::Value, field: &str) -> Result<(), String> {
    let valid = props
        .get(field)
        .and_then(|v| v.as_str())
        .is_some_and(|s| Uuid::parse_str(s).is_ok());
    if valid {
        Ok(())
    } else {
        Err(format!("missing or invalid uuid \"{field}\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn block(kind: BlockKind, props: serde_json::Value) -> Block {
        Block {
            id: Uuid::nil(),
            kind,
            props,
        }
    }

    #[test]
    fn accepts_a_well_formed_page() {
        let blocks = vec![
            block(BlockKind::Heading, json!({"text": "Hello"})),
            block(BlockKind::RichText, json!({"html": "<p>hi</p>"})),
            block(
                BlockKind::Columns,
                json!({"columns": [{"blocks": []}, {"blocks": []}]}),
            ),
        ];
        assert!(validate_blocks(&blocks).is_ok());
    }

    #[test]
    fn rejects_empty_heading_text() {
        let blocks = vec![block(BlockKind::Heading, json!({"text": ""}))];
        assert!(validate_blocks(&blocks).is_err());
    }

    #[test]
    fn rejects_columns_block_with_no_columns_array() {
        let blocks = vec![block(BlockKind::Columns, json!({}))];
        assert!(validate_blocks(&blocks).is_err());
    }

    #[test]
    fn rejects_too_many_columns() {
        let cols: Vec<_> = (0..MAX_COLUMNS_PER_ROW + 1)
            .map(|_| json!({"blocks": []}))
            .collect();
        let blocks = vec![block(BlockKind::Columns, json!({"columns": cols}))];
        assert!(validate_blocks(&blocks).is_err());
    }

    #[test]
    fn rejects_data_table_missing_query_id() {
        let blocks = vec![block(BlockKind::DataTable, json!({}))];
        assert!(validate_blocks(&blocks).is_err());
    }

    #[test]
    fn accepts_chart_with_valid_query_id() {
        let blocks = vec![block(
            BlockKind::Chart,
            json!({"query_id": Uuid::nil().to_string()}),
        )];
        assert!(validate_blocks(&blocks).is_ok());
    }

    #[test]
    fn rejects_component_block_outside_the_allow_list() {
        let blocks = vec![block(
            BlockKind::Component,
            json!({"component_key": "arbitrary-injected-widget"}),
        )];
        assert!(validate_blocks(&blocks).is_err());
    }

    #[test]
    fn accepts_component_block_from_the_allow_list() {
        for key in ALLOWED_COMPONENTS {
            let blocks = vec![block(BlockKind::Component, json!({"component_key": key}))];
            assert!(validate_blocks(&blocks).is_ok(), "{key} should be allowed");
        }
    }

    #[test]
    fn rejects_too_many_blocks() {
        let blocks: Vec<_> = (0..MAX_BLOCKS_PER_PAGE + 1)
            .map(|_| block(BlockKind::Heading, json!({"text": "x"})))
            .collect();
        assert!(validate_blocks(&blocks).is_err());
    }
}

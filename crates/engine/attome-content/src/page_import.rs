//! T2-T4: a CMS page as a page-kind document (T2-T1), so the page designer
//! opens an existing CMS page and a builder can save it as a page.
//!
//! [`cms_to_page`] maps each block onto the page palette:
//!
//! | CMS block | page component |
//! |---|---|
//! | `heading` | `text` (`props.text`, `props.level`, `props.style = heading`) |
//! | `rich_text` | `text` (`props.html`) |
//! | `alert` | `text` (`props.message`, `props.variant`, `props.style = alert`) |
//! | `image` | `text` (`props.image`, `props.alt`, `props.style = image`): the palette has no image component |
//! | `columns` | `container` (`props.layout = columns`) of one `container` per column |
//! | `data_table` | `list` bound to the block's stored query |
//! | `chart` | `chart` bound to the block's stored query |
//! | `form` | `form` (`props.entity` or `props.marketing_form_id`) |
//! | `component` | `text` (`props.component_key`): a CMS widget key is not a component manifest |
//!
//! A component's id is `b-` and the block's id without hyphens, so a page
//! saved from it keeps one component per block. The page is a `portal` page
//! for the `public` and `portal` audiences and a `custom` page for
//! `internal`; the CMS page's title and SEO title and description carry over.

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::model::{Block, BlockKind};

/// The audiences a page may have (the page kind's own list).
pub const AUDIENCES: [&str; 3] = ["public", "portal", "internal"];

/// A component id for a block. Pure.
pub fn node_id(block: Uuid) -> String {
    format!("b-{}", block.simple())
}

fn copy(props: &Value, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|k| props.get(*k).map(|v| ((*k).to_owned(), v.clone())))
        .collect()
}

fn node(block: &Block) -> Value {
    let id = node_id(block.id);
    let p = &block.props;
    let text = |mut props: Map<String, Value>, style: Option<&str>| {
        if let Some(style) = style {
            props.insert("style".into(), json!(style));
        }
        json!({ "id": id, "type": "text", "props": props })
    };
    match block.kind {
        BlockKind::Heading => text(copy(p, &["text", "level"]), Some("heading")),
        BlockKind::RichText => text(copy(p, &["html"]), None),
        BlockKind::Alert => text(copy(p, &["message", "variant"]), Some("alert")),
        BlockKind::Image => {
            let mut props = copy(p, &["alt"]);
            if let Some(src) = p.get("src") {
                props.insert("image".into(), src.clone());
            }
            text(props, Some("image"))
        }
        BlockKind::Component => text(copy(p, &["component_key"]), Some("component")),
        BlockKind::DataTable | BlockKind::Chart => {
            let node_type = if block.kind == BlockKind::Chart {
                "chart"
            } else {
                "list"
            };
            let mut out = json!({ "id": id, "type": node_type });
            if let Some(query) = p.get("query_id") {
                out["binding"] = json!({ "query": query });
            }
            out
        }
        BlockKind::Form => json!({
            "id": id,
            "type": "form",
            "props": copy(p, &["entity", "marketing_form_id"]),
        }),
        BlockKind::Columns => {
            let columns: Vec<Value> = p
                .get("columns")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(n, column)| {
                    let children: Vec<Value> = column
                        .get("blocks")
                        .and_then(Value::as_array)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|b| serde_json::from_value::<Block>(b.clone()).ok())
                        .map(|b| node(&b))
                        .collect();
                    json!({ "id": format!("{id}-c{n}"), "type": "container", "children": children })
                })
                .collect();
            json!({ "id": id, "type": "container", "props": { "layout": "columns" }, "children": columns })
        }
    }
}

/// The page document for a CMS page's blocks. Pure.
pub fn cms_to_page(
    title: &str,
    seo_title: Option<&str>,
    seo_description: Option<&str>,
    audience: &str,
    blocks: &[Block],
) -> Value {
    let page_type = if audience == "internal" {
        "custom"
    } else {
        "portal"
    };
    let mut page = json!({
        "page_type": page_type,
        "audience": audience,
        "title_en": title,
        "root": {
            "id": "main",
            "type": "container",
            "children": blocks.iter().map(node).collect::<Vec<_>>(),
        },
    });
    if let Some(t) = seo_title.filter(|t| !t.trim().is_empty()) {
        page["seo_title"] = json!(t);
    }
    if let Some(d) = seo_description.filter(|d| !d.trim().is_empty()) {
        page["seo_description"] = json!(d);
    }
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(kind: BlockKind, props: Value) -> Block {
        Block {
            id: Uuid::now_v7(),
            kind,
            props,
        }
    }

    #[test]
    fn cms_to_page_maps_every_block() {
        let query = Uuid::now_v7().to_string();
        let inner = block(BlockKind::Heading, json!({ "text": "Inside" }));
        let blocks = vec![
            block(BlockKind::Heading, json!({ "text": "Welcome", "level": 1 })),
            block(BlockKind::RichText, json!({ "html": "<p>Hi</p>" })),
            block(
                BlockKind::Image,
                json!({ "src": "/files/a.png", "alt": "A" }),
            ),
            block(BlockKind::DataTable, json!({ "query_id": query })),
            block(BlockKind::Chart, json!({ "query_id": query })),
            block(BlockKind::Form, json!({ "entity": "lead" })),
            block(
                BlockKind::Columns,
                json!({ "columns": [{ "blocks": [serde_json::to_value(&inner).unwrap()] }, { "blocks": [] }] }),
            ),
        ];
        let page = cms_to_page("Home", Some("Home | Acme"), None, "public", &blocks);
        assert_eq!(page["page_type"], "portal");
        assert_eq!(page["seo_title"], "Home | Acme");
        assert!(page.get("seo_description").is_none());
        let children = page["root"]["children"].as_array().unwrap();
        let types: Vec<&str> = children
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            ["text", "text", "text", "list", "chart", "form", "container"]
        );
        assert_eq!(children[0]["props"]["style"], "heading");
        assert_eq!(children[2]["props"]["image"], "/files/a.png");
        assert_eq!(children[3]["binding"]["query"], json!(query));
        assert_eq!(
            children[6]["children"][0]["children"][0]["props"]["text"],
            "Inside"
        );
        assert_eq!(children[0]["id"], json!(node_id(blocks[0].id)));
        assert_eq!(
            cms_to_page("x", None, None, "internal", &[])["page_type"],
            "custom"
        );
    }

    #[test]
    fn cms_to_page_is_a_valid_page() {
        use attome_model::Kind;
        let blocks = vec![
            block(BlockKind::Heading, json!({ "text": "Welcome" })),
            block(
                BlockKind::Chart,
                json!({ "query_id": Uuid::now_v7().to_string() }),
            ),
            block(BlockKind::Columns, json!({ "columns": [{ "blocks": [] }] })),
        ];
        for audience in AUDIENCES {
            let page = cms_to_page(
                "Home",
                Some("Home"),
                Some("The home page"),
                audience,
                &blocks,
            );
            attome_model::kinds::page::PageKind
                .validate_shape(&page)
                .unwrap_or_else(|issues| panic!("{audience}: {issues:?}"));
        }
    }
}

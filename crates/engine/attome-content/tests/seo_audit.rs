//! E13-T7: the page audit is cheap enough to run after every save.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_content::model::PageDetail;
use attome_content::seo::audit::{AuditInputs, audit_page, score};
use attome_content::seo::settings::PageSeo;
use serde_json::{Value, json};
use uuid::Uuid;

fn block(kind: &str, props: Value) -> Value {
    json!({"id": Uuid::now_v7(), "kind": kind, "props": props})
}

// feature: E13
#[test]
fn audit_on_save_under_50ms_for_200_blocks() {
    let mut blocks = vec![block("heading", json!({"text": "Guide", "level": 1}))];
    for i in 0..199 {
        blocks.push(match i % 3 {
            0 => block("heading", json!({"text": format!("Part {i}"), "level": 2})),
            1 => block(
                "rich_text",
                json!({"html": format!("<p>{} <a href=\"/page-{i}\">more</a></p>", "word ".repeat(40))}),
            ),
            _ => block("image", json!({"src": "https://example.com/a.png", "alt": "A chart"})),
        });
    }
    let page: PageDetail = serde_json::from_value(json!({
        "id": Uuid::now_v7(),
        "parent_page_id": null,
        "content_space_id": Uuid::now_v7(),
        "title": "Guide",
        "url_path": "/guide",
        "status": "draft",
        "template_id": null,
        "blocks_draft": blocks,
        "blocks_published": null,
        "seo_title": "The complete guide to running Attome yourself",
        "seo_description": "Everything about installing, configuring and running Attome on your own server, step by step, in English and Arabic.",
        "published_at": null,
        "publish_at": null,
        "unpublish_at": null,
        "row_version": 1,
        "created_at": chrono::Utc::now(),
        "updated_at": chrono::Utc::now(),
    }))
    .expect("a page");
    let inputs = AuditInputs {
        noindex_paths: (0..500).map(|i| format!("/hidden-{i}")).collect(),
        ..AuditInputs::default()
    };
    let started = std::time::Instant::now();
    let findings = audit_page(&page, &PageSeo::default(), &inputs);
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_millis() < 50,
        "the audit of a 200-block page took {elapsed:?}"
    );
    assert!(findings.is_empty(), "{findings:?}");
    assert_eq!(score(&findings), 100);
}

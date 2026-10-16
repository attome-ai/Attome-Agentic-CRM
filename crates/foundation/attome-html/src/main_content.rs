//! Main-content extraction (roadmap K6-T5): the readable part of a web page
//! as Markdown, without its navigation, header, footer, side panels and
//! cookie banner, with the page's language and text direction.
//!
//! The page's main block is the `<main>`/`<article>`/`role="main"` element
//! when there is one, otherwise the block element holding the most text.
//! Headings, paragraphs, lists and tables keep their shape in Markdown.
//! Blocks a crawler has seen on most pages of a site (a repeated "related
//! links" panel) are dropped when their hash is in `repeated`; see
//! [`block_hashes`].

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};

use scraper::{ElementRef, Html, Node};

/// The extracted content of one page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainContent {
    pub title: Option<String>,
    pub text_markdown: String,
    /// `ar`, `en`, or the page's own `lang`; `None` when unknown.
    pub lang: Option<String>,
    /// `rtl` for Arabic, otherwise `ltr`.
    pub dir: &'static str,
}

const DROPPED_TAGS: &[&str] = &[
    "nav", "header", "footer", "aside", "script", "style", "noscript", "template", "form",
    "button", "svg", "iframe",
];
const DROPPED_ROLES: &[&str] = &[
    "navigation",
    "banner",
    "contentinfo",
    "complementary",
    "dialog",
];
const COOKIE_MARKERS: &[&str] = &["cookie", "consent", "gdpr", "onetrust"];
const BLOCK_TAGS: &[&str] = &[
    "p",
    "div",
    "section",
    "article",
    "main",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "li",
    "table",
    "tr",
    "blockquote",
    "pre",
];

fn dropped(el: &ElementRef<'_>) -> bool {
    let v = el.value();
    if DROPPED_TAGS.contains(&v.name()) {
        return true;
    }
    if v.attr("role").is_some_and(|r| DROPPED_ROLES.contains(&r)) {
        return true;
    }
    if v.attr("hidden").is_some() || v.attr("aria-hidden") == Some("true") {
        return true;
    }
    let marks = format!(
        "{} {}",
        v.attr("id").unwrap_or_default(),
        v.attr("class").unwrap_or_default()
    )
    .to_ascii_lowercase();
    COOKIE_MARKERS.iter().any(|m| marks.contains(m))
}

/// The visible text of `el`, skipping dropped elements.
fn text_of(el: ElementRef<'_>) -> String {
    let mut out = String::new();
    for child in el.children() {
        match child.value() {
            Node::Text(t) => out.push_str(t),
            Node::Element(_) => {
                if let Some(child) = ElementRef::wrap(child)
                    && !dropped(&child)
                {
                    out.push(' ');
                    out.push_str(&text_of(child));
                }
            }
            _ => {}
        }
    }
    out
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hash_text(text: &str) -> u64 {
    let mut h = DefaultHasher::new();
    squash(text).hash(&mut h);
    h.finish()
}

/// The element to extract from: an explicit main region, else the block
/// with the most text directly or below it.
fn main_block(doc: &Html) -> Option<ElementRef<'_>> {
    let root = doc.root_element();
    let mut explicit = None;
    let mut best: Option<(usize, ElementRef<'_>)> = None;
    let mut stack = vec![root];
    while let Some(el) = stack.pop() {
        if dropped(&el) {
            continue;
        }
        let name = el.value().name();
        if explicit.is_none()
            && (name == "main" || name == "article" || el.value().attr("role") == Some("main"))
        {
            explicit = Some(el);
        }
        if matches!(name, "div" | "section" | "body") {
            let len = squash(&text_of(el)).chars().count();
            if best.is_none_or(|(b, _)| len > b) {
                best = Some((len, el));
            }
        }
        stack.extend(el.children().filter_map(ElementRef::wrap));
    }
    explicit.or(best.map(|(_, el)| el))
}

fn render(el: ElementRef<'_>, repeated: &HashSet<u64>, out: &mut Vec<String>) {
    for child in el.children() {
        let Some(child) = ElementRef::wrap(child) else {
            if let Node::Text(t) = child.value() {
                let t = squash(t);
                if !t.is_empty() {
                    out.push(t);
                }
            }
            continue;
        };
        if dropped(&child) {
            continue;
        }
        let name = child.value().name();
        if BLOCK_TAGS.contains(&name) && repeated.contains(&hash_text(&text_of(child))) {
            continue;
        }
        match name {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = name[1..].parse::<usize>().unwrap_or(1);
                let text = squash(&text_of(child));
                if !text.is_empty() {
                    out.push(format!("{} {text}", "#".repeat(level)));
                }
            }
            "p" | "blockquote" | "pre" => {
                let text = squash(&text_of(child));
                if !text.is_empty() {
                    out.push(if name == "blockquote" {
                        format!("> {text}")
                    } else {
                        text
                    });
                }
            }
            "ul" | "ol" => {
                let mut items = Vec::new();
                for (i, li) in child
                    .children()
                    .filter_map(ElementRef::wrap)
                    .filter(|li| li.value().name() == "li" && !dropped(li))
                    .enumerate()
                {
                    let text = squash(&text_of(li));
                    if text.is_empty() {
                        continue;
                    }
                    items.push(if name == "ol" {
                        format!("{}. {text}", i + 1)
                    } else {
                        format!("- {text}")
                    });
                }
                if !items.is_empty() {
                    out.push(items.join("\n"));
                }
            }
            "table" => render_table(child, out),
            _ => render(child, repeated, out),
        }
    }
}

fn render_table(table: ElementRef<'_>, out: &mut Vec<String>) {
    let mut rows = Vec::new();
    let mut stack = vec![table];
    while let Some(el) = stack.pop() {
        for child in el.children().filter_map(ElementRef::wrap) {
            if child.value().name() == "tr" {
                let cells: Vec<String> = child
                    .children()
                    .filter_map(ElementRef::wrap)
                    .filter(|c| matches!(c.value().name(), "td" | "th"))
                    .map(|c| squash(&text_of(c)).replace('|', "\\|"))
                    .collect();
                if !cells.is_empty() {
                    rows.push(cells);
                }
            } else if matches!(child.value().name(), "thead" | "tbody" | "tfoot") {
                stack.push(child);
            }
        }
    }
    let Some(width) = rows.iter().map(Vec::len).max() else {
        return;
    };
    let mut lines = Vec::with_capacity(rows.len() + 1);
    for (i, row) in rows.iter().enumerate() {
        let mut cells = row.clone();
        cells.resize(width, String::new());
        lines.push(format!("| {} |", cells.join(" | ")));
        if i == 0 {
            lines.push(format!("|{}", " --- |".repeat(width)));
        }
    }
    out.push(lines.join("\n"));
}

fn arabic_ratio(text: &str) -> f64 {
    let letters: Vec<char> = text.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return 0.0;
    }
    let arabic = letters
        .iter()
        .filter(|c| matches!(**c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{08A0}'..='\u{08FF}'))
        .count();
    arabic as f64 / letters.len() as f64
}

/// Extracts the main content of `html`, dropping blocks whose text hash is
/// in `repeated`.
pub fn extract_main_with(html: &str, repeated: &HashSet<u64>) -> MainContent {
    let doc = Html::parse_document(html);
    let root = doc.root_element();
    let title = root
        .descendants()
        .filter_map(ElementRef::wrap)
        .find(|e| e.value().name() == "title")
        .map(|t| squash(&t.text().collect::<String>()))
        .filter(|t| !t.is_empty());
    let mut lines = Vec::new();
    if let Some(main) = main_block(&doc) {
        render(main, repeated, &mut lines);
    }
    let text_markdown = lines.join("\n\n");
    let declared = root
        .value()
        .attr("lang")
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty());
    let lang = if arabic_ratio(&text_markdown) > 0.3 {
        Some("ar".to_owned())
    } else {
        declared.or_else(|| (!text_markdown.is_empty()).then(|| "en".to_owned()))
    };
    let dir = if lang
        .as_deref()
        .is_some_and(|l| l == "ar" || l.starts_with("ar-"))
    {
        "rtl"
    } else {
        "ltr"
    };
    MainContent {
        title,
        text_markdown,
        lang,
        dir,
    }
}

/// [`extract_main_with`] with no repeated blocks.
pub fn extract_main(html: &str) -> MainContent {
    extract_main_with(html, &HashSet::new())
}

/// The text hashes of a page's block elements, for a crawler to count across
/// a run: blocks present on more than half the pages go in `repeated`.
pub fn block_hashes(html: &str) -> HashSet<u64> {
    let doc = Html::parse_document(html);
    doc.root_element()
        .descendants()
        .filter_map(ElementRef::wrap)
        .filter(|e| BLOCK_TAGS.contains(&e.value().name()) && e.value().name() != "main")
        .map(|e| squash(&text_of(e)))
        .filter(|t| t.chars().count() >= 20)
        .map(|t| hash_text(&t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_headings_lists_and_tables() {
        let html = "<html><body><main><h2>Plans</h2><p>Pick one.</p>\
                    <ul><li>Basic</li><li>Pro</li></ul>\
                    <table><tr><th>Plan</th><th>Price</th></tr><tr><td>Pro</td><td>10</td></tr></table>\
                    </main></body></html>";
        let m = extract_main(html);
        assert_eq!(
            m.text_markdown,
            "## Plans\n\nPick one.\n\n- Basic\n- Pro\n\n| Plan | Price |\n| --- | --- |\n| Pro | 10 |"
        );
    }

    #[test]
    fn repeated_blocks_are_dropped() {
        let related = "<div class=\"related\">Related reading for every page of the site</div>";
        let html =
            format!("<html><body><main><p>The article body.</p>{related}</main></body></html>");
        let repeated = block_hashes(&format!("<html><body>{related}</body></html>"));
        let m = extract_main_with(&html, &repeated);
        assert!(m.text_markdown.contains("article body"));
        assert!(!m.text_markdown.contains("Related reading"));
    }
}

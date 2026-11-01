//! Performance checks at publish (roadmap T1-T4): static checks on a form's
//! or a page's layout for what makes it slow to open, each finding with the
//! fix to make. Like the accessibility checks ([`crate::a11y`]) they warn,
//! unless the deployment's `model.publish.quality_gate` setting is `block`.
//!
//! - **Form fields**: more than [`MAX_FORM_FIELDS`] fields on one form; each
//!   is read, rendered and validated on every open.
//! - **Related lists**: more than [`MAX_RELATED_LISTS`] on one form; each is
//!   a query when the form opens.
//! - **Page data components**: more than [`MAX_PAGE_DATA_COMPONENTS`]
//!   components that load data (list, chart, kanban, map, timeline, metric,
//!   form) on one page; each is at least one request on load.

use serde_json::Value;

/// The most fields one form should show.
pub const MAX_FORM_FIELDS: usize = 120;
/// The most related lists one form should show.
pub const MAX_RELATED_LISTS: usize = 8;
/// The most data-loading components one page should hold.
pub const MAX_PAGE_DATA_COMPONENTS: usize = 12;

const DATA_COMPONENTS: [&str; 7] = [
    "list", "chart", "kanban", "map", "timeline", "metric", "form",
];

/// One finding: where, what, and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfFinding {
    /// A JSON pointer into the document.
    pub path: String,
    pub code: &'static str,
    pub message: String,
    pub fix: String,
}

impl PerfFinding {
    /// One line for a publish warning.
    pub fn as_warning(&self) -> String {
        format!(
            "{} ({}): {} Fix: {}",
            self.path, self.code, self.message, self.fix
        )
    }
}

/// The performance findings of a document of `kind`; none for other kinds.
/// Pure.
pub fn check(kind: &str, doc: &Value) -> Vec<PerfFinding> {
    match kind {
        "form" => check_form(doc),
        "page" => check_page(doc),
        _ => Vec::new(),
    }
}

fn sections(doc: &Value) -> impl Iterator<Item = &Value> {
    doc["sections"].as_array().into_iter().flatten().chain(
        doc["tabs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|tab| tab["sections"].as_array().into_iter().flatten()),
    )
}

fn check_form(doc: &Value) -> Vec<PerfFinding> {
    let mut out = Vec::new();
    let fields: usize = sections(doc)
        .map(|s| s["fields"].as_array().map_or(0, Vec::len))
        .sum();
    if fields > MAX_FORM_FIELDS {
        out.push(PerfFinding {
            path: String::new(),
            code: "too_many_fields",
            message: format!(
                "The form shows {fields} fields; every one is read and rendered each time it opens."
            ),
            fix: format!(
                "Keep it to {MAX_FORM_FIELDS} or fewer: move rarely used fields to a second form or a related record."
            ),
        });
    }
    let related: usize = sections(doc)
        .map(|s| s["related"].as_array().map_or(0, Vec::len))
        .sum();
    if related > MAX_RELATED_LISTS {
        out.push(PerfFinding {
            path: String::new(),
            code: "too_many_related_lists",
            message: format!(
                "The form shows {related} related lists; each is a query when it opens."
            ),
            fix: format!(
                "Keep it to {MAX_RELATED_LISTS} or fewer, or put the rest on a tab of their own."
            ),
        });
    }
    out
}

fn count_data_components(node: &Value) -> usize {
    let own = usize::from(
        node.get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| DATA_COMPONENTS.contains(&t)),
    );
    own + node["children"]
        .as_array()
        .into_iter()
        .flatten()
        .map(count_data_components)
        .sum::<usize>()
}

fn check_page(doc: &Value) -> Vec<PerfFinding> {
    let count = count_data_components(&doc["root"]);
    if count > MAX_PAGE_DATA_COMPONENTS {
        vec![PerfFinding {
            path: "/root".to_owned(),
            code: "too_many_data_components",
            message: format!(
                "The page holds {count} components that load data; each is at least one request on load."
            ),
            fix: format!(
                "Keep it to {MAX_PAGE_DATA_COMPONENTS} or fewer: split the page or put some behind tabs."
            ),
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_heavy_form_and_a_busy_page_are_found() {
        let fields: Vec<String> = (0..=MAX_FORM_FIELDS).map(|n| format!("f{n}")).collect();
        let related: Vec<Value> = (0..=MAX_RELATED_LISTS)
            .map(|n| json!({ "label": format!("r{n}") }))
            .collect();
        let form = json!({ "tabs": [{ "label": "All", "sections": [
            { "label": "A", "fields": fields, "related": related }
        ] }] });
        let codes: Vec<&str> = check("form", &form).iter().map(|f| f.code).collect();
        assert_eq!(codes, vec!["too_many_fields", "too_many_related_lists"]);

        let light = json!({ "sections": [{ "label": "A", "fields": ["a", "b"] }] });
        assert!(check("form", &light).is_empty());

        let lists: Vec<Value> = (0..=MAX_PAGE_DATA_COMPONENTS)
            .map(|_| json!({ "type": "list" }))
            .collect();
        let page = json!({ "root": { "type": "stack", "children": [
            { "type": "tabs", "children": lists },
            { "type": "text" }
        ] } });
        assert_eq!(check("page", &page)[0].code, "too_many_data_components");
        assert!(check("view", &page).is_empty());
    }
}

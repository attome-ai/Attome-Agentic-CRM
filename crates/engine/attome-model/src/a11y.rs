//! Accessibility checks at publish (roadmap B22-T2): static checks on a
//! form's or a page's layout, each finding with the fix to make. They warn;
//! they never block a publish, because the person publishing may have a
//! reason the check cannot see.
//!
//! - **Labels**: a form tab, section or related list with no label; a page
//!   whose title is missing in a language; a page component that shows data
//!   or acts (list, form, chart, kanban, map, timeline, metric, button, tabs)
//!   with no English or no Arabic title or label, so a screen reader can name
//!   it in both.
//! - **Order**: a form showing the same field twice (read out twice, and the
//!   second copy edits the same value); a form section with nothing in it.
//! - **Contrast**: a page component whose `props.color` and
//!   `props.background` are both set and read below 4.5:1 (WCAG AA for
//!   body text).

use std::collections::BTreeSet;

use serde_json::Value;

/// One finding: where, what, and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A11yFinding {
    /// A JSON pointer into the document.
    pub path: String,
    pub code: &'static str,
    pub message: String,
    pub fix: String,
}

impl A11yFinding {
    /// One line for a publish warning.
    pub fn as_warning(&self) -> String {
        format!(
            "{} ({}): {} Fix: {}",
            self.path, self.code, self.message, self.fix
        )
    }
}

/// The minimum contrast for body text (WCAG 2 AA).
pub const MIN_CONTRAST: f64 = 4.5;

const NAMED_COMPONENTS: [&str; 9] = [
    "list", "form", "chart", "kanban", "map", "timeline", "metric", "button", "tabs",
];

fn text(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).map_or("", str::trim)
}

fn finding(path: String, code: &'static str, message: &str, fix: &str) -> A11yFinding {
    A11yFinding {
        path,
        code,
        message: message.to_owned(),
        fix: fix.to_owned(),
    }
}

/// The findings for a document of `kind` (only `form` and `page` are
/// checked). Pure.
pub fn check(kind: &str, doc: &Value) -> Vec<A11yFinding> {
    match kind {
        "form" => check_form(doc),
        "page" => check_page(doc),
        _ => Vec::new(),
    }
}

fn check_form(doc: &Value) -> Vec<A11yFinding> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut sections: Vec<(String, &Value)> = Vec::new();
    for (i, section) in doc["sections"].as_array().into_iter().flatten().enumerate() {
        sections.push((format!("/sections/{i}"), section));
    }
    for (t, tab) in doc["tabs"].as_array().into_iter().flatten().enumerate() {
        if text(tab.get("label")).is_empty() {
            out.push(finding(
                format!("/tabs/{t}/label"),
                "missing_label",
                "This tab has no label, so it is announced without a name.",
                "Give the tab a short label that says what it holds.",
            ));
        }
        for (i, section) in tab["sections"].as_array().into_iter().flatten().enumerate() {
            sections.push((format!("/tabs/{t}/sections/{i}"), section));
        }
    }
    for (path, section) in sections {
        if text(section.get("label")).is_empty() {
            out.push(finding(
                format!("{path}/label"),
                "missing_label",
                "This section has no label, so its fields have no group name.",
                "Give the section a label that names its fields as a group.",
            ));
        }
        let fields = section["fields"].as_array().map_or(0, Vec::len);
        let related = section["related"].as_array().map_or(0, Vec::len);
        let components = section["components"].as_array().map_or(0, Vec::len);
        if fields + related + components == 0 {
            out.push(finding(
                path.clone(),
                "empty_section",
                "This section shows nothing.",
                "Add fields to the section or remove it.",
            ));
        }
        for (j, field) in section["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(id) = field.as_str() else {
                continue;
            };
            if !seen.insert(id.to_owned()) {
                out.push(finding(
                    format!("{path}/fields/{j}"),
                    "duplicate_field",
                    "This field is already on the form; it is read out twice and both copies edit the same value.",
                    "Keep the field in one place.",
                ));
            }
        }
        for (j, list) in section["related"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if text(list.get("label")).is_empty() {
                out.push(finding(
                    format!("{path}/related/{j}/label"),
                    "missing_label",
                    "This related list has no label.",
                    "Give the list a label that names the related records.",
                ));
            }
        }
    }
    out
}

fn check_page(doc: &Value) -> Vec<A11yFinding> {
    let mut out = Vec::new();
    for (key, language) in [("title_en", "English"), ("title_ar", "Arabic")] {
        if text(doc.get(key)).is_empty() {
            out.push(finding(
                format!("/{key}"),
                "missing_label",
                &format!("The page has no {language} title."),
                &format!("Add a {language} title; it names the page and its browser tab."),
            ));
        }
    }
    walk_node(&doc["root"], "/root", &mut out);
    out
}

fn walk_node(node: &Value, path: &str, out: &mut Vec<A11yFinding>) {
    let kind = text(node.get("type"));
    let props = &node["props"];
    if NAMED_COMPONENTS.contains(&kind) {
        let key = if kind == "button" { "label" } else { "title" };
        for (suffix, language) in [("en", "English"), ("ar", "Arabic")] {
            if text(props.get(format!("{key}_{suffix}"))).is_empty() {
                out.push(A11yFinding {
                    path: format!("{path}/props/{key}_{suffix}"),
                    code: "missing_label",
                    message: format!(
                        "This {kind} has no {language} {key}, so a screen reader cannot name it."
                    ),
                    fix: format!("Set props.{key}_{suffix}."),
                });
            }
        }
    }
    if let (Some(fg), Some(bg)) = (
        props.get("color").and_then(Value::as_str).and_then(hex_rgb),
        props
            .get("background")
            .and_then(Value::as_str)
            .and_then(hex_rgb),
    ) {
        let ratio = contrast(fg, bg);
        if ratio < MIN_CONTRAST {
            out.push(A11yFinding {
                path: format!("{path}/props/color"),
                code: "low_contrast",
                message: format!(
                    "The text colour reads at {ratio:.1}:1 on its background; body text needs {MIN_CONTRAST}:1."
                ),
                fix: "Darken the text or lighten the background (or the reverse) until the ratio is at least 4.5:1.".to_owned(),
            });
        }
    }
    for (i, child) in node["children"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        walk_node(child, &format!("{path}/children/{i}"), out);
    }
}

/// `#rrggbb` (or `#rgb`) as RGB. Pure.
pub fn hex_rgb(hex: &str) -> Option<(u8, u8, u8)> {
    let digits = hex.trim().strip_prefix('#')?;
    let full: String = match digits.len() {
        3 => digits.chars().flat_map(|c| [c, c]).collect(),
        6 => digits.to_owned(),
        _ => return None,
    };
    let byte = |i: usize| u8::from_str_radix(full.get(i..i + 2)?, 16).ok();
    Some((byte(0)?, byte(2)?, byte(4)?))
}

fn luminance((r, g, b): (u8, u8, u8)) -> f64 {
    let channel = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.039_28 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

/// The WCAG contrast ratio of two colours, 1 to 21. Pure.
pub fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn codes(findings: &[A11yFinding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn a11y_publish_warns_on_an_unlabelled_form_field_group_with_a_fix() {
        let form = json!({ "entity": "e", "sections": [
            { "label": "", "fields": ["a", "b"] },
            { "label": "More", "fields": ["a"] },
            { "label": "Empty", "fields": [] },
        ]});
        let found = check("form", &form);
        assert_eq!(
            codes(&found),
            vec!["missing_label", "duplicate_field", "empty_section"]
        );
        assert_eq!(found[0].path, "/sections/0/label");
        assert!(!found[0].fix.is_empty());
        assert!(found[0].as_warning().contains("Fix:"));
    }

    #[test]
    fn a11y_publish_checks_tabbed_forms_and_related_lists() {
        let form = json!({ "entity": "e", "tabs": [ { "label": " ", "sections": [
            { "label": "Main", "fields": ["a"], "related": [ { "entity": "x" } ] } ] } ] });
        let found = check("form", &form);
        assert_eq!(codes(&found), vec!["missing_label", "missing_label"]);
        assert_eq!(found[1].path, "/tabs/0/sections/0/related/0/label");
        let fine = json!({ "entity": "e", "sections": [ { "label": "Main", "fields": ["a"] } ] });
        assert!(check("form", &fine).is_empty());
    }

    #[test]
    fn a11y_publish_names_page_components_in_both_languages() {
        let page = json!({ "page_type": "custom", "title_en": "Home",
            "root": { "id": "main", "type": "container", "children": [
                { "id": "deals", "type": "list", "props": { "title_en": "Deals" } },
                { "id": "go", "type": "button", "props": { "label_en": "Go", "label_ar": "اذهب" } },
                { "id": "note", "type": "text", "props": { "text_en": "Hi" } } ] } });
        let found = check("page", &page);
        let paths: Vec<&str> = found.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["/title_ar", "/root/children/0/props/title_ar"],
            "{found:?}"
        );
    }

    #[test]
    fn a11y_publish_flags_low_contrast_colours() {
        assert!((contrast((0, 0, 0), (255, 255, 255)) - 21.0).abs() < 0.01);
        assert_eq!(hex_rgb("#fff"), Some((255, 255, 255)));
        assert_eq!(hex_rgb("#12345"), None);
        let page = json!({ "title_en": "A", "title_ar": "أ", "root": { "id": "m", "type": "text",
            "props": { "color": "#999999", "background": "#ffffff" } } });
        assert_eq!(codes(&check("page", &page)), vec!["low_contrast"]);
        let readable = json!({ "title_en": "A", "title_ar": "أ", "root": { "id": "m", "type": "text",
            "props": { "color": "#333333", "background": "#ffffff" } } });
        assert!(check("page", &readable).is_empty());
        assert!(check("navigation", &readable).is_empty());
    }
}

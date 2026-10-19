//! The tour kind (roadmap B14-T1): a guided walk through a screen, step by
//! step, each step pointing at one element.
//!
//! ```json
//! { "title": { "en": "Your first deal", "ar": "صفقتك الأولى" },
//!   "route": "/xrm/entity/opportunity",
//!   "roles": ["0190…"],
//!   "auto_start": true,
//!   "steps": [
//!     { "selector": "[data-tour=new-record]",
//!       "title": { "en": "Add a deal", "ar": "أضف صفقة" },
//!       "text": { "en": "Start here.", "ar": "ابدأ من هنا." },
//!       "placement": "bottom" } ] }
//! ```
//!
//! `route` is the path prefix the tour belongs to; `roles` limits it to
//! people holding one of those roles (empty: everyone). With `auto_start` a
//! person sees it once, the first time they open that route; anyone can
//! replay it. Every text has English, Arabic or both. Tours are served to
//! every signed-in user as cooked artefacts (`/api/v1/cooked/tour`): they
//! hold only on-screen help text, a route and role ids.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const TOUR: KindName = KindName("tour");

/// Most steps in one tour.
pub const MAX_STEPS: usize = 20;
/// Longest CSS selector a step may point with.
pub const MAX_SELECTOR_CHARS: usize = 200;
/// Longest step text, per language.
pub const MAX_TEXT_CHARS: usize = 1_000;
/// Longest title, per language.
pub const MAX_TITLE_CHARS: usize = 120;
/// Where a step's bubble sits beside its element.
pub const PLACEMENTS: &[&str] = &["top", "bottom", "start", "end"];
/// The languages a text may carry.
pub const LANGUAGES: &[&str] = &["en", "ar"];

/// The tour kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct TourKind;

/// The issues of one `{ "en": .., "ar": .. }` text at `at`.
fn check_text(
    value: Option<&Value>,
    at: &str,
    limit: usize,
    required: bool,
    issues: &mut Vec<Issue>,
) {
    let Some(value) = value else {
        if required {
            issues.push(Issue::new(
                at,
                "required",
                "this text is required, in English, Arabic or both",
            ));
        }
        return;
    };
    let Some(object) = value.as_object() else {
        issues.push(Issue::new(
            at,
            "invalid",
            "a text is { \"en\": .., \"ar\": .. }",
        ));
        return;
    };
    let mut any = false;
    for (language, text) in object {
        let here = format!("{at}/{language}");
        if !LANGUAGES.contains(&language.as_str()) {
            issues.push(Issue::new(
                here,
                "unknown_language",
                "a text is in en or ar",
            ));
            continue;
        }
        match text.as_str() {
            Some(t) if !t.trim().is_empty() => {
                any = true;
                if t.chars().count() > limit {
                    issues.push(Issue::new(
                        here,
                        "too_long",
                        format!("at most {limit} characters"),
                    ));
                }
            }
            Some(_) => {}
            None => issues.push(Issue::new(here, "invalid", "a text is a string")),
        }
    }
    if !any && required {
        issues.push(Issue::new(
            at,
            "required",
            "this text is required, in English, Arabic or both",
        ));
    }
}

impl Kind for TourKind {
    fn name(&self) -> KindName {
        TOUR
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        let text = |limit: usize| {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "en": { "type": "string", "maxLength": limit },
                    "ar": { "type": "string", "maxLength": limit }
                }
            })
        };
        json!({
            "type": "object",
            "required": ["title", "route", "steps"],
            "additionalProperties": false,
            "properties": {
                "title": text(MAX_TITLE_CHARS),
                "route": { "type": "string", "pattern": "^/", "maxLength": 200 },
                "roles": { "type": "array", "items": { "type": "string", "format": "uuid" }, "maxItems": 50 },
                "auto_start": { "type": "boolean" },
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_STEPS,
                    "items": {
                        "type": "object",
                        "required": ["selector", "text"],
                        "additionalProperties": false,
                        "properties": {
                            "selector": { "type": "string", "minLength": 1, "maxLength": MAX_SELECTOR_CHARS },
                            "title": text(MAX_TITLE_CHARS),
                            "text": text(MAX_TEXT_CHARS),
                            "placement": { "type": "string", "enum": PLACEMENTS }
                        }
                    }
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a tour is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !["title", "route", "roles", "auto_start", "steps"].contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a tour has no `{key}`"),
                ));
            }
        }
        check_text(
            doc.get("title"),
            "/title",
            MAX_TITLE_CHARS,
            true,
            &mut issues,
        );
        match doc["route"].as_str() {
            Some(route) if route.starts_with('/') && route.chars().count() <= 200 => {}
            _ => issues.push(Issue::new(
                "/route",
                "invalid",
                "a route is an app path starting with /",
            )),
        }
        if let Some(roles) = doc.get("roles") {
            match roles.as_array() {
                Some(roles) => {
                    for (i, role) in roles.iter().enumerate() {
                        if role
                            .as_str()
                            .is_none_or(|r| uuid::Uuid::parse_str(r).is_err())
                        {
                            issues.push(Issue::new(
                                format!("/roles/{i}"),
                                "invalid",
                                "a role is an id",
                            ));
                        }
                    }
                }
                None => issues.push(Issue::new(
                    "/roles",
                    "invalid",
                    "roles are a list of role ids",
                )),
            }
        }
        if doc.get("auto_start").is_some_and(|a| !a.is_boolean()) {
            issues.push(Issue::new(
                "/auto_start",
                "invalid",
                "auto_start is true or false",
            ));
        }
        match doc["steps"].as_array() {
            Some(steps) if !steps.is_empty() && steps.len() <= MAX_STEPS => {
                for (i, step) in steps.iter().enumerate() {
                    let at = format!("/steps/{i}");
                    match step["selector"].as_str() {
                        Some(s) if !s.trim().is_empty() && s.chars().count() <= MAX_SELECTOR_CHARS => {}
                        _ => issues.push(Issue::new(
                            format!("{at}/selector"),
                            "invalid",
                            "a step points at an element with a CSS selector of at most 200 characters",
                        )),
                    }
                    check_text(
                        step.get("title"),
                        &format!("{at}/title"),
                        MAX_TITLE_CHARS,
                        false,
                        &mut issues,
                    );
                    check_text(
                        step.get("text"),
                        &format!("{at}/text"),
                        MAX_TEXT_CHARS,
                        true,
                        &mut issues,
                    );
                    if step
                        .get("placement")
                        .is_some_and(|p| p.as_str().is_none_or(|p| !PLACEMENTS.contains(&p)))
                    {
                        issues.push(Issue::new(
                            format!("{at}/placement"),
                            "invalid",
                            "a placement is top, bottom, start or end",
                        ));
                    }
                }
            }
            _ => issues.push(Issue::new(
                "/steps",
                "invalid",
                format!("a tour has 1 to {MAX_STEPS} steps"),
            )),
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut tour = input.doc.clone();
                if let Some(object) = tour.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object.entry("roles").or_insert_with(|| json!([]));
                    object.entry("auto_start").or_insert(json!(false));
                }
                let text = crate::canonical::canonicalize(&tour).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: TOUR,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit a guided tour: its title, the app route it belongs to, the roles that see it, whether it starts by itself the first time, and its steps (a CSS selector and English/Arabic text each)."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tour() -> Value {
        json!({
            "title": { "en": "Your first deal", "ar": "صفقتك الأولى" },
            "route": "/xrm/entity/opportunity",
            "roles": ["01900000-0000-7000-8000-000000000001"],
            "auto_start": true,
            "steps": [
                { "selector": "[data-tour=new-record]",
                  "title": { "en": "Add a deal" },
                  "text": { "en": "Start here.", "ar": "ابدأ من هنا." },
                  "placement": "bottom" }
            ]
        })
    }

    fn codes(doc: &Value) -> Vec<String> {
        TourKind
            .validate_shape(doc)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|issue| format!("{} {}", issue.path, issue.code))
            .collect()
    }

    #[test]
    fn a_valid_tour_passes() {
        assert!(TourKind.validate_shape(&tour()).is_ok());
    }

    #[test]
    fn bad_tours_name_where() {
        let mut t = tour();
        t["route"] = json!("xrm");
        t["steps"][0]["selector"] = json!("");
        t["steps"][0]["text"] = json!({ "fr": "Bonjour" });
        t["steps"][0]["placement"] = json!("left");
        t["roles"] = json!(["not-a-uuid"]);
        let found = codes(&t);
        for expected in [
            "/route invalid",
            "/steps/0/selector invalid",
            "/steps/0/text/fr unknown_language",
            "/steps/0/text required",
            "/steps/0/placement invalid",
            "/roles/0 invalid",
        ] {
            assert!(
                found.iter().any(|f| f == expected),
                "{expected} in {found:?}"
            );
        }
        let mut empty = tour();
        empty["steps"] = json!([]);
        assert!(codes(&empty).iter().any(|f| f == "/steps invalid"));
        let mut untitled = tour();
        untitled["title"] = json!({ "en": " " });
        assert!(codes(&untitled).iter().any(|f| f == "/title required"));
    }
}

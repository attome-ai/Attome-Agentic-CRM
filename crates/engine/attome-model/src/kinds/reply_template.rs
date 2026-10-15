//! The reply template kind (roadmap G6-T1): a canned reply an agent or a
//! person inserts, with merge fields filled from the record.
//!
//! ```json
//! { "folder": "Billing",
//!   "visibility": { "scope": "team", "ref": "0190…" },
//!   "body": "Dear {{first_name}}, your invoice {{invoice_number}} is paid.",
//!   "variants": { "sms": "Invoice {{invoice_number}} paid. Thank you." } }
//! ```
//!
//! `body` is the reply for every channel without its own variant; a variant
//! for `sms` or `whatsapp` is the short form those channels need. A merge
//! field is `{{name}}` (letters, digits, `_`, and `.` for a lookup's field);
//! one the record lacks renders empty.

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const REPLY_TEMPLATE: KindName = KindName("reply_template");

/// Who sees a template.
pub const SCOPES: &[&str] = &["everyone", "user", "team", "role", "queue"];
/// The channels a variant may be for.
pub const CHANNELS: &[&str] = &["email", "sms", "whatsapp", "chat", "portal"];
/// Longest body.
pub const MAX_BODY_CHARS: usize = 10_000;
/// Longest SMS variant: two segments.
pub const MAX_SMS_CHARS: usize = 320;
/// Longest WhatsApp variant.
pub const MAX_WHATSAPP_CHARS: usize = 1_000;
/// Longest folder name.
pub const MAX_FOLDER_CHARS: usize = 100;

/// The reply template kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplyTemplateKind;

/// The longest text a channel takes.
fn channel_limit(channel: &str) -> usize {
    match channel {
        "sms" => MAX_SMS_CHARS,
        "whatsapp" => MAX_WHATSAPP_CHARS,
        _ => MAX_BODY_CHARS,
    }
}

/// Whether `name` is a usable merge field name.
fn valid_field(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// The `{{name}}` merge fields in `text`, in order, with any that are not
/// usable names as `Err`.
fn fields_in(text: &str) -> Vec<Result<String, String>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find("}}") else { break };
        let name = rest[..end].trim();
        out.push(if valid_field(name) {
            Ok(name.to_owned())
        } else {
            Err(name.to_owned())
        });
        rest = &rest[end + 2..];
    }
    out
}

/// Every merge field the template uses, in any of its texts, sorted.
pub fn merge_fields(doc: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    let texts = std::iter::once(&doc["body"]).chain(
        doc["variants"]
            .as_object()
            .into_iter()
            .flat_map(|v| v.values()),
    );
    for text in texts.filter_map(Value::as_str) {
        names.extend(fields_in(text).into_iter().flatten());
    }
    names.into_iter().collect()
}

/// The reply for `channel`: its variant, else the body, with each merge
/// field replaced by the record's value (a lookup's field by `a.b`).
pub fn render(doc: &Value, channel: &str, record: &Map<String, Value>) -> String {
    let text = doc["variants"][channel]
        .as_str()
        .or_else(|| doc["body"].as_str())
        .unwrap_or_default();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = after[..end].trim();
        let mut value = Value::Object(record.clone());
        for part in name.split('.') {
            value = value.get(part).cloned().unwrap_or(Value::Null);
        }
        match value {
            Value::String(s) => out.push_str(&s),
            Value::Null => {}
            other => out.push_str(&other.to_string()),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

impl Kind for ReplyTemplateKind {
    fn name(&self) -> KindName {
        REPLY_TEMPLATE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["body"],
            "additionalProperties": false,
            "properties": {
                "folder": { "type": "string", "maxLength": MAX_FOLDER_CHARS },
                "visibility": {
                    "type": "object",
                    "required": ["scope"],
                    "additionalProperties": false,
                    "properties": {
                        "scope": { "type": "string", "enum": SCOPES },
                        "ref": { "type": "string", "format": "uuid" }
                    }
                },
                "body": { "type": "string", "minLength": 1, "maxLength": MAX_BODY_CHARS },
                "variants": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "email": { "type": "string", "maxLength": MAX_BODY_CHARS },
                        "sms": { "type": "string", "maxLength": MAX_SMS_CHARS },
                        "whatsapp": { "type": "string", "maxLength": MAX_WHATSAPP_CHARS },
                        "chat": { "type": "string", "maxLength": MAX_BODY_CHARS },
                        "portal": { "type": "string", "maxLength": MAX_BODY_CHARS }
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
                "a reply template is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !["folder", "visibility", "body", "variants"].contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a reply template has no `{key}`"),
                ));
            }
        }
        if doc.get("folder").is_some_and(|f| {
            f.as_str()
                .is_none_or(|f| f.chars().count() > MAX_FOLDER_CHARS)
        }) {
            issues.push(Issue::new(
                "/folder",
                "invalid",
                "a folder is text of at most 100 characters",
            ));
        }
        if let Some(visibility) = doc.get("visibility") {
            let scope = visibility["scope"].as_str();
            if !scope.is_some_and(|s| SCOPES.contains(&s)) {
                issues.push(Issue::new(
                    "/visibility/scope",
                    "invalid",
                    "visibility is everyone, user, team, role or queue",
                ));
            }
            let reference = visibility.get("ref");
            match (scope, reference) {
                (Some("everyone"), Some(_)) => issues.push(Issue::new(
                    "/visibility/ref",
                    "not_allowed",
                    "a template for everyone names no one",
                )),
                (Some(s), None) if s != "everyone" => issues.push(Issue::new(
                    "/visibility/ref",
                    "required",
                    format!("a template for one {s} names it"),
                )),
                (_, Some(r)) if r.as_str().is_none_or(|r| uuid::Uuid::parse_str(r).is_err()) => {
                    issues.push(Issue::new(
                        "/visibility/ref",
                        "invalid",
                        "the reference is an id",
                    ));
                }
                _ => {}
            }
        }
        let mut texts: Vec<(String, &str, usize)> = Vec::new();
        match doc["body"].as_str() {
            Some(body) if !body.trim().is_empty() => {
                texts.push(("/body".into(), body, MAX_BODY_CHARS));
            }
            _ => issues.push(Issue::new(
                "/body",
                "required",
                "a reply template has a body",
            )),
        }
        if let Some(variants) = doc.get("variants") {
            match variants.as_object() {
                Some(variants) => {
                    for (channel, text) in variants {
                        let at = format!("/variants/{channel}");
                        if !CHANNELS.contains(&channel.as_str()) {
                            issues.push(Issue::new(
                                at,
                                "unknown_channel",
                                "a variant is for email, sms, whatsapp, chat or portal",
                            ));
                            continue;
                        }
                        match text.as_str() {
                            Some(text) => texts.push((at, text, channel_limit(channel))),
                            None => issues.push(Issue::new(at, "invalid", "a variant is text")),
                        }
                    }
                }
                None => issues.push(Issue::new(
                    "/variants",
                    "invalid",
                    "variants are text by channel",
                )),
            }
        }
        for (at, text, limit) in texts {
            if text.chars().count() > limit {
                issues.push(Issue::new(
                    at.clone(),
                    "too_long",
                    format!("this text is at most {limit} characters"),
                ));
            }
            for bad in fields_in(text).into_iter().filter_map(Result::err) {
                issues.push(Issue::new(
                    at.clone(),
                    "bad_merge_field",
                    format!("`{{{{{bad}}}}}` is not a field name"),
                ));
            }
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
                let mut template = input.doc.clone();
                if let Some(object) = template.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object.insert("merge_fields".into(), json!(merge_fields(&input.doc)));
                }
                let text =
                    crate::canonical::canonicalize(&template).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: REPLY_TEMPLATE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit a canned reply: its folder, who sees it (everyone, a user, team, role or queue), the body with {{field}} merge fields, and short variants for SMS and WhatsApp."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Value {
        json!({
            "folder": "Billing",
            "visibility": { "scope": "team", "ref": "01900000-0000-7000-8000-000000000001" },
            "body": "Dear {{first_name}}, invoice {{invoice_number}} for {{ account.name }} is paid.",
            "variants": { "sms": "Invoice {{invoice_number}} paid." }
        })
    }

    #[test]
    fn a_template_validates_and_lists_its_merge_fields() {
        assert!(ReplyTemplateKind.validate_shape(&template()).is_ok());
        assert_eq!(
            merge_fields(&template()),
            ["account.name", "first_name", "invoice_number"]
        );
    }

    #[test]
    fn each_channel_gets_its_variant_or_the_body() {
        let record = json!({
            "first_name": "Mona",
            "invoice_number": 1042,
            "account": { "name": "Nakheel" }
        });
        let record = record.as_object().unwrap();
        assert_eq!(render(&template(), "sms", record), "Invoice 1042 paid.");
        assert_eq!(
            render(&template(), "email", record),
            "Dear Mona, invoice 1042 for Nakheel is paid."
        );
        let empty = Map::new();
        assert_eq!(
            render(&template(), "chat", &empty),
            "Dear , invoice  for  is paid."
        );
    }

    #[test]
    fn bad_templates_are_named() {
        let doc = json!({
            "visibility": { "scope": "team" },
            "body": "Hi {{bad name}}",
            "variants": { "sms": "x".repeat(MAX_SMS_CHARS + 1), "fax": "no" },
            "extra": true
        });
        let issues = ReplyTemplateKind.validate_shape(&doc).unwrap_err();
        let found: Vec<(&str, &str)> = issues.iter().map(|i| (i.path.as_str(), i.code)).collect();
        assert!(found.contains(&("/visibility/ref", "required")));
        assert!(found.contains(&("/body", "bad_merge_field")));
        assert!(found.contains(&("/variants/sms", "too_long")));
        assert!(found.contains(&("/variants/fax", "unknown_channel")));
        assert!(found.contains(&("/extra", "unknown_property")));
    }

    #[test]
    fn a_template_for_everyone_names_no_one() {
        let doc = json!({
            "visibility": { "scope": "everyone", "ref": "01900000-0000-7000-8000-000000000001" },
            "body": "Hello"
        });
        let issues = ReplyTemplateKind.validate_shape(&doc).unwrap_err();
        assert!(issues.iter().any(|i| i.code == "not_allowed"));
    }
}

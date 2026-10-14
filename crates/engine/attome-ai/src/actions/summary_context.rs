//! What `record.summarize` puts in front of the model (roadmap N2-T1): the
//! record, the records it points to and its recent timeline, within a
//! budget, and the cache key a finished summary is kept under.
//!
//! **Masking.** Every part comes from a read that already applied the
//! caller's grants: the record's fields from the record read (a sensitive
//! field without its read grant is absent), the related records' names from
//! the same read's lookup metadata (a target row security hides has no
//! name), and the timeline from `record_timeline` (each source gated by its
//! own entity read and row security, sensitive fields never named). Only an
//! entry's kind, time and summary line are used, never its `detail`.
//!
//! **Budget.** The record comes first and whole; related names next; then
//! timeline entries newest first until [`CONTEXT_BUDGET_CHARS`] is reached,
//! with a closing line saying how many were left out.
//!
//! **Cache** (guidelines §5). Source of truth: the generation itself.
//! Key: `attome-ai:summary:{sha256}` over the prompt version, the model, the
//! language, the entity and the exact context text, so any change to the
//! record (its row version), a related name or the timeline is a new key,
//! and two callers share an entry only when they were shown identical facts.
//! TTL [`CACHE_TTL`]; no invalidation is needed since a changed input never
//! reads a stale key. A cache failure degrades to generating; a cold cache
//! generates.

use std::time::Duration;

use attome_records::entity_crud::timeline::TimelineEntry;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The longest context sent for one summary.
pub const CONTEXT_BUDGET_CHARS: usize = 12_000;
/// Timeline entries read for one summary.
pub const TIMELINE_ENTRIES: i64 = 30;
/// How long a finished summary is kept.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The names of the records `lookups` (the record read's lookup metadata)
/// points to, by field, for the targets the caller may see.
pub fn related_names(lookups: Option<&Map<String, Value>>) -> Vec<(String, String)> {
    let mut names: Vec<(String, String)> = lookups
        .into_iter()
        .flatten()
        .filter_map(|(field, meta)| {
            let name = meta.get("name").and_then(Value::as_str)?;
            meta.get("exists")
                .and_then(Value::as_bool)
                .filter(|exists| *exists)?;
            Some((field.clone(), name.to_owned()))
        })
        .collect();
    names.sort();
    names
}

/// The context text: the record, its related records, its timeline.
pub fn build_context(
    record: &Value,
    related: &[(String, String)],
    timeline: &[TimelineEntry],
    budget: usize,
) -> String {
    let mut text = String::from("Record:\n");
    text.push_str(&serde_json::to_string(record).unwrap_or_default());
    text.push('\n');
    if !related.is_empty() {
        text.push_str("\nRelated records:\n");
        for (field, name) in related {
            text.push_str(&format!("- {field}: {name}\n"));
        }
    }
    if timeline.is_empty() {
        return text;
    }
    text.push_str("\nTimeline, newest first:\n");
    for (shown, entry) in timeline.iter().enumerate() {
        let line = format!(
            "- {} {}: {}\n",
            entry.occurred_at.format("%Y-%m-%d %H:%M"),
            entry.kind.as_str(),
            entry.summary.trim()
        );
        if text.chars().count() + line.chars().count() > budget {
            text.push_str(&format!(
                "- ({} older entries left out)\n",
                timeline.len() - shown
            ));
            break;
        }
        text.push_str(&line);
    }
    text
}

/// The cache key a summary of `context` is kept under.
pub fn cache_key(
    prompt_version: &str,
    model_id: &str,
    language: &str,
    entity: &str,
    context: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [prompt_version, model_id, language, entity, context] {
        hasher.update(part.as_bytes());
        // A separator no part can end in, so ("ab","c") != ("a","bc").
        hasher.update([0u8]);
    }
    format!("attome-ai:summary:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_records::entity_crud::timeline::TimelineEntryKind;
    use serde_json::json;

    fn entry(minute: u32, summary: &str) -> TimelineEntry {
        TimelineEntry {
            kind: TimelineEntryKind::Note,
            occurred_at: chrono::DateTime::parse_from_rfc3339(&format!(
                "2026-10-14T10:{minute:02}:00Z"
            ))
            .unwrap()
            .with_timezone(&chrono::Utc),
            source_entity: "note".into(),
            source_id: uuid::Uuid::now_v7(),
            summary: summary.into(),
            detail: json!({ "secret": "never shown" }),
        }
    }

    #[test]
    fn summary_context_holds_record_related_and_timeline() {
        let related = related_names(Some(
            json!({
                "account_ref": { "exists": true, "is_active": true, "name": "Al Noor Trading" },
                "owner_ref": { "exists": false, "is_active": false, "name": null }
            })
            .as_object()
            .unwrap(),
        ));
        assert_eq!(
            related,
            [("account_ref".to_owned(), "Al Noor Trading".to_owned())]
        );
        let text = build_context(
            &json!({ "name": "Renewal" }),
            &related,
            &[entry(30, "Called the buyer"), entry(10, "Sent the quote")],
            CONTEXT_BUDGET_CHARS,
        );
        assert!(text.contains("{\"name\":\"Renewal\"}"));
        assert!(text.contains("- account_ref: Al Noor Trading"));
        assert!(text.contains("2026-10-14 10:30 note: Called the buyer"));
        assert!(!text.contains("never shown"), "detail is never sent");
        assert!(text.find("Called").unwrap() < text.find("Sent").unwrap());
    }

    #[test]
    fn summary_context_stops_at_the_budget() {
        let timeline: Vec<_> = (0..20).map(|m| entry(m, &"x".repeat(100))).collect();
        let text = build_context(&json!({}), &[], &timeline, 500);
        assert!(text.chars().count() < 600);
        assert!(text.contains("older entries left out"));
    }

    #[test]
    fn summary_context_cache_key_follows_every_input() {
        let base = cache_key("v1", "m", "en", "deal", "ctx");
        assert_eq!(base, cache_key("v1", "m", "en", "deal", "ctx"));
        assert!(base.starts_with("attome-ai:summary:"));
        for other in [
            cache_key("v2", "m", "en", "deal", "ctx"),
            cache_key("v1", "n", "en", "deal", "ctx"),
            cache_key("v1", "m", "ar", "deal", "ctx"),
            cache_key("v1", "m", "en", "lead", "ctx"),
            cache_key("v1", "m", "en", "deal", "ctx2"),
            cache_key("v1", "m", "end", "eal", "ctx"),
        ] {
            assert_ne!(base, other);
        }
    }
}

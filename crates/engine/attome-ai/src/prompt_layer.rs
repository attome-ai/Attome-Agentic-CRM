//! Prompt overrides applied at run time (roadmap N10-T1): the published
//! `prompt_override` for an action is layered over the code's prompt.
//!
//! The code's prompt is the locked part and always comes first, unchanged
//! (`attome_model::kinds::prompt_override::render`); the override adds its
//! editable sections after it. Slots are filled from each slot's `default`,
//! or a choice slot's first value, since no caller supplies slot values yet.
//!
//! The effective version is the code's version plus the override's content
//! hash (`record.summarize/v2+o:1a2b3c4d`), so provenance, quality
//! comparisons and every cache keyed on the version tell a changed override
//! apart. A failure to read overrides degrades to the code's prompt.
//!
//! **Staged rollout** (N10-T3): an override with `rollout.share` reaches that
//! percentage of callers, chosen by a stable hash of the prompt, the
//! override and the caller, so one person always sees the same version; the
//! rest keep the code's prompt. Outcomes are recorded per version
//! (`ai_suggestion_outcome.prompt_version`), which is the comparison.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;
use sha2::Digest;

/// The most override objects read when looking one up.
const MAX_OVERRIDES: i64 = 200;

/// The prompt a generation sends, and its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layered {
    pub system: String,
    pub version: String,
}

/// Slot values from each slot's `default`, or a choice's first value.
pub fn slot_defaults(doc: &Value) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for (name, slot) in doc["slots"].as_object().into_iter().flatten() {
        let value = slot["default"]
            .as_str()
            .or_else(|| slot["values"].get(0).and_then(Value::as_str));
        if let Some(value) = value {
            values.insert(name.clone(), value.to_owned());
        }
    }
    values
}

/// The code's prompt with an override (its document and content hash)
/// layered over it, or the code's prompt alone.
pub fn layered(locked: &str, base_version: &str, found: Option<(&Value, &str)>) -> Layered {
    match found {
        None => Layered {
            system: locked.to_owned(),
            version: base_version.to_owned(),
        },
        Some((doc, hash)) => Layered {
            system: attome_model::kinds::prompt_override::render(locked, doc, &slot_defaults(doc)),
            version: format!(
                "{base_version}+o:{}",
                hash.chars().take(8).collect::<String>()
            ),
        },
    }
}

/// The published override for `prompt_id`: among active override objects,
/// each one's newest published version, the most recent naming the prompt.
async fn published_override(
    db: &DbPool,
    prompt_id: &str,
) -> Result<Option<(Value, String)>, AppError> {
    let rows: Vec<(Value, String)> = sqlx::query_as(
        "SELECT doc, content_hash FROM ( \
             SELECT DISTINCT ON (o.id) v.doc, v.content_hash, v.created_at \
             FROM metadata_object o \
             JOIN metadata_object_version v ON v.object_id = o.id \
             WHERE o.kind = 'prompt_override' AND o.is_active AND v.state = 'published' \
             ORDER BY o.id, v.version_no DESC \
             LIMIT $2 \
         ) newest \
         WHERE doc->>'prompt' = $1 \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .bind(prompt_id)
    .bind(MAX_OVERRIDES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().next())
}

/// Whether `caller` is in an override's rollout: always without a
/// `rollout.share`, otherwise for that percentage of callers.
pub fn in_rollout(prompt_id: &str, doc: &Value, hash: &str, caller: &str) -> bool {
    let Some(share) = doc["rollout"]["share"].as_u64() else {
        return true;
    };
    let digest = sha2::Sha256::digest(format!("{prompt_id}|{hash}|{caller}").as_bytes());
    let bucket = u64::from(u16::from_be_bytes([digest[0], digest[1]])) % 100;
    bucket < share.min(100)
}

/// The prompt `prompt_id` runs with now for `caller` (a stable id, such as
/// the user's).
pub async fn effective(
    db: &DbPool,
    prompt_id: &str,
    base_version: &str,
    locked: &str,
    caller: &str,
) -> Layered {
    match published_override(db, prompt_id).await {
        Ok(found) => layered(
            locked,
            base_version,
            found
                .as_ref()
                .filter(|(doc, hash)| in_rollout(prompt_id, doc, hash, caller))
                .map(|(doc, hash)| (doc, hash.as_str())),
        ),
        Err(error) => {
            tracing::warn!(%error, prompt_id, "prompt overrides unavailable; using the code prompt");
            layered(locked, base_version, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_override_layers_after_the_locked_prompt_and_changes_the_version() {
        let doc = json!({
            "prompt": "record.summarize",
            "sections": [ { "name": "tone", "text": "Write for {{audience}}." } ],
            "slots": { "audience": { "type": "choice", "values": ["staff", "customers"], "trusted": true } }
        });
        let out = layered(
            "LOCKED RULES",
            "record.summarize/v2",
            Some((&doc, "1a2b3c4d5e6f")),
        );
        assert!(out.system.starts_with("LOCKED RULES"));
        assert!(out.system.ends_with("Write for staff."));
        assert_eq!(out.version, "record.summarize/v2+o:1a2b3c4d");
        let none = layered("LOCKED RULES", "record.summarize/v2", None);
        assert_eq!(none.system, "LOCKED RULES");
        assert_eq!(none.version, "record.summarize/v2");
    }

    #[test]
    fn a_rollout_reaches_about_its_share_and_is_stable() {
        let doc = json!({ "rollout": { "share": 20 } });
        let callers: Vec<String> = (0..2000).map(|i| format!("user-{i}")).collect();
        let reached = callers
            .iter()
            .filter(|c| in_rollout("record.summarize", &doc, "h1", c))
            .count();
        assert!(
            (300..=500).contains(&reached),
            "{reached} of 2000 for a 20% share"
        );
        assert_eq!(
            in_rollout("record.summarize", &doc, "h1", "user-7"),
            in_rollout("record.summarize", &doc, "h1", "user-7")
        );
        assert!(
            in_rollout("p", &json!({}), "h", "anyone"),
            "no rollout: everyone"
        );
        assert!(in_rollout(
            "p",
            &json!({ "rollout": { "share": 100 } }),
            "h",
            "x"
        ));
    }

    #[test]
    fn a_default_wins_over_the_first_choice() {
        let doc = json!({ "slots": {
            "a": { "values": ["x", "y"], "default": "y" },
            "b": { "values": ["p"] },
            "c": { "type": "text" }
        } });
        let values = slot_defaults(&doc);
        assert_eq!(values.get("a").map(String::as_str), Some("y"));
        assert_eq!(values.get("b").map(String::as_str), Some("p"));
        assert!(!values.contains_key("c"));
    }
}

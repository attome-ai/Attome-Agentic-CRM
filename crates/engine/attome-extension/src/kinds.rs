//! M17-T1: extensions that are not record hooks. A **job** extension runs as
//! a Z7 job (`on_job`), a **webhook** extension handles an inbound hook's
//! event after the hook's signature checks (`on_webhook`). Both are called
//! through the same JSON convention as a hook and answer the records they
//! want written:
//!
//! ```json
//! { "records": [
//!     { "entity": "order", "values": { "number": "o-9", "total": 120 } },
//!     { "entity": "account", "id": "…", "values": { "status": "active" } } ] }
//! ```
//!
//! (`"continue"` writes nothing.) The server makes each write as the run's
//! user through the generic write path, after [`check_writes`] holds every
//! one to the extension's grants: a module never writes anything itself.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::grants::Grants;

/// The export a job extension implements.
pub const JOB_EXPORT: &str = "on_job";
/// The export a webhook extension implements.
pub const WEBHOOK_EXPORT: &str = "on_webhook";
/// The most writes one answer may ask for.
pub const MAX_WRITES: usize = 100;

/// One record a job or webhook asks the server to write: a create without
/// `id`, an update of that record with it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordWrite {
    pub entity: String,
    #[serde(default)]
    pub id: Option<String>,
    pub values: Map<String, Value>,
}

/// What a job or webhook extension answered.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct KindAnswer {
    pub records: Vec<RecordWrite>,
}

/// The answer in a module's output: `"continue"` or `{"records": [...]}`.
/// Pure.
pub fn parse_answer(out: &[u8]) -> Result<KindAnswer, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Records {
        records: Vec<RecordWrite>,
    }
    let value: Value =
        serde_json::from_slice(out).map_err(|e| format!("the answer is not JSON: {e}"))?;
    if value.as_str() == Some("continue") {
        return Ok(KindAnswer::default());
    }
    serde_json::from_value::<Records>(value)
        .map(|r| KindAnswer { records: r.records })
        .map_err(|e| format!("the answer is not continue or a records list: {e}"))
}

/// Every write held to the grants: at most [`MAX_WRITES`], each entity and
/// attribute granted for writing. Pure.
pub fn check_writes(grants: &Grants, answer: &KindAnswer) -> Result<(), String> {
    if answer.records.len() > MAX_WRITES {
        return Err(format!("an answer writes at most {MAX_WRITES} records"));
    }
    for (i, write) in answer.records.iter().enumerate() {
        if write.values.is_empty() {
            return Err(format!("records[{i}] has no values"));
        }
        let keys: Vec<&str> = write.values.keys().map(String::as_str).collect();
        grants
            .may_write(&write.entity, &keys)
            .map_err(|denied| format!("records[{i}]: {denied}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn job_webhook_kinds_answers_are_held_to_grants() {
        let grants: Grants = serde_json::from_value(json!({
            "entities": { "order": { "read": true, "write": true, "attributes": ["number", "total"] } }
        }))
        .unwrap();
        assert_eq!(parse_answer(b"\"continue\""), Ok(KindAnswer::default()));
        let answer = parse_answer(
            br#"{"records": [{"entity": "order", "values": {"number": "o-9", "total": 120}}]}"#,
        )
        .unwrap();
        assert_eq!(answer.records.len(), 1);
        assert_eq!(check_writes(&grants, &answer), Ok(()));

        let ungranted = parse_answer(
            br#"{"records": [{"entity": "order", "id": "x", "values": {"discount": 50}}]}"#,
        )
        .unwrap();
        assert_eq!(
            check_writes(&grants, &ungranted),
            Err("records[0]: the extension may not use order.discount".into())
        );
        let elsewhere =
            parse_answer(br#"{"records": [{"entity": "invoice", "values": {"n": 1}}]}"#).unwrap();
        assert!(check_writes(&grants, &elsewhere).is_err());
        assert!(parse_answer(br#"{"records": [], "extra": 1}"#).is_err());
        assert!(parse_answer(b"not json").is_err());
    }
}

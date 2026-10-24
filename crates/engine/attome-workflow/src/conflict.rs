//! A16-T5: what an `update_record` node does when the record changed under
//! it (a `version_conflict`). Its `config.on_conflict` names the rule:
//!
//! - `retry_fresh` (the default): read the record again and apply the node's
//!   changes to it, up to [`MAX_ATTEMPTS`] attempts in all.
//! - `merge`: write over the version the run saw (the trigger record's
//!   `row_version`, or one the node's input carries); when the versions it
//!   missed changed none of the attributes the node writes, apply them over
//!   the current version (A16-T2's rule, `If-Match-Merge` for a flow);
//!   otherwise stop.
//! - `stop`: write over the version the run saw and fail the node on a
//!   conflict, with the A16-T1 conflict body.
//! - `ask_person`: write over the version the run saw; on a conflict, open
//!   an approval request carrying the conflict and wait. Approved, the node
//!   applies its changes over the record as it is then; declined, it fails.
//!
//! The rule is a pure decision ([`after_conflict`]) so it is tested without a
//! database; the scheduler does the reading and writing.

use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The most write attempts `retry_fresh` makes, the first included.
pub const MAX_ATTEMPTS: usize = 3;

/// The approval action type an `ask_person` conflict opens.
pub const CONFLICT_ACTION_TYPE: &str = "workflow.conflict";

/// An `update_record` node's conflict rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    RetryFresh,
    Merge,
    Stop,
    AskPerson,
}

impl OnConflict {
    /// From the node's `config.on_conflict`; absent is `retry_fresh`.
    pub fn from_config(value: Option<&Value>) -> Result<Self, AppError> {
        match value {
            None | Some(Value::Null) => Ok(Self::RetryFresh),
            Some(Value::String(s)) => Self::parse(s).ok_or_else(|| invalid(s)),
            Some(other) => Err(invalid(&other.to_string())),
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "retry_fresh" => Self::RetryFresh,
            "merge" => Self::Merge,
            "stop" => Self::Stop,
            "ask_person" => Self::AskPerson,
            _ => return None,
        })
    }

    /// Whether the first write goes over the version the run saw (else the
    /// version read just before writing).
    pub fn writes_over_seen_version(self) -> bool {
        !matches!(self, Self::RetryFresh)
    }
}

fn invalid(value: &str) -> AppError {
    AppError::Validation(format!(
        "update_record on_conflict must be retry_fresh, merge, stop or ask_person, not {value}"
    ))
}

/// What the versions after the one written over changed, for `merge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeCheck {
    /// The record's row version now.
    pub current_version: i64,
    /// Whether they changed an attribute the node writes.
    pub overlaps: bool,
}

/// The next step after attempt number `attempt` (1-based) hit a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictStep {
    /// Read the record again and write once more.
    Retry,
    /// Write once more over this version.
    MergeAt(i64),
    /// Fail the node with the conflict.
    Stop,
    /// Open an approval request with the conflict and wait.
    AskPerson,
}

/// The rule's decision. `merge` is `None` when no merge was tried or the
/// record's history cannot account for the versions missed (A16-T2), and a
/// merge happens at most once: a conflict on the merged write stops.
pub fn after_conflict(
    rule: OnConflict,
    attempt: usize,
    merge: Option<&MergeCheck>,
    merged_already: bool,
) -> ConflictStep {
    match rule {
        OnConflict::RetryFresh if attempt < MAX_ATTEMPTS => ConflictStep::Retry,
        OnConflict::RetryFresh | OnConflict::Stop => ConflictStep::Stop,
        OnConflict::Merge => match merge {
            Some(check) if !check.overlaps && !merged_already => {
                ConflictStep::MergeAt(check.current_version)
            }
            _ => ConflictStep::Stop,
        },
        OnConflict::AskPerson => ConflictStep::AskPerson,
    }
}

/// The version of `record_id` the run saw: the `row_version` the node's
/// input carries (`row_version`, or `record.row_version` of the same record),
/// else the trigger record's (`record.row_version` in the run's context, when
/// it is the same record). `None` when the run never saw one.
pub fn seen_version(input: &Value, context: &Value, record_id: Uuid) -> Option<i64> {
    if let Some(v) = input.get("row_version").and_then(Value::as_i64) {
        return Some(v);
    }
    let same_record = |record: &Value| {
        record
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            == Some(record_id)
    };
    [input.get("record"), context.get("record")]
        .into_iter()
        .flatten()
        .find(|record| same_record(record))
        .and_then(|record| record.get("row_version"))
        .and_then(Value::as_i64)
}

/// The decision a person made on an `ask_person` conflict, when this node
/// is resuming from one: the scheduler records `{decision,
/// approval_request_id}` as the node's output when the request settles.
pub fn conflict_decision(node_output: Option<&Value>) -> Option<&str> {
    let output = node_output?;
    output.get("approval_request_id")?;
    output.get("decision").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn on_conflict_retry_fresh_retries_then_stops() {
        assert_eq!(
            OnConflict::from_config(None).unwrap(),
            OnConflict::RetryFresh
        );
        let rule = OnConflict::RetryFresh;
        assert!(!rule.writes_over_seen_version());
        assert_eq!(after_conflict(rule, 1, None, false), ConflictStep::Retry);
        assert_eq!(after_conflict(rule, 2, None, false), ConflictStep::Retry);
        assert_eq!(
            after_conflict(rule, MAX_ATTEMPTS, None, false),
            ConflictStep::Stop
        );
    }

    #[test]
    fn on_conflict_merge_applies_over_untouched_attributes_once() {
        let rule = OnConflict::from_config(Some(&json!("merge"))).unwrap();
        assert!(rule.writes_over_seen_version());
        let clean = MergeCheck {
            current_version: 9,
            overlaps: false,
        };
        assert_eq!(
            after_conflict(rule, 1, Some(&clean), false),
            ConflictStep::MergeAt(9)
        );
        // A conflict on the merged write, an overlap, or no basis stops.
        assert_eq!(
            after_conflict(rule, 2, Some(&clean), true),
            ConflictStep::Stop
        );
        let overlap = MergeCheck {
            current_version: 9,
            overlaps: true,
        };
        assert_eq!(
            after_conflict(rule, 1, Some(&overlap), false),
            ConflictStep::Stop
        );
        assert_eq!(after_conflict(rule, 1, None, false), ConflictStep::Stop);
    }

    #[test]
    fn on_conflict_stop_and_ask_person() {
        let stop = OnConflict::from_config(Some(&json!("stop"))).unwrap();
        assert_eq!(after_conflict(stop, 1, None, false), ConflictStep::Stop);
        let ask = OnConflict::from_config(Some(&json!("ask_person"))).unwrap();
        assert_eq!(after_conflict(ask, 1, None, false), ConflictStep::AskPerson);
        for bad in [json!("overwrite"), json!(3)] {
            assert!(matches!(
                OnConflict::from_config(Some(&bad)),
                Err(AppError::Validation(_))
            ));
        }
    }

    #[test]
    fn on_conflict_seen_version_and_decision() {
        let id = Uuid::from_u128(4);
        let context = json!({"record": {"id": id.to_string(), "row_version": 5}});
        assert_eq!(seen_version(&json!({}), &context, id), Some(5));
        assert_eq!(
            seen_version(&json!({"row_version": 7}), &context, id),
            Some(7)
        );
        // Another record's version is not this one's.
        assert_eq!(seen_version(&json!({}), &context, Uuid::from_u128(5)), None);

        let resumed = json!({"decision": "approved", "approval_request_id": Uuid::nil()});
        assert_eq!(conflict_decision(Some(&resumed)), Some("approved"));
        assert_eq!(conflict_decision(Some(&json!({"id": id}))), None);
        assert_eq!(conflict_decision(None), None);
    }
}

//! Z14-T6: the standard per-item result of a batch, and the warnings a
//! response may carry.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Why one item of a batch did not apply: a stable machine-readable `code`
/// (the same codes as `ErrorResponse.code` where one fits, e.g.
/// `version_conflict`), English `message`, and an optional `detail` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Problem {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub detail: Option<Value>,
}

/// One item of a batch, by its zero-based `index` in the request: `ok` when
/// it applied, `problem` when it did not, and neither while it has not run
/// yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ItemResult<T> {
    pub index: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<Problem>,
}

impl<T> ItemResult<T> {
    pub fn ok(index: i64, value: T) -> Self {
        Self {
            index,
            ok: Some(value),
            problem: None,
        }
    }

    pub fn problem(index: i64, problem: Problem) -> Self {
        Self {
            index,
            ok: None,
            problem: Some(problem),
        }
    }

    pub fn pending(index: i64) -> Self {
        Self {
            index,
            ok: None,
            problem: None,
        }
    }
}

/// The per-item results of a batch, in request order (Z14-T6). Every bulk
/// response reports its items through this shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BatchResult<T> {
    pub items: Vec<ItemResult<T>>,
}

impl<T> BatchResult<T> {
    /// How many items applied.
    pub fn succeeded(&self) -> usize {
        self.items.iter().filter(|item| item.ok.is_some()).count()
    }

    /// How many items did not apply.
    pub fn failed(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.problem.is_some())
            .count()
    }
}

/// Something the server did that the caller should know about though the
/// request succeeded (a value truncated, a default applied, a page clamped):
/// a stable `code` and English `message`. Sent only when there is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn batch_result_items_carry_ok_or_problem_by_index() {
        let batch = BatchResult {
            items: vec![
                ItemResult::ok(0, json!({"id": "a"})),
                ItemResult::problem(
                    1,
                    Problem {
                        code: "version_conflict".to_owned(),
                        message: "the record changed".to_owned(),
                        detail: Some(json!({"current_version": 4})),
                    },
                ),
                ItemResult::pending(2),
            ],
        };
        assert_eq!(batch.succeeded(), 1);
        assert_eq!(batch.failed(), 1);
        let wire = serde_json::to_value(&batch).expect("serialize");
        assert_eq!(
            wire,
            json!({"items": [
                {"index": 0, "ok": {"id": "a"}},
                {"index": 1, "problem": {
                    "code": "version_conflict",
                    "message": "the record changed",
                    "detail": {"current_version": 4}
                }},
                {"index": 2}
            ]})
        );
        let back: BatchResult<serde_json::Value> = serde_json::from_value(wire).expect("parse");
        assert_eq!(back, batch);
    }

    #[test]
    fn batch_result_warnings_are_omitted_when_empty() {
        let page = crate::PaginatedResponse::<i32> {
            items: vec![1],
            total: 1,
            page: 1,
            page_size: 1,
            warnings: Vec::new(),
        };
        let wire = serde_json::to_value(&page).expect("serialize");
        assert!(wire.get("warnings").is_none(), "{wire}");
        let warned = crate::PaginatedResponse::<i32> {
            warnings: vec![Warning {
                code: "page_size_clamped".to_owned(),
                message: "page_size was lowered to 100".to_owned(),
            }],
            ..page
        };
        let wire = serde_json::to_value(&warned).expect("serialize");
        assert_eq!(wire["warnings"][0]["code"], "page_size_clamped");
        let back: crate::PaginatedResponse<i32> =
            serde_json::from_value(json!({"items": [], "total": 0, "page": 1, "page_size": 1}))
                .expect("a body without warnings still parses");
        assert!(back.warnings.is_empty());
    }
}

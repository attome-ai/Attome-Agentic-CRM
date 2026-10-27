//! The one catalogue of error codes the API answers with (roadmap Z14-T2):
//! every `error` value an [`crate::AppError`] response can carry, what it
//! means and whether the same request may succeed when retried unchanged.
//! The OpenAPI document publishes it as the `ErrorCode` enum, so the SDK
//! knows every code; a test checks that every variant's code is listed, once.

/// One error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode {
    pub code: &'static str,
    pub description: &'static str,
    /// Whether retrying the same request later may succeed.
    pub retryable: bool,
}

const fn code(code: &'static str, description: &'static str, retryable: bool) -> ErrorCode {
    ErrorCode {
        code,
        description,
        retryable,
    }
}

/// Every error code, in a stable order.
pub const ERROR_CODES: &[ErrorCode] = &[
    code(
        "not_found",
        "No such resource, or the caller may not see it.",
        false,
    ),
    code("unauthorized", "Missing or invalid credentials.", false),
    code(
        "forbidden",
        "The caller lacks the privilege for this action.",
        false,
    ),
    code(
        "attribute_not_writable",
        "The write sets an attribute the caller may not write; `field` names it.",
        false,
    ),
    code(
        "limit_exceeded",
        "The request is past a limit; `limit`, `value` and `next` say which and what to do.",
        false,
    ),
    code(
        "conflict",
        "The request conflicts with the current state.",
        false,
    ),
    code(
        "version_conflict",
        "The record changed since the caller read it; read it again and retry.",
        false,
    ),
    code(
        "duplicate_detected",
        "The save matches existing records under a blocking duplicate rule.",
        false,
    ),
    code(
        "idempotency_conflict",
        "The idempotency key was used for a different request.",
        false,
    ),
    code("validation_error", "The request failed validation.", false),
    code(
        "customer_tests_failed",
        "A publish was refused because blocking customer tests failed; `tests` names them.",
        false,
    ),
    code(
        "rule_violation",
        "A business rule refused the write; `rule_id` names it.",
        false,
    ),
    code(
        "field_locked",
        "A business rule locks a field the write changed.",
        false,
    ),
    code(
        "field_locked_required",
        "A locked field is required and was left empty.",
        false,
    ),
    code(
        "feature_unavailable",
        "The feature is not available on this deployment.",
        false,
    ),
    code(
        "feature_hidden",
        "The feature is switched off for this deployment.",
        false,
    ),
    code(
        "rate_limit_exceeded",
        "Too many requests; wait for `Retry-After`.",
        true,
    ),
    code(
        "overloaded",
        "The server is overloaded; retry shortly.",
        true,
    ),
    code(
        "capability_unavailable",
        "A service the request needs is down; retry after `Retry-After`.",
        true,
    ),
    code(
        "metadata_authoring_locked",
        "Metadata changes are locked on this deployment.",
        false,
    ),
    code(
        "transition_not_allowed",
        "The state model does not allow this change of state.",
        false,
    ),
    code(
        "reauth_required",
        "The action needs a fresh sign-in or second factor first.",
        false,
    ),
    code(
        "server_timeout",
        "The request took too long; it may be retried.",
        true,
    ),
    code(
        "query_timeout",
        "An interactive query ran past its limit; run it as an export.",
        false,
    ),
    code(
        "read_only",
        "Changes are paused on this deployment; reads still work.",
        true,
    ),
    code(
        "payload_too_large",
        "The request body is too large or too deeply nested.",
        false,
    ),
    code(
        "request_rejected",
        "The request was refused before it reached a route: a malformed path or oversized headers.",
        false,
    ),
    code(
        "invalid_cursor",
        "The cursor was not issued by this deployment; start again from the first page.",
        false,
    ),
    code(
        "resync_needed",
        "The delta token is older than the change feed keeps; read the list again for a new token.",
        false,
    ),
    code(
        "cascade_restricted",
        "The delete would cascade to a record a restrict-mode lookup still references; the message names the path.",
        false,
    ),
    code(
        "idempotency_outcome_unknown",
        "An earlier attempt with this key did not finish; its outcome is unknown.",
        false,
    ),
    code(
        "idempotency_replay_unavailable",
        "The stored response for this key can no longer be replayed.",
        false,
    ),
    code(
        "method_not_allowed",
        "The path exists but not for this method; see `Allow`.",
        false,
    ),
    code(
        "api_version_sunset",
        "The API version this request is answered at was retired; `supported` lists the current ones.",
        false,
    ),
    code(
        "unsupported_api_version",
        "The `Attome-Version` header names a version this server does not answer; `supported` lists the ones it does.",
        false,
    ),
    code(
        "internal_error",
        "An unexpected error; the request id finds it in the logs.",
        true,
    ),
];

/// The catalogue entry for `code`.
pub fn lookup(code: &str) -> Option<&'static ErrorCode> {
    ERROR_CODES.iter().find(|c| c.code == code)
}

/// The `ErrorCode` schema: a string enum of every code, each described.
pub fn openapi_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{ObjectBuilder, SchemaType, Type};
    let description = ERROR_CODES
        .iter()
        .map(|c| {
            format!(
                "`{}`{}: {}",
                c.code,
                if c.retryable { " (retryable)" } else { "" },
                c.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ObjectBuilder::new()
        .schema_type(SchemaType::Type(Type::String))
        .enum_values(Some(ERROR_CODES.iter().map(|c| c.code)))
        .description(Some(format!(
            "Every `error` code the API answers with.\n\n{description}"
        )))
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_code_appears_once() {
        let mut seen = HashSet::new();
        for c in ERROR_CODES {
            assert!(seen.insert(c.code), "{} is listed twice", c.code);
            assert!(!c.description.is_empty(), "{} has no description", c.code);
        }
        assert!(lookup("version_conflict").is_some());
        assert!(lookup("no_such_code").is_none());
    }

    #[test]
    fn the_schema_lists_every_code() {
        let json = serde_json::to_value(openapi_schema()).expect("schema");
        let listed = json["enum"].as_array().expect("enum").len();
        assert_eq!(listed, ERROR_CODES.len());
    }
}

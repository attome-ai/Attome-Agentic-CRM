//! Per-call transport metrics (BIN-FX2, plan §5 "Visibility").
//!
//! One latency sample and one outcome count per **call** — an embedding
//! call's D-645 retries are one call, and its outcome is the last attempt's.
//! Every label value is a fixed string from the closed sets below; a model id,
//! a URL or a provider string is never a label, so the series count is
//! bounded by construction.

use std::time::Instant;

use crate::{InferenceError, UpstreamClass};

/// `attome_inference_request_seconds{endpoint,outcome}`.
pub const REQUEST_SECONDS: &str = "attome_inference_request_seconds";
/// `attome_inference_requests_total{endpoint,outcome,class}`.
pub const REQUESTS_TOTAL: &str = "attome_inference_requests_total";

/// The `endpoint` label's values.
pub const ENDPOINTS: &[&str] = &[
    "generation",
    "embedding",
    "models",
    "speech",
    "ocr",
    "rerank",
];
/// The `outcome` label's values.
pub const OUTCOMES: &[&str] = &[
    "ok",
    "timeout",
    "transport",
    "upstream",
    "bad_response",
    "cancelled",
    "breaker_open",
];
/// The `class` label's values; `none` for every outcome but `upstream`.
pub const CLASSES: &[&str] = &[
    "none",
    "unauthorized",
    "forbidden",
    "rate_limited",
    "client_error",
    "server_error",
];

/// `(outcome, class)` for a finished call, or `None` for a refusal that never
/// reached a socket (a configuration error), which is not a model call.
pub(crate) fn labels<T>(
    result: &Result<T, InferenceError>,
) -> Option<(&'static str, &'static str)> {
    let error = match result {
        Ok(_) => return Some(("ok", "none")),
        Err(error) => error,
    };
    Some(match error {
        InferenceError::Timeout(_) => ("timeout", "none"),
        InferenceError::Transport { .. } => ("transport", "none"),
        InferenceError::Upstream { class, .. } => ("upstream", class_label(*class)),
        InferenceError::BadResponse { .. } => ("bad_response", "none"),
        InferenceError::Cancelled(_) => ("cancelled", "none"),
        InferenceError::Unavailable { .. } => ("breaker_open", "none"),
        InferenceError::NotConfigured(_)
        | InferenceError::Misconfigured { .. }
        | InferenceError::BudgetExhausted
        | InferenceError::ExternalProviderForbidden(_) => return None,
    })
}

fn class_label(class: UpstreamClass) -> &'static str {
    match class {
        UpstreamClass::Unauthorized => "unauthorized",
        UpstreamClass::Forbidden => "forbidden",
        UpstreamClass::RateLimited { .. } => "rate_limited",
        UpstreamClass::ClientError => "client_error",
        UpstreamClass::ServerError { .. } => "server_error",
    }
}

/// Records one call. `endpoint` must be one of [`ENDPOINTS`].
pub(crate) fn record<T>(
    endpoint: &'static str,
    started: Instant,
    result: &Result<T, InferenceError>,
) {
    let Some((outcome, class)) = labels(result) else {
        return;
    };
    metrics::histogram!(REQUEST_SECONDS, "endpoint" => endpoint, "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
    metrics::counter!(
        REQUESTS_TOTAL,
        "endpoint" => endpoint,
        "outcome" => outcome,
        "class" => class,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every variant a call can end in maps into the closed sets, and the two
    /// names are namespaced and distinct from `budget`'s.
    #[test]
    fn every_call_outcome_maps_into_the_closed_label_sets() {
        let calls: Vec<Result<(), InferenceError>> = vec![
            Ok(()),
            Err(InferenceError::Timeout("generation")),
            Err(InferenceError::Transport {
                endpoint: "embedding",
                kind: "request failed",
            }),
            Err(InferenceError::BadResponse {
                endpoint: "generation",
                reason: "x",
            }),
            Err(InferenceError::Cancelled("generation")),
            Err(InferenceError::Unavailable {
                endpoint: "generation",
                retry_after_secs: 30,
            }),
            Err(InferenceError::Upstream {
                endpoint: "embedding",
                class: UpstreamClass::Unauthorized,
            }),
            Err(InferenceError::Upstream {
                endpoint: "embedding",
                class: UpstreamClass::Forbidden,
            }),
            Err(InferenceError::Upstream {
                endpoint: "embedding",
                class: UpstreamClass::RateLimited {
                    retry_after: Some(Duration::from_secs(1)),
                },
            }),
            Err(InferenceError::Upstream {
                endpoint: "embedding",
                class: UpstreamClass::ClientError,
            }),
            Err(InferenceError::Upstream {
                endpoint: "embedding",
                class: UpstreamClass::ServerError { retryable: true },
            }),
        ];
        let mut outcomes = std::collections::HashSet::new();
        let mut classes = std::collections::HashSet::new();
        for call in &calls {
            let (outcome, class) = labels(call).expect("a call outcome is recorded");
            assert!(OUTCOMES.contains(&outcome), "{outcome}");
            assert!(CLASSES.contains(&class), "{class}");
            assert_eq!(outcome == "upstream", class != "none", "{outcome}/{class}");
            outcomes.insert(outcome);
            classes.insert(class);
        }
        assert_eq!(outcomes.len(), OUTCOMES.len(), "every outcome is reachable");
        assert_eq!(classes.len(), CLASSES.len(), "every class is reachable");

        let refusal: Result<(), InferenceError> = Err(InferenceError::NotConfigured("generation"));
        assert_eq!(labels(&refusal), None, "a refusal never dialled anything");

        for name in [REQUEST_SECONDS, REQUESTS_TOTAL] {
            assert!(name.starts_with("attome_inference_"), "{name}");
            assert_ne!(name, crate::budget::TOKENS_TOTAL);
            assert_ne!(name, crate::budget::BUDGET_REJECTED_TOTAL);
        }
    }
}

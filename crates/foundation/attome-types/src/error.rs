use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("conflict: {0}")]
    Conflict(&'static str),

    #[error("version conflict")]
    VersionConflict,

    /// BTY-16c (P-error-response (d)): a version conflict that also answers
    /// *what* the server currently holds, so a caller can reconcile instead
    /// of guessing what the winner wrote. Shares `version_conflict` with
    /// `VersionConflict` as a declared alias (BTY-D6) — that variant's 52
    /// references are untouched. `current_state` must already be filtered
    /// through the engine's sensitivity rules before a caller constructs
    /// this: the filter test in `xrm_entity_engine` is the precondition the
    /// attome-server plan names for BTY-16c callers.
    #[error("version conflict")]
    VersionConflictAt {
        current_version: i64,
        current_state: serde_json::Value,
    },

    /// P-idempotency-hardening §4.2/§9 — distinguishable from `Conflict`'s
    /// generic `code` so a client (or an operator reading logs) can tell
    /// "your retry raced with another in-flight attempt" (`Conflict`, e.g.
    /// idempotency's own "duplicate request already in progress") apart from
    /// "you reused an idempotency key for a materially different request"
    /// (this variant). A new variant rather than adding a `reason` field to
    /// `Conflict` — the latter would require touching every existing
    /// `AppError::Conflict(...)` call site across the workspace to keep
    /// compiling; this is a pure addition.
    #[error("idempotency conflict: {0}")]
    IdempotencyConflict(&'static str),

    #[error("validation error: {0}")]
    Validation(String),

    /// A validation failure that carries *every* bad field in one response
    /// (BTY-16b, P-error-response (c)), so a form renders them all at once
    /// instead of discovering them one 422 at a time. Shares
    /// `validation_error` with `Validation(String)` as a **declared alias**
    /// (BTY-D6) rather than publishing a second code: a client that already
    /// handles `validation_error` needs no change, and `details` carries the
    /// structure. `Validation(String)`'s 1,000-odd call sites are untouched.
    #[error("validation error: {} field(s) failed", .0.len())]
    FieldValidation(Vec<crate::types::FieldError>),

    /// A feature this deployment has switched off outright — **permanent for
    /// the configuration it describes**, never a transient outage, so a
    /// generic retry policy must not back off and retry it. It stays
    /// distinguishable from the two *transient* 503s by its
    /// `feature_unavailable` code alone: `Overloaded` is the node shedding
    /// writes under load, `CapabilityUnavailable` is a named dependency that
    /// is down right now.
    ///
    /// Raisers today: `attome_email::SendError::Disabled` (mail is off in
    /// config), `crates/server/src/auth/local.rs` (local password auth is
    /// off), `xrm_security::mfa` (MFA is not available on this deployment), and
    /// the `xrm_portal` routes whose feature flag is off.
    ///
    /// Stays 503 (BTY-D4): moving it to 403/501 would be a wire change across
    /// the SDK and D-499's status table for no consumer that needs one.
    #[error("feature unavailable")]
    FeatureUnavailable,

    /// D-279 (P-license-enforcement-hardening Phase 2, Option 1) — honest
    /// 403 naming the unlicensed module, not a stealth 404: this deployment
    /// model is single-tenant/on-premise (D-002), so there's no multi-tenant
    /// traffic for stealth to protect, and an unnamed 404 was a real,
    /// ongoing support cost for enterprise API integrators.
    #[error("module '{0}' is not included in your license")]
    FeatureHidden(String),

    #[error("rate limit exceeded")]
    TooManyRequests {
        /// BTY-11 — how long the caller should wait, when the limiter knows its
        /// window. `None` means "no hint available", which is why the body field
        /// and the `Retry-After` header are both driven from this one value:
        /// a client reading either gets the same number, and neither invents one.
        retry_after_secs: Option<u64>,
    },

    /// P-audit-chain-hardening item (e) — a mutating request rejected by a
    /// circuit breaker (e.g. the audit-ingest backlog gate), distinct from
    /// `TooManyRequests` (a per-client rate limit) and `FeatureUnavailable`
    /// (a license/module gate): this is "the system is protecting itself,
    /// retry later," not "you personally are being throttled" or "you never
    /// had access." `&'static str` names which breaker tripped, for logs —
    /// never included in the client-facing message (see `into_response`).
    #[error("service overloaded: {0}")]
    Overloaded(&'static str),

    /// D-344 (amends D-167) — this route's work cannot durably complete
    /// because a named dependency is confirmed unavailable on this node
    /// (`attome_server::capability`). Distinct from every neighbour above:
    /// `Overloaded` is the system throttling itself under load,
    /// `FeatureUnavailable`/`FeatureHidden` are licensing/configuration
    /// answers that no amount of waiting changes, and `Internal` would hide
    /// an operationally actionable state behind a masked 500. This is
    /// "everything about your request is fine, come back when the relay/
    /// object store/worker is back."
    ///
    /// The capability name **is** returned to the client, unlike
    /// `Overloaded`'s breaker name: it is the same operational state D-167
    /// already publishes unauthenticated on `/health/dependencies`, so there
    /// is nothing to protect, and an API integrator seeing a bare 503 has no
    /// way to tell a transient dependency outage from a bug. Same honesty
    /// trade-off D-279 made for `FeatureHidden` in this single-tenant,
    /// on-premise deployment model (D-002).
    #[error("capability '{0}' is unavailable")]
    CapabilityUnavailable(&'static str),

    /// P-environment-promotion Phase 0 — a metadata-authoring write refused
    /// because this deployment runs `app.deployment_profile = "production"`
    /// (`attome_server::middleware::authoring_gate`). Its own variant rather
    /// than `Forbidden`: a client/operator must be able to tell "you lack the
    /// privilege" (`forbidden`, fixable by a grant) from "nobody authors
    /// here — promote a bundle, or open an approved break-glass window"
    /// (this, fixable only by process) by the stable `error` code alone.
    /// Same 403 status as `FeatureHidden`, same reasoning for being honest
    /// about the reason (D-279, single-tenant on-premise, D-002).
    #[error("metadata authoring is disabled on the production profile; promote a bundle instead")]
    AuthoringLocked,

    /// D-406 (xrm-state Phase 1) — a write to a state-bound field named a
    /// target value with no configured `xrm_core_state_transition` from the
    /// record's current value (or, on create, a value other than the
    /// model's `initial_state`). Distinct from generic `Validation` so a
    /// caller can render "pick a different target state" rather than a
    /// generic form error, and so a raw `PATCH` and `POST .../transition`
    /// surface the identical, distinguishable 422 code — see
    /// `xrm_foundation::state_registry`.
    #[error("no transition is configured for this state change: {0}")]
    TransitionNotAllowed(String),

    /// M45 Phase 2 (D-472) — a `kind = validation` (or `requirement`, Phase 4)
    /// `xrm_core_rule` expression evaluated to a failing result for
    /// `severity = "error"`. Distinct from generic `Validation` so a caller
    /// can identify exactly which rule fired (`rule_id`) without parsing
    /// prose out of the message — same reasoning D-406's
    /// `TransitionNotAllowed` used for the identical problem. `into_response`
    /// below adds a top-level `"rule_id"` to the JSON body as a pure
    /// addition; every other variant's response shape is unchanged.
    ///
    /// D-789: a business rule's blocking `error` policies raise this too; then
    /// `details` names every one that fired (`details.rules`) and the first
    /// one's field (`details.field`). `None` keeps the pre-D-789 body.
    #[error("rule violation: {message}")]
    RuleViolation {
        rule_id: uuid::Uuid,
        message: String,
        details: Option<crate::types::RuleViolationDetails>,
    },

    /// D-789 §3.4/§3.5 — a business rule locks (`hidden`/`disabled`) a field
    /// for this writer: either the write changes it (`required == false`,
    /// code `field_locked`), or it is required and left empty
    /// (`required == true`, code `field_locked_required`). `locks` is never
    /// empty; the first is echoed at the top level (`field`, `rule_id`,
    /// `rule_name`, `effect`) and all are in `details.fields`. No value is
    /// echoed. A structured variant rather than an overload of `Validation`,
    /// the D-406/D-472 precedent.
    #[error("{}", field_locked_message(.locks, *.required))]
    FieldLocked {
        locks: Vec<crate::types::LockedField>,
        required: bool,
    },

    /// D-510 rule 6 — a sensitive operation needs a fresh step-up the
    /// caller's session does not hold. A 401 with its own code rather than
    /// `Unauthorized`, so a client never treats it as an expired session:
    /// refreshing does not help, re-authenticating does. `into_response` adds
    /// top-level `"operation"` and `"acceptable_factors"` to the JSON body, as
    /// `RuleViolation` adds `rule_id`.
    #[error("re-authentication is required for this operation")]
    ReauthRequired {
        operation: &'static str,
        acceptable_factors: Vec<&'static str>,
    },

    /// The request outlived `app.request_timeout_secs` and the server stopped
    /// executing it (`attome_server::app::apply_outer_layers`). A 503, not 408:
    /// 408 means the *client* was slow to send its request. Deliberately says
    /// nothing about whether a write happened — work may have committed before
    /// the deadline, so a caller must not treat this as "not applied".
    #[error("the request exceeded the server's processing time limit")]
    ServerTimeout,

    /// The request body exceeds `app.max_body_size_bytes`. Raised by
    /// `attome_server`'s Content-Length guard before any handler runs, or by the
    /// idempotency gate while it buffers the body before acquiring its key —
    /// in both places nothing has been written.
    #[error("the request body exceeds the configured size limit")]
    PayloadTooLarge,

    /// A same-key retry of an earlier request whose outcome the server cannot
    /// know: it timed out, panicked, lost its client mid-request, or failed
    /// with an error that may have followed a write. The server will not run
    /// it again under this key. The caller should check the resource's state
    /// and, if needed, retry with a new idempotency key.
    #[error(
        "the outcome of the earlier request with this idempotency key is unknown; check the \
         resource and retry with a new key if needed"
    )]
    IdempotencyOutcomeUnknown,

    /// A same-key retry of an earlier request that completed, but whose
    /// response was too large to store for replay.
    #[error(
        "the earlier request with this idempotency key completed, but its response is too \
         large to replay"
    )]
    IdempotencyReplayUnavailable,

    /// attome-server plan A5 (BSV-F09) — the path exists but not for this
    /// method. axum's own 405 is a bare status; routing it through this
    /// variant gives it the envelope and `request_id` every other error has.
    /// Additive (D-438): no existing response changes code.
    #[error("method not allowed")]
    MethodNotAllowed,

    #[error("internal error")]
    Internal(String),
}

/// The client-facing message of [`AppError::FieldLocked`]: names the first
/// field and rule, never a value.
fn field_locked_message(locks: &[crate::types::LockedField], required: bool) -> String {
    let Some(first) = locks.first() else {
        return "a business rule locks a field of this record".to_owned();
    };
    let more = match locks.len() {
        1 => String::new(),
        n => format!(" ({} more field(s) locked)", n - 1),
    };
    if required {
        format!(
            "'{}' is required but the rule '{}' locks it for your role{more}",
            first.field, first.rule_name
        )
    } else {
        format!(
            "'{}' is locked by the rule '{}' and cannot be changed{more}",
            first.field, first.rule_name
        )
    }
}

impl AppError {
    /// Convenience constructor for the masked 500. The detail is masked from
    /// the client but must still be diagnosable, so it is emitted at `error`
    /// exactly once at the response boundary, where every `Internal` —
    /// including one built directly as a variant — passes; see
    /// `into_response`. The construction site is recorded here at
    /// `debug`, so the call chain that produced the failure is available
    /// without logging the detail twice on the normal path.
    #[track_caller]
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::debug!(
            caller = %std::panic::Location::caller(),
            "internal error constructed"
        );
        AppError::Internal(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::VersionConflict => (StatusCode::CONFLICT, "version_conflict"),
            AppError::VersionConflictAt { .. } => (StatusCode::CONFLICT, "version_conflict"),
            AppError::IdempotencyConflict(_) => (StatusCode::CONFLICT, "idempotency_conflict"),
            AppError::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            AppError::FieldValidation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error"),
            AppError::FeatureUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "feature_unavailable")
            }
            AppError::FeatureHidden(_) => (StatusCode::FORBIDDEN, "feature_hidden"),
            AppError::TooManyRequests { .. } => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
            }
            AppError::Overloaded(_) => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
            AppError::CapabilityUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "capability_unavailable")
            }
            AppError::AuthoringLocked => (StatusCode::FORBIDDEN, "metadata_authoring_locked"),
            AppError::TransitionNotAllowed(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "transition_not_allowed")
            }
            AppError::RuleViolation { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "rule_violation"),
            AppError::FieldLocked {
                required: false, ..
            } => (StatusCode::UNPROCESSABLE_ENTITY, "field_locked"),
            AppError::FieldLocked { required: true, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, "field_locked_required")
            }
            AppError::ReauthRequired { .. } => (StatusCode::UNAUTHORIZED, "reauth_required"),
            AppError::ServerTimeout => (StatusCode::SERVICE_UNAVAILABLE, "server_timeout"),
            AppError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            AppError::IdempotencyOutcomeUnknown => {
                (StatusCode::CONFLICT, "idempotency_outcome_unknown")
            }
            AppError::IdempotencyReplayUnavailable => {
                (StatusCode::CONFLICT, "idempotency_replay_unavailable")
            }
            AppError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        // Never expose internal details to the client
        let message = match &self {
            AppError::Internal(_) => "an internal error occurred".to_string(),
            // The breaker name is operator-facing (it's logged separately by
            // whoever raises this), not for the client — same masking
            // posture as Internal, just with a fixed generic message instead
            // of a blanket "internal error occurred".
            AppError::Overloaded(_) => {
                "the service is temporarily unable to accept this request, try again shortly"
                    .to_string()
            }
            other => other.to_string(),
        };

        // BTY-5 (S4): every masked 500 must be diagnosable, and this is the
        // one sink every `Internal` reaches — whether it was built through
        // `AppError::internal` or as a bare variant — so the real detail is
        // logged exactly once per response (correlated by attome-server's
        // request_id span) and still never reaches the client.
        if let AppError::Internal(detail) = &self {
            tracing::error!(detail = %detail, "internal error");
        }

        let mut body = json!({ "error": code, "message": message });
        if let AppError::RuleViolation {
            rule_id, details, ..
        } = &self
        {
            body["rule_id"] = json!(rule_id);
            if let Some(details) = details {
                body["details"] = json!(details);
            }
        }
        if let AppError::FieldLocked { locks, .. } = &self {
            if let Some(first) = locks.first() {
                body["field"] = json!(first.field);
                body["rule_id"] = json!(first.rule_id);
                body["rule_name"] = json!(first.rule_name);
                body["effect"] = json!(first.effect);
            }
            body["details"] = json!({ "fields": locks });
        }
        if let AppError::ReauthRequired {
            operation,
            acceptable_factors,
        } = &self
        {
            body["operation"] = json!(operation);
            body["acceptable_factors"] = json!(acceptable_factors);
        }
        if let AppError::FieldValidation(details) = &self {
            body["details"] = json!(details);
        }
        if let AppError::VersionConflictAt {
            current_version,
            current_state,
        } = &self
        {
            body["current_version"] = json!(current_version);
            body["current_state"] = json!(current_state);
        }

        // BTY-11 (the 429 hint): one value drives both surfaces. RFC 9110 allows
        // `Retry-After` in seconds, and the body carries the same number for
        // clients that only parse JSON.
        let retry_after = match &self {
            AppError::TooManyRequests { retry_after_secs } => *retry_after_secs,
            _ => None,
        };
        if let Some(secs) = retry_after {
            body["retry_after_sec"] = json!(secs);
        }

        let mut resp = (status, Json(body)).into_response();
        if let Some(value) =
            retry_after.and_then(|secs| axum::http::HeaderValue::from_str(&secs.to_string()).ok())
        {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response body must be JSON")
    }

    #[tokio::test]
    async fn not_found_maps_to_404_with_its_error_code() {
        let resp = AppError::NotFound.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "not_found");
        assert_eq!(body["message"], "not found");
    }

    /// BTY-11 — the 429 hint reaches both surfaces from one value, and an
    /// absent hint invents nothing.
    #[tokio::test]
    async fn too_many_requests_carries_its_retry_after_hint() {
        let resp = AppError::TooManyRequests {
            retry_after_secs: Some(30),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("30")),
            "RFC 9110 Retry-After, in seconds"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "rate_limit_exceeded");
        assert_eq!(body["retry_after_sec"], 30);

        let bare = AppError::TooManyRequests {
            retry_after_secs: None,
        }
        .into_response();
        assert_eq!(bare.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            bare.headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_none()
        );
        let body = body_json(bare).await;
        assert!(
            body.get("retry_after_sec").is_none(),
            "no hint must not become a zero"
        );
    }

    #[tokio::test]
    async fn unauthorized_maps_to_401() {
        let resp = AppError::Unauthorized.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "unauthorized");
    }

    #[tokio::test]
    async fn forbidden_maps_to_403() {
        let resp = AppError::Forbidden.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "forbidden");
    }

    #[tokio::test]
    async fn conflict_maps_to_409_and_preserves_its_message() {
        let resp = AppError::Conflict("duplicate key").into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "conflict");
        assert_eq!(body["message"], "conflict: duplicate key");
    }

    #[tokio::test]
    async fn version_conflict_maps_to_409_with_its_own_distinct_code() {
        let resp = AppError::VersionConflict.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "version_conflict");
    }

    /// BTY-16c (P-error-response (d)): a version conflict that also answers
    /// what the server currently holds, under the code clients already handle
    /// for a plain version conflict — and the plain variant keeps its own
    /// unchanged shape.
    #[tokio::test]
    async fn version_conflict_at_maps_to_409_with_current_version_and_state() {
        let resp = AppError::VersionConflictAt {
            current_version: 7,
            current_state: serde_json::json!({ "name": "as stored now" }),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "version_conflict");
        assert_eq!(body["current_version"], 7);
        assert_eq!(body["current_state"]["name"], "as stored now");

        let plain = body_json(AppError::VersionConflict.into_response()).await;
        assert_eq!(plain["error"], "version_conflict");
        assert!(plain.get("current_version").is_none());
        assert!(plain.get("current_state").is_none());
    }

    /// Distinguishes "your retry raced" (`Conflict`) from "you reused an
    /// idempotency key for a different request" — both 409, but a client or
    /// operator needs to tell them apart (P-idempotency-hardening §4.2).
    #[tokio::test]
    async fn idempotency_conflict_maps_to_409_with_its_own_distinct_code() {
        let resp = AppError::IdempotencyConflict("payload mismatch").into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "idempotency_conflict");
        assert_ne!(body["error"], "conflict");
        assert_eq!(body["message"], "idempotency conflict: payload mismatch");
    }

    #[tokio::test]
    async fn validation_maps_to_422_and_preserves_its_message() {
        let resp = AppError::Validation("field is required".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "validation_error");
        assert_eq!(body["message"], "validation error: field is required");
    }

    /// BTY-16b (P-error-response (c)): one 422 carries *every* bad field,
    /// under the code clients already handle for a plain validation failure —
    /// so a form renders all of them at once and an existing client needs no
    /// change to keep working.
    #[tokio::test]
    async fn field_validation_maps_to_422_validation_error_with_details() {
        let resp = AppError::FieldValidation(vec![
            crate::types::FieldError {
                field: "email".to_string(),
                code: "invalid_format".to_string(),
                message: "email is not a valid address".to_string(),
            },
            crate::types::FieldError {
                field: "amount".to_string(),
                code: "must_be_positive".to_string(),
                message: "amount must be greater than zero".to_string(),
            },
        ])
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "validation_error");
        let details = body["details"].as_array().expect("details is an array");
        assert_eq!(
            details.len(),
            2,
            "every field error must be in one response"
        );
        assert_eq!(details[0]["field"], "email");
        assert_eq!(details[0]["code"], "invalid_format");
        assert!(
            details[0]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("email")
        );
        assert_eq!(details[1]["field"], "amount");

        // The plain variant keeps its own shape: the two share a wire code,
        // not a body.
        let plain = body_json(AppError::Validation("x".to_string()).into_response()).await;
        assert!(plain.get("details").is_none());
    }
    #[tokio::test]
    async fn feature_unavailable_maps_to_503() {
        let resp = AppError::FeatureUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "feature_unavailable");
    }

    /// D-279 — honest 403 naming the module, not a stealth 404.
    #[tokio::test]
    async fn feature_hidden_maps_to_403_and_names_the_module() {
        let resp = AppError::FeatureHidden("advanced_audit".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "feature_hidden");
        assert_eq!(
            body["message"],
            "module 'advanced_audit' is not included in your license"
        );
    }

    #[tokio::test]
    async fn too_many_requests_maps_to_429() {
        let resp = AppError::TooManyRequests {
            retry_after_secs: None,
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "rate_limit_exceeded");
    }

    #[tokio::test]
    async fn overloaded_maps_to_503_and_never_leaks_the_breaker_name_to_the_client() {
        let resp = AppError::Overloaded("audit_ingest_backlog").into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "overloaded");
        assert!(!body.to_string().contains("audit_ingest_backlog"));
    }

    /// D-344. The deliberate inverse of the assertion directly above: the
    /// capability name is *meant* to reach the client (see the variant's own
    /// doc comment for why that is not an information leak), and the two
    /// 503s must stay distinguishable by `error` code so a caller can tell
    /// "the whole node is shedding writes" from "this one dependency is
    /// down".
    #[tokio::test]
    async fn capability_unavailable_maps_to_503_and_names_the_capability() {
        let resp = AppError::CapabilityUnavailable("object_storage").into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "capability_unavailable");
        assert_eq!(
            body["message"],
            "capability 'object_storage' is unavailable"
        );
    }

    /// P-environment-promotion Phase 0 — distinct from `forbidden` by code, so
    /// a caller can tell a missing privilege from a profile-level lock.
    #[tokio::test]
    async fn authoring_locked_maps_to_403_with_its_own_distinct_code() {
        let resp = AppError::AuthoringLocked.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "metadata_authoring_locked");
        assert_ne!(body["error"], "forbidden");
        assert_eq!(
            body["message"],
            "metadata authoring is disabled on the production profile; promote a bundle instead"
        );
    }

    /// D-406 — distinct from `validation_error` by code, so `/transition` and
    /// a raw `PATCH` that lands on the same illegal state change can be told
    /// apart from an ordinary field-validation failure by the `error` field
    /// alone.
    #[tokio::test]
    async fn transition_not_allowed_maps_to_422_with_its_own_distinct_code() {
        let resp = AppError::TransitionNotAllowed("no transition from 'draft' to 'closed'".into())
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "transition_not_allowed");
        assert_ne!(body["error"], "validation_error");
        assert_eq!(
            body["message"],
            "no transition is configured for this state change: no transition from 'draft' to 'closed'"
        );
    }

    /// D-510 rule 6 — a 401 with its own code, never `unauthorized`, carrying
    /// the operation and the factors the account can step up with.
    #[tokio::test]
    async fn reauth_required_maps_to_401_and_names_the_operation_and_factors() {
        let resp = AppError::ReauthRequired {
            operation: "api_key_create",
            acceptable_factors: vec!["totp", "recovery_code"],
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "reauth_required");
        assert_ne!(body["error"], "unauthorized");
        assert_eq!(body["operation"], "api_key_create");
        assert_eq!(
            body["acceptable_factors"],
            serde_json::json!(["totp", "recovery_code"])
        );
    }

    /// Base-auth hardening 2.1d — the documented `ReauthRequiredResponse`
    /// schema is exactly the body `into_response` builds: it parses with
    /// unknown fields denied, and a plain `unauthorized` body does not, so the
    /// `UnauthorizedResponse` union a client decodes resolves each to the
    /// right variant.
    #[tokio::test]
    async fn the_reauth_required_body_matches_its_documented_schema() {
        let reauth = body_json(
            AppError::ReauthRequired {
                operation: "identity_link",
                acceptable_factors: vec!["password", "federated"],
            }
            .into_response(),
        )
        .await;
        let parsed: crate::types::ReauthRequiredResponse =
            serde_json::from_value(reauth.clone()).expect("reauth_required body fits its schema");
        assert_eq!(parsed.error, "reauth_required");
        assert_eq!(parsed.operation, "identity_link");
        assert_eq!(parsed.acceptable_factors, vec!["password", "federated"]);
        assert!(matches!(
            serde_json::from_value::<crate::types::UnauthorizedResponse>(reauth).unwrap(),
            crate::types::UnauthorizedResponse::ReauthRequired(_)
        ));

        let plain = body_json(AppError::Unauthorized.into_response()).await;
        assert!(
            serde_json::from_value::<crate::types::ReauthRequiredResponse>(plain.clone()).is_err(),
            "a plain unauthorized body must not read as reauth_required"
        );
        assert!(matches!(
            serde_json::from_value::<crate::types::UnauthorizedResponse>(plain).unwrap(),
            crate::types::UnauthorizedResponse::Unauthorized(_)
        ));
    }

    /// M45 Phase 2 (D-472) — distinct from `validation_error` by code, and
    /// carries a structured `rule_id` the generic `Validation(String)`
    /// variant has no field for, so a client can identify exactly which
    /// `xrm_core_rule` fired without parsing the message text.
    #[tokio::test]
    async fn rule_violation_maps_to_422_and_carries_a_structured_rule_id() {
        let rule_id = uuid::Uuid::now_v7();
        let resp = AppError::RuleViolation {
            rule_id,
            message: "amount must be positive".to_string(),
            details: None,
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "rule_violation");
        assert_ne!(body["error"], "validation_error");
        assert_eq!(body["rule_id"], rule_id.to_string());
        assert_eq!(body["message"], "rule violation: amount must be positive");
        assert!(
            body.get("details").is_none(),
            "no details without a business rule"
        );
    }

    /// D-789: a business rule's violation names every firing rule in
    /// `details.rules` and the first one's field in `details.field`; the body
    /// still reads as an `ErrorResponse`.
    #[tokio::test]
    async fn rule_violation_carries_its_business_rule_details() {
        let first = uuid::Uuid::now_v7();
        let second = uuid::Uuid::now_v7();
        let details = crate::types::RuleViolationDetails {
            field: Some("amount".to_owned()),
            rules: vec![
                crate::types::RuleFailure {
                    rule_id: first,
                    rule_name: "Positive amount".to_owned(),
                    field: Some("amount".to_owned()),
                    message: "amount must be positive".to_owned(),
                },
                crate::types::RuleFailure {
                    rule_id: second,
                    rule_name: "Needs a region".to_owned(),
                    field: None,
                    message: "pick a region".to_owned(),
                },
            ],
        };
        let body = body_json(
            AppError::RuleViolation {
                rule_id: first,
                message: "amount must be positive".to_owned(),
                details: Some(details),
            }
            .into_response(),
        )
        .await;
        assert_eq!(body["rule_id"], first.to_string());
        assert_eq!(body["details"]["field"], "amount");
        assert_eq!(body["details"]["rules"][1]["rule_id"], second.to_string());
        assert!(body["details"]["rules"][1].get("field").is_none());
        let parsed: crate::types::ErrorResponse =
            serde_json::from_value(body).expect("fits ErrorResponse");
        assert!(matches!(
            parsed.details,
            Some(crate::types::ErrorDetails::RuleViolation(_))
        ));
    }

    fn lock(field: &str, effect: &str) -> crate::types::LockedField {
        crate::types::LockedField {
            field: field.to_owned(),
            rule_id: uuid::Uuid::nil(),
            rule_name: "Closed deals".to_owned(),
            effect: effect.to_owned(),
        }
    }

    /// D-789 §3.5: a locked field refusal is 422 `field_locked`, names the
    /// first field and rule at the top level, lists every one, and echoes no
    /// value.
    #[tokio::test]
    async fn field_locked_maps_to_422_and_names_field_and_rule() {
        let resp = AppError::FieldLocked {
            locks: vec![lock("amount", "disabled"), lock("notes", "hidden")],
            required: false,
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "field_locked");
        assert_eq!(body["field"], "amount");
        assert_eq!(body["rule_name"], "Closed deals");
        assert_eq!(body["effect"], "disabled");
        assert_eq!(body["details"]["fields"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            body["message"],
            "'amount' is locked by the rule 'Closed deals' and cannot be changed (1 more field(s) locked)"
        );
        let parsed: crate::types::ErrorResponse =
            serde_json::from_value(body).expect("fits ErrorResponse");
        assert!(matches!(
            parsed.details,
            Some(crate::types::ErrorDetails::FieldLocked(_))
        ));
    }

    /// D-789 §3.4: a required field left empty because a rule locks it is its
    /// own code.
    #[tokio::test]
    async fn field_locked_required_has_its_own_code() {
        let body = body_json(
            AppError::FieldLocked {
                locks: vec![lock("owner_note", "hidden")],
                required: true,
            }
            .into_response(),
        )
        .await;
        assert_eq!(body["error"], "field_locked_required");
        assert_eq!(
            body["message"],
            "'owner_note' is required but the rule 'Closed deals' locks it for your role"
        );
    }

    /// A server-side deadline is 503, never 408 (which blames the client), and
    /// its code stays distinct from `overloaded` so a caller can tell a slow
    /// request from a node shedding writes.
    #[tokio::test]
    async fn server_timeout_maps_to_503_with_its_own_distinct_code() {
        let resp = AppError::ServerTimeout.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "server_timeout");
        assert_ne!(body["error"], "overloaded");
        assert_eq!(
            body["message"],
            "the request exceeded the server's processing time limit"
        );
    }

    /// An oversized body gets the standard envelope with its own code, not a
    /// bare 413 or a `validation_error`.
    #[tokio::test]
    async fn payload_too_large_maps_to_413_with_its_own_distinct_code() {
        let resp = AppError::PayloadTooLarge.into_response();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "payload_too_large");
        assert_eq!(
            body["message"],
            "the request body exceeds the configured size limit"
        );
    }

    /// A same-key retry of an ambiguous earlier request is refused with its own
    /// 409 code, distinct from the in-progress `conflict` and the
    /// different-body `idempotency_conflict`.
    #[tokio::test]
    async fn idempotency_outcome_unknown_maps_to_409_with_its_own_distinct_code() {
        let resp = AppError::IdempotencyOutcomeUnknown.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "idempotency_outcome_unknown");
        assert_ne!(body["error"], "conflict");
        assert_ne!(body["error"], "idempotency_conflict");
    }

    /// A same-key retry of a request that completed with an unstorable response
    /// learns the operation completed, via its own 409 code.
    #[tokio::test]
    async fn idempotency_replay_unavailable_maps_to_409_with_its_own_distinct_code() {
        let resp = AppError::IdempotencyReplayUnavailable.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "idempotency_replay_unavailable");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("completed"),
            "the message must tell the caller the operation completed"
        );
    }

    /// The masking rule this whole error type exists to enforce: an internal
    /// error's real message (which may carry DB/internal details) must never
    /// reach the client, regardless of what it contains.
    #[tokio::test]
    async fn internal_error_maps_to_500_and_never_leaks_its_message_to_the_client() {
        let resp =
            AppError::Internal("password=hunter2 leaked from panic".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "internal_error");
        assert_eq!(body["message"], "an internal error occurred");
        assert!(!body.to_string().contains("hunter2"));
    }

    #[test]
    fn internal_helper_wraps_any_displayable_value() {
        let err = AppError::internal("db pool exhausted");
        assert!(matches!(err, AppError::Internal(msg) if msg == "db pool exhausted"));
    }

    // ── BTY-P0.3 → BTY-F3 (S4): every masked 500 is diagnosable ─────────────

    /// Minimal tracing subscriber that records (level, rendered fields) for
    /// every event, so the log volume at the masked-500 sink can be asserted
    /// without pulling tracing-subscriber into this crate.
    #[derive(Default)]
    struct RecordingSubscriber {
        events: std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
    }

    #[derive(Default)]
    struct EventFieldVisitor(String);

    impl tracing::field::Visit for EventFieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={value:?}", field.name()));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for RecordingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = EventFieldVisitor::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("events mutex")
                .push((*event.metadata().level(), visitor.0));
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Renders the response and returns every ERROR-level event it emitted,
    /// field-by-field.
    fn error_events_emitted_by(err: AppError) -> Vec<String> {
        let subscriber = RecordingSubscriber::default();
        let events = subscriber.events.clone();
        tracing::subscriber::with_default(subscriber, || {
            let _response = err.into_response();
        });
        events
            .lock()
            .expect("events mutex")
            .iter()
            .filter(|(level, _)| *level == tracing::Level::ERROR)
            .map(|(_, fields)| fields.clone())
            .collect()
    }

    /// S4/BTY-F3. into_response is the single sink every Internal passes
    /// through, whether it was built via internal() or as a bare
    /// AppError::Internal(..). Emitting the real detail there exactly once is
    /// what makes a render-sidecar outage distinguishable from a bug: before
    /// this, the direct builds logged nothing at all and internal() logged at
    /// construction, which direct builds bypass.
    #[tokio::test]
    async fn internal_detail_is_logged_exactly_once_at_the_response_boundary() {
        let via_helper = error_events_emitted_by(AppError::internal("render sidecar unreachable"));
        assert_eq!(
            via_helper.len(),
            1,
            "internal() must emit exactly one error event per response, got {via_helper:?}"
        );
        assert!(
            via_helper[0].contains("render sidecar unreachable"),
            "the masked detail must be the logged field: {via_helper:?}"
        );

        let direct =
            error_events_emitted_by(AppError::Internal("bulk item ledger row is missing".into()));
        assert_eq!(
            direct.len(),
            1,
            "a directly built Internal must also emit exactly one error event, got {direct:?}"
        );
        assert!(
            direct[0].contains("bulk item ledger row is missing"),
            "the masked detail must be the logged field: {direct:?}"
        );

        for other in [
            AppError::NotFound,
            AppError::Validation("x".to_string()),
            AppError::TooManyRequests {
                retry_after_secs: None,
            },
            AppError::Overloaded("audit_ingest_backlog"),
            AppError::CapabilityUnavailable("object_storage"),
            AppError::ServerTimeout,
        ] {
            let events = error_events_emitted_by(other);
            assert!(
                events.is_empty(),
                "only Internal may log at error level per response, got {events:?}"
            );
        }
    }

    /// BTY-D6: two variants may share a wire code only as a declared alias
    /// pair, which is what keeps a code clients already handle. Any other
    /// collision fails, and a declaration that has gone stale fails too — so
    /// the list cannot rot into a blanket exemption.
    fn assert_only_declared_code_aliases(codes: &[(usize, String, u16)]) {
        let mut by_code: std::collections::BTreeMap<&str, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (index, code, _) in codes {
            by_code.entry(code.as_str()).or_default().push(*index);
        }
        for (code, indices) in &by_code {
            if indices.len() == 1 {
                continue;
            }
            assert_eq!(
                indices.len(),
                2,
                "wire code {code} is shared by more than a declared pair: {indices:?}"
            );
            let pair = (indices[0].min(indices[1]), indices[0].max(indices[1]));
            assert!(
                DECLARED_CODE_ALIASES.contains(&pair),
                "wire code {code} is shared by undeclared variants {pair:?}"
            );
        }
        for pair in DECLARED_CODE_ALIASES {
            let left = codes
                .iter()
                .find(|(index, _, _)| index == &pair.0)
                .expect("a declared alias variant is in one_of_each_variant");
            let right = codes
                .iter()
                .find(|(index, _, _)| index == &pair.1)
                .expect("a declared alias variant is in one_of_each_variant");
            assert_eq!(
                left.1, right.1,
                "declared alias {pair:?} no longer shares a wire code"
            );
        }
    }

    /// The failure direction of the mechanism above, which the drift test
    /// itself can never exercise while the enum is consistent.
    #[test]
    #[should_panic(expected = "undeclared")]
    fn an_undeclared_shared_wire_code_fails_the_guard() {
        assert_only_declared_code_aliases(&[
            (0, "not_found".to_string(), 404),
            (1, "not_found".to_string(), 404),
            (6, "validation_error".to_string(), 422),
            (21, "validation_error".to_string(), 422),
        ]);
    }

    /// A declaration that no longer describes reality must fail too, not sit
    /// there as a permanent exemption.
    #[test]
    #[should_panic(expected = "no longer shares")]
    fn a_stale_declared_alias_fails_the_guard() {
        assert_only_declared_code_aliases(&[
            // The declared pair that still shares, so only the stale pair can
            // be the reason this panics.
            (4, "version_conflict".to_string(), 409),
            (22, "version_conflict".to_string(), 409),
            // Declared, but the two variants no longer answer the same code.
            (6, "validation_error".to_string(), 422),
            (21, "not_validation_error".to_string(), 422),
        ]);
    }
    // ── Wire-code drift guard ────────────────────────────────────────────────

    /// No wildcard arm: a new variant fails to compile here. Give it the next
    /// index and add a sample of it to `one_of_each_variant`, directly below.
    fn variant_index(e: &AppError) -> usize {
        match e {
            AppError::NotFound => 0,
            AppError::Unauthorized => 1,
            AppError::Forbidden => 2,
            AppError::Conflict(_) => 3,
            AppError::VersionConflict => 4,
            AppError::IdempotencyConflict(_) => 5,
            AppError::Validation(_) => 6,
            AppError::FeatureUnavailable => 7,
            AppError::FeatureHidden(_) => 8,
            AppError::TooManyRequests { .. } => 9,
            AppError::Overloaded(_) => 10,
            AppError::CapabilityUnavailable(_) => 11,
            AppError::AuthoringLocked => 12,
            AppError::TransitionNotAllowed(_) => 13,
            AppError::RuleViolation { .. } => 14,
            AppError::ServerTimeout => 15,
            AppError::PayloadTooLarge => 16,
            AppError::IdempotencyOutcomeUnknown => 17,
            AppError::IdempotencyReplayUnavailable => 18,
            AppError::Internal(_) => 19,
            AppError::ReauthRequired { .. } => 20,
            AppError::FieldValidation(_) => 21,
            AppError::VersionConflictAt { .. } => 22,
            AppError::MethodNotAllowed => 23,
            AppError::FieldLocked { .. } => 24,
        }
    }

    fn one_of_each_variant() -> Vec<AppError> {
        vec![
            AppError::NotFound,
            AppError::Unauthorized,
            AppError::Forbidden,
            AppError::Conflict("x"),
            AppError::VersionConflict,
            AppError::IdempotencyConflict("x"),
            AppError::Validation("x".to_string()),
            AppError::FeatureUnavailable,
            AppError::FeatureHidden("x".to_string()),
            AppError::TooManyRequests {
                retry_after_secs: None,
            },
            AppError::Overloaded("x"),
            AppError::CapabilityUnavailable("x"),
            AppError::AuthoringLocked,
            AppError::TransitionNotAllowed("x".to_string()),
            AppError::RuleViolation {
                rule_id: uuid::Uuid::now_v7(),
                message: "x".to_string(),
                details: None,
            },
            AppError::ServerTimeout,
            AppError::PayloadTooLarge,
            AppError::IdempotencyOutcomeUnknown,
            AppError::IdempotencyReplayUnavailable,
            AppError::Internal("x".to_string()),
            AppError::ReauthRequired {
                operation: "identity_link",
                acceptable_factors: vec!["password"],
            },
            AppError::FieldValidation(vec![crate::types::FieldError {
                field: "email".to_string(),
                code: "invalid_format".to_string(),
                message: "x".to_string(),
            }]),
            AppError::VersionConflictAt {
                current_version: 7,
                current_state: serde_json::json!({ "name": "x" }),
            },
            AppError::MethodNotAllowed,
            AppError::FieldLocked {
                locks: vec![crate::types::LockedField {
                    field: "x".to_string(),
                    rule_id: uuid::Uuid::now_v7(),
                    rule_name: "x".to_string(),
                    effect: "disabled".to_string(),
                }],
                required: false,
            },
        ]
    }

    /// Codes the SDK is known not to declare yet, tracked outside the
    /// attome-server hardening plan. The test also fails once one of these is
    /// declared, so the exemption is removed rather than left stale.
    ///
    /// `field_locked` / `field_locked_required` (D-789, lane BR-B) are
    /// published by the server first; the SDK's `ApiErrorKind` declares them
    /// with the business-rule editor lane (BR-D). `rule_violation` (BTY-3) and
    /// `method_not_allowed` (attome-server A5) are declared already.
    const SDK_KNOWN_GAPS: &[&str] = &[];

    /// Variant-index pairs allowed to answer the same wire code (BTY-D6). A
    /// structured variant answers the code its plain sibling already
    /// publishes, so a client handles one code; an undeclared collision still
    /// fails, and so does a pair listed here that no longer shares its code.
    const DECLARED_CODE_ALIASES: &[(usize, usize)] = &[(4, 22), (6, 21)];

    fn repo_file(relative: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(relative);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let from = text
            .find(start)
            .unwrap_or_else(|| panic!("marker {start:?} not found"));
        let rest = &text[from + start.len()..];
        let to = rest
            .find(end)
            .unwrap_or_else(|| panic!("marker {end:?} not found after {start:?}"));
        &rest[..to]
    }

    /// Every wire code with its variant index and HTTP status, after checking
    /// that `one_of_each_variant` covers every variant and that only declared
    /// aliases share a code.
    async fn wire_codes() -> Vec<(usize, String, u16)> {
        let samples = one_of_each_variant();
        let mut indices: Vec<usize> = samples.iter().map(variant_index).collect();
        indices.sort_unstable();
        assert_eq!(
            indices,
            (0..=24).collect::<Vec<_>>(),
            "one_of_each_variant must hold exactly one sample of every variant_index arm"
        );

        let mut codes = Vec::new();
        for sample in samples {
            let index = variant_index(&sample);
            let resp = sample.into_response();
            let status = resp.status().as_u16();
            let code = body_json(resp).await["error"]
                .as_str()
                .expect("every error body carries a string code")
                .to_owned();
            codes.push((index, code, status));
        }
        assert_only_declared_code_aliases(&codes);
        codes
    }

    /// Every wire code is declared in the `ErrorResponse` doc in `types.rs`,
    /// the list clients read in the generated API documentation.
    #[tokio::test]
    async fn every_wire_code_is_declared_in_the_error_response_doc() {
        let doc_list = between(
            include_str!("types.rs"),
            "pub struct ErrorResponse",
            "pub error",
        );
        for (_, code, _) in wire_codes().await {
            let ticked = format!("`{code}`");
            assert!(
                doc_list.contains(&ticked),
                "types.rs ErrorResponse doc lacks {ticked}"
            );
        }
    }

    /// Every wire code is declared on each generated or hand-copied client
    /// surface: the OpenAPI document, the generated `api-types.ts` and the
    /// SDK's `ApiErrorKind` union, `KNOWN_KINDS` set and spec status table.
    /// Each of these has drifted from the enum before.
    #[tokio::test]
    #[ignore = "enable when v2 generates openapi.json and has the web SDK (web/)"]
    async fn every_wire_code_is_declared_on_every_client_surface() {
        let openapi: serde_json::Value =
            serde_json::from_str(&repo_file("openapi.json")).expect("openapi.json parses");
        let openapi_list = openapi["components"]["schemas"]["ErrorResponse"]["properties"]["error"]
            ["description"]
            .as_str()
            .expect("ErrorResponse.error has a description");
        let api_types = [repo_file("web/projects/sdk/src/lib/generated/api-types.ts")];
        let sdk = repo_file("web/projects/sdk/src/lib/errors.ts");
        let sdk_union = between(&sdk, "export type ApiErrorKind =", ";");
        let sdk_known = between(&sdk, "new Set<ApiErrorKind>([", "]);");
        let sdk_spec = repo_file("web/projects/sdk/src/lib/errors.spec.ts");

        for (_, code, status) in wire_codes().await {
            let ticked = format!("`{code}`");
            assert!(
                openapi_list.contains(&ticked),
                "openapi.json lacks {ticked}; regenerate the API artefacts"
            );
            for generated in &api_types {
                assert!(
                    generated.contains(&ticked),
                    "an api-types.ts lacks {ticked}; regenerate the API artefacts"
                );
            }

            let quoted = format!("'{code}'");
            if SDK_KNOWN_GAPS.contains(&code.as_str()) {
                assert!(
                    !sdk_union.contains(&quoted),
                    "{code} is now in the SDK; remove it from SDK_KNOWN_GAPS"
                );
                continue;
            }
            assert!(sdk_union.contains(&quoted), "ApiErrorKind lacks {quoted}");
            assert!(sdk_known.contains(&quoted), "KNOWN_KINDS lacks {quoted}");
            let row = format!("['{code}', {status}]");
            assert!(
                sdk_spec.contains(&row),
                "errors.spec.ts lacks the row {row}"
            );
        }
    }
}

//! Q21-T2: `POST /api/v1/security/csp-report`, where browsers report
//! Content-Security-Policy violations.
//!
//! Public (a browser sends the report with no credential) and so listed in
//! `middleware::bypass::EXACT_BYPASS_PATHS`, rate-limited per address
//! (`rate_limit`'s `consent_capture` class) and bounded to 16 KiB. Both
//! report formats are read: the legacy `application/csp-report` body
//! (`{"csp-report": {...}}`) and the Reporting API's
//! `application/reports+json` list. Each violation is grouped by directive
//! and blocked source: a counter `csp_violations_total{directive}` (the
//! directive from a fixed list, so its labels stay few) and a `warn` log with
//! the source's scheme and host only, never a full URL, which can carry a
//! token. Nothing is stored. The answer is always `204`.

use axum::{
    Router,
    body::Bytes,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::Value;


/// Reports read from one request; the rest are dropped.
const MAX_REPORTS: usize = 20;

/// The directives a counter label may name; anything else is `other`.
const DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "font-src",
    "connect-src",
    "frame-src",
    "frame-ancestors",
    "object-src",
    "base-uri",
    "form-action",
    "worker-src",
    "manifest-src",
    "media-src",
];

/// One violation: its directive and the blocked source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Violation {
    pub directive: &'static str,
    pub source: String,
}

/// The directive a report names, from the fixed list.
fn directive_of(raw: &str) -> &'static str {
    // `violated-directive` may carry the whole directive with its sources.
    let name = raw.split_whitespace().next().unwrap_or_default();
    DIRECTIVES
        .iter()
        .copied()
        .find(|d| d.eq_ignore_ascii_case(name))
        .unwrap_or("other")
}

/// The blocked source as a keyword (`inline`, `eval`, `data`) or a scheme and
/// host, never a path or query.
fn source_of(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return "unknown".into();
    }
    if !raw.contains(':') {
        return raw.chars().take(32).collect();
    }
    match url::Url::parse(raw) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => url.scheme().to_owned(),
        },
        Err(_) => "unparsed".into(),
    }
}

/// Every violation in a report body, in either format.
pub(crate) fn violations(body: &[u8]) -> Vec<Violation> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let reports: Vec<&Value> = match &value {
        // Reporting API: a list of `{type, body}`.
        Value::Array(items) => items
            .iter()
            .filter(|r| r.get("type").and_then(Value::as_str) == Some("csp-violation"))
            .filter_map(|r| r.get("body"))
            .collect(),
        // Legacy `report-uri`: one `{"csp-report": {...}}`.
        Value::Object(map) => map.get("csp-report").into_iter().collect(),
        _ => Vec::new(),
    };
    reports
        .into_iter()
        .take(MAX_REPORTS)
        .map(|report| {
            let field = |names: &[&str]| {
                names
                    .iter()
                    .find_map(|n| report.get(*n).and_then(Value::as_str))
                    .unwrap_or_default()
                    .to_owned()
            };
            Violation {
                directive: directive_of(&field(&[
                    "effectiveDirective",
                    "effective-directive",
                    "violated-directive",
                ])),
                source: source_of(&field(&["blockedURL", "blocked-uri"])),
            }
        })
        .collect()
}

/// Report a Content-Security-Policy violation
///
/// Q21-T2: browsers send CSP violation reports here, in the legacy
/// `application/csp-report` format or the Reporting API's
/// `application/reports+json`. Public and rate-limited; grouped by
/// directive and blocked source; nothing is stored.
#[utoipa::path(
    post,
    path = "/api/v1/security/csp-report",
    tag = "operations",
    operation_id = "report_csp_violation",
    request_body(content = String, content_type = "application/csp-report", description = "A browser's CSP violation report"),
    extensions(
        ("x-body-limit" = json!(16_384)),
        ("x-audit-exempt" = json!({
            "reason": "telemetry",
            "via": null,
            "note": "browser reports: CSP violations a page saw, counted and logged, nothing stored",
        })),
    ),
    responses(
        (status = 204, description = "Received"),
        (status = 413, description = "Larger than 16 KiB", body = attome_types::ErrorResponse),
        (status = 429, description = "Too many reports from this address", body = attome_types::ErrorResponse),
    ),
)]
async fn report_csp_violation(body: Bytes) -> Response {
    for violation in violations(&body) {
        metrics::counter!("csp_violations_total", "directive" => violation.directive).increment(1);
        tracing::warn!(
            event = "security.csp_violation",
            directive = violation.directive,
            source = %violation.source,
            "a browser reported a CSP violation"
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

/// The route, for `crate::app::health_routes`.
pub(crate) fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // A literal, equal to `CSP_REPORT_PATH` (pinned by the test below), so the
    // route census sees it.
    Router::new().route("/api/v1/security/csp-report", post(report_csp_violation))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(report_csp_violation))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_report_route_is_the_reported_path() {
        assert_eq!(crate::middleware::security_headers::CSP_REPORT_PATH, "/api/v1/security/csp-report");
    }

    #[test]
    fn csp_reports_in_both_formats_are_grouped_by_directive_and_source() {
        let legacy = br#"{"csp-report": {"document-uri": "https://crm.example.com/a",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.example.net/x.js?token=secret"}}"#;
        assert_eq!(
            violations(legacy),
            vec![Violation {
                directive: "script-src",
                source: "https://evil.example.net".into()
            }]
        );

        let reporting = br#"[
            {"type": "csp-violation", "body": {"effectiveDirective": "style-src-elem", "blockedURL": "inline"}},
            {"type": "deprecation", "body": {}},
            {"type": "csp-violation", "body": {"effectiveDirective": "made-up", "blockedURL": "data:"}}
        ]"#;
        assert_eq!(
            violations(reporting),
            vec![
                Violation {
                    directive: "style-src-elem",
                    source: "inline".into()
                },
                Violation {
                    directive: "other",
                    source: "data".into()
                },
            ]
        );
        assert!(violations(b"not json").is_empty());
        let many = format!(
            "[{}]",
            vec![r#"{"type":"csp-violation","body":{"effectiveDirective":"img-src"}}"#; 50]
                .join(",")
        );
        assert_eq!(violations(many.as_bytes()).len(), MAX_REPORTS);
    }
}

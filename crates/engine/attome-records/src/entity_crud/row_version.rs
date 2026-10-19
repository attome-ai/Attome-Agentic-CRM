use attome_types::AppError;
use serde_json::Value;

pub(super) const SYSTEM_COLS: &[&str] =
    &["id", "created_at", "modified_at", "deleteon", "row_version"];

/// Parses the `If-Match` header into an expected `row_version` (F027).
/// Accepts `"3"` (quoted, as `@attome/base`'s ApiService sends) or `3`.
/// Mandatory on every PATCH (D-079: entity contracts are database-enforced
/// and evolution is fail-closed) â€” no header is a 422, not an unguarded
/// last-write-wins update. `coding-guidelines.md` Â§2 Layer 3 still describes
/// the older opt-in contract; that's the doc lagging D-079, not this being
/// wrong â€” don't "fix" this back to optional without re-reading D-079 first.
pub(super) fn expected_row_version(headers: &axum::http::HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match is required for every update".into()))?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// A16-T2: whether a PATCH asks for an automatic merge
/// (`If-Match-Merge: attributes`, the one value it takes). Absent is no.
///
/// A16-T3: the header is outside the S2S signature, so a signed request never
/// merges: on one carrying `x-s2s-client-id` it is ignored and a stale
/// version is the usual 409 (fail-closed, as `x-override-reason` is).
pub(super) fn merge_requested(headers: &axum::http::HeaderMap) -> Result<bool, AppError> {
    if headers.contains_key("x-s2s-client-id") {
        return Ok(false);
    }
    let Some(raw) = headers.get("if-match-merge") else {
        return Ok(false);
    };
    match raw.to_str().map(str::trim) {
        Ok(value) if value.eq_ignore_ascii_case("attributes") => Ok(true),
        _ => Err(AppError::Validation(
            "If-Match-Merge takes only the value `attributes`".into(),
        )),
    }
}

/// Parses `If-Match` for the delete/restore paths, where the header is
/// **optional** (DATA-7/CONC-1, PLATFORM-REVIEW-2026-08-24).
///
/// Deliberately not `expected_row_version` above: that one is mandatory,
/// because D-079 made a version-less PATCH a 422 rather than an unguarded
/// last-write-wins update. DELETE and restore are outside D-079's scope — they
/// had no version guard at all — so this is purely additive: a caller that
/// sends the header gets optimistic concurrency and a 409 on mismatch, and one
/// that doesn't keeps exactly today's behaviour. **That leaves a deliberate
/// asymmetry — mandatory on PATCH, optional here — recorded rather than
/// discovered.** Tightening these to mandatory later is a breaking API change
/// and should be its own decision, not a drive-by.
///
/// A *malformed* header is still a 422. Absence means "no expectation";
/// garbage must never silently degrade into the unguarded path, which is the
/// same reasoning `expected_upsert_row_version` below applies to its envelope
/// field.
pub fn optional_expected_row_version(
    headers: &axum::http::HeaderMap,
) -> Result<Option<i64>, AppError> {
    if headers.get(axum::http::header::IF_MATCH).is_none() {
        return Ok(None);
    }
    expected_row_version(headers).map(Some)
}

/// Parses the optional upsert envelope version. Absence is meaningful for a
/// fresh insert, but an explicitly supplied value must be a non-negative JSON
/// integer. In particular, malformed values must not silently become the
/// version-less last-write-wins path.
pub(super) fn expected_upsert_row_version(
    body: &serde_json::Map<String, Value>,
) -> Result<Option<i64>, AppError> {
    let Some(value) = body.get("row_version") else {
        return Ok(None);
    };
    Ok(Some(parse_row_version_value(value)?))
}

/// Parses a `row_version` JSON value into a non-negative `i64`, rejecting
/// strings/floats/negatives the same way `expected_upsert_row_version` does.
/// Shared by any envelope-carried (non-header) version field.
fn parse_row_version_value(value: &Value) -> Result<i64, AppError> {
    let version = value
        .as_i64()
        .ok_or_else(|| AppError::Validation("row_version must be a non-negative integer".into()))?;
    if version < 0 {
        return Err(AppError::Validation(
            "row_version must be a non-negative integer".into(),
        ));
    }
    Ok(version)
}

/// Parses `If-None-Match` for the single-record GET's conditional-read
/// short-circuit (caching-efficiency finding, 2026-07-30). Encodes the same
/// `row_version` integer `expected_row_version` above parses out of
/// `If-Match`, optionally wrapped as a weak ETag (`W/"3"`) since that's the
/// shape `row_version_etag` below emits on this handler's own `ETag`
/// response header. Unlike `expected_row_version`, this is a pure caching
/// optimization, not a concurrency guard: a missing or malformed header
/// must never fail the request, it just means "skip the short-circuit and
/// do the full read" — so this returns `Option`, not `Result`.
pub(super) fn if_none_match_row_version(headers: &axum::http::HeaderMap) -> Option<i64> {
    let raw = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())?;
    let s = raw
        .trim()
        .strip_prefix("W/")
        .unwrap_or(raw.trim())
        .trim_matches('"');
    s.parse::<i64>().ok()
}

/// The read-side mirror of `expected_row_version`: encodes a record's
/// `row_version` as a weak ETag. Weak (`W/`) because the JSON body's key
/// order/formatting isn't guaranteed byte-stable across requests even when
/// `row_version` is unchanged, and RFC 7232 reserves strong ETags for
/// byte-identical comparison.
pub(super) fn row_version_etag(row_version: i64) -> String {
    format!("W/\"{row_version}\"")
}

#[cfg(test)]
mod tests {
    use super::merge_requested;
    use axum::http::{HeaderMap, HeaderValue};

    /// A16-T3: the merge header is outside the S2S signature, so a signed
    /// request never merges.
    #[test]
    fn merge_header_is_ignored_on_a_signed_request() {
        let mut headers = HeaderMap::new();
        headers.insert("if-match-merge", HeaderValue::from_static("attributes"));
        assert!(merge_requested(&headers).unwrap());
        headers.insert("x-s2s-client-id", HeaderValue::from_static("client"));
        assert!(!merge_requested(&headers).unwrap());
    }
}

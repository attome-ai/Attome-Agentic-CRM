//! P-api-contract Phase 5: RFC 8594 `Sunset` + the companion `Deprecation`
//! response header, emitted **as RFC 9745 defines it**: a Structured Field
//! Date, `@<seconds since the Unix epoch>`. The expired
//! draft-ietf-httpapi-deprecation-header this originally followed accepted
//! `true` or an IMF-fixdate; RFC 9745 allows neither, so an RFC-conformant
//! client rejected the header outright (BSV-F19 / A7). Where an entry names a
//! URI, a `Link: <...>; rel="deprecation"` is emitted with it (RFC 9745 §3);
//! an entry whose `replacement` is a reason sentence has no URI to link, so it
//! carries only `Deprecation` + `Sunset`. For a small, explicit,
//! compile-time registry of deprecated-path -> sunset-date entries — the same
//! "compile-time list, never runtime config" posture as
//! `middleware::bypass::BYPASS_PATHS` (guidelines §3's "any new public
//! endpoint MUST be added to the bypass list constant explicitly — never a
//! runtime config" precedent, applied here to the *retiring* half of that
//! same class of decision).
//!
//! The policy this registry embodies (P-api-contract §4): a path being
//! retired gets an entry here the same release its replacement ships (not
//! after), carrying a concrete sunset date and a documented replacement
//! path; the entry is removed only once that date has passed AND the path
//! itself is deleted from the router — never left dual-mounted indefinitely
//! with a stale, ignored header.
//!
//! M61 Phase 1 (API Management, D-438) — this registry is now also the
//! *single* source of truth for the OpenAPI half of a deprecation notice
//! (`deprecated: true` plus `x-sunset`/`x-replacement` extensions), not just
//! the response headers: `apply_to_openapi` below walks it against the fully
//! merged document (`crates/server/src/openapi.rs::build()`) rather than
//! requiring every deprecated handler to remember a manual
//! `#[utoipa::path(...)]` edit — D-309 already found utoipa 5's derive macro
//! has no `deprecated` key at all, so that manual edit was never even
//! possible; this mutates the runtime `utoipa::openapi::OpenApi` value
//! directly instead. The two halves must stay in lockstep (held by review
//! since D-768 removed the coverage script): any operation the document marks `deprecated: true`
//! must carry both extensions, which in practice means "went through this
//! registry" — there is no other way to set `deprecated: true` on the
//! assembled document.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use utoipa::openapi::{Deprecated, OpenApi, extensions::Extensions, path::Operation};

/// One entry per deprecated-but-still-mounted path. `sunset` MUST be an
/// RFC 7231 IMF-fixdate string (`Sun, 06 Nov 1994 08:49:37 GMT` shape) — RFC
/// 8594 §3 requires the `Sunset` header value in exactly that format, not a
/// bare date. `path` is an exact match against `Uri::path()`, same
/// exact-match convention as `bypass::EXACT_BYPASS_PATHS` (no prefix
/// matching here — a deprecation notice on the wrong path is actively
/// misleading, so this deliberately does not offer `bypass`'s subtree-prefix
/// option). `replacement` is the path a caller should move to — required
/// (never `""`), a rule on the assembled document (held by review since
/// D-768) rather than a Rust-side check, since the document is where a
/// consumer (a generated client, the not-yet-built developer portal) reads it
/// from.
pub struct DeprecatedPath {
    pub path: &'static str,
    /// When this path was deprecated, as seconds since the Unix epoch — the
    /// value RFC 9745 requires in the `Deprecation` response header. Must be
    /// at or before `sunset` (`deprecation_header_is_an_rfc9745_sf_date`
    /// asserts it).
    pub deprecated_at: i64,
    pub sunset: &'static str,
    pub replacement: &'static str,
}

impl std::fmt::Debug for DeprecatedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeprecatedPath").finish_non_exhaustive()
    }
}

/// The registry of record. Empty (D-793): a retired route is deleted outright
/// in the change that retires it, together with its callers, instead of being
/// listed here with a sunset window. The seven entries this list last carried
/// (the dashboard widget `group`/`ungroup`/`align` actions, licence
/// `import`/`usage`, and the legacy dashboard-migration `runs` routes) were
/// deleted from the router together with their handlers. The mechanism (the
/// middleware, the OpenAPI decoration and their tests, which use a local
/// fixture) stays available but optional: an entry is added only when the
/// owner chooses to give an outside caller notice before a removal (D-793
/// rule 3).
pub const DEPRECATED_PATHS: &[DeprecatedPath] = &[];

fn find_in<'a>(paths: &'a [DeprecatedPath], path: &str) -> Option<&'a DeprecatedPath> {
    paths.iter().find(|entry| entry.path == path)
}

fn find(path: &str) -> Option<&'static DeprecatedPath> {
    find_in(DEPRECATED_PATHS, path)
}

/// Applies `DEPRECATED_PATHS` to the assembled OpenAPI document: for every
/// entry whose `path` has a matching `PathItem`, every HTTP-method operation
/// actually present on it (there is normally exactly one) gets
/// `deprecated: true` plus `x-sunset`/`x-replacement` extensions carrying
/// this entry's `sunset`/`replacement` values verbatim. A registry entry
/// naming a path the document doesn't have (a stale entry after a route was
/// already deleted) is silently skipped here — that drift is
/// for review to catch, not this function's.
pub fn apply_to_openapi(doc: &mut OpenApi) {
    apply_registry_to_openapi(DEPRECATED_PATHS, doc);
}

/// The actual walk, parameterised over the registry so tests can exercise it
/// against a non-empty synthetic registry even while [`DEPRECATED_PATHS`]
/// itself is empty (no path is currently mid-deprecation) — see this
/// module's tests.
fn apply_registry_to_openapi(paths: &[DeprecatedPath], doc: &mut OpenApi) {
    for entry in paths {
        let Some(item) = doc.paths.paths.get_mut(entry.path) else {
            continue;
        };
        for operation in [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.options,
            &mut item.head,
            &mut item.patch,
            &mut item.trace,
        ]
        .into_iter()
        .flatten()
        {
            mark_deprecated(operation, entry);
        }
    }
}

fn mark_deprecated(operation: &mut Operation, entry: &DeprecatedPath) {
    operation.deprecated = Some(Deprecated::True);
    let extra: Extensions = [
        ("x-sunset", serde_json::Value::from(entry.sunset)),
        ("x-replacement", serde_json::Value::from(entry.replacement)),
    ]
    .into_iter()
    .collect();
    match &mut operation.extensions {
        Some(existing) => existing.merge(extra),
        None => operation.extensions = Some(extra),
    }
}

/// Stateless response-mapping middleware, same shape as
/// `request_id_body::attach_request_id_to_error_body` — reads the request
/// path before handing off to `next`, then (only for a registered path)
/// decorates whatever response comes back, success or error alike, since a
/// deprecation notice is about the *endpoint*, not any particular response
/// status.
pub async fn deprecation_headers(req: Request, next: Next) -> Response {
    let entry = find(req.uri().path());
    let response = next.run(req).await;
    let Some(entry) = entry else {
        return response;
    };

    let (mut parts, body) = response.into_parts();
    apply_headers(entry, &mut parts.headers);
    Response::from_parts(parts, body)
}

/// A7 (BSV-F19) — the headers one registry entry contributes. Split out so the
/// RFC 9745 SF Date shape and the conditional `Link` are unit-testable without
/// a router.
///
/// - `Deprecation` is a Structured Field Date: `@` followed by seconds since
///   the Unix epoch (RFC 9745 §2). The expired draft's bare `true` is not a
///   valid SF Date, and an RFC-conformant client rejects the header outright.
/// - `Link` with relation type `deprecation` points at documentation
///   (RFC 9745 §3). Only an entry whose `replacement` is actually a URI (a
///   route path or an absolute URL) has something to point at; a reason
///   sentence does not, so no `Link` is emitted for it rather than inventing a
///   URL.
/// - `Sunset` is the RFC 8594 IMF-fixdate this registry has always carried.
fn apply_headers(entry: &DeprecatedPath, headers: &mut axum::http::HeaderMap) {
    if let Ok(value) = HeaderValue::from_str(&format!("@{}", entry.deprecated_at)) {
        headers.insert("deprecation", value);
    }
    if (entry.replacement.starts_with('/') || entry.replacement.starts_with("http"))
        && let Ok(value) =
            HeaderValue::from_str(&format!("<{}>; rel=\"deprecation\"", entry.replacement))
    {
        headers.insert("link", value);
    }
    if let Ok(value) = HeaderValue::from_str(entry.sunset) {
        headers.insert("sunset", value);
    }
}

/// S8-T3: an API version being retired (`attome_types::api_version`). A
/// request answered at it carries `Deprecation` and `Sunset`, like a
/// deprecated path; after `sunset_at` it is refused with 410
/// `api_version_sunset`.
pub struct DeprecatedVersion {
    pub version: &'static str,
    /// Seconds since the Unix epoch.
    pub deprecated_at: i64,
    /// The RFC 8594 IMF-fixdate for the `Sunset` header.
    pub sunset: &'static str,
    /// The same moment as `sunset`, in seconds since the Unix epoch.
    pub sunset_at: i64,
}

impl std::fmt::Debug for DeprecatedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeprecatedVersion")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// S8-T3: the versions being retired. Empty while one version exists.
pub const DEPRECATED_VERSIONS: &[DeprecatedVersion] = &[];

/// S8-T3: what the registry says about one version at `now`.
#[derive(Debug)]
pub enum VersionNotice<'a> {
    Current,
    Deprecated(&'a DeprecatedVersion),
    Sunset(&'a DeprecatedVersion),
}

/// S8-T3: [`VersionNotice`] for `version` in `registry`.
pub fn version_notice_in<'a>(
    registry: &'a [DeprecatedVersion],
    version: &str,
    now: i64,
) -> VersionNotice<'a> {
    match registry.iter().find(|entry| entry.version == version) {
        Some(entry) if now >= entry.sunset_at => VersionNotice::Sunset(entry),
        Some(entry) => VersionNotice::Deprecated(entry),
        None => VersionNotice::Current,
    }
}

/// S8-T3: [`VersionNotice`] for `version` in [`DEPRECATED_VERSIONS`].
pub fn version_notice(version: &str, now: i64) -> VersionNotice<'static> {
    version_notice_in(DEPRECATED_VERSIONS, version, now)
}

/// S8-T3: the `Deprecation` and `Sunset` headers of a deprecated version.
pub fn apply_version_headers(entry: &DeprecatedVersion, headers: &mut axum::http::HeaderMap) {
    if let Ok(value) = HeaderValue::from_str(&format!("@{}", entry.deprecated_at)) {
        headers.insert("deprecation", value);
    }
    if let Ok(value) = HeaderValue::from_str(entry.sunset) {
        headers.insert("sunset", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_VERSION: DeprecatedVersion = DeprecatedVersion {
        version: "2025-01",
        deprecated_at: 1_750_000_000,
        sunset: "Sat, 29 Aug 2026 00:00:00 GMT",
        sunset_at: 1_788_048_000,
    };

    #[test]
    fn a_deprecated_version_carries_its_headers() {
        let registry = [OLD_VERSION];
        let notice = version_notice_in(&registry, "2025-01", 1_760_000_000);
        let VersionNotice::Deprecated(entry) = notice else {
            panic!("expected deprecated, got {notice:?}");
        };
        let mut headers = axum::http::HeaderMap::new();
        apply_version_headers(entry, &mut headers);
        assert_eq!(headers["deprecation"], "@1750000000");
        assert_eq!(headers["sunset"], "Sat, 29 Aug 2026 00:00:00 GMT");
        assert!(matches!(
            version_notice_in(&registry, "2026-10", 1_760_000_000),
            VersionNotice::Current
        ));
    }

    #[test]
    fn a_version_past_its_sunset_is_refused() {
        let registry = [OLD_VERSION];
        assert!(matches!(
            version_notice_in(&registry, "2025-01", 1_788_048_000),
            VersionNotice::Sunset(_)
        ));
        assert!(DEPRECATED_VERSIONS.is_empty());
    }

    /// A synthetic entry for exercising `find_in`/`apply_registry_to_openapi`
    /// against a fixed, known shape rather than asserting on real production
    /// entries that may come and go.
    const SAMPLE_PATH: DeprecatedPath = DeprecatedPath {
        path: "/api/v1/widgets/legacy-list",
        deprecated_at: 1_750_000_000,
        sunset: "Sat, 29 Aug 2026 00:00:00 GMT",
        replacement: "/api/v1/widgets/list",
    };
    const SAMPLE_REGISTRY: &[DeprecatedPath] = &[SAMPLE_PATH];

    #[test]
    fn a_registered_path_is_found() {
        assert!(find_in(SAMPLE_REGISTRY, "/api/v1/widgets/legacy-list").is_some());
    }

    #[test]
    fn its_replacement_path_is_not_itself_registered() {
        assert!(find_in(SAMPLE_REGISTRY, "/api/v1/widgets/list").is_none());
    }

    #[test]
    fn an_unrelated_path_is_not_registered() {
        assert!(find_in(SAMPLE_REGISTRY, "/api/v1/query/execute").is_none());
        assert!(find("/api/v1/query/execute").is_none());
    }

    #[test]
    fn the_retired_sidebar_alias_is_gone_from_the_real_registry() {
        // C-25 retired the sidebar alias, this registry's first entry, and
        // deleted its route — not merely unlisted it here.
        assert!(find("/api/sidebar/get").is_none());
    }

    #[test]
    fn the_real_registry_is_empty() {
        // D-793: retired routes are deleted outright with their callers, never
        // listed here with a sunset window unless the owner opts in.
        assert!(DEPRECATED_PATHS.is_empty());
        for path in [
            "/api/v1/xrm-dashboard/widget/group",
            "/api/v1/admin/license/import",
            "/api/v1/admin/dashboard-migration/runs",
        ] {
            assert!(find(path).is_none());
        }
    }

    #[test]
    fn every_sunset_date_parses_as_a_valid_header_value() {
        for entry in SAMPLE_REGISTRY.iter().chain(DEPRECATED_PATHS) {
            assert!(
                HeaderValue::from_str(entry.sunset).is_ok(),
                "invalid Sunset header value for {}: {}",
                entry.path,
                entry.sunset
            );
        }
    }

    #[test]
    fn every_entry_names_a_non_empty_replacement() {
        for entry in SAMPLE_REGISTRY {
            assert!(
                !entry.replacement.is_empty(),
                "{} has no documented replacement",
                entry.path
            );
            assert_ne!(
                entry.replacement, entry.path,
                "{} names itself as its own replacement",
                entry.path
            );
        }
    }

    fn doc_with_get(path: &str) -> OpenApi {
        let mut doc = OpenApi::default();
        doc.paths.paths.insert(
            path.to_string(),
            utoipa::openapi::PathItem::new(utoipa::openapi::HttpMethod::Get, Operation::new()),
        );
        doc
    }

    #[test]
    fn apply_registry_to_openapi_marks_the_registered_path_deprecated_with_sunset_and_replacement()
    {
        let mut doc = doc_with_get("/api/v1/widgets/legacy-list");
        apply_registry_to_openapi(SAMPLE_REGISTRY, &mut doc);

        let op = doc.paths.paths["/api/v1/widgets/legacy-list"]
            .get
            .as_ref()
            .expect("get operation must still be present");
        assert!(matches!(op.deprecated, Some(Deprecated::True)));
        let ext = op.extensions.as_ref().expect("extensions must be set");
        assert_eq!(
            ext.get("x-sunset"),
            Some(&serde_json::json!("Sat, 29 Aug 2026 00:00:00 GMT"))
        );
        assert_eq!(
            ext.get("x-replacement"),
            Some(&serde_json::json!("/api/v1/widgets/list"))
        );
    }

    #[test]
    fn apply_registry_to_openapi_leaves_an_unregistered_path_untouched() {
        let mut doc = doc_with_get("/api/v1/widgets/list");
        apply_registry_to_openapi(SAMPLE_REGISTRY, &mut doc);

        let op = doc.paths.paths["/api/v1/widgets/list"]
            .get
            .as_ref()
            .unwrap();
        assert!(op.deprecated.is_none());
        assert!(op.extensions.is_none());
    }

    #[test]
    fn apply_registry_to_openapi_is_a_no_op_for_a_registry_entry_the_document_does_not_mount() {
        // Regression guard: a stale registry entry (path already deleted
        // from the router) must not panic — flagging that drift is review's
        // job, not this function's to fail on it.
        let mut doc = OpenApi::default();
        apply_registry_to_openapi(SAMPLE_REGISTRY, &mut doc);
        assert!(doc.paths.paths.is_empty());
    }

    #[test]
    fn apply_to_openapi_over_the_real_empty_registry_is_a_no_op() {
        let mut doc = doc_with_get("/api/v1/sidebar/get");
        apply_to_openapi(&mut doc);
        let op = doc.paths.paths["/api/v1/sidebar/get"].get.as_ref().unwrap();
        assert!(op.deprecated.is_none());
        assert!(op.extensions.is_none());
    }

    /// A7 (BSV-F19) — the `Deprecation` header must be an RFC 9745 Structured
    /// Field Date, and the deprecation instant must be at or before the
    /// `Sunset` instant it announces.
    #[test]
    fn deprecation_header_is_an_rfc9745_sf_date() {
        for entry in SAMPLE_REGISTRY.iter().chain(DEPRECATED_PATHS) {
            let value = format!("@{}", entry.deprecated_at);
            assert!(
                value.len() > 1
                    && value.starts_with('@')
                    && value[1..].chars().all(|c| c.is_ascii_digit()),
                "{}: Deprecation must be `@<epoch seconds>`, got {value:?} (RFC 9745)",
                entry.path
            );
            let sunset = chrono::DateTime::parse_from_rfc2822(entry.sunset)
                .unwrap_or_else(|e| {
                    panic!("{}: unparseable Sunset {:?}: {e}", entry.path, entry.sunset)
                })
                .timestamp();
            assert!(
                entry.deprecated_at <= sunset,
                "{}: deprecated_at ({}) must not be after sunset ({sunset})",
                entry.path,
                entry.deprecated_at
            );
        }
    }

    /// A7 — a URI replacement is linked (`rel="deprecation"`); a reason
    /// sentence, which has no URI, gets no `Link` rather than an invented one.
    #[test]
    fn a_uri_replacement_is_linked_and_a_reason_sentence_is_not() {
        let mut linked = axum::http::HeaderMap::new();
        apply_headers(&SAMPLE_PATH, &mut linked);
        assert_eq!(linked.get("deprecation").unwrap(), "@1750000000");
        assert_eq!(
            linked.get("link").unwrap(),
            "</api/v1/widgets/list>; rel=\"deprecation\""
        );
        assert_eq!(
            linked.get("sunset").unwrap(),
            "Sat, 29 Aug 2026 00:00:00 GMT"
        );

        const REASON_ONLY: DeprecatedPath = DeprecatedPath {
            path: "/api/v1/widgets/gone",
            deprecated_at: 1_750_000_000,
            sunset: "Sat, 29 Aug 2026 00:00:00 GMT",
            replacement: "none: no grid-editor equivalent",
        };
        let mut reason = axum::http::HeaderMap::new();
        apply_headers(&REASON_ONLY, &mut reason);
        assert_eq!(reason.get("deprecation").unwrap(), "@1750000000");
        assert!(
            reason.get("link").is_none(),
            "a reason sentence has no URI to link"
        );
    }
}

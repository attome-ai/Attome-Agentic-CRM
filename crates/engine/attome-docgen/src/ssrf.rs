//! SSRF-shaped guard for rendered document HTML.
//!
//! The render sidecar drives a real headless Chrome instance
//! (`pdf-chrome-dev`/`deploy/docgen-render-service.md`) which, left
//! unguarded, will happily fetch any resource a rendered page references —
//! `<img src>`, `<link href>`, `<script src>`, `<iframe src>`, CSS
//! `url(...)` — exactly the SSRF vector `attome-webcrawl::safety` and
//! `attome-events`' webhook delivery (`attome_server::ssrf_guard`) already guard
//! for their own outbound fetches (D-463 / plan §3 "Security"). This module
//! is the same discipline applied to a different trigger: instead of
//! screening one admin-supplied URL before a `reqwest` call, it screens
//! every resource reference embedded in HTML before that HTML is ever
//! handed to Chrome.
//!
//! Scoped to the **fully-merged** HTML (called after `merge::render_template`,
//! never on the raw template body alone) — a merge field is exactly as
//! capable of smuggling an external URL into the document as the template
//! author is, since its value comes from record data an editor doesn't
//! control at template-authoring time.
//!
//! Phase 1 policy is deliberately blunt: **any** absolute `http(s):`/`//`
//! (protocol-relative) reference in a resource-loading attribute or a CSS
//! `url(...)` blocks the whole render. There is no legitimate Phase 1 use
//! case for a generated document fetching arbitrary external content — an
//! image belongs in the template as a `data:` URI, or the deployment adds an
//! explicit allowlist in a later phase. Reject, not silently strip: a
//! silently-dropped image is a confusing rendered document; a clear
//! validation error tells the template author what to fix.
use attome_types::AppError;
use regex::Regex;
use std::sync::LazyLock;

/// `src="http://..."` / `href="https://..."` on the resource-loading
/// attributes Chrome will actually fetch for. Deliberately NOT `href` in
/// general (an `<a href="https://...">` in a PDF is an inert, non-fetched
/// hyperlink — blocking it would reject completely ordinary "see policy at
/// https://…" template text for no security benefit); `link`/`script`
/// /`iframe` DO use `href`/`src` as fetch triggers, so their occurrences are
/// still caught by the attribute-name-agnostic `src=`/CSS branches below,
/// and `<link href=...>` specifically by its own arm.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
static RESOURCE_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\bsrc\s*=\s*["']|<link\b[^>]*\bhref\s*=\s*["']|url\(\s*["']?)((?:https?:)?//[^"')\s]+)"#,
    )
    .expect("static regex")
});

/// Returns every blocked external resource reference found in `html`, empty
/// when none. Callers treat any non-empty result as a hard render failure
/// (see `render::process`) — see this module's doc comment for why reject
/// rather than strip.
pub fn find_blocked_resource_urls(html: &str) -> Vec<String> {
    RESOURCE_URL_RE
        .captures_iter(html)
        .map(|c| c[1].to_string())
        .collect()
}

/// Fails closed with a validation error naming the first blocked reference
/// when [`find_blocked_resource_urls`] finds any.
pub fn guard(html: &str) -> Result<(), AppError> {
    let blocked = find_blocked_resource_urls(html);
    if let Some(first) = blocked.first() {
        return Err(AppError::Validation(format!(
            "rendered document references an external resource ({first}), which the render \
             sidecar is not permitted to fetch (SSRF guard) — embed images as data: URIs instead"
        )));
    }
    Ok(())
}

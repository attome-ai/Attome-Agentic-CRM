//! Regression proof for `attome_docgen::ssrf` (M57 Phase 1, D-463): the render
//! sidecar must never be handed HTML that references an external resource,
//! because a real headless-Chrome instance will happily fetch it — exactly
//! the SSRF vector `attome-webcrawl::safety`/`attome_server::ssrf_guard` already
//! guard for their own outbound calls, applied here to embedded resource
//! references instead of an admin-supplied URL.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_docgen::ssrf::{find_blocked_resource_urls, guard};

#[test]
fn an_absolute_http_img_src_is_blocked() {
    let html = r#"<img src="http://evil.example.com/track.png">"#;
    assert!(guard(html).is_err());
    assert_eq!(
        find_blocked_resource_urls(html),
        vec!["http://evil.example.com/track.png"]
    );
}

#[test]
fn an_absolute_https_img_src_is_blocked() {
    let html = r#"<img src="https://evil.example.com/track.png">"#;
    assert!(guard(html).is_err());
}

#[test]
fn a_protocol_relative_resource_reference_is_blocked() {
    let html = r#"<script src="//evil.example.com/x.js"></script>"#;
    assert!(guard(html).is_err());
}

#[test]
fn a_link_stylesheet_href_is_blocked() {
    let html = r#"<link rel="stylesheet" href="https://evil.example.com/style.css">"#;
    assert!(guard(html).is_err());
}

#[test]
fn a_css_background_url_is_blocked() {
    let html = r#"<div style="background: url('https://evil.example.com/bg.png')"></div>"#;
    assert!(guard(html).is_err());
}

#[test]
fn an_iframe_src_is_blocked() {
    let html = r#"<iframe src="https://evil.example.com/"></iframe>"#;
    assert!(guard(html).is_err());
}

#[test]
fn a_data_uri_image_is_allowed() {
    let html = r#"<img src="data:image/png;base64,iVBORw0KGgo=">"#;
    assert!(guard(html).is_ok());
}

#[test]
fn an_ordinary_hyperlink_is_never_fetched_and_is_allowed() {
    // `<a href="https://...">` is an inert, non-fetched hyperlink in a
    // rendered PDF — blocking it would reject completely ordinary template
    // text ("see our policy at https://...") for no security benefit. See
    // ssrf.rs's own doc comment for why `href` is deliberately excluded
    // except on `<link>`.
    let html = r#"<p>See our policy at <a href="https://example.com/policy">this link</a>.</p>"#;
    assert!(guard(html).is_ok());
    assert!(find_blocked_resource_urls(html).is_empty());
}

#[test]
fn plain_text_mentioning_a_url_with_no_markup_is_allowed() {
    let html = "<p>Visit https://example.com for more information.</p>";
    assert!(guard(html).is_ok());
}

#[test]
fn a_relative_image_path_is_allowed() {
    // Not a network fetch outside the render sidecar's own control in the
    // same sense an absolute/protocol-relative URL is; Phase 1's blunt
    // policy only targets absolute/protocol-relative references (ssrf.rs's
    // documented scope).
    let html = r#"<img src="logo.png">"#;
    assert!(guard(html).is_ok());
}

#[test]
fn the_guard_error_names_the_first_blocked_url() {
    let html =
        r#"<img src="https://one.example.com/a.png"><img src="https://two.example.com/b.png">"#;
    let err = guard(html).unwrap_err();
    assert!(err.to_string().contains("one.example.com"));
}

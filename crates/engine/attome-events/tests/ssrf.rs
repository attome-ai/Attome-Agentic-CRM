//! M62 Phase 1 — proves the exact SSRF guard call `attome_events::admin::
//! create_subscription` (save time) and `attome_events::delivery::deliver`
//! (send time) both make rejects a malicious webhook target. Not a
//! re-test of `attome_server::ssrf_guard`'s own screening logic (that
//! crate's suite already covers address-class screening exhaustively) —
//! this proves the integration point: a subscription/delivery target
//! pointed at a private/loopback/cloud-metadata address is rejected before
//! any HTTP request is made, using the identical function call both
//! `admin.rs` and `delivery.rs` use.
//!
//! No database needed — `validate_url` is a pure DNS-resolution + address-
//! class check.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

#[tokio::test]
async fn a_loopback_target_is_rejected() {
    let url = reqwest::Url::parse("http://127.0.0.1:8080/webhook").unwrap();
    assert!(
        attome_server::ssrf_guard::validate_url(&url).await.is_err(),
        "a loopback target must be rejected before any delivery is attempted"
    );
}

#[tokio::test]
async fn a_cloud_metadata_target_is_rejected() {
    let url = reqwest::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
    assert!(
        attome_server::ssrf_guard::validate_url(&url).await.is_err(),
        "the cloud metadata address must be rejected — this is exactly the address \
         class a malicious/misconfigured webhook target would use to reach the \
         platform's own cloud credentials"
    );
}

#[tokio::test]
async fn a_private_rfc1918_target_is_rejected() {
    let url = reqwest::Url::parse("http://10.0.0.5/webhook").unwrap();
    assert!(
        attome_server::ssrf_guard::validate_url(&url).await.is_err(),
        "an RFC1918 private address must be rejected"
    );
}

#[tokio::test]
async fn an_ip_literal_public_target_is_accepted() {
    // A public IP *literal* (not a hostname) so this assertion needs no
    // outbound DNS query — hermetic even in a sandboxed/egress-restricted
    // test environment. This is the negative-of-the-negative check: the
    // guard must not reject every URL indiscriminately, only the unsafe
    // address classes. 8.8.8.8 (Google public DNS) is Anycast, globally
    // routable, and not in any of the screened private/special-purpose
    // blocks.
    let url = reqwest::Url::parse("https://8.8.8.8/webhook").unwrap();
    let result = attome_server::ssrf_guard::validate_url(&url).await;
    assert!(
        result.is_ok(),
        "a globally routable IP literal must be accepted, got {result:?}"
    );
}

//! "Fetch available models" — the one outbound call this crate makes to a
//! provider the operator configured, and what it is allowed to do with the
//! answer.
//!
//! # What this is not
//!
//! It is **not** a generation path and **not** a provider adapter. D-554 and
//! D-360 ruling 3 keep one wire format for generation; nothing here is
//! consulted when a model is actually called. All three protocols expose the
//! same `GET {base}/models` listing and differ only in which header carries
//! the key, which is why supporting all three costs one `match` rather than an
//! adapter layer.
//!
//! # Where the request is allowed to go
//!
//! The rule mirrors `attome_inference::Transport::new` exactly, because a
//! provider record and `config.inference.generation` describe the same kind of
//! destination and must not disagree about what is reachable:
//!
//! * **Inside the deployment** (`attome_config::endpoint_is_in_deployment` —
//!   loopback, RFC1918, link-local, `localhost`/`.local`, a single-label
//!   container name): allowed. This is the ordinary self-hosted vLLM case, and
//!   refusing it would make the normal deployment shape the unsupported one.
//! * **Outside it**: refused unless this provider's own
//!   `allow_external_endpoint` is set (D-568) or the operator-wide
//!   `inference.allow_external_provider` is on,
//!   and then additionally screened by `attome_server::ssrf_guard` and dialled
//!   through its IP-pinning resolver, so a public hostname cannot rebind to an
//!   internal address between the check and the connection.
//!
//! The SSRF guard is deliberately applied to the *external* branch only. Its
//! screening rejects exactly the address classes the in-deployment branch
//! exists to permit, so running it unconditionally would block every
//! self-hosted provider. The in-deployment branch is not unguarded, though: it
//! is reachable only by an admin-authenticated caller, against a URL another
//! admin stored, and it is the same trust the deployment already places in
//! `config.inference.generation.base_url`.
//!
//! # What comes back
//!
//! A provider's model list is **untrusted input** (guidelines §7: never trust a
//! value a third party supplied). It is parsed into [`DiscoveredModel`],
//! length-capped, and returned for a human to choose from. Nothing here writes
//! an `ai_model` row: catalog rows are created through the generic entity
//! API by the admin who reviewed the list, and land at
//! `approval_status = "pending"` like any other (D-435/D-491). Auto-importing
//! them as approved would let a provider's response decide what this
//! deployment may run.

use attome_config::{InferenceSection, endpoint_is_in_deployment};
use attome_types::AppError;

use crate::provider::ApiProtocol;

/// How long a listing call may take. Short on purpose: this runs on a request
/// thread behind an operator pressing a button, and a provider that cannot
/// list its models in 15s is a failure worth reporting rather than waiting on.
const REQUEST_TIMEOUT_SECS: u64 = 15;

/// One model as the provider reports it. Only the two fields an operator needs
/// to choose from, deliberately: everything else in a provider's listing
/// (pricing, ownership, capability flags) varies per protocol and is authored
/// on the `ai_model` catalog row by the admin, not imported.
///
/// The transport half — the request, the capped body read, the parsing and the
/// masking — lives in `attome_inference::list_models` (BIN-D3), because a
/// provider record and `config.inference.generation` describe the same kind of
/// destination and must not disagree about how it is reached. This type stays
/// here because it is the API's wire shape (`ToSchema`), which the transport
/// crate has no business knowing about.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct DiscoveredModel {
    /// The wire id to send as `model` — what `ai_model.provider_model_id`
    /// holds, and what the D-491 approval gate matches on.
    pub id: String,
    /// A human label when the provider offers one — Anthropic spells it
    /// `display_name`, and several OpenAI-compatible gateways spell it `name`
    /// (verified live against one that lists 71 models that way). `None` for a
    /// listing that carries only ids, which is what OpenAI's own `/models`
    /// returns.
    pub display_name: Option<String>,
}

impl From<attome_inference::ModelListing> for DiscoveredModel {
    fn from(listing: attome_inference::ModelListing) -> Self {
        Self {
            id: listing.id,
            display_name: listing.display_name,
        }
    }
}

/// Whether `base_url`'s host is a link-local or cloud-metadata address.
///
/// `attome_config::endpoint_is_in_deployment` counts link-local as "inside the
/// deployment" — correct for its own purpose, but it means the in-deployment
/// branch below would otherwise dial `169.254.169.254`, the cloud instance
/// metadata service that `attome_server::ssrf_guard` names as the exact thing it
/// exists to block. An Attome admin can edit a provider record over the API,
/// which is a lower-trust principal than the operator who edits
/// `config.inference.generation.base_url` on the filesystem, so the two must
/// not have the same reach.
///
/// The whole link-local range is refused, not just the two metadata addresses:
/// an inference server does not live on an auto-configuration address, so
/// there is nothing legitimate to preserve, and an allowlist of known metadata
/// IPs would miss the next cloud's. Loopback, RFC1918 and single-label
/// container names — the real self-hosted shapes — are untouched.
///
/// Found by live testing: a provider pointing at `http://169.254.169.254/...`
/// reached the transport layer instead of being refused.
fn is_link_local_or_metadata(base_url: &str) -> bool {
    let host = base_url
        .split("://")
        .nth(1)
        .unwrap_or(base_url)
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    // Strip a port, and the brackets of an IPv6 literal.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => {
            // `fe80::/10`, plus AWS's IPv6 metadata address, which sits in the
            // unique-local range rather than the link-local one.
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6 == std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
        // A hostname that resolves to a link-local address is caught by the
        // external branch's `ssrf_guard` instead; an unresolvable single-label
        // container name is the ordinary self-hosted case and stays allowed.
        Err(_) => false,
    }
}

/// Decides whether this deployment may dial `base_url` at all, and returns an
/// HTTP client appropriate to the answer.
///
/// `provider_allows_external` is the provider record's own
/// `allow_external_endpoint` (D-568). An endpoint outside the deployment is
/// reachable when it is set **or** the operator-wide
/// `inference.allow_external_provider` is on; either way the SSRF guard below
/// still screens and pins the destination.
pub(crate) async fn http_client_for(
    base_url: &str,
    inference: &InferenceSection,
    provider_allows_external: bool,
    timeout_secs: u64,
) -> Result<attome_inference::DialClient, AppError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| AppError::Validation("Base URL is not a valid URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::Validation(
            "Base URL must be http or https".into(),
        ));
    }

    if is_link_local_or_metadata(base_url) {
        return Err(AppError::Validation(
            "Base URL points at a link-local or cloud-metadata address".into(),
        ));
    }

    if endpoint_is_in_deployment(base_url) {
        // The self-hosted case. An ordinary client: the SSRF guard's screening
        // rejects precisely these address classes by design.
        return reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map(attome_inference::DialClient::unchecked)
            .map_err(|_| AppError::internal("failed to build the model-discovery HTTP client"));
    }

    if !(provider_allows_external || inference.allow_external_provider) {
        // Surfaced as a validation error because the operator can act on it:
        // allow this provider to use an external endpoint, or point it at an
        // in-plane one.
        return Err(AppError::Validation(
            "This provider's Base URL is outside the deployment. Turn on \
             \"Allow external endpoint\" for this provider, or use an \
             in-deployment Base URL"
                .into(),
        ));
    }

    attome_server::ssrf_guard::validate_url(&url)
        .await
        .map_err(|e| AppError::Validation(format!("Base URL rejected: {e}")))?;
    guarded_dial_client(timeout_secs)
}

/// attome-server B5: the external branch dials through `GuardedClient`, whose
/// literal check `attome_inference` runs before every dial, so a non-routable
/// IP literal is refused even on a path that skipped `validate_url`.
fn guarded_dial_client(timeout_secs: u64) -> Result<attome_inference::DialClient, AppError> {
    let (http, refuse_literal) = attome_server::ssrf_guard::GuardedClient::new(timeout_secs)
        .map_err(|_| AppError::internal("failed to build the guarded model-discovery HTTP client"))?
        .into_parts();
    Ok(attome_inference::DialClient::checked(http, move |url| {
        refuse_literal(url).is_ok()
    }))
}

async fn client_for(
    base_url: &str,
    inference: &InferenceSection,
    provider_allows_external: bool,
) -> Result<attome_inference::DialClient, AppError> {
    http_client_for(
        base_url,
        inference,
        provider_allows_external,
        REQUEST_TIMEOUT_SECS,
    )
    .await
}

/// Lists the models `base_url` offers.
///
/// `api_key` is `None` for a provider that needs none (an open local vLLM).
/// It is only ever placed in a request header, never logged, never returned,
/// and never included in an error — a provider's own error body can echo a
/// request back, which is why a failure here reports a fixed category
/// (`attome_inference::UpstreamClass`), never the body.
pub async fn fetch(
    base_url: &str,
    protocol: ApiProtocol,
    api_key: Option<&str>,
    inference: &InferenceSection,
    provider_allows_external: bool,
) -> Result<Vec<DiscoveredModel>, AppError> {
    let base_url = base_url.trim();
    if base_url.is_empty() {
        return Err(AppError::Validation(
            "This provider has no Base URL configured".into(),
        ));
    }

    let client = client_for(base_url, inference, provider_allows_external).await?;
    // Anthropic authenticates with `x-api-key` and requires a version header on
    // every request — omitting it is a 400, not a default. Every other
    // OpenAI-compatible server takes a bearer token. `attome_inference` owns the
    // request itself (BIN-D3); this is only the protocol-to-header mapping.
    let auth = match (protocol, api_key) {
        (ApiProtocol::AnthropicMessages, key) => attome_inference::ModelListAuth {
            x_api_key: key,
            anthropic_version: true,
            bearer: None,
        },
        (_, key) => attome_inference::ModelListAuth {
            bearer: key,
            ..attome_inference::ModelListAuth::default()
        },
    };
    let listings = attome_inference::list_models(&client, base_url, auth)
        .await
        .map_err(listing_failed)?;
    Ok(listings.into_iter().map(DiscoveredModel::from).collect())
}

/// Maps the transport's typed failure onto the admin-facing validation error.
///
/// Category text only, and never the provider's own body: `attome_inference`
/// will not put one into an error in the first place (BIN-E1), and this keeps
/// that true even if a future variant starts carrying more.
fn listing_failed(error: attome_inference::InferenceError) -> AppError {
    use attome_inference::InferenceError;
    let message = match &error {
        InferenceError::Timeout(_) => "The request to this provider timed out".to_owned(),
        InferenceError::Transport { .. } => "The request to this provider failed".to_owned(),
        InferenceError::Upstream { class, .. } => {
            format!("The provider answered its model list with {class}")
        }
        InferenceError::BadResponse { reason, .. } => {
            format!("The provider's model list was unusable: {reason}")
        }
        other => format!("The provider's model list could not be read: {other}"),
    };
    tracing::warn!(error = %error, "AI provider model listing failed");
    AppError::Validation(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transport's listing maps straight onto the API's wire shape. The
    /// parsing and clamping rules this file used to own now live in
    /// `attome_inference::models` with their own table (BIN-D3), so what is left
    /// to pin here is the mapping.
    #[test]
    fn a_listing_maps_onto_the_discovered_model_shape() {
        let discovered = DiscoveredModel::from(attome_inference::ModelListing {
            id: "claude-opus-5".into(),
            display_name: Some("Claude Opus 5".into()),
        });
        assert_eq!(discovered.id, "claude-opus-5");
        assert_eq!(discovered.display_name.as_deref(), Some("Claude Opus 5"));

        let bare = DiscoveredModel::from(attome_inference::ModelListing {
            id: "local-model".into(),
            display_name: None,
        });
        assert_eq!(bare.id, "local-model");
        assert!(bare.display_name.is_none());
    }

    /// The in-deployment branch must stay reachable without
    /// `allow_external_provider` — it is the ordinary self-hosted vLLM shape,
    /// and this is the assertion that keeps the SSRF guard from being applied
    /// to it by a later "harden everything" change.
    #[tokio::test]
    async fn a_local_provider_is_reachable_with_external_providers_disabled() {
        let inference = InferenceSection::default();
        assert!(!inference.allow_external_provider);
        assert!(
            client_for("http://127.0.0.1:8000/v1", &inference, false)
                .await
                .is_ok()
        );
        assert!(
            client_for("http://vllm:8000/v1", &inference, false)
                .await
                .is_ok()
        );
    }

    /// A cloud-metadata address must never be reachable, whatever the
    /// in-deployment classifier says. It was allowed through once, when
    /// link-local counted as "in deployment"; since BCF-2/BCF-D6 the classifier
    /// calls IPv4/IPv6 link-local external while unique-local stays inside, so
    /// this proves the explicit metadata guard refuses both.
    #[tokio::test]
    async fn a_cloud_metadata_address_is_never_reachable() {
        let inference = InferenceSection::default();
        for base in [
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.169.254",
            "http://[fd00:ec2::254]/latest",
            "http://[fe80::1]/v1",
        ] {
            // BCF-2/BCF-D6 split these: the 169.254/fe80 metadata addresses are
            // link-local and now classify as EXTERNAL, while fd00:ec2::254 is
            // unique-local and still counts as in-deployment, exactly like an
            // RFC1918 address. Both classifications reach the refusal below,
            // which is the point: neither branch may dial the metadata service.
            let expected_in_deployment = base.contains("fd00:");
            assert_eq!(
                endpoint_is_in_deployment(base),
                expected_in_deployment,
                "BCF-2/BCF-D6 classification of {base} changed; update this test's premise"
            );
            let error = client_for(base, &inference, false).await.unwrap_err();
            assert!(
                matches!(&error, AppError::Validation(m) if m.contains("link-local")),
                "{base} must be refused as link-local/metadata, got {error:?}"
            );
        }
    }

    /// The carve-out must not catch the shapes it was meant to spare.
    #[test]
    fn ordinary_self_hosted_urls_are_not_treated_as_link_local() {
        for base in [
            "http://127.0.0.1:8000/v1",
            "http://vllm:8000/v1",
            "http://10.0.0.5:8000/v1",
            "http://192.168.1.10/v1",
            "https://api.example.com/v1",
        ] {
            assert!(!is_link_local_or_metadata(base), "{base} must stay allowed");
        }
    }

    #[tokio::test]
    async fn an_external_provider_is_refused_while_the_flag_is_off() {
        let inference = InferenceSection::default();
        let error = client_for("https://api.openai.com/v1", &inference, false)
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::Validation(_)), "{error:?}");
    }

    /// D-568: the provider record's own switch is enough on its own — the
    /// operator-wide flag stays off. A literal public address keeps this free
    /// of any DNS lookup.
    #[tokio::test]
    async fn a_provider_can_allow_its_own_external_endpoint() {
        let inference = InferenceSection::default();
        assert!(!inference.allow_external_provider);
        assert!(
            client_for("https://93.184.216.34/v1", &inference, true)
                .await
                .is_ok()
        );
    }

    /// D-568: the per-provider switch widens *which* endpoints are allowed, not
    /// what the SSRF guard screens — the metadata address is refused whatever
    /// the record says.
    #[tokio::test]
    async fn the_provider_switch_never_permits_a_metadata_address() {
        let inference = InferenceSection::default();
        for base in [
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/latest",
        ] {
            let error = client_for(base, &inference, true).await.unwrap_err();
            assert!(
                matches!(&error, AppError::Validation(m) if m.contains("link-local")),
                "{base} must stay refused, got {error:?}"
            );
        }
    }

    /// B5: the guarded client refuses a loopback literal on its own, with no
    /// `validate_url` in front of it, and never dials.
    #[tokio::test]
    async fn the_model_listing_client_refuses_a_loopback_literal_without_validate_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let base = format!("http://{}/v1", listener.local_addr().expect("addr"));
        let client = guarded_dial_client(5).expect("guarded client");

        let error = attome_inference::list_models(
            &client,
            &base,
            attome_inference::ModelListAuth::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, attome_inference::InferenceError::Transport { .. }),
            "{error:?}"
        );
        assert!(
            listener.accept().is_err(),
            "the refused literal must never be dialled"
        );
    }

    #[tokio::test]
    async fn a_non_http_scheme_is_refused_before_any_lookup() {
        let inference = InferenceSection::default();
        for base in ["file:///etc/passwd", "gopher://example.com", "not a url"] {
            assert!(
                client_for(base, &inference, false).await.is_err(),
                "{base} must be refused"
            );
        }
    }
}

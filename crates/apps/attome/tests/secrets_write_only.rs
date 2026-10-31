//! Q18-T6: stored secrets are write-only. Walks every response schema of
//! `attome::openapi::document()` (and the schemas they reach) for a property
//! named like a secret, and holds each one to a reasoned allow-list:
//!
//! - **shown once, at creation:** a secret the server generates (an API key,
//!   an S2S key, a webhook signing secret, an MFA enrolment, a share link or
//!   portal token) has to reach its owner once; it is never readable again;
//! - **a presence flag or a reference:** `is_set`, `has_*`, a `*_ref` id;
//! - **a hint for a generated key:** the last four characters of a
//!   server-generated, high-entropy key, which tells two keys apart.
//!
//! A user-supplied secret (a provider API key, an integration credential, an
//! environment variable) answers only `is_set` and `updated_at`. A new
//! secret-looking response property fails here until it is listed with its
//! reason, so no route starts returning a stored secret by accident.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeSet, HashSet};

use serde_json::Value;

/// `(schema, property, why it may appear in a response)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "DeviceTokens",
        "access_token",
        "C7-T1/T4-T1: the session the device grant issues, returned once to the device that redeemed it.",
    ),
    (
        "DeviceTokens",
        "refresh_token",
        "C7-T1/T4-T1: the single-use refresh token, returned once; only its hash is stored.",
    ),
    (
        "DeviceTokens",
        "token_type",
        "C7-T1/T4-T1: always `Bearer`, not a secret.",
    ),
    (
        "AnonymousRequestAccepted",
        "status_token",
        "G2-T1: the anonymous submitter's status bearer, generated and shown once; only its hash is stored",
    ),
    (
        "Booked",
        "manage_token",
        "the booker's reschedule/cancel link token, generated for them and also emailed",
    ),
    (
        "PreferenceLink",
        "token",
        "E26-T1: a signed preference-centre link minted for an admin to send; not a stored secret",
    ),
    (
        "PreviewLink",
        "token",
        "a signed content preview link minted on request; not a stored secret",
    ),
    (
        "SessionJoined",
        "token",
        "J9-T2: the customer side's co-browse frame token, generated at join and handed to that side",
    ),
    (
        "SoftphoneConfig",
        "token",
        "a short-lived Voice SDK access token minted per request for the agent's browser; not a stored secret",
    ),
    (
        "ApiKeyCreated",
        "secret",
        "generated API key, shown once at creation",
    ),
    (
        "KeyCreatedResponse",
        "secret",
        "generated S2S key, shown once at creation",
    ),
    (
        "AccountActionResult",
        "secret",
        "generated one-time secret, shown once",
    ),
    (
        "SubscriptionCreatedResponse",
        "webhook_secret",
        "generated signing secret, shown once",
    ),
    (
        "SecretRotatedResponse",
        "webhook_secret",
        "newly generated signing secret, shown once",
    ),
    (
        "SubscriptionCreatedResponse",
        "webhook_secret_standard",
        "M13-T2: the same generated signing secret in Standard Webhooks form (whsec_), shown once",
    ),
    (
        "SecretRotatedResponse",
        "webhook_secret_standard",
        "M13-T2: the new signing secret in Standard Webhooks form (whsec_), shown once",
    ),
    (
        "EmbedToken",
        "token",
        "P8-T1: a short-lived signed viewer link minted per request; nothing is stored",
    ),
    (
        "ExportStatusResponse",
        "stream_token",
        "L7-T5: a change-stream cursor at the export's snapshot, not a credential; reading from it still needs the subscription's own client",
    ),
    (
        "InboundHookView",
        "secret_last4",
        "M14-T1: the last four characters of the hook secret as a hint; the secret itself is never returned",
    ),
    (
        "IssuedScimToken",
        "token",
        "Q3-T1: the generated SCIM bearer token, shown once at issue; only its peppered hash is stored",
    ),
    (
        "OidcProviderItem",
        "secret_set",
        "whether a client secret is set: the is_set this test asks for",
    ),
    (
        "OidcProviderItem",
        "secret_updated_at",
        "when the client secret last changed: the updated_at this test asks for",
    ),
    (
        "OidcProviderItem",
        "secret_fingerprint",
        "the first 8 hex characters of the secret's SHA-256, to tell secrets apart; not the secret",
    ),
    (
        "TokenBody",
        "access_token",
        "the OAuth token endpoint's response (RFC 6749 5.1): a short-lived token minted per request",
    ),
    (
        "TokenBody",
        "token_type",
        "always `Bearer` (RFC 6749 5.1); not a secret",
    ),
    (
        "MfaEnrollment",
        "secret",
        "TOTP seed, shown once to enrol an authenticator",
    ),
    (
        "EnrollResponseBody",
        "secret_base32",
        "portal TOTP seed, shown once to enrol",
    ),
    (
        "CreatedShareLink",
        "token",
        "generated share-link token, shown once",
    ),
    ("CreatedShareLink", "has_password", "presence flag"),
    (
        "CreateWorkRequestFromOfferingResponse",
        "portal_token",
        "generated portal token for the requester",
    ),
    (
        "SendMessageResponse",
        "session_token",
        "web chat session token for the visitor",
    ),
    (
        "KeySummary",
        "secret_last4",
        "hint for a generated, high-entropy S2S key",
    ),
    ("McpServerView", "has_credential", "presence flag"),
    (
        "SystemCreatedResponse",
        "credential_configured",
        "presence flag",
    ),
    (
        "TargetListItem",
        "credential_ref",
        "reference to a stored credential, not the credential",
    ),
    (
        "ComplianceModelRow",
        "prompt_tokens",
        "token counts, not a credential",
    ),
    (
        "ComplianceModelRow",
        "completion_tokens",
        "token counts, not a credential",
    ),
    (
        "GovernanceView",
        "max_tokens_per_session",
        "a token budget, not a credential",
    ),
    (
        "ModelCard",
        "max_output_tokens",
        "a token limit, not a credential",
    ),
    ("ThemeRow", "tokens", "design tokens, not a credential"),
];

/// A property name that may carry a secret.
fn looks_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "private_key",
        "credential",
        "passphrase",
        "api_key",
        "token",
    ]
    .iter()
    .any(|word| name.contains(word))
}

fn refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if key == "$ref" {
                    if let Some(name) = inner.as_str().and_then(|r| r.rsplit('/').next()) {
                        out.insert(name.to_owned());
                    }
                } else {
                    refs(inner, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| refs(item, out)),
        _ => {}
    }
}

/// Every `(schema, property)` named like a secret in a schema a response
/// reaches.
fn secret_looking_response_properties(document: &Value) -> BTreeSet<(String, String)> {
    let schemas = &document["components"]["schemas"];
    let mut pending = BTreeSet::new();
    for operations in document["paths"]
        .as_object()
        .into_iter()
        .flat_map(|p| p.values())
    {
        for operation in operations.as_object().into_iter().flat_map(|o| o.values()) {
            refs(&operation["responses"], &mut pending);
        }
    }
    let mut seen = HashSet::new();
    let mut found = BTreeSet::new();
    while let Some(name) = pending.pop_first() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let schema = &schemas[&name];
        if let Some(properties) = schema["properties"].as_object() {
            for property in properties.keys() {
                if looks_secret(property) {
                    found.insert((name.clone(), property.clone()));
                }
            }
        }
        let mut inner = BTreeSet::new();
        refs(schema, &mut inner);
        pending.extend(inner.into_iter().filter(|n| !seen.contains(n)));
    }
    found
}

#[test]
fn no_response_returns_a_stored_secret() {
    let document =
        serde_json::to_value(&*attome::openapi::document()).expect("the document serialises");
    let found = secret_looking_response_properties(&document);
    let allowed: BTreeSet<(String, String)> = ALLOWED
        .iter()
        .map(|(schema, property, _)| ((*schema).to_owned(), (*property).to_owned()))
        .collect();
    let unexplained: Vec<_> = found.difference(&allowed).collect();
    assert!(
        unexplained.is_empty(),
        "a response carries a secret-looking property with no listed reason; return `is_set` and \
         `updated_at` for a stored secret, or list it in ALLOWED with why: {unexplained:?}"
    );
    let stale: Vec<_> = allowed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "ALLOWED lists properties no response has any more; remove them: {stale:?}"
    );
}

#[test]
fn user_supplied_credentials_answer_is_set_not_a_hint() {
    let document =
        serde_json::to_value(&*attome::openapi::document()).expect("the document serialises");
    let schemas = &document["components"]["schemas"];
    for name in ["SetCredentialResponse", "RotateCredentialResponse"] {
        let properties = schemas[name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{name} is in the document"));
        assert!(properties.contains_key("is_set"), "{name}");
        assert!(properties.contains_key("updated_at"), "{name}");
        assert!(!properties.contains_key("secret_last4"), "{name}");
    }
}

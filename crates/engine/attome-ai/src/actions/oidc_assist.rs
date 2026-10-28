//! Q1-T13: `identity.propose_oidc_provider`, a read-only assist for an
//! administrator adding a sign-in provider. Given an issuer URL it reads the
//! provider's discovery document (`{issuer}/.well-known/openid-configuration`)
//! through the guarded outbound client (public addresses only, no
//! redirects, 5 s, at most [`MAX_DISCOVERY_BYTES`]) and answers a draft: the
//! matching preset, the settings the add-provider form takes (never a
//! secret), the endpoints it found, what to map the groups claim from, and
//! warnings. Nothing is saved: the person saves the draft through the
//! provider routes, which this action never calls.

use std::future::Future;
use std::pin::Pin;

use attome_auth::oidc_presets::{PRESETS, PresetKind};
use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const IDENTITY_PROPOSE_OIDC: &str = "identity.propose_oidc_provider";

/// The largest discovery document read.
pub const MAX_DISCOVERY_BYTES: usize = 256 * 1024;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            IDENTITY_PROPOSE_OIDC,
            "Read an OpenID Connect provider's discovery document from its issuer URL and \
             draft the provider settings to add it (preset, scopes, claim names, the groups \
             claim to map), with warnings. Saves nothing: a person reviews the draft and adds \
             the provider and its client secret.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &["system.admin"],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": {
    "issuer": {"type": "string", "maxLength": 500, "description": "The provider's issuer URL, https, without a trailing slash."}
  },
  "required": ["issuer"],
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ProposeOidc)]
}

/// Whether `issuer` fits `template`, where each `{name}` stands for one or
/// more characters other than `/`. Pure.
pub fn template_matches(template: &str, issuer: &str) -> bool {
    fn go(t: &str, s: &str) -> bool {
        match t.find('{') {
            None => t == s,
            Some(open) => {
                let Some(close) = t[open..].find('}').map(|c| open + c) else {
                    return t == s;
                };
                let (lit, rest) = (&t[..open], &t[close + 1..]);
                let Some(after) = s.strip_prefix(lit) else {
                    return false;
                };
                // The placeholder takes one or more characters up to the next
                // '/', split only on character boundaries.
                let limit = after.find('/').unwrap_or(after.len());
                after[..limit]
                    .char_indices()
                    .skip(1)
                    .map(|(i, _)| i)
                    .chain(std::iter::once(limit))
                    .filter(|n| *n > 0)
                    .any(|n| go(rest, &after[n..]))
            }
        }
    }
    go(template, issuer)
}

/// The literal text of `template` outside its placeholders. Pure.
fn literal_len(template: &str) -> usize {
    let mut len = 0;
    let mut inside = false;
    for c in template.chars() {
        match c {
            '{' => inside = true,
            '}' => inside = false,
            _ if !inside => len += c.len_utf8(),
            _ => {}
        }
    }
    len
}

/// The direct-OIDC preset `issuer` fits, the most specific first. A template
/// that is a placeholder host and nothing more (`https://{domain}`) fits
/// every issuer, so it is never taken as a match. Pure.
pub fn preset_for(issuer: &str) -> Option<&'static attome_auth::oidc_presets::OidcPreset> {
    PRESETS
        .iter()
        .filter(|p| p.kind == PresetKind::Oidc)
        .filter(|p| literal_len(p.issuer_template) > "https://".len())
        .filter(|p| template_matches(p.issuer_template, issuer))
        .max_by_key(|p| literal_len(p.issuer_template))
}

/// A provider key from the issuer's host: lowercase letters, digits and
/// `-`, 2 to 40 characters. Pure.
fn suggested_key(issuer: &str, preset: Option<&str>) -> String {
    if let Some(preset) = preset {
        return preset.to_owned();
    }
    let host = issuer
        .split("://")
        .nth(1)
        .unwrap_or(issuer)
        .split(['/', ':'])
        .next()
        .unwrap_or_default();
    let mut key: String = host
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    key.truncate(40);
    if key.len() < 2 {
        "sign-in".to_owned()
    } else {
        key
    }
}

fn strings(v: &Value, name: &str) -> Vec<String> {
    v.get(name)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The draft for `issuer` from its discovery document. Pure.
pub fn propose(issuer: &str, discovery: &Value) -> Value {
    let issuer = issuer.trim_end_matches('/');
    let preset = preset_for(issuer);
    let mut warnings: Vec<String> = Vec::new();

    let doc_issuer = discovery.get("issuer").and_then(Value::as_str);
    if doc_issuer != Some(issuer) {
        warnings.push(format!(
            "The document names the issuer {}, not {issuer}; sign-in refuses a mismatch.",
            doc_issuer.unwrap_or("(none)")
        ));
    }
    let endpoint = |name: &str| {
        discovery
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let endpoints = json!({
        "authorization_endpoint": endpoint("authorization_endpoint"),
        "token_endpoint": endpoint("token_endpoint"),
        "jwks_uri": endpoint("jwks_uri"),
        "end_session_endpoint": endpoint("end_session_endpoint"),
        "backchannel_logout_supported": discovery.get("backchannel_logout_supported").and_then(Value::as_bool).unwrap_or(false),
    });
    for name in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        match endpoint(name) {
            None => warnings.push(format!("The document has no {name}; sign-in needs it.")),
            Some(url) if !url.starts_with("https://") => {
                warnings.push(format!("{name} is not https; sign-in refuses it."))
            }
            Some(_) => {}
        }
    }
    if endpoint("end_session_endpoint").is_none() {
        warnings.push(
            "No end_session_endpoint: signing out of Attome will not sign out of the provider."
                .to_owned(),
        );
    }

    let supported_scopes = strings(discovery, "scopes_supported");
    let wanted: Vec<&str> = preset
        .map_or(&["openid", "email", "profile"][..], |p| p.scopes)
        .to_vec();
    let scopes: Vec<String> = wanted
        .iter()
        .filter(|s| supported_scopes.is_empty() || supported_scopes.iter().any(|x| x == *s))
        .map(|s| (*s).to_owned())
        .collect();
    if !scopes.iter().any(|s| s == "openid") {
        warnings.push("The provider does not list the openid scope.".to_owned());
    }

    let claims_supported = strings(discovery, "claims_supported");
    let (email_claim, groups_claim) =
        preset.map_or(("email", "groups"), |p| (p.email_claim, p.groups_claim));
    if !claims_supported.is_empty() && !claims_supported.iter().any(|c| c == email_claim) {
        warnings.push(format!(
            "The provider does not list the {email_claim} claim; sign-in needs an email."
        ));
    }
    let mut claim_map = serde_json::Map::new();
    claim_map.insert("email".into(), json!(email_claim));
    if !groups_claim.is_empty() {
        claim_map.insert("groups".into(), json!(groups_claim));
    }
    if let Some(p) = preset {
        for (field, claim) in [
            ("name", p.profile_claims.name),
            ("phone", p.profile_claims.phone),
        ] {
            if !claim.is_empty() {
                claim_map.insert(field.into(), json!(claim));
            }
        }
        if !p.mfa_acr_values.is_empty() {
            claim_map.insert("mfa_acr".into(), json!(p.mfa_acr_values));
        }
    }

    json!({
        "preset": preset.map(|p| p.key),
        "provider": {
            "key": suggested_key(issuer, preset.map(|p| p.key)),
            "display_name": preset.map_or("Company sign-in", |p| p.display_name),
            "issuer": issuer,
            "scopes": scopes,
            "claim_map": Value::Object(claim_map),
            "link_mode": "link_only",
            "client_id": null,
            "client_secret": null,
        },
        "endpoints": endpoints,
        "group_mappings": {
            "claim": if groups_claim.is_empty() { Value::Null } else { json!(groups_claim) },
            "note": "Map values of this claim to teams or roles under the provider's group mappings after adding it; a mapping can never give system administration.",
        },
        "warnings": warnings,
        "next_steps": [
            "Register Attome at the provider with the redirect URI {frontend}/api/v1/auth/oidc/{key}/callback.",
            "Add the provider with this draft and the client id and secret from the provider.",
            "Add and verify the email domains it signs in.",
        ],
    })
}

/// Reads the discovery document for `issuer`.
async fn fetch_discovery(issuer: &str) -> Result<Value, AppError> {
    if !issuer.starts_with("https://") {
        return Err(AppError::Validation("issuer must be an https URL".into()));
    }
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let parsed = reqwest::Url::parse(&url)
        .map_err(|e| AppError::Validation(format!("issuer rejected: {e}")))?;
    attome_server::ssrf_guard::validate_url(&parsed)
        .await
        .map_err(|e| AppError::Validation(format!("issuer rejected: {e}")))?;
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("oidc-discovery").no_redirects(),
        |b| b.timeout(TIMEOUT),
    )
    .map_err(|_| AppError::internal("the discovery HTTP client could not be built"))?;
    let response = tokio::time::timeout(TIMEOUT, client.get(&url).send())
        .await
        .map_err(|_| AppError::Validation("the provider did not answer within 5 seconds".into()))?
        .map_err(|_| AppError::Validation("the provider could not be reached".into()))?;
    if !response.status().is_success() {
        return Err(AppError::Validation(format!(
            "the discovery document answered {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_DISCOVERY_BYTES as u64)
    {
        return Err(AppError::Validation(
            "the discovery document is too large".into(),
        ));
    }
    let body = tokio::time::timeout(TIMEOUT, response.bytes())
        .await
        .map_err(|_| AppError::Validation("the provider did not answer within 5 seconds".into()))?
        .map_err(|_| AppError::Validation("the discovery document could not be read".into()))?;
    if body.len() > MAX_DISCOVERY_BYTES {
        return Err(AppError::Validation(
            "the discovery document is too large".into(),
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|_| AppError::Validation("the discovery document is not JSON".into()))
}

struct ProposeOidc;

impl Action for ProposeOidc {
    fn id(&self) -> ActionId {
        ActionId(IDENTITY_PROPOSE_OIDC)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let issuer = args["issuer"].as_str().unwrap_or_default().trim();
            let discovery = fetch_discovery(issuer).await?;
            Ok(ActionResult::plain(propose(issuer, &discovery)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propose_matches_keycloak_preset() {
        let issuer = "https://sso.example.sa/realms/attome";
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth"),
            "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
            "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
            "end_session_endpoint": format!("{issuer}/protocol/openid-connect/logout"),
            "backchannel_logout_supported": true,
            "scopes_supported": ["openid", "email", "profile", "roles"],
            "claims_supported": ["sub", "email", "name", "groups"],
        });
        let draft = propose(issuer, &discovery);
        assert_eq!(draft["preset"], "keycloak");
        assert_eq!(draft["provider"]["key"], "keycloak");
        assert_eq!(draft["provider"]["issuer"], issuer);
        assert_eq!(draft["provider"]["claim_map"]["email"], "email");
        assert_eq!(draft["provider"]["claim_map"]["groups"], "groups");
        assert_eq!(draft["group_mappings"]["claim"], "groups");
        assert!(
            draft["provider"]["client_secret"].is_null(),
            "never a secret"
        );
        assert!(
            draft["provider"]["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "openid")
        );
        assert_eq!(draft["endpoints"]["backchannel_logout_supported"], true);
        assert!(draft["warnings"].as_array().unwrap().is_empty(), "{draft}");
    }

    #[test]
    fn a_doubtful_document_is_flagged() {
        let draft = propose(
            "https://idp.example.com",
            &json!({
                "issuer": "https://other.example.com",
                "authorization_endpoint": "http://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/token",
                "claims_supported": ["sub"],
            }),
        );
        assert!(draft["preset"].is_null());
        assert_eq!(draft["provider"]["key"], "idp");
        let warnings = draft["warnings"].to_string();
        for expected in [
            "not https://idp.example.com",
            "authorization_endpoint is not https",
            "no jwks_uri",
            "end_session_endpoint",
            "email claim",
        ] {
            assert!(warnings.contains(expected), "{expected}: {warnings}");
        }
    }

    #[test]
    fn templates_match_one_segment_per_placeholder() {
        assert!(template_matches(
            "https://{keycloak_host}/realms/{realm}",
            "https://sso.example.sa/realms/attome"
        ));
        assert!(!template_matches(
            "https://{keycloak_host}/realms/{realm}",
            "https://sso.example.sa/realms/a/b"
        ));
        assert!(template_matches(
            "https://login.microsoftonline.com/{tenant_id}/v2.0",
            "https://login.microsoftonline.com/0000-1111/v2.0"
        ));
        assert!(template_matches(
            "https://accounts.google.com",
            "https://accounts.google.com"
        ));
        assert!(
            template_matches("https://{h}/x", "https://مثال.sa/x"),
            "a non-ASCII host does not panic"
        );
        // A bare placeholder host fits everything, so it is never a match.
        assert!(preset_for("https://idp.example.com").is_none());
        assert_eq!(
            preset_for("https://accounts.google.com").map(|p| p.key),
            Some("google")
        );
        assert!(!template_matches(
            "https://accounts.google.com",
            "https://accounts.google.com.evil"
        ));
    }
}

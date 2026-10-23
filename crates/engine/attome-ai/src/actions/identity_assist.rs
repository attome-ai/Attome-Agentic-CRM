//! Q2-T5: the identity agent assists, both read-only and for
//! administrators.
//!
//! - `identity.broker_steps`: given an identity provider's SAML metadata
//!   (at most [`MAX_METADATA_BYTES`]), the setup steps for brokering it
//!   into Attome's OIDC sign-in through the chosen broker (Keycloak by
//!   default), with its entity id, single sign-on URL and signing
//!   certificate's SHA-256 fingerprint filled in. The metadata is scanned
//!   as text: no DTD, entity or external reference is ever processed, and
//!   no signature is checked or trusted. Nothing is saved.
//! - `identity.explain_signin_failure`: the last 20 failed sign-in events
//!   (optionally those whose name mentions a provider key), each with a
//!   plain reason.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use base64::Engine;
use serde_json::{Value, json};
use sha2::Digest;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const IDENTITY_BROKER_STEPS: &str = "identity.broker_steps";
pub const IDENTITY_EXPLAIN_FAILURE: &str = "identity.explain_signin_failure";

/// The largest metadata document read.
pub const MAX_METADATA_BYTES: usize = 256 * 1024;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            IDENTITY_BROKER_STEPS,
            "Read an identity provider's SAML metadata XML and list the steps to broker it \
             into Attome's sign-in through a broker (Keycloak by default), with the entity \
             id, single sign-on URL and signing certificate fingerprint filled in. Saves \
             nothing and trusts no signature.",
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
    "metadata_xml": {"type": "string", "maxLength": 262144},
    "broker": {"type": "string", "enum": ["keycloak"]}
  },
  "required": ["metadata_xml"],
  "additionalProperties": false
}"#,
        ),
        ActionDescriptor::new(
            IDENTITY_EXPLAIN_FAILURE,
            "List the last 20 failed sign-ins (optionally those for one identity provider \
             key) with a plain reason for each. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &["system.admin"],
        )
        .input_schema(
            r#"{
  "type": "object",
  "properties": { "provider_key": {"type": "string", "maxLength": 100} },
  "additionalProperties": false
}"#,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Identity(IDENTITY_BROKER_STEPS)),
        Box::new(Identity(IDENTITY_EXPLAIN_FAILURE)),
    ]
}

/// What the metadata says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub entity_id: String,
    /// The HTTP-Redirect or HTTP-POST single sign-on location.
    pub sso_url: Option<String>,
    /// SHA-256 of the signing certificate, `AB:CD:...`.
    pub certificate_sha256: Option<String>,
}

/// One tag's local name and attributes, from `<prefix:Name a="1" b='2'>`.
fn tags(xml: &str) -> Vec<(String, Vec<(String, String)>, usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(open) = xml[i..].find('<').map(|p| p + i) {
        let Some(close) = xml[open..].find('>').map(|p| p + open) else {
            break;
        };
        let inner = &xml[open + 1..close];
        i = close + 1;
        // Comments, declarations, processing instructions and end tags
        // carry nothing read here (and a DTD is never processed).
        if inner.starts_with('!') || inner.starts_with('?') || inner.starts_with('/') {
            continue;
        }
        let name_end = inner
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(inner.len());
        let name = inner[..name_end]
            .rsplit(':')
            .next()
            .unwrap_or_default()
            .to_owned();
        let mut attrs = Vec::new();
        let rest = inner[name_end..].as_bytes();
        let mut j = 0;
        while j < rest.len() {
            while j < rest.len() && (rest[j] as char).is_whitespace() {
                j += 1;
            }
            let key_start = j;
            while j < rest.len() && rest[j] != b'=' && !(rest[j] as char).is_whitespace() {
                j += 1;
            }
            let key = String::from_utf8_lossy(&rest[key_start..j]).to_string();
            while j < rest.len() && (rest[j] as char).is_whitespace() {
                j += 1;
            }
            if j >= rest.len() || rest[j] != b'=' {
                j += 1;
                continue;
            }
            j += 1;
            while j < rest.len() && (rest[j] as char).is_whitespace() {
                j += 1;
            }
            if j >= rest.len() || !(rest[j] == b'"' || rest[j] == b'\'') {
                continue;
            }
            let quote = rest[j];
            j += 1;
            let value_start = j;
            while j < rest.len() && rest[j] != quote {
                j += 1;
            }
            let value = String::from_utf8_lossy(&rest[value_start..j.min(rest.len())]).to_string();
            j += 1;
            let local = key.rsplit(':').next().unwrap_or_default().to_owned();
            if !local.is_empty() {
                attrs.push((local, unescape(&value)));
            }
        }
        out.push((name, attrs, open, close));
    }
    out
}

/// The five predefined XML entities and numeric references only.
fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The SHA-256 of a base64 certificate, colon-separated hex.
pub fn fingerprint(certificate_b64: &str) -> Option<String> {
    let compact: String = certificate_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()?;
    let digest = sha2::Sha256::digest(&der);
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Reads SAML metadata: refuses a document over the limit or with a DTD.
pub fn read_metadata(xml: &str) -> Result<Metadata, String> {
    if xml.len() > MAX_METADATA_BYTES {
        return Err(format!(
            "the metadata is over {} KB",
            MAX_METADATA_BYTES / 1024
        ));
    }
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err("metadata with a DTD or entities is refused".into());
    }
    let all = tags(xml);
    let entity_id = all
        .iter()
        .find(|(n, ..)| n == "EntityDescriptor")
        .and_then(|(_, a, ..)| attr(a, "entityID"))
        .map(str::to_owned)
        .ok_or("no EntityDescriptor entityID")?;
    let sso = all
        .iter()
        .filter(|(n, ..)| n == "SingleSignOnService")
        .map(|(_, a, ..)| a)
        .find(|a| {
            attr(a, "Binding")
                .is_some_and(|b| b.ends_with("HTTP-Redirect") || b.ends_with("HTTP-POST"))
        })
        .and_then(|a| attr(a, "Location"))
        .map(str::to_owned);
    // The signing key's certificate (else the first certificate).
    let mut signing = false;
    let mut certificate = None;
    for (index, (name, attrs, _, close)) in all.iter().enumerate() {
        if name == "KeyDescriptor" {
            signing = attr(attrs, "use").is_none_or(|u| u == "signing");
        }
        if name == "X509Certificate" {
            let text_end = all
                .get(index + 1)
                .map(|(_, _, open, _)| *open)
                .unwrap_or(xml.len());
            let body = xml[close + 1..text_end]
                .split('<')
                .next()
                .unwrap_or_default();
            if signing || certificate.is_none() {
                certificate = Some(body.to_owned());
                if signing {
                    break;
                }
            }
        }
    }
    Ok(Metadata {
        entity_id,
        sso_url: sso,
        certificate_sha256: certificate.as_deref().and_then(fingerprint),
    })
}

/// The broker steps with the metadata's values filled in.
pub fn broker_steps(meta: &Metadata) -> Vec<String> {
    let sso = meta
        .sso_url
        .as_deref()
        .unwrap_or("(the metadata names none: ask the IdP)");
    let cert = meta
        .certificate_sha256
        .as_deref()
        .unwrap_or("(none in the metadata: ask the IdP for its signing certificate)");
    vec![
        "In Keycloak, open the realm that Attome signs in with and add an identity provider of type SAML v2.0.".into(),
        format!("Set the identity provider entity ID to {}.", meta.entity_id),
        format!("Set the single sign-on service URL to {sso}."),
        format!("Turn on signature validation and add the signing certificate; check that its SHA-256 fingerprint is {cert}."),
        "Copy Keycloak's service provider metadata URL for this provider and register it at the IdP as a new SAML application.".into(),
        "Map the IdP's email attribute to the user's email (first login flow: link to an existing account by verified email only).".into(),
        "In Attome, keep the realm's OIDC client as the sign-in provider; sign in once through the new provider to confirm, then check the failed sign-in list if it does not work.".into(),
    ]
}

/// A plain reason for a failed sign-in event's name.
pub fn plain_reason(event_name: &str) -> &'static str {
    let n = event_name.to_ascii_lowercase();
    if n.contains("mfa") || n.contains("totp") || n.contains("step_up") {
        "the second factor was missing or wrong"
    } else if n.contains("spray") || n.contains("challenge") {
        "many failures from one address: a challenge was required"
    } else if n.contains("delay") || n.contains("throttle") || n.contains("lock") {
        "repeated failures for the account: sign-in was slowed"
    } else if n.contains("disabled") || n.contains("inactive") {
        "the account is disabled"
    } else if n.contains("oidc") || n.contains("federat") || n.contains("saml") || n.contains("idp")
    {
        "the identity provider's answer was refused (issuer, audience, signature or state)"
    } else if n.contains("password") || n.contains("credential") || n.starts_with("acct:") {
        "a wrong password for a known account"
    } else if n.starts_with("ip:") {
        "an unknown email or user name"
    } else {
        "a failed sign-in"
    }
}

struct Identity(&'static str);

impl Action for Identity {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            match self.0 {
                IDENTITY_BROKER_STEPS => {
                    let xml = args["metadata_xml"].as_str().unwrap_or_default();
                    let meta = read_metadata(xml).map_err(AppError::Validation)?;
                    Ok(ActionResult::plain(json!({
                        "entity_id": meta.entity_id,
                        "sso_url": meta.sso_url,
                        "certificate_sha256": meta.certificate_sha256,
                        "steps": broker_steps(&meta)
                            .iter()
                            .enumerate()
                            .map(|(i, s)| format!("{}. {s}", i + 1))
                            .collect::<Vec<_>>(),
                    })))
                }
                IDENTITY_EXPLAIN_FAILURE => {
                    let provider = args["provider_key"]
                        .as_str()
                        .map(str::trim)
                        .filter(|p| !p.is_empty());
                    let rows: Vec<(Option<chrono::DateTime<chrono::Utc>>, Option<String>)> =
                        sqlx::query_as(
                            "SELECT changed_on, event_name FROM audit_header \
                              WHERE operation = $1 \
                                AND ($2::text IS NULL OR event_name ILIKE '%' || $2 || '%') \
                              ORDER BY changed_on DESC NULLS LAST LIMIT 20",
                        )
                        .bind(attome_audit::AuditOperation::FailedLogin as i32)
                        .bind(provider)
                        .fetch_all(&state.base.db)
                        .await
                        .map_err(AppError::internal)?;
                    Ok(ActionResult::plain(json!({
                        "failures": rows
                            .iter()
                            .map(|(at, name)| {
                                let name = name.as_deref().unwrap_or_default();
                                json!({ "at": at, "event": name, "reason": plain_reason(name) })
                            })
                            .collect::<Vec<_>>(),
                    })))
                }
                other => Err(AppError::internal(format!(
                    "unknown identity action {other}"
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRA: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor ID="_a1" entityID="https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/"
  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <!-- a comment -->
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>
          AQIDBAUGBwgJCgsMDQ4PEA==
        </X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://login.microsoftonline.com/x/saml2/logout"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://login.microsoftonline.com/72f988bf/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;

    #[test]
    fn broker_steps_extracts_entity_id() {
        let meta = read_metadata(ENTRA).unwrap();
        assert_eq!(
            meta.entity_id,
            "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/"
        );
        assert_eq!(
            meta.sso_url.as_deref(),
            Some("https://login.microsoftonline.com/72f988bf/saml2"),
            "the sign-on service, not the logout one"
        );
        let expected = fingerprint("AQIDBAUGBwgJCgsMDQ4PEA==").unwrap();
        assert_eq!(meta.certificate_sha256.as_deref(), Some(expected.as_str()));
        assert_eq!(expected.split(':').count(), 32);
        let steps = broker_steps(&meta);
        assert!(steps.iter().any(|s| s.contains(&meta.entity_id)));
        assert!(steps.iter().any(|s| s.contains(&expected)));
    }

    #[test]
    fn broker_steps_rejects_oversized_xml() {
        let big = format!(
            "<EntityDescriptor entityID=\"x\">{}</EntityDescriptor>",
            " ".repeat(MAX_METADATA_BYTES)
        );
        assert!(read_metadata(&big).unwrap_err().contains("over"));
        let dtd = "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><EntityDescriptor entityID=\"&e;\"/>";
        assert!(
            read_metadata(dtd).is_err(),
            "a DTD is refused, never resolved"
        );
        assert!(read_metadata("<Other/>").is_err());
    }

    #[test]
    fn identity_failures_get_plain_reasons() {
        assert_eq!(
            plain_reason("acct:0192:ab12"),
            "a wrong password for a known account"
        );
        assert_eq!(plain_reason("ip:ab12"), "an unknown email or user name");
        assert!(plain_reason("login_guard spray challenge").contains("challenge"));
        assert!(
            descriptors()
                .iter()
                .all(|d| d.risk == RiskTier::Read && d.effect == Effect::Read)
        );
    }
}

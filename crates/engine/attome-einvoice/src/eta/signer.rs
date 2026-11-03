//! Signing an ETA document (roadmap AG3-T1).
//!
//! ETA takes a CAdES-BES signature made with the taxpayer's signing
//! certificate, which Egypt's certification authorities issue on a USB
//! token (or an HSM). The Attome server never holds that key: a signer
//! service runs where the token is (a small program on the machine it is
//! plugged into, or the HSM's own service) and Attome asks it to sign:
//!
//! - `POST {base}/sign` with `{"format": "cades-bes", "data": <base64 of
//!   the canonical text>, "digest": <its SHA-256, hex>}` answers
//!   `{"signature": <base64 CMS>}`.
//!
//! The call carries the signer's key as a bearer token. A 5xx or no answer
//! is retryable (the token may be unplugged for a while); a 4xx is not.
//! The signature goes in the document's `signatures` as type `I` (issuer).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};

use super::serialize::{canonical, digest_hex};
use crate::zatca::api::{HttpAnswer, Transport};

/// Where the signer service is and its key.
#[derive(Clone)]
pub struct SignerConfig {
    pub base_url: String,
    pub api_key: String,
}

impl std::fmt::Debug for SignerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerConfig")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("the signer could not be reached: {0}")]
    Retryable(String),
    #[error("the signer refused: {0}")]
    Refused(String),
}

#[derive(Deserialize)]
struct Answer {
    signature: Option<String>,
}

fn read(answer: HttpAnswer) -> Result<String, SignerError> {
    match answer.status {
        200..=299 => {
            let parsed: Answer = serde_json::from_str(&answer.body).map_err(|e| {
                SignerError::Retryable(format!("an answer that is not the contract: {e}"))
            })?;
            let signature = parsed
                .signature
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| SignerError::Refused("the answer carries no signature".into()))?;
            STANDARD
                .decode(signature.trim())
                .map_err(|_| SignerError::Refused("the signature is not base64".into()))?;
            Ok(signature.trim().to_owned())
        }
        500..=599 => Err(SignerError::Retryable(format!("status {}", answer.status))),
        status => Err(SignerError::Refused(format!(
            "status {status}: {}",
            answer.body.chars().take(300).collect::<String>()
        ))),
    }
}

/// Signs `document` (without its signatures) and returns it with them.
pub async fn sign(
    transport: &dyn Transport,
    config: &SignerConfig,
    document: &Value,
) -> Result<Value, SignerError> {
    let text = canonical(document);
    let body = json!({
        "format": "cades-bes",
        "data": STANDARD.encode(text.as_bytes()),
        "digest": digest_hex(document),
    })
    .to_string();
    let headers = vec![("Authorization", format!("Bearer {}", config.api_key))];
    let url = format!("{}/sign", config.base_url.trim_end_matches('/'));
    let answer = transport
        .post(&url, &headers, body)
        .await
        .map_err(|e| SignerError::Retryable(e.0))?;
    let signature = read(answer)?;
    let mut signed = document.clone();
    if let Value::Object(map) = &mut signed {
        map.insert(
            "signatures".into(),
            json!([{ "signatureType": "I", "value": signature }]),
        );
    }
    Ok(signed)
}

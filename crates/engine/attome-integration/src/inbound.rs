//! M14-T1: builder-defined inbound endpoints, `POST /api/v1/hooks/{name}`.
//!
//! An administrator defines a hook (`inbound_hook`, migration 0217): its
//! name, how a caller proves itself, which addresses may call it, the fields
//! a body must carry, and what an accepted call does (create a record or
//! start a flow, as the hook's service user, `attome_api::inbound_hooks`).
//! This module owns the checks a call passes before anything runs.
//!
//! ## Authentication
//!
//! `auth.kind` is `hmac` or `bearer`; the secret is stored encrypted under
//! the integration credential key (`crate::crypto`) and never returned.
//! - `hmac`, with a `preset`:
//!   - `github`: `X-Hub-Signature-256: sha256=<hex>` over the body; the
//!     event id is `X-GitHub-Delivery`. GitHub sends no timestamp, so the
//!     delivery id alone guards replay, kept a day.
//!   - `stripe`: `Stripe-Signature: t=<unix>,v1=<hex>[,v1=…]` over
//!     `{t}.{body}`.
//!   - `standard` (Standard Webhooks): `webhook-signature: v1,<base64> …`
//!     over `{webhook-id}.{webhook-timestamp}.{body}`, a `whsec_` secret
//!     base64-decoded.
//!   - `docusign` (K4-T3, DocuSign Connect): `X-DocuSign-Signature-1`
//!     (to `-5`, one per Connect key) is the base64 HMAC-SHA256 of the
//!     body. Connect sends no timestamp; the event, envelope and the time
//!     DocuSign generated the message guard replay, kept a day.
//!   - `custom`: the signature in `header` (default `x-signature`), `hex`
//!     or `base64`, an optional `prefix` (`sha256=`), over the body or, with
//!     `timestamp_header`, over `{timestamp}.{body}`.
//! - `bearer`: `Authorization: Bearer <secret>`, compared in constant time;
//!   the caller's event id comes in `id_header` (default `x-event-id`).
//!
//! ## Replay
//!
//! A signed timestamp must fall within [`TIMESTAMP_WINDOW_SECS`] of now. The
//! event id (or the signature, when there is none) is claimed once per hook,
//! in Redis when the deployment has it and in `inbound_hook_nonce` on Solo,
//! for twice the window (a day for GitHub). A store that cannot answer
//! refuses the call: replay protection fails closed. A refused signature is
//! 401; a replay is 409.
//!
//! ## Network
//!
//! `ip_allow` lists CIDRs (or addresses); the caller's address is resolved
//! through the trusted-proxy walk, never a raw forwarding header. With
//! `require_mtls`, TLS client certificates are checked at the TLS edge, and
//! the call must arrive from a trusted proxy carrying
//! `x-client-cert-verified: SUCCESS`.

use std::net::IpAddr;
use std::time::Duration;

use attome_cache::Store;
use attome_core::EngineState;
use attome_types::AppError;
use axum::http::HeaderMap;
use base64::Engine;
use serde_json::Value;
use sha2::Digest;
use uuid::Uuid;

/// A signed timestamp's tolerance, in seconds either side of now.
pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// How long an event id stays claimed when the call carries a timestamp.
pub const NONCE_TTL_SECS: i64 = 2 * TIMESTAMP_WINDOW_SECS;

/// How long a GitHub delivery id stays claimed (no timestamp to bound it).
pub const UNTIMED_NONCE_TTL_SECS: i64 = 24 * 3600;

/// The header the TLS edge sets after verifying a client certificate.
pub const MTLS_VERIFIED_HEADER: &str = "x-client-cert-verified";

/// The hook presets.
pub const PRESETS: [&str; 5] = ["github", "stripe", "standard", "docusign", "custom"];

/// Why a call was refused before anything ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is missing, malformed or wrong (401).
    BadCredential,
    /// The signed timestamp is outside the window (401).
    Stale,
    /// The caller's address is not allowed, or mTLS was required (403).
    Network,
}

impl From<Refusal> for AppError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::BadCredential | Refusal::Stale => AppError::Unauthorized,
            Refusal::Network => AppError::Forbidden,
        }
    }
}

/// A verified call: the id its replay is guarded by, and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub nonce: String,
    pub ttl_secs: i64,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Option<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(part);
    }
    Some(mac.finalize().into_bytes().to_vec())
}

/// Constant-time equality.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn timestamp_ok(raw: &str, now: i64) -> Result<i64, Refusal> {
    if raw.is_empty() || raw.len() > 12 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::BadCredential);
    }
    let ts: i64 = raw.parse().map_err(|_| Refusal::BadCredential)?;
    if (now - ts).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(Refusal::Stale);
    }
    Ok(ts)
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// K4-T3: a DocuSign Connect message's identity: its event, envelope and
/// generation time, the same on every retry of one message; the body's
/// digest when the body is not Connect JSON.
fn docusign_event_id(body: &[u8]) -> String {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match (
        value["event"].as_str(),
        value["data"]["envelopeId"].as_str(),
        value["generatedDateTime"].as_str(),
    ) {
        (Some(event), Some(envelope), Some(at)) => format!("docusign:{event}:{envelope}:{at}"),
        _ => digest_hex(body),
    }
}

/// M14-T1: checks a call's credential against the hook's `auth` and
/// `secret`; the id its replay is guarded by.
pub fn verify(
    auth: &Value,
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> Result<Verified, Refusal> {
    let kind = auth["kind"].as_str().unwrap_or_default();
    match kind {
        "bearer" => {
            let presented = header(headers, "authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(Refusal::BadCredential)?;
            if !same(presented.trim().as_bytes(), secret.as_bytes()) {
                return Err(Refusal::BadCredential);
            }
            let id_header = auth["id_header"].as_str().unwrap_or("x-event-id");
            let id = header(headers, id_header)
                .filter(|v| !v.is_empty() && v.len() <= 200)
                .ok_or(Refusal::BadCredential)?;
            Ok(Verified {
                nonce: id.to_owned(),
                ttl_secs: UNTIMED_NONCE_TTL_SECS,
            })
        }
        "hmac" => match auth["preset"].as_str().unwrap_or("custom") {
            "github" => {
                let sig = header(headers, "x-hub-signature-256")
                    .and_then(|v| v.strip_prefix("sha256="))
                    .and_then(|v| hex::decode(v).ok())
                    .ok_or(Refusal::BadCredential)?;
                let expected =
                    hmac_sha256(secret.as_bytes(), &[body]).ok_or(Refusal::BadCredential)?;
                if !same(&sig, &expected) {
                    return Err(Refusal::BadCredential);
                }
                let id = header(headers, "x-github-delivery")
                    .filter(|v| !v.is_empty() && v.len() <= 200)
                    .ok_or(Refusal::BadCredential)?;
                Ok(Verified {
                    nonce: id.to_owned(),
                    ttl_secs: UNTIMED_NONCE_TTL_SECS,
                })
            }
            "stripe" => {
                let raw = header(headers, "stripe-signature").ok_or(Refusal::BadCredential)?;
                let mut t = None;
                let mut v1 = Vec::new();
                for part in raw.split(',') {
                    match part.trim().split_once('=') {
                        Some(("t", value)) => t = Some(value),
                        Some(("v1", value)) => v1.extend(hex::decode(value).ok()),
                        _ => {}
                    }
                }
                let t = t.ok_or(Refusal::BadCredential)?;
                timestamp_ok(t, now)?;
                let expected = hmac_sha256(secret.as_bytes(), &[t.as_bytes(), b".", body])
                    .ok_or(Refusal::BadCredential)?;
                let Some(matched) = v1.iter().find(|sig| same(sig, &expected)) else {
                    return Err(Refusal::BadCredential);
                };
                Ok(Verified {
                    nonce: hex::encode(matched),
                    ttl_secs: NONCE_TTL_SECS,
                })
            }
            "standard" => {
                let id = header(headers, "webhook-id")
                    .filter(|v| !v.is_empty() && v.len() <= 200)
                    .ok_or(Refusal::BadCredential)?;
                let ts = header(headers, "webhook-timestamp").ok_or(Refusal::BadCredential)?;
                timestamp_ok(ts, now)?;
                let key = match secret.strip_prefix("whsec_") {
                    Some(encoded) => base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|_| Refusal::BadCredential)?,
                    None => secret.as_bytes().to_vec(),
                };
                let expected = hmac_sha256(&key, &[id.as_bytes(), b".", ts.as_bytes(), b".", body])
                    .ok_or(Refusal::BadCredential)?;
                let signatures =
                    header(headers, "webhook-signature").ok_or(Refusal::BadCredential)?;
                let ok = signatures.split_whitespace().any(|entry| {
                    entry
                        .strip_prefix("v1,")
                        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
                        .is_some_and(|sig| same(&sig, &expected))
                });
                if !ok {
                    return Err(Refusal::BadCredential);
                }
                Ok(Verified {
                    nonce: id.to_owned(),
                    ttl_secs: NONCE_TTL_SECS,
                })
            }
            "docusign" => {
                let expected =
                    hmac_sha256(secret.as_bytes(), &[body]).ok_or(Refusal::BadCredential)?;
                let ok = (1..=5).any(|n| {
                    header(headers, &format!("x-docusign-signature-{n}"))
                        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
                        .is_some_and(|sig| same(&sig, &expected))
                });
                if !ok {
                    return Err(Refusal::BadCredential);
                }
                Ok(Verified {
                    nonce: docusign_event_id(body),
                    ttl_secs: UNTIMED_NONCE_TTL_SECS,
                })
            }
            _ => {
                let name = auth["header"].as_str().unwrap_or("x-signature");
                let mut raw = header(headers, name).ok_or(Refusal::BadCredential)?;
                if let Some(prefix) = auth["prefix"].as_str() {
                    raw = raw.strip_prefix(prefix).ok_or(Refusal::BadCredential)?;
                }
                let sig = match auth["encoding"].as_str().unwrap_or("hex") {
                    "base64" => base64::engine::general_purpose::STANDARD.decode(raw).ok(),
                    _ => hex::decode(raw).ok(),
                }
                .ok_or(Refusal::BadCredential)?;
                let (expected, ttl) = match auth["timestamp_header"].as_str() {
                    Some(ts_header) => {
                        let ts = header(headers, ts_header).ok_or(Refusal::BadCredential)?;
                        timestamp_ok(ts, now)?;
                        (
                            hmac_sha256(secret.as_bytes(), &[ts.as_bytes(), b".", body]),
                            NONCE_TTL_SECS,
                        )
                    }
                    None => (
                        hmac_sha256(secret.as_bytes(), &[body]),
                        UNTIMED_NONCE_TTL_SECS,
                    ),
                };
                let expected = expected.ok_or(Refusal::BadCredential)?;
                if !same(&sig, &expected) {
                    return Err(Refusal::BadCredential);
                }
                Ok(Verified {
                    nonce: hex::encode(&sig),
                    ttl_secs: ttl,
                })
            }
        },
        _ => Err(Refusal::BadCredential),
    }
}

/// Whether `ip` is inside one of `allow` (CIDRs or addresses); an empty
/// list allows every address.
pub fn ip_allowed(allow: &[String], ip: IpAddr) -> bool {
    if allow.is_empty() {
        return true;
    }
    let ip = ip.to_canonical();
    allow.iter().any(|entry| {
        let (net, bits) = match entry.split_once('/') {
            Some((net, bits)) => (net, bits.parse::<u32>().ok()),
            None => (entry.as_str(), None),
        };
        let Ok(net) = net.trim().parse::<IpAddr>() else {
            return false;
        };
        match (ip, net.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let bits = bits.unwrap_or(32).min(32);
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(a) & mask == u32::from(n) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let bits = bits.unwrap_or(128).min(128);
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(a) & mask == u128::from(n) & mask
            }
            _ => false,
        }
    })
}

/// Checks an `auth` document an administrator saves: a known kind and
/// preset, and the custom fields well formed.
pub fn check_auth(auth: &Value) -> Result<(), String> {
    match auth["kind"].as_str() {
        Some("bearer") => Ok(()),
        Some("hmac") => {
            let preset = auth["preset"].as_str().unwrap_or("custom");
            if !PRESETS.contains(&preset) {
                return Err(format!("preset is one of {}", PRESETS.join(", ")));
            }
            if let Some(encoding) = auth.get("encoding")
                && !matches!(encoding.as_str(), Some("hex" | "base64"))
            {
                return Err("encoding is hex or base64".into());
            }
            for key in ["header", "prefix", "timestamp_header", "id_header"] {
                if auth
                    .get(key)
                    .is_some_and(|v| v.as_str().is_none_or(|s| s.is_empty() || s.len() > 100))
                {
                    return Err(format!("{key} is a short text"));
                }
            }
            Ok(())
        }
        _ => Err("auth.kind is hmac or bearer".into()),
    }
}

/// The body fields `schema.required` names that `body` does not carry.
pub fn missing_fields(schema: &Value, body: &Value) -> Vec<String> {
    schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|field| body.get(*field).is_none_or(Value::is_null))
        .map(str::to_owned)
        .collect()
}

/// Claims `nonce` for `hook_id`; `false` for a replay. In Redis when the
/// deployment has it, else in `inbound_hook_nonce`. Fails closed.
pub async fn claim_nonce(
    state: &EngineState,
    hook_id: Uuid,
    nonce: &str,
    ttl_secs: i64,
) -> Result<bool, AppError> {
    let digest = digest_hex(nonce.as_bytes());
    let store = &state.base.redis_coordination;
    if let Store::Redis(_) = store {
        let key = format!("attome-integration:hook-nonce:{hook_id}:{digest}");
        return tokio::time::timeout(
            attome_cache::timeouts::REQUEST_PATH,
            store.set_nx(
                key.as_str(),
                "1",
                Some(Duration::from_secs(u64::try_from(ttl_secs).unwrap_or(600))),
            ),
        )
        .await
        .map_err(|_| AppError::CapabilityUnavailable("redis"))?
        .map_err(|_| AppError::CapabilityUnavailable("redis"));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM inbound_hook_nonce WHERE hook_id = $1 AND expires_at < now()")
        .bind(hook_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::CapabilityUnavailable("postgres"))?;
    let claimed = sqlx::query(
        "INSERT INTO inbound_hook_nonce (hook_id, nonce_hash, expires_at) \
         VALUES ($1, $2, now() + make_interval(secs => $3)) ON CONFLICT DO NOTHING",
    )
    .bind(hook_id)
    .bind(&digest)
    .bind(ttl_secs as f64)
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::CapabilityUnavailable("postgres"))?
    .rows_affected()
        == 1;
    attome_db::tx::commit(tx).await?;
    Ok(claimed)
}

/// Gives a claimed nonce back after a call that ran nothing failed, so the
/// sender's retry is not refused as a replay. Best effort.
pub async fn release_nonce(state: &EngineState, hook_id: Uuid, nonce: &str) {
    let digest = digest_hex(nonce.as_bytes());
    let store = &state.base.redis_coordination;
    let outcome = if let Store::Redis(_) = store {
        let key = format!("attome-integration:hook-nonce:{hook_id}:{digest}");
        tokio::time::timeout(
            attome_cache::timeouts::REQUEST_PATH,
            store.del(key.as_str()),
        )
        .await
        .map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
        .unwrap_or_else(|_| Err("timed out".into()))
    } else {
        sqlx::query("DELETE FROM inbound_hook_nonce WHERE hook_id = $1 AND nonce_hash = $2")
            .bind(hook_id)
            .bind(&digest)
            .execute(&state.base.db)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    if let Err(error) = outcome {
        tracing::warn!(%hook_id, error, "inbound hook: could not release the event id");
    }
}

/// Encrypts a hook secret for storage.
pub fn seal_secret(state: &EngineState, hook_id: Uuid, secret: &str) -> Result<String, AppError> {
    let ring = crate::credential::ring(state);
    if ring.is_empty() {
        return Err(AppError::internal(
            "integration.credential_encryption_key has no active key configured",
        ));
    }
    crate::crypto::encrypt_credential(&ring, hook_id, secret)
}

/// Decrypts a stored hook secret.
pub fn open_secret(
    state: &EngineState,
    hook_id: Uuid,
    sealed: &str,
) -> Result<zeroize::Zeroizing<String>, AppError> {
    let ring = crate::credential::ring(state);
    crate::crypto::decrypt_credential(&ring, hook_id, sealed).map(zeroize::Zeroizing::new)
}

#[cfg(test)]
mod inbound_endpoints {
    use super::*;
    use axum::http::HeaderValue;
    use serde_json::json;

    const SECRET: &str = "s3cret";
    const NOW: i64 = 1_800_000_000;

    fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn hex_mac(key: &[u8], parts: &[&[u8]]) -> String {
        hex::encode(hmac_sha256(key, parts).unwrap())
    }

    #[test]
    fn inbound_endpoints_bad_signature_is_refused() {
        let auth = json!({ "kind": "hmac", "preset": "github" });
        let body = br#"{"action":"opened"}"#;
        let good = headers(&[
            (
                "x-hub-signature-256",
                format!("sha256={}", hex_mac(SECRET.as_bytes(), &[body])),
            ),
            ("x-github-delivery", "d-1".into()),
        ]);
        assert_eq!(
            verify(&auth, SECRET, &good, body, NOW),
            Ok(Verified {
                nonce: "d-1".into(),
                ttl_secs: UNTIMED_NONCE_TTL_SECS
            })
        );
        let bad = headers(&[
            (
                "x-hub-signature-256",
                format!("sha256={}", hex_mac(b"other", &[body])),
            ),
            ("x-github-delivery", "d-1".into()),
        ]);
        assert_eq!(
            verify(&auth, SECRET, &bad, body, NOW),
            Err(Refusal::BadCredential)
        );
        assert!(matches!(
            AppError::from(Refusal::BadCredential),
            AppError::Unauthorized
        ));
        assert!(matches!(
            AppError::from(Refusal::Network),
            AppError::Forbidden
        ));
    }

    #[test]
    fn inbound_endpoints_stripe_and_standard_check_the_window() {
        let body = b"{}";
        let t = NOW.to_string();
        let stripe = json!({ "kind": "hmac", "preset": "stripe" });
        let sig = hex_mac(SECRET.as_bytes(), &[t.as_bytes(), b".", body]);
        let h = headers(&[("stripe-signature", format!("t={t},v1=deadbeef,v1={sig}"))]);
        assert!(verify(&stripe, SECRET, &h, body, NOW).is_ok());
        assert_eq!(
            verify(&stripe, SECRET, &h, body, NOW + 301),
            Err(Refusal::Stale)
        );

        let standard = json!({ "kind": "hmac", "preset": "standard" });
        let key = b"raw-key-bytes";
        let secret = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(key)
        );
        let mac = hmac_sha256(key, &[b"msg_1", b".", t.as_bytes(), b".", body]).unwrap();
        let h = headers(&[
            ("webhook-id", "msg_1".into()),
            ("webhook-timestamp", t.clone()),
            (
                "webhook-signature",
                format!(
                    "v1,{}",
                    base64::engine::general_purpose::STANDARD.encode(mac)
                ),
            ),
        ]);
        assert_eq!(
            verify(&standard, &secret, &h, body, NOW).unwrap().nonce,
            "msg_1"
        );
    }

    #[test]
    fn docusign_connect_signature_and_event_id() {
        let docusign = json!({ "kind": "hmac", "preset": "docusign" });
        let body = br#"{"event":"envelope-completed","generatedDateTime":"2026-10-25T09:00:00Z","data":{"envelopeId":"e-1"}}"#;
        let mac = hmac_sha256(b"connect-key", &[body]).unwrap();
        let signed = base64::engine::general_purpose::STANDARD.encode(mac);
        // The second Connect key's signature is accepted too.
        let h = headers(&[
            ("x-docusign-signature-1", "bm90LWl0".into()),
            ("x-docusign-signature-2", signed.clone()),
        ]);
        let verified = verify(&docusign, "connect-key", &h, body, NOW).unwrap();
        assert_eq!(
            verified.nonce,
            "docusign:envelope-completed:e-1:2026-10-25T09:00:00Z"
        );
        let wrong = headers(&[("x-docusign-signature-1", signed)]);
        assert_eq!(
            verify(&docusign, "another-key", &wrong, body, NOW),
            Err(Refusal::BadCredential)
        );
        assert_eq!(
            verify(&docusign, "connect-key", &headers(&[]), body, NOW),
            Err(Refusal::BadCredential)
        );
    }

    #[test]
    fn inbound_endpoints_custom_bearer_ip_and_schema() {
        let body = b"payload";
        let custom = json!({ "kind": "hmac", "preset": "custom", "header": "x-sig", "prefix": "sha256=", "encoding": "base64" });
        let mac = hmac_sha256(SECRET.as_bytes(), &[body]).unwrap();
        let h = headers(&[(
            "x-sig",
            format!(
                "sha256={}",
                base64::engine::general_purpose::STANDARD.encode(&mac)
            ),
        )]);
        assert!(verify(&custom, SECRET, &h, body, NOW).is_ok());

        let bearer = json!({ "kind": "bearer" });
        let h = headers(&[
            ("authorization", format!("Bearer {SECRET}")),
            ("x-event-id", "e-9".into()),
        ]);
        assert_eq!(verify(&bearer, SECRET, &h, body, NOW).unwrap().nonce, "e-9");
        let wrong = headers(&[
            ("authorization", "Bearer nope".into()),
            ("x-event-id", "e-9".into()),
        ]);
        assert_eq!(
            verify(&bearer, SECRET, &wrong, body, NOW),
            Err(Refusal::BadCredential)
        );

        let allow = vec!["10.0.0.0/8".to_owned(), "2001:db8::1".to_owned()];
        assert!(ip_allowed(&allow, "10.1.2.3".parse().unwrap()));
        assert!(!ip_allowed(&allow, "11.0.0.1".parse().unwrap()));
        assert!(ip_allowed(&allow, "2001:db8::1".parse().unwrap()));
        assert!(ip_allowed(&[], "11.0.0.1".parse().unwrap()));

        assert_eq!(
            missing_fields(
                &json!({ "required": ["id", "amount"] }),
                &json!({ "id": 1 })
            ),
            vec!["amount"]
        );
        assert!(check_auth(&json!({ "kind": "hmac", "preset": "gitlab" })).is_err());
        assert!(check_auth(&json!({ "kind": "hmac", "encoding": "hex" })).is_ok());
    }
}

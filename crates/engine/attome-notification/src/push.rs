//! Push notifications (roadmap J12-T1): Web Push to browsers, APNs to iOS and
//! FCM to Android, for the `push` dispatch channel.
//!
//! **Addresses.** A signed-in person registers where to reach them
//! (`POST /api/v1/push/subscriptions`): a browser's Web Push subscription or
//! a device token. One address belongs to one person; registering it again
//! moves it. A provider's "this address is gone" answer deletes the row.
//!
//! **Providers** are `integration_system` rows (`kind = channel`) whose
//! `config` names `"push": "webpush" | "apns" | "fcm"`, with the secret kept
//! as that system's envelope-encrypted credential:
//! - `webpush`: config `subject` (a `mailto:` or `https:` contact for the push
//!   service); credential = the VAPID P-256 private key, PKCS#8 PEM;
//! - `apns`: config `key_id`, `team_id`, `topic` (the app's bundle id) and
//!   `sandbox`; credential = the `.p8` token-signing key;
//! - `fcm`: credential = the Firebase service-account JSON.
//!
//! **Crypto** is `ring`'s, nothing hand-rolled below it: Web Push messages are
//! encrypted per RFC 8291 (`aes128gcm`, RFC 8188) to the browser's key and
//! signed for the push service per RFC 8292 (VAPID, ES256); APNs uses its
//! ES256 provider token; FCM's OAuth token is an RS256 service-account
//! assertion.

use std::sync::OnceLock;
use std::time::Duration;

use attome_audit::security::{ExemptReason, x_audit_exempt};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::KeyPair as _;
use ring::{aead, agreement, hkdf, signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Most addresses one person is pushed to at once.
const MAX_ADDRESSES: i64 = 20;
/// The record size Web Push messages are encrypted with (RFC 8188).
const RECORD_SIZE: u32 = 4096;
/// Largest Web Push payload before encryption (RFC 8291 §4).
const MAX_WEB_PAYLOAD: usize = 3993;
/// How long a push service keeps an undelivered message.
const TTL_SECS: u32 = 86_400;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

// ── Web Push encryption (RFC 8291) ──────────────────────────────────────────

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn crypto_err(_: ring::error::Unspecified) -> AppError {
    AppError::internal("push: a cryptographic step failed")
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, AppError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = vec![0u8; len];
    prk.expand(&[info], Len(len))
        .map_err(crypto_err)?
        .fill(&mut out)
        .map_err(crypto_err)?;
    Ok(out)
}

/// The content key and nonce for one message (RFC 8291 §3.3–3.4). Pure.
fn derive_keys(
    ecdh_secret: &[u8],
    auth_secret: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf_expand(auth_secret, ecdh_secret, &key_info, 32)?;
    let cek = hkdf_expand(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16)?;
    let nonce = hkdf_expand(salt, &ikm, b"Content-Encoding: nonce\0", 12)?;
    Ok((cek, nonce))
}

/// Encrypts `payload` to a browser's subscription keys: the `aes128gcm`
/// body, header included (RFC 8188 §2.1, RFC 8291 §4).
pub fn encrypt_web_push(
    payload: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
) -> Result<Vec<u8>, AppError> {
    if payload.len() > MAX_WEB_PAYLOAD {
        return Err(AppError::Validation("push payload too large".into()));
    }
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(crypto_err)?;
    let as_public = ephemeral.compute_public_key().map_err(crypto_err)?;
    let as_public = as_public.as_ref().to_vec();
    let ecdh_secret = agreement::agree_ephemeral(
        ephemeral,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ua_public),
        |secret| secret.to_vec(),
    )
    .map_err(|_| AppError::Validation("push: the subscription's public key is not valid".into()))?;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(crypto_err)?;
    let (cek, nonce) = derive_keys(&ecdh_secret, auth_secret, ua_public, &as_public, &salt)?;

    // One record: the payload, then the last-record delimiter.
    let mut record = payload.to_vec();
    record.push(0x02);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &cek).map_err(crypto_err)?,
    );
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce).map_err(crypto_err)?;
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut record)
        .map_err(crypto_err)?;

    let mut body = Vec::with_capacity(21 + as_public.len() + record.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(u8::try_from(as_public.len()).unwrap_or(65));
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&record);
    Ok(body)
}

// ── ES256 tokens (VAPID, APNs) ─────────────────────────────────────────────

/// The DER inside a PEM block.
fn pem_der(pem: &str) -> Result<Vec<u8>, AppError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .map_err(|_| AppError::Validation("push: the provider key is not a PEM key".into()))
}

fn es256_key(pem: &str) -> Result<signature::EcdsaKeyPair, AppError> {
    let der = pem_der(pem)?;
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &der,
        &SystemRandom::new(),
    )
    .map_err(|_| AppError::Validation("push: the provider key is not a P-256 PKCS#8 key".into()))
}

/// A compact JWT signed with ES256.
fn es256_jwt(
    key: &signature::EcdsaKeyPair,
    header: &Value,
    claims: &Value,
) -> Result<String, AppError> {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig = key
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(crypto_err)?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    ))
}

/// The origin a Web Push endpoint lives on, the VAPID `aud`. Pure.
pub fn endpoint_origin(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://")?;
    let host = rest.split('/').next().filter(|h| !h.is_empty())?;
    Some(format!("https://{host}"))
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

// ── Provider answers ────────────────────────────────────────────────────────

/// What a provider said about one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// The address no longer exists; it is removed.
    Gone,
    Failed,
}

/// Reads a provider's answer. Pure.
pub fn outcome(platform: &str, status: u16, body: &str) -> Outcome {
    if (200..300).contains(&status) {
        return Outcome::Delivered;
    }
    let gone = match platform {
        "web" => matches!(status, 404 | 410),
        "ios" => {
            status == 410
                || (status == 400
                    && (body.contains("BadDeviceToken") || body.contains("DeviceTokenNotForTopic")))
        }
        "android" => status == 404 || body.contains("UNREGISTERED"),
        _ => false,
    };
    if gone { Outcome::Gone } else { Outcome::Failed }
}

// ── Providers ───────────────────────────────────────────────────────────────

struct Provider {
    config: Value,
    secret: String,
}

/// The active provider for `push` (`webpush`, `apns`, `fcm`), if configured.
async fn provider(state: &EngineState, push: &str) -> Result<Option<Provider>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'push' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(push)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Ok(None);
    };
    let secret = attome_integration::credential::resolve(
        &state.base.db,
        &attome_integration::credential::ring(state),
        credential_ref.as_deref(),
    )
    .await?;
    let Some(secret) = secret else {
        tracing::warn!(push, "push: provider configured without a credential");
        return Ok(None);
    };
    // Z1-T10: the push providers sign with the key itself (VAPID, APNs,
    // FCM's service account), inside this module only.
    let secret = secret.with_value(str::to_owned);
    let config = config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(Value::Null);
    Ok(Some(Provider { config, secret }))
}

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the push services (browsers', APNs, FCM) are public. A browser
    // supplies its own endpoint, so a private one must never be dialed.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("push"), |b| {
            b.timeout(SEND_TIMEOUT)
        })
    })
}

fn text(config: &Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// What a push says.
#[derive(Debug, Clone, Serialize)]
pub struct PushMessage {
    pub title: String,
    pub body: String,
    pub route: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct Address {
    id: Uuid,
    platform: String,
    address: String,
    p256dh: Option<String>,
    auth: Option<String>,
}

/// B19-T2: a Web Push message in the shape the Angular service worker shows:
/// a `notification` with the title, body and app icon, which opens `route` in
/// the app (or focuses it) when tapped, and carries `route` for the app itself
/// when it is open. A route that is not an app path opens the app's start.
/// Pure.
pub fn web_payload(msg: &PushMessage) -> Value {
    let route = msg
        .route
        .as_deref()
        .filter(|r| r.starts_with('/') && !r.starts_with("//"))
        .unwrap_or("/");
    json!({
        "notification": {
            "title": msg.title,
            "body": msg.body,
            "icon": "/icons/icon-192.png",
            "badge": "/icons/icon-192.png",
            "data": {
                "route": route,
                "onActionClick": {
                    "default": { "operation": "navigateLastFocusedOrOpen", "url": route }
                }
            }
        }
    })
}

async fn send_web(p: &Provider, a: &Address, msg: &PushMessage) -> Result<(u16, String), AppError> {
    let ua_public = URL_SAFE_NO_PAD
        .decode(
            a.p256dh
                .as_deref()
                .unwrap_or_default()
                .trim_end_matches('='),
        )
        .map_err(|_| AppError::Validation("push: bad subscription key".into()))?;
    let auth = URL_SAFE_NO_PAD
        .decode(a.auth.as_deref().unwrap_or_default().trim_end_matches('='))
        .map_err(|_| AppError::Validation("push: bad subscription secret".into()))?;
    let mut payload = serde_json::to_vec(&web_payload(msg)).map_err(AppError::internal)?;
    if payload.len() > MAX_WEB_PAYLOAD {
        let short = PushMessage {
            title: msg.title.chars().take(200).collect(),
            body: msg.body.chars().take(1000).collect(),
            route: msg.route.clone(),
        };
        payload = serde_json::to_vec(&web_payload(&short)).map_err(AppError::internal)?;
    }
    let body = encrypt_web_push(&payload, &ua_public, &auth)?;
    let key = es256_key(&p.secret)?;
    let aud = endpoint_origin(&a.address)
        .ok_or_else(|| AppError::Validation("push: endpoint is not https".into()))?;
    let jwt = es256_jwt(
        &key,
        &json!({"typ": "JWT", "alg": "ES256"}),
        &json!({
            "aud": aud,
            "exp": now_secs() + 12 * 3600,
            "sub": text(&p.config, "subject").unwrap_or_else(|| "mailto:admin@localhost".into()),
        }),
    )?;
    let public = URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
    let res = client()
        .post(&a.address)
        .header("TTL", TTL_SECS.to_string())
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("Urgency", "normal")
        .header("Authorization", format!("vapid t={jwt}, k={public}"))
        .body(body)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

async fn send_apns(
    p: &Provider,
    a: &Address,
    msg: &PushMessage,
) -> Result<(u16, String), AppError> {
    let (Some(key_id), Some(team_id), Some(topic)) = (
        text(&p.config, "key_id"),
        text(&p.config, "team_id"),
        text(&p.config, "topic"),
    ) else {
        return Err(AppError::Validation(
            "push: the APNs provider needs key_id, team_id and topic".into(),
        ));
    };
    let key = es256_key(&p.secret)?;
    let jwt = es256_jwt(
        &key,
        &json!({"alg": "ES256", "kid": key_id}),
        &json!({"iss": team_id, "iat": now_secs()}),
    )?;
    let host = if p
        .config
        .get("sandbox")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "api.sandbox.push.apple.com"
    } else {
        "api.push.apple.com"
    };
    let res = client()
        .post(format!("https://{host}/3/device/{}", a.address))
        .header("authorization", format!("bearer {jwt}"))
        .header("apns-topic", topic)
        .header("apns-push-type", "alert")
        .json(&json!({
            "aps": {"alert": {"title": msg.title, "body": msg.body}, "sound": "default"},
            "route": msg.route,
        }))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

/// An FCM access token from the service account (RS256 assertion grant).
async fn fcm_token(sa: &ServiceAccount) -> Result<String, AppError> {
    let iat = now_secs();
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &json!({
            "iss": sa.client_email,
            "scope": FCM_SCOPE,
            "aud": sa.token_uri,
            "iat": iat,
            "exp": iat + 3600,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|_| {
            AppError::Validation("push: the FCM service account key is not RSA PEM".into())
        })?,
    )
    .map_err(AppError::internal)?;
    let res = client()
        .post(&sa.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .map_err(AppError::internal)?;
    if !res.status().is_success() {
        return Err(AppError::internal(format!(
            "push: FCM token request failed with {}",
            res.status()
        )));
    }
    let body: Value = res.json().await.map_err(AppError::internal)?;
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("push: FCM token response had no access_token"))
}

async fn send_fcm(
    sa: &ServiceAccount,
    token: &str,
    a: &Address,
    msg: &PushMessage,
) -> Result<(u16, String), AppError> {
    let res = client()
        .post(format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            sa.project_id
        ))
        .bearer_auth(token)
        .json(&json!({
            "message": {
                "token": a.address,
                "notification": {"title": msg.title, "body": msg.body},
                "data": {"route": msg.route.clone().unwrap_or_default()},
            }
        }))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

/// Pushes `msg` to every address `user` registered. Gone addresses are
/// removed. Succeeds when at least one push was delivered or none was
/// possible (no address, no provider); fails (so the dispatch retries) only
/// when every attempt failed.
pub async fn send_to_user(
    state: &EngineState,
    user: Option<Uuid>,
    msg: &PushMessage,
) -> Result<(), AppError> {
    let Some(user) = user else {
        return Ok(());
    };
    let addresses: Vec<Address> = sqlx::query_as(
        "SELECT id, platform, address, p256dh, auth FROM push_subscription \
          WHERE user_id = $1 ORDER BY last_seen_at DESC LIMIT $2",
    )
    .bind(user)
    .bind(MAX_ADDRESSES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if addresses.is_empty() {
        return Ok(());
    }
    let web = provider(state, "webpush").await?;
    let apns = provider(state, "apns").await?;
    let fcm = match provider(state, "fcm").await? {
        Some(p) => match serde_json::from_str::<ServiceAccount>(&p.secret) {
            Ok(sa) => Some(sa),
            Err(_) => {
                tracing::warn!("push: the FCM credential is not a service-account JSON");
                None
            }
        },
        None => None,
    };
    let mut fcm_access: Option<String> = None;
    let (mut delivered, mut failed, mut last_error) = (0usize, 0usize, None::<AppError>);
    for a in &addresses {
        let answer = match a.platform.as_str() {
            "web" => match &web {
                Some(p) => send_web(p, a, msg).await,
                None => continue,
            },
            "ios" => match &apns {
                Some(p) => send_apns(p, a, msg).await,
                None => continue,
            },
            "android" => match &fcm {
                Some(sa) => {
                    if fcm_access.is_none() {
                        match fcm_token(sa).await {
                            Ok(t) => fcm_access = Some(t),
                            Err(e) => {
                                failed += 1;
                                last_error = Some(e);
                                continue;
                            }
                        }
                    }
                    send_fcm(sa, fcm_access.as_deref().unwrap_or_default(), a, msg).await
                }
                None => continue,
            },
            _ => continue,
        };
        match answer {
            Ok((status, body)) => match outcome(&a.platform, status, &body) {
                Outcome::Delivered => delivered += 1,
                Outcome::Gone => {
                    sqlx::query("DELETE FROM push_subscription WHERE id = $1")
                        .bind(a.id)
                        .execute(&state.base.db)
                        .await
                        .map_err(AppError::internal)?;
                    tracing::info!(subscription = %a.id, platform = %a.platform, "push: address gone, removed");
                }
                Outcome::Failed => {
                    failed += 1;
                    tracing::warn!(subscription = %a.id, platform = %a.platform, status, "push: provider refused");
                    last_error = Some(AppError::internal(format!(
                        "push: {} provider answered {status}",
                        a.platform
                    )));
                }
            },
            Err(e) => {
                failed += 1;
                tracing::warn!(subscription = %a.id, platform = %a.platform, error = %e, "push: send failed");
                last_error = Some(e);
            }
        }
    }
    match (delivered, failed, last_error) {
        (0, f, Some(e)) if f > 0 => Err(e),
        _ => Ok(()),
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// `POST /api/v1/push/subscriptions`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewSubscription {
    /// `web`, `ios` or `android`.
    pub platform: String,
    /// A browser's Web Push endpoint (`https://`).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// A browser's `p256dh` key and `auth` secret, base64url.
    #[serde(default)]
    pub p256dh: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    /// An APNs or FCM device token.
    #[serde(default)]
    pub token: Option<String>,
    /// The registered device (B17-T4) this address belongs to.
    #[serde(default)]
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Subscription {
    pub id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VapidKey {
    /// The application server key for `PushManager.subscribe`, base64url.
    pub public_key: String,
}

/// A checked registration: platform, address and Web Push keys. Pure.
pub fn check_subscription(
    body: &NewSubscription,
) -> Result<(String, String, Option<String>, Option<String>), AppError> {
    let clean = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    match body.platform.as_str() {
        "web" => {
            let endpoint = clean(&body.endpoint)
                .filter(|e| e.len() <= 4096 && endpoint_origin(e).is_some())
                .ok_or_else(|| AppError::Validation("endpoint: an https URL is required".into()))?;
            let p256dh = clean(&body.p256dh)
                .filter(|k| {
                    URL_SAFE_NO_PAD
                        .decode(k.trim_end_matches('='))
                        .is_ok_and(|b| b.len() == 65 && b[0] == 4)
                })
                .ok_or_else(|| {
                    AppError::Validation("p256dh: a P-256 public key is required".into())
                })?;
            let auth = clean(&body.auth)
                .filter(|k| {
                    URL_SAFE_NO_PAD
                        .decode(k.trim_end_matches('='))
                        .is_ok_and(|b| b.len() == 16)
                })
                .ok_or_else(|| AppError::Validation("auth: a 16-byte secret is required".into()))?;
            Ok(("web".into(), endpoint, Some(p256dh), Some(auth)))
        }
        "ios" | "android" => {
            let token = clean(&body.token)
                .filter(|t| t.len() <= 4096 && !t.contains(char::is_whitespace))
                .ok_or_else(|| AppError::Validation("token: a device token is required".into()))?;
            Ok((body.platform.clone(), token, None, None))
        }
        _ => Err(AppError::Validation(
            "platform: must be web, ios or android".into(),
        )),
    }
}

/// Registers (or moves to the caller) one push address.
#[utoipa::path(
    post,
    path = "/api/v1/push/subscriptions",
    operation_id = "register_push_subscription",
    tag = "notification",
    request_body = NewSubscription,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::UserPreference,
        None,
        "the caller's own push address"
    )))),
    responses(
        (status = 200, description = "Registered", body = Subscription),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn register(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<NewSubscription>,
) -> Result<Json<Subscription>, AppError> {
    let (platform, address, p256dh, auth) = check_subscription(&body)?;
    if let Some(device) = body.device_id {
        let mine: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_device WHERE id = $1 AND user_id = $2)",
        )
        .bind(device)
        .bind(ctx.user_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if !mine {
            return Err(AppError::Validation("device_id: not your device".into()));
        }
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO push_subscription (user_id, device_id, platform, address, p256dh, auth) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (address) DO UPDATE \
            SET user_id = EXCLUDED.user_id, device_id = EXCLUDED.device_id, \
                platform = EXCLUDED.platform, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth, \
                last_seen_at = now() \
         RETURNING id",
    )
    .bind(ctx.user_id)
    .bind(body.device_id)
    .bind(&platform)
    .bind(&address)
    .bind(&p256dh)
    .bind(&auth)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(Subscription { id }))
}

/// Removes one of the caller's push addresses.
#[utoipa::path(
    delete,
    path = "/api/v1/push/subscriptions/{id}",
    tag = "notification",
    params(("id" = Uuid, Path)),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::UserPreference,
        None,
        "the caller's own push address"
    )))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such address of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn unregister(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let removed = sqlx::query("DELETE FROM push_subscription WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(ctx.user_id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The key a browser subscribes with; 404 while Web Push is not configured.
#[utoipa::path(
    get,
    path = "/api/v1/push/vapid-public-key",
    tag = "notification",
    responses(
        (status = 200, description = "Success", body = VapidKey),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Web Push is not configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn vapid_public_key(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Result<Json<VapidKey>, AppError> {
    let p = provider(&state, "webpush")
        .await?
        .ok_or(AppError::NotFound)?;
    let key = es256_key(&p.secret)?;
    Ok(Json(VapidKey {
        public_key: URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/push/subscriptions", post(register))
        .route("/api/v1/push/subscriptions/{id}", delete(unregister))
        .route("/api/v1/push/vapid-public-key", get(vapid_public_key))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(register, unregister, vapid_public_key))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_web_push_opens_its_route_in_the_app() {
        let msg = PushMessage {
            title: "Ticket 42".into(),
            body: "updated".into(),
            route: Some("/xrm/entity/ticket/form/42".into()),
        };
        let payload = web_payload(&msg);
        assert_eq!(payload["notification"]["title"], "Ticket 42");
        assert_eq!(
            payload["notification"]["data"]["onActionClick"]["default"]["url"],
            "/xrm/entity/ticket/form/42"
        );
        let elsewhere = PushMessage {
            route: Some("//evil.example".into()),
            ..msg
        };
        assert_eq!(
            web_payload(&elsewhere)["notification"]["data"]["route"],
            "/"
        );
    }

    /// The browser's side of RFC 8291: decrypts what [`encrypt_web_push`]
    /// produced, with the browser's private key.
    fn browser_decrypt(
        body: &[u8],
        ua_private: agreement::EphemeralPrivateKey,
        ua_public: &[u8],
        auth: &[u8],
    ) -> Vec<u8> {
        let salt = &body[..16];
        assert_eq!(
            u32::from_be_bytes(body[16..20].try_into().unwrap()),
            RECORD_SIZE
        );
        let idlen = body[20] as usize;
        let as_public = &body[21..21 + idlen];
        let ecdh = agreement::agree_ephemeral(
            ua_private,
            &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, as_public),
            |s| s.to_vec(),
        )
        .unwrap();
        let (cek, nonce) = derive_keys(&ecdh, auth, ua_public, as_public, salt).unwrap();
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut record = body[21 + idlen..].to_vec();
        let plain = key
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                aead::Aad::empty(),
                &mut record,
            )
            .unwrap();
        assert_eq!(plain.last(), Some(&0x02), "last-record delimiter");
        plain[..plain.len() - 1].to_vec()
    }

    #[test]
    fn push_web_payload_decrypts_in_the_browser() {
        let rng = SystemRandom::new();
        let ua_private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let ua_public = ua_private.compute_public_key().unwrap().as_ref().to_vec();
        let mut auth = [0u8; 16];
        rng.fill(&mut auth).unwrap();
        let message = br#"{"title":"Ticket 42","body":"updated"}"#;
        let body = encrypt_web_push(message, &ua_public, &auth).unwrap();
        assert_eq!(
            browser_decrypt(&body, ua_private, &ua_public, &auth),
            message
        );
        assert!(encrypt_web_push(&[b'x'; MAX_WEB_PAYLOAD + 1], &ua_public, &auth).is_err());
    }

    #[test]
    fn push_tokens_are_es256_signed() {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(pkcs8.as_ref())
        );
        let key = es256_key(&pem).unwrap();
        let jwt = es256_jwt(
            &key,
            &json!({"alg": "ES256"}),
            &json!({"aud": "https://push.example"}),
        )
        .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            key.public_key().as_ref(),
        )
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .unwrap();
        assert!(es256_key("not a key").is_err());
    }

    #[test]
    fn push_dead_addresses_are_recognised_per_provider() {
        assert_eq!(outcome("web", 201, ""), Outcome::Delivered);
        assert_eq!(outcome("web", 410, ""), Outcome::Gone);
        assert_eq!(outcome("web", 404, ""), Outcome::Gone);
        assert_eq!(outcome("web", 429, ""), Outcome::Failed);
        assert_eq!(
            outcome("ios", 410, r#"{"reason":"Unregistered"}"#),
            Outcome::Gone
        );
        assert_eq!(
            outcome("ios", 400, r#"{"reason":"BadDeviceToken"}"#),
            Outcome::Gone
        );
        assert_eq!(
            outcome("ios", 400, r#"{"reason":"PayloadTooLarge"}"#),
            Outcome::Failed
        );
        assert_eq!(outcome("android", 404, ""), Outcome::Gone);
        assert_eq!(
            outcome("android", 400, r#"{"errorCode":"UNREGISTERED"}"#),
            Outcome::Gone
        );
        assert_eq!(outcome("android", 503, ""), Outcome::Failed);
    }

    #[test]
    fn push_registrations_are_checked() {
        let web = |endpoint: &str, p256dh: &str, auth: &str| NewSubscription {
            platform: "web".into(),
            endpoint: Some(endpoint.into()),
            p256dh: Some(p256dh.into()),
            auth: Some(auth.into()),
            token: None,
            device_id: None,
        };
        let mut key = vec![4u8];
        key.extend([7u8; 64]);
        let p256dh = URL_SAFE_NO_PAD.encode(&key);
        let auth = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(check_subscription(&web("https://push.example/abc", &p256dh, &auth)).is_ok());
        assert!(check_subscription(&web("http://push.example/abc", &p256dh, &auth)).is_err());
        assert!(check_subscription(&web("https://push.example/abc", "short", &auth)).is_err());
        assert!(check_subscription(&web("https://push.example/abc", &p256dh, "x")).is_err());
        let ios = NewSubscription {
            platform: "ios".into(),
            endpoint: None,
            p256dh: None,
            auth: None,
            token: Some("ab12cd".into()),
            device_id: None,
        };
        assert_eq!(check_subscription(&ios).unwrap().1, "ab12cd");
        assert_eq!(
            endpoint_origin("https://fcm.googleapis.com/fcm/send/x").as_deref(),
            Some("https://fcm.googleapis.com")
        );
        assert!(endpoint_origin("ftp://x").is_none());
    }
}

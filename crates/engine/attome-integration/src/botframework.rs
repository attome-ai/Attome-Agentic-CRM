//! V2-D1532 (7): the inbound half of the Teams bot (C5-T1 sends). An
//! integration system with `auth_type = "botframework"` receives the
//! activities Teams posts to `/api/v1/integrations/{system}/webhook`, each
//! with `Authorization: Bearer <token>` the Bot Framework signed.
//!
//! [`verify`] accepts the token only when all of these hold:
//!
//! - it is RS256, signed by a key in Bot Framework's published key set
//!   ([`KEYS_URL`]), and that key's `endorsements` name the activity's
//!   `channelId` (Microsoft's rule: a key is good only for the channels it
//!   endorses);
//! - `iss` is [`ISSUER`] and `aud` is the bot's app id (the system's
//!   credential, `app id` or `app id:secret`);
//! - it is within its `nbf`..`exp`, with [`LEEWAY_SECS`] of skew;
//! - its `serviceUrl` claim equals the activity's `serviceUrl`, so a token
//!   issued for one Teams endpoint cannot carry an activity naming another.
//!
//! The key set is fetched over https with a bounded body and timeout, kept in
//! Redis (`attome-integration:botframework:keys`, [`KEYS_TTL_SECS`]) and
//! refetched once when a token names a key id the cached set lacks. Anything
//! that cannot be checked is refused: no key set, an unknown key, Redis down.
//! Each activity is accepted once ([`activity_key`], a day): Teams retries
//! with the same activity id.

use std::time::Duration;

use attome_cache::Store;
use attome_types::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// The `integration_system.auth_type` of a Teams bot.
pub const AUTH_TYPE: &str = "botframework";
/// The `iss` of every Bot Framework token.
pub const ISSUER: &str = "https://api.botframework.com";
/// Bot Framework's published signing keys.
pub const KEYS_URL: &str = "https://login.botframework.com/v1/.well-known/keys";
/// How long a fetched key set is kept.
pub const KEYS_TTL_SECS: u64 = 3_600;
/// Clock skew allowed on `nbf` and `exp` (Microsoft documents five minutes).
pub const LEEWAY_SECS: u64 = 300;
/// How long an accepted activity id is remembered.
pub const ACTIVITY_TTL_SECS: u64 = 86_400;
/// The largest key set read.
const KEYS_MAX_BYTES: usize = 256 * 1024;
/// The key-set fetch's time limit.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Where the key set is kept in Redis.
pub const KEYS_CACHE: &str = "attome-integration:botframework:keys";

/// The claims a Bot Framework token carries that are checked here.
#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(rename = "serviceUrl", alias = "serviceurl")]
    service_url: Option<String>,
}

/// The bot's app id from the system's credential: `app id` or
/// `app id:secret`. Pure.
pub fn app_id(credential: &str) -> Option<&str> {
    let id = credential.split(':').next()?.trim();
    (!id.is_empty()).then_some(id)
}

/// The bearer token of an `Authorization` header value. Pure.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

/// The key `kid` of `keys` when it endorses `channel`, as a decoding key.
/// Pure.
pub fn endorsed_key(keys: &Value, kid: &str, channel: &str) -> Option<DecodingKey> {
    let key = keys
        .get("keys")?
        .as_array()?
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid))?;
    let endorses = key["endorsements"]
        .as_array()
        .is_some_and(|e| e.iter().any(|c| c.as_str() == Some(channel)));
    if !endorses || key["kty"].as_str() != Some("RSA") {
        return None;
    }
    DecodingKey::from_rsa_components(key["n"].as_str()?, key["e"].as_str()?).ok()
}

/// Checks `token` for `activity` against `keys` (see the module docs).
/// `Unauthorized` for every failure, saying nothing of which check failed.
/// Pure.
pub fn verify_with(
    token: &str,
    activity: &Value,
    app_id: &str,
    keys: &Value,
) -> Result<(), AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| AppError::Unauthorized)?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::Unauthorized);
    }
    let kid = header.kid.ok_or(AppError::Unauthorized)?;
    let channel = activity["channelId"]
        .as_str()
        .ok_or(AppError::Unauthorized)?;
    let key = endorsed_key(keys, &kid, channel).ok_or(AppError::Unauthorized)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[app_id]);
    validation.leeway = LEEWAY_SECS;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized)?;
    let claimed = data.claims.service_url.ok_or(AppError::Unauthorized)?;
    let sent = activity["serviceUrl"]
        .as_str()
        .ok_or(AppError::Unauthorized)?;
    if claimed.trim_end_matches('/') != sent.trim_end_matches('/') {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

async fn fetch_keys(http: &reqwest::Client, url: &str) -> Result<Value, AppError> {
    let unavailable = || AppError::CapabilityUnavailable("botframework_keys");
    let response = tokio::time::timeout(FETCH_TIMEOUT, http.get(url).send())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    if !response.status().is_success() {
        return Err(unavailable());
    }
    let body = tokio::time::timeout(FETCH_TIMEOUT, response.bytes())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    if body.len() > KEYS_MAX_BYTES {
        return Err(unavailable());
    }
    let keys: Value = serde_json::from_slice(&body).map_err(|_| unavailable())?;
    if !keys["keys"].is_array() {
        return Err(unavailable());
    }
    Ok(keys)
}

/// The key set, from Redis or fetched; `fresh` forces a fetch.
async fn keys(redis: &Store, http: &reqwest::Client, fresh: bool) -> Result<Value, AppError> {
    if !fresh
        && let Some(cached) = redis.get(KEYS_CACHE).await?
        && let Ok(keys) = serde_json::from_str::<Value>(&cached)
    {
        return Ok(keys);
    }
    let keys = fetch_keys(http, KEYS_URL).await?;
    redis
        .set(
            KEYS_CACHE,
            keys.to_string(),
            Some(Duration::from_secs(KEYS_TTL_SECS)),
        )
        .await?;
    Ok(keys)
}

/// Checks the request's token for `activity`, refetching the key set once
/// for a key id the cached set lacks.
pub async fn verify(
    redis: &Store,
    http: &reqwest::Client,
    authorization: Option<&str>,
    activity: &Value,
    app_id: &str,
) -> Result<(), AppError> {
    let token = bearer(authorization).ok_or(AppError::Unauthorized)?;
    let cached = keys(redis, http, false).await?;
    match verify_with(token, activity, app_id, &cached) {
        Ok(()) => Ok(()),
        Err(_) => {
            // A rotated key: look once more at the published set.
            let kid = jsonwebtoken::decode_header(token)
                .ok()
                .and_then(|h| h.kid)
                .ok_or(AppError::Unauthorized)?;
            let known = cached["keys"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k["kid"].as_str() == Some(kid.as_str())));
            if known {
                return Err(AppError::Unauthorized);
            }
            let fresh = keys(redis, http, true).await?;
            verify_with(token, activity, app_id, &fresh)
        }
    }
}

/// The client the key set is fetched with: https only, no redirects, a
/// connect and request time limit.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(FETCH_TIMEOUT)
        .timeout(FETCH_TIMEOUT)
        .build()
        .unwrap_or_default()
}

/// The Redis key that marks activity `id` of `system` accepted.
pub fn activity_key(system: Uuid, id: &str) -> String {
    format!("attome-integration:botframework:activity:{system}:{id}")
}

/// Records the activity as accepted; false when it already was (a retry).
pub async fn first_delivery(
    redis: &Store,
    system: Uuid,
    activity: &Value,
) -> Result<bool, AppError> {
    let id = activity["id"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .ok_or_else(|| AppError::Validation("the activity has no id".into()))?;
    redis
        .set_nx(
            activity_key(system, id),
            "1",
            Some(Duration::from_secs(ACTIVITY_TTL_SECS)),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    // A 2048-bit RSA test key, generated for these tests only.
    const PRIVATE_PEM: &str = include_str!("../tests/fixtures/botframework_test_key.pem");
    const MODULUS_B64: &str = include_str!("../tests/fixtures/botframework_test_key.n");

    const APP: &str = "11111111-2222-3333-4444-555555555555";
    const SERVICE: &str = "https://smba.trafficmanager.net/emea/";

    fn keyset(endorsements: &[&str]) -> Value {
        json!({ "keys": [{
            "kty": "RSA", "use": "sig", "kid": "k1",
            "n": MODULUS_B64.trim(), "e": URL_SAFE_NO_PAD.encode([1u8, 0, 1]),
            "endorsements": endorsements,
        }]})
    }

    fn token(claims: Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn claims() -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({ "iss": ISSUER, "aud": APP, "nbf": now - 10, "exp": now + 600,
                "serviceUrl": SERVICE })
    }

    fn activity() -> Value {
        json!({ "id": "a1", "type": "message", "channelId": "msteams", "serviceUrl": SERVICE })
    }

    #[test]
    fn a_token_signed_for_this_bot_and_endpoint_passes() {
        let keys = keyset(&["msteams"]);
        assert!(verify_with(&token(claims(), "k1"), &activity(), APP, &keys).is_ok());
    }

    #[test]
    fn every_other_token_is_refused() {
        let keys = keyset(&["msteams"]);
        let refused = |t: String, a: &Value, k: &Value| {
            matches!(verify_with(&t, a, APP, k), Err(AppError::Unauthorized))
        };
        // Another bot.
        let mut c = claims();
        c["aud"] = json!("another-app");
        assert!(refused(token(c, "k1"), &activity(), &keys));
        // Another issuer.
        let mut c = claims();
        c["iss"] = json!("https://login.microsoftonline.com/x/v2.0");
        assert!(refused(token(c, "k1"), &activity(), &keys));
        // Expired past the leeway.
        let mut c = claims();
        c["exp"] = json!(chrono::Utc::now().timestamp() - 3_600);
        assert!(refused(token(c, "k1"), &activity(), &keys));
        // Issued for another endpoint than the activity names.
        let mut a = activity();
        a["serviceUrl"] = json!("https://evil.example/");
        assert!(refused(token(claims(), "k1"), &a, &keys));
        // A key that does not endorse the channel.
        assert!(refused(
            token(claims(), "k1"),
            &activity(),
            &keyset(&["skype"])
        ));
        // A key id the set does not hold.
        assert!(refused(token(claims(), "k2"), &activity(), &keys));
        // Not a token at all.
        assert!(refused("abc.def.ghi".to_owned(), &activity(), &keys));
    }

    #[test]
    fn a_token_without_the_service_url_claim_is_refused() {
        let mut c = claims();
        c.as_object_mut().unwrap().remove("serviceUrl");
        assert!(verify_with(&token(c, "k1"), &activity(), APP, &keyset(&["msteams"])).is_err());
    }

    #[test]
    fn bearer_and_app_id_are_read_strictly() {
        assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("bearer  abc ")), Some("abc"));
        assert_eq!(bearer(Some("Basic abc")), None);
        assert_eq!(bearer(Some("Bearer ")), None);
        assert_eq!(bearer(None), None);
        assert_eq!(app_id("app:secret"), Some("app"));
        assert_eq!(app_id("app"), Some("app"));
        assert_eq!(app_id(":secret"), None);
    }

    #[tokio::test]
    async fn an_activity_is_accepted_once() {
        let redis = Store::memory();
        let system = Uuid::now_v7();
        assert!(first_delivery(&redis, system, &activity()).await.unwrap());
        assert!(!first_delivery(&redis, system, &activity()).await.unwrap());
        assert!(
            first_delivery(&redis, Uuid::now_v7(), &activity())
                .await
                .unwrap()
        );
    }
}

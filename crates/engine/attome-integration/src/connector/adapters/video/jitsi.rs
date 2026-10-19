//! J7-T1: a self-hosted Jitsi Meet. A meeting is a hard-to-guess room on the
//! configured domain; with an `app_id` and the app secret, the link carries
//! an HS256 token valid for the meeting's span (Jitsi's JWT authentication).

use attome_core::EngineState;
use attome_types::AppError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use super::{Meeting, video_app};

/// A room name: a readable prefix from the subject and a random part. Pure
/// apart from the random part, which the caller passes.
pub fn room_name(subject: &str, random: Uuid) -> String {
    let slug: String = subject
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(24)
        .collect();
    let slug = if slug.is_empty() {
        "meeting".to_owned()
    } else {
        slug
    };
    format!("{slug}-{}", random.simple())
}

/// An HS256 JWT for a room. Pure.
pub fn room_token(
    app_id: &str,
    secret: &str,
    domain: &str,
    room: &str,
    not_before: i64,
    expires: i64,
) -> Option<String> {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "HS256", "typ": "JWT"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "aud": "jitsi", "iss": app_id, "sub": domain, "room": room,
            "nbf": not_before, "exp": expires,
        })
        .to_string(),
    );
    let input = format!("{header}.{claims}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Some(format!("{input}.{sig}"))
}

/// The join URL. Pure.
pub fn join_url(domain: &str, room: &str, token: Option<&str>) -> String {
    let base = format!("https://{}/{room}", domain.trim_end_matches('/'));
    match token {
        Some(t) => format!("{base}?jwt={t}"),
        None => base,
    }
}

pub async fn create(
    state: &EngineState,
    subject: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Meeting, AppError> {
    let (config, secret) = video_app(state, "jitsi").await?.ok_or(AppError::NotFound)?;
    let domain = config
        .get("domain")
        .and_then(Value::as_str)
        .map(|d| {
            d.trim_start_matches("https://")
                .trim_end_matches('/')
                .to_owned()
        })
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Validation("jitsi: domain is not configured".into()))?;
    let room = room_name(subject, Uuid::new_v4());
    let token = match (
        config.get("app_id").and_then(Value::as_str),
        secret.as_deref(),
    ) {
        (Some(app_id), Some(secret)) => room_token(
            app_id,
            secret,
            &domain,
            &room,
            (start - chrono::Duration::minutes(15)).timestamp(),
            (end + chrono::Duration::hours(1)).timestamp(),
        ),
        _ => None,
    };
    Ok(Meeting {
        provider: "jitsi".into(),
        id: room.clone(),
        join_url: join_url(&domain, &room, token.as_deref()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_adapters_jitsi_rooms_and_tokens() {
        let room = room_name("Q3 review!", Uuid::nil());
        assert_eq!(room, "Q3review-00000000000000000000000000000000");
        assert_eq!(
            room_name("مراجعة", Uuid::nil()),
            "meeting-00000000000000000000000000000000"
        );
        assert_eq!(
            join_url("meet.example.com/", "r1", None),
            "https://meet.example.com/r1"
        );
        let token = room_token("attome", "s3cret", "meet.example.com", "r1", 0, 60).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["room"], "r1");
        // The signature is the HMAC of the first two parts.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
            parts[2]
        );
        assert!(join_url("meet.example.com", "r1", Some(&token)).contains("?jwt="));
    }
}

//! J8-T1: social channels: Facebook Messenger and page comments, Instagram
//! messages and comments (Meta's Graph API, [`meta`]), and Google Business
//! Profile reviews ([`google_reviews`]).
//!
//! Each is an `integration_system` row whose config names it (`"social":
//! "meta"` or `"social": "google_reviews"`) with its secrets as the system's
//! encrypted credential, a JSON object (`meta`: `app_secret`, `page_token`;
//! `google_reviews`: `client_secret`, `refresh_token`). Meta posts to
//! `/api/v1/social/meta/{key}`, `key` being the system's `inbound_key`
//! (compared by digest, as for SMS); reviews are read every 15 minutes.
//!
//! What arrives becomes an inbound communication on the system's record
//! (the caller's side writes it). The person or comment it came from is kept
//! as its address ([`ReplyTarget`]), so a reply goes back the same way.

pub mod brandwatch;
pub mod google_reviews;
pub mod meta;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::system::IntegrationSystem;

/// One message, comment or review that arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocialMessage {
    /// The communication channel: `messenger`, `instagram`, `facebook` or
    /// `google_review`.
    pub channel: &'static str,
    /// Where a reply goes ([`ReplyTarget::address`]).
    pub address: String,
    /// The author's name or handle, when the provider gives one.
    pub author: Option<String>,
    pub subject: String,
    pub text: String,
}

/// Where a reply goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyTarget {
    /// A Messenger conversation, by page-scoped id.
    MessengerDm(String),
    /// An Instagram conversation, by Instagram-scoped id.
    InstagramDm(String),
    /// A comment on the Facebook page.
    FacebookComment(String),
    /// A comment on an Instagram post.
    InstagramComment(String),
    /// A Google review, by its resource name.
    GoogleReview(String),
}

impl ReplyTarget {
    /// The address kept on the communication. Pure.
    pub fn address(&self) -> String {
        match self {
            Self::MessengerDm(id) => format!("fb_dm:{id}"),
            Self::InstagramDm(id) => format!("ig_dm:{id}"),
            Self::FacebookComment(id) => format!("fb_comment:{id}"),
            Self::InstagramComment(id) => format!("ig_comment:{id}"),
            Self::GoogleReview(name) => format!("gbp_review:{name}"),
        }
    }

    /// Reads an address back. Pure.
    pub fn parse(address: &str) -> Option<Self> {
        let (kind, id) = address.trim().split_once(':')?;
        if id.is_empty() {
            return None;
        }
        let id = id.to_owned();
        Some(match kind {
            "fb_dm" => Self::MessengerDm(id),
            "ig_dm" => Self::InstagramDm(id),
            "fb_comment" => Self::FacebookComment(id),
            "ig_comment" => Self::InstagramComment(id),
            "gbp_review" => Self::GoogleReview(id),
            _ => return None,
        })
    }

    /// The channel a reply to this target is recorded under. Pure.
    pub fn channel(&self) -> &'static str {
        match self {
            Self::MessengerDm(_) => "messenger",
            Self::InstagramDm(_) | Self::InstagramComment(_) => "instagram",
            Self::FacebookComment(_) => "facebook",
            Self::GoogleReview(_) => "google_review",
        }
    }
}

/// The system's config as JSON.
pub fn config(system: &IntegrationSystem) -> Value {
    system
        .config
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null)
}

/// The system's credential as a JSON object of secrets.
pub(crate) async fn secrets(
    state: &EngineState,
    system: &IntegrationSystem,
) -> Result<Value, AppError> {
    let raw = crate::credential::resolve_value(
        &state.base.db,
        &crate::credential::ring(state),
        system.credential_ref.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::Validation(format!("{}: no credential set", system.name)))?;
    serde_json::from_str::<Value>(&raw)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "{}: the credential is not a JSON object",
                system.name
            ))
        })
}

/// Z1-T10: one named secret of a social system's credential, sealed.
pub async fn sealed_secret(
    state: &EngineState,
    system: &IntegrationSystem,
    name: &str,
) -> Result<crate::credential::Credential, AppError> {
    let secrets = secrets(state, system).await?;
    Ok(crate::credential::Credential::new(
        secret(&secrets, name)?.to_owned(),
    ))
}

/// One secret by name.
pub(crate) fn secret<'a>(secrets: &'a Value, name: &str) -> Result<&'a str, AppError> {
    secrets
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation(format!("the credential has no {name}")))
}

/// The active systems of one kind (`"social": kind`).
pub async fn systems(state: &EngineState, kind: &str) -> Result<Vec<IntegrationSystem>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'social' END = $1 \
          ORDER BY created_at, id",
    )
    .bind(kind)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for id in ids {
        if let Some(system) = crate::system::load(&state.base.db, id).await? {
            out.push(system);
        }
    }
    Ok(out)
}

/// The system of `kind` whose `inbound_key` is `key` (at least 16
/// characters, compared by SHA-256 digest).
pub async fn system_by_key(
    state: &EngineState,
    kind: &str,
    key: &str,
) -> Result<Option<IntegrationSystem>, AppError> {
    use sha2::{Digest, Sha256};
    let presented = Sha256::digest(key.as_bytes());
    for system in systems(state, kind).await? {
        let expected = config(&system)
            .get("inbound_key")
            .and_then(Value::as_str)
            .filter(|k| k.len() >= 16)
            .map(str::to_owned);
        if let Some(expected) = expected
            && Sha256::digest(expected.as_bytes()) == presented
        {
            return Ok(Some(system));
        }
    }
    Ok(None)
}

/// Sends `text` as a reply to `target` through the system it arrived on;
/// answers the provider's id for the reply when it gives one.
pub async fn reply(
    state: &EngineState,
    system: &IntegrationSystem,
    target: &ReplyTarget,
    text: &str,
) -> Result<Option<String>, AppError> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > 2000 {
        return Err(AppError::Validation("body: 1 to 2000 characters".into()));
    }
    match target {
        ReplyTarget::GoogleReview(name) => {
            google_reviews::send_reply(state, system, name, text).await?;
            Ok(None)
        }
        _ => {
            let secrets = secrets(state, system).await?;
            meta::send_reply(secret(&secrets, "page_token")?, target, text).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn social_meta_addresses_round_trip() {
        for target in [
            ReplyTarget::MessengerDm("123".into()),
            ReplyTarget::InstagramDm("456".into()),
            ReplyTarget::FacebookComment("789_1".into()),
            ReplyTarget::InstagramComment("1789".into()),
            ReplyTarget::GoogleReview("accounts/1/locations/2/reviews/x:y".into()),
        ] {
            assert_eq!(ReplyTarget::parse(&target.address()), Some(target.clone()));
        }
        assert_eq!(ReplyTarget::parse("fb_dm:"), None);
        assert_eq!(ReplyTarget::parse("sms:+966"), None);
        assert_eq!(
            ReplyTarget::InstagramComment("1".into()).channel(),
            "instagram"
        );
        assert_eq!(
            ReplyTarget::FacebookComment("1".into()).channel(),
            "facebook"
        );
    }
}

//! J8-T1: Google Business Profile reviews.
//!
//! The system's config names the location (`account_id`, `location_id`) and
//! the OAuth app's `client_id`; its credential holds `client_secret` and a
//! `refresh_token` granted the `business.manage` scope. Reviews are read
//! newest first, and a reply is the review's single owner reply (`PUT
//! .../reply`, which replaces an earlier one).

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};

use super::{ReplyTarget, SocialMessage, config, secret, secrets};
use crate::system::IntegrationSystem;

const API: &str = "https://mybusiness.googleapis.com/v4";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const TIMEOUT: Duration = Duration::from_secs(15);

/// One review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// `accounts/{a}/locations/{l}/reviews/{id}`.
    pub name: String,
    pub reviewer: Option<String>,
    /// 1 to 5; 0 when the review gives no rating.
    pub stars: u8,
    pub comment: Option<String>,
    pub replied: bool,
}

/// The star count of a `starRating`. Pure.
pub fn stars(rating: &str) -> u8 {
    match rating {
        "ONE" => 1,
        "TWO" => 2,
        "THREE" => 3,
        "FOUR" => 4,
        "FIVE" => 5,
        _ => 0,
    }
}

/// The reviews in a list answer. Pure.
pub fn parse_reviews(body: &str) -> Option<Vec<Review>> {
    let v: Value = serde_json::from_str(body).ok()?;
    let Some(list) = v.get("reviews") else {
        // No reviews yet: the field is left out.
        return v.is_object().then(Vec::new);
    };
    Some(
        list.as_array()?
            .iter()
            .filter_map(|r| {
                Some(Review {
                    name: r.get("name")?.as_str()?.to_owned(),
                    reviewer: r
                        .get("reviewer")
                        .and_then(|p| p.get("displayName"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    stars: stars(
                        r.get("starRating")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    ),
                    comment: r
                        .get("comment")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .map(str::to_owned),
                    replied: r.get("reviewReply").is_some(),
                })
            })
            .collect(),
    )
}

/// The communication a review becomes. Pure.
pub fn review_message(review: &Review) -> SocialMessage {
    let rating = if review.stars > 0 {
        format!(
            "{}{} ",
            "★".repeat(usize::from(review.stars)),
            "☆".repeat(usize::from(5 - review.stars.min(5)))
        )
    } else {
        String::new()
    };
    let who = review
        .reviewer
        .clone()
        .unwrap_or_else(|| "A customer".to_owned());
    SocialMessage {
        channel: "google_review",
        address: ReplyTarget::GoogleReview(review.name.clone()).address(),
        author: review.reviewer.clone(),
        subject: format!("{rating}Google review from {who}"),
        text: review
            .comment
            .clone()
            .unwrap_or_else(|| "(a rating without a comment)".to_owned()),
    }
}

fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .unwrap_or_default()
    })
}

/// A fresh access token from the system's refresh token.
async fn access_token(state: &EngineState, system: &IntegrationSystem) -> Result<String, AppError> {
    let cfg = config(system);
    let client_id = cfg
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation(format!("{}: config has no client_id", system.name)))?;
    let secrets = secrets(state, system).await?;
    let res = client()
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", secret(&secrets, "client_secret")?),
            ("refresh_token", secret(&secrets, "refresh_token")?),
        ])
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::Validation(format!("Google refused the token refresh ({status})")))
}

fn location(system: &IntegrationSystem) -> Result<String, AppError> {
    let cfg = config(system);
    let part = |key: &str| {
        cfg.get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric()))
            .ok_or_else(|| {
                AppError::Validation(format!("{}: config has no valid {key}", system.name))
            })
    };
    Ok(format!(
        "accounts/{}/locations/{}",
        part("account_id")?,
        part("location_id")?
    ))
}

/// The location's latest reviews, newest first.
pub async fn fetch_reviews(
    state: &EngineState,
    system: &IntegrationSystem,
) -> Result<Vec<Review>, AppError> {
    let token = access_token(state, system).await?;
    let url = url::Url::parse_with_params(
        &format!("{API}/{}/reviews", location(system)?),
        &[("pageSize", "50"), ("orderBy", "updateTime desc")],
    )
    .map_err(AppError::internal)?;
    let res = client()
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(AppError::Validation(format!(
            "Google refused the reviews list ({status})"
        )));
    }
    parse_reviews(&body)
        .ok_or_else(|| AppError::Validation("Google answered an unreadable review list".into()))
}

/// Posts (or replaces) the owner's reply to a review of this location.
pub async fn send_reply(
    state: &EngineState,
    system: &IntegrationSystem,
    name: &str,
    text: &str,
) -> Result<(), AppError> {
    if !name.starts_with(&format!("{}/reviews/", location(system)?)) {
        return Err(AppError::Validation("not a review of this location".into()));
    }
    let token = access_token(state, system).await?;
    let res = client()
        .put(format!("{API}/{name}/reply"))
        .bearer_auth(token)
        .json(&json!({ "comment": text }))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "Google refused the reply ({status})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"{"reviews":[
        {"name":"accounts/1/locations/2/reviews/AbC","reviewId":"AbC",
         "reviewer":{"displayName":"Fahad"},"starRating":"FOUR","comment":" خدمة ممتازة ",
         "createTime":"2026-10-18T10:00:00Z","updateTime":"2026-10-18T10:00:00Z"},
        {"name":"accounts/1/locations/2/reviews/DeF","reviewId":"DeF",
         "reviewer":{"isAnonymous":true},"starRating":"ONE",
         "reviewReply":{"comment":"Sorry","updateTime":"2026-10-18T11:00:00Z"}}],
        "averageRating":2.5,"totalReviewCount":2}"#;

    #[test]
    fn social_google_reviews_are_read() {
        let reviews = parse_reviews(LIST).unwrap();
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].stars, 4);
        assert_eq!(reviews[0].comment.as_deref(), Some("خدمة ممتازة"));
        assert!(!reviews[0].replied);
        assert_eq!(reviews[1].reviewer, None);
        assert!(reviews[1].replied);
        assert_eq!(parse_reviews(r#"{"totalReviewCount":0}"#), Some(Vec::new()));
        assert_eq!(parse_reviews("nope"), None);
    }

    #[test]
    fn social_google_reviews_become_messages() {
        let reviews = parse_reviews(LIST).unwrap();
        let m = review_message(&reviews[0]);
        assert_eq!(m.channel, "google_review");
        assert_eq!(m.address, "gbp_review:accounts/1/locations/2/reviews/AbC");
        assert_eq!(m.subject, "★★★★☆ Google review from Fahad");
        let anonymous = review_message(&reviews[1]);
        assert_eq!(anonymous.subject, "★☆☆☆☆ Google review from A customer");
        assert_eq!(anonymous.text, "(a rating without a comment)");
        assert_eq!(stars("STAR_RATING_UNSPECIFIED"), 0);
    }
}

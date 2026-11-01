//! E4-T1: A/B tests of email campaigns, on top of [`crate::ab_test`]'s
//! decision.
//!
//! A campaign started with `variants` (and optionally `ab_test` settings)
//! sends its own design as variant `A` and each extra design as `B`, `C`, ...
//! Recipients are taken in a random order (their random tokens); the first
//! `recipients_per_variant` of them per variant (default 1,000) get that
//! variant and the rest are `held`.
//!
//! A test counts opens and clicks, so it needs email tracking on
//! (`email.tracking.enabled`, D16-T1) and follows its rules: a test
//! recipient gets a tracked copy of the variant, whose fixed links (those
//! with no placeholder) go through `GET /api/v1/marketing/c/{token}/{n}`,
//! which records the click and redirects to the variant's `n`th link, never
//! to an address the request names, and whose one-pixel image
//! `GET /api/v1/marketing/o/{token}` records the open; a person who
//! withdrew the `email_tracking` purpose gets the untracked copy and is not
//! counted; a hit within two seconds of sending or from a known mail scanner
//! is not counted (`attome_notification::tracking::is_scanner`). These are
//! the campaign's own routes, not D16's `/api/v1/track/...`, because a D16
//! token names a `communication` row and a campaign recipient has none;
//! the recipient's random token is the key. Campaigns without a test, and
//! the held recipients the winner goes to, are not tracked.
//!
//! When every test recipient has been worked through and the window
//! (default four hours from the start) has passed, the campaign sweep
//! decides: the variant with the best open (or click) rate wins when a
//! two-proportion z-test says so at 5%; otherwise the `fallback` applies,
//! `leader` (default) sending the best variant anyway and `stop` sending
//! nothing more. The held recipients then get the winner, through the same
//! consent, cap and unsubscribe rules as everyone else.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::ab_test::{Decision, Metric, Thresholds, VariantStats};

/// The most variants one test sends, its own design included.
pub const MAX_VARIANTS: usize = 5;
/// Recipients per variant when the test does not say.
pub const DEFAULT_PER_VARIANT: u32 = 1_000;
/// Minutes from the start before a winner is picked, by default.
pub const DEFAULT_WINDOW_MINUTES: u32 = 240;
/// The significance level.
pub const ALPHA: f64 = 0.05;
/// The most tracked links one variant's body keeps.
pub const MAX_LINKS: usize = 100;

/// One more version of the email to test.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EmailVariantBody {
    /// Its subject line (at most 200 characters).
    pub subject: String,
    /// Its email designer JSON.
    #[schema(value_type = Object)]
    pub design: Value,
}

/// How a test picks its winner; every field has a default.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct AbTestBody {
    /// `opens` (default) or `clicks`.
    #[serde(default)]
    pub metric: Option<String>,
    /// Recipients per variant in the test, 10 to 50,000 (default 1,000).
    #[serde(default)]
    pub recipients_per_variant: Option<u32>,
    /// Minutes before the winner is picked, 15 to 10,080 (default 240).
    #[serde(default)]
    pub window_minutes: Option<u32>,
    /// Without a significant winner: `leader` (default) sends the best
    /// variant to the rest, `stop` sends nothing more.
    #[serde(default)]
    pub fallback: Option<String>,
}

/// A test's checked settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbSettings {
    pub metric: &'static str,
    pub per_variant: u32,
    pub window_minutes: u32,
    pub fallback: &'static str,
}

/// Checks a test's settings. Pure.
pub fn settings(body: Option<&AbTestBody>) -> Result<AbSettings, AppError> {
    let default = AbTestBody::default();
    let body = body.unwrap_or(&default);
    let metric = match body.metric.as_deref().map(str::trim) {
        None | Some("opens") => "opens",
        Some("clicks") => "clicks",
        Some(_) => {
            return Err(AppError::Validation(
                "ab_test.metric must be opens or clicks".into(),
            ));
        }
    };
    let per_variant = body.recipients_per_variant.unwrap_or(DEFAULT_PER_VARIANT);
    if !(10..=50_000).contains(&per_variant) {
        return Err(AppError::Validation(
            "ab_test.recipients_per_variant must be 10 to 50,000".into(),
        ));
    }
    let window_minutes = body.window_minutes.unwrap_or(DEFAULT_WINDOW_MINUTES);
    if !(15..=10_080).contains(&window_minutes) {
        return Err(AppError::Validation(
            "ab_test.window_minutes must be 15 to 10,080".into(),
        ));
    }
    let fallback = match body.fallback.as_deref().map(str::trim) {
        None | Some("leader") => "leader",
        Some("stop") => "stop",
        Some(_) => {
            return Err(AppError::Validation(
                "ab_test.fallback must be leader or stop".into(),
            ));
        }
    };
    Ok(AbSettings {
        metric,
        per_variant,
        window_minutes,
        fallback,
    })
}

/// The name of the `i`th variant: `A`, `B`, ... Pure.
pub fn variant_name(i: usize) -> String {
    char::from(b'A' + (i % 26) as u8).to_string()
}

/// Which variant each of `people` recipients gets, in their (random)
/// order: the first `per_variant` per variant round-robin, `None` (held)
/// for the rest. Pure.
pub fn assign(people: usize, variants: usize, per_variant: usize) -> Vec<Option<usize>> {
    let in_test = people.min(variants.saturating_mul(per_variant));
    (0..people)
        .map(|i| (i < in_test && variants > 0).then_some(i % variants.max(1)))
        .collect()
}

fn unescape(attr: &str) -> String {
    attr.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// A variant's body with its fixed links tracked and an open pixel, and
/// the links in order. A link that holds a placeholder (it differs per
/// person) or is not `http(s)` stays as it is. `base` is the deployment's
/// address. Pure.
pub fn track_body(html: &str, base: &str) -> (String, Vec<String>) {
    let base = base.trim_end_matches('/');
    let mut out = String::with_capacity(html.len() + 200);
    let mut links: Vec<String> = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("href=\"") {
        let (before, after) = rest.split_at(at + "href=\"".len());
        out.push_str(before);
        let Some(end) = after.find('"') else {
            rest = after;
            break;
        };
        let raw = &after[..end];
        let url = unescape(raw);
        let lower = url.to_ascii_lowercase();
        let trackable = (lower.starts_with("https://") || lower.starts_with("http://"))
            && !raw.contains("{{")
            && links.len() < MAX_LINKS;
        if trackable {
            out.push_str(&format!(
                "{base}/api/v1/marketing/c/{{{{ tracking_token }}}}/{}",
                links.len()
            ));
            links.push(url);
        } else {
            out.push_str(raw);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    let pixel = format!(
        "<img src=\"{base}/api/v1/marketing/o/{{{{ tracking_token }}}}\" width=\"1\" height=\"1\" alt=\"\" style=\"display:block;border:0\">"
    );
    match out.to_ascii_lowercase().rfind("</body>") {
        Some(at) => out.insert_str(at, &pixel),
        None => out.push_str(&pixel),
    }
    (out, links)
}

/// What the test decided, as kept on the send.
fn decision_json(decision: &Decision) -> Value {
    match decision {
        Decision::Waiting { reason } => json!({ "kind": "waiting", "reason": reason }),
        Decision::Winner {
            variant,
            z,
            p_value,
        } => json!({ "kind": "winner", "variant": variant, "z": z, "p_value": p_value }),
        Decision::NoClearWinner { leader, z, p_value } => {
            json!({ "kind": "no_clear_winner", "leader": leader, "z": z, "p_value": p_value })
        }
    }
}

/// The variant the held recipients get, or `None` to send them nothing,
/// for a decision past its window. `Waiting` is not final. Pure.
pub fn release_to(decision: &Decision, fallback: &str) -> Option<Option<String>> {
    match decision {
        Decision::Waiting { .. } => None,
        Decision::Winner { variant, .. } => Some(Some(variant.clone())),
        Decision::NoClearWinner { leader, .. } => {
            Some((fallback == "leader").then(|| leader.clone()))
        }
    }
}

type StatRow = (String, i64, i64, i64);

/// Decides a test whose test recipients are all worked through, and
/// releases the held recipients to the winner (or skips them). Answers
/// whether it decided. Safe to run again: only one run records a decision.
pub async fn decide(
    state: &EngineState,
    send_id: Uuid,
    started_at: DateTime<Utc>,
    metric: &str,
    window_minutes: i32,
    fallback: &str,
) -> Result<bool, AppError> {
    let db = &state.base.db;
    let rows: Vec<StatRow> = sqlx::query_as(
        "SELECT variant, \
                COUNT(*) FILTER (WHERE status = 'sent'), \
                COUNT(*) FILTER (WHERE status = 'sent' AND opened_at IS NOT NULL), \
                COUNT(*) FILTER (WHERE status = 'sent' AND clicked_at IS NOT NULL) \
           FROM email_campaign_recipient \
          WHERE send_id = $1 AND variant IS NOT NULL AND tracked \
          GROUP BY variant ORDER BY variant",
    )
    .bind(send_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let clicks = metric == "clicks";
    let stats: Vec<VariantStats> = rows
        .iter()
        .map(|(name, sent, opened, clicked)| VariantStats {
            name: name.clone(),
            exposures: u64::try_from(*sent).unwrap_or(0),
            successes: u64::try_from(if clicks { *clicked } else { *opened }).unwrap_or(0),
        })
        .collect();
    // Every test recipient has been worked through, so the samples are
    // what they will be: only the window is waited for.
    let thresholds = Thresholds {
        min_samples_per_variant: 1,
        window: chrono::Duration::minutes(i64::from(window_minutes.max(0))),
    };
    let decision = crate::ab_test::decide(
        started_at,
        Utc::now(),
        thresholds,
        if clicks {
            Metric::Clicks
        } else {
            Metric::Opens
        },
        &stats,
        ALPHA,
    );
    let Some(winner) = release_to(&decision, fallback) else {
        return Ok(false);
    };
    let mut tx = attome_db::tx::begin(db).await?;
    let claimed = sqlx::query(
        "UPDATE email_campaign_send SET ab_winner = $2, ab_decided_at = now(), ab_decision = $3 \
          WHERE id = $1 AND ab_decided_at IS NULL",
    )
    .bind(send_id)
    .bind(winner.as_deref())
    .bind(decision_json(&decision))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        return Ok(false);
    }
    match &winner {
        Some(variant) => {
            sqlx::query(
                "UPDATE email_campaign_recipient SET status = 'pending', variant = $2 \
                  WHERE send_id = $1 AND status = 'held'",
            )
            .bind(send_id)
            .bind(variant)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        None => {
            sqlx::query(
                "UPDATE email_campaign_recipient SET status = 'skipped', attempted_at = now() \
                  WHERE send_id = $1 AND status = 'held'",
            )
            .bind(send_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "email_campaign_send",
            send_id,
            AuditOperation::Update,
            "email_campaign.ab_decided",
            Uuid::nil(),
        )
        .comment(match &winner {
            Some(variant) => format!("variant {variant} goes to the held recipients"),
            None => "no clear winner; the held recipients get nothing".to_owned(),
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// A recipient token as campaign emails carry it.
fn token_ok(token: &str) -> bool {
    token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether a hit on a tracked recipient's token counts: tracking is on, the
/// recipient was tracked, and the hit is not a scanner's.
async fn counts(state: &EngineState, token: &str, headers: &HeaderMap) -> bool {
    if !token_ok(token) || !attome_notification::tracking::enabled(state) {
        return false;
    }
    let sent: Option<(Option<DateTime<Utc>>,)> = match sqlx::query_as(
        "SELECT attempted_at FROM email_campaign_recipient \
          WHERE unsubscribe_token = $1 AND tracked AND status = 'sent'",
    )
    .bind(token)
    .fetch_optional(&state.base.db)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(error = %e, "email campaign: a hit was not checked");
            return false;
        }
    };
    let Some((Some(sent_at),)) = sent else {
        return false;
    };
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    !attome_notification::tracking::is_scanner(agent, sent_at.timestamp(), Utc::now())
}

/// A transparent 1x1 GIF.
const PIXEL: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

#[utoipa::path(
    get,
    path = "/api/v1/marketing/o/{token}",
    operation_id = "email_campaign_open",
    tag = "marketing",
    params(("token" = String, Path, description = "The token from the email's tracking image")),
    responses(
        (status = 200, description = "A transparent one-pixel image (the same for any token)", content_type = "image/gif", body = Vec<u8>),
    ),
)]
/// Email open pixel
///
/// E6-T9: the recipient of `token` engaged; failures are logged.
async fn engaged(state: &EngineState, token: &str) {
    let person: Option<(String, Uuid)> = match sqlx::query_as(
        "SELECT subject_entity, subject_id FROM email_campaign_recipient \
          WHERE unsubscribe_token = $1",
    )
    .bind(token)
    .fetch_optional(&state.base.db)
    .await
    {
        Ok(person) => person,
        Err(error) => {
            tracing::warn!(%error, "email campaign: engagement not recorded");
            return;
        }
    };
    if let Some((entity, id)) = person
        && let Err(error) = attome_core::engagement::touch(state, &entity, &[id]).await
    {
        tracing::warn!(%error, "email campaign: engagement not recorded");
    }
}

/// The image an A/B-tested campaign email carries: the first load records
/// that the recipient opened it. Public; the token is the recipient's own,
/// and an unknown one answers the same image.
pub(crate) async fn get_open(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = token.trim();
    if counts(&state, token, &headers).await
        && let Err(e) = sqlx::query(
            "UPDATE email_campaign_recipient SET opened_at = now() \
              WHERE unsubscribe_token = $1 AND opened_at IS NULL",
        )
        .bind(token)
        .execute(&state.base.db)
        .await
    {
        tracing::warn!(error = %e, "email campaign: an open was not recorded");
    }
    if counts(&state, token, &headers).await {
        engaged(&state, token).await;
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/gif"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        PIXEL,
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/c/{token}/{n}",
    operation_id = "email_campaign_click",
    tag = "marketing",
    params(
        ("token" = String, Path, description = "The token from the email's link"),
        ("n" = u32, Path, description = "The link's position in the email"),
    ),
    responses(
        (status = 302, description = "On to the link's address, as the email was sent with it"),
        (status = 404, description = "No such email link", body = ErrorResponse),
    ),
)]
/// Email link click
///
/// A tracked link in an A/B-tested campaign email: records the click (and
/// the open) and redirects to the email's own link at that position, never
/// to an address the request names. Public; the token is the recipient's
/// own.
pub(crate) async fn get_click(
    State(state): State<EngineState>,
    Path((token, n)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let token = token.trim();
    if !token_ok(token) {
        return Err(AppError::NotFound);
    }
    let link: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT v.links ->> $2::int FROM email_campaign_recipient r \
           JOIN email_campaign_variant v ON v.send_id = r.send_id AND v.name = r.variant \
          WHERE r.unsubscribe_token = $1",
    )
    .bind(token)
    .bind(i32::try_from(n).unwrap_or(i32::MAX))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(url) = link
        .and_then(|(url,)| url)
        .filter(|u| attome_notification::tracking::safe_url(u))
    else {
        return Err(AppError::NotFound);
    };
    if counts(&state, token, &headers).await
        && let Err(e) = sqlx::query(
            "UPDATE email_campaign_recipient \
            SET clicked_at = COALESCE(clicked_at, now()), opened_at = COALESCE(opened_at, now()) \
          WHERE unsubscribe_token = $1 AND clicked_at IS NULL",
        )
        .bind(token)
        .execute(&state.base.db)
        .await
    {
        tracing::warn!(error = %e, "email campaign: a click was not recorded");
    }
    if counts(&state, token, &headers).await {
        engaged(&state, token).await;
    }
    Ok((
        StatusCode::FOUND,
        [
            (header::LOCATION, url.as_str()),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_links_are_tracked_and_personal_ones_left() {
        let html = "<html><body><a href=\"https://shop.example/sale?a=1&amp;b=2\">Sale</a>\
                    <a href=\"{{ profile_url }}\">You</a>\
                    <a href=\"mailto:help@example.com\">Help</a></body></html>";
        let (body, links) = track_body(html, "https://crm.example/");
        assert_eq!(links, vec!["https://shop.example/sale?a=1&b=2".to_owned()]);
        assert!(
            body.contains("href=\"https://crm.example/api/v1/marketing/c/{{ tracking_token }}/0\"")
        );
        assert!(body.contains("href=\"{{ profile_url }}\""));
        assert!(body.contains("href=\"mailto:help@example.com\""));
        let pixel = body
            .find("/api/v1/marketing/o/{{ tracking_token }}")
            .unwrap();
        assert!(pixel < body.find("</body>").unwrap(), "{body}");
    }

    #[test]
    fn the_test_takes_its_share_round_robin_and_holds_the_rest() {
        let got = assign(7, 2, 2);
        assert_eq!(
            got,
            vec![Some(0), Some(1), Some(0), Some(1), None, None, None]
        );
        assert_eq!(assign(3, 2, 1000), vec![Some(0), Some(1), Some(0)]);
        assert_eq!(variant_name(0), "A");
        assert_eq!(variant_name(2), "C");
    }

    #[test]
    fn settings_default_and_refuse_out_of_range() {
        assert_eq!(
            settings(None).unwrap(),
            AbSettings {
                metric: "opens",
                per_variant: 1_000,
                window_minutes: 240,
                fallback: "leader",
            }
        );
        let bad = AbTestBody {
            metric: Some("replies".into()),
            ..AbTestBody::default()
        };
        assert!(settings(Some(&bad)).is_err());
        let short = AbTestBody {
            window_minutes: Some(5),
            ..AbTestBody::default()
        };
        assert!(settings(Some(&short)).is_err());
    }

    #[test]
    fn a_winner_or_the_fallback_decides_who_gets_the_rest() {
        let winner = Decision::Winner {
            variant: "B".into(),
            z: 3.0,
            p_value: 0.001,
        };
        assert_eq!(release_to(&winner, "stop"), Some(Some("B".into())));
        let unclear = Decision::NoClearWinner {
            leader: "A".into(),
            z: 0.5,
            p_value: 0.6,
        };
        assert_eq!(release_to(&unclear, "leader"), Some(Some("A".into())));
        assert_eq!(release_to(&unclear, "stop"), Some(None));
        assert_eq!(
            release_to(&Decision::Waiting { reason: "early" }, "leader"),
            None
        );
    }
}

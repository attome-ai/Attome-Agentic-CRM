//! E6-T8: sender reputation from Google Postmaster Tools and Microsoft
//! SNDS, read into the deployment and nowhere else.
//!
//! Each source is an `integration_system` row the operator adds:
//! - `{"reputation": "google_postmaster", "user_id": "<uuid>"}` reads
//!   Postmaster Tools as that person, through their own Google connection
//!   (D15-T1), which must include the Postmaster scope;
//! - `{"reputation": "microsoft_snds"}` with the SNDS automated-access key
//!   as its credential.
//!
//! Each source is a pure codec here, tested with recorded answers.

use std::sync::OnceLock;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use serde_json::Value;
use uuid::Uuid;

use super::user_mail_sync::{Provider, access_token};

const TIMEOUT: Duration = Duration::from_secs(20);

/// One day's reputation for a domain (Postmaster) or an IP (SNDS).
#[derive(Debug, Clone, PartialEq)]
pub struct Reputation {
    pub day: NaiveDate,
    /// The sending domain, or for SNDS the sending IP.
    pub subject: String,
    /// Lower case: `high`, `medium`, `low`, `bad` (Postmaster);
    /// `green`, `yellow`, `red` (SNDS).
    pub reputation: Option<String>,
    /// A fraction (0.003 is 0.3%).
    pub spam_rate: Option<f64>,
}

pub fn postmaster_url(domain: &str, day: NaiveDate) -> String {
    format!(
        "https://gmailpostmastertools.googleapis.com/v1/domains/{domain}/trafficStats/{}",
        day.format("%Y%m%d")
    )
}

/// A Postmaster `trafficStats` answer. Pure.
pub fn parse_postmaster(domain: &str, day: NaiveDate, body: &str) -> Option<Reputation> {
    let v: Value = serde_json::from_str(body).ok()?;
    let reputation = v
        .get("domainReputation")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    let spam_rate = v.get("userReportedSpamRatio").and_then(Value::as_f64);
    (reputation.is_some() || spam_rate.is_some()).then(|| Reputation {
        day,
        subject: domain.to_owned(),
        reputation,
        spam_rate,
    })
}

pub fn snds_url(key: &str) -> String {
    format!("https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key={key}")
}

/// A complaint rate as SNDS writes it (`< 0.1%`, `0.3%`). Pure.
fn snds_rate(raw: &str) -> Option<f64> {
    let raw = raw
        .trim()
        .trim_start_matches('<')
        .trim()
        .trim_end_matches('%')
        .trim();
    raw.parse::<f64>().ok().map(|p| p / 100.0)
}

/// SNDS's CSV: one row per IP (IP, start, end, RCPT, DATA, recipients,
/// filter result, complaint rate, ...); the day is the activity start's.
/// Pure.
pub fn parse_snds(body: &str) -> Vec<Reputation> {
    body.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split(',').map(str::trim).collect();
            if cols.len() < 8 || cols[0].parse::<std::net::IpAddr>().is_err() {
                return None;
            }
            let day = cols[1]
                .split_whitespace()
                .next()
                .and_then(|d| NaiveDate::parse_from_str(d, "%m/%d/%Y").ok())?;
            Some(Reputation {
                day,
                subject: cols[0].to_owned(),
                reputation: Some(cols[6].to_ascii_lowercase()).filter(|r| !r.is_empty()),
                spam_rate: snds_rate(cols[7]),
            })
        })
        .collect()
}

fn client() -> &'static attome_outbound::http::Outbound {
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(
            attome_outbound::http::Purpose::public("sender-reputation"),
            |b| b.timeout(TIMEOUT),
        )
    })
}

/// A configured reputation source: its config and credential.
async fn source(
    state: &EngineState,
    kind: &str,
) -> Result<Option<(Value, Option<String>)>, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'reputation' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(kind)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((config, credential_ref)) = row else {
        return Ok(None);
    };
    let secret = crate::credential::resolve(
        &state.base.db,
        &state.base.config.integration.credential_encryption_key,
        credential_ref.as_deref(),
    )
    .await?;
    Ok(Some((
        config
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or(Value::Null),
        secret,
    )))
}

async fn get(request: reqwest::RequestBuilder) -> Result<(u16, String), AppError> {
    let res = request.send().await.map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

/// Postmaster Tools for `domains` on `day`; empty without a configured
/// source. A domain Postmaster has no data for is left out.
pub async fn postmaster(
    state: &EngineState,
    domains: &[String],
    day: NaiveDate,
) -> Result<Vec<Reputation>, AppError> {
    let Some((config, _)) = source(state, "google_postmaster").await? else {
        return Ok(Vec::new());
    };
    let user = config
        .get("user_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::Validation("google_postmaster: user_id is not configured".into())
        })?;
    let token = access_token(state, user, Provider::Google)
        .await?
        .ok_or_else(|| {
            AppError::Validation("google_postmaster: the user has not connected Google".into())
        })?;
    let mut out = Vec::new();
    for domain in domains {
        let (status, body) = get(client()
            .get(postmaster_url(domain, day))
            .bearer_auth(&token))
        .await?;
        if status == 404 {
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(AppError::Validation(format!(
                "google_postmaster refused the request ({status})"
            )));
        }
        out.extend(parse_postmaster(domain, day, &body));
    }
    Ok(out)
}

/// SNDS data for the key's IPs; empty without a configured source.
pub async fn snds(state: &EngineState) -> Result<Vec<Reputation>, AppError> {
    let Some((_, key)) = source(state, "microsoft_snds").await? else {
        return Ok(Vec::new());
    };
    let key = key
        .ok_or_else(|| AppError::Validation("microsoft_snds: the key is not configured".into()))?;
    let (status, body) = get(client().get(snds_url(&key))).await?;
    if !(200..300).contains(&status) {
        return Err(AppError::Validation(format!(
            "microsoft_snds refused the request ({status})"
        )));
    }
    Ok(parse_snds(&body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 19).unwrap()
    }

    #[test]
    fn reputation_postmaster_answer() {
        let body = r#"{"name": "domains/example.com/trafficStats/20261019", "domainReputation": "HIGH", "userReportedSpamRatio": 0.0012}"#;
        assert_eq!(
            parse_postmaster("example.com", day(), body),
            Some(Reputation {
                day: day(),
                subject: "example.com".into(),
                reputation: Some("high".into()),
                spam_rate: Some(0.0012),
            })
        );
        assert_eq!(parse_postmaster("example.com", day(), "{}"), None);
        assert!(postmaster_url("example.com", day()).ends_with("/trafficStats/20261019"));
    }

    #[test]
    fn reputation_snds_csv() {
        let body = "192.0.2.10,10/19/2026 1:00 AM,10/19/2026 11:00 PM,1200,1180,1300,GREEN,< 0.1%,,,0,mail.example.com,,\n\
                    not,a,row\n\
                    192.0.2.11,10/19/2026 1:00 AM,10/19/2026 11:00 PM,90,90,95,RED,0.3%,,,4,mail.example.com,,";
        let rows = parse_snds(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].reputation.as_deref(), Some("green"));
        assert!((rows[0].spam_rate.unwrap() - 0.001).abs() < 1e-12);
        assert_eq!(rows[1].subject, "192.0.2.11");
        assert!((rows[1].spam_rate.unwrap() - 0.003).abs() < 1e-12);
        assert_eq!(rows[1].day, day());
    }
}

//! E22-T1: webinars on Zoom and Microsoft Teams. Registrants are pushed to
//! the provider before the webinar (so each gets the provider's own join
//! link and reminders) and attendance is read after it; the marketing
//! engine matches the attendance to its registrations.
//!
//! Zoom uses the deployment's server-to-server app (as its meetings do).
//! Teams webinars are Microsoft Graph virtual events and act as the
//! webinar's organizer, with that person's own connection (D15-T1).
//! Each provider is a pure codec here, tested with recorded answers; the
//! calls are [`push_registrant`] and [`attendance`].

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Attendee, answer, client, refused};
use crate::connector::adapters::user_mail_sync::{Provider as MailProvider, access_token};

const GRAPH: &str = "https://graph.microsoft.com/v1.0/solutions/virtualEvents/webinars";

/// A person to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registrant {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

/// What the provider answered for a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub registrant_id: String,
    /// The person's own join link, where the provider gives one.
    pub join_url: Option<String>,
}

/// The webinar platforms supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebinarProvider {
    Zoom,
    Teams,
}

impl WebinarProvider {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "zoom" => Some(Self::Zoom),
            "teams" => Some(Self::Teams),
            _ => None,
        }
    }
}

/// The two halves of a display name. Pure.
pub fn split_name(name: &str) -> (String, String) {
    let name = name.trim();
    match name.rsplit_once(' ') {
        Some((first, last)) => (first.trim().to_owned(), last.trim().to_owned()),
        None => (name.to_owned(), String::new()),
    }
}

pub fn zoom_registrant_url(webinar: &str) -> String {
    format!("https://api.zoom.us/v2/webinars/{webinar}/registrants")
}

pub fn zoom_registrant_body(r: &Registrant) -> Value {
    json!({ "email": r.email, "first_name": r.first_name, "last_name": r.last_name })
}

pub fn parse_zoom_registrant(status: u16, body: &str) -> Option<Registered> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    Some(Registered {
        registrant_id: v.get("registrant_id")?.as_str()?.to_owned(),
        join_url: v.get("join_url").and_then(Value::as_str).map(str::to_owned),
    })
}

/// Zoom's past-webinar participant report (same shape as a meeting's).
pub fn zoom_participants_url(webinar: &str) -> String {
    format!("https://api.zoom.us/v2/report/webinars/{webinar}/participants?page_size=300")
}

pub fn teams_registration_url(webinar: &str) -> String {
    format!("{GRAPH}/{webinar}/registrations")
}

pub fn teams_registration_body(r: &Registrant) -> Value {
    json!({ "firstName": r.first_name, "lastName": r.last_name, "email": r.email })
}

pub fn parse_teams_registration(status: u16, body: &str) -> Option<Registered> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    Some(Registered {
        registrant_id: v.get("id")?.as_str()?.to_owned(),
        join_url: None,
    })
}

pub fn teams_sessions_url(webinar: &str) -> String {
    format!("{GRAPH}/{webinar}/sessions")
}

pub fn teams_reports_url(webinar: &str, session: &str) -> String {
    format!("{GRAPH}/{webinar}/sessions/{session}/attendanceReports")
}

pub fn teams_records_url(webinar: &str, session: &str, report: &str) -> String {
    format!("{GRAPH}/{webinar}/sessions/{session}/attendanceReports/{report}/attendanceRecords")
}

/// The ids in a Graph collection (`value[].id`). Pure.
pub fn parse_ids(body: &str) -> Vec<String> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|x| x.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// A Teams attendance report's records. Pure.
pub fn parse_teams_records(body: &str) -> Vec<Attendee> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|r| Attendee {
            name: r
                .pointer("/identity/displayName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            email: r
                .get("emailAddress")
                .and_then(Value::as_str)
                .filter(|e| !e.is_empty())
                .map(str::to_owned),
            seconds: r
                .get("totalAttendanceInSeconds")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        })
        .collect()
}

async fn token(
    state: &EngineState,
    provider: WebinarProvider,
    organizer: Option<Uuid>,
) -> Result<String, AppError> {
    match provider {
        WebinarProvider::Zoom => super::zoom::app_token(state).await,
        WebinarProvider::Teams => {
            let organizer = organizer.ok_or_else(|| {
                AppError::Validation("a Teams webinar needs its organizer".into())
            })?;
            access_token(state, organizer, MailProvider::Microsoft)
                .await?
                .ok_or_else(|| {
                    AppError::Validation(
                        "the webinar's organizer has not connected Microsoft".into(),
                    )
                })
        }
    }
}

/// Registers one person for the webinar at the provider.
pub async fn push_registrant(
    state: &EngineState,
    provider: WebinarProvider,
    webinar: &str,
    organizer: Option<Uuid>,
    registrant: &Registrant,
) -> Result<Registered, AppError> {
    let token = token(state, provider, organizer).await?;
    let (url, body, name) = match provider {
        WebinarProvider::Zoom => (
            zoom_registrant_url(webinar),
            zoom_registrant_body(registrant),
            "zoom",
        ),
        WebinarProvider::Teams => (
            teams_registration_url(webinar),
            teams_registration_body(registrant),
            "teams",
        ),
    };
    let (status, text) = answer(client().post(&url).bearer_auth(&token).json(&body)).await?;
    let parsed = match provider {
        WebinarProvider::Zoom => parse_zoom_registrant(status, &text),
        WebinarProvider::Teams => parse_teams_registration(status, &text),
    };
    parsed.ok_or_else(|| refused(name, status))
}

/// Who attended the webinar and for how long.
pub async fn attendance(
    state: &EngineState,
    provider: WebinarProvider,
    webinar: &str,
    organizer: Option<Uuid>,
) -> Result<Vec<Attendee>, AppError> {
    let token = token(state, provider, organizer).await?;
    match provider {
        WebinarProvider::Zoom => {
            let (status, text) = answer(
                client()
                    .get(zoom_participants_url(webinar))
                    .bearer_auth(&token),
            )
            .await?;
            if !(200..300).contains(&status) {
                return Err(refused("zoom", status));
            }
            Ok(super::zoom::parse_attendance(&text))
        }
        WebinarProvider::Teams => {
            let get = |url: String| {
                let token = token.clone();
                async move {
                    let (status, text) = answer(client().get(url).bearer_auth(&token)).await?;
                    if (200..300).contains(&status) {
                        Ok(text)
                    } else {
                        Err(refused("teams", status))
                    }
                }
            };
            let mut out = Vec::new();
            for session in parse_ids(&get(teams_sessions_url(webinar)).await?) {
                for report in parse_ids(&get(teams_reports_url(webinar, &session)).await?) {
                    out.extend(parse_teams_records(
                        &get(teams_records_url(webinar, &session, &report)).await?,
                    ));
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lina() -> Registrant {
        Registrant {
            email: "lina@x.com".into(),
            first_name: "Lina".into(),
            last_name: "Haddad".into(),
        }
    }

    #[test]
    fn webinar_sync_zoom_codec() {
        assert_eq!(zoom_registrant_body(&lina())["first_name"], "Lina");
        let answer = r#"{"id": 9, "registrant_id": "r-1", "join_url": "https://zoom.us/w/9?tk=a"}"#;
        assert_eq!(
            parse_zoom_registrant(201, answer),
            Some(Registered {
                registrant_id: "r-1".into(),
                join_url: Some("https://zoom.us/w/9?tk=a".into()),
            })
        );
        assert_eq!(parse_zoom_registrant(429, answer), None);
        assert!(zoom_participants_url("9").contains("/report/webinars/9/"));
    }

    #[test]
    fn webinar_sync_teams_codec() {
        assert_eq!(teams_registration_body(&lina())["lastName"], "Haddad");
        assert_eq!(
            parse_teams_registration(201, r#"{"id": "reg-7", "status": "registered"}"#)
                .map(|r| r.registrant_id),
            Some("reg-7".into())
        );
        assert_eq!(
            parse_ids(r#"{"value": [{"id": "s1"}, {"id": "s2"}]}"#),
            vec!["s1", "s2"]
        );
        let records = r#"{"value": [
            {"emailAddress": "lina@x.com", "totalAttendanceInSeconds": 1800, "identity": {"displayName": "Lina"}},
            {"emailAddress": "", "totalAttendanceInSeconds": 60}
        ]}"#;
        let parsed = parse_teams_records(records);
        assert_eq!(parsed[0].email.as_deref(), Some("lina@x.com"));
        assert_eq!(parsed[0].seconds, 1800);
        assert_eq!(parsed[1].email, None);
    }

    #[test]
    fn webinar_sync_names_split() {
        assert_eq!(
            split_name("Lina Al Haddad"),
            ("Lina Al".into(), "Haddad".into())
        );
        assert_eq!(split_name("Lina"), ("Lina".into(), String::new()));
        assert_eq!(
            WebinarProvider::parse("teams"),
            Some(WebinarProvider::Teams)
        );
        assert_eq!(WebinarProvider::parse("meet"), None);
    }
}

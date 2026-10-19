//! J7-T1: Zoom through a server-to-server OAuth app (account credentials).

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{Attendee, Meeting, Recording, answer, client, video_app};

pub const CREATE_URL: &str = "https://api.zoom.us/v2/users/me/meetings";
const TOKEN_URL: &str = "https://zoom.us/oauth/token";

/// A scheduled meeting (type 2) at `start` for the length up to `end`.
pub fn create_body(subject: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Value {
    let minutes = (end - start).num_minutes().max(1);
    json!({
        "topic": subject,
        "type": 2,
        "start_time": start.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "duration": minutes,
        "timezone": "UTC",
    })
}

pub fn parse_meeting(status: u16, body: &str) -> Option<Meeting> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    Some(Meeting {
        provider: "zoom".into(),
        id: v.get("id")?.to_string().trim_matches('"').to_owned(),
        join_url: v.get("join_url")?.as_str()?.to_owned(),
    })
}

pub fn participants_url(id: &str) -> String {
    format!("https://api.zoom.us/v2/report/meetings/{id}/participants?page_size=300")
}

pub fn recordings_url(id: &str) -> String {
    format!("https://api.zoom.us/v2/meetings/{id}/recordings")
}

pub fn parse_attendance(body: &str) -> Vec<Attendee> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("participants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|p| Attendee {
            name: p.get("name").and_then(Value::as_str).map(str::to_owned),
            email: p
                .get("user_email")
                .and_then(Value::as_str)
                .filter(|e| !e.is_empty())
                .map(str::to_owned),
            seconds: p.get("duration").and_then(Value::as_i64).unwrap_or(0),
        })
        .collect()
}

pub fn parse_recordings(body: &str) -> Vec<Recording> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("recording_files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some(Recording {
                url: r.get("download_url")?.as_str()?.to_owned(),
                kind: r
                    .get("file_type")
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase),
            })
        })
        .collect()
}

/// The app's access token (account credentials grant).
pub async fn app_token(state: &EngineState) -> Result<String, AppError> {
    let (config, secret) = video_app(state, "zoom").await?.ok_or(AppError::NotFound)?;
    let account = config
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("zoom: account_id is not configured".into()))?;
    let client_id = config
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("zoom: client_id is not configured".into()))?;
    let secret = secret.ok_or(AppError::NotFound)?;
    let (status, body) = answer(
        client()
            .post(TOKEN_URL)
            .basic_auth(client_id, Some(secret))
            .form(&[
                ("grant_type", "account_credentials"),
                ("account_id", account),
            ]),
    )
    .await?;
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    v.get("access_token")
        .and_then(Value::as_str)
        .filter(|_| (200..300).contains(&status))
        .map(str::to_owned)
        .ok_or_else(|| AppError::Validation(format!("zoom refused the app's sign-in ({status})")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_adapters_zoom_reads_recorded_answers() {
        let created = r#"{"id": 85746065432, "join_url": "https://us06web.zoom.us/j/85746065432?pwd=x", "topic": "Demo"}"#;
        assert_eq!(
            parse_meeting(201, created),
            Some(Meeting {
                provider: "zoom".into(),
                id: "85746065432".into(),
                join_url: "https://us06web.zoom.us/j/85746065432?pwd=x".into(),
            })
        );
        let participants =
            r#"{"participants": [{"name": "Lina", "user_email": "lina@x.com", "duration": 2400}]}"#;
        assert_eq!(parse_attendance(participants)[0].seconds, 2400);
        let recordings = r#"{"recording_files": [{"file_type": "MP4", "download_url": "https://zoom.us/rec/download/a"}]}"#;
        assert_eq!(parse_recordings(recordings)[0].kind.as_deref(), Some("mp4"));
        let body = create_body(
            "Demo",
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(5400, 0).unwrap(),
        );
        assert_eq!(
            (body["duration"].as_i64(), body["start_time"].as_str()),
            (Some(90), Some("1970-01-01T00:00:00Z"))
        );
    }
}

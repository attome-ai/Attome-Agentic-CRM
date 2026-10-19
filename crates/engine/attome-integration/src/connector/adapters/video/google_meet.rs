//! J7-T1: Google Meet, created as a Calendar event with a Meet conference
//! (`conferenceDataVersion=1`), as the signed-in person. Attendance and
//! recordings come from the Meet REST API's conference records, named by
//! the meeting code.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Attendee, Meeting, Recording};

pub const CREATE_URL: &str =
    "https://www.googleapis.com/calendar/v3/calendars/primary/events?conferenceDataVersion=1";

pub fn create_body(
    subject: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    request_id: Uuid,
) -> Value {
    json!({
        "summary": subject,
        "start": {"dateTime": start.to_rfc3339()},
        "end": {"dateTime": end.to_rfc3339()},
        "conferenceData": {"createRequest": {
            "requestId": request_id.to_string(),
            "conferenceSolutionKey": {"type": "hangoutsMeet"}
        }}
    })
}

/// The meeting: the conference id (the meeting code) and its link.
pub fn parse_meeting(status: u16, body: &str) -> Option<Meeting> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    let join_url = v
        .get("hangoutLink")
        .and_then(Value::as_str)
        .or_else(|| {
            v.pointer("/conferenceData/entryPoints")?
                .as_array()?
                .iter()
                .find(|e| e.get("entryPointType").and_then(Value::as_str) == Some("video"))?
                .get("uri")?
                .as_str()
        })?
        .to_owned();
    let id = v
        .pointer("/conferenceData/conferenceId")
        .and_then(Value::as_str)
        .or_else(|| v.get("id").and_then(Value::as_str))?
        .to_owned();
    Some(Meeting {
        provider: "meet".into(),
        id,
        join_url,
    })
}

/// The conference record's participants for a meeting code.
pub fn participants_url(code: &str) -> String {
    format!(
        "https://meet.googleapis.com/v2/conferenceRecords/-/participants?filter=space.meeting_code%3D%22{code}%22"
    )
}

pub fn recordings_url(code: &str) -> String {
    format!(
        "https://meet.googleapis.com/v2/conferenceRecords/-/recordings?filter=space.meeting_code%3D%22{code}%22"
    )
}

fn seconds_between(start: Option<&str>, end: Option<&str>) -> i64 {
    match (start, end) {
        (Some(s), Some(e)) => match (
            DateTime::parse_from_rfc3339(s),
            DateTime::parse_from_rfc3339(e),
        ) {
            (Ok(s), Ok(e)) => (e - s).num_seconds().max(0),
            _ => 0,
        },
        _ => 0,
    }
}

pub fn parse_attendance(body: &str) -> Vec<Attendee> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("participants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|p| Attendee {
            name: p
                .pointer("/signedinUser/displayName")
                .or_else(|| p.pointer("/anonymousUser/displayName"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            email: None,
            seconds: seconds_between(
                p.get("earliestStartTime").and_then(Value::as_str),
                p.get("latestEndTime").and_then(Value::as_str),
            ),
        })
        .collect()
}

pub fn parse_recordings(body: &str) -> Vec<Recording> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("recordings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some(Recording {
                url: r
                    .pointer("/driveDestination/exportUri")?
                    .as_str()?
                    .to_owned(),
                kind: Some("video".into()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_adapters_meet_reads_recorded_answers() {
        let created = r#"{"id": "evt1", "hangoutLink": "https://meet.google.com/abc-defg-hij",
            "conferenceData": {"conferenceId": "abc-defg-hij",
              "entryPoints": [{"entryPointType": "video", "uri": "https://meet.google.com/abc-defg-hij"}]}}"#;
        assert_eq!(
            parse_meeting(200, created),
            Some(Meeting {
                provider: "meet".into(),
                id: "abc-defg-hij".into(),
                join_url: "https://meet.google.com/abc-defg-hij".into(),
            })
        );
        assert_eq!(parse_meeting(401, "{}"), None);
        let participants = r#"{"participants": [{"signedinUser": {"displayName": "Omar"},
            "earliestStartTime": "2026-10-19T09:00:00Z", "latestEndTime": "2026-10-19T09:25:00Z"}]}"#;
        assert_eq!(parse_attendance(participants)[0].seconds, 1500);
        let recordings = r#"{"recordings": [{"driveDestination": {"exportUri": "https://drive.google.com/file/d/1"}}]}"#;
        assert_eq!(
            parse_recordings(recordings)[0].url,
            "https://drive.google.com/file/d/1"
        );
        let body = create_body(
            "Kickoff",
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(60, 0).unwrap(),
            Uuid::nil(),
        );
        assert_eq!(
            body["conferenceData"]["createRequest"]["conferenceSolutionKey"]["type"],
            "hangoutsMeet"
        );
    }
}

//! J7-T1: Teams meetings through Microsoft Graph `onlineMeetings`, as the
//! signed-in person.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{Attendee, Meeting, Recording};

pub const CREATE_URL: &str = "https://graph.microsoft.com/v1.0/me/onlineMeetings";

pub fn create_body(subject: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Value {
    json!({
        "subject": subject,
        "startDateTime": start.to_rfc3339(),
        "endDateTime": end.to_rfc3339(),
    })
}

pub fn parse_meeting(status: u16, body: &str) -> Option<Meeting> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    Some(Meeting {
        provider: "teams".into(),
        id: v.get("id")?.as_str()?.to_owned(),
        join_url: v.get("joinWebUrl")?.as_str()?.to_owned(),
    })
}

pub fn attendance_url(id: &str) -> String {
    format!("{CREATE_URL}/{id}/attendanceReports?$expand=attendanceRecords")
}

pub fn recordings_url(id: &str) -> String {
    format!("{CREATE_URL}/{id}/recordings")
}

pub fn parse_attendance(body: &str) -> Vec<Attendee> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|report| {
            report
                .get("attendanceRecords")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .map(|r| Attendee {
            name: r
                .pointer("/identity/displayName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            email: r
                .get("emailAddress")
                .and_then(Value::as_str)
                .map(str::to_owned),
            seconds: r
                .get("totalAttendanceInSeconds")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        })
        .collect()
}

pub fn parse_recordings(body: &str) -> Vec<Recording> {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    v.get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some(Recording {
                url: r.get("recordingContentUrl")?.as_str()?.to_owned(),
                kind: Some("video".into()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_adapters_teams_reads_recorded_answers() {
        let created = r#"{"id": "MSo1N2Y5", "joinWebUrl": "https://teams.microsoft.com/l/meetup-join/19%3ameeting", "subject": "Renewal"}"#;
        assert_eq!(
            parse_meeting(201, created),
            Some(Meeting {
                provider: "teams".into(),
                id: "MSo1N2Y5".into(),
                join_url: "https://teams.microsoft.com/l/meetup-join/19%3ameeting".into(),
            })
        );
        assert_eq!(
            parse_meeting(403, r#"{"error": {"code": "Forbidden"}}"#),
            None
        );
        let reports = r#"{"value": [{"id": "r1", "attendanceRecords": [
            {"emailAddress": "sara@contoso.com", "totalAttendanceInSeconds": 1800,
             "identity": {"displayName": "Sara"}}]}]}"#;
        assert_eq!(
            parse_attendance(reports),
            vec![Attendee {
                name: Some("Sara".into()),
                email: Some("sara@contoso.com".into()),
                seconds: 1800
            }]
        );
        let recordings = r#"{"value": [{"id": "x", "recordingContentUrl": "https://graph.microsoft.com/rec/x/content"}]}"#;
        assert_eq!(
            parse_recordings(recordings)[0].url,
            "https://graph.microsoft.com/rec/x/content"
        );
        let body = create_body(
            "Renewal",
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(3600, 0).unwrap(),
        );
        assert_eq!(body["startDateTime"], "1970-01-01T00:00:00+00:00");
    }
}

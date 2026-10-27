//! A24-T1: reading another CRM so its model and records can move into
//! Attome. A [`SourceConnector`] describes the source's model (entities,
//! fields, each field's Attome type), reads one entity's records changed
//! since a time a page at a time, and lists a record's files. A page ends
//! with a cursor the caller keeps, so a read stopped half-way resumes where
//! it was. Every call goes through [`send_with_backoff`], which waits out a
//! `429`/`503` (its `Retry-After`, else a doubling wait) and keeps what the
//! source said about its remaining API allowance in [`RateLimit`].
//!
//! The connectors are [`super::salesforce`] (REST describe and Bulk API 2.0
//! queries) and [`super::dynamics`] (Web API metadata and OData pages).
//! Credentials are [`Secret`]s; nothing here writes to Attome.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

use crate::connector::sdk::{Request, Response, Transport};

/// The most attempts one call makes while the source answers `429`/`503`.
pub const MAX_ATTEMPTS: u32 = 5;
/// The first wait when the source gives no `Retry-After`, doubled each time.
pub const BASE_BACKOFF_SECS: u64 = 2;
/// The longest single wait.
pub const MAX_BACKOFF_SECS: u64 = 120;
/// The most entities one model description covers.
pub const MAX_ENTITIES: usize = 200;

/// A boxed future of a source call.
pub type SourceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// The source's model.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SourceModel {
    pub entities: Vec<SourceEntity>,
}

/// One entity of the source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SourceEntity {
    /// The source's API name (`Account`, `account`).
    pub name: String,
    pub label: String,
    /// Whether the source marks it as its own customisation.
    pub custom: bool,
    pub fields: Vec<SourceField>,
}

/// One field of a source entity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SourceField {
    pub name: String,
    pub label: String,
    /// The source's own type name.
    pub source_type: String,
    /// The Attome field type it becomes (`text`, `number`, `currency`,
    /// `date`, `date_time`, `time`, `bool`, `choice`, `lookup`, `file`,
    /// `image`, `rich_text`).
    #[serde(deserialize_with = "attome_type_of")]
    pub attome_type: String,
    pub required: bool,
    /// A lookup's target entity, by its source name.
    pub lookup_target: Option<String>,
    /// A choice field's values.
    pub choices: Vec<String>,
    /// A choice field that holds several values.
    pub multi: bool,
}

/// The Attome field types a source field can become.
pub const ATTOME_TYPES: [&str; 12] = [
    "text",
    "number",
    "currency",
    "date",
    "date_time",
    "time",
    "bool",
    "choice",
    "lookup",
    "file",
    "image",
    "rich_text",
];

/// A source field's Attome type read back (a model posted to the mapping
/// draft): one of [`ATTOME_TYPES`].
fn attome_type_of<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let name = String::deserialize(d)?;
    if ATTOME_TYPES.contains(&name.as_str()) {
        Ok(name)
    } else {
        Err(serde::de::Error::custom(format!(
            "unknown field type {name:?}"
        )))
    }
}

/// One record as the source holds it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourceRecord {
    /// The source's record id.
    pub id: String,
    /// When the source last changed it, as the source wrote it.
    pub modified_at: Option<String>,
    pub fields: Map<String, Value>,
}

/// One page of records and where the next one starts.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RecordPage {
    pub records: Vec<SourceRecord>,
    /// Pass back to read the next page; `None` after the last one.
    pub next: Option<String>,
}

/// One file attached to a record.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourceFile {
    pub id: String,
    pub name: String,
    pub content_type: Option<String>,
    pub size: Option<i64>,
    /// Where its bytes are read, with the same credentials.
    pub url: String,
}

/// What the source said about its API allowance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RateLimit {
    /// Calls left in the source's current window, when it says.
    pub remaining: Option<u64>,
    /// The window's allowance, when it says.
    pub limit: Option<u64>,
    /// Times a call was answered `429`/`503` and waited.
    pub throttled: u32,
}

impl RateLimit {
    /// Keeps what an answer says: Salesforce's `Sforce-Limit-Info:
    /// api-usage=used/limit`, and Dynamics' remaining-requests header.
    pub fn observe(&mut self, answer: &Response) {
        if let Some(info) = header(answer, "sforce-limit-info")
            && let Some(usage) = info
                .split(';')
                .find_map(|part| part.trim().strip_prefix("api-usage="))
            && let Some((used, limit)) = usage.split_once('/')
            && let (Ok(used), Ok(limit)) = (used.trim().parse::<u64>(), limit.trim().parse::<u64>())
        {
            self.limit = Some(limit);
            self.remaining = Some(limit.saturating_sub(used));
        }
        if let Some(left) = header(answer, "x-ms-ratelimit-burst-remaining-xrm-requests")
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            self.remaining = Some(left);
        }
    }
}

/// A source of records to migrate.
pub trait SourceConnector: Send {
    /// The source's entities and their fields.
    fn describe_model<'a>(&'a mut self) -> SourceFuture<'a, SourceModel>;

    /// One page of `entity`'s records changed after `since` (all records
    /// when `None`), oldest change first; `cursor` is the previous page's
    /// [`RecordPage::next`].
    fn read_records<'a>(
        &'a mut self,
        entity: &'a str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&'a str>,
    ) -> SourceFuture<'a, RecordPage>;

    /// The files attached to one record.
    fn read_files<'a>(
        &'a mut self,
        entity: &'a str,
        record_id: &'a str,
    ) -> SourceFuture<'a, Vec<SourceFile>>;

    /// What the source last said about its API allowance.
    fn rate_limit(&self) -> RateLimit;
}

/// An answer's header, by name in any case.
pub fn header<'a>(answer: &'a Response, name: &str) -> Option<&'a str> {
    answer
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// How long to wait before attempt `attempt + 1`: the answer's
/// `Retry-After` seconds, else a doubling wait; capped. Pure.
pub fn backoff_secs(answer: &Response, attempt: u32) -> u64 {
    header(answer, "retry-after")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or_else(|| BASE_BACKOFF_SECS.saturating_mul(1 << attempt.min(16)))
        .min(MAX_BACKOFF_SECS)
}

/// Sends `request`, waiting out `429`/`503` answers up to [`MAX_ATTEMPTS`],
/// and notes the source's allowance on `limit`. Any other answer is
/// returned as it is.
pub async fn send_with_backoff(
    transport: &dyn Transport,
    request: Request,
    limit: &mut RateLimit,
) -> Result<Response, AppError> {
    for attempt in 0..MAX_ATTEMPTS {
        let answer = transport.send(request.clone()).await?;
        limit.observe(&answer);
        if answer.status != 429 && answer.status != 503 {
            return Ok(answer);
        }
        limit.throttled += 1;
        if attempt + 1 < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(backoff_secs(&answer, attempt))).await;
        }
    }
    Err(AppError::Validation(
        "the source kept refusing calls over its API limit; try again later".into(),
    ))
}

/// Splits CSV text (RFC 4180: commas, `"` quoting, doubled quotes, line
/// breaks inside quotes) into rows. Pure.
pub fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}

/// Whether `name` is a plain API name (letters, digits, `_`), safe to put
/// in a query or a path.
pub fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Recorded answers, matched by the start of a request's URL path.

    use std::sync::Mutex;

    use super::*;

    pub struct Recorded {
        /// (method, URL prefix, answer); an entry matches once, in order.
        answers: Mutex<Vec<(String, String, Response)>>,
        pub seen: Mutex<Vec<Request>>,
    }

    impl Recorded {
        pub fn new(answers: Vec<(&str, &str, u16, &str, Vec<(&str, &str)>)>) -> Self {
            Recorded {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .map(|(method, prefix, status, body, headers)| {
                            (
                                method.to_owned(),
                                prefix.to_owned(),
                                Response {
                                    status,
                                    headers: headers
                                        .into_iter()
                                        .map(|(n, v)| (n.to_owned(), v.to_owned()))
                                        .collect(),
                                    body: body.to_owned(),
                                },
                            )
                        })
                        .collect(),
                ),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Recorded {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send + 'a>> {
            let mut answers = self.answers.lock().unwrap();
            let found = answers
                .iter()
                .position(|(m, p, _)| *m == request.method && request.url.starts_with(p.as_str()));
            let answer = found.map(|i| answers.remove(i).2);
            drop(answers);
            let url = request.url.clone();
            self.seen.lock().unwrap().push(request);
            Box::pin(async move {
                answer.ok_or_else(|| AppError::internal(format!("no recorded answer for {url}")))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::Recorded;
    use super::*;

    #[test]
    fn sources_csv_rows_handle_quotes_and_line_breaks() {
        let rows = csv_rows("\"Id\",\"Name\"\n\"1\",\"Acme, \"\"Ltd\"\"\"\n\"2\",\"two\nlines\"\n");
        assert_eq!(
            rows,
            vec![
                vec!["Id", "Name"],
                vec!["1", "Acme, \"Ltd\""],
                vec!["2", "two\nlines"],
            ]
        );
        assert!(plain_name("Account__c"));
        assert!(!plain_name("Account; DROP"));
    }

    #[tokio::test]
    async fn sources_back_off_on_429_and_keep_the_allowance() {
        let source = Recorded::new(vec![
            (
                "GET",
                "https://x.example/a",
                429,
                "",
                vec![("Retry-After", "0")],
            ),
            (
                "GET",
                "https://x.example/a",
                200,
                "{}",
                vec![("Sforce-Limit-Info", "api-usage=25/15000")],
            ),
        ]);
        let mut limit = RateLimit::default();
        let answer = send_with_backoff(
            &source,
            Request {
                method: "GET".into(),
                url: "https://x.example/a".into(),
                headers: vec![],
                body: None,
            },
            &mut limit,
        )
        .await
        .unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(limit.throttled, 1);
        assert_eq!(limit.remaining, Some(14_975));
        assert_eq!(limit.limit, Some(15_000));
        let no_header = Response {
            status: 503,
            headers: vec![],
            body: String::new(),
        };
        assert_eq!(backoff_secs(&no_header, 0), 2);
        assert_eq!(backoff_secs(&no_header, 3), 16);
        assert_eq!(backoff_secs(&no_header, 10), MAX_BACKOFF_SECS);
    }
}

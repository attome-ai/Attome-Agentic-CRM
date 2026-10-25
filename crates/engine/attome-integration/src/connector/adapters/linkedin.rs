//! D30-T1: LinkedIn Lead Gen Forms, synced into leads.
//!
//! Over LinkedIn's versioned Marketing API (`/rest`, a `LinkedIn-Version`
//! header, an OAuth token with `r_marketing_leadgen_automation`):
//!
//! - [`LinkedInClient::form`] reads a form's questions, each with the
//!   standard field it asks for (`FIRST_NAME`, `EMAIL` …) when it is one;
//! - [`LinkedInClient::responses`] pages through an ad account's sponsored
//!   form responses submitted since a time (newest polling cursor kept by
//!   the caller), 100 a page;
//! - [`lead_patch`] maps one response onto `lead` fields (crm changesets 0001
//!   and 0003): standard questions by [`STANDARD_FIELDS`], custom questions
//!   by the connection's own `question id -> field` map, the name from the
//!   first and last name, and `source` set to `linkedin_lead_gen`. The
//!   response id is returned beside the patch for the caller to key the
//!   upsert on, so a response polled twice is one lead.
//!
//! An answer to a question with no mapping is kept in the patch's
//! `unmapped` list, never dropped silently. Checked against recorded
//! answers only: no LinkedIn app is configured here.

use std::collections::BTreeMap;

use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::connector::sdk::{Request, Secret, Transport};

/// The REST root.
pub const DEFAULT_BASE_URL: &str = "https://api.linkedin.com/rest";
/// The API version sent with every request (`YYYYMM`).
pub const API_VERSION: &str = "202410";
/// Responses per page.
pub const PAGE_SIZE: u32 = 100;
/// The most pages one poll reads.
pub const MAX_PAGES: u32 = 50;
/// The `lead.source` a synced lead gets.
pub const SOURCE: &str = "linkedin_lead_gen";

/// LinkedIn's standard question fields and the lead field each fills.
pub const STANDARD_FIELDS: &[(&str, &str)] = &[
    ("EMAIL", "email"),
    ("PHONE_NUMBER", "phone"),
    ("COMPANY_NAME", "company_name"),
    ("CITY", "city"),
    ("COUNTRY", "country_code"),
    ("LINKEDIN_PROFILE_LINK", "linkedin_url"),
    ("JOB_FUNCTION", "department"),
];

/// One question of a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: String,
    /// The standard field it asks for, when it is one.
    pub predefined: Option<String>,
    pub name: Option<String>,
}

/// One submitted response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadResponse {
    pub id: String,
    pub form: String,
    pub submitted_at_ms: i64,
    /// `(question id, answer)`.
    pub answers: Vec<(String, String)>,
    /// Whether LinkedIn marked it a test lead.
    pub test: bool,
}

/// A response as lead fields.
#[derive(Debug, Clone, PartialEq)]
pub struct LeadPatch {
    pub response_id: String,
    pub fields: Map<String, Value>,
    /// `(question id or name, answer)` of answers no mapping placed.
    pub unmapped: Vec<(String, String)>,
}

/// A LinkedIn answer as JSON, or why it was refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Value, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let message = || {
        value
            .as_ref()
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("no reason given")
            .to_owned()
    };
    match status {
        401 | 403 => Err(AppError::Validation(format!(
            "LinkedIn refused the token: {}",
            message()
        ))),
        404 => Err(AppError::Validation(format!(
            "LinkedIn does not know that form or account: {}",
            message()
        ))),
        400 | 422 => Err(AppError::Validation(format!(
            "LinkedIn refused the request: {}",
            message()
        ))),
        429 => Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }),
        s if s >= 400 => Err(AppError::internal(format!("LinkedIn answered {s}"))),
        _ => value.ok_or_else(|| AppError::internal("LinkedIn answered no JSON")),
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The questions of a `leadForms` answer. Pure.
pub fn questions_of(form: &Value) -> Vec<Question> {
    form["content"]["questions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|q| {
            Some(Question {
                id: text(&q["questionId"])?,
                predefined: text(&q["predefinedField"]),
                name: text(&q["name"]).or_else(|| text(&q["question"]["localized"]["en_US"])),
            })
        })
        .collect()
}

/// The responses of one `leadFormResponses` page, and whether another
/// follows. Pure.
pub fn responses_of(page: &Value) -> (Vec<LeadResponse>, bool) {
    let elements = page["elements"].as_array().cloned().unwrap_or_default();
    let responses = elements
        .iter()
        .filter_map(|e| {
            let answers = e["formResponse"]["answers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|a| {
                    let id = text(&a["questionId"])?;
                    let detail = &a["answerDetails"];
                    let answer = text(&detail["textQuestionAnswer"]["answer"]).or_else(|| {
                        detail["multipleChoiceAnswer"]["options"]
                            .as_array()
                            .map(|o| o.iter().filter_map(text).collect::<Vec<_>>().join(", "))
                            .filter(|s| !s.is_empty())
                    })?;
                    Some((id, answer))
                })
                .collect();
            Some(LeadResponse {
                id: text(&e["id"])?,
                form: text(&e["versionedLeadGenFormUrn"]).or_else(|| text(&e["leadGenFormUrn"]))?,
                submitted_at_ms: e["submittedAt"].as_i64().unwrap_or(0),
                answers,
                test: e["testLead"].as_bool().unwrap_or(false),
            })
        })
        .collect();
    let paging = &page["paging"];
    let start = paging["start"].as_u64().unwrap_or(0);
    let count = paging["count"].as_u64().unwrap_or(elements.len() as u64);
    let more = paging["total"]
        .as_u64()
        .map_or(elements.len() as u64 == count && count > 0, |total| {
            start + count < total
        });
    (responses, more)
}

/// One response as `lead` fields. `custom` maps a custom question's id to a
/// lead field. Pure.
pub fn lead_patch(
    response: &LeadResponse,
    questions: &[Question],
    custom: &BTreeMap<String, String>,
) -> LeadPatch {
    let by_id: BTreeMap<&str, &Question> = questions.iter().map(|q| (q.id.as_str(), q)).collect();
    let mut fields = Map::new();
    let mut unmapped = Vec::new();
    let (mut first, mut last) = (None, None);
    for (id, answer) in &response.answers {
        let question = by_id.get(id.as_str());
        let predefined = question.and_then(|q| q.predefined.as_deref());
        match predefined {
            Some("FIRST_NAME") => first = Some(answer.clone()),
            Some("LAST_NAME") => last = Some(answer.clone()),
            Some(standard) => match STANDARD_FIELDS.iter().find(|(f, _)| *f == standard) {
                Some((_, "country_code")) if answer.len() == 2 => {
                    fields.insert("country_code".into(), json!(answer.to_ascii_uppercase()));
                }
                Some((_, "email")) => {
                    fields.insert("email".into(), json!(answer.to_ascii_lowercase()));
                }
                Some((_, field)) if *field != "country_code" => {
                    fields.insert((*field).into(), json!(answer));
                }
                _ => unmapped.push((standard.to_owned(), answer.clone())),
            },
            None => match custom.get(id) {
                Some(field) => {
                    fields.insert(field.clone(), json!(answer));
                }
                None => unmapped.push((
                    question
                        .and_then(|q| q.name.clone())
                        .unwrap_or_else(|| id.clone()),
                    answer.clone(),
                )),
            },
        }
    }
    let name = [first, last]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if !name.is_empty() {
        fields.insert("name".into(), json!(name));
    } else if let Some(email) = fields.get("email").cloned() {
        fields.insert("name".into(), email);
    }
    fields.insert("source".into(), json!(SOURCE));
    LeadPatch {
        response_id: response.id.clone(),
        fields,
        unmapped,
    }
}

/// A LinkedIn Marketing API connection.
pub struct LinkedInClient<'a> {
    pub base_url: String,
    pub access_token: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for LinkedInClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkedInClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// `urn:li:…` with its colons percent-encoded, as LinkedIn's REST.li
/// parameters take it; `None` for anything else. Pure.
pub fn encoded_urn(urn: &str, kind: &str) -> Option<String> {
    let id = urn.strip_prefix(&format!("urn:li:{kind}:"))?;
    (!id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| format!("urn%3Ali%3A{kind}%3A{id}"))
}

impl<'a> LinkedInClient<'a> {
    pub fn new(base_url: &str, access_token: Secret, transport: &'a dyn Transport) -> Self {
        LinkedInClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            access_token,
            transport,
        }
    }

    async fn get(&self, url: String) -> Result<Value, AppError> {
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url,
                headers: vec![
                    ("Accept".into(), "application/json".into()),
                    ("LinkedIn-Version".into(), API_VERSION.into()),
                    ("X-Restli-Protocol-Version".into(), "2.0.0".into()),
                    (
                        "Authorization".into(),
                        format!("Bearer {}", self.access_token.wire_value()),
                    ),
                ],
                body: None,
            })
            .await?;
        parse_answer(answer.status, &answer.body)
    }

    /// A form's questions; `form` is `urn:li:leadGenForm:<id>`.
    pub async fn form(&self, form: &str) -> Result<Vec<Question>, AppError> {
        let encoded = encoded_urn(form, "leadGenForm")
            .ok_or_else(|| AppError::Validation("not a lead form URN".into()))?;
        let value = self
            .get(format!("{}/leadForms/{encoded}", self.base_url))
            .await?;
        Ok(questions_of(&value))
    }

    /// Every sponsored response of `account` (`urn:li:sponsoredAccount:<id>`)
    /// submitted at or after `since_ms`, oldest first, at most
    /// [`MAX_PAGES`] pages.
    pub async fn responses(
        &self,
        account: &str,
        since_ms: i64,
    ) -> Result<Vec<LeadResponse>, AppError> {
        let encoded = encoded_urn(account, "sponsoredAccount")
            .ok_or_else(|| AppError::Validation("not a sponsored account URN".into()))?;
        let mut out = Vec::new();
        for page in 0..MAX_PAGES {
            let url = format!(
                "{}/leadFormResponses?q=owner&owner=(sponsoredAccount:{encoded})\
                 &leadType=(leadType:SPONSORED)&submittedAtTimeRange=(start:{since_ms})\
                 &count={PAGE_SIZE}&start={}",
                self.base_url,
                page * PAGE_SIZE
            );
            let (responses, more) = responses_of(&self.get(url).await?);
            out.extend(responses);
            if !more {
                break;
            }
        }
        out.sort_by_key(|r| r.submitted_at_ms);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    const FORM: &str = r#"{"id": 9, "content": {"questions": [
        {"questionId": 1, "predefinedField": "FIRST_NAME", "name": "firstName"},
        {"questionId": 2, "predefinedField": "LAST_NAME", "name": "lastName"},
        {"questionId": 3, "predefinedField": "EMAIL", "name": "email"},
        {"questionId": 4, "predefinedField": "COUNTRY", "name": "country"},
        {"questionId": 5, "predefinedField": "COMPANY_NAME", "name": "company"},
        {"questionId": 6, "name": "budget"},
        {"questionId": 7, "name": "notes"}]}}"#;

    const PAGE: &str = r#"{"paging": {"start": 0, "count": 100, "total": 1}, "elements": [{
        "id": "38b3a5f2-1c19-4d3a-a5b0-5f3f9e7a1c11",
        "versionedLeadGenFormUrn": "urn:li:versionedLeadGenForm:(urn:li:leadGenForm:9,1)",
        "submittedAt": 1729850000000, "testLead": false,
        "formResponse": {"answers": [
          {"questionId": 1, "answerDetails": {"textQuestionAnswer": {"answer": "Sara"}}},
          {"questionId": 2, "answerDetails": {"textQuestionAnswer": {"answer": "Ali"}}},
          {"questionId": 3, "answerDetails": {"textQuestionAnswer": {"answer": "Sara@Example.SA"}}},
          {"questionId": 4, "answerDetails": {"textQuestionAnswer": {"answer": "sa"}}},
          {"questionId": 5, "answerDetails": {"textQuestionAnswer": {"answer": "Example Trading"}}},
          {"questionId": 6, "answerDetails": {"multipleChoiceAnswer": {"options": ["50k-100k"]}}},
          {"questionId": 7, "answerDetails": {"textQuestionAnswer": {"answer": "Call after Eid"}}}]}}]}"#;

    struct Recorded {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<Request>>,
    }

    impl Transport for Recorded {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send + 'a>> {
            self.asked.lock().unwrap().push(request);
            let (status, body) = self.answers.lock().unwrap().remove(0);
            Box::pin(async move {
                Ok(Response {
                    status,
                    headers: Vec::new(),
                    body: body.to_owned(),
                })
            })
        }
    }

    #[test]
    fn linkedin_leadgen_maps_a_response_onto_lead_fields() {
        let questions = questions_of(&serde_json::from_str(FORM).unwrap());
        let (responses, more) = responses_of(&serde_json::from_str(PAGE).unwrap());
        assert!(!more);
        assert_eq!(responses.len(), 1);
        let custom = BTreeMap::from([("6".to_owned(), "need".to_owned())]);
        let patch = lead_patch(&responses[0], &questions, &custom);
        assert_eq!(patch.response_id, "38b3a5f2-1c19-4d3a-a5b0-5f3f9e7a1c11");
        assert_eq!(patch.fields["name"], "Sara Ali");
        assert_eq!(patch.fields["email"], "sara@example.sa");
        assert_eq!(patch.fields["country_code"], "SA");
        assert_eq!(patch.fields["company_name"], "Example Trading");
        assert_eq!(patch.fields["need"], "50k-100k");
        assert_eq!(patch.fields["source"], SOURCE);
        assert_eq!(
            patch.unmapped,
            vec![("notes".to_owned(), "Call after Eid".to_owned())]
        );
    }

    #[tokio::test]
    async fn linkedin_leadgen_polls_with_the_versioned_api() {
        let transport = Recorded {
            answers: Mutex::new(vec![(200, FORM), (200, PAGE)]),
            asked: Mutex::new(Vec::new()),
        };
        let client = LinkedInClient::new(DEFAULT_BASE_URL, Secret::new("tok"), &transport);
        let questions = client.form("urn:li:leadGenForm:9").await.unwrap();
        assert_eq!(questions.len(), 7);
        let responses = client
            .responses("urn:li:sponsoredAccount:5072", 1_729_800_000_000)
            .await
            .unwrap();
        assert_eq!(responses.len(), 1);
        {
            let asked = transport.asked.lock().unwrap();
            assert!(
                asked[0]
                    .url
                    .ends_with("/leadForms/urn%3Ali%3AleadGenForm%3A9")
            );
            assert!(
                asked[1]
                    .url
                    .contains("owner=(sponsoredAccount:urn%3Ali%3AsponsoredAccount%3A5072)")
            );
            assert!(
                asked[1]
                    .url
                    .contains("submittedAtTimeRange=(start:1729800000000)")
            );
            assert!(
                asked[1]
                    .headers
                    .contains(&("LinkedIn-Version".into(), API_VERSION.into()))
            );
        }
        assert!(client.form("leadGenForm:9").await.is_err());
    }

    #[test]
    fn linkedin_leadgen_refusals() {
        assert!(matches!(
            parse_answer(401, r#"{"message":"Invalid access token"}"#),
            Err(AppError::Validation(m)) if m.contains("Invalid access token")
        ));
        assert!(matches!(
            parse_answer(429, "{}"),
            Err(AppError::TooManyRequests { .. })
        ));
        assert_eq!(
            encoded_urn("urn:li:sponsoredAccount:12/../x", "sponsoredAccount"),
            None
        );
    }
}

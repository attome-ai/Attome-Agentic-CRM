//! K4-T3: DocuSign, for customers who must sign there rather than with
//! Attome's own signing (`attome_document::esign`).
//!
//! [`DocuSignClient::send_envelope`] sends documents for signature through
//! the eSignature REST API v2.1 (`POST /v2.1/accounts/{account}/envelopes`
//! with `status: sent`), signers in routing order, each signing where the
//! document carries their anchor text (`/sn1/`, `/sn2/` …, see
//! [`anchor_of`]). [`DocuSignClient::envelope_status`] reads one envelope's
//! status back.
//!
//! Status changes come by DocuSign Connect: an inbound hook (M14) with the
//! `docusign` preset checks the message's HMAC signature, and
//! [`parse_connect`] reads the event, the envelope and each signer's status
//! out of the JSON (SIM) message. [`envelope_status_of`] and
//! [`signer_status_of`] map DocuSign's statuses onto the `esign_envelope`
//! and `esign_signer` vocabularies, so a DocuSign envelope reads like one
//! of Attome's.
//!
//! The adapter takes an OAuth access token; obtaining one (DocuSign's JWT
//! grant with an RSA key, or authorization code) is the connection's
//! credential flow, not this module's. Checked against recorded answers
//! only: no DocuSign account is configured here.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::connector::sdk::{Request, Secret, Transport};

/// The demo (developer) environment's REST root.
pub const DEMO_BASE_URL: &str = "https://demo.docusign.net/restapi";
/// The most documents one envelope may carry here.
pub const MAX_DOCUMENTS: usize = 20;
/// The most signers one envelope may carry here.
pub const MAX_SIGNERS: usize = 20;

/// One document to sign: its bytes as base64, a name and its extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub name: String,
    /// `pdf`, `docx` …
    pub extension: String,
    pub content_base64: String,
}

/// One signer, in routing order (1 signs first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub name: String,
    pub email: String,
    pub routing_order: u32,
}

/// An envelope to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeDraft {
    pub subject: String,
    pub message: Option<String>,
    pub documents: Vec<Document>,
    pub signers: Vec<Signer>,
}

/// A sent envelope as DocuSign answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSent {
    pub envelope_id: String,
    pub status: String,
    pub status_at: Option<String>,
}

/// The anchor text a signer's signature field is placed on: `/sn1/` for the
/// first signer. Pure.
pub fn anchor_of(index: usize) -> String {
    format!("/sn{}/", index + 1)
}

fn email_ok(email: &str) -> bool {
    let email = email.trim();
    email.len() <= 254
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

/// The `envelopeDefinition` for `draft`, or why it cannot be sent. Pure.
pub fn envelope_definition(draft: &EnvelopeDraft) -> Result<Value, AppError> {
    let subject = draft.subject.trim();
    if subject.is_empty() || subject.chars().count() > 100 {
        return Err(AppError::Validation(
            "the email subject is 1 to 100 characters".into(),
        ));
    }
    if draft.documents.is_empty() || draft.documents.len() > MAX_DOCUMENTS {
        return Err(AppError::Validation(format!(
            "an envelope carries 1 to {MAX_DOCUMENTS} documents"
        )));
    }
    if draft.signers.is_empty() || draft.signers.len() > MAX_SIGNERS {
        return Err(AppError::Validation(format!(
            "an envelope has 1 to {MAX_SIGNERS} signers"
        )));
    }
    if let Some(bad) = draft.signers.iter().find(|s| !email_ok(&s.email)) {
        return Err(AppError::Validation(format!(
            "{:?} is not an email address",
            bad.email
        )));
    }
    let documents: Vec<Value> = draft
        .documents
        .iter()
        .enumerate()
        .map(|(i, d)| {
            json!({
                "documentId": (i + 1).to_string(),
                "name": d.name,
                "fileExtension": d.extension.trim_start_matches('.'),
                "documentBase64": d.content_base64,
            })
        })
        .collect();
    let signers: Vec<Value> = draft
        .signers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            json!({
                "recipientId": (i + 1).to_string(),
                "name": s.name.trim(),
                "email": s.email.trim(),
                "routingOrder": s.routing_order.max(1).to_string(),
                "tabs": { "signHereTabs": [{
                    "anchorString": anchor_of(i),
                    "anchorUnits": "pixels",
                    "anchorXOffset": "0",
                    "anchorYOffset": "0",
                }]},
            })
        })
        .collect();
    let mut definition = json!({
        "emailSubject": subject,
        "documents": documents,
        "recipients": { "signers": signers },
        "status": "sent",
    });
    if let Some(message) = draft.message.as_deref().filter(|m| !m.trim().is_empty()) {
        definition["emailBlurb"] = json!(message.trim());
    }
    Ok(definition)
}

/// A DocuSign answer as JSON (`None` for an unknown envelope), or why it was
/// refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Option<Value>, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let message = || {
        value
            .as_ref()
            .and_then(|v| v.get("message").or_else(|| v.get("errorCode")))
            .and_then(Value::as_str)
            .unwrap_or("no reason given")
            .to_owned()
    };
    match status {
        404 => Ok(None),
        401 | 403 => Err(AppError::Validation(format!(
            "DocuSign refused the access token: {}",
            message()
        ))),
        400 => Err(AppError::Validation(format!(
            "DocuSign refused the envelope: {}",
            message()
        ))),
        429 => Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }),
        s if s >= 400 => Err(AppError::internal(format!("DocuSign answered {s}"))),
        _ => value
            .map(Some)
            .ok_or_else(|| AppError::internal("DocuSign answered no JSON")),
    }
}

fn sent_of(value: &Value) -> Result<EnvelopeSent, AppError> {
    let envelope_id = value["envelopeId"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::internal("DocuSign answered no envelopeId"))?;
    Ok(EnvelopeSent {
        envelope_id: envelope_id.to_owned(),
        status: value["status"].as_str().unwrap_or("sent").to_owned(),
        status_at: value["statusDateTime"]
            .as_str()
            .or_else(|| value["statusChangedDateTime"].as_str())
            .map(str::to_owned),
    })
}

/// A DocuSign connection.
pub struct DocuSignClient<'a> {
    /// The account's REST root (`https://eu.docusign.net/restapi` …).
    pub base_url: String,
    pub account_id: String,
    pub access_token: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for DocuSignClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocuSignClient")
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

impl<'a> DocuSignClient<'a> {
    pub fn new(
        base_url: &str,
        account_id: &str,
        access_token: Secret,
        transport: &'a dyn Transport,
    ) -> Self {
        DocuSignClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            account_id: account_id.trim().to_owned(),
            access_token,
            transport,
        }
    }

    /// The account's envelopes URL; an account id is a GUID or a number.
    fn envelopes_url(&self) -> Result<String, AppError> {
        if self.account_id.is_empty()
            || !self
                .account_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(AppError::Validation("not a DocuSign account id".into()));
        }
        Ok(format!(
            "{}/v2.1/accounts/{}/envelopes",
            self.base_url, self.account_id
        ))
    }

    fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("Accept".into(), "application/json".into()),
            ("Content-Type".into(), "application/json".into()),
            (
                "Authorization".into(),
                format!("Bearer {}", self.access_token.wire_value()),
            ),
        ]
    }

    /// Sends `draft` for signature.
    pub async fn send_envelope(&self, draft: &EnvelopeDraft) -> Result<EnvelopeSent, AppError> {
        let body = envelope_definition(draft)?;
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url: self.envelopes_url()?,
                headers: self.headers(),
                body: Some(body.to_string()),
            })
            .await?;
        let value = parse_answer(answer.status, &answer.body)?
            .ok_or_else(|| AppError::Validation("DocuSign does not know this account".into()))?;
        sent_of(&value)
    }

    /// One envelope's status; `None` when DocuSign knows no such envelope.
    pub async fn envelope_status(
        &self,
        envelope_id: &str,
    ) -> Result<Option<EnvelopeSent>, AppError> {
        if envelope_id.is_empty()
            || !envelope_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(AppError::Validation("not a DocuSign envelope id".into()));
        }
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url: format!("{}/{envelope_id}", self.envelopes_url()?),
                headers: self.headers(),
                body: None,
            })
            .await?;
        match parse_answer(answer.status, &answer.body)? {
            Some(value) => sent_of(&value).map(Some),
            None => Ok(None),
        }
    }
}

/// `esign_envelope.status` for a DocuSign envelope status; `None` for one
/// that changes nothing (`created`, `delivered` …). Pure.
pub fn envelope_status_of(docusign: &str) -> Option<&'static str> {
    match docusign.to_ascii_lowercase().as_str() {
        "sent" => Some("sent"),
        "completed" => Some("completed"),
        "declined" => Some("declined"),
        "voided" | "deleted" => Some("voided"),
        _ => None,
    }
}

/// `esign_signer.status` for a DocuSign recipient status. Pure.
pub fn signer_status_of(docusign: &str) -> Option<&'static str> {
    match docusign.to_ascii_lowercase().as_str() {
        "created" => Some("waiting"),
        "sent" | "delivered" => Some("notified"),
        "signed" | "completed" => Some("signed"),
        "declined" => Some("declined"),
        _ => None,
    }
}

/// One signer's state in a Connect message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerEvent {
    pub email: String,
    pub status: String,
    pub signed_at: Option<String>,
    pub declined_reason: Option<String>,
}

/// A DocuSign Connect message (JSON SIM), read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEvent {
    /// `envelope-sent`, `envelope-completed`, `recipient-declined` …
    pub event: String,
    pub envelope_id: String,
    pub envelope_status: Option<String>,
    pub signers: Vec<SignerEvent>,
}

/// Reads a Connect message; an error for a body that is not one. Pure.
pub fn parse_connect(body: &str) -> Result<ConnectEvent, AppError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| AppError::Validation("a DocuSign Connect message is JSON".into()))?;
    let event = value["event"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("the Connect message names no event".into()))?;
    let data = &value["data"];
    let envelope_id = data["envelopeId"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("the Connect message names no envelope".into()))?;
    let summary = &data["envelopeSummary"];
    let text = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
    let signers = summary["recipients"]["signers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| {
            Some(SignerEvent {
                email: text(&s["email"])?,
                status: text(&s["status"])?,
                signed_at: text(&s["signedDateTime"]),
                declined_reason: text(&s["declinedReason"]),
            })
        })
        .collect();
    Ok(ConnectEvent {
        event: event.to_owned(),
        envelope_id: envelope_id.to_owned(),
        envelope_status: text(&summary["status"]),
        signers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct Recorded {
        status: u16,
        body: &'static str,
        asked: Mutex<Vec<Request>>,
    }

    impl Transport for Recorded {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send + 'a>> {
            self.asked.lock().unwrap().push(request);
            Box::pin(async move {
                Ok(Response {
                    status: self.status,
                    headers: Vec::new(),
                    body: self.body.to_owned(),
                })
            })
        }
    }

    fn recorded(status: u16, body: &'static str) -> Recorded {
        Recorded {
            status,
            body,
            asked: Mutex::new(Vec::new()),
        }
    }

    fn draft() -> EnvelopeDraft {
        EnvelopeDraft {
            subject: "Please sign the MSA".into(),
            message: Some("Two signatures needed.".into()),
            documents: vec![Document {
                name: "MSA".into(),
                extension: ".pdf".into(),
                content_base64: "JVBERi0=".into(),
            }],
            signers: vec![
                Signer {
                    name: "Sara Ali".into(),
                    email: "sara@example.sa".into(),
                    routing_order: 1,
                },
                Signer {
                    name: "Omar Saleh".into(),
                    email: "omar@example.sa".into(),
                    routing_order: 2,
                },
            ],
        }
    }

    #[tokio::test]
    async fn docusign_sends_an_envelope_in_routing_order() {
        let transport = recorded(
            201,
            r#"{"envelopeId":"4c7b-91","status":"sent","statusDateTime":"2026-10-25T09:00:00Z"}"#,
        );
        let client = DocuSignClient::new(
            "https://demo.docusign.net/restapi/",
            "acct-1",
            Secret::new("token-xyz"),
            &transport,
        );
        let sent = client.send_envelope(&draft()).await.unwrap();
        assert_eq!(sent.envelope_id, "4c7b-91");
        assert_eq!(sent.status_at.as_deref(), Some("2026-10-25T09:00:00Z"));
        let asked = transport.asked.lock().unwrap();
        assert_eq!(asked[0].method, "POST");
        assert_eq!(
            asked[0].url,
            "https://demo.docusign.net/restapi/v2.1/accounts/acct-1/envelopes"
        );
        assert!(
            asked[0]
                .headers
                .contains(&("Authorization".into(), "Bearer token-xyz".into()))
        );
        let body: Value = serde_json::from_str(asked[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["status"], "sent");
        assert_eq!(body["documents"][0]["fileExtension"], "pdf");
        assert_eq!(body["recipients"]["signers"][1]["routingOrder"], "2");
        assert_eq!(
            body["recipients"]["signers"][1]["tabs"]["signHereTabs"][0]["anchorString"],
            "/sn2/"
        );
        assert_eq!(body["emailBlurb"], "Two signatures needed.");
    }

    #[tokio::test]
    async fn docusign_refusals_and_unknown_envelopes() {
        let transport = recorded(401, r#"{"errorCode":"USER_AUTHENTICATION_FAILED"}"#);
        let client = DocuSignClient::new(DEMO_BASE_URL, "a", Secret::new("t"), &transport);
        assert!(matches!(
            client.send_envelope(&draft()).await,
            Err(AppError::Validation(m)) if m.contains("USER_AUTHENTICATION_FAILED")
        ));
        let missing = recorded(404, "{}");
        let client = DocuSignClient::new(DEMO_BASE_URL, "a", Secret::new("t"), &missing);
        assert_eq!(client.envelope_status("abc-1").await.unwrap(), None);
        assert!(client.envelope_status("../x").await.is_err());

        let mut bad = draft();
        bad.signers[0].email = "not-an-email".into();
        assert!(envelope_definition(&bad).is_err());
        bad = draft();
        bad.documents.clear();
        assert!(envelope_definition(&bad).is_err());
    }

    #[test]
    fn docusign_connect_message_maps_onto_esign_statuses() {
        let body = r#"{"event":"recipient-completed","apiVersion":"v2.1","generatedDateTime":"2026-10-25T10:00:00Z",
            "data":{"accountId":"acct-1","envelopeId":"4c7b-91","envelopeSummary":{"status":"sent",
            "recipients":{"signers":[
              {"email":"sara@example.sa","status":"completed","signedDateTime":"2026-10-25T09:59:00Z"},
              {"email":"omar@example.sa","status":"delivered"}]}}}}"#;
        let event = parse_connect(body).unwrap();
        assert_eq!(event.event, "recipient-completed");
        assert_eq!(event.envelope_id, "4c7b-91");
        assert_eq!(event.signers.len(), 2);
        assert_eq!(signer_status_of(&event.signers[0].status), Some("signed"));
        assert_eq!(signer_status_of(&event.signers[1].status), Some("notified"));
        assert_eq!(envelope_status_of("Completed"), Some("completed"));
        assert_eq!(envelope_status_of("delivered"), None);
        assert!(parse_connect(r#"{"event":"envelope-sent","data":{}}"#).is_err());
        assert!(parse_connect("not json").is_err());
    }
}

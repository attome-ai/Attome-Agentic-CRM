//! Z8-T1: Amazon SES through its v2 HTTPS API (`SendEmail` with raw
//! content): the message goes out exactly as built for SMTP, its MIME bytes
//! base64-encoded, and the request is signed with AWS Signature Version 4.
//! No AWS SDK: one signed `POST`, over the shared guarded client.

use attome_config::SesSettings;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::{
    EmailProvider, OutgoingEmail, ProviderMessageId, SES, classify_http_status, classify_transport,
    host_of, http_client,
};
use crate::error::SendError;

const SERVICE: &str = "ses";
const PATH: &str = "/v2/email/outbound-emails";

pub struct Ses<'a> {
    pub settings: &'a SesSettings,
}

impl std::fmt::Debug for Ses<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ses").finish_non_exhaustive()
    }
}

impl Ses<'_> {
    fn endpoint(&self) -> String {
        self.settings
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(|e| e.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://email.{}.amazonaws.com", self.settings.region))
    }
}

impl EmailProvider for Ses<'_> {
    fn name(&self) -> &str {
        SES
    }

    async fn send(&self, msg: &OutgoingEmail<'_>) -> Result<ProviderMessageId, SendError> {
        let raw = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            msg.mime.formatted(),
        );
        let body = serde_json::json!({
            "FromEmailAddress": msg.from.email.to_string(),
            "Destination": { "ToAddresses": [msg.to.email.to_string()] },
            "Content": { "Raw": { "Data": raw } },
        })
        .to_string();
        let endpoint = self.endpoint();
        let host = host_of(&endpoint)?.to_string();
        let signed = sign(self.settings, &host, PATH, &body, Utc::now());

        let mut request = http_client(&endpoint)?
            .post(format!("{endpoint}{PATH}"))
            .header("content-type", "application/json")
            .header("x-amz-date", &signed.amz_date)
            .header("authorization", &signed.authorization);
        if let Some(token) = &self.settings.session_token {
            request = request.header("x-amz-security-token", token.expose());
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| classify_transport(SES, &e))?;
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(classify_http_status(SES, status, &text));
        }
        let id = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("MessageId")?.as_str().map(str::to_owned));
        Ok(ProviderMessageId(id))
    }
}

/// The two headers a signed request carries.
#[derive(Debug)]
pub(crate) struct Signed {
    pub amz_date: String,
    pub authorization: String,
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    // HMAC takes a key of any length, so this never fails.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// SigV4's signing key for one day, region and service.
pub(crate) fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date);
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    hmac(&k_service, "aws4_request")
}

/// Signs a JSON `POST` of `body` to `path` on `host` at `now`.
pub(crate) fn sign(
    settings: &SesSettings,
    host: &str,
    path: &str,
    body: &str,
    now: DateTime<Utc>,
) -> Signed {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let token = settings.session_token.as_ref().map(|t| t.expose());
    let mut canonical_headers =
        format!("content-type:application/json\nhost:{host}\nx-amz-date:{amz_date}\n");
    let mut signed_headers = String::from("content-type;host;x-amz-date");
    if let Some(token) = token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }
    let canonical_request = format!(
        "POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{}",
        sha256_hex(body.as_bytes())
    );
    let scope = format!("{date}/{}/{SERVICE}/aws4_request", settings.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(
        settings.secret_access_key.expose(),
        &date,
        &settings.region,
        SERVICE,
    );
    let signature = hex::encode(hmac(&key, &string_to_sign));
    Signed {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            settings.access_key_id
        ),
        amz_date,
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use lettre::message::Mailbox;

    use super::*;
    use crate::message::EmailMessage;
    use crate::provider::mock::serve_once;

    fn settings(endpoint: Option<String>) -> SesSettings {
        SesSettings {
            region: "eu-west-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            endpoint,
        }
    }

    fn message() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".into(),
            subject: "Hello".into(),
            text_body: "body".into(),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
        }
    }

    /// AWS's own worked example of deriving a signing key.
    #[test]
    fn the_signing_key_matches_the_aws_example() {
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn a_signature_names_its_scope_and_headers() {
        let now = Utc.with_ymd_and_hms(2026, 10, 18, 9, 30, 0).unwrap();
        let signed = sign(
            &settings(None),
            "email.eu-west-1.amazonaws.com",
            PATH,
            "{}",
            now,
        );
        assert_eq!(signed.amz_date, "20261018T093000Z");
        assert!(signed.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261018/eu-west-1/ses/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, Signature="
        ));
        let again = sign(
            &settings(None),
            "email.eu-west-1.amazonaws.com",
            PATH,
            "{}",
            now,
        );
        assert_eq!(signed.authorization, again.authorization, "deterministic");
        let other = sign(
            &settings(None),
            "email.eu-west-1.amazonaws.com",
            PATH,
            "{ }",
            now,
        );
        assert_ne!(
            signed.authorization, other.authorization,
            "the body is signed"
        );
    }

    async fn send_to(url: String) -> Result<ProviderMessageId, SendError> {
        let settings = settings(Some(url));
        let msg = message();
        let from: Mailbox = "Attome <noreply@example.com>".parse().unwrap();
        let to: Mailbox = msg.to.parse().unwrap();
        let mime = lettre::Message::builder()
            .from(from.clone())
            .to(to.clone())
            .subject("Hello")
            .body("body".to_string())
            .unwrap();
        let outgoing = OutgoingEmail {
            message: &msg,
            mime: &mime,
            from: &from,
            to: &to,
            original_to: None,
        };
        Ses {
            settings: &settings,
        }
        .send(&outgoing)
        .await
    }

    #[tokio::test]
    async fn ses_accepts_a_signed_raw_message() {
        let (url, request) = serve_once(
            200,
            "content-type: application/json\r\n",
            r#"{"MessageId":"0102-abc"}"#,
        )
        .await;
        let id = send_to(url).await.unwrap();
        assert_eq!(id, ProviderMessageId(Some("0102-abc".into())));
        let request = request.await.unwrap();
        assert!(
            request.starts_with("POST /v2/email/outbound-emails "),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: aws4-hmac-sha256 credential=akidexample/"));
        assert!(lower.contains("x-amz-date: "));
        assert!(
            request.contains(r#""FromEmailAddress":"noreply@example.com""#),
            "{request}"
        );
        assert!(request.contains(r#""Raw":{"Data":""#), "{request}");
    }

    #[tokio::test]
    async fn ses_refusals_classify() {
        let (url, _) = serve_once(403, "", r#"{"message":"signature mismatch"}"#).await;
        assert!(matches!(send_to(url).await, Err(SendError::Config { .. })));
        let (url, _) = serve_once(429, "", r#"{"message":"Maximum sending rate exceeded"}"#).await;
        assert!(matches!(
            send_to(url).await,
            Err(SendError::Transient { .. })
        ));
        let (url, _) = serve_once(400, "", r#"{"message":"Email address is not verified"}"#).await;
        assert!(matches!(
            send_to(url).await,
            Err(SendError::Permanent {
                recipient_attributable: false,
                ..
            })
        ));
    }
}

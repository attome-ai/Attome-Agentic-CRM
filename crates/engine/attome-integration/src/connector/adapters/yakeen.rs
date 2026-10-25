//! AJ3-T1: Yakeen (Elm) identity checks: does this national ID or iqama
//! belong to a person born on this date?
//!
//! [`YakeenClient::verify`] asks Yakeen's person lookup with the ID and the
//! birth date (Hijri `YYYY-MM` for a citizen, Gregorian `YYYY-MM-DD` for a
//! resident, as Yakeen expects) and answers an [`Outcome`] only: `Matched`,
//! `NotMatched` or `NotFound`. Whatever personal data Yakeen returns is read
//! for nothing and dropped; the caller never sees it.
//!
//! A check cannot run without the person's [`Consent`] (the text version
//! they agreed to, when, and where), and [`record`] keeps the check in
//! `identity_verification` (migration 0246) with that consent, the ID's
//! kind and last four digits, and the outcome, never the full ID or the
//! register's data. The credentials (`app-id`, `app-key`) are [`Secret`]s;
//! a refused key or an answer that is not the expected shape is an error,
//! never a "not matched". Checked against recorded answers only: no Yakeen
//! account is configured here.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::connector::sdk::{Request, Secret, Transport};

/// The provider name stored with each check.
pub const PROVIDER: &str = "yakeen";

/// A placeholder root; each Elm subscription names its own.
pub const DEFAULT_BASE_URL: &str = "https://yakeen.api.elm.sa/api/v1";

/// Whose ID it is, from its first digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// A national ID (starts with 1).
    Citizen,
    /// An iqama (starts with 2).
    Resident,
}

impl IdKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IdKind::Citizen => "citizen",
            IdKind::Resident => "resident",
        }
    }
}

/// What the register said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Matched,
    NotMatched,
    NotFound,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Matched => "matched",
            Outcome::NotMatched => "not_matched",
            Outcome::NotFound => "not_found",
        }
    }
}

/// The person's agreement to the check, captured before it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// The version of the consent text shown.
    pub text_version: String,
    pub given_at: DateTime<Utc>,
    /// Where it was given (`portal`, `branch`, `call`, ...).
    pub source: String,
}

/// A checked ID: its kind and the digits Yakeen is asked about.
#[derive(Clone, PartialEq, Eq)]
pub struct NationalId {
    digits: String,
    kind: IdKind,
}

impl std::fmt::Debug for NationalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NationalId({}, ******{})",
            self.kind.as_str(),
            self.last4()
        )
    }
}

impl NationalId {
    /// Ten digits starting with 1 or 2 (Arabic-Indic digits accepted).
    pub fn parse(input: &str) -> Option<Self> {
        let digits: String = input
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| match c {
                '٠'..='٩' => char::from(b'0' + (c as u32 - '٠' as u32) as u8),
                other => other,
            })
            .collect();
        if digits.len() != 10 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let kind = match digits.as_bytes()[0] {
            b'1' => IdKind::Citizen,
            b'2' => IdKind::Resident,
            _ => return None,
        };
        Some(NationalId { digits, kind })
    }

    pub fn kind(&self) -> IdKind {
        self.kind
    }

    pub fn last4(&self) -> &str {
        &self.digits[6..]
    }
}

/// The birth date in the form Yakeen takes for `kind`: `YYYY-MM` (Hijri)
/// for a citizen, `YYYY-MM-DD` (Gregorian) for a resident.
pub fn birth_date(kind: IdKind, input: &str) -> Option<String> {
    fn num(s: &str, len: usize) -> Option<&str> {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
    }
    let parts: Vec<&str> = input.trim().split(['-', '/']).collect();
    match (kind, parts.as_slice()) {
        (IdKind::Citizen, &[y, m] | &[y, m, _]) => {
            let (y, m) = (num(y, 4)?, num(m, 2)?);
            let year: u32 = y.parse().ok()?;
            let month: u32 = m.parse().ok()?;
            ((1300..1500).contains(&year) && (1..=12).contains(&month)).then(|| format!("{y}-{m}"))
        }
        (IdKind::Resident, &[y, m, d]) => {
            let date = chrono::NaiveDate::from_ymd_opt(
                num(y, 4)?.parse().ok()?,
                num(m, 2)?.parse().ok()?,
                num(d, 2)?.parse().ok()?,
            )?;
            Some(date.format("%Y-%m-%d").to_string())
        }
        _ => None,
    }
}

/// A Yakeen connection.
pub struct YakeenClient<'a> {
    pub base_url: String,
    pub app_id: Secret,
    pub app_key: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for YakeenClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YakeenClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// One check's answer: the outcome and Yakeen's reference for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub outcome: Outcome,
    pub provider_reference: Option<String>,
}

impl<'a> YakeenClient<'a> {
    pub fn new(
        base_url: &str,
        app_id: Secret,
        app_key: Secret,
        transport: &'a dyn Transport,
    ) -> Self {
        YakeenClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            app_id,
            app_key,
            transport,
        }
    }

    /// Checks `id` against `birth` (see [`birth_date`]). `consent` must be
    /// given before the call; an empty text version or source refuses.
    pub async fn verify(
        &self,
        id: &NationalId,
        birth: &str,
        consent: &Consent,
    ) -> Result<Checked, AppError> {
        if consent.text_version.trim().is_empty() || consent.source.trim().is_empty() {
            return Err(AppError::Validation(
                "an identity check needs the person's consent first".into(),
            ));
        }
        let birth = birth_date(id.kind, birth).ok_or_else(|| {
            AppError::Validation(match id.kind {
                IdKind::Citizen => {
                    "a citizen's birth date is the Hijri year and month (YYYY-MM)".into()
                }
                IdKind::Resident => "a resident's birth date is YYYY-MM-DD".into(),
            })
        })?;
        let mut url = url::Url::parse(&format!(
            "{}/person/{}/information",
            self.base_url, id.digits
        ))
        .map_err(|e| AppError::Validation(format!("Yakeen URL: {e}")))?;
        url.query_pairs_mut().append_pair("dateOfBirth", &birth);
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url: url.into(),
                headers: vec![
                    ("Accept".into(), "application/json".into()),
                    ("app-id".into(), self.app_id.wire_value().to_owned()),
                    ("app-key".into(), self.app_key.wire_value().to_owned()),
                ],
                body: None,
            })
            .await?;
        parse_answer(answer.status, &answer.body)
    }
}

/// Error codes Yakeen uses for "the ID exists but the birth date differs".
const MISMATCH_CODES: &[&str] = &[
    "DOB_MISMATCH",
    "DATE_OF_BIRTH_MISMATCH",
    "INVALID_DOB",
    "E-11",
];
/// Error codes Yakeen uses for "no such ID".
const NOT_FOUND_CODES: &[&str] = &["NOT_FOUND", "PERSON_NOT_FOUND", "NIN_NOT_FOUND", "E-10"];

/// The outcome of a Yakeen answer, or why it is refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Checked, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let read = |names: &[&str]| {
        let v = value.as_ref()?;
        names.iter().find_map(|n| match v.get(*n) {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_owned()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        })
    };
    let code = read(&["code", "errorCode", "error"]).map(|c| c.to_ascii_uppercase());
    let reference = read(&["referenceNumber", "requestId", "transactionId"]);
    let coded = |codes: &[&str]| code.as_deref().is_some_and(|c| codes.contains(&c));
    match status {
        401 | 403 => Err(AppError::Validation(
            "Yakeen refused the credentials".into(),
        )),
        429 => Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }),
        404 => Ok(Checked {
            outcome: Outcome::NotFound,
            provider_reference: reference,
        }),
        400 | 422 if coded(MISMATCH_CODES) => Ok(Checked {
            outcome: Outcome::NotMatched,
            provider_reference: reference,
        }),
        400 | 422 if coded(NOT_FOUND_CODES) => Ok(Checked {
            outcome: Outcome::NotFound,
            provider_reference: reference,
        }),
        400 | 422 => Err(AppError::Validation(format!(
            "Yakeen refused the check: {}",
            read(&["message", "errorMessage"]).unwrap_or_else(|| "no reason given".into())
        ))),
        s if s >= 400 => Err(AppError::internal(format!("Yakeen answered {s}"))),
        _ => {
            // A person record came back: the ID and birth date belong
            // together. Its contents are not read.
            if !value.as_ref().is_some_and(Value::is_object) {
                return Err(AppError::internal("Yakeen answered no JSON"));
            }
            Ok(Checked {
                outcome: Outcome::Matched,
                provider_reference: reference,
            })
        }
    }
}

/// One check to keep.
#[derive(Debug, Clone)]
pub struct Verification<'a> {
    pub subject_entity: &'a str,
    pub subject_id: Uuid,
    pub id: &'a NationalId,
    pub checked: &'a Checked,
    pub consent: &'a Consent,
    pub requested_by: Option<Uuid>,
}

/// Keeps one check in the caller's transaction; returns its id.
pub async fn record(tx: &mut attome_db::Tx<'_>, v: &Verification<'_>) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        "INSERT INTO identity_verification \
           (subject_entity, subject_id, provider, id_kind, id_last4, outcome, \
            provider_reference, consent_text_version, consent_given_at, consent_source, \
            requested_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(v.subject_entity)
    .bind(v.subject_id)
    .bind(PROVIDER)
    .bind(v.id.kind.as_str())
    .bind(v.id.last4())
    .bind(v.checked.outcome.as_str())
    .bind(&v.checked.provider_reference)
    .bind(v.consent.text_version.trim())
    .bind(v.consent.given_at)
    .bind(v.consent.source.trim())
    .bind(v.requested_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
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

    impl Recorded {
        fn new(status: u16, body: &'static str) -> Self {
            Recorded {
                status,
                body,
                asked: Mutex::new(Vec::new()),
            }
        }
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

    const PERSON: &str = r#"{"referenceNumber": "YK-778812", "firstName": "محمد", "familyName": "العتيبي",
      "dateOfBirthH": "1410-03", "gender": "M", "idExpiryDate": "1450-01-01"}"#;
    const MISMATCH: &str = r#"{"code": "dob_mismatch", "message": "date of birth does not match", "requestId": "YK-1"}"#;
    const UNKNOWN: &str = r#"{"code": "NIN_NOT_FOUND", "message": "no such person"}"#;

    fn consent() -> Consent {
        Consent {
            text_version: "kyc-v2".into(),
            given_at: Utc::now(),
            source: "portal".into(),
        }
    }

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn client(t: &Recorded) -> YakeenClient<'_> {
        YakeenClient::new(
            DEFAULT_BASE_URL,
            Secret::new("app-1"),
            Secret::new("key-1"),
            t,
        )
    }

    #[test]
    fn yakeen_ids_and_birth_dates() {
        let citizen = NationalId::parse("١٠٢٣٤٥٦٧٨٩").unwrap();
        assert_eq!(citizen.kind(), IdKind::Citizen);
        assert_eq!(citizen.last4(), "6789");
        assert_eq!(format!("{citizen:?}"), "NationalId(citizen, ******6789)");
        assert_eq!(
            NationalId::parse("2123456789").unwrap().kind(),
            IdKind::Resident
        );
        assert!(NationalId::parse("3123456789").is_none());
        assert!(NationalId::parse("12345").is_none());

        assert_eq!(
            birth_date(IdKind::Citizen, "1410/03").as_deref(),
            Some("1410-03")
        );
        assert_eq!(
            birth_date(IdKind::Citizen, "1410-03-15").as_deref(),
            Some("1410-03")
        );
        assert_eq!(birth_date(IdKind::Citizen, "1990-03"), None);
        assert_eq!(
            birth_date(IdKind::Resident, "1990-03-15").as_deref(),
            Some("1990-03-15")
        );
        assert_eq!(birth_date(IdKind::Resident, "1990-02-30"), None);
        assert_eq!(birth_date(IdKind::Resident, "1990-03"), None);
    }

    #[test]
    fn yakeen_match_keeps_only_the_outcome() {
        let t = Recorded::new(200, PERSON);
        let id = NationalId::parse("1023456789").unwrap();
        let checked = run(client(&t).verify(&id, "1410-03", &consent())).unwrap();
        assert_eq!(
            checked,
            Checked {
                outcome: Outcome::Matched,
                provider_reference: Some("YK-778812".into())
            }
        );
        let asked = &t.asked.lock().unwrap()[0];
        assert!(
            asked.url.contains("/person/1023456789/information"),
            "{}",
            asked.url
        );
        assert!(asked.url.contains("dateOfBirth=1410-03"), "{}", asked.url);
        assert!(
            asked
                .headers
                .iter()
                .any(|(k, v)| k == "app-key" && v == "key-1")
        );
    }

    #[test]
    fn yakeen_mismatch_and_unknown() {
        let id = NationalId::parse("2123456789").unwrap();
        let t = Recorded::new(400, MISMATCH);
        let checked = run(client(&t).verify(&id, "1990-03-15", &consent())).unwrap();
        assert_eq!(checked.outcome, Outcome::NotMatched);
        assert_eq!(checked.provider_reference.as_deref(), Some("YK-1"));

        let t = Recorded::new(400, UNKNOWN);
        let checked = run(client(&t).verify(&id, "1990-03-15", &consent())).unwrap();
        assert_eq!(checked.outcome, Outcome::NotFound);

        let t = Recorded::new(404, "");
        let checked = run(client(&t).verify(&id, "1990-03-15", &consent())).unwrap();
        assert_eq!(checked.outcome, Outcome::NotFound);
    }

    #[test]
    fn yakeen_refusals_never_read_as_no_match() {
        let id = NationalId::parse("1023456789").unwrap();
        let t = Recorded::new(401, "");
        assert!(matches!(
            run(client(&t).verify(&id, "1410-03", &consent())),
            Err(AppError::Validation(_))
        ));
        let t = Recorded::new(400, r#"{"code": "BAD_REQUEST", "message": "malformed"}"#);
        let err = run(client(&t).verify(&id, "1410-03", &consent())).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("malformed")),
            "{err:?}"
        );
        let t = Recorded::new(200, "<html>");
        assert!(run(client(&t).verify(&id, "1410-03", &consent())).is_err());
        let t = Recorded::new(503, "");
        assert!(run(client(&t).verify(&id, "1410-03", &consent())).is_err());
    }

    #[test]
    fn yakeen_needs_consent_and_a_valid_birth_date_first() {
        let t = Recorded::new(200, PERSON);
        let id = NationalId::parse("1023456789").unwrap();
        let mut no_consent = consent();
        no_consent.text_version = " ".into();
        assert!(run(client(&t).verify(&id, "1410-03", &no_consent)).is_err());
        assert!(run(client(&t).verify(&id, "1990-03-15", &consent())).is_err());
        assert!(t.asked.lock().unwrap().is_empty(), "nothing reaches Yakeen");
    }
}

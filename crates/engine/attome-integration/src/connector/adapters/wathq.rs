//! AJ4-T1: Wathq commercial registration (CR) lookups, to fill an account
//! from the Ministry of Commerce's register.
//!
//! One lookup over Wathq's Commercial Registration API (v5, JSON, the key in
//! an `apiKey` header): [`WathqClient::full_info`] takes a ten-digit CR
//! number and answers the registered company ([`Registration`]): legal name
//! in Arabic and English, status, legal form, city, issue and expiry dates,
//! ISIC activities, contact details and, for a branch, its main CR.
//!
//! [`account_patch`] turns a registration into the CRM `account` fields
//! (crm changesets 0001 and 0003) to write through the generic update. A
//! branch's main CR is a proposal, never a link: the caller finds the
//! account holding that CR and passes it, and the patch sets
//! `proposed_parent_ref` (the org-chart review accepts or rejects it), not
//! `parent_account_ref`. The activity codes are returned for the caller to
//! resolve to `isic_code` records; the patch does not guess an id.
//!
//! A CR Wathq does not know is `None`; a refused key, a malformed number or
//! an answer that is not the expected shape is an error, never an empty
//! match. Field names are read with the aliases Wathq has used across API
//! versions. Checked against recorded answers only: no Wathq subscription
//! is configured here.

use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::connector::sdk::{Request, Secret, Transport};

/// Wathq's Commercial Registration API root.
pub const DEFAULT_BASE_URL: &str = "https://api.wathq.sa/v5/commercialregistration";

/// One ISIC activity a CR is registered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activity {
    pub code: String,
    pub name_ar: Option<String>,
    pub name_en: Option<String>,
}

/// A registered company as Wathq answers it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Registration {
    pub cr_number: String,
    /// The unified 700 number shared by a company's main CR and branches.
    pub entity_number: Option<String>,
    pub name_ar: Option<String>,
    pub name_en: Option<String>,
    /// Wathq's status in English when given (`Active`, `Suspended`, ...).
    pub status: Option<String>,
    pub legal_form: Option<String>,
    pub city: Option<String>,
    /// As Wathq gives it: Hijri `YYYY/MM/DD` or Gregorian `YYYY-MM-DD`.
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
    /// Whether this is the company's main CR; `None` when not stated.
    pub is_main: Option<bool>,
    /// For a branch, the main CR it belongs to.
    pub main_cr_number: Option<String>,
    pub activities: Vec<Activity>,
    pub phone: Option<String>,
    pub website: Option<String>,
    pub email: Option<String>,
    pub address: Option<String>,
}

impl Registration {
    /// Whether the register shows the CR as active.
    pub fn is_active(&self) -> bool {
        self.status.as_deref().is_some_and(|s| {
            let s = s.trim();
            s.eq_ignore_ascii_case("active") || s == "نشط" || s == "قائم"
        })
    }

    /// The main CR this branch should hang under, when it is a branch.
    pub fn proposed_parent_cr(&self) -> Option<&str> {
        let main = self.main_cr_number.as_deref()?;
        (self.is_main != Some(true) && main != self.cr_number).then_some(main)
    }
}

/// A CR number: ten digits (Arabic-Indic digits accepted), spaces dropped.
pub fn cr_number(input: &str) -> Option<String> {
    let digits: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c {
            '٠'..='٩' => char::from(b'0' + (c as u32 - '٠' as u32) as u8),
            '۰'..='۹' => char::from(b'0' + (c as u32 - '۰' as u32) as u8),
            other => other,
        })
        .collect();
    (digits.len() == 10 && digits.chars().all(|c| c.is_ascii_digit())).then_some(digits)
}

/// A Wathq connection.
pub struct WathqClient<'a> {
    pub base_url: String,
    pub api_key: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for WathqClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WathqClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl<'a> WathqClient<'a> {
    pub fn new(base_url: &str, api_key: Secret, transport: &'a dyn Transport) -> Self {
        WathqClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            transport,
        }
    }

    /// The registration behind `cr`; `None` when Wathq knows no such CR.
    pub async fn full_info(&self, cr: &str) -> Result<Option<Registration>, AppError> {
        let cr = cr_number(cr)
            .ok_or_else(|| AppError::Validation("a CR number is ten digits".into()))?;
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url: format!("{}/fullinfo/{cr}", self.base_url),
                headers: vec![
                    ("Accept".into(), "application/json".into()),
                    ("apiKey".into(), self.api_key.wire_value().to_owned()),
                ],
                body: None,
            })
            .await?;
        let Some(value) = parse_answer(answer.status, &answer.body)? else {
            return Ok(None);
        };
        registration(&value, &cr).map(Some)
    }
}

/// A Wathq answer as JSON (`None` for an unknown CR), or why it is refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Option<Value>, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let message = || {
        value
            .as_ref()
            .and_then(|v| v.get("message").or_else(|| v.get("error")))
            .and_then(Value::as_str)
            .unwrap_or("no reason given")
            .to_owned()
    };
    match status {
        404 => Ok(None),
        401 | 403 => Err(AppError::Validation(format!(
            "Wathq refused the API key: {}",
            message()
        ))),
        400 => Err(AppError::Validation(format!(
            "Wathq refused the lookup: {}",
            message()
        ))),
        429 => Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }),
        s if s >= 400 => Err(AppError::internal(format!("Wathq answered {s}"))),
        _ => value
            .map(Some)
            .ok_or_else(|| AppError::internal("Wathq answered no JSON")),
    }
}

fn text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The first of `names` present on `v` as text.
fn field(v: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| text(v.get(*n)))
}

/// A `{id, name, nameEn}` object (or a plain string): English, else Arabic.
fn named(v: Option<&Value>) -> Option<String> {
    let v = v?;
    if let Some(s) = text(Some(v)) {
        return Some(s);
    }
    field(v, &["nameEn", "name_en", "name"])
}

fn boolean(v: Option<&Value>) -> Option<bool> {
    match v? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// The registration in a full-info answer for `asked` (the CR looked up).
pub fn registration(answer: &Value, asked: &str) -> Result<Registration, AppError> {
    if !answer.is_object() {
        return Err(AppError::internal("Wathq answered no registration"));
    }
    let cr = field(answer, &["crNumber", "crNationalNumber", "cr_number"])
        .and_then(|c| cr_number(&c))
        .unwrap_or_else(|| asked.to_owned());
    let status = answer.get("status");
    let activities = answer
        .get("activities")
        .and_then(|a| a.get("isic").or(Some(a)))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    Some(Activity {
                        code: field(a, &["id", "code", "isicCode"])?,
                        name_ar: field(a, &["name", "nameAr"]),
                        name_en: field(a, &["nameEn", "name_en"]),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let general = answer
        .get("address")
        .and_then(|a| a.get("general").or(Some(a)))
        .filter(|a| a.is_object());
    let contact = |names: &[&str]| general.and_then(|g| field(g, names));
    let main_cr = field(
        answer,
        &[
            "mainCrNumber",
            "mainCRNumber",
            "parentCRNumber",
            "parentCrNumber",
        ],
    )
    .and_then(|c| cr_number(&c));
    Ok(Registration {
        entity_number: field(answer, &["crEntityNumber", "entityNumber", "unifiedNumber"]),
        name_ar: field(answer, &["crName", "name", "crNameAr"]),
        name_en: field(answer, &["crNameEn", "nameEn"])
            .or_else(|| answer.get("company").and_then(|c| field(c, &["nameEn"]))),
        status: status.and_then(|s| field(s, &["nameEn", "name"]).or_else(|| text(Some(s)))),
        legal_form: named(
            answer
                .get("businessType")
                .or_else(|| answer.get("entityType")),
        ),
        city: named(
            answer
                .get("location")
                .or_else(|| answer.get("headquarterCity")),
        ),
        issue_date: field(answer, &["issueDateGregorian", "issueDate"]),
        expiry_date: field(answer, &["expiryDateGregorian", "expiryDate"]),
        is_main: boolean(answer.get("isMain")),
        main_cr_number: main_cr,
        activities,
        phone: contact(&["telephone1", "phone", "mobile"]),
        website: contact(&["website"]),
        email: contact(&["email"]),
        address: contact(&["address"]),
        cr_number: cr,
    })
}

/// The Gregorian year of a date, when it is one (`2009-04-30`, `30/04/2009`).
/// Hijri dates (a year below 1600) give `None`.
fn gregorian_year(date: &str) -> Option<i64> {
    date.split(['-', '/'])
        .filter_map(|part| part.trim().parse::<i64>().ok())
        .find(|n| *n >= 1000)
        .filter(|y| (1600..=2200).contains(y))
}

/// The `account` fields a registration sets, ready for the generic update;
/// only what Wathq returned, so a field it left out keeps its value.
/// `proposed_parent` is the account found for [`Registration::proposed_parent_cr`].
pub fn account_patch(found: &Registration, proposed_parent: Option<Uuid>) -> Map<String, Value> {
    let mut patch = Map::new();
    patch.insert("cr_number".into(), json!(found.cr_number));
    let mut put = |name: &str, value: &Option<String>| {
        if let Some(v) = value {
            patch.insert(name.to_owned(), json!(v));
        }
    };
    put("legal_name_ar", &found.name_ar);
    put("legal_name_en", &found.name_en);
    put("phone", &found.phone);
    put("website", &found.website);
    put("hq_address", &found.address);
    if let Some(year) = found.issue_date.as_deref().and_then(gregorian_year) {
        patch.insert("founded_year".into(), json!(year));
    }
    if let Some(parent) = proposed_parent {
        patch.insert("proposed_parent_ref".into(), json!(parent));
    }
    patch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// A recorded Wathq answer, and the requests asked.
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

    const BRANCH: &str = r#"{"crName": "شركة المثال للتجارة - فرع جدة", "crNumber": "4030000001",
      "crEntityNumber": "7001234567", "issueDate": "1430/05/12", "expiryDate": "1447/05/11",
      "businessType": {"id": "201", "name": "شركة ذات مسؤولية محدودة", "nameEn": "Limited Liability Company"},
      "status": {"id": "active", "name": "نشط", "nameEn": "Active"},
      "location": {"id": "4030", "name": "جدة"},
      "isMain": false, "mainCrNumber": "1010000009",
      "activities": {"description": "البيع بالجملة", "isic": [
        {"id": "464101", "name": "البيع بالجملة للأقمشة", "nameEn": "Wholesale of fabrics"},
        {"id": "477111", "name": "البيع بالتجزئة للملابس"}]},
      "address": {"general": {"address": "طريق الملك عبدالعزيز، جدة", "telephone1": "0126000000",
        "website": "https://example.sa", "email": "info@example.sa"}}}"#;

    const MAIN: &str = r#"{"crName": "شركة المثال للتجارة", "crNumber": "1010000009", "isMain": true,
      "issueDateGregorian": "2009-04-30", "status": {"name": "نشط"}, "activities": {"isic": []}}"#;

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn wathq_cr_numbers_are_ten_digits() {
        assert_eq!(cr_number(" 4030 000 001 ").as_deref(), Some("4030000001"));
        assert_eq!(cr_number("٤٠٣٠٠٠٠٠٠١").as_deref(), Some("4030000001"));
        assert_eq!(cr_number("403000000"), None);
        assert_eq!(cr_number("40300000AB"), None);
    }

    #[test]
    fn wathq_full_info_reads_a_branch() {
        let t = Recorded::new(200, BRANCH);
        let client = WathqClient::new(DEFAULT_BASE_URL, Secret::new("k-123"), &t);
        let found = run(client.full_info("4030000001")).unwrap().unwrap();
        assert_eq!(found.cr_number, "4030000001");
        assert_eq!(found.entity_number.as_deref(), Some("7001234567"));
        assert_eq!(found.status.as_deref(), Some("Active"));
        assert!(found.is_active());
        assert_eq!(
            found.legal_form.as_deref(),
            Some("Limited Liability Company")
        );
        assert_eq!(found.city.as_deref(), Some("جدة"));
        assert_eq!(found.activities.len(), 2);
        assert_eq!(found.activities[0].code, "464101");
        assert_eq!(found.activities[1].name_en, None);
        assert_eq!(found.proposed_parent_cr(), Some("1010000009"));

        let asked = &t.asked.lock().unwrap()[0];
        assert!(asked.url.ends_with("/fullinfo/4030000001"), "{}", asked.url);
        assert!(
            asked
                .headers
                .iter()
                .any(|(k, v)| k == "apiKey" && v == "k-123")
        );

        let parent = Uuid::nil();
        let patch = account_patch(&found, Some(parent));
        assert_eq!(patch["cr_number"], "4030000001");
        assert_eq!(patch["legal_name_ar"], "شركة المثال للتجارة - فرع جدة");
        assert_eq!(patch["phone"], "0126000000");
        assert_eq!(patch["proposed_parent_ref"], json!(parent));
        // A Hijri issue date gives no founded year.
        assert!(patch.get("founded_year").is_none());
        assert!(patch.get("parent_account_ref").is_none());
    }

    #[test]
    fn wathq_main_cr_proposes_no_parent() {
        let found = registration(&serde_json::from_str(MAIN).unwrap(), "1010000009").unwrap();
        assert_eq!(found.proposed_parent_cr(), None);
        assert!(found.is_active());
        let patch = account_patch(&found, None);
        assert_eq!(patch["founded_year"], 2009);
        assert!(patch.get("proposed_parent_ref").is_none());
        assert!(patch.get("legal_name_en").is_none());
    }

    #[test]
    fn wathq_unknown_refused_and_bad_input() {
        let missing = Recorded::new(404, r#"{"code": "404", "message": "CR not found"}"#);
        let client = WathqClient::new(DEFAULT_BASE_URL, Secret::new("k"), &missing);
        assert_eq!(run(client.full_info("1010000009")).unwrap(), None);
        assert!(run(client.full_info("12")).is_err());
        assert_eq!(
            missing.asked.lock().unwrap().len(),
            1,
            "bad input never reaches Wathq"
        );

        let refused = Recorded::new(401, r#"{"message": "Invalid apiKey"}"#);
        let client = WathqClient::new(DEFAULT_BASE_URL, Secret::new("k"), &refused);
        let err = run(client.full_info("1010000009")).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("Invalid apiKey")),
            "{err:?}"
        );

        let broken = Recorded::new(200, "<html>");
        let client = WathqClient::new(DEFAULT_BASE_URL, Secret::new("k"), &broken);
        assert!(run(client.full_info("1010000009")).is_err());

        let busy = Recorded::new(429, "");
        let client = WathqClient::new(DEFAULT_BASE_URL, Secret::new("k"), &busy);
        assert!(matches!(
            run(client.full_info("1010000009")),
            Err(AppError::TooManyRequests { .. })
        ));
    }

    #[test]
    fn wathq_gregorian_years_only() {
        assert_eq!(gregorian_year("2009-04-30"), Some(2009));
        assert_eq!(gregorian_year("30/04/2009"), Some(2009));
        assert_eq!(gregorian_year("1430/05/12"), None);
    }
}

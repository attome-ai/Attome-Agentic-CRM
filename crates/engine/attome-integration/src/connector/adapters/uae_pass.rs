//! AJ2-T1: UAE Pass, the UAE national digital identity, as a sign-in
//! provider preset.
//!
//! UAE Pass speaks OAuth 2.0 with its own user-info shape rather than plain
//! OpenID Connect discovery, so the preset carries its endpoints per
//! environment ([`Environment`]) instead of an issuer to discover:
//!
//! - [`UaePassClient::authorize_url`] builds the authorization request
//!   (`response_type=code`, the `urn:uae:digitalid:profile:general` scope,
//!   `acr_values` asking for the mobile app);
//! - [`UaePassClient::exchange_code`] trades the code for an access token at
//!   the token endpoint (client id and secret as HTTP Basic);
//! - [`UaePassClient::profile`] reads the user-info endpoint and maps it into a
//!   [`Profile`]: the UAE Pass `uuid`, the Emirates ID (`idn`, checked: 15
//!   digits, `784`, Luhn check digit), email, mobile, names in English and
//!   Arabic, nationality and the account level (`SOP1` unverified, `SOP2` and
//!   `SOP3` verified). [`Profile::verified`] is what a caller should require
//!   before trusting the Emirates ID.
//!
//! [`contact_patch`] gives the fields a sign-in or a lookup may fill on a
//! contact (library-core `person` fields where they exist). The client
//! secret is a [`Secret`]; a refused key or an answer of the wrong shape is
//! an error, never an empty profile. Checked against recorded answers only:
//! no UAE Pass account is configured here. Document signing through UAE
//! Pass (the K4 adapter) is not built.

use attome_types::AppError;
use serde_json::{Map, Value, json};

use crate::connector::sdk::{Request, Secret, Transport};

/// The scope UAE Pass grants profile data under.
pub const SCOPE: &str = "urn:uae:digitalid:profile:general";
/// Ask for authentication through the UAE Pass mobile app.
pub const ACR_MOBILE: &str = "urn:safelayer:tws:policies:authentication:level:low";

/// Which UAE Pass to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Staging,
    Production,
}

impl Environment {
    /// The identity host of the environment.
    pub fn base(self) -> &'static str {
        match self {
            Environment::Staging => "https://stg-id.uaepass.ae",
            Environment::Production => "https://id.uaepass.ae",
        }
    }

    pub fn authorize_endpoint(self) -> String {
        format!("{}/idshub/authorize", self.base())
    }

    pub fn token_endpoint(self) -> String {
        format!("{}/idshub/token", self.base())
    }

    pub fn userinfo_endpoint(self) -> String {
        format!("{}/idshub/userinfo", self.base())
    }

    pub fn logout_endpoint(self) -> String {
        format!("{}/idshub/logout", self.base())
    }
}

/// An Emirates ID: fifteen digits starting `784` with a Luhn check digit
/// (dashes and spaces ignored, Arabic-Indic digits read as Western).
pub fn emirates_id(input: &str) -> Option<String> {
    let digits: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c {
            '٠'..='٩' => char::from(b'0' + (c as u32 - '٠' as u32) as u8),
            other => other,
        })
        .collect();
    if digits.len() != 15
        || !digits.starts_with("784")
        || !digits.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    (sum % 10 == 0).then_some(digits)
}

/// The account level UAE Pass reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// SOP1: a basic, unverified account.
    Basic,
    /// SOP2: verified.
    Verified,
    /// SOP3: verified in person.
    VerifiedInPerson,
    /// A level this adapter does not know.
    Other,
}

impl Level {
    fn parse(s: Option<&str>) -> Self {
        match s.map(str::trim) {
            Some("SOP1") => Level::Basic,
            Some("SOP2") => Level::Verified,
            Some("SOP3") => Level::VerifiedInPerson,
            _ => Level::Other,
        }
    }
}

/// A UAE Pass profile.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// UAE Pass's own id for the person.
    pub uuid: String,
    /// The Emirates ID, when UAE Pass gave a valid one.
    pub emirates_id: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub full_name_en: Option<String>,
    pub full_name_ar: Option<String>,
    pub first_name_en: Option<String>,
    pub last_name_en: Option<String>,
    pub nationality: Option<String>,
    pub gender: Option<String>,
    pub level: Level,
}

impl Profile {
    /// Whether the account is verified (SOP2 or SOP3) and carries a valid
    /// Emirates ID: only then is the ID evidence of who signed in.
    pub fn verified(&self) -> bool {
        matches!(self.level, Level::Verified | Level::VerifiedInPerson)
            && self.emirates_id.is_some()
    }
}

fn text(v: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| match v.get(*n) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    })
}

/// Reads a user-info answer.
pub fn profile(info: &Value) -> Result<Profile, AppError> {
    let uuid = text(info, &["uuid", "sub"])
        .ok_or_else(|| AppError::internal("UAE Pass answered a profile with no uuid"))?;
    Ok(Profile {
        uuid,
        emirates_id: text(info, &["idn", "emiratesId"]).and_then(|id| emirates_id(&id)),
        email: text(info, &["email"]),
        mobile: text(info, &["mobile"]),
        full_name_en: text(info, &["fullnameEN", "fullnameEn"]),
        full_name_ar: text(info, &["fullnameAR", "fullnameAr"]),
        first_name_en: text(info, &["firstnameEN", "firstnameEn"]),
        last_name_en: text(info, &["lastnameEN", "lastnameEn"]),
        nationality: text(info, &["nationalityEN", "nationalityEn"]),
        gender: text(info, &["gender"]),
        level: Level::parse(text(info, &["userType"]).as_deref()),
    })
}

/// The contact fields a profile fills; the Emirates ID only from a verified
/// account. Only what UAE Pass returned, so a field it left out keeps its
/// value.
pub fn contact_patch(p: &Profile) -> Map<String, Value> {
    let mut patch = Map::new();
    let mut put = |name: &str, value: &Option<String>| {
        if let Some(v) = value {
            patch.insert(name.to_owned(), json!(v));
        }
    };
    put("email", &p.email);
    put("mobile", &p.mobile);
    put("first_name", &p.first_name_en);
    put("last_name", &p.last_name_en);
    put("full_name_ar", &p.full_name_ar);
    if p.verified() {
        put("emirates_id", &p.emirates_id);
    }
    patch
}

/// A UAE Pass connection.
pub struct UaePassClient<'a> {
    pub environment: Environment,
    pub client_id: String,
    pub client_secret: Secret,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for UaePassClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UaePassClient")
            .field("environment", &self.environment)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

fn answer_json(status: u16, body: &str, what: &str) -> Result<Value, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    match status {
        400 | 401 | 403 => {
            let reason = value
                .as_ref()
                .and_then(|v| text(v, &["error_description", "error", "message"]))
                .unwrap_or_else(|| "no reason given".into());
            Err(AppError::Validation(format!(
                "UAE Pass refused the {what}: {reason}"
            )))
        }
        s if s >= 400 => Err(AppError::internal(format!("UAE Pass answered {s}"))),
        _ => value
            .filter(Value::is_object)
            .ok_or_else(|| AppError::internal("UAE Pass answered no JSON")),
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        out.append_pair(k, v);
    }
    out.finish()
}

impl<'a> UaePassClient<'a> {
    /// The authorization request to send the browser to. `state` must be a
    /// fresh value the caller checks on return.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, ui_locale: &str) -> String {
        format!(
            "{}?{}",
            self.environment.authorize_endpoint(),
            form(&[
                ("response_type", "code"),
                ("client_id", &self.client_id),
                ("scope", SCOPE),
                ("state", state),
                ("redirect_uri", redirect_uri),
                ("acr_values", ACR_MOBILE),
                ("ui_locales", if ui_locale == "ar" { "ar" } else { "en" }),
            ])
        )
    }

    /// Trades an authorization code for an access token.
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<Secret, AppError> {
        if code.trim().is_empty() || code.len() > 2048 {
            return Err(AppError::Validation("the UAE Pass code is missing".into()));
        }
        use base64::Engine as _;
        let basic = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            self.client_id,
            self.client_secret.wire_value()
        ));
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url: self.environment.token_endpoint(),
                headers: vec![
                    ("Authorization".into(), format!("Basic {basic}")),
                    (
                        "Content-Type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    ("Accept".into(), "application/json".into()),
                ],
                body: Some(form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                ])),
            })
            .await?;
        let value = answer_json(answer.status, &answer.body, "code")?;
        text(&value, &["access_token"])
            .map(Secret::new)
            .ok_or_else(|| AppError::internal("UAE Pass answered no access token"))
    }

    /// Reads the signed-in person's profile with an access token.
    pub async fn profile(&self, access_token: &Secret) -> Result<Profile, AppError> {
        let answer = self
            .transport
            .send(Request {
                method: "GET".into(),
                url: self.environment.userinfo_endpoint(),
                headers: vec![
                    (
                        "Authorization".into(),
                        format!("Bearer {}", access_token.wire_value()),
                    ),
                    ("Accept".into(), "application/json".into()),
                ],
                body: None,
            })
            .await?;
        profile(&answer_json(
            answer.status,
            &answer.body,
            "profile request",
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct Recorded {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<Request>>,
    }

    impl Recorded {
        fn new(answers: &[(u16, &'static str)]) -> Self {
            Recorded {
                answers: Mutex::new(answers.iter().rev().copied().collect()),
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
            let (status, body) = self.answers.lock().unwrap().pop().unwrap_or((500, ""));
            Box::pin(async move {
                Ok(Response {
                    status,
                    headers: Vec::new(),
                    body: body.to_owned(),
                })
            })
        }
    }

    const TOKEN: &str = r#"{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}"#;
    const INFO: &str = r#"{"sub": "uae-123", "uuid": "uae-123", "idn": "784-1990-1234567-6",
      "email": "a@example.ae", "mobile": "971500000000", "fullnameEN": "Ahmed Ali",
      "fullnameAR": "أحمد علي", "firstnameEN": "Ahmed", "lastnameEN": "Ali",
      "nationalityEN": "ARE", "gender": "Male", "userType": "SOP3"}"#;

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn client(t: &Recorded) -> UaePassClient<'_> {
        UaePassClient {
            environment: Environment::Staging,
            client_id: "sandbox_stage".into(),
            client_secret: Secret::new("s3cret"),
            transport: t,
        }
    }

    #[test]
    fn uae_pass_emirates_id_checks_prefix_length_and_luhn() {
        assert_eq!(
            emirates_id("784-1990-1234567-6").as_deref(),
            Some("784199012345676")
        );
        assert_eq!(emirates_id("784-1990-1234567-1"), None, "check digit");
        assert_eq!(emirates_id("785-1990-1234567-6"), None, "not 784");
        assert_eq!(emirates_id("784-1990-123456"), None, "too short");
    }

    #[test]
    fn uae_pass_authorize_url_carries_scope_state_and_locale() {
        let t = Recorded::new(&[]);
        let url = client(&t).authorize_url("https://crm.example.ae/cb", "st-9", "ar");
        assert!(
            url.starts_with("https://stg-id.uaepass.ae/idshub/authorize?"),
            "{url}"
        );
        assert!(
            url.contains("scope=urn%3Auae%3Adigitalid%3Aprofile%3Ageneral"),
            "{url}"
        );
        assert!(url.contains("state=st-9"), "{url}");
        assert!(url.contains("ui_locales=ar"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fcrm.example.ae%2Fcb"),
            "{url}"
        );
    }

    #[test]
    fn uae_pass_code_to_profile() {
        let t = Recorded::new(&[(200, TOKEN), (200, INFO)]);
        let c = client(&t);
        let token = run(c.exchange_code("code-1", "https://crm.example.ae/cb")).unwrap();
        let p = run(c.profile(&token)).unwrap();
        assert_eq!(p.uuid, "uae-123");
        assert_eq!(p.emirates_id.as_deref(), Some("784199012345676"));
        assert_eq!(p.level, Level::VerifiedInPerson);
        assert!(p.verified());
        let asked = t.asked.lock().unwrap();
        assert!(
            asked[0]
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.starts_with("Basic "))
        );
        assert!(
            asked[0]
                .body
                .as_deref()
                .unwrap_or("")
                .contains("grant_type=authorization_code")
        );
        assert!(
            asked[1]
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer at-1")
        );
        let patch = contact_patch(&p);
        assert_eq!(patch["emirates_id"], "784199012345676");
        assert_eq!(patch["full_name_ar"], "أحمد علي");
    }

    #[test]
    fn uae_pass_unverified_account_never_supplies_an_id() {
        let info: Value = serde_json::from_str(
            r#"{"uuid": "u-1", "idn": "784199012345676", "userType": "SOP1", "email": "b@example.ae"}"#,
        )
        .unwrap();
        let p = profile(&info).unwrap();
        assert_eq!(p.level, Level::Basic);
        assert!(!p.verified());
        assert!(contact_patch(&p).get("emirates_id").is_none());
        assert!(
            profile(&serde_json::json!({"email": "x"})).is_err(),
            "no uuid"
        );
    }

    #[test]
    fn uae_pass_refusals_are_errors() {
        let t = Recorded::new(&[(
            400,
            r#"{"error": "invalid_grant", "error_description": "code expired"}"#,
        )]);
        let err = run(client(&t).exchange_code("old", "https://crm.example.ae/cb")).unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("code expired")),
            "{err:?}"
        );
        let t = Recorded::new(&[(200, "<html>")]);
        assert!(run(client(&t).profile(&Secret::new("at"))).is_err());
        let t = Recorded::new(&[]);
        assert!(run(client(&t).exchange_code(" ", "x")).is_err());
        assert!(t.asked.lock().unwrap().is_empty());
    }
}

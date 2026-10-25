//! Marketing forms (roadmap E10-T1): a published `marketing_form` maps a
//! website form's fields onto a lead or contact, asks for consent per
//! purpose and keeps the visit's UTM tags.
//!
//! A submission ([`submit`]) is anonymous, so it is filed the way G2-T1's
//! anonymous intake files a request: as the service account named in
//! `marketing.form_intake.user`, through the generic create and update
//! (field validation, Auto Value, audit and the change feed apply). Without
//! that setting, or for a form that is not published, every answer is the
//! same 404. The person is found by email (case-insensitive) on the form's
//! target entity and updated with the mapped fields, else created; each
//! ticked consent checkbox (`consent_<purpose>`, for a purpose the form
//! lists) records a grant on `any` channel in the consent ledger with the
//! form as its proof, in one transaction; and one
//! `marketing_form_submission` row keeps the UTM tags, the page and the
//! consents given.
//!
//! Only fields named in the form's map reach the record; everything else
//! the browser sends is ignored.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The UTM tags a submission may carry.
pub const UTM_KEYS: [&str; 5] = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
];
/// The longest value one form field may send.
pub const MAX_VALUE_CHARS: usize = 2_000;

/// A form as the submission needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormDefinition {
    pub id: Uuid,
    /// `lead` or `contact`.
    pub target: String,
    /// Form field name to target attribute.
    pub field_map: BTreeMap<String, String>,
    pub consent_purposes: Vec<String>,
    pub capture_utm: bool,
    pub thank_you: Option<String>,
    pub redirect_url: Option<String>,
}

/// What a submission maps to. Pure.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Mapped {
    pub record: Map<String, Value>,
    pub email: String,
    /// The purposes the person ticked.
    pub consents: Vec<String>,
    pub utm: BTreeMap<String, String>,
    pub page_url: Option<String>,
}

/// The map from a form's `field_map` text (`{"form field": "attribute"}`).
/// Pure.
pub fn parse_field_map(raw: Option<&str>) -> Result<BTreeMap<String, String>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str::<BTreeMap<String, String>>(raw).map_err(|_| {
        AppError::Validation("the form's field map is not a JSON object of names".into())
    })
}

/// The form's consent purposes from a comma-separated list. Pure.
pub fn parse_purposes(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1"),
        Value::Number(n) => n.as_i64() == Some(1),
        _ => false,
    }
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().chars().take(MAX_VALUE_CHARS).collect()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

/// Maps a browser's form payload through the definition. The email is
/// required (from the field mapped to `email`, or a field named `email`).
/// Pure.
pub fn map_submission(
    def: &FormDefinition,
    payload: &Map<String, Value>,
) -> Result<Mapped, AppError> {
    let mut mapped = Mapped::default();
    for (field, attribute) in &def.field_map {
        if let Some(value) = payload.get(field).and_then(text) {
            mapped
                .record
                .insert(attribute.clone(), Value::String(value));
        }
    }
    let email = mapped
        .record
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| payload.get("email").and_then(text))
        .ok_or_else(|| AppError::Validation("email is required".into()))?;
    crate::address_check::check_syntax(&email)
        .map_err(|_| AppError::Validation("email is not a valid address".into()))?;
    mapped.email = email.trim().to_lowercase();
    mapped
        .record
        .insert("email".into(), Value::String(mapped.email.clone()));
    for purpose in &def.consent_purposes {
        if payload
            .get(&format!("consent_{purpose}"))
            .is_some_and(truthy)
        {
            mapped.consents.push(purpose.clone());
        }
    }
    if def.capture_utm {
        for key in UTM_KEYS {
            if let Some(value) = payload.get(key).and_then(text) {
                mapped
                    .utm
                    .insert(key.to_owned(), value.chars().take(200).collect());
            }
        }
    }
    mapped.page_url = payload
        .get("page_url")
        .and_then(text)
        .map(|u| u.chars().take(2_000).collect());
    Ok(mapped)
}

type FormRow = (
    String,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<bool>,
    Option<String>,
    Option<String>,
);

/// A published form; `NotFound` for any other.
pub async fn load_form(state: &EngineState, form: Uuid) -> Result<FormDefinition, AppError> {
    let row: Option<FormRow> = sqlx::query_as(
        "SELECT target_entity, field_map, consent_purposes, capture_utm, is_published, \
                thank_you_message, redirect_url \
           FROM marketing_form WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(form)
    .fetch_optional(&state.base.db)
    .await
    .map_err(|_| AppError::NotFound)?;
    let Some((target, map, purposes, utm, published, thank_you, redirect)) = row else {
        return Err(AppError::NotFound);
    };
    if published != Some(true) || !matches!(target.as_str(), "lead" | "contact") {
        return Err(AppError::NotFound);
    }
    Ok(FormDefinition {
        id: form,
        target,
        field_map: parse_field_map(map.as_deref())?,
        consent_purposes: parse_purposes(purposes.as_deref()),
        capture_utm: utm.unwrap_or(false),
        thank_you,
        redirect_url: redirect,
    })
}

/// The service account submissions are filed as; `None` when unset.
fn intake_user(state: &EngineState) -> Option<Uuid> {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("marketing.form_intake.user")
        .and_then(|d| store.resolve(d, None, None).0.as_str().map(str::to_owned))
        .and_then(|v| Uuid::parse_str(v.trim()).ok())
}

/// What the browser hears back.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FormAccepted {
    pub thank_you: Option<String>,
    pub redirect_url: Option<String>,
}

/// The browser's submission.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct FormSubmission {
    /// The form's fields, consent checkboxes (`consent_<purpose>`), UTM tags
    /// and `page_url`, as the form sent them.
    #[schema(value_type = Object)]
    pub fields: Map<String, Value>,
    /// The solved challenge, when the deployment asks for one.
    #[serde(default)]
    pub captcha_token: Option<String>,
}

/// Files one submission. See the module doc.
pub async fn submit(
    state: &EngineState,
    form: Uuid,
    payload: &Map<String, Value>,
) -> Result<FormAccepted, AppError> {
    let def = load_form(state, form).await?;
    let user = intake_user(state).ok_or(AppError::NotFound)?;
    let mapped = map_submission(&def, payload)?;
    let ctx = state.base.security.resolve(user).await?;
    let attrs: Vec<String> = state
        .entities
        .load()
        .get(&def.target)
        .map(|m| m.attrs.iter().map(|a| a.logicalname.clone()).collect())
        .unwrap_or_default();
    // Only attributes the target really has.
    let record: Map<String, Value> = mapped
        .record
        .iter()
        .filter(|(k, _)| attrs.iter().any(|a| a == *k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let existing: Option<(Uuid, i64)> = sqlx::query_as(&format!(
        "SELECT id, row_version FROM {} WHERE lower(email) = $1 AND is_active IS NOT FALSE \
          ORDER BY created_at LIMIT 1",
        attome_core::quote_ident(&def.target)
    ))
    .bind(&mapped.email)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (person, created_new) = match existing {
        Some((id, version)) => {
            let mut update = record.clone();
            update.remove("email");
            if !update.is_empty() {
                attome_records::entity_crud::update_record_for(
                    state,
                    &ctx,
                    user,
                    &def.target,
                    id,
                    version,
                    Value::Object(update),
                )
                .await?;
            }
            (id, false)
        }
        None => {
            let mut create = record.clone();
            if def.target == "lead"
                && attrs.iter().any(|a| a == "name")
                && !create.contains_key("name")
            {
                create.insert("name".into(), Value::String(mapped.email.clone()));
            }
            if attrs.iter().any(|a| a == "source") && !create.contains_key("source") {
                create.insert("source".into(), Value::String("web_form".into()));
            }
            let (id, _) = attome_records::entity_crud::create_record_with_id_for(
                state,
                &ctx,
                user,
                &def.target,
                Value::Object(create),
                Uuid::now_v7(),
            )
            .await?;
            (id, true)
        }
    };

    let now = Utc::now();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for purpose in &mapped.consents {
        attome_compliance::consent::record(
            &mut tx,
            &attome_compliance::consent::ConsentChange {
                subject_entity: def.target.clone(),
                subject_id: person,
                purpose_key: purpose.clone(),
                channel: "any".into(),
                grant: true,
                source: "web_form".into(),
                proof: json!({
                    "form_id": def.id,
                    "page_url": mapped.page_url,
                    "checkbox": format!("consent_{purpose}"),
                }),
                occurred_at: now,
                recorded_by: Some(user),
            },
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;

    let mut submission = json!({
        "form_ref": def.id.to_string(),
        "person_entity": def.target,
        "person_id": person.to_string(),
        "created_new": created_new,
        "consents": mapped.consents.join(", "),
    });
    for (key, value) in &mapped.utm {
        submission[key] = json!(value);
    }
    if let Some(url) = &mapped.page_url {
        submission["page_url"] = json!(url);
    }
    attome_records::entity_crud::create_record_with_id_for(
        state,
        &ctx,
        user,
        "marketing_form_submission",
        submission,
        Uuid::now_v7(),
    )
    .await?;
    // E14-T7: the tracking script sends its visitor id as `atm_vid`; the
    // visitor's sessions and campaign touches go to the person when they
    // consented to marketing. A failure here never refuses the submission.
    let visitor = payload
        .get("atm_vid")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok());
    let target = match def.target.as_str() {
        "lead" => Some(crate::tracking::identify::IdentifyTarget::Lead(person)),
        "contact" => Some(crate::tracking::identify::IdentifyTarget::Contact(person)),
        _ => None,
    };
    if let (Some(visitor), Some(target)) = (visitor, target)
        && let Err(error) = crate::tracking::identify::identify(
            state,
            &ctx,
            user,
            visitor,
            target,
            crate::tracking::identify::Source::FormSubmit,
            mapped.consents.iter().any(|p| p == "marketing"),
        )
        .await
    {
        tracing::warn!(%error, form = %def.id, "form visitor not identified");
    }
    Ok(FormAccepted {
        thank_you: def.thank_you,
        redirect_url: def.redirect_url,
    })
}

// ── The public submission route ──────────────────────────────────────────────

/// Submissions one address may send a minute, across forms.
const PER_ADDRESS_PER_MINUTE: i32 = 5;
/// Submissions one form takes a minute, from everyone.
const PER_FORM_PER_MINUTE: i32 = 120;

/// Submit a marketing form.
///
/// Public: a published form's submission, filed as the service account in
/// `marketing.form_intake.user`. Every miss (unknown, unpublished, no intake
/// account, marketing not licensed) is the same 404. At most five a minute
/// from one address and 120 a minute to one form; when the deployment has a
/// challenge, `captcha_token` must carry it solved (429 with
/// `Attome-Challenge` otherwise).
#[utoipa::path(
    post,
    path = "/api/v1/marketing/forms/{id}/submit",
    operation_id = "submit_marketing_form",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The published form")),
    request_body = FormSubmission,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("attome_records::entity_crud::create_record_with_id_for"),
        "anonymous form submission: the lead or contact, its consent events and the submission row are written by the generic create and the consent ledger, as the intake service account",
    )))),
    responses(
        (status = 200, description = "Accepted; what to show next", body = FormAccepted),
        (status = 404, description = "This form takes no submissions (the same answer for every reason)", body = attome_types::ErrorResponse),
        (status = 422, description = "No valid email, or a field is not accepted", body = attome_types::ErrorResponse),
        (status = 429, description = "Too many submissions, or the challenge was not solved", body = attome_types::ErrorResponse),
    ),
)]
async fn post_submit(
    axum::extract::State(state): axum::extract::State<EngineState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(form): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<FormSubmission>,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;
    if state
        .modules
        .load()
        .require(attome_modules::MODULE_MARKETING)
        .is_err()
    {
        return Err(AppError::NotFound);
    }
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    );
    for (key, limit) in [
        (
            format!("marketing:rl:form:address:{ip}"),
            PER_ADDRESS_PER_MINUTE,
        ),
        (format!("marketing:rl:form:{form}"), PER_FORM_PER_MINUTE),
    ] {
        let outcome =
            attome_cache::rate_limit::check(&state.base.redis_coordination, &key, limit).await?;
        if !outcome.allowed {
            return Err(AppError::TooManyRequests {
                retry_after_secs: None,
            });
        }
    }
    let captcha = &state.base.config.portal.captcha;
    let sovereign = state.base.config.deployment.sovereign;
    let provider = captcha.effective_provider(sovereign);
    if provider != attome_config::CaptchaProvider::None {
        let pow_secret = state
            .base
            .secrets
            .load()
            .jwt_secret
            .active()
            .map(str::to_owned);
        let remote_ip = ip.to_string();
        let solved = attome_auth::captcha::verify_challenge(
            captcha,
            sovereign,
            &state.base.redis_coordination,
            pow_secret.as_deref(),
            body.captcha_token.as_deref(),
            Some(remote_ip.as_str()),
        )
        .await;
        if !solved {
            let mut refused = AppError::TooManyRequests {
                retry_after_secs: None,
            }
            .into_response();
            let kind = match provider {
                attome_config::CaptchaProvider::Pow => "pow",
                attome_config::CaptchaProvider::Turnstile => "turnstile",
                attome_config::CaptchaProvider::Hcaptcha => "hcaptcha",
                attome_config::CaptchaProvider::None => "wait",
            };
            refused.headers_mut().insert(
                "attome-challenge",
                axum::http::HeaderValue::from_static(kind),
            );
            return Ok(refused);
        }
    }
    let accepted = submit(&state, form, &body.fields).await?;
    Ok(axum::Json(accepted).into_response())
}

/// The public form route, merged beside the other bypass-listed public
/// routes (its path is `bypass::is_marketing_form_path`).
pub fn public_routes() -> axum::Router<EngineState> {
    axum::Router::new().route(
        "/api/v1/marketing/forms/{id}/submit",
        axum::routing::post(post_submit),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_submit), components(schemas(FormSubmission, FormAccepted)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod form_to_lead {
    use super::*;

    fn form() -> FormDefinition {
        FormDefinition {
            id: Uuid::now_v7(),
            target: "lead".into(),
            field_map: [
                ("full_name".to_owned(), "name".to_owned()),
                ("work_email".to_owned(), "email".to_owned()),
                ("company".to_owned(), "company_name".to_owned()),
            ]
            .into_iter()
            .collect(),
            consent_purposes: vec!["newsletter".into(), "events".into()],
            capture_utm: true,
            thank_you: None,
            redirect_url: None,
        }
    }

    fn payload(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn mapped_fields_consent_and_utm_reach_the_lead() {
        let mapped = map_submission(
            &form(),
            &payload(json!({
                "full_name": "Sara Ahmed",
                "work_email": " Sara@Acme.SA ",
                "company": "Acme",
                "consent_newsletter": "on",
                "consent_events": false,
                "consent_partners": true,
                "utm_source": "linkedin",
                "utm_campaign": "ramadan",
                "is_admin": true,
                "page_url": "https://acme.sa/contact"
            })),
        )
        .unwrap();
        assert_eq!(mapped.email, "sara@acme.sa");
        assert_eq!(mapped.record["name"], "Sara Ahmed");
        assert_eq!(mapped.record["company_name"], "Acme");
        assert_eq!(mapped.record["email"], "sara@acme.sa");
        assert!(
            !mapped.record.contains_key("is_admin"),
            "unmapped fields are dropped"
        );
        assert_eq!(
            mapped.consents,
            vec!["newsletter"],
            "only the form's purposes, only ticked"
        );
        assert_eq!(mapped.utm["utm_source"], "linkedin");
        assert_eq!(mapped.page_url.as_deref(), Some("https://acme.sa/contact"));
    }

    #[test]
    fn an_email_is_required_and_valid() {
        assert!(map_submission(&form(), &payload(json!({"full_name": "x"}))).is_err());
        assert!(
            map_submission(&form(), &payload(json!({"work_email": "not-an-address"}))).is_err()
        );
        let mut no_utm = form();
        no_utm.capture_utm = false;
        let mapped = map_submission(
            &no_utm,
            &payload(json!({"work_email": "a@b.sa", "utm_source": "x"})),
        )
        .unwrap();
        assert!(mapped.utm.is_empty());
    }

    #[test]
    fn the_map_and_purposes_parse() {
        assert_eq!(parse_field_map(Some(r#"{"a":"b"}"#)).unwrap()["a"], "b");
        assert!(parse_field_map(Some("[1]")).is_err());
        assert!(parse_field_map(None).unwrap().is_empty());
        assert_eq!(
            parse_purposes(Some(" newsletter, events ;")),
            vec!["newsletter", "events"]
        );
    }
}

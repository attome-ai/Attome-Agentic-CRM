//! G14-T2: surveys sent on events, answered through signed links.
//!
//! A published `survey` (`attome_model::kinds::survey`) with a `send_on`
//! (entity, field, value, recipient lookup) is sent when a record of that
//! entity reaches the value: closing a case (`service_ticket.status =
//! closed`) is the usual one. The `survey_send` job (every minute) reads the
//! change feed (consumer [`CONSUMER`]); for each changed record that now
//! matches, it adds one pending row to the survey's response entity
//! (regarding the record, for the recipient) unless the record already has
//! one, and emails the recipient a link signed over that row (30 days).
//! Events older than a day are passed over, so a new deployment or a long
//! outage never mails a backlog.
//!
//! The link opens `GET /api/v1/surveys/form?token=`, a plain bilingual page
//! whose form posts to `POST /api/v1/surveys/form`; an app uses the JSON
//! pair `GET`/`POST /api/v1/surveys/respond`. All four are public (the
//! signed link is the credential) and store the answers once: the row is written only while it has no `submitted_at`, so
//! a link answers one response. Every answer is checked against its
//! question (type, choice options, required) before anything is written.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_model::kinds::survey::{SendOn, field_type_of, response_entity_of, send_on_of};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "survey_send";
/// The change-feed consumer.
pub const CONSUMER: &str = "attome-service/survey_send";
/// The link's signing domain.
const LINK_DOMAIN: &str = "attome-service/survey-response";
const LINK_DAYS: i64 = 30;
const BATCH: i64 = 500;
const MAX_BATCHES: usize = 10;
/// Events older than this are not sent.
const FRESH_HOURS: i64 = 24;
/// Most published surveys considered.
const MAX_SURVEYS: i64 = 200;

/// A published survey that sends on an event.
#[derive(Debug, Clone)]
struct Sender {
    id: Uuid,
    doc: Value,
    send_on: SendOn,
    entity: String,
}

/// Whether a changed record now matches a trigger. Pure.
pub fn triggers(send_on: &SendOn, record: &Value) -> bool {
    match record.get(&send_on.field) {
        Some(Value::String(s)) => s == &send_on.value,
        Some(Value::Bool(b)) => b.to_string() == send_on.value,
        Some(Value::Number(n)) => n.to_string() == send_on.value,
        _ => false,
    }
}

/// The link's subject for one response row. Pure.
pub fn subject_of(survey: Uuid, row: Uuid) -> String {
    format!("survey|{survey}|{row}")
}

/// The survey and response row a link's subject names. Pure.
pub fn parse_subject(subject: &str) -> Option<(Uuid, Uuid)> {
    let mut parts = subject.split('|');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("survey"), Some(s), Some(r), None) => {
            Some((Uuid::parse_str(s).ok()?, Uuid::parse_str(r).ok()?))
        }
        _ => None,
    }
}

/// Checks the answers against the questions: known keys only, the right
/// type, a choice among the options, every required question answered.
/// Answers the columns to write. Pure.
pub fn check_answers(
    doc: &Value,
    answers: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let questions = doc
        .get("questions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Map::new();
    for key in answers.keys() {
        if !questions
            .iter()
            .any(|q| q.get("key").and_then(Value::as_str) == Some(key))
        {
            return Err(format!("{key}: not a question of this survey"));
        }
    }
    for q in &questions {
        let key = q.get("key").and_then(Value::as_str).unwrap_or_default();
        let qtype = q.get("type").and_then(Value::as_str).unwrap_or_default();
        let required = q.get("required").and_then(Value::as_bool).unwrap_or(false);
        let options: Vec<&str> = q
            .get("options")
            .and_then(Value::as_array)
            .map(|o| o.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let Some(answer) = answers.get(key).filter(|a| !a.is_null()) else {
            if required {
                return Err(format!("{key}: an answer is required"));
            }
            continue;
        };
        let ok = match qtype {
            "text" | "long_text" => answer.as_str().is_some_and(|s| s.chars().count() <= 4000),
            "number" => answer.is_number(),
            "rating" => answer.as_f64().is_some_and(|r| (0.0..=10.0).contains(&r)),
            "bool" => answer.is_boolean(),
            "date" => answer
                .as_str()
                .is_some_and(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok()),
            "choice" => answer.as_str().is_some_and(|c| options.contains(&c)),
            "multi_choice" => answer.as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.iter()
                        .all(|c| c.as_str().is_some_and(|c| options.contains(&c)))
            }),
            _ => false,
        };
        if !ok || field_type_of(qtype).is_none() {
            return Err(format!("{key}: not a valid {qtype} answer"));
        }
        out.insert(key.to_owned(), answer.clone());
    }
    Ok(out)
}

fn link_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

async fn senders(state: &EngineState) -> Result<Vec<Sender>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM metadata_object WHERE kind = 'survey' AND is_active ORDER BY id LIMIT $1",
    )
    .bind(MAX_SURVEYS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for id in ids {
        let Ok(version) = attome_model::store::read_published(&state.base.db, id).await else {
            continue;
        };
        let (Some(send_on), Some(entity)) =
            (send_on_of(&version.doc), response_entity_of(&version.doc))
        else {
            continue;
        };
        let entity = entity.to_owned();
        out.push(Sender {
            id,
            doc: version.doc,
            send_on,
            entity,
        });
    }
    Ok(out)
}

/// One tick: sends the surveys the changes since the cursor trigger.
/// Answers how many were sent.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let senders = senders(state).await?;
    let mut sent = 0;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        let fresh_after = Utc::now() - Duration::hours(FRESH_HOURS);
        for event in &events {
            if event.event_name.is_some() || event.created_at < fresh_after {
                continue;
            }
            for sender in senders
                .iter()
                .filter(|s| s.send_on.entity == event.entity_logicalname)
            {
                match send_one(state, sender, event.record_id).await {
                    Ok(true) => sent += 1,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(survey = %sender.id, record = %event.record_id, %error, "survey not sent");
                    }
                }
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(sent)
}

async fn send_one(state: &EngineState, sender: &Sender, record_id: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let registry = state.entities.load();
    if registry.get(&sender.send_on.entity).is_none() || registry.get(&sender.entity).is_none() {
        return Ok(false);
    }
    drop(registry);
    let source = attome_core::quote_ident(&sender.send_on.entity);
    let record: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {source} t WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(record) = record.filter(|r| triggers(&sender.send_on, r)) else {
        return Ok(false);
    };
    let Some(recipient) = record
        .get(&sender.send_on.recipient)
        .and_then(Value::as_str)
        .and_then(|r| Uuid::parse_str(r).ok())
    else {
        return Ok(false);
    };
    // A user, else a contact, with an address.
    let user_email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(recipient)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let (respondent, email) = match user_email.flatten() {
        Some(email) => (Some(recipient), Some(email)),
        None => {
            let contact: Option<Option<String>> =
                sqlx::query_scalar("SELECT to_jsonb(c)->>'email' FROM contact c WHERE id = $1")
                    .bind(recipient)
                    .fetch_optional(db)
                    .await
                    .unwrap_or(None);
            (None, contact.flatten())
        }
    };
    let Some(email) = email.filter(|e| crate::status_page::email_ok(e)) else {
        return Ok(false);
    };
    // One survey per record: a row regarding it means it was sent.
    let target = attome_core::quote_ident(&sender.entity);
    let row: Option<Uuid> = sqlx::query_scalar(&format!(
        "INSERT INTO {target} (id, respondent_ref, respondent_email, regarding_entity, regarding_id) \
         SELECT $1, $2, $3, $4, $5 \
          WHERE NOT EXISTS (SELECT 1 FROM {target} \
                             WHERE regarding_entity = $4 AND regarding_id = $5) \
         RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .bind(respondent)
    .bind(&email)
    .bind(&sender.send_on.entity)
    .bind(record_id.to_string())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let token = attome_auth::signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &subject_of(sender.id, row),
        (Utc::now() + Duration::days(LINK_DAYS)).timestamp(),
    )
    .ok_or_else(|| AppError::internal("could not sign the survey link"))?;
    let title = sender
        .doc
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or("our survey");
    let link = format!(
        "{}/api/v1/surveys/form?token={token}",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    let job = attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
        to: email,
        subject: format!("Tell us how we did: {title}"),
        text_body: format!(
            "Please answer a short survey: {link}\n\nشاركنا رأيك في استبيان قصير: {link}"
        ),
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
    }));
    let mut tx = attome_db::tx::begin(db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, job)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// The link.
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct SurveyToken {
    /// The signed token from the email.
    pub token: String,
}

/// A survey as the respondent sees it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SurveyForm {
    pub title: String,
    pub title_ar: Option<String>,
    /// The questions: key, label, label_ar, type, required, options.
    #[schema(value_type = Vec<Object>)]
    pub questions: Vec<Value>,
}

/// The answers.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SurveyAnswers {
    pub token: String,
    /// Question key to answer.
    #[schema(value_type = Object)]
    pub answers: Map<String, Value>,
}

/// Stored.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SurveyThanks {
    pub received: bool,
}

/// The survey and its response row a valid token names.
async fn resolve(state: &EngineState, token: &str) -> Result<(Value, String, Uuid), AppError> {
    let subject = attome_auth::signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token.trim(),
        Utc::now().timestamp(),
    )
    .ok_or(AppError::NotFound)?;
    let (survey, row) = parse_subject(&subject).ok_or(AppError::NotFound)?;
    let version = attome_model::store::read_published(&state.base.db, survey)
        .await
        .map_err(|_| AppError::NotFound)?;
    let entity = response_entity_of(&version.doc)
        .ok_or(AppError::NotFound)?
        .to_owned();
    if state.entities.load().get(&entity).is_none() {
        return Err(AppError::NotFound);
    }
    Ok((version.doc, entity, row))
}

#[utoipa::path(
    get,
    path = "/api/v1/surveys/respond",
    operation_id = "get_survey_respond",
    tag = "service",
    params(SurveyToken),
    responses(
        (status = 200, description = "The survey to answer", body = SurveyForm),
        (status = 404, description = "The link is not valid, has expired or was answered", body = ErrorResponse),
    ),
)]
/// The survey a signed link opens.
///
/// No sign-in: the link is the credential. A link that was answered, has
/// expired or was tampered with answers the same 404.
async fn get_respond(
    State(state): State<EngineState>,
    Query(q): Query<SurveyToken>,
) -> Result<Json<SurveyForm>, AppError> {
    let (doc, entity, row) = resolve(&state, &q.token).await?;
    let open: Option<bool> = sqlx::query_scalar(&format!(
        "SELECT submitted_at IS NULL FROM {} WHERE id = $1",
        attome_core::quote_ident(&entity)
    ))
    .bind(row)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if open != Some(true) {
        return Err(AppError::NotFound);
    }
    Ok(Json(SurveyForm {
        title: doc
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        title_ar: doc
            .get("display_name_ar")
            .and_then(Value::as_str)
            .map(str::to_owned),
        questions: doc
            .get("questions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/surveys/respond",
    operation_id = "post_survey_respond",
    tag = "service",
    request_body = SurveyAnswers,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Stored", body = SurveyThanks),
        (status = 404, description = "The link is not valid, has expired or was answered", body = ErrorResponse),
        (status = 422, description = "An answer does not fit its question", body = ErrorResponse),
    ),
)]
/// Stores the answers of a signed link, once.
///
/// Each answer is checked against its question; the response is written
/// only while it is unanswered, so one link answers one response.
async fn post_respond(
    State(state): State<EngineState>,
    Json(body): Json<SurveyAnswers>,
) -> Result<Json<SurveyThanks>, AppError> {
    let (doc, entity, row) = resolve(&state, &body.token).await?;
    store(&state, &doc, &entity, row, &body.answers).await?;
    Ok(Json(SurveyThanks { received: true }))
}

/// Checks and stores one response's answers, once.
async fn store(
    state: &EngineState,
    doc: &Value,
    entity: &str,
    row: Uuid,
    answers: &Map<String, Value>,
) -> Result<(), AppError> {
    let answers = check_answers(doc, answers).map_err(AppError::Validation)?;
    let table = attome_core::quote_ident(entity);
    let mut columns: Vec<String> = answers
        .keys()
        .map(|k| attome_core::quote_ident(k))
        .collect();
    columns.push("submitted_at".to_owned());
    let mut record: HashMap<String, Value> = answers.into_iter().collect();
    record.insert("submitted_at".to_owned(), json!(Utc::now().to_rfc3339()));
    let list = columns.join(", ");
    // Typed by the table itself: jsonb_populate_record casts each answer to
    // its column's type.
    let sql = format!(
        "UPDATE {table} SET ({list}) = (SELECT {list} FROM jsonb_populate_record(NULL::{table}, $2)), \
             modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND submitted_at IS NULL"
    );
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let written = sqlx::query(&sql)
        .bind(row)
        .bind(json!(record))
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Validation("the answers do not fit the survey".into()))?
        .rows_affected();
    if written == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity,
            row,
            attome_audit::AuditOperation::Update,
            "survey.answered",
            Uuid::nil(),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// The bilingual form page a link opens. Pure.
pub fn render_form(doc: &Value, token: &str) -> String {
    use attome_html::escape_html as e;
    let text = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut fields = String::new();
    for q in doc
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = e(&text(q, "key"));
        let label = e(&text(q, "label"));
        let label_ar = e(&text(q, "label_ar"));
        let required = if q.get("required").and_then(Value::as_bool) == Some(true) {
            " required"
        } else {
            ""
        };
        let options: Vec<String> = q
            .get("options")
            .and_then(Value::as_array)
            .map(|o| o.iter().filter_map(Value::as_str).map(e).collect())
            .unwrap_or_default();
        let input = match text(q, "type").as_str() {
            "long_text" => format!("<textarea name=\"{key}\" rows=\"4\"{required}></textarea>"),
            "number" => format!("<input type=\"number\" step=\"any\" name=\"{key}\"{required}>"),
            "rating" => {
                format!("<input type=\"number\" min=\"0\" max=\"10\" name=\"{key}\"{required}>")
            }
            "bool" => format!(
                "<select name=\"{key}\"{required}><option value=\"\"></option>\
                 <option value=\"true\">Yes / نعم</option><option value=\"false\">No / لا</option></select>"
            ),
            "date" => format!("<input type=\"date\" name=\"{key}\"{required}>"),
            "choice" => {
                let opts: String = options
                    .iter()
                    .map(|o| format!("<option value=\"{o}\">{o}</option>"))
                    .collect();
                format!(
                    "<select name=\"{key}\"{required}><option value=\"\"></option>{opts}</select>"
                )
            }
            "multi_choice" => options
                .iter()
                .map(|o| {
                    format!(
                        "<label><input type=\"checkbox\" name=\"{key}\" value=\"{o}\"> {o}</label> "
                    )
                })
                .collect(),
            _ => format!("<input type=\"text\" name=\"{key}\"{required}>"),
        };
        fields.push_str(&format!(
            "<p><label>{label}<br><span dir=\"rtl\" lang=\"ar\">{label_ar}</span><br>{input}</label></p>"
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>{title}</title></head><body style=\"font:16px system-ui,sans-serif;max-inline-size:36rem;margin:2rem auto;padding:0 1rem\">\
         <h1>{title}</h1><p dir=\"rtl\" lang=\"ar\">{title_ar}</p>\
         <form method=\"post\" action=\"/api/v1/surveys/form\"><input type=\"hidden\" name=\"token\" value=\"{token}\">\
         {fields}<button type=\"submit\">Send / إرسال</button></form></body></html>",
        title = e(&text(doc, "display_name")),
        title_ar = e(&text(doc, "display_name_ar")),
        token = e(token),
    )
}

/// The answers a posted form carries, typed by question; empty fields are
/// left out. Pure.
pub fn form_answers(doc: &Value, pairs: &[(String, String)]) -> Map<String, Value> {
    let mut out = Map::new();
    for q in doc
        .get("questions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(key) = q.get("key").and_then(Value::as_str) else {
            continue;
        };
        let values: Vec<&str> = pairs
            .iter()
            .filter(|(k, v)| k == key && !v.trim().is_empty())
            .map(|(_, v)| v.trim())
            .collect();
        let Some(first) = values.first() else {
            continue;
        };
        let value = match q.get("type").and_then(Value::as_str).unwrap_or_default() {
            "number" | "rating" => first
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map_or_else(|| json!(first), Value::Number),
            "bool" => match *first {
                "true" => json!(true),
                "false" => json!(false),
                other => json!(other),
            },
            "multi_choice" => json!(values),
            _ => json!(first),
        };
        out.insert(key.to_owned(), value);
    }
    out
}

fn page(en: &str, ar: &str) -> axum::response::Html<String> {
    use attome_html::escape_html as e;
    axum::response::Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Survey</title></head>\
         <body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <p>{}</p><p dir=\"rtl\" lang=\"ar\">{}</p></body></html>",
        e(en),
        e(ar)
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/surveys/form",
    operation_id = "get_survey_form",
    tag = "service",
    params(SurveyToken),
    responses((status = 200, description = "The survey as a form page, or a page saying the link is no longer valid", content_type = "text/html")),
)]
/// The survey page a signed link opens.
///
/// A plain bilingual form that posts its answers; a link that is invalid,
/// expired or answered shows a page saying so.
async fn get_form(
    State(state): State<EngineState>,
    Query(q): Query<SurveyToken>,
) -> axum::response::Html<String> {
    let Ok((doc, entity, row)) = resolve(&state, &q.token).await else {
        return page(
            "This survey link is no longer valid.",
            "رابط الاستبيان لم يعد صالحاً.",
        );
    };
    let open: Option<bool> = sqlx::query_scalar(&format!(
        "SELECT submitted_at IS NULL FROM {} WHERE id = $1",
        attome_core::quote_ident(&entity)
    ))
    .bind(row)
    .fetch_optional(&state.base.db)
    .await
    .unwrap_or(None);
    if open != Some(true) {
        return page(
            "This survey was already answered. Thank you.",
            "تمت الإجابة على هذا الاستبيان. شكراً لك.",
        );
    }
    axum::response::Html(render_form(&doc, q.token.trim()))
}

#[utoipa::path(
    post,
    path = "/api/v1/surveys/form",
    operation_id = "post_survey_form",
    tag = "service",
    request_body(content = SurveyToken, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses((status = 200, description = "A page thanking the respondent, or saying what is wrong", content_type = "text/html")),
)]
/// Stores the answers a survey page posts, once.
///
/// The same checks as the JSON route; the answer is a page, not JSON.
async fn post_form(
    State(state): State<EngineState>,
    axum::Form(pairs): axum::Form<Vec<(String, String)>>,
) -> axum::response::Html<String> {
    let token = pairs
        .iter()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let Ok((doc, entity, row)) = resolve(&state, &token).await else {
        return page(
            "This survey link is no longer valid.",
            "رابط الاستبيان لم يعد صالحاً.",
        );
    };
    match store(&state, &doc, &entity, row, &form_answers(&doc, &pairs)).await {
        Ok(()) => page("Thank you for your answers.", "شكراً لإجاباتك."),
        Err(AppError::Validation(message)) => {
            page(&message, "يرجى مراجعة الإجابات والمحاولة مرة أخرى.")
        }
        Err(_) => page(
            "This survey was already answered. Thank you.",
            "تمت الإجابة على هذا الاستبيان. شكراً لك.",
        ),
    }
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/surveys/respond",
            get(get_respond).post(post_respond),
        )
        .route("/api/v1/surveys/form", get(get_form).post(post_form))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_respond, post_respond, get_form, post_form),
    components(schemas(SurveyToken, SurveyForm, SurveyAnswers, SurveyThanks))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod survey_send_tests {
    use super::*;

    fn doc() -> Value {
        json!({
            "response_entity": "csat_response",
            "display_name": "CSAT",
            "questions": [
                { "key": "score", "label": "Score", "type": "rating", "required": true },
                { "key": "channel", "label": "Channel", "type": "choice", "options": ["phone", "email"] },
                { "key": "tags", "label": "Tags", "type": "multi_choice", "options": ["fast", "kind"] },
                { "key": "comment", "label": "Comment", "type": "long_text" }
            ]
        })
    }

    fn answers(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn closing_a_case_triggers_its_survey() {
        let on = SendOn {
            entity: "service_ticket".into(),
            field: "status".into(),
            value: "closed".into(),
            recipient: "requester_id".into(),
        };
        assert!(triggers(&on, &json!({ "status": "closed" })));
        assert!(!triggers(&on, &json!({ "status": "resolved" })));
        assert!(!triggers(&on, &json!({})));
    }

    #[test]
    fn a_link_names_its_survey_and_response() {
        let (s, r) = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert_eq!(parse_subject(&subject_of(s, r)), Some((s, r)));
        assert_eq!(parse_subject("status|a@b.c"), None);
        assert_eq!(parse_subject(&format!("survey|{s}|{r}|x")), None);
    }

    #[test]
    fn a_form_post_becomes_typed_answers() {
        let pairs: Vec<(String, String)> = [
            ("token", "t"),
            ("score", "8"),
            ("channel", "phone"),
            ("tags", "fast"),
            ("tags", "kind"),
            ("comment", "  "),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let a = form_answers(&doc(), &pairs);
        assert_eq!(a.get("score"), Some(&json!(8.0)));
        assert_eq!(a.get("tags"), Some(&json!(["fast", "kind"])));
        assert!(!a.contains_key("comment"), "an empty field is no answer");
        assert!(check_answers(&doc(), &a).is_ok());
    }

    #[test]
    fn the_form_page_escapes_what_it_shows() {
        let mut d = doc();
        d["display_name"] = json!("<b>CSAT</b>");
        let html = render_form(&d, "tok\"en");
        assert!(html.contains("&lt;b&gt;CSAT&lt;/b&gt;"));
        assert!(!html.contains("<b>CSAT"));
        assert!(html.contains("name=\"tags\" value=\"fast\""));
        assert!(!html.contains("tok\"en"));
    }

    #[test]
    fn answers_fit_their_questions() {
        let ok = check_answers(
            &doc(),
            &answers(json!({
                "score": 9, "channel": "email", "tags": ["fast"], "comment": "Thanks"
            })),
        )
        .expect("valid");
        assert_eq!(ok.len(), 4);
        assert!(
            check_answers(&doc(), &answers(json!({ "channel": "email" }))).is_err(),
            "score is required"
        );
        assert!(
            check_answers(&doc(), &answers(json!({ "score": 11 }))).is_err(),
            "out of range"
        );
        assert!(check_answers(&doc(), &answers(json!({ "score": 5, "channel": "fax" }))).is_err());
        assert!(check_answers(&doc(), &answers(json!({ "score": 5, "tags": [] }))).is_err());
        assert!(check_answers(&doc(), &answers(json!({ "score": 5, "extra": 1 }))).is_err());
    }
}

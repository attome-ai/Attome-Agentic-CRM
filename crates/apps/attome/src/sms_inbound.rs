//! J4-T2: texts people send to the deployment's SMS number.
//!
//! The provider posts each one to `POST /api/v1/sms/inbound/{key}`, where
//! `key` is the SMS system's `inbound_key` (set by the administrator, at
//! least 16 characters, compared by digest): the key is the authority, as
//! the provider cannot sign per message. The route is public, rate-limited
//! and licensed with the omnichannel module.
//!
//! **Conversation.** The sender's number is matched to a contact (or a lead
//! or account) by any phone field, digits only. The message is written as an
//! inbound `sms` communication on that record, threaded with earlier texts,
//! through the M52 writer as the SMS system's service principal (D-425), so
//! privileges, audit and the timeline apply. A number that matches no
//! record is written on the SMS system itself, for an agent to pick up.
//!
//! **STOP.** A message that is only a stop word (STOP, UNSUBSCRIBE, …, or
//! الغاء / إيقاف) withdraws the matched person's consent to texts for every
//! consent-based purpose (E27), with the message as proof. Texts the
//! deployment sends afterwards are refused by the consent gate.

use attome_core::EngineState;
use attome_integration::sms::{InboundSms, inbound_system, is_stop, parse_inbound};
use attome_modules::MODULE_OMNICHANNEL;
use attome_security::SecurityContextExt;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::Utc;
use uuid::Uuid;

/// Entities a sender may be found in, and the phone fields looked at.
const PEOPLE: &[&str] = &["contact", "lead", "account"];
const PHONE_FIELDS: &[&str] = &[
    "phone",
    "mobile",
    "mobile_phone",
    "telephone",
    "phone_number",
];

/// The sender's record: the first person entity with a phone field holding
/// the same digits.
pub(crate) async fn find_sender(
    state: &EngineState,
    e164: &str,
) -> Result<Option<(String, Uuid)>, AppError> {
    let digits: String = e164.chars().filter(char::is_ascii_digit).collect();
    for entity in PEOPLE {
        let fields: Vec<String> = {
            let registry = state.entities.load();
            let Some(meta) = registry.get(entity) else {
                continue;
            };
            meta.attrs
                .iter()
                .filter(|a| PHONE_FIELDS.contains(&a.logicalname.as_str()))
                .map(|a| a.logicalname.clone())
                .collect()
        };
        if fields.is_empty() {
            continue;
        }
        for field in &fields {
            let sql = format!(
                "SELECT id FROM {} WHERE (is_active IS NULL OR is_active = true) \
                   AND regexp_replace(coalesce({}::text, ''), '\\D', '', 'g') = $1 \
                 ORDER BY id LIMIT 1",
                attome_core::quote_ident(entity),
                attome_core::quote_ident(field)
            );
            let found: Option<Uuid> =
                sqlx::query_scalar(&attome_db::tag_dynamic("sms.inbound", &sql))
                    .bind(&digits)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
            if let Some(id) = found {
                return Ok(Some(((*entity).to_owned(), id)));
            }
        }
    }
    Ok(None)
}

async fn thread_of(state: &EngineState, entity: &str, id: Uuid) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT thread_id FROM communication \
          WHERE entity_name = $1 AND record_id = $2 AND channel = 'sms' \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(entity)
    .bind(id.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Withdraws the person's consent to texts for every consent-based purpose.
async fn opt_out(
    state: &EngineState,
    person: (&str, Uuid),
    message: &InboundSms,
) -> Result<usize, AppError> {
    let purposes: Vec<String> = sqlx::query_scalar(
        "SELECT key FROM audit_consent_purpose \
          WHERE (is_active IS NULL OR is_active = true) AND lawful_basis = 'consent'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for purpose in &purposes {
        attome_compliance::consent::record(
            &mut tx,
            &attome_compliance::consent::ConsentChange {
                subject_entity: person.0.to_owned(),
                subject_id: person.1,
                purpose_key: purpose.clone(),
                channel: "sms".into(),
                grant: false,
                source: "sms_stop".into(),
                proof: serde_json::json!({
                    "from": message.from,
                    "body": message.body,
                    "provider_message_id": message.provider_message_id,
                }),
                occurred_at: Utc::now(),
                recorded_by: None,
            },
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(purposes.len())
}

/// An inbound text message
///
/// A text someone sent to the deployment's number.
#[utoipa::path(
    post,
    path = "/api/v1/sms/inbound/{key}",
    tag = "omnichannel",
    params(("key" = String, Path, description = "The SMS system's inbound key")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 204, description = "Received"),
        (status = 404, description = "Not licensed, or no SMS system has this key", body = ErrorResponse),
        (status = 422, description = "Not a message this route reads", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn inbound(
    State(state): State<EngineState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    if state.modules.load().require(MODULE_OMNICHANNEL).is_err() {
        return Err(AppError::NotFound);
    }
    let system = inbound_system(&state, &key)
        .await?
        .ok_or(AppError::NotFound)?;
    let message =
        parse_inbound(&body).ok_or_else(|| AppError::Validation("not an inbound text".into()))?;
    let principal = attome_integration::system::service_principal_id(&system)?;
    let ctx = state.base.security.resolve(principal).await?;
    ctx.require("communication", "create")?;

    let sender = find_sender(&state, &message.from).await?;
    let (entity, record) = sender
        .clone()
        .unwrap_or_else(|| ("integration_system".to_owned(), system.id));
    let thread = thread_of(&state, &entity, record).await?;
    attome_notification::communication::write_communication(
        &state,
        &ctx,
        principal,
        &entity,
        record,
        "sms",
        "inbound",
        std::slice::from_ref(&message.from),
        &[],
        "SMS",
        &message.body,
        None,
        thread,
        None,
        None,
    )
    .await?;

    if is_stop(&message.body) {
        match &sender {
            Some((entity, id)) => {
                let withdrawn = opt_out(&state, (entity, *id), &message).await?;
                tracing::info!(%id, entity = %entity, withdrawn, "sms: opted out of texts");
            }
            None => tracing::info!("sms: a stop from a number no record holds"),
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/sms/inbound/{key}", post(inbound))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(inbound))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

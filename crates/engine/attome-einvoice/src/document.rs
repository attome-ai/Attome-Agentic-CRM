//! Each invoice's e-invoice (AG2-T3): stamped on an onboarded device, kept
//! in its device's hash chain, and sent to ZATCA.
//!
//! - [`create`] stamps the invoice on the oldest active device in one
//!   transaction: the device row is locked (`FOR UPDATE`), the document
//!   takes the next counter value and the previous hash, and the device's
//!   chain moves on, so two invoices never share a place and the chain never
//!   forks. An invoice keeps the one document it got.
//! - [`submit`] sends a pending document: clearance for a standard invoice
//!   (it is shared only once cleared, as ZATCA's cleared copy), reporting
//!   for a simplified one. Accepted documents end `cleared` or `reported`;
//!   refused ones `rejected` with ZATCA's messages; an outage or rate limit
//!   keeps the document pending for a later try ([`super::zatca::api::retry_after`]),
//!   which the billing sweep makes. ZATCA is called outside any transaction.

use attome_core::EngineState;
use attome_types::AppError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration as ChronoDuration, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::zatca::api::{Api, Credentials, DocumentAnswer, DocumentRequest, Outcome, Transport};
use crate::zatca::csr::Environment;
use crate::zatca::sign::{self, Certificate, DeviceKey};
use crate::zatca::xml::{Profile, ZatcaInvoice};

/// An invoice's e-invoice as people and the billing engine see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DocumentState {
    pub id: Uuid,
    pub invoice_id: Uuid,
    /// `standard` or `simplified`.
    pub profile: String,
    /// `pending`, `cleared`, `reported`, `rejected` or `failed`.
    pub status: String,
    pub icv: i64,
    pub invoice_hash: String,
    /// The QR code (base64 TLV) to print.
    pub qr: String,
    pub attempts: i32,
    /// ZATCA's validation results, as it sent them.
    #[schema(value_type = Object)]
    pub validation: Option<serde_json::Value>,
    pub last_error: Option<String>,
}

type StateRow = (
    Uuid,
    Uuid,
    String,
    String,
    i64,
    String,
    String,
    i32,
    Option<serde_json::Value>,
    Option<String>,
);

const STATE_COLUMNS: &str = "id, invoice_ref, profile, status, icv, invoice_hash, qr, attempts, \
     validation, last_error";

fn state_of(row: StateRow) -> DocumentState {
    let (id, invoice_id, profile, status, icv, invoice_hash, qr, attempts, validation, last_error) =
        row;
    DocumentState {
        id,
        invoice_id,
        profile,
        status,
        icv,
        invoice_hash,
        qr,
        attempts,
        validation,
        last_error,
    }
}

/// The invoice's e-invoice, if it has one.
pub async fn for_invoice(
    state: &EngineState,
    invoice_id: Uuid,
) -> Result<Option<DocumentState>, AppError> {
    let row: Option<StateRow> = sqlx::query_as(&format!(
        "SELECT {STATE_COLUMNS} FROM einvoice_document WHERE invoice_ref = $1"
    ))
    .bind(invoice_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(state_of))
}

/// Whether a device can stamp invoices.
pub async fn has_active_device(state: &EngineState) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM einvoice_device WHERE status = 'active')")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

type DeviceRow = (
    Uuid,
    String,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
);

/// Stamps `invoice_id` on the oldest active device. `build` writes the
/// invoice's data given its counter value and previous hash.
pub async fn create(
    state: &EngineState,
    invoice_id: Uuid,
    build: impl FnOnce(u64, String) -> ZatcaInvoice,
) -> Result<DocumentState, AppError> {
    if let Some(existing) = for_invoice(state, invoice_id).await? {
        return Ok(existing);
    }
    let ring = crate::device::ring(state)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let device: Option<DeviceRow> = sqlx::query_as(
        "SELECT id, private_key_encrypted, last_icv, last_hash, certificate, cert_issuer, \
                cert_serial, cert_ca_signature \
         FROM einvoice_device WHERE status = 'active' \
         ORDER BY created_at, id LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((device_id, key_encrypted, last_icv, last_hash, cert, issuer, serial, ca_sig)) =
        device
    else {
        return Err(AppError::Conflict(
            "no onboarded e-invoicing device; onboard one first",
        ));
    };
    let key = DeviceKey::from_pkcs8_der(&crate::crypto::decrypt_key(ring, &key_encrypted)?)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let certificate = Certificate {
        base64: cert.ok_or_else(|| AppError::internal("an active device has no certificate"))?,
        issuer_name: issuer.unwrap_or_default(),
        serial_number: serial.unwrap_or_default(),
        ca_signature: ca_sig.unwrap_or_default(),
    };
    let icv = u64::try_from(last_icv).unwrap_or_default() + 1;
    let invoice = build(icv, last_hash);
    let stamped = sign::stamp(&invoice, &key, &certificate, Utc::now().naive_utc())
        .map_err(|e| AppError::Validation(format!("the invoice cannot be e-invoiced: {e}")))?;
    let profile = match invoice.profile {
        Profile::Standard => "standard",
        Profile::Simplified => "simplified",
    };
    let document_uuid = Uuid::parse_str(&invoice.uuid).map_err(AppError::internal)?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO einvoice_document (id, invoice_ref, device_ref, profile, icv, \
             document_uuid, invoice_hash, xml, qr, next_attempt_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())",
    )
    .bind(id)
    .bind(invoice_id)
    .bind(device_id)
    .bind(profile)
    .bind(i64::try_from(icv).unwrap_or(i64::MAX))
    .bind(document_uuid)
    .bind(&stamped.hash)
    .bind(&stamped.xml)
    .bind(&stamped.qr)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE einvoice_device SET last_icv = $2, last_hash = $3, updated_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(device_id)
    .bind(i64::try_from(icv).unwrap_or(i64::MAX))
    .bind(&stamped.hash)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    for_invoice(state, invoice_id)
        .await?
        .ok_or_else(|| AppError::internal("a stamped document was not kept"))
}

type SubmitRow = (
    Uuid,
    String,
    String,
    Uuid,
    String,
    String,
    i32,
    String,
    Option<String>,
    Option<String>,
);

/// Sends a pending document to ZATCA through `transport`; returns its state.
pub async fn submit(
    state: &EngineState,
    document_id: Uuid,
    transport: &dyn Transport,
) -> Result<DocumentState, AppError> {
    let ring = crate::device::ring(state)?;
    let row: Option<SubmitRow> = sqlx::query_as(
        "SELECT d.invoice_ref, d.profile, d.status, d.document_uuid, d.invoice_hash, d.xml, \
                d.attempts, v.environment, v.production_token, v.production_secret_encrypted \
         FROM einvoice_document d JOIN einvoice_device v ON v.id = d.device_ref \
         WHERE d.id = $1",
    )
    .bind(document_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((invoice_id, profile, status, uuid, hash, xml, attempts, env, token, secret)) = row
    else {
        return Err(AppError::NotFound);
    };
    if status != "pending" {
        return for_invoice(state, invoice_id)
            .await?
            .ok_or(AppError::NotFound);
    }
    let (Some(token), Some(secret)) = (token, secret) else {
        return Err(AppError::Conflict(
            "the document's device has no production CSID",
        ));
    };
    let credentials = Credentials {
        token,
        secret: crate::crypto::decrypt_secret(ring, &secret)?,
    };
    let api = Api {
        environment: Environment::parse(&env)
            .ok_or_else(|| AppError::internal("a device has an unknown environment"))?,
        transport,
    };
    let request = DocumentRequest::new(&hash, &uuid.to_string(), &xml);
    let outcome = if profile == "standard" {
        api.clear(&credentials, &request).await
    } else {
        api.report(&credentials, &request).await
    };
    record(state, document_id, &profile, attempts, outcome).await?;
    for_invoice(state, invoice_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Where a submission left the document.
struct Settled {
    status: &'static str,
    validation: Option<serde_json::Value>,
    cleared: Option<String>,
    error: Option<String>,
    next: Option<chrono::DateTime<Utc>>,
}

async fn record(
    state: &EngineState,
    document_id: Uuid,
    profile: &str,
    attempts: i32,
    outcome: Outcome<DocumentAnswer>,
) -> Result<(), AppError> {
    let validation = |answer: &Option<DocumentAnswer>| {
        answer
            .as_ref()
            .and_then(|a| a.validation_results.as_ref())
            .and_then(|v| serde_json::to_value(v).ok())
    };
    let Settled {
        status,
        validation,
        cleared,
        error,
        next,
    } = match outcome {
        Outcome::Accepted { answer, .. } => {
            let cleared = answer
                .cleared_invoice
                .as_deref()
                .and_then(|b| STANDARD.decode(b).ok())
                .and_then(|b| String::from_utf8(b).ok());
            let done = if profile == "standard" {
                "cleared"
            } else {
                "reported"
            };
            Settled {
                status: done,
                validation: validation(&Some(answer)),
                cleared,
                error: None,
                next: None,
            }
        }
        Outcome::Rejected { answer, body } => {
            let v = validation(&answer);
            let message = if v.is_some() {
                "ZATCA refused the document; see its validation results".to_owned()
            } else {
                format!(
                    "ZATCA refused the document: {}",
                    body.chars().take(500).collect::<String>()
                )
            };
            Settled {
                status: "rejected",
                validation: v,
                cleared: None,
                error: Some(message),
                next: None,
            }
        }
        Outcome::Unauthorized => Settled {
            status: "pending",
            validation: None,
            cleared: None,
            error: Some("ZATCA refused the device's production CSID; renew it".to_owned()),
            next: Some(Utc::now() + ChronoDuration::hours(1)),
        },
        Outcome::RetryLater { reason } => {
            let wait = crate::zatca::api::retry_after(u32::try_from(attempts).unwrap_or(0));
            Settled {
                status: "pending",
                validation: None,
                cleared: None,
                error: Some(reason),
                next: Some(
                    Utc::now() + ChronoDuration::from_std(wait).unwrap_or(ChronoDuration::hours(1)),
                ),
            }
        }
    };
    sqlx::query(
        "UPDATE einvoice_document SET status = $2, validation = COALESCE($3, validation), \
             cleared_xml = COALESCE($4, cleared_xml), last_error = $5, next_attempt_at = $6, \
             attempts = attempts + 1, updated_at = now() \
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(document_id)
    .bind(status)
    .bind(validation)
    .bind(cleared)
    .bind(error)
    .bind(next)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Pending documents due for another try, oldest first.
pub async fn due(state: &EngineState, limit: i64) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM einvoice_document \
         WHERE status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= now()) \
         ORDER BY next_attempt_at NULLS FIRST, created_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The XML to share with the buyer: ZATCA's cleared copy when there is one.
pub async fn shareable_xml(
    state: &EngineState,
    invoice_id: Uuid,
) -> Result<Option<String>, AppError> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT xml, cleared_xml, status FROM einvoice_document WHERE invoice_ref = $1",
    )
    .bind(invoice_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(
        row.and_then(|(xml, cleared, status)| match status.as_str() {
            "cleared" => Some(cleared.unwrap_or(xml)),
            "reported" => Some(xml),
            _ => None,
        }),
    )
}

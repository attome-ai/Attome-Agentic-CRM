//! E-invoicing devices (EGS units) and their onboarding to ZATCA (AG2-T3).
//!
//! - [`create_device`] makes the device's signing key (stored encrypted under
//!   `einvoice.key_encryption_key`) and its certificate signing request,
//!   naming the seller from the billing settings.
//! - [`onboard`] takes the OTP an administrator got from the Fatoora
//!   portal: the compliance CSID, one compliance check per document kind the
//!   device will issue (standard and/or simplified invoice, credit note and
//!   debit note, stamped with the compliance certificate), then the
//!   production CSID. ZATCA is called outside any transaction; the row is
//!   written afterwards only if nobody changed it meanwhile (`row_version`).
//!   Every credential write records a Credential security event in its own
//!   transaction. A failed step leaves the device `failed` with ZATCA's
//!   reason, and onboarding can start again with a new OTP.
//!
//! Secrets (the key, the CSID secrets) never leave this module in clear and
//! are never logged.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_config::KeyRing;
use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{NaiveDate, Timelike as _, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::zatca::api::{Api, Credentials, DocumentRequest, Outcome, Transport};
use crate::zatca::csr::{self, CsrFields, Environment};
use crate::zatca::hash::ChainState;
use crate::zatca::sign::{self, Certificate, DeviceKey};
use crate::zatca::xml::{Address, DocumentKind, Line, Party, Profile, TaxCategory, ZatcaInvoice};

/// A device as administrators see it (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DeviceSummary {
    pub id: Uuid,
    pub name: String,
    /// `sandbox`, `simulation` or `production`.
    pub environment: String,
    /// `new`, `compliance`, `active`, `failed` or `retired`.
    pub status: String,
    pub egs_serial: String,
    pub invoice_types: String,
    /// Documents stamped so far.
    pub last_icv: i64,
    pub has_production_csid: bool,
    /// Why the last onboarding step failed.
    pub last_error: Option<String>,
}

/// A device to create.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewDevice {
    /// Unique; the certificate's common name.
    pub name: String,
    /// `sandbox` (the developer portal), `simulation` or `production`.
    pub environment: String,
    /// The branch or unit the device invoices for.
    pub organization_unit: String,
    /// Where it is (a short address or national address code).
    pub location: String,
    pub industry: String,
    /// `1100` (standard and simplified, the default), `1000` standard only,
    /// `0100` simplified only.
    pub invoice_types: Option<String>,
}

/// The e-invoicing key ring, refused while e-invoicing is off.
pub(crate) fn ring(state: &EngineState) -> Result<&KeyRing, AppError> {
    let section = &state.base.config.einvoice;
    if !section.enabled || section.key_encryption_key.is_empty() {
        return Err(AppError::Validation(
            "e-invoicing is off: set einvoice.enabled and einvoice.key_encryption_key".into(),
        ));
    }
    Ok(&section.key_encryption_key)
}

fn setting(state: &EngineState, key: &str) -> String {
    attome_core::setting_registry()
        .get(key)
        .and_then(|d| {
            let (value, _) = state.settings.load().resolve(d, None, None);
            value.as_str().map(|s| s.trim().to_owned())
        })
        .unwrap_or_default()
}

/// The seller, from the billing settings; every field ZATCA requires.
pub fn seller(state: &EngineState) -> Result<Party, AppError> {
    let get = |k: &str| setting(state, k);
    let party = Party {
        registration_name: get("billing.seller_name"),
        vat_number: Some(get("billing.seller_vat_number")),
        other_id: Some(get("billing.seller_crn"))
            .filter(|c| !c.is_empty())
            .map(|crn| ("CRN".to_owned(), crn)),
        address: Some(Address {
            street: get("billing.seller_street"),
            building_number: get("billing.seller_building_number"),
            city_subdivision: get("billing.seller_district"),
            city: get("billing.seller_city"),
            postal_zone: get("billing.seller_postal_zone"),
            country: {
                let c = get("billing.seller_country");
                if c.is_empty() { "SA".to_owned() } else { c }
            },
        }),
    };
    let address = party.address.as_ref().map(|a| {
        [
            &a.street,
            &a.building_number,
            &a.city_subdivision,
            &a.city,
            &a.postal_zone,
        ]
        .iter()
        .all(|v| !v.is_empty())
    });
    if party.registration_name.is_empty()
        || party.vat_number.as_deref().is_none_or(str::is_empty)
        || address != Some(true)
    {
        return Err(AppError::Validation(
            "set the seller's name, VAT number and national address in the billing settings first"
                .into(),
        ));
    }
    Ok(party)
}

type SummaryRow = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    i64,
    bool,
    Option<String>,
);

const SUMMARY_COLUMNS: &str = "id, name, environment, status, egs_serial, invoice_types, \
     last_icv, production_token IS NOT NULL, last_error";

fn summary(row: SummaryRow) -> DeviceSummary {
    let (id, name, environment, status, egs_serial, invoice_types, last_icv, prod, last_error) =
        row;
    DeviceSummary {
        id,
        name,
        environment,
        status,
        egs_serial,
        invoice_types,
        last_icv,
        has_production_csid: prod,
        last_error,
    }
}

/// Every device, newest first.
pub async fn list_devices(state: &EngineState) -> Result<Vec<DeviceSummary>, AppError> {
    let rows: Vec<SummaryRow> = sqlx::query_as(&format!(
        "SELECT {SUMMARY_COLUMNS} FROM einvoice_device ORDER BY created_at DESC, id DESC LIMIT 200"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(summary).collect())
}

async fn device_summary(state: &EngineState, id: Uuid) -> Result<DeviceSummary, AppError> {
    let row: Option<SummaryRow> = sqlx::query_as(&format!(
        "SELECT {SUMMARY_COLUMNS} FROM einvoice_device WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    row.map(summary).ok_or(AppError::NotFound)
}

/// Creates a device with its key and CSR.
pub async fn create_device(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &NewDevice,
) -> Result<DeviceSummary, AppError> {
    let ring = ring(state)?;
    let environment = Environment::parse(req.environment.trim()).ok_or_else(|| {
        AppError::Validation("environment is sandbox, simulation or production".into())
    })?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(AppError::Validation(
            "a device needs a name (at most 64 characters)".into(),
        ));
    }
    let types = req.invoice_types.as_deref().unwrap_or("1100");
    if !matches!(types, "1100" | "1000" | "0100") {
        return Err(AppError::Validation(
            "invoice_types is 1100, 1000 or 0100".into(),
        ));
    }
    let seller = seller(state)?;
    let id = Uuid::now_v7();
    let egs_serial = format!("1-Attome|2-{}|3-{id}", env!("CARGO_PKG_VERSION"));
    let key = DeviceKey::generate();
    let csr = csr::build(
        &CsrFields {
            environment,
            common_name: name.to_owned(),
            serial_number: egs_serial.clone(),
            vat_number: seller.vat_number.clone().unwrap_or_default(),
            organization_unit: req.organization_unit.trim().to_owned(),
            organization: seller.registration_name.clone(),
            country: seller
                .address
                .as_ref()
                .map_or_else(|| "SA".to_owned(), |a| a.country.clone()),
            invoice_types: types.to_owned(),
            location: req.location.trim().to_owned(),
            industry: req.industry.trim().to_owned(),
        },
        &key,
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    let encrypted = crate::crypto::encrypt_key(
        ring,
        &key.to_pkcs8_der()
            .map_err(|e| AppError::internal(e.to_string()))?,
    )?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inserted = sqlx::query(
        "INSERT INTO einvoice_device (id, name, environment, egs_serial, invoice_types, \
             private_key_encrypted, csr, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (name) DO NOTHING",
    )
    .bind(id)
    .bind(name)
    .bind(environment.as_str())
    .bind(&egs_serial)
    .bind(types)
    .bind(&encrypted)
    .bind(csr.pem())
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::Conflict("a device with this name exists"));
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "einvoice_device",
            Some(id),
        )
        .comment(format!(
            "e-invoicing device {name} created with a new signing key"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    device_summary(state, id).await
}

type OnboardRow = (String, String, String, String, String, i64);

async fn fail(state: &EngineState, id: Uuid, message: &str) -> AppError {
    if let Err(e) = sqlx::query(
        "UPDATE einvoice_device SET status = 'failed', last_error = $2, updated_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(message)
    .execute(&state.base.db)
    .await
    {
        tracing::error!(device = %id, error = %e, "einvoice: could not record an onboarding failure");
    }
    AppError::Validation(message.to_owned())
}

fn zatca_messages(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let errors = v
                .pointer("/validationResults/errorMessages")
                .or_else(|| v.get("errors"))?
                .as_array()?
                .iter()
                .filter_map(|m| {
                    let code = m.get("code").and_then(|c| c.as_str()).unwrap_or("");
                    let text = m.get("message").and_then(|c| c.as_str()).unwrap_or("");
                    (!code.is_empty() || !text.is_empty()).then(|| format!("{code} {text}"))
                })
                .collect::<Vec<_>>();
            (!errors.is_empty()).then(|| errors.join("; "))
        })
        .unwrap_or_else(|| "no reason given".to_owned())
}

/// Writes credentials, guarded by the row version read before the calls.
#[allow(clippy::too_many_arguments)]
async fn store_csid(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    version: i64,
    production: bool,
    token: &str,
    secret_encrypted: &str,
    request_id: Option<&str>,
    cert: &Certificate,
) -> Result<i64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let sql = if production {
        "UPDATE einvoice_device SET production_token = $3, production_secret_encrypted = $4, \
             certificate = $5, cert_issuer = $6, cert_serial = $7, cert_ca_signature = $8, \
             status = 'active', last_error = NULL, updated_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING row_version"
    } else {
        "UPDATE einvoice_device SET compliance_token = $3, compliance_secret_encrypted = $4, \
             compliance_request_id = $9, status = 'compliance', last_error = NULL, \
             updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING row_version"
    };
    let next: Option<i64> = sqlx::query_scalar(sql)
        .bind(id)
        .bind(version)
        .bind(token)
        .bind(secret_encrypted)
        .bind(&cert.base64)
        .bind(&cert.issuer_name)
        .bind(&cert.serial_number)
        .bind(&cert.ca_signature)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let Some(next) = next else {
        return Err(AppError::VersionConflict);
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            ctx.user_id,
            "einvoice_device",
            Some(id),
        )
        .comment(if production {
            "ZATCA production CSID stored".to_owned()
        } else {
            "ZATCA compliance CSID stored".to_owned()
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(next)
}

fn outcome_error<T>(step: &str, outcome: Outcome<T>) -> String {
    match outcome {
        Outcome::Accepted { .. } => format!("{step}: accepted"),
        Outcome::Rejected { body, .. } => {
            format!("{step}: ZATCA refused it: {}", zatca_messages(&body))
        }
        Outcome::Unauthorized => format!("{step}: ZATCA refused the credentials (or the OTP)"),
        Outcome::RetryLater { reason } => format!("{step}: {reason}; try again later"),
    }
}

/// Onboards a device with the portal's OTP, through `transport`.
pub async fn onboard(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    otp: &str,
    transport: &dyn Transport,
) -> Result<DeviceSummary, AppError> {
    let ring = ring(state)?;
    let otp = otp.trim();
    if otp.is_empty() || otp.len() > 12 || !otp.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::Validation(
            "the OTP is the digits the Fatoora portal shows".into(),
        ));
    }
    let row: Option<OnboardRow> = sqlx::query_as(
        "SELECT status, environment, invoice_types, private_key_encrypted, csr, row_version \
         FROM einvoice_device WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, environment, types, key_encrypted, csr_pem, version)) = row else {
        return Err(AppError::NotFound);
    };
    if !matches!(status.as_str(), "new" | "failed") {
        return Err(AppError::Conflict("the device is onboarded already"));
    }
    let environment = Environment::parse(&environment)
        .ok_or_else(|| AppError::internal("a device has an unknown environment"))?;
    let key = DeviceKey::from_pkcs8_der(&crate::crypto::decrypt_key(ring, &key_encrypted)?)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let seller = seller(state)?;
    let api = Api {
        environment,
        transport,
    };

    // 1. The compliance CSID.
    let csr_for_api = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &csr_pem);
    let compliance = match api.compliance_csid(otp, &csr_for_api).await {
        Outcome::Accepted { answer, .. } => answer,
        other => return Err(fail(state, id, &outcome_error("compliance CSID", other)).await),
    };
    let (Some(token), Some(secret), Some(request_id)) = (
        compliance.binary_security_token.clone(),
        compliance.secret.clone(),
        compliance.request_id_text(),
    ) else {
        return Err(fail(
            state,
            id,
            "compliance CSID: ZATCA's answer lacks the token, secret or request id",
        )
        .await);
    };
    let compliance_cert = match crate::zatca::cert::from_token(&token) {
        Ok(cert) => cert,
        Err(e) => return Err(fail(state, id, &format!("compliance CSID: {e}")).await),
    };
    let secret_encrypted = crate::crypto::encrypt_secret(ring, &secret)?;
    let version = store_csid(
        state,
        ctx,
        id,
        version,
        false,
        &token,
        &secret_encrypted,
        Some(&request_id),
        &compliance_cert,
    )
    .await?;
    let credentials = Credentials {
        token: token.clone(),
        secret,
    };

    // 2. One compliance check per document kind the device issues.
    let mut chain = ChainState::default();
    for profile in profiles(&types) {
        for kind in [
            DocumentKind::Invoice,
            DocumentKind::CreditNote,
            DocumentKind::DebitNote,
        ] {
            let (icv, pih) = chain.next();
            let sample = sample_document(&seller, profile, kind, icv, pih);
            let stamped = match sign::stamp(&sample, &key, &compliance_cert, Utc::now().naive_utc())
            {
                Ok(s) => s,
                Err(e) => return Err(fail(state, id, &format!("compliance check: {e}")).await),
            };
            let request = DocumentRequest::new(&stamped.hash, &sample.uuid, &stamped.xml);
            match api.compliance_check(&credentials, &request).await {
                Outcome::Accepted { .. } => {}
                other => {
                    let step = format!("compliance check ({profile:?} {kind:?})");
                    return Err(fail(state, id, &outcome_error(&step, other)).await);
                }
            }
            chain = chain
                .advance(icv, stamped.hash)
                .map_err(|e| AppError::internal(e.to_string()))?;
        }
    }

    // 3. The production CSID.
    let production = match api.production_csid(&credentials, &request_id).await {
        Outcome::Accepted { answer, .. } => answer,
        other => return Err(fail(state, id, &outcome_error("production CSID", other)).await),
    };
    let (Some(token), Some(secret)) = (production.binary_security_token, production.secret) else {
        return Err(fail(
            state,
            id,
            "production CSID: ZATCA's answer lacks the token or secret",
        )
        .await);
    };
    let cert = match crate::zatca::cert::from_token(&token) {
        Ok(cert) => cert,
        Err(e) => return Err(fail(state, id, &format!("production CSID: {e}")).await),
    };
    let secret_encrypted = crate::crypto::encrypt_secret(ring, &secret)?;
    store_csid(
        state,
        ctx,
        id,
        version,
        true,
        &token,
        &secret_encrypted,
        None,
        &cert,
    )
    .await?;
    device_summary(state, id).await
}

/// The profiles a device's `invoice_types` cover.
fn profiles(types: &str) -> Vec<Profile> {
    let bytes = types.as_bytes();
    let mut out = Vec::new();
    if bytes.first() == Some(&b'1') {
        out.push(Profile::Standard);
    }
    if bytes.get(1) == Some(&b'1') {
        out.push(Profile::Simplified);
    }
    out
}

/// A sample document for a compliance check: one standard-rated line.
fn sample_document(
    seller: &Party,
    profile: Profile,
    kind: DocumentKind,
    icv: u64,
    pih: String,
) -> ZatcaInvoice {
    let today: NaiveDate = Utc::now().date_naive();
    let note = matches!(kind, DocumentKind::CreditNote | DocumentKind::DebitNote);
    ZatcaInvoice {
        profile,
        kind,
        number: format!("COMPLIANCE-{icv}"),
        uuid: Uuid::new_v4().to_string(),
        issue_date: today,
        issue_time: Utc::now().time().with_nanosecond(0).unwrap_or_default(),
        currency: "SAR".into(),
        icv,
        pih,
        seller: seller.clone(),
        buyer: (profile == Profile::Standard).then(|| Party {
            registration_name: "Compliance Buyer".into(),
            vat_number: Some("399999999800003".into()),
            other_id: None,
            address: seller.address.clone(),
        }),
        supply_date: Some(today),
        payment_means: "10".into(),
        original_number: note.then(|| "COMPLIANCE-1".to_owned()),
        reason: note.then(|| "Compliance check".to_owned()),
        vat_in_sar: None,
        lines: vec![Line {
            name: "Compliance item".into(),
            quantity: Decimal::ONE,
            unit_code: "PCE".into(),
            unit_price: Decimal::ONE_HUNDRED,
            discount: Decimal::ZERO,
            net: Decimal::ONE_HUNDRED,
            category: TaxCategory::Standard,
            percent: Decimal::from(15),
            vat: Decimal::from(15),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zatca_api_profiles_follow_the_invoice_types() {
        assert_eq!(
            profiles("1100"),
            vec![Profile::Standard, Profile::Simplified]
        );
        assert_eq!(profiles("1000"), vec![Profile::Standard]);
        assert_eq!(profiles("0100"), vec![Profile::Simplified]);
    }

    #[test]
    fn zatca_api_zatcas_reasons_are_kept_without_secrets() {
        let body = crate::zatca::api::tests::REJECTED;
        assert!(zatca_messages(body).contains("invoiceHash_QRCODE_INVALID"));
        assert_eq!(zatca_messages("not json"), "no reason given");
    }
}

//! F6-T11: delivery by the deployment's own drivers, with proof.
//!
//! Only the shipment's driver (`shipment.driver_ref`) uses these routes;
//! anyone else, even with the privilege, gets 403.
//!
//! - `POST /api/v1/fulfilment/shipments/{id}/out-for-delivery` moves the
//!   shipment to `out_for_delivery` through the tracking path
//!   ([`crate::tracking::apply`]). When the setting [`OTP_SETTING`] is on, it
//!   also makes a six-digit code, keeps only its salted SHA-256
//!   (`shipment_delivery_otp`, migration 0286) and texts it to the order's
//!   `delivery_phone`, else its account's `phone`.
//! - `POST /api/v1/fulfilment/shipments/{id}/proof` records the outcome
//!   (`delivered`, `failed_attempt` or `refused`) as a `delivery_proof`
//!   record (photo and signature as files already uploaded, who received
//!   it, where) and moves the shipment to that status, so a delivery sets
//!   `delivered_on`, adds the shipped quantities to the order lines and
//!   raises `fulfilment.shipment.delivered`. With the code on, a delivery
//!   needs the code, compared in constant time; [`MAX_OTP_ATTEMPTS`] wrong
//!   codes lock it until the shipment goes out again.
//! - Cash on delivery: when the order's `cod_amount` (fulfilment pack
//!   changeset 0006) is above zero, a delivery records a `cash` payment from
//!   the order's account through billing's `record_payment`, referenced
//!   `shipment <id>`. It is recorded before the shipment moves and never
//!   twice for one shipment, so a retried proof after a failure neither
//!   loses nor doubles it.

use attome_core::EngineState;
use attome_integration::connector::adapters::carrier_aramex::TrackingUpdate;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The setting that turns the delivery code on.
pub const OTP_SETTING: &str = "fulfilment.delivery.otp";
/// Wrong codes before the code locks.
pub const MAX_OTP_ATTEMPTS: i32 = 5;
/// The outcomes a driver records.
pub const OUTCOMES: [&str; 3] = ["delivered", "failed_attempt", "refused"];
/// The carrier name the tracking path records for the own fleet.
const OWN_FLEET: &str = "own_fleet";

/// `delivery_proof.create`: the driver's privilege.
#[derive(Debug)]
pub struct DeliveryProofCreate;

impl PrivilegeKey for DeliveryProofCreate {
    const KEY: &'static str = "delivery_proof.create";
}

/// A new six-digit code.
pub fn new_code() -> String {
    format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32))
}

/// The stored form of a shipment's code: SHA-256 over the shipment id and
/// the code, hex. Pure.
pub fn hash_code(shipment: Uuid, code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(shipment.as_bytes());
    hasher.update(b":");
    hasher.update(code.trim().as_bytes());
    hex::encode(hasher.finalize())
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `code` is the shipment's code. Constant time. Pure.
pub fn code_matches(shipment: Uuid, code: &str, stored_hash: &str) -> bool {
    ct_eq(&hash_code(shipment, code), stored_hash)
}

/// The proof checks that need no database. Pure.
pub fn check_proof(body: &ProofBody) -> Result<(), AppError> {
    if !OUTCOMES.contains(&body.outcome.as_str()) {
        return Err(AppError::Validation(format!(
            "outcome is one of {}",
            OUTCOMES.join(", ")
        )));
    }
    if body.latitude.is_some_and(|v| !(-90.0..=90.0).contains(&v))
        || body
            .longitude
            .is_some_and(|v| !(-180.0..=180.0).contains(&v))
    {
        return Err(AppError::Validation(
            "latitude is -90 to 90 and longitude -180 to 180".into(),
        ));
    }
    if body.received_by.as_deref().is_some_and(|r| r.len() > 200) {
        return Err(AppError::Validation(
            "received_by is at most 200 characters".into(),
        ));
    }
    Ok(())
}

fn otp_enabled(state: &EngineState) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(OTP_SETTING) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

fn order_has(state: &EngineState, attribute: &str) -> bool {
    state
        .entities
        .load()
        .get("order")
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == attribute))
}

/// The shipment's status and sales order, when the caller is its driver.
async fn assigned(
    state: &EngineState,
    ctx: &SecurityContext,
    shipment: Uuid,
) -> Result<(Option<String>, Option<Uuid>), AppError> {
    let row: Option<(Option<String>, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT s.status::text, s.driver_ref, f.order_ref \
           FROM shipment s LEFT JOIN fulfilment_order f ON f.id = s.fulfilment_order_ref \
          WHERE s.id = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(shipment)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (status, driver, order) = row.ok_or(AppError::NotFound)?;
    if driver != Some(ctx.user_id) {
        return Err(AppError::Forbidden);
    }
    Ok((status, order))
}

fn is_final(status: Option<&str>) -> bool {
    status.is_some_and(|s| crate::tracking::FINAL.contains(&s))
}

async fn move_to(
    state: &EngineState,
    shipment: Uuid,
    status: &'static str,
    actor: Uuid,
) -> Result<(), AppError> {
    let update = TrackingUpdate {
        code: format!("driver:{}", Uuid::now_v7()),
        status,
        at_ms: None,
    };
    crate::tracking::apply(state, shipment, OWN_FLEET, &update, Some(actor)).await?;
    Ok(())
}

/// The phone a delivery code goes to: the order's delivery phone, else its
/// account's phone.
async fn delivery_phone(state: &EngineState, order: Uuid) -> Result<Option<String>, AppError> {
    let own = if order_has(state, "delivery_phone") {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT NULLIF(trim(delivery_phone), '') FROM \"order\" WHERE id = $1",
        )
        .bind(order)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten()
    } else {
        None
    };
    if own.is_some() {
        return Ok(own);
    }
    let has_phone = state
        .entities
        .load()
        .get("account")
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "phone"));
    if !has_phone {
        return Ok(None);
    }
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT NULLIF(trim(a.phone), '') FROM \"order\" o JOIN account a ON a.id = o.account_ref \
          WHERE o.id = $1",
    )
    .bind(order)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten())
}

/// Out for delivery.
#[derive(Debug, Serialize, ToSchema)]
pub struct OutForDelivery {
    pub shipment_id: Uuid,
    pub status: String,
    /// A delivery code was texted to the customer.
    pub code_sent: bool,
}

/// Moves the shipment out for delivery and, with codes on, sends one.
pub async fn out_for_delivery(
    state: &EngineState,
    ctx: &SecurityContext,
    shipment: Uuid,
) -> Result<OutForDelivery, AppError> {
    let (status, order) = assigned(state, ctx, shipment).await?;
    if is_final(status.as_deref()) {
        return Err(AppError::Conflict("the shipment is already closed"));
    }
    move_to(state, shipment, "out_for_delivery", ctx.user_id).await?;
    let mut code_sent = false;
    if otp_enabled(state) {
        let code = new_code();
        sqlx::query(
            "INSERT INTO shipment_delivery_otp (shipment_id, code_hash) VALUES ($1, $2) \
             ON CONFLICT (shipment_id) DO UPDATE \
                SET code_hash = EXCLUDED.code_hash, failed_attempts = 0, created_at = now()",
        )
        .bind(shipment)
        .bind(hash_code(shipment, &code))
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let phone = match order {
            Some(order) => delivery_phone(state, order).await?,
            None => None,
        };
        if let Some(phone) = phone {
            let body = format!("Your delivery code: {code}\nرمز التسليم: {code}");
            code_sent = matches!(
                attome_integration::sms::send(state, &phone, &body, None).await?,
                attome_integration::sms::Sent::Accepted(_)
            );
        }
        if !code_sent {
            tracing::warn!(%shipment, "delivery code not sent: no phone or no SMS provider");
        }
    }
    Ok(OutForDelivery {
        shipment_id: shipment,
        status: "out_for_delivery".to_owned(),
        code_sent,
    })
}

/// What the driver records.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProofBody {
    /// `delivered`, `failed_attempt` or `refused`.
    pub outcome: String,
    /// A photo, already uploaded through the files API (its file key).
    #[serde(default)]
    pub photo: Option<String>,
    /// A signature image, already uploaded (its file key).
    #[serde(default)]
    pub signature: Option<String>,
    /// The customer's delivery code, when codes are on.
    #[serde(default)]
    pub otp: Option<String>,
    /// Who took the delivery.
    #[serde(default)]
    pub received_by: Option<String>,
    #[serde(default)]
    pub latitude: Option<f64>,
    #[serde(default)]
    pub longitude: Option<f64>,
}

/// The recorded proof.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProofRecorded {
    pub proof_id: Uuid,
    pub shipment_id: Uuid,
    pub status: String,
    pub otp_verified: bool,
    /// The cash payment recorded for cash on delivery.
    pub cod_payment_id: Option<Uuid>,
}

/// Checks the code, refusing a wrong or locked one.
async fn verify_code(
    state: &EngineState,
    shipment: Uuid,
    code: Option<&str>,
) -> Result<(), AppError> {
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT code_hash, failed_attempts FROM shipment_delivery_otp WHERE shipment_id = $1",
    )
    .bind(shipment)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((stored, attempts)) = row else {
        return Err(AppError::Validation(
            "no delivery code was sent; send the shipment out for delivery first".into(),
        ));
    };
    if attempts >= MAX_OTP_ATTEMPTS {
        return Err(AppError::Conflict(
            "too many wrong codes; send the shipment out for delivery again for a new code",
        ));
    }
    if code.is_some_and(|c| code_matches(shipment, c, &stored)) {
        return Ok(());
    }
    sqlx::query(
        "UPDATE shipment_delivery_otp SET failed_attempts = failed_attempts + 1 \
          WHERE shipment_id = $1",
    )
    .bind(shipment)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Err(AppError::Validation("the delivery code is wrong".into()))
}

/// The order's cash-on-delivery amount, its account and currency, when one
/// is due.
async fn cod_due(
    state: &EngineState,
    order: Uuid,
) -> Result<Option<(Uuid, String, String)>, AppError> {
    if !order_has(state, "cod_amount") {
        return Ok(None);
    }
    let row: Option<(Option<String>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT cod_amount::text, account_ref, currency FROM \"order\" \
          WHERE id = $1 AND cod_amount > 0",
    )
    .bind(order)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(amount), account, currency)) = row else {
        return Ok(None);
    };
    let account = account.ok_or_else(|| {
        AppError::Validation("the order has cash on delivery but no account to pay it".into())
    })?;
    Ok(Some((
        account,
        amount,
        currency.unwrap_or_else(|| "SAR".to_owned()),
    )))
}

/// Records cash on delivery once per shipment.
async fn record_cod(
    state: &EngineState,
    ctx: &SecurityContext,
    shipment: Uuid,
    (account, amount, currency): (Uuid, String, String),
) -> Result<Uuid, AppError> {
    let reference = format!("shipment {shipment}");
    let earlier: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM customer_payment WHERE reference = $1 AND method = 'cash' LIMIT 1",
    )
    .bind(&reference)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(payment) = earlier {
        return Ok(payment);
    }
    let amount: serde_json::Number = serde_json::from_str(&amount)
        .map_err(|_| AppError::Validation("cod_amount is not a number".into()))?;
    let input = attome_billing::payment::service::NewPayment {
        payer_account_id: account,
        amount,
        currency,
        method: Some("cash".to_owned()),
        received_on: None,
        reference: Some(reference),
        allocations: None,
    };
    attome_billing::payment::service::record_payment(state, ctx, &input)
        .await
        .map(|p| p.payment_id)
}

/// Records the driver's proof and moves the shipment.
pub async fn record_proof(
    state: &EngineState,
    ctx: &SecurityContext,
    shipment: Uuid,
    body: &ProofBody,
) -> Result<ProofRecorded, AppError> {
    check_proof(body)?;
    ctx.require("delivery_proof", "create")?;
    let (status, order) = assigned(state, ctx, shipment).await?;
    if is_final(status.as_deref()) {
        return Err(AppError::Conflict("the shipment is already closed"));
    }
    let delivered = body.outcome == "delivered";
    let otp_verified = if delivered && otp_enabled(state) {
        verify_code(state, shipment, body.otp.as_deref()).await?;
        true
    } else {
        false
    };
    let cod = match (delivered, order) {
        (true, Some(order)) => cod_due(state, order).await?,
        _ => None,
    };
    let cod_payment_id = match cod {
        Some(due) => {
            ctx.require("customer_payment", "create")?;
            ctx.require("payment_allocation", "create")?;
            Some(record_cod(state, ctx, shipment, due).await?)
        }
        None => None,
    };
    let (proof_id, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "delivery_proof",
        json!({
            "shipment_ref": shipment,
            "outcome": body.outcome,
            "photo": body.photo,
            "signature": body.signature,
            "otp_verified": otp_verified,
            "received_by": body.received_by.as_deref().map(str::trim),
            "captured_at": Utc::now(),
            "latitude": body.latitude,
            "longitude": body.longitude,
        }),
    )
    .await?;
    let next = OUTCOMES
        .into_iter()
        .find(|o| *o == body.outcome)
        .unwrap_or("failed_attempt");
    move_to(state, shipment, next, ctx.user_id).await?;
    if delivered {
        sqlx::query("DELETE FROM shipment_delivery_otp WHERE shipment_id = $1")
            .bind(shipment)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(ProofRecorded {
        proof_id,
        shipment_id: shipment,
        status: next.to_owned(),
        otp_verified,
        cod_payment_id,
    })
}

// ── Routes ───────────────────────────────────────────────────────────────────

/// Out for delivery
///
/// The shipment's driver starts the delivery; with delivery codes on, the
/// customer is texted a code.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/shipments/{id}/out-for-delivery",
    operation_id = "fulfilment_shipment_out_for_delivery",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The shipment")),
    responses(
        (status = 200, description = "Out for delivery", body = OutForDelivery),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks delivery_proof.create or is not the shipment's driver", body = ErrorResponse),
        (status = 404, description = "No such shipment", body = ErrorResponse),
        (status = 409, description = "The shipment is already closed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_out_for_delivery(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DeliveryProofCreate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<OutForDelivery>, AppError> {
    out_for_delivery(&state, &ctx, id).await.map(Json)
}

/// Record delivery proof
///
/// The shipment's driver records delivered, a failed attempt or a refusal,
/// with photo, signature, the customer's code (when codes are on), who
/// received it and where. A delivery with cash on delivery records the
/// cash payment.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/shipments/{id}/proof",
    operation_id = "fulfilment_shipment_proof",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The shipment")),
    request_body = ProofBody,
    responses(
        (status = 200, description = "Recorded", body = ProofRecorded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks delivery_proof.create (or, for cash on delivery, customer_payment.create) or is not the shipment's driver", body = ErrorResponse),
        (status = 404, description = "No such shipment", body = ErrorResponse),
        (status = 409, description = "The shipment is already closed, or too many wrong codes", body = ErrorResponse),
        (status = 422, description = "A bad outcome or position, or a wrong or missing code", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Closed)])))),
)]
pub(crate) async fn post_proof(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DeliveryProofCreate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProofBody>,
) -> Result<Json<ProofRecorded>, AppError> {
    record_proof(&state, &ctx, id, &body).await.map(Json)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/fulfilment/shipments/{id}/out-for-delivery",
            post(post_out_for_delivery),
        )
        .route("/api/v1/fulfilment/shipments/{id}/proof", post(post_proof))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_out_for_delivery, post_proof),
    components(schemas(OutForDelivery, ProofBody, ProofRecorded))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_code_is_six_digits_and_hashed() {
        let shipment = Uuid::now_v7();
        let code = new_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let stored = hash_code(shipment, &code);
        assert_ne!(stored, code);
        assert!(code_matches(shipment, &code, &stored));
        assert!(code_matches(shipment, &format!(" {code} "), &stored));
        assert!(!code_matches(shipment, "000000x", &stored));
        // The same code for another shipment hashes differently.
        assert!(!code_matches(Uuid::now_v7(), &code, &stored));
    }

    #[test]
    fn delivery_proof_checks() {
        let body = |outcome: &str, lat: Option<f64>| ProofBody {
            outcome: outcome.to_owned(),
            photo: None,
            signature: None,
            otp: None,
            received_by: None,
            latitude: lat,
            longitude: None,
        };
        assert!(check_proof(&body("delivered", Some(24.7))).is_ok());
        assert!(check_proof(&body("lost", None)).is_err());
        assert!(check_proof(&body("refused", Some(91.0))).is_err());
    }
}

//! `/api/v1/einvoice`: devices and their onboarding (AG2-T3), for holders of
//! `einvoice.manage` (the billing pack grants it to Finance Manager).

use std::time::Duration;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, PaginatedResponse};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::device::{DeviceSummary, NewDevice};

/// `einvoice.manage`: may create and onboard e-invoicing devices.
#[derive(Debug)]
pub struct EinvoiceManage;

impl PrivilegeKey for EinvoiceManage {
    const KEY: &'static str = "einvoice.manage";
}

/// How long one ZATCA call may take during onboarding.
const ZATCA_TIMEOUT: Duration = Duration::from_secs(30);

/// List e-invoicing devices
///
/// The e-invoicing units (ZATCA devices) and whether each is onboarded. Holders of `einvoice.manage`.
#[utoipa::path(
    get,
    path = "/api/v1/einvoice/devices",
    tag = "einvoice",
    responses(
        (status = 200, description = "Every e-invoicing device (a handful), newest first", body = PaginatedResponse<DeviceSummary>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not manage e-invoicing", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_devices(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EinvoiceManage>>,
) -> Result<Json<PaginatedResponse<DeviceSummary>>, AppError> {
    let items = crate::device::list_devices(&state).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        page_size: total.max(1),
        items,
        total,
        page: 1,
        warnings: Vec::new(),
    }))
}

/// Add an e-invoicing device
///
/// A ZATCA e-invoicing unit, to be onboarded before it can sign invoices. Holders of
/// `einvoice.manage`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/einvoice/devices",
    tag = "einvoice",
    request_body = NewDevice,
    responses(
        (status = 200, description = "The new device, with its key and certificate request", body = DeviceSummary),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not manage e-invoicing", body = attome_types::ErrorResponse),
        (status = 409, description = "A device with this name exists", body = attome_types::ErrorResponse),
        (status = 422, description = "E-invoicing is off, the seller settings are incomplete, or a field is wrong", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_device(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EinvoiceManage>>,
    Json(body): Json<NewDevice>,
) -> Result<Json<DeviceSummary>, AppError> {
    Ok(Json(
        crate::device::create_device(&state, &ctx, &body).await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OnboardRequest {
    /// The one-time password the Fatoora portal shows.
    pub otp: String,
}

/// Onboard an e-invoicing device
///
/// Onboards the device with ZATCA using the one-time password the Fatoora portal shows, so it can
/// stamp invoices. Holders of `einvoice.manage`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/einvoice/devices/{id}/onboard",
    tag = "einvoice",
    params(("id" = Uuid, Path, description = "The device")),
    request_body = OnboardRequest,
    responses(
        (status = 200, description = "Onboarded: the device holds its production CSID", body = DeviceSummary),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not manage e-invoicing", body = attome_types::ErrorResponse),
        (status = 404, description = "No such device", body = attome_types::ErrorResponse),
        (status = 409, description = "The device is onboarded already, or changed meanwhile", body = attome_types::ErrorResponse),
        (status = 422, description = "A bad OTP, or ZATCA refused a step (the reason is kept on the device)", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_onboard(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EinvoiceManage>>,
    Path(id): Path<Uuid>,
    Json(body): Json<OnboardRequest>,
) -> Result<Json<DeviceSummary>, AppError> {
    let transport = crate::zatca::api::HttpTransport::new(ZATCA_TIMEOUT)
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(
        crate::device::onboard(&state, &ctx, id, &body.otp, &transport).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_devices, post_device, post_onboard),
    components(schemas(DeviceSummary, NewDevice, OnboardRequest))
)]
pub(crate) struct ApiDocFragment;

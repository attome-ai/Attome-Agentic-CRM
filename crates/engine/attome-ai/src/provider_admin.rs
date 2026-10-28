//! The two bespoke AI-provider routes: set/rotate a provider's API key, and
//! list the models that provider offers.
//!
//! Both are thin (guidelines §12): parse, call the owning module, shape the
//! response. Everything else about a provider — creating one, editing its
//! Provider ID, Display name, Base URL or API protocol, listing them — is
//! ordinary generic CRUD on `ai_provider` and gets no handler here
//! (guidelines §9: no per-entity CRUD for what the generic engine expresses).
//!
//! Neither route writes an `ai_model` row. An operator picks from the
//! fetched list and creates catalog rows through the generic entity API, which
//! lands them at `approval_status = "pending"` under the existing D-435/D-491
//! gate.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;
// `Authorized::require(entity, action)` — the same resource/action check every
// other admin handler in this workspace uses (guidelines §7).
use attome_security::SecurityContextExt;

use crate::provider::{self, ApiProtocol, ENTITY};
use crate::provider_credential;
use crate::provider_models::{self, DiscoveredModel};

/// Bounds what an operator can paste into the key field. Generous enough for
/// any real provider key and any signed gateway token, small enough that the
/// body limit is not the only thing standing between a paste accident and the
/// encryption path.
const MAX_CREDENTIAL_LEN: usize = 8 * 1024;

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCredentialBody {
    /// The provider's API key. Write-only: no route ever returns it, and the
    /// response carries only its last four characters.
    pub api_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SetCredentialResponse {
    pub provider_id: Uuid,
    /// Q18-T6: a key is stored. The key itself, or any part of it, is never
    /// returned.
    pub is_set: bool,
    /// When the stored key was set.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FetchModelsResponse {
    pub provider_id: Uuid,
    /// The protocol the listing was performed under, echoed so a UI can label
    /// results that arrived before an operator changed the field.
    pub api_protocol: String,
    pub models: Vec<DiscoveredModel>,
}

/// Loads the provider and checks the caller may act on it.
///
/// `"update"` for both routes, not `"read"` for the fetch: listing a
/// provider's models spends the operator's quota with that third party and
/// sends this deployment's credential to it. That is not a read.
async fn authorized_provider(
    state: &EngineState,
    ctx: &Authorized<Privilege<area::Ai>>,
    id: Uuid,
) -> Result<provider::ProviderRow, AppError> {
    let row = provider::load(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    ctx.require(ENTITY, "update")?;
    Ok(row)
}

/// Set an AI provider's API key
///
/// Sets or replaces the provider's API key, stored encrypted and never returned. AI administrators
/// only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/providers/{id}/credential",
    tag = "admin-ai-providers",
    params(("id" = Uuid, Path, description = "The `ai_provider` record")),
    request_body = SetCredentialBody,
    responses(
        (status = 200, description = "Success", body = SetCredentialResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "A rotation for this provider is already in progress", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(
        attome_audit::AuditCategory::Credential,
        attome_audit::AuditOperation::Update,
    )])))),
)]
async fn set_credential(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
    Json(body): Json<SetCredentialBody>,
) -> Result<Json<SetCredentialResponse>, AppError> {
    let api_key = body.api_key.trim().to_string();
    if api_key.is_empty() {
        return Err(AppError::Validation("api_key must not be empty".into()));
    }
    if api_key.len() > MAX_CREDENTIAL_LEN {
        return Err(AppError::Validation(format!(
            "api_key must be at most {MAX_CREDENTIAL_LEN} bytes"
        )));
    }
    let row = authorized_provider(&state, &ctx, id).await?;

    let ring = state.base.secrets.load().ai_provider_credential_key.clone();

    // The credential write and its audit event share one transaction (D-542):
    // a rotation that is not in the audit trail, or an audit entry for a
    // rotation that rolled back, are both worse than a failed request.
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Credential,
        attome_audit::AuditOperation::Update,
        ctx.user_id,
        ENTITY,
        Some(id),
    )
    .named("ai_provider.credential.rotate")
    .comment(format!(
        "provider {}",
        row.provider_id.as_deref().unwrap_or("(no provider_id)")
    ));
    let mut audited = attome_audit::security::SecurityTx::begin(&state, event).await?;

    // D-351 two-argument form under this crate's own namespace: serializes
    // concurrent rotations for one provider so `rotate`'s "supersede, then
    // insert" pair cannot interleave and leave two live credential rows.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-ai/provider-credential:{id}"))
        .fetch_one(audited.tx().as_mut())
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another credential rotation for this provider is already in progress",
        ));
    }

    let credential_id = provider_credential::rotate(audited.tx(), &ring, id, &api_key).await?;
    audited.commit().await?;

    // Pointing the record at the new credential is a separate, generic-engine
    // write (D-425) rather than raw SQL in this handler. It is deliberately
    // after the commit: the credential row is the source of truth, and a
    // failure here leaves a stored-but-unreferenced credential (recoverable by
    // retrying) rather than a reference to a credential that was rolled back.
    attome_records::entity_crud::update_record_for(
        &state,
        &ctx,
        ctx.user_id,
        ENTITY,
        id,
        row.row_version,
        json!({ "credential_ref": credential_id.to_string() }),
    )
    .await?;

    let meta = provider_credential::meta(&state.base.db, &credential_id.to_string())
        .await?
        .ok_or_else(|| AppError::internal("the just-rotated provider credential vanished"))?;

    Ok(Json(SetCredentialResponse {
        provider_id: id,
        is_set: true,
        updated_at: meta.created_at,
    }))
}

/// Fetch an AI provider's models
///
/// Asks the provider for the models it offers, with the provider's own credential, and returns the
/// list; it writes no catalogue rows (an operator adds the ones wanted, which then wait for
/// approval). Needs update rights on the provider, since it spends the operator's quota. AI
/// administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/providers/{id}/models/fetch",
    tag = "admin-ai-providers",
    params(("id" = Uuid, Path, description = "The `ai_provider` record")),
    responses(
        (status = 200, description = "Success", body = FetchModelsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 422, description = "The provider is misconfigured, or refused the listing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    // D-542 rule 2: a reviewed exemption, not a declared event. This is a
    // POST because it has side effects a GET must not have (outbound egress,
    // and it spends the operator's quota with the provider) — but it changes
    // no persistent state, which is exactly what `ReadOnly` covers. Declaring
    // an `Ai` event instead would derive `policy: mandatory` and oblige an
    // emission this handler has no transaction to write in.
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "lists the models an already-configured provider offers; writes no row, creates no ai_model catalog entry, and changes no credential — the operator authors catalog rows afterwards through the audited generic entity API",
    )))),
)]
async fn fetch_models(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<Json<FetchModelsResponse>, AppError> {
    let row = authorized_provider(&state, &ctx, id).await?;

    let raw_protocol = row.api_protocol.as_deref().unwrap_or("").trim().to_string();
    let Some(protocol) = ApiProtocol::parse(&raw_protocol) else {
        // Never guess: the protocol decides which header carries the key, so a
        // default would hand the operator's credential to a provider in a
        // header it never asked for.
        return Err(AppError::Validation(format!(
            "This provider's API protocol is not set to one of: {}",
            ApiProtocol::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };

    let base_url = row.endpoint_url.as_deref().unwrap_or("");
    let ring = state.base.secrets.load().ai_provider_credential_key.clone();
    let api_key =
        provider_credential::resolve(&state.base.db, &ring, row.credential_ref.as_deref()).await?;

    let models = provider_models::fetch(
        base_url,
        protocol,
        api_key.as_deref(),
        &state.base.config.inference,
        row.allow_external_endpoint.unwrap_or(false),
    )
    .await?;

    tracing::info!(
        provider = %id,
        protocol = protocol.as_str(),
        count = models.len(),
        "listed an AI provider's available models"
    );

    Ok(Json(FetchModelsResponse {
        provider_id: id,
        api_protocol: protocol.as_str().to_string(),
        models,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/ai/providers/{id}/credential",
            post(set_credential),
        )
        .route(
            "/api/v1/admin/ai/providers/{id}/models/fetch",
            post(fetch_models),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(set_credential, fetch_models),
    components(schemas(
        SetCredentialBody,
        SetCredentialResponse,
        FetchModelsResponse,
        DiscoveredModel,
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

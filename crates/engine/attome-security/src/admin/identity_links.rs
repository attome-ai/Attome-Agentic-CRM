//! Federated identity pre-provisioning (P-federation-linking-policy §4.3(b)).
//! Lets an admin bind a (provider_key, provider_sub) pair to an existing
//! user_ref BEFORE that user's first SSO login — the bulk-onboarding
//! primitive for a workforce cutover onto SSO without relying on
//! email-based JIT-linking at all. That JIT path is now gated by default
//! (`attome_security::accounts::reject_if_linking_would_bypass_existing_
//! credential`): an incoming federated login whose email collides with an
//! account that already has a password or a different-provider identity is
//! rejected outright, with no in-band way to complete the link itself — this
//! endpoint (and the session-gated self-service `/api/v1/auth/identity-link/
//! oidc/{provider}` routes, §4.3(a)) are the two ways such a link gets
//! created deliberately instead. system.admin-gated like every other
//! admin-surface mutation here (D-011) — pre-linking an identity to an
//! account is equivalent to deciding who may sign in as whom, exactly the
//! kind of decision this coarse gate exists for.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateIdentityLinkBody {
    provider_key: String,
    provider_sub: String,
    user_ref: Uuid,
}

#[derive(Serialize, ToSchema)]
pub struct IdentityLinkItem {
    provider_key: String,
    provider_sub: String,
    user_ref: Uuid,
}

impl std::fmt::Debug for IdentityLinkItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLinkItem").finish_non_exhaustive()
    }
}

/// Binds `(provider_key, provider_sub)` to `user_ref` via the same
/// `link_identity_to_user` primitive the session-gated self-service linking
/// callback uses (§4.3(a)/(b) share one write path) — idempotent if this
/// exact pair is already linked to this exact user, `Conflict` if linked to
/// a different one. The target account's *current* email is reused as the
/// link's display value; the user's actual first SSO login overwrites it via
/// `link_external_identity`'s existing `(provider_key, sub)`-is-authoritative
/// branch regardless (`accounts.rs`), so nothing here needs to be kept in
/// sync with whatever the IdP will eventually assert.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/identity-links",
    tag = "admin-security",
    request_body = CreateIdentityLinkBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = IdentityLinkItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_identity_link(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateIdentityLinkBody>,
) -> Result<(StatusCode, Json<IdentityLinkItem>), AppError> {
    let provider_key = body.provider_key.trim();
    let provider_sub = body.provider_sub.trim();
    if provider_key.is_empty() || provider_sub.is_empty() {
        return Err(AppError::Validation(
            "provider_key and provider_sub are required".into(),
        ));
    }

    let email: Option<String> = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(body.user_ref)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let email = email.ok_or(AppError::NotFound)?;

    // Audit plan 3.4 / 3.6: the mandatory event is written by a hook inside
    // `link_identity_to_user_with`'s transaction, so the link and its event
    // commit together (D-062).
    let event_name = format!("identity_link:{provider_key}");
    let admin_id = ctx.user_id;
    let hook = attome_audit::security::AuditHook::new(
        attome_audit::audit_service(&state),
        move |linked: &uuid::Uuid| {
            vec![attome_audit::security::HookEvent::Security(
                attome_audit::security::SecurityEvent::new(
                    attome_audit::security::MandatoryCategory::Credential,
                    AuditOperation::Create,
                    admin_id,
                    "user_identity",
                    Some(*linked),
                )
                .named(event_name.clone()),
            )]
        },
    );
    crate::accounts::link_identity_to_user_with(
        &state.base.db,
        body.user_ref,
        provider_key,
        provider_sub,
        &email,
        &hook,
    )
    .await?;

    tracing::info!(
        provider_key = %provider_key,
        user_ref = %body.user_ref,
        admin_id = %ctx.user_id,
        "admin pre-provisioned a federated identity link"
    );

    Ok((
        StatusCode::CREATED,
        Json(IdentityLinkItem {
            provider_key: provider_key.to_string(),
            provider_sub: provider_sub.to_string(),
            user_ref: body.user_ref,
        }),
    ))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/identity-links",
        axum::routing::post(create_identity_link),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_identity_link))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

//! P-key-rotation-and-jwt (b) — the admin trigger for
//! `EngineJob::RewrapSecrets`. A dedicated route (guidelines §9: this isn't
//! CRUD on a registered entity), gated on `system.admin` the same way
//! `s2s_admin`/`license_admin`/`erasure_admin` are.
//!
//! Enqueues, never runs the rewrap inline — a large table's full convergence
//! can take a while (guidelines §10: no long-running work on the request
//! thread), and the advisory lock below is what makes triggering the same
//! domain twice concurrently a `Conflict` instead of two workers racing each
//! other's `row_version` writes.

use attome_core::EngineState;
use attome_core::jobs::{EngineJob, RewrapDomain};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// `attome-jobs`'s `RewrapDomain` rewrap — the four-eyes `action_type` for
/// `trigger_rewrap` below. Namespaced `"{domain}.{action}"` by convention
/// only — `attome_approval` itself treats every `action_type` as an opaque
/// string (guidelines §1: it has zero `xrm-*` knowledge). Declared here
/// rather than in `attome-api::approval_admin` since ARCH-5, matching how
/// every other gated flow declares its own constant; `attome-api` imports
/// it for `execute_approved` and `KNOWN_ACTION_TYPES`.
pub const ACTION_SECURITY_REWRAP: &str = "security.rewrap";

#[derive(Serialize, ToSchema)]
struct RewrapTriggered {
    domain: String,
    enqueued: bool,
    /// D-195 / P-four-eyes-approval — `true` when `approval.required_actions`
    /// (attome-config) names `ACTION_SECURITY_REWRAP`:
    /// this call did NOT enqueue the rewrap, it only submitted an approval
    /// request. A second `system.admin` (never the same user) must decide it
    /// via `POST /api/v1/admin/approvals/{id}/decide` before it actually runs.
    approval_pending: bool,
    approval_request_id: Option<Uuid>,
}

/// The actual advisory-locked enqueue, factored out of the handler so
/// `approval_admin::execute_approved` can call the exact same path once a
/// gated request is approved — one execution path per action (D-195's design
/// goal), never a duplicated "approved" branch that could drift from the
/// direct-call path.
///
/// `actor_id` is the admin who triggered it, or the approving admin on the
/// four-eyes path. The `Credential` + `Rotate` event is written in the same
/// transaction as the enqueue (D-541 rule 4, D-062).
pub async fn do_trigger_rewrap(
    state: &EngineState,
    domain: RewrapDomain,
    actor_id: uuid::Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Namespace is `attome-auth`'s, not this crate's: the key lives under the
    // `"attome-auth/…"` prefix and `crates/server`'s rewrap job takes the same
    // key on its own session, so both sides must name the same namespace or
    // the two locks would stop conflicting (L-1 / TODO-027).
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_auth::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-auth/rewrap:{domain}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a rewrap for this domain is already in progress",
        ));
    }
    // This transaction lock is an early conflict response for an already
    // running worker. The worker independently holds the same key on a
    // dedicated session for the complete rewrap; that is the authoritative
    // concurrency boundary.
    //
    // P-job-queue-hardening (D-165): the advisory lock above only rejects a
    // second trigger once the first job has actually started running (the
    // worker holds the lock on its own dedicated session while processing).
    // It does not stop two admin clicks in quick succession, before either
    // job starts, from both landing rows in the queue — the dedup key
    // closes that narrower window at the row level.
    //
    // PLATFORM-REVIEW-2026-08-24 §3.12: the enqueue happens INSIDE the
    // lock-holding transaction, not after its commit — so the "no worker
    // holds this domain" check and the queue-row insert are one atomic
    // step. A lost lock (the `Conflict` above) rolls the transaction back
    // with no job row ever written, and the job row only becomes visible
    // — to a worker, or to a second trigger's dedup probe — at the same
    // commit that releases the lock.
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        EngineJob::RewrapSecrets { domain },
        &format!("rewrap:{domain}"),
    )
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            attome_audit::AuditOperation::Rotate,
            actor_id,
            "base_secret_rewrap",
            None,
        )
        .named(format!("rewrap:{domain}")),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(())
}

/// `POST /api/v1/admin/security/rewrap/{domain}` — `system.admin` only.
/// `domain` is one of `"mfa"`/`"s2s"`/`"erasure"` (see `EngineJob::RewrapSecrets`'s
/// doc for what each covers). Advisory-locked per domain (guidelines §2 Layer 2)
/// so a second trigger while one is still running is rejected with `Conflict`
/// rather than enqueuing a redundant concurrent pass.
///
/// D-195: gated behind `approval.required_actions` (empty/off by default —
/// see `attome_audit::approval::gate`'s doc comment). When gated, this
/// submits an approval request instead of enqueuing anything and returns
/// `202` with `approval_pending: true`; the rewrap only actually enqueues
/// once a second, different `system.admin` approves it (`approval_admin.rs`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/rewrap/{domain}",
    tag = "admin-security",
    params(("domain" = String, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, attome_audit::AuditOperation::Rotate)])))),
    responses(
        (status = 201, description = "Success", body = RewrapTriggered),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trigger_rewrap(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(domain): Path<String>,
) -> Result<(StatusCode, Json<RewrapTriggered>), AppError> {
    let domain = domain
        .parse::<RewrapDomain>()
        .map_err(|message| AppError::Validation(format!("{message}; got {domain:?}")))?;

    if let Some(request) = attome_audit::approval::gate(
        &state,
        ACTION_SECURITY_REWRAP,
        serde_json::json!({ "domain": domain.to_string() }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(RewrapTriggered {
                domain: domain.to_string(),
                enqueued: false,
                approval_pending: true,
                approval_request_id: Some(request.id),
            }),
        ));
    }

    do_trigger_rewrap(&state, domain, ctx.user_id).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RewrapTriggered {
            domain: domain.to_string(),
            enqueued: true,
            approval_pending: false,
            approval_request_id: None,
        }),
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/rewrap/{domain}",
        post(trigger_rewrap),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(trigger_rewrap))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

//! D-442 / M58 Phase 1 (Digital Signature, internal sign-off, core only) —
//! `GET /api/v1/signoff/{decision_id}/verify`. `decision_id` is one
//! `approval_grant` row's own id (not the parent
//! `approval_request`'s id — one request can carry several
//! decisions across a D-421 plan's steps, each with its own grant row and
//! its own digest).
//!
//! `attome_audit::signoff::record_decision_digest` (called from this crate's
//! `approval_admin::decide_approval`, right after the decision itself is
//! recorded) is what *writes* the digest this endpoint checks; see that
//! module's doc comment for what the digest covers and what it does not.
//!
//! This handler runs two independent checks and reports both rather than
//! collapsing them into one boolean, because they catch different tamper
//! shapes:
//!
//! - **Digest match** — recomputes the digest from the grant row's *current*
//!   state (plus the parent request's current `payload`) and compares it to
//!   what `record_decision_digest` stored on `approval_grant.
//!   signature` at decision time. A mismatch means the decision (or its
//!   linked document reference) was changed since it was recorded — the
//!   headline tamper case this whole feature exists to catch. Always
//!   available immediately; does not depend on the audit chain having caught
//!   up.
//! - **Chain row check** — `attome_audit::signoff::decision_chain_evidence`
//!   resolves the `DecisionDigest` audit event and checks its header row's own
//!   `event_hash`/signature with `attome_audit::verify::verify_header_row` (no
//!   new comparison logic). Proves the digest *event itself* was not swapped
//!   for a different one at the header-row level. Four outcomes (audit 10/10
//!   plan item 1.7):
//!   - **checked** — exactly one header row: its hash and signature results;
//!   - **pending** — no header row yet, but the event is still in
//!     `audit_ingest` under `audit.chainer_enabled` (D-316's production
//!     default): both chain fields `null`, and never verified;
//!   - **missing** — the event is in neither table: `chain_row_hash_ok` is
//!     `false`;
//!   - **ambiguous** — more than one digest header for the decision:
//!     `chain_row_hash_ok` is `false`.
//!
//! `verified` is `true` only when a digest was recorded AND it matches AND the
//! chain row was checked and checks out clean AND the chain binds the
//! recomputed digest — never while the evidence is pending, missing or
//! ambiguous. The last condition closes register item A-2 for decisions
//! recorded under audit hash v2: the digest event's `event_name` carries the
//! digest and v2 hashes it, so rewriting a grant together with its stored
//! (unkeyed, publicly computable) digest no longer verifies. A decision whose
//! digest event is a hash-v1 row keeps its pre-v2 check.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct GrantRow {
    id: Uuid,
    request_id: Uuid,
    approver_id: Uuid,
    decision: String,
    decided_at: DateTime<Utc>,
    step: i32,
    signature: Option<serde_json::Value>,
}

#[derive(Serialize, ToSchema)]
struct SignoffVerifyResponse {
    decision_id: Uuid,
    request_id: Uuid,
    step: i32,
    decision: String,
    decided_by: Uuid,
    decided_at: DateTime<Utc>,
    /// Whether a digest was ever recorded for this decision at all — `false`
    /// for a decision made before this feature existed, or if
    /// `record_decision_digest` failed at decision time (logged, not fatal
    /// to the decide response — see its own doc comment).
    digest_recorded: bool,
    /// The digest recomputed from this decision's *current* stored state.
    recomputed_digest: String,
    /// Recomputed vs. what was stored at decision time. `false` whenever
    /// `digest_recorded` is `false` too (nothing to match against).
    digest_matches: bool,
    /// `None` only while the `DecisionDigest` audit event is pending: still in
    /// `audit_ingest`, not yet chained into `audit_header` (see this
    /// module's doc comment). `false` when the event is missing from both
    /// tables, when more than one digest header exists for the decision, or
    /// when the header row's hash does not recompute.
    chain_row_hash_ok: Option<bool>,
    /// `None` while pending, or when the header row is covered by its chain
    /// batch's signature instead of its own. `false` when the row's signature
    /// does not verify, or when an unsigned row has nothing verifiable
    /// covering it once audit signing is configured.
    chain_row_signature_ok: Option<bool>,
    /// `true` only when a digest was recorded, it matches, and the chain row
    /// was checked and checks out clean. Never `true` while the audit
    /// evidence is pending, missing or ambiguous.
    verified: bool,
}

/// `GET /api/v1/signoff/{decision_id}/verify` — `system.admin` only, same
/// gate as the rest of the approval admin surface this sits beside.
#[utoipa::path(
    get,
    path = "/api/v1/signoff/{decision_id}/verify",
    tag = "admin",
    params(("decision_id" = Uuid, Path, description = "approval_grant.id")),
    responses(
        (status = 200, description = "Success", body = SignoffVerifyResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such decision", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn verify_decision(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(decision_id): Path<Uuid>,
) -> Result<Json<SignoffVerifyResponse>, AppError> {
    let grant: GrantRow = sqlx::query_as(
        "SELECT id, request_id, approver_id, decision, decided_at, step, signature \
         FROM approval_grant WHERE id = $1",
    )
    .bind(decision_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    // Re-derive the document hash from the *current* state of the parent
    // request's payload, same convention `record_decision_digest` used when
    // it first computed this digest — a payload edited since decision time
    // (were that ever possible through this crate's own API, which it is
    // not) would also show up as a mismatch here.
    let request = attome_approval::get(&state.base.db, grant.request_id).await?;
    let document_hash = request
        .payload
        .get("document_hash")
        .and_then(|v| v.as_str());

    let recomputed_digest = attome_audit::signoff::compute_decision_digest(
        grant.request_id,
        grant.step,
        &grant.decision,
        grant.approver_id,
        grant.decided_at,
        document_hash,
    );

    let stored_digest = grant
        .signature
        .as_ref()
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.as_str());
    let digest_recorded = stored_digest.is_some();
    let digest_matches = stored_digest == Some(recomputed_digest.as_str());

    let chain = attome_audit::signoff::decision_chain_evidence(
        &state.base.db,
        state.audit_signer.as_deref(),
        decision_id,
    )
    .await?;
    // A-2: the digest must also be the one the signed chain binds. For a
    // hash-v2 digest event that is the digest its hashed `event_name` carries,
    // so a grant rewritten together with its recomputed stored digest fails.
    let verified = digest_recorded
        && digest_matches
        && chain.is_verified()
        && chain.binds_digest(&recomputed_digest);

    Ok(Json(SignoffVerifyResponse {
        decision_id: grant.id,
        request_id: grant.request_id,
        step: grant.step,
        decision: grant.decision,
        decided_by: grant.approver_id,
        decided_at: grant.decided_at,
        digest_recorded,
        recomputed_digest,
        digest_matches,
        chain_row_hash_ok: chain.hash_ok,
        chain_row_signature_ok: chain.signature_ok,
        verified,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/signoff/{decision_id}/verify", get(verify_decision))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, same shape as `approval_admin`'s own fragment.
#[derive(utoipa::OpenApi)]
#[openapi(paths(verify_decision))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

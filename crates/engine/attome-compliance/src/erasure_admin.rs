//! D-107 (P-data-lifecycle item (d)'s erasure ruling) — the admin action that
//! destroys a record's crypto-shredding key (`audit_erasure_key`, migration
//! 0039). Irreversible: once destroyed, every `audit_detail`/
//! `audit_snapshot` value ever encrypted under that key is permanently
//! unreadable — see `attome_audit::erasure`'s doc comment for the full design
//! and `document/ERASURE-OPTIONS-2026-07-21.md` for why this cannot break
//! chain verification.
//!
//! A dedicated route, not the generic entity dispatcher (guidelines §9):
//! this isn't CRUD on a registered entity, it's a one-way destructive action
//! against `audit_erasure_key`, gated on `system.admin` the same way
//! `s2s_admin`/`license_admin` are.
//!
//! **D-195/P-four-eyes-approval §5 step 9's open design question, resolved:**
//! erasure fits the same gate/`do_*` model every other wired action uses
//! unchanged. The concern was that a *pending, reversible* approval request
//! seemed like a poor fit for an action whose whole point is
//! irreversibility — but that conflates the request with its execution. A
//! submitted erasure request is exactly as reversible as any other pending
//! request (rejectable, expirable, cancelable — none of that touches
//! `audit_erasure_key`); only `do_erase_record`'s actual key destruction is
//! irreversible, and that already only ever ran once, at the moment one
//! admin called this endpoint — gating just moves that one moment behind a
//! second, distinct admin's decision instead of the first admin's own
//! request. No different, in that respect, from key rotation
//! (`security.rewrap`) or license import, both already wired.

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService};
use attome_core::EngineState;
use attome_metadata::provision::valid_identifier;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// D-195/P-four-eyes-approval §5 step 9.
pub const ACTION_SECURITY_ERASURE: &str = "security.erasure";

#[derive(Serialize)]
pub struct ErasureResult {
    record_id: Uuid,
    entity_name: String,
    /// Whether a live key existed and was destroyed by this call. `false`
    /// means the record never had any crypto-shredded audit history (nothing
    /// to destroy) — not an error, since requesting erasure for a record
    /// with no protected history is a legitimate no-op.
    key_destroyed: bool,
    /// R2-T2: the erasure certificate: what was erased, when and by whom,
    /// its SHA-256 digest, and the deployment's audit signature over that
    /// digest when an audit signing key is configured.
    certificate: Value,
}

impl std::fmt::Debug for ErasureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureResult").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct ErasurePending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

/// `POST /api/v1/admin/security/erasure/{logicalname}/{record_id}` —
/// `system.admin` only. Destroys `record_id`'s crypto-shredding key (if one
/// exists) and appends one audit event (`AuditOperation::Erasure`, no
/// `changed_fields`) recording that the erasure happened, by whom, and when
/// — through the same hash-chained `AuditService` path as every other audit
/// event, so the erasure action itself is exactly as tamper-evident as
/// anything else in the ledger.
///
/// Idempotent: erasing an already-erased (or never-protected) record returns
/// 200 with `key_destroyed: false/true` reflecting what THIS call actually
/// changed, never an error — a retried erasure request must not fail.
///
/// D-195: gated behind `approval.required_actions` (empty/off by default,
/// same opt-in shape as every other wired action). When gated, submits an
/// approval request for `{logicalname, record_id}` instead of destroying
/// anything and returns `202` with `approval_pending: true` — see this
/// module's doc comment for why a pending erasure request is exactly as
/// reversible as any other despite the underlying action's own
/// irreversibility.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/erasure/{logicalname}/{record_id}",
    tag = "admin-security",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Erasure)])))),
    params(
        ("logicalname" = String, Path, description = "The entity's logical name"),
        ("record_id" = Uuid, Path, description = "The record"),
    ),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn erase_record(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path((logicalname, record_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    if !valid_identifier(&logicalname) {
        return Err(AppError::Validation(format!(
            "invalid entity logicalname: {logicalname}"
        )));
    }

    if let Some(request) = attome_audit::approval::gate(
        &state,
        ACTION_SECURITY_ERASURE,
        serde_json::json!({ "logicalname": logicalname, "record_id": record_id }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(ErasurePending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let result = do_erase_record(&state, ctx.user_id, logicalname, record_id).await?;
    Ok(Json(result).into_response())
}

/// The real mutation, factored out so `erase_record` (the direct, un-gated
/// path) and `approval_admin::execute_approved` (the approved-and-executed
/// path) call the exact same code — one execution path per action, same
/// convention as every other wired flow.
/// L7-T6: the change event an erasure writes.
pub const ERASED_EVENT: &str = "record.erased";

pub async fn do_erase_record(
    state: &EngineState,
    actor_id: Uuid,
    logicalname: String,
    record_id: Uuid,
) -> Result<ErasureResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Advisory lock (guidelines §2 Layer 2) — non-blocking, same primitive
    // as every other mutating admin action in this codebase. Namespaced per
    // record so concurrent erasure requests for different records never
    // contend, and a retried request for the same record is simply
    // serialized rather than racing itself.
    // `attome-audit`'s namespace, not this crate's — the key lives under the
    // `"attome-audit/…"` prefix (L-1 / TODO-027).
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_audit::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/erasure:{record_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another erasure request for this record is already in progress",
        ));
    }

    let key_destroyed =
        attome_audit::destroy_key(&mut tx, &logicalname, record_id, actor_id).await?;
    // D-788 rule 9 (design §8.2): the record's values in the 30-day recovery
    // archive go with it, in the same transaction.
    let archived_erased =
        attome_core::recovery_archive::erase_record(&mut tx, &logicalname, record_id).await?;
    if archived_erased > 0 {
        tracing::info!(record_id = %record_id, archived_erased, "erasure: recovery-archive values deleted");
    }
    // Solution 7 Phase 2 design §9.3: the record's sealed release-report
    // conflict values and its baseline rows go too, in the same transaction.
    let report_erased =
        attome_core::release_report::erase_record(&mut tx, &logicalname, record_id).await?;
    if report_erased > 0 {
        tracing::info!(record_id = %record_id, report_erased, "erasure: release-report conflict items deleted");
    }
    // M3-T4: workflow step payloads that mention the record go too.
    let payloads_erased = attome_core::run_payload::erase_record(&mut tx, record_id).await?;
    if payloads_erased > 0 {
        tracing::info!(record_id = %record_id, payloads_erased, "erasure: workflow step payloads cleared");
    }

    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, actor_id).await;

    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());

    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some(logicalname.clone()),
        record_id: Some(record_id),
        operation: AuditOperation::Erasure,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("erasure".to_string()),
        event_comment: Some(format!(
            "crypto-shredding key destroyed for {logicalname}/{record_id} (D-107)"
        )),
        // Deliberately empty: there is nothing left to encrypt (the key is
        // already destroyed above) and nothing to reveal — this event
        // itself needs no key, so write_in_tx's erasure guard
        // (`encrypt_event_in_place`'s empty-changed-fields-and-no-snapshot
        // check) skips re-provisioning a key for a record whose data was
        // just intentionally shredded.
        changed_fields: vec![],
        snapshot_json: None,
    };

    audit_service.write_in_tx(&mut tx, event).await?;
    // L7-T6: consumers holding a copy erase it too (a purge; the event names
    // the entity and id only, never a value).
    attome_core::change_feed::emit_named(
        &mut tx,
        &logicalname,
        record_id,
        attome_core::change_feed::ChangeOperation::Purge,
        ERASED_EVENT,
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;
    // R2-T1: outside the database, so a restore cannot bring it back.
    attome_audit::erasure_ledger::record_or_log(
        &state.base.storage,
        &attome_audit::erasure_ledger::LedgerEntry {
            kind: attome_audit::erasure_ledger::ErasureKind::Erasure,
            entity: logicalname.clone(),
            record_id,
        },
    )
    .await;

    let certificate = erasure_certificate(
        state,
        &logicalname,
        record_id,
        actor_id,
        key_destroyed,
        &json!({
            "archive_values": archived_erased,
            "release_report_items": report_erased,
            "workflow_payloads": payloads_erased,
        }),
    );
    Ok(ErasureResult {
        record_id,
        entity_name: logicalname,
        key_destroyed,
        certificate,
    })
}

/// R2-T2: a certificate of one erasure. The digest covers the canonical
/// JSON of everything above it; the signature, when the deployment signs its
/// audit chain, is that key's signature over the digest.
fn erasure_certificate(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    actor_id: Uuid,
    key_destroyed: bool,
    erased: &Value,
) -> Value {
    use sha2::{Digest, Sha256};
    let body = json!({
        "kind": "erasure",
        "entity": entity,
        "record_id": record_id,
        "erased_at": chrono::Utc::now().to_rfc3339(),
        "erased_by": actor_id,
        "audit_key_destroyed": key_destroyed,
        "erased": erased,
    });
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&body).unwrap_or_default())
    );
    let signature = state.audit_signer.as_ref().map(
        |signer| json!({"key_id": signer.key_id, "signature": signer.sign("erasure", &digest)}),
    );
    json!({ "body": body, "sha256": digest, "signature": signature })
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/erasure/{logicalname}/{record_id}",
        post(erase_record),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(erase_record))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

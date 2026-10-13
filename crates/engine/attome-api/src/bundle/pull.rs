//! Pull-by-reference: fetch a signed `attome-bundle/v1` artifact named by
//! `deployment.bundle_ref`, Ed25519-verify it against
//! `deployment.bundle_signing_public_key`, and hand it to the same plan/apply
//! path the admin import route uses (P-environment-promotion §4 "Target
//! operating model: source-driven, pull not push" / §5 step 23).
//!
//! This is the F273 `APP_VERTICAL` vertical-seed loader, generalized: instead
//! of a hard-coded loader keyed on an env var, a deployment declares a
//! reference to a bundle and a public key in config, and the same mechanism
//! that already applies an operator-pushed bundle
//! (`POST /api/v1/admin/metadata/import`) plans and — subject to approval on
//! a production profile — applies it. [`sync`] is called from two places:
//! `EngineSystem::build()` at first boot only (never on a restart that has
//! already applied something — see that call site's guard), and the admin
//! route `POST /api/v1/admin/metadata/sync` for an operator-triggered
//! re-check.
//!
//! **The signed artifact.** `{ "bundle": <canonical bundle JSON>, "signature":
//! "<base64 Ed25519 over the canonical bundle bytes>" }`. The signature is
//! verified over this binary's own re-canonicalization of the parsed
//! `bundle` field (`canonical::canonical_json`), not over the artifact's raw
//! bytes as transmitted — so whitespace/key-order in the artifact file never
//! matters, only the bundle's actual content does, matching what
//! `bundle-tool` (or any signer) computed before signing. An unparseable
//! bundle, a bundle declaring the wrong `format`, or a signature that does
//! not verify is refused before any plan is computed — this module never
//! hands an unverified bundle to `plan_bundle`/`ledger::insert_plan`.
//!
//! **Never apply an unverified bundle.** [`fetch_and_verify`] is the only
//! function in this file that reads network/filesystem bytes; every other
//! caller only ever sees a [`Bundle`] that has already verified.

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::canonical::canonical_json;
use super::export::PLATFORM_VERSION;
use super::ledger;
use super::model::{BUNDLE_FORMAT, Bundle, check_format};
use super::plan::{PlanAction, PlanOptions, plan_bundle};
use super::routes::apply_with_gate;

/// Bounded like every other outbound network call this platform makes
/// (guidelines §10) — an unreachable/slow `https://` reference must not hang
/// boot or an admin request indefinitely.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The wire shape `deployment.bundle_ref` must point to.
#[derive(Deserialize)]
struct SignedArtifact {
    bundle: serde_json::Value,
    signature: String,
}

/// Fetches and Ed25519-verifies the bundle named by `deployment.bundle_ref`.
/// `Ok(None)` when neither config field is set (config loading already
/// refuses one without the other — `AppConfig::validate` — so in practice
/// this is "both set" or "neither"). `Err(AppError::Validation)` for every
/// failure short of success: unreachable reference, malformed artifact,
/// wrong bundle format, or a signature that does not verify — the exact
/// reason is in the message, but this function never distinguishes "refused"
/// from "unreachable" in its return *type*, because both mean the same thing
/// to every caller: do not apply anything.
pub async fn fetch_and_verify(state: &EngineState) -> Result<Option<Bundle>, AppError> {
    let cfg = &state.base.config.deployment;
    let (Some(bundle_ref), Some(public_key_b64)) = (
        cfg.bundle_ref.as_deref(),
        cfg.bundle_signing_public_key.as_deref(),
    ) else {
        return Ok(None);
    };

    let raw = fetch_bytes(bundle_ref).await?;
    let artifact: SignedArtifact = serde_json::from_slice(&raw).map_err(|e| {
        AppError::Validation(format!(
            "deployment.bundle_ref {bundle_ref:?}: not a signed bundle artifact \
             ({{\"bundle\", \"signature\"}} JSON): {e}"
        ))
    })?;

    let mut bundle: Bundle = serde_json::from_value(artifact.bundle).map_err(|e| {
        AppError::Validation(format!(
            "deployment.bundle_ref {bundle_ref:?}: \"bundle\" does not parse as \
             {BUNDLE_FORMAT}: {e}"
        ))
    })?;
    check_format(&bundle.format).map_err(|e| AppError::Validation(e.to_string()))?;
    bundle.normalize();

    let canonical = canonical_json(&bundle);
    verify_ed25519(public_key_b64, &canonical, &artifact.signature).map_err(|reason| {
        AppError::Validation(format!(
            "deployment.bundle_ref {bundle_ref:?}: signature does not verify against \
             deployment.bundle_signing_public_key ({reason}) — refusing to apply an \
             unverified bundle"
        ))
    })?;

    Ok(Some(bundle))
}

/// `https://` fetches over the network (bounded timeout); anything else is
/// read as a local file path via `tokio::fs` — the two forms
/// `deployment.bundle_ref`'s doc comment promises. Plain `http://` is
/// refused: a bundle artifact is verified by signature, not transport, but
/// accepting `http://` here would invite an operator to point a production
/// deployment at an unencrypted endpoint by habit.
async fn fetch_bytes(bundle_ref: &str) -> Result<Vec<u8>, AppError> {
    if let Some(scheme_rest) = bundle_ref.strip_prefix("http://") {
        let _ = scheme_rest;
        return Err(AppError::Validation(format!(
            "deployment.bundle_ref {bundle_ref:?}: only https:// or a local file path is \
             accepted, not plain http://"
        )));
    }
    if bundle_ref.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|e| AppError::internal(format!("building the bundle_ref http client: {e}")))?;
        let resp = client
            .get(bundle_ref)
            .send()
            .await
            .map_err(|e| AppError::Validation(format!("fetching {bundle_ref:?}: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::Validation(format!(
                "fetching {bundle_ref:?}: HTTP {}",
                resp.status()
            )));
        }
        return resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
            AppError::Validation(format!("reading response from {bundle_ref:?}: {e}"))
        });
    }
    tokio::fs::read(bundle_ref)
        .await
        .map_err(|e| AppError::Validation(format!("reading {bundle_ref:?}: {e}")))
}

/// Decodes both base64 values and verifies `signature_b64` over `payload`
/// with `public_key_b64` — same crate, same base64 engine, same key/
/// signature byte widths `attome-modules::verifier` uses, so a bundle signed
/// with the platform's ordinary Ed25519 tooling verifies here unchanged. The
/// error string never repeats the input bytes.
fn verify_ed25519(
    public_key_b64: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), &'static str> {
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|_| "bundle_signing_public_key is not valid base64")?
        .try_into()
        .map_err(|_| "bundle_signing_public_key is not 32 bytes")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "bundle_signing_public_key is not a valid Ed25519 key")?;

    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| "signature is not valid base64")?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;

    key.verify(payload, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| "signature mismatch")
}

// ── Sync: fetch → plan → (no-op | persist + apply) ─────────────────────────

/// What one [`sync`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// Neither `deployment.bundle_ref` nor `bundle_signing_public_key` is set.
    NotConfigured,
    /// The pulled bundle plans as all-noop against live metadata — nothing
    /// to apply.
    NoChange,
    /// The plan has blocked entries (e.g. a would-be retire — `sync` never
    /// sets `allow_retire`) and was left `planned` for a human to review
    /// through the ordinary `GET …/plans/{id}` / `POST …/import?mode=apply`
    /// path; `sync` does not retry it.
    Planned,
    /// The plan was queued directly (development profile, or `apply`
    /// unconditionally allowed).
    Queued,
    /// `metadata.bundle_apply` is required on this profile — a second
    /// `system.admin` must approve before the apply is queued.
    ApprovalPending,
}

/// The result of one [`sync`] call. `approval_pending` mirrors
/// `routes::ApplyAccepted`'s field of the same name/meaning byte for byte —
/// deliberately, so `bundle-tool`'s `render::approval_request_id` (written
/// against `ApplyAccepted`'s shape) recognizes this reply too with no
/// special-casing.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SyncOutcome {
    pub status: SyncStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<Uuid>,
    pub approval_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
}

/// Fetch → verify → plan → (no-op, or persist and apply through the same
/// gated path `POST …/import?mode=apply` uses). `actor` is the identity
/// recorded as `requested_by`/the approval requester — `None` (the boot
/// caller) records `Uuid::nil()`, the platform's established "no human
/// actor" convention (mirrors `bundle::apply`'s own deferred-contract path
/// and `retention.rs`'s approved-by fallback).
///
/// Never applies without going through [`apply_with_gate`] — on a
/// production-profile deployment that still means `metadata.bundle_apply`'s
/// mandatory approval; `sync` does not bypass it. `allow_retire` is always
/// `false`: a bundle that would retire a live object is reported `Planned`
/// (blocked) rather than silently removing something a pull-by-reference
/// deployment never reviewed for that.
pub async fn sync(state: &EngineState, actor: Option<Uuid>) -> Result<SyncOutcome, AppError> {
    let Some(bundle) = fetch_and_verify(state).await? else {
        return Ok(SyncOutcome {
            status: SyncStatus::NotConfigured,
            plan_id: None,
            approval_pending: false,
            approval_request_id: None,
        });
    };

    let license = state.license.load_full();
    let plan = plan_bundle(
        &state.base.db_migrator,
        &license,
        &bundle,
        PlanOptions {
            allow_retire: false,
            additive_only: false,
        },
    )
    .await?;

    let all_noop = plan.retires.is_empty()
        && plan.blocked.is_empty()
        && plan.entries.iter().all(|e| e.action == PlanAction::Noop);
    if all_noop {
        tracing::info!(bundle_hash = %plan.bundle_hash, "bundle sync: pulled bundle matches live metadata; nothing to do");
        return Ok(SyncOutcome {
            status: SyncStatus::NoChange,
            plan_id: None,
            approval_pending: false,
            approval_request_id: None,
        });
    }

    let bundle_json: serde_json::Value = serde_json::from_slice(&canonical_json(&bundle))
        .map_err(|e| AppError::internal(format!("canonical bundle is not JSON: {e}")))?;
    let plan_json = serde_json::to_value(&plan).map_err(AppError::internal)?;
    let plan_id = ledger::insert_plan(
        &state.base.db,
        &bundle_json,
        &plan_json,
        &plan.bundle_hash,
        &plan.basis_hash,
        BUNDLE_FORMAT,
        PLATFORM_VERSION,
        false,
        actor,
    )
    .await?;

    if !plan.is_applicable() {
        tracing::warn!(
            plan_id = %plan_id,
            blocked = plan.blocked.len(),
            "bundle sync: pulled bundle's plan has blocked entries; left planned for manual review"
        );
        return Ok(SyncOutcome {
            status: SyncStatus::Planned,
            plan_id: Some(plan_id),
            approval_pending: false,
            approval_request_id: None,
        });
    }

    let requester = actor.unwrap_or(Uuid::nil());
    let accepted = apply_with_gate(state, plan_id, requester).await?;
    let status = if accepted.approval_pending {
        SyncStatus::ApprovalPending
    } else {
        SyncStatus::Queued
    };
    Ok(SyncOutcome {
        status,
        plan_id: Some(plan_id),
        approval_pending: accepted.approval_pending,
        approval_request_id: accepted.approval_request_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn verify_ed25519_accepts_a_valid_signature_and_rejects_a_tampered_payload() {
        let (signing_key, verifying_key) = keypair();
        let payload = b"canonical bundle bytes";
        let signature = signing_key.sign(payload);
        let key_b64 = b64(verifying_key.as_bytes());
        let sig_b64 = b64(&signature.to_bytes());

        assert!(verify_ed25519(&key_b64, payload, &sig_b64).is_ok());
        assert!(verify_ed25519(&key_b64, b"different bytes", &sig_b64).is_err());

        let (_, wrong_key) = {
            let other = SigningKey::from_bytes(&[22u8; 32]);
            let vk = other.verifying_key();
            (other, vk)
        };
        let wrong_key_b64 = b64(wrong_key.as_bytes());
        assert!(verify_ed25519(&wrong_key_b64, payload, &sig_b64).is_err());
    }

    #[test]
    fn verify_ed25519_rejects_malformed_base64_and_wrong_lengths() {
        assert!(verify_ed25519("not base64 !!!", b"x", "AA==").is_err());
        assert!(verify_ed25519(&b64(b"too-short"), b"x", "AA==").is_err());
        let (_, verifying_key) = keypair();
        let key_b64 = b64(verifying_key.as_bytes());
        assert!(verify_ed25519(&key_b64, b"x", "not base64 !!!").is_err());
        assert!(verify_ed25519(&key_b64, b"x", &b64(b"too-short")).is_err());
    }
}

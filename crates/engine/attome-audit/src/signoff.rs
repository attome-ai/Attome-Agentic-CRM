//! D-442 / M58 Phase 1 (Digital Signature) — internal sign-off, core only.
//!
//! **Scope (module plan §4 checklist item 1):** on every `attome-approval`
//! decision — one `approval_grant` row, written by
//! `attome_approval::decide`/`decide_step` — compute a **decision digest** =
//! `SHA256(request_id, step, decision, decided_by, decided_at, document_hash?)`
//! and record it as its own `attome_audit` event, in addition to (never instead
//! of) the `Approved`/`Rejected` event `attome-server::approval_admin::
//! decide_approval` already writes for the same decision. Explicitly OUT of
//! scope here: the M57-rendered certificate PDF (needs a render service this
//! repo does not have), the optional per-user signing key (needs its own
//! key-custody/recovery decision), and part (2), legally-binding e-signature
//! via an external provider — see `D-442.md` for the full boundary.
//!
//! **No new cryptography.** This reuses exactly the primitives
//! `attome_audit::service`/`attome_core::audit_signing` already use for the
//! chain itself: `sha2::Sha256`, hex-encoded the same way
//! `service::compute_hash_raw` does. The digest is deliberately a *content*
//! hash, not a substitute for the chain's own per-row `event_hash` (which,
//! for hash-version-1 rows, only covered `operation`/`entity_name`/
//! `record_id`/`user_id`/`changed_on`; hash v2 covers the whole event and
//! so binds the digest this event carries in `event_name`, D-539): storing
//! it lets `GET /api/v1/signoff/{decision_id}/verify`
//! (`attome-server::signoff`) recompute it from the grant row's *current* state
//! and catch a content-level tamper (e.g. `decision`/`decided_by` rewritten
//! directly in the database) that the structural hash chain alone would not
//! detect, while the chain still protects the digest event's own
//! existence/ordering (deleting or reordering it breaks chain continuity the
//! same as any other event).
//!
//! **Non-repudiation against the operator, not against the platform.** A
//! deployment operator with direct database access could, in principle,
//! rewrite both the grant row and its stored digest consistently together —
//! no purely server-side chained-hash design defeats an attacker with your
//! own signing key and full DB access. What this closes is the ordinary
//! tamper case: a `decision`/`decided_by`/`decided_at` changed *without*
//! recomputing and overwriting the matching digest, which
//! `record_decision_digest`'s caller never does through the API. See
//! `D-442.md` for why the stronger property (non-repudiation against the
//! platform itself, via a per-user signing key) is deliberately deferred.

use attome_approval::Decision;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use attome_core::{AuditSigner, EngineState};

use crate::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx, verify,
};

/// Versions the digest formula (bound into the stored JSON, not the digest
/// bytes themselves) so a future change to what goes into the hash is
/// distinguishable from a genuine tamper when read back by an operator or a
/// future verify-endpoint revision.
pub const DIGEST_ALGO: &str = "sha256-v1";

/// `SHA256(request_id | step | decision | decided_by | decided_at |
/// document_hash?)`, hex-encoded the same way `service::compute_hash_raw`
/// is. `decided_at` is truncated to microsecond precision first — the same
/// defensive normalization `service::normalize_changed_on` applies to
/// `changed_on` before hashing, for the same reason (a `DateTime<Utc>` that
/// went through `sqlx` should already be microsecond-precision, but nothing
/// upstream guarantees it, and this function must be called with the exact
/// same value at record time and at verify time to agree).
pub fn compute_decision_digest(
    request_id: Uuid,
    step: i32,
    decision: &str,
    decided_by: Uuid,
    decided_at: DateTime<Utc>,
    document_hash: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(request_id.as_bytes());
    h.update(step.to_le_bytes());
    h.update(decision.as_bytes());
    h.update(decided_by.as_bytes());
    h.update(
        decided_at
            .trunc_subsecs(6)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
            .as_bytes(),
    );
    if let Some(doc) = document_hash {
        h.update(doc.as_bytes());
    }

    hex::encode(h.finalize())
}

fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Approve => "approved",
        Decision::Reject => "rejected",
    }
}

/// One `approval_grant` row's identity, as needed to compute and
/// store its digest — the columns `decide`/`decide_step` themselves insert
/// but never return to their caller.
#[derive(sqlx::FromRow)]
struct GrantRow {
    id: Uuid,
    step: i32,
    decided_at: DateTime<Utc>,
}

/// Called right after a successful `attome_approval::decide`/`decide_step`
/// call (from `attome-server::approval_admin::decide_approval` — the one
/// generic decision surface every `KNOWN_ACTION_TYPES` sign-off flows
/// through, covering both the flat and D-421 plan-bearing paths since
/// `decide_step` is only ever reached through it). Looks up the grant row
/// that call just inserted (`decide`/`decide_step` return the parent
/// `ApprovalRequest`, never the grant's own id — the most-recent
/// `(request_id, approver_id)` row is unambiguously the one this exact call
/// created: `already_decided` inside `decide`/`decide_step` refuses a second
/// decision by the same approver on the same step before this is ever
/// reached), computes its digest, and:
///
/// 1. stores `{"algo", "digest", "document_hash", "recorded_at"}` on that
///    grant row's schema-ready `signature JSONB` column (migration `0186`,
///    left unused specifically for this feature — see that migration's own
///    comment), and
/// 2. writes a `DecisionDigest` audit event carrying the same JSON as its
///    `snapshot_json`, `record_id = grant.id`.
///
/// Both in one transaction (atomic with each other); NOT atomic with the
/// original `decide`/`decide_step` commit that produced the grant row —
/// same known, accepted gap every other audit write in `approval_admin.rs`
/// already has (see `decide_approval`'s own comment). Returns the digest so
/// the caller can log it; the caller decides whether a failure here should
/// be fatal to the HTTP response (today: no — logged and swallowed, same
/// posture as the `Approved`/`Rejected` write immediately above it).
///
/// `document_hash` — this release's scoped convention (no existing
/// file-hash-attachment mechanism was found in this workspace to attach to
/// instead, see `D-442.md`): a top-level string field named
/// `"document_hash"` on the approval request's own `payload`, if the
/// submitting flow chose to put one there. `None` when absent — most
/// `action_type`s carry no document at all.
pub async fn record_decision_digest(
    state: &EngineState,
    request_id: Uuid,
    decider_id: Uuid,
    decision: Decision,
) -> Result<String, AppError> {
    let request = attome_approval::get(&state.base.db, request_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let digest =
        record_decision_digest_in_tx(&mut tx, state, &request, decider_id, decision).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(digest)
}

/// [`record_decision_digest`] inside the caller's transaction. The decide
/// handler calls it from the `attome_approval::decide_with` hook, so the grant,
/// its digest and both audit events commit together (audit plan 3.6, D-062);
/// the grant row is read through `tx`, which already holds it uncommitted.
pub async fn record_decision_digest_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    request: &attome_approval::ApprovalRequest,
    decider_id: Uuid,
    decision: Decision,
) -> Result<String, AppError> {
    let request_id = request.id;
    let grant: Option<GrantRow> = sqlx::query_as(
        "SELECT id, step, decided_at FROM approval_grant \
         WHERE request_id = $1 AND approver_id = $2 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(request_id)
    .bind(decider_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let Some(grant) = grant else {
        return Err(AppError::internal(
            "record_decision_digest: no approval_grant row found for \
             (request_id, approver_id) — decide()/decide_step() must already have inserted one",
        ));
    };

    let document_hash = request
        .payload
        .get("document_hash")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let decision_word = decision_str(decision);
    let digest = compute_decision_digest(
        request_id,
        grant.step,
        decision_word,
        decider_id,
        grant.decided_at,
        document_hash.as_deref(),
    );

    let signature_json = json!({
        "algo": DIGEST_ALGO,
        "digest": digest,
        "document_hash": document_hash,
        "recorded_at": Utc::now().to_rfc3339(),
    });

    sqlx::query("UPDATE approval_grant SET signature = $1::jsonb WHERE id = $2")
        .bind(&signature_json)
        .bind(grant.id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    let (user_ctx, organization_ref) = fetch_audit_ctx(state, decider_id).await;
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some("approval_grant".to_string()),
        record_id: Some(grant.id),
        operation: AuditOperation::DecisionDigest,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: grant.decided_at,
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        // A-2 (audit 10/10 plan, D-539 consequences): the decision digest is
        // carried in `event_name`, a field hash v2 covers and D-540 never
        // encrypts, so the signed chain binds it. A DB-level writer who
        // rewrites the grant and recomputes the unkeyed digest can no longer
        // make `verify` pass: the chained event still names the original.
        event_name: Some(chained_digest_label(&digest)),
        event_comment: Some(format!(
            "M58 decision digest recorded for approval request {request_id} ({}) step {} ({decision_word})",
            request.action_type, grant.step
        )),
        changed_fields: vec![],
        snapshot_json: Some(signature_json),
    };
    audit_service(state).write_in_tx(tx, event).await?;

    Ok(digest)
}

/// `event_name` of a `DecisionDigest` event: `"sha256-v1:<digest>"`.
fn chained_digest_label(digest: &str) -> String {
    format!("{DIGEST_ALGO}:{digest}")
}

/// The chain-evidence half of `GET /api/v1/signoff/{decision_id}/verify`
/// (`attome-server::signoff`), resolved here so that handler stays a thin
/// mapping (audit 10/10 plan item 1.7). The two values map one-to-one onto the
/// response's `chain_row_hash_ok` and `chain_row_signature_ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionChainEvidence {
    pub hash_ok: Option<bool>,
    pub signature_ok: Option<bool>,
    /// The checked header's `hash_version` (D-539); `None` unless exactly one
    /// header was checked.
    pub hash_version: Option<i16>,
    /// The decision digest the checked header's `event_name` carries. Bound by
    /// the chain only when `hash_version` is 2.
    pub chained_digest: Option<String>,
}

impl DecisionChainEvidence {
    const PENDING: Self = Self {
        hash_ok: None,
        signature_ok: None,
        hash_version: None,
        chained_digest: None,
    };
    const MISSING: Self = Self {
        hash_ok: Some(false),
        signature_ok: None,
        hash_version: None,
        chained_digest: None,
    };

    /// True only for evidence that was actually checked and passed. Pending
    /// evidence (both `None`) is never verified.
    pub fn is_verified(&self) -> bool {
        self.hash_ok == Some(true) && self.signature_ok != Some(false)
    }

    /// A-2: whether the chain binds `recomputed_digest` — the digest
    /// recomputed from the grant row's current state.
    ///
    /// - A hash-version-2 header hashes `event_name`, so the digest it carries
    ///   must equal `recomputed_digest`. A grant rewritten together with its
    ///   stored digest (the unkeyed formula is public) fails here.
    /// - A version-1 header (a decision recorded before hash v2) never hashed
    ///   `event_name`; nothing in the chain binds its digest, so this returns
    ///   `true` and such a decision keeps its pre-v2 verification, with A-2
    ///   still open for it. The v1 cutover checkpoint (plan item 2.6) freezes
    ///   that history.
    /// - No single checked header: `false`.
    pub fn binds_digest(&self, recomputed_digest: &str) -> bool {
        match self.hash_version {
            Some(crate::canonical::HASH_VERSION_V1) => true,
            Some(crate::canonical::HASH_VERSION_V2) => {
                self.chained_digest.as_deref() == Some(recomputed_digest)
            }
            _ => false,
        }
    }
}

/// Resolves one decision's `DecisionDigest` audit evidence:
///
/// - **checked** — exactly one header row: that row's single-row
///   verification ([`verify::verify_header_row`]);
/// - **pending** — no header row, but the event is still in
///   `audit_ingest` waiting for the chainer: both `None`;
/// - **missing** — the event is in neither table: `hash_ok = Some(false)`;
/// - **ambiguous** — more than one header row for the decision:
///   `hash_ok = Some(false)`, with the newest row's own signature result, so
///   a forged newest header still reports its signature failure.
///
/// The ingest lookup matches payload fields and has no index. It runs only
/// when no header row exists, behind an admin-only endpoint.
pub async fn decision_chain_evidence(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    decision_id: Uuid,
) -> Result<DecisionChainEvidence, AppError> {
    let headers: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_header \
         WHERE record_id = $1 AND operation = $2 \
         ORDER BY id DESC LIMIT 2",
    )
    .bind(decision_id)
    .bind(AuditOperation::DecisionDigest as i32)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    match headers.as_slice() {
        [] => {
            // The ingest payload is the serialized `AuditEvent`, so the
            // operation is its serde name, not its discriminant.
            let operation =
                serde_json::to_value(AuditOperation::DecisionDigest).map_err(AppError::internal)?;
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM audit_ingest
                     WHERE payload->>'record_id' = $1 AND payload->>'operation' = $2
                 )",
            )
            .bind(decision_id.to_string())
            .bind(operation.as_str().unwrap_or_default())
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            Ok(if pending {
                DecisionChainEvidence::PENDING
            } else {
                DecisionChainEvidence::MISSING
            })
        }
        [only] => Ok(match verify::verify_header_row(db, signer, *only).await? {
            Some(row) => {
                let event_name: Option<String> =
                    sqlx::query_scalar("SELECT event_name FROM audit_header WHERE id = $1")
                        .bind(*only)
                        .fetch_optional(db)
                        .await
                        .map_err(AppError::internal)?
                        .flatten();
                DecisionChainEvidence {
                    hash_ok: Some(row.hash_ok),
                    signature_ok: row.signature_ok,
                    hash_version: Some(row.hash_version),
                    chained_digest: event_name.and_then(|name| {
                        name.strip_prefix(&format!("{DIGEST_ALGO}:"))
                            .map(str::to_owned)
                    }),
                }
            }
            None => DecisionChainEvidence::MISSING,
        }),
        [newest, ..] => {
            let signature_ok = verify::verify_header_row(db, signer, *newest)
                .await?
                .and_then(|row| row.signature_ok);
            Ok(DecisionChainEvidence {
                hash_ok: Some(false),
                signature_ok,
                hash_version: None,
                chained_digest: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_checked_passing_evidence_is_verified() {
        assert!(!DecisionChainEvidence::PENDING.is_verified());
        assert!(!DecisionChainEvidence::MISSING.is_verified());
        let checked = |hash_ok, signature_ok| DecisionChainEvidence {
            hash_ok: Some(hash_ok),
            signature_ok,
            hash_version: Some(crate::canonical::HASH_VERSION_V2),
            chained_digest: None,
        };
        assert!(checked(true, Some(true)).is_verified());
        assert!(checked(true, None).is_verified());
        assert!(!checked(true, Some(false)).is_verified());
        assert!(!checked(false, Some(true)).is_verified());
    }

    #[test]
    fn only_a_v2_header_carrying_the_recomputed_digest_binds_it() {
        let evidence = |hash_version, chained: Option<&str>| DecisionChainEvidence {
            hash_ok: Some(true),
            signature_ok: None,
            hash_version,
            chained_digest: chained.map(str::to_owned),
        };
        assert!(evidence(Some(2), Some("abc")).binds_digest("abc"));
        assert!(!evidence(Some(2), Some("abc")).binds_digest("def"));
        assert!(!evidence(Some(2), None).binds_digest("abc"));
        // v1 never hashed event_name: legacy verification, A-2 open for it.
        assert!(evidence(Some(1), None).binds_digest("abc"));
        assert!(!evidence(Some(7), Some("abc")).binds_digest("abc"));
        assert!(!DecisionChainEvidence::PENDING.binds_digest("abc"));
        assert!(!DecisionChainEvidence::MISSING.binds_digest("abc"));
        assert_eq!(chained_digest_label("abc"), "sha256-v1:abc");
    }

    fn ts() -> DateTime<Utc> {
        "2026-08-28T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn digest_is_deterministic_for_the_same_inputs() {
        let id = Uuid::now_v7();
        let user = Uuid::now_v7();
        let a = compute_decision_digest(id, 0, "approved", user, ts(), None);
        let b = compute_decision_digest(id, 0, "approved", user, ts(), None);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn digest_changes_when_decision_changes() {
        let id = Uuid::now_v7();
        let user = Uuid::now_v7();
        let approved = compute_decision_digest(id, 0, "approved", user, ts(), None);
        let rejected = compute_decision_digest(id, 0, "rejected", user, ts(), None);
        assert_ne!(approved, rejected);
    }

    #[test]
    fn digest_changes_when_decided_by_changes() {
        let id = Uuid::now_v7();
        let a = compute_decision_digest(id, 0, "approved", Uuid::now_v7(), ts(), None);
        let b = compute_decision_digest(id, 0, "approved", Uuid::now_v7(), ts(), None);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_when_step_changes() {
        let id = Uuid::now_v7();
        let user = Uuid::now_v7();
        let a = compute_decision_digest(id, 0, "approved", user, ts(), None);
        let b = compute_decision_digest(id, 1, "approved", user, ts(), None);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_when_request_id_changes() {
        let user = Uuid::now_v7();
        let a = compute_decision_digest(Uuid::now_v7(), 0, "approved", user, ts(), None);
        let b = compute_decision_digest(Uuid::now_v7(), 0, "approved", user, ts(), None);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_when_decided_at_changes() {
        let id = Uuid::now_v7();
        let user = Uuid::now_v7();
        let later: DateTime<Utc> = "2026-08-28T12:00:01Z".parse().unwrap();
        let a = compute_decision_digest(id, 0, "approved", user, ts(), None);
        let b = compute_decision_digest(id, 0, "approved", user, later, None);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_when_document_hash_changes() {
        let id = Uuid::now_v7();
        let user = Uuid::now_v7();
        let none = compute_decision_digest(id, 0, "approved", user, ts(), None);
        let some = compute_decision_digest(id, 0, "approved", user, ts(), Some("abc123"));
        let other = compute_decision_digest(id, 0, "approved", user, ts(), Some("def456"));
        assert_ne!(none, some);
        assert_ne!(some, other);
    }
}

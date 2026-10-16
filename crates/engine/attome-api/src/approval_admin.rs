//! D-195 / `document/detailed-plans/P-four-eyes-approval.md` — the generic
//! admin surface over `attome_approval`: list/get pending requests, decide
//! (approve/reject) one, and — on approve — actually execute the underlying
//! action. `gate()` is what a gated flow's own handler (today:
//! `rewrap_admin.rs`, `retention_admin.rs`, …) calls at the top, before doing
//! anything else, to ask "does this action_type require approval right now."
//!
//! Scope note (plan §5): action_types wired so far — `ACTION_SECURITY_REWRAP`,
//! `attome_security::admin::ACTION_ROLE_GRANT` (direct
//! user→role assignment), `retention_admin::ACTION_RETENTION_APPROVE`
//! (approving a proposed archive/drop/purge action), `query_admin::
//! ACTION_QUERY_PUBLISH` (create/republish a stored query),
//! `erasure_admin::ACTION_SECURITY_ERASURE` (crypto-shredding key
//! destruction), `admin::attribute::ACTION_SCHEMA_CHANGE` (the
//! async/expensive schema-change path only — see that constant's doc
//! comment for why the cheap/inline path is not gated), and (D-268)
//! `dsr_admin::ACTION_DSR_FULFILL_ERASURE` (P-data-protection-governance's
//! DSR erasure fulfillment — same D-107 `destroy_key` call underneath as
//! `ACTION_SECURITY_ERASURE`, wired separately since the payloads differ:
//! one record vs. a DSR request's whole scope list), and (P-environment-
//! promotion) `bundle::ACTION_BUNDLE_APPLY` (queue an already-planned
//! metadata bundle for apply — payload `{plan_id}`) and
//! `bundle::ACTION_BREAK_GLASS` (open the production authoring window —
//! payload `{ttl_minutes}`), both on the production-mandatory floor, and
//! (D-432 / M13) `duplicates_admin::ACTION_MDM_AUTO_MERGE` — the one
//! action_type this crate submits to itself (`duplicates_match::
//! submit_auto_merge_request`, `requested_by = attome_approval::
//! POLICY_ACTOR_ID`) rather than a human ever calling `gate()` for it; every
//! other entry above is submitted by a live request; and (M69 master-plan)
//! `attome_project::change_request::ACTION_CHANGE_REQUEST_DECIDE`/
//! `attome_project::timesheet::ACTION_TIMESHEET_DECIDE` — the change-request
//! and timesheet approve/reject decisions, closing the "a requester can
//! approve their own change request" gap for any deployment that turns
//! gating on for those two action_types (see `attome-project::change_request`'s
//! own doc comment for exactly what this does and does not guarantee when
//! gating is off). IdP config changes
//! are NOT gated — D-065 established OIDC provider config as a
//! deployment-time file, not a runtime-mutable row, so there is no request
//! to gate without first reversing that decision (see
//! `document/detailed-plans/P-four-eyes-approval.md` §5 for the open
//! question this leaves). The gate (`gate()`, re-exported
//! below) is `attome_audit::approval::gate`: ARCH-5 moved it down the stack
//! so a gated flow whose HTTP entrypoint lives in an engine crate
//! (`attome-security::admin`'s role grant, every `attome-compliance` bundle) can
//! call it — `attome-api` depends on those crates, never the reverse, so
//! before the move `attome-security` carried a duplicate. `execute_approved`
//! below still owns dispatch for every action_type regardless of which crate its `do_*`
//! lives in. `execute_approved` takes the *deciding* admin's identity
//! (`approver_id`) as well as the request — most `do_*` ignore it, but a flow
//! whose ungated path already records an approving identity
//! (`retention_admin::do_approve_retention_action`'s `approved_by`) must
//! record this one, not `request.requested_by` (the original submitter).
//!
//! Wiring one more is:
//!   1. call `gate()` at the top of that flow's handler with a new
//!      `ACTION_*` constant and a JSON-serializable payload capturing its
//!      parameters (mirror `rewrap_admin::trigger_rewrap`/
//!      `retention_admin::approve_action`),
//!   2. extract that flow's actual mutation into a plain `do_*` function
//!      callable both directly and from `execute_approved` below — fold any
//!      safety invariant (not just input validation) into this function so
//!      it's enforced on both paths, never only the ungated one,
//!   3. add one match arm to `execute_approved`.
//!
//! No change to `attome_approval` or to this module's list/get/decide
//! endpoints is needed for any of the remaining four. (Erasure specifically
//! may not even fit this model unchanged — see the plan doc §5 step 9's open
//! design question before wiring it.)

use attome_approval::{ApprovalRequest, ApprovalStatus, Decision};
use attome_audit::security::{AuditHook, HookEvent, MandatoryCategory, SecurityEvent};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_security::MetadataRollout;
use attome_server::authz::{Admin, Authorized, Privilege, RecordScoped, SelfService};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `security.rewrap` is declared beside its handler in `attome-compliance`
/// (ARCH-5); imported so `execute_approved`'s match arm and
/// `KNOWN_ACTION_TYPES` keep naming it unqualified.
pub(crate) use attome_compliance::rewrap_admin::ACTION_SECURITY_REWRAP;
/// `dashboard.publish` is declared beside its handler in `attome-dashboard`
/// (`document/XRM-Dashboard-Module.md` Phase 1, same ARCH-5-style layering as
/// `ACTION_SECURITY_REWRAP` above) — imported so `execute_approved`'s match
/// arm and `KNOWN_ACTION_TYPES` keep naming it unqualified.
pub(crate) use attome_dashboard::lifecycle::ACTION_DASHBOARD_PUBLISH;

/// Every `action_type` this binary's `execute_approved` (below) actually
/// knows how to dispatch. `approval.required_actions` is a free-form
/// `Vec<String>` that `attome-config` cannot validate itself (guidelines §1 —
/// base-* has zero xrm-* knowledge of what an action_type means), so
/// `server::boot::init` (the composition root, which does depend on this
/// crate) checks every configured entry against this list at boot and fails
/// closed on an unrecognized one — closing the gap this crate's own doc
/// comments used to just flag ("silently never gates anything").  Kept next
/// to `execute_approved`'s match arms so the two can never drift apart.
pub const KNOWN_ACTION_TYPES: &[&str] = &[
    ACTION_SECURITY_REWRAP,
    attome_security::admin::ACTION_ROLE_GRANT,
    attome_compliance::retention_admin::ACTION_RETENTION_APPROVE,
    attome_records::query_admin::ACTION_QUERY_PUBLISH,
    attome_compliance::erasure_admin::ACTION_SECURITY_ERASURE,
    crate::admin::ACTION_SCHEMA_CHANGE,
    crate::admin::ACTION_ENTITY_DELETE,
    crate::admin::ACTION_ENTITY_HARD_DELETE,
    attome_compliance::dsr_admin::ACTION_DSR_FULFILL_ERASURE,
    attome_records::entity_crud::ACTION_RECORD_HARD_DELETE,
    crate::bundle::ACTION_BUNDLE_APPLY,
    crate::bundle::ACTION_BREAK_GLASS,
    // Solution 7 Phase 1 (D-785): applying changesets, the counterpart of
    // `metadata.bundle_apply` (production-mandatory below, like it).
    crate::changeset::ACTION_CHANGESET_APPLY,
    ACTION_DASHBOARD_PUBLISH,
    crate::bulk_transform::ACTION_DATA_BULK_TRANSFORM,
    crate::duplicates_admin::ACTION_MDM_AUTO_MERGE,
    attome_project::change_request::ACTION_CHANGE_REQUEST_DECIDE,
    attome_project::timesheet::ACTION_TIMESHEET_DECIDE,
];

/// Whether [`execute_approved`] has a dispatch arm for `action_type`.
///
/// A `false` answer is not an error. Some requests are decided here but
/// carried out by the engine that owns the action — a workflow approval node
/// resumes from the request's own state once it is `approved`, and never
/// wants the approval dispatcher to run it. Such a request must decide
/// cleanly and stay `approved` for its owner to observe; routing it into
/// `execute_approved` fails with "no execution handler registered" and turns
/// a valid decision into a 500 for the caller (Dashboard 10/10 Phase 6,
/// found while testing the Workflow `MyWorkProvider`).
///
/// D-518: checked before claiming. A request without a dispatch arm must
/// never be moved to `executing` here, or its owner would stop seeing it
/// `approved`.
///
/// M07 Phase F: `state.transition` is dispatched here but deliberately not in
/// `KNOWN_ACTION_TYPES` — that list is also what `approval.required_actions`
/// may name, and a transition approval is opened by the state engine from
/// transition metadata, never by `gate()`.
fn has_execution_handler(action_type: &str) -> bool {
    KNOWN_ACTION_TYPES.contains(&action_type)
        || action_type.starts_with(attome_ai::approval::ACTION_TYPE_PREFIX)
        || action_type == attome_core::ACTION_STATE_TRANSITION
}

/// The mandatory production approval baseline (closes the follow-up
/// `server::boot::validate_operation_registries` explicitly left open: "left
/// as a documented follow-up, not silently addressed"). Same criterion
/// `attome_api::bulk::MANDATORY_TIER_OPERATIONS` uses for its own D-207
/// production floor — not "every wired action_type", but the ones whose
/// *execution* cannot be undone: `security.erasure` and (D-268)
/// `dsr.fulfill_erasure` both permanently destroy a crypto-shredding key
/// (D-107 — every audit record ever encrypted under it becomes permanently
/// unreadable; the DSR flow just resolves *which* records via a request's
/// scopes instead of one direct `{logicalname, record_id}`, same irreversible
/// call underneath) and `retention.approve_action` authorizes an
/// archive/drop/purge that, once it runs, is exactly as gone as erasure is.
/// `security.rewrap`/`security.role_grant`/
/// `query.publish`/`schema.attribute_change`/`dashboard.publish` are each
/// reversible by a follow-up action (rotate again, revoke,
/// unpublish, alter back, unpublish again) even though getting them wrong is
/// still costly — so they stay
/// deployment-opt-in, not baseline-mandatory. A deployment may still add any
/// of them to `approval.required_actions` for its own contractual/regulatory
/// posture; this baseline is the floor every `deployment_profile =
/// "production"` boot must clear, not a ceiling.
///
/// P-environment-promotion (§4 "Production change control") widens the
/// criterion by one deliberate case: the two actions that ARE the production
/// change-control mechanism. On the production profile the authoring gate
/// refuses every direct metadata write, so `metadata.bundle_apply` is the
/// one sanctioned way configuration changes reach production at all — the
/// plan requires a second person on it by default, enforced at boot like the
/// rest of this floor. `metadata.break_glass` suspends that gate for a
/// bounded window; an action that switches the control itself off must sit
/// behind the same dual control as the writes it unlocks, or the gate is
/// only as strong as one admin's judgement.
pub const PRODUCTION_MANDATORY_ACTIONS: &[&str] = &[
    attome_compliance::erasure_admin::ACTION_SECURITY_ERASURE,
    attome_compliance::retention_admin::ACTION_RETENTION_APPROVE,
    attome_compliance::dsr_admin::ACTION_DSR_FULFILL_ERASURE,
    // `DELETE /admin/entities/{id}?hard=true` drops the physical table and
    // deletes the metadata rows outright — no follow-up action restores
    // either, which is this list's stated criterion. Its soft sibling
    // (`schema.entity_delete`) is reversible by flipping `is_active` back and
    // so stays opt-in, which is why the two are separate action types.
    crate::admin::ACTION_ENTITY_HARD_DELETE,
    // P-environment-promotion — see the doc comment above for why these two
    // join the floor despite being reversible (re-apply the previous bundle;
    // close the window).
    crate::bundle::ACTION_BUNDLE_APPLY,
    crate::bundle::ACTION_BREAK_GLASS,
    // Solution 7 (D-785, design §5.3): applying changesets is the other
    // sanctioned way production metadata changes, so it sits behind the same
    // dual control as `metadata.bundle_apply`.
    crate::changeset::ACTION_CHANGESET_APPLY,
];

/// `do_create_attribute`/`do_update_attribute` return a full axum `Response`
/// (they can also answer a `dry_run` estimate with a different body shape,
/// though that branch is unreachable via this path — `gate()` never fires
/// for a `dry_run` payload, see `admin::attribute`'s doc comments), not a
/// plain serializable value like every other wired action's `do_*`. This
/// reads the JSON back out of that response body so `execute_approved` can
/// return it in the same opaque-`Value` shape as every other action_type.
async fn response_json_body(response: axum::response::Response) -> Result<Value, AppError> {
    let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(AppError::internal)
}

/// Solution 7 (design §4.5) — how an approval-deferred metadata write is
/// recorded when the approved request executes. The request's payload may
/// carry the `changeset_id` resolved when the write was requested: the
/// execution records into that changeset, and fails with
/// `changeset_not_open` if it has since been closed or abandoned (the
/// approval then shows the error). Without one, the execution gets its own
/// automatic changeset (`auto` mode, whatever the deployment's mode: the
/// author could not have named a changeset the request did not carry).
/// Attributed to the requester, who authored the change.
fn deferred_recording(
    state: &EngineState,
    request: &ApprovalRequest,
    action: &str,
) -> attome_core::changeset::Recording {
    use attome_core::changeset::{Recording, RecordingMode, RequestContext};
    let header = request
        .payload
        .get("changeset_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let config = &state.base.config;
    let changesets = &config.metadata.changesets;
    let mode = if header.is_some() {
        changesets.effective_mode(&config.app.deployment_profile)
    } else {
        RecordingMode::Auto
    };
    Recording::for_request(RequestContext {
        header,
        actor: Some(request.requested_by),
        actor_label: format!("user:{}", request.requested_by),
        request_id: None,
        route: format!("APPROVAL {action} {}", request.id),
        mode,
        auto_layer: changesets.auto_layer,
        break_glass: false,
    })
}

/// The gate itself is `attome_audit::approval::gate` since ARCH-5 — it moved
/// down the stack so the compliance route bundles (now `attome-compliance`)
/// and `attome-security`'s role-grant flow can call it without a reverse
/// edge. Re-exported here so this crate's own gated handlers
/// (`admin::{attribute,entity}`, `query_admin`,
/// `bundle`) keep naming `crate::approval_admin::gate`.
pub(crate) use attome_audit::approval::gate;

/// Refuses, before any claim, a retry of a request this module does not
/// dispatch (D-551). Such an action type is carried out by the engine that
/// owns it — a workflow Approval node resumes from the request's own state —
/// so `approved` is its terminal state here, not a stuck one. D-518: it is
/// also never claimed, or its owner would stop seeing it `approved`.
fn ensure_dispatchable(action_type: &str) -> Result<(), AppError> {
    if has_execution_handler(action_type) {
        return Ok(());
    }
    Err(AppError::Conflict(
        "this action type is carried out by the engine that owns it, not by the approval \
         dispatcher; there is nothing to retry",
    ))
}

/// How [`execute_approved`] closed a claimed request.
enum Closed {
    /// The action ran and the request is `executed`; the action's result.
    Executed(Value),
    /// Execution-time revalidation refused it; the request is invalidated.
    Invalidated,
    /// Nothing ran and the claim was released; the request is `approved`.
    Deferred,
}

impl Closed {
    /// The human paths' contract: only an executed action is a success.
    fn into_result(self) -> Result<Value, AppError> {
        match self {
            Self::Executed(value) => Ok(value),
            Self::Invalidated => Err(AppError::Conflict(
                "the approved action is no longer permitted and was not executed; \
                 the request has been invalidated",
            )),
            Self::Deferred => Err(AppError::Conflict(
                "the requesting agent session is paused, so the approved action was not \
                 executed; the request stays approved — retry execution after the \
                 session is resumed",
            )),
        }
    }
}

/// What [`dispatch_approved`] produced for a claimed request.
enum Dispatched {
    /// The action ran; its result.
    Executed(Value),
    /// Execution-time revalidation refused the action permanently (D-502).
    Invalidated { reason: &'static str },
    /// The action cannot run now, and nothing ran (D-502 pause, D-512 write
    /// limit).
    Deferred { reason: &'static str },
}

/// Runs a request this call has just claimed (D-518), then closes the claim
/// the way the outcome requires:
///
/// - executed: `complete_execution`, and the action's result is returned;
/// - invalidated: `invalidate_execution`;
/// - deferred: `release_execution` — the request is `approved` again for
///   `retry-execution`;
/// - an executor error: `release_execution`, then that error. This keeps
///   D-502's "a transient failure stays retryable", with the caveat
///   `retry_execution` documents for a `do_*` that partly applied.
///
/// If a close-out itself fails, the claim stays: the request reads
/// `executing` until its lease passes and an admin reconciles it through
/// `retry-execution`. Nothing re-runs it automatically.
///
/// `claimed` must be the request exactly as `attome_approval::claim_execution`
/// or `take_over_stale_execution` returned it: its `row_version` is the
/// claim. `approver_id` is passed through to [`dispatch_approved`].
async fn execute_approved(
    state: &EngineState,
    claimed: &ApprovalRequest,
    approver_id: Uuid,
) -> Result<Closed, AppError> {
    let db = &state.base.db;
    let dispatched = match dispatch_approved(state, claimed, approver_id).await {
        Ok(dispatched) => dispatched,
        Err(e) => {
            release_claim_after_failure(state, claimed).await;
            return Err(e);
        }
    };
    match dispatched {
        Dispatched::Executed(result) => {
            // D-541 rule 7 / D-062: the `Execute` `BusinessEvent` commits with
            // the `executing -> executed` transition. The action's own
            // mutation ran above in its own transaction(s) and wrote its own
            // events; this event records that the approved request was
            // carried out, by whom, and under which request.
            let hook = AuditHook::new(audit_service(state), |executed: &ApprovalRequest| {
                vec![HookEvent::Business(
                    attome_audit::BusinessEvent::new(
                        "approval_request",
                        executed.id,
                        AuditOperation::Execute,
                        executed.action_type.clone(),
                        approver_id,
                    )
                    .versions(Some(claimed.row_version), Some(executed.row_version))
                    .comment(format!(
                        "approved request {} (requested by {}) executed",
                        executed.id, executed.requested_by
                    )),
                )]
            });
            // C10-A: an executed agent action completes its conversation tool
            // call (`tool.call.completed`) in the same transaction.
            let hook = attome_db::Chain(
                &hook,
                &attome_ai::conversation_event::ApprovalConversationHook,
            );
            if let Err(e) =
                attome_approval::complete_execution_with(db, claimed.id, claimed.row_version, &hook)
                    .await
            {
                tracing::error!(
                    request_id = %claimed.id,
                    action_type = %claimed.action_type,
                    error = %e,
                    "approved action executed, but its request could not be marked executed; \
                     it stays `executing` until an admin reconciles it after the claim lease"
                );
                return Err(e);
            }
            Ok(Closed::Executed(result))
        }
        Dispatched::Invalidated { reason } => {
            // C10-A: the conversation's tool call fails in this same
            // transaction (`tool.call.failed{invalidated}`).
            attome_approval::invalidate_execution_with(
                db,
                claimed.id,
                claimed.row_version,
                &attome_ai::conversation_event::ApprovalConversationHook,
            )
            .await?;
            tracing::warn!(
                request_id = %claimed.id,
                action_type = %claimed.action_type,
                reason,
                "approved agent action invalidated at execution time"
            );
            Ok(Closed::Invalidated)
        }
        Dispatched::Deferred { reason } => {
            attome_approval::release_execution(db, claimed.id, claimed.row_version).await?;
            tracing::info!(
                request_id = %claimed.id,
                action_type = %claimed.action_type,
                reason,
                "approved agent action deferred; request stays approved"
            );
            Ok(Closed::Deferred)
        }
    }
}

/// BAP-11b — what one delivery of the auto-approval execution job did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoExecution {
    /// This delivery claimed the request and its action ran.
    Executed,
    /// This delivery claimed it; execution-time revalidation refused it.
    Invalidated,
    /// This delivery claimed it; the action cannot run now and the claim was
    /// released, so the request is `approved` again for `retry-execution`.
    Deferred,
    /// Not this delivery's to run: already executed, no longer approved, or
    /// held by a claim it does not own. A foreign claim is never taken over,
    /// however old (invariant A3) — it waits for an admin's acknowledgement.
    NotClaimed,
    /// No dispatch arm here: the engine that owns the action carries it out
    /// from the request's `approved` state (D-551).
    NotDispatchable,
}

/// BAP-11b — carries out a request a policy step timeout auto-approved, for
/// `EngineJob::ExecuteApprovedRequest`. The same `claim -> dispatch ->
/// close` path the decide route and `retry-execution` use, so a duplicate
/// delivery, a manual retry racing this job, or a retry after a crash
/// dispatches at most once (D-518).
///
/// `Err` means "retry this delivery": an executor error (the claim was
/// released, so the next attempt may claim again), a close-out that failed
/// (the claim stays, so the next attempt finds it `executing` and dispatches
/// nothing), or a request that changed between the read and the claim.
pub async fn execute_approved_request(
    state: &EngineState,
    request_id: Uuid,
) -> Result<AutoExecution, AppError> {
    let request = attome_approval::get(&state.base.db, request_id).await?;
    if request.status != ApprovalStatus::Approved || request.executed_at.is_some() {
        return Ok(AutoExecution::NotClaimed);
    }
    if !has_execution_handler(&request.action_type) {
        return Ok(AutoExecution::NotDispatchable);
    }
    let claimed = match attome_approval::claim_execution(
        &state.base.db,
        request.id,
        request.row_version,
        attome_approval::POLICY_ACTOR_ID,
    )
    .await
    {
        Ok(claimed) => claimed,
        Err(AppError::Conflict(_)) => return Ok(AutoExecution::NotClaimed),
        // Still approved but changed since the read (a released claim, say):
        // the next attempt reads it afresh.
        Err(e) => return Err(e),
    };
    Ok(
        match execute_approved(state, &claimed, attome_approval::POLICY_ACTOR_ID).await? {
            Closed::Executed(_) => AutoExecution::Executed,
            Closed::Invalidated => AutoExecution::Invalidated,
            Closed::Deferred => AutoExecution::Deferred,
        },
    )
}

/// Best-effort release after the executor failed. A failed release leaves the
/// claim in place for an admin to reconcile after the lease, which is logged
/// rather than masking the executor's own error.
async fn release_claim_after_failure(state: &EngineState, claimed: &ApprovalRequest) {
    if let Err(e) =
        attome_approval::release_execution(&state.base.db, claimed.id, claimed.row_version).await
    {
        tracing::error!(
            request_id = %claimed.id,
            action_type = %claimed.action_type,
            error = %e,
            "approved action failed and its execution claim could not be released; the request \
             stays `executing` until an admin reconciles it after the claim lease"
        );
    }
}

/// Dispatches a claimed request to whichever flow owns `action_type`. See
/// this module's doc comment for how to wire a new `action_type`; a new arm
/// also needs an entry in [`has_execution_handler`]. `Dispatched::Executed`
/// carries the executed action's result as opaque JSON — shape depends on
/// `action_type`, mirroring what that flow's own direct (un-gated) response
/// would contain. Only [`execute_approved`] calls this, holding the claim.
///
/// `approver_id` is the identity that just called `decide(approve)` — the
/// second, distinct admin under four-eyes. Most wired actions' `do_*` don't
/// need it (they don't record who approved), but a flow whose direct path
/// already records an approving identity (`retention_admin::
/// do_approve_retention_action`'s `approved_by`) must record *this* identity,
/// not `request.requested_by` (the original submitter) — matching what that
/// column means in the ungated case.
async fn dispatch_approved(
    state: &EngineState,
    request: &ApprovalRequest,
    approver_id: Uuid,
) -> Result<Dispatched, AppError> {
    let result = match request.action_type.as_str() {
        ACTION_SECURITY_REWRAP => {
            let domain_str = request
                .payload
                .get("domain")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::internal("approval payload missing \"domain\""))?;
            let domain = domain_str
                .parse::<attome_core::jobs::RewrapDomain>()
                .map_err(AppError::internal)?;
            attome_compliance::rewrap_admin::do_trigger_rewrap(state, domain, approver_id).await?;
            serde_json::json!({ "domain": domain_str, "enqueued": true })
        }
        action if action == attome_security::admin::ACTION_ROLE_GRANT => {
            #[derive(serde::Deserialize)]
            struct RoleGrantPayload {
                user_id: Uuid,
                role_id: Uuid,
                #[serde(default)]
                valid_until: Option<chrono::DateTime<chrono::Utc>>,
                #[serde(default)]
                reason: Option<String>,
            }
            let payload: RoleGrantPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let item = attome_security::admin::do_assign_user_role(
                state,
                payload.user_id,
                payload.role_id,
                payload.valid_until,
                payload.reason.as_deref(),
                attome_security::admin::role_grant_event(approver_id)
                    .comment(format!("approval request {}", request.id)),
            )
            .await?;
            serde_json::to_value(&item).map_err(AppError::internal)?
        }
        attome_compliance::retention_admin::ACTION_RETENTION_APPROVE => {
            #[derive(serde::Deserialize)]
            struct RetentionApprovePayload {
                action_id: Uuid,
            }
            let payload: RetentionApprovePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let item = attome_compliance::retention_admin::do_approve_retention_action(
                state,
                payload.action_id,
                approver_id,
            )
            .await?;
            serde_json::to_value(&item).map_err(AppError::internal)?
        }
        attome_records::query_admin::ACTION_QUERY_PUBLISH => {
            // Attributed to `request.requested_by` (whoever actually wrote
            // the SQL that was submitted), not `approver_id` — unlike
            // retention's `approved_by`, `sql_query_version.created_by`
            // is an authorship field, not a record of who authorized the
            // transition, so it keeps meaning the same thing under gating
            // that it means on the direct (ungated) path.
            #[derive(serde::Deserialize)]
            #[serde(tag = "op", rename_all = "snake_case")]
            enum QueryPublishPayload {
                Create { body: Value },
                Update { query_id: Uuid, body: Value },
            }
            let payload: QueryPublishPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            match payload {
                QueryPublishPayload::Create { body } => {
                    let body = serde_json::from_value(body).map_err(AppError::internal)?;
                    let (_, detail) = attome_records::query_admin::do_create_query(
                        state,
                        request.requested_by,
                        body,
                    )
                    .await?;
                    serde_json::to_value(&detail).map_err(AppError::internal)?
                }
                QueryPublishPayload::Update { query_id, body } => {
                    let body = serde_json::from_value(body).map_err(AppError::internal)?;
                    // C-19: no `If-Match` to carry through the approval
                    // gate — the approved execution has no request headers
                    // of its own, so this path never guards on row_version
                    // (additive: absent = no check).
                    let detail = attome_records::query_admin::do_update_query(
                        state,
                        query_id,
                        request.requested_by,
                        body,
                        None,
                    )
                    .await?;
                    serde_json::to_value(&detail).map_err(AppError::internal)?
                }
            }
        }
        crate::admin::ACTION_ENTITY_DELETE | crate::admin::ACTION_ENTITY_HARD_DELETE => {
            // `approver_id`, not `request.requested_by` — same reasoning as
            // erasure below: `hard: true` drops the physical table, and the
            // audit event for an irreversible destruction must record who
            // authorized it, not merely who asked.
            #[derive(serde::Deserialize)]
            struct EntityDeletePayload {
                entity_id: Uuid,
                #[serde(default)]
                hard: bool,
            }
            let payload: EntityDeletePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            crate::admin::do_delete_entity(state, payload.entity_id, approver_id, payload.hard)
                .await?;
            serde_json::json!({ "entity_id": payload.entity_id, "hard": payload.hard })
        }
        attome_compliance::erasure_admin::ACTION_SECURITY_ERASURE => {
            // `approver_id`, not `request.requested_by`: the audit event
            // `do_erase_record` writes records who performed the
            // (irreversible) destruction, and under four-eyes that is the
            // deciding admin, not whoever merely asked for it — same
            // reasoning as retention's `approved_by`.
            #[derive(serde::Deserialize)]
            struct ErasurePayload {
                logicalname: String,
                record_id: Uuid,
            }
            let payload: ErasurePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let result = attome_compliance::erasure_admin::do_erase_record(
                state,
                approver_id,
                payload.logicalname,
                payload.record_id,
            )
            .await?;
            serde_json::to_value(&result).map_err(AppError::internal)?
        }
        attome_records::entity_crud::ACTION_RECORD_HARD_DELETE => {
            // A18-T6: run as the approver, who holds the privilege the
            // requester was waiting on a second person for.
            #[derive(serde::Deserialize)]
            struct RecordHardDeletePayload {
                entity: String,
                record_id: Uuid,
                expected_version: Option<i64>,
            }
            let payload: RecordHardDeletePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let ctx = state.base.security.resolve(approver_id).await?;
            attome_records::entity_crud::hard_delete_record_for(
                state,
                &ctx,
                approver_id,
                &payload.entity,
                payload.record_id,
                payload.expected_version,
            )
            .await?;
            serde_json::json!({ "entity": payload.entity, "record_id": payload.record_id })
        }
        attome_compliance::dsr_admin::ACTION_DSR_FULFILL_ERASURE => {
            // `approver_id`, not `request.requested_by` — same reasoning as
            // `ACTION_SECURITY_ERASURE` above: the audit event
            // `do_fulfill_erasure` writes records who performed the
            // (irreversible) destruction, which under four-eyes is the
            // deciding admin.
            #[derive(serde::Deserialize)]
            struct DsrFulfillErasurePayload {
                request_id: Uuid,
                scopes: Vec<attome_compliance::dsr_admin::DsrScope>,
            }
            let payload: DsrFulfillErasurePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let result = attome_compliance::dsr_admin::do_fulfill_erasure(
                state,
                approver_id,
                payload.request_id,
                payload.scopes,
            )
            .await?;
            serde_json::to_value(&result).map_err(AppError::internal)?
        }
        crate::bulk_transform::ACTION_DATA_BULK_TRANSFORM => {
            // M12 — the gated payload `enqueue_bulk_transform` submitted
            // verbatim; `user_id` here is the original requester (the
            // caller who submitted the transform), not `approver_id` —
            // matching `entity_mutation`'s existing "who acted" convention
            // for an ordinary update, which this ultimately is one of.
            #[derive(serde::Deserialize)]
            struct BulkTransformPayload {
                entity: String,
                field: String,
                transform: String,
                value: Option<String>,
                record_ids: Vec<Uuid>,
                user_id: Uuid,
            }
            let payload: BulkTransformPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            // Re-resolves rather than trusting the gated payload's entity
            // name verbatim — same defense-in-depth re-check
            // `bulk::approve_staged_import` applies to `is_append_only`
            // between submission and approval.
            let (_, entity_name, _, is_append_only) =
                attome_records::entity_crud::resolve_entity(state, &payload.entity).await?;
            if is_append_only {
                return Err(AppError::Forbidden);
            }
            let result = crate::bulk_transform::do_bulk_transform(
                state,
                &entity_name,
                &payload.field,
                &payload.transform,
                payload.value.as_deref(),
                &payload.record_ids,
                payload.user_id,
            )
            .await?;
            serde_json::to_value(&result).map_err(AppError::internal)?
        }
        crate::admin::ACTION_SCHEMA_CHANGE => {
            // Attributed to `request.requested_by` — same authorship
            // reasoning as `query.publish` above, not `approver_id`: nothing
            // about a field's definition records "who approved this", only
            // who defined it.
            #[derive(serde::Deserialize)]
            #[serde(tag = "op", rename_all = "snake_case")]
            enum SchemaChangePayload {
                Create {
                    entity_id: Uuid,
                    body: Value,
                },
                Update {
                    entity_id: Uuid,
                    attr_id: Uuid,
                    body: Value,
                },
                /// Solution 7 Phase 2 (D-788): rename, change type, delete,
                /// add/remove a choice value.
                Structure {
                    action: crate::admin::StructureAction,
                    entity_id: Uuid,
                    attr_id: Uuid,
                    body: Value,
                },
            }
            let payload: SchemaChangePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            // Solution 7 (design §4.5): the deferred write records into the
            // changeset captured at request time (`changeset_id` in the
            // payload), or into its own automatic changeset.
            let recording = deferred_recording(state, request, "schema.attribute_change");
            // L7.3: a structure change (or a PATCH's rename) that ends blocked
            // is answered `Ok` with a 409 body on the route, so the caller
            // sees the blockers. Here it must be an error: nothing was
            // applied, so the request is not recorded `executed` (the claim
            // is released and the request stays `approved` for a retry once
            // the blocker is cleared).
            let response = match payload {
                SchemaChangePayload::Create { entity_id, body } => {
                    let body: crate::admin::CreateAttributeBody =
                        serde_json::from_value(body).map_err(AppError::internal)?;
                    crate::admin::do_create_attribute_recorded(
                        state,
                        entity_id,
                        request.requested_by,
                        body,
                        Some(&recording),
                    )
                    .await?
                }
                SchemaChangePayload::Update {
                    entity_id,
                    attr_id,
                    body,
                } => {
                    let body: crate::admin::UpdateAttributeBody =
                        serde_json::from_value(body).map_err(AppError::internal)?;
                    crate::admin::do_update_attribute_recorded(
                        state,
                        entity_id,
                        attr_id,
                        request.requested_by,
                        body,
                        Some(&recording),
                    )
                    .await?
                }
                SchemaChangePayload::Structure {
                    action,
                    entity_id,
                    attr_id,
                    body,
                } => {
                    let result = crate::admin::run_structure_change(
                        state,
                        request.requested_by,
                        entity_id,
                        attr_id,
                        action,
                        body,
                        &recording,
                    )
                    .await?;
                    if let Some(code) = result.error {
                        tracing::warn!(
                            request_id = %request.id,
                            op = result.op,
                            entity = %result.entity,
                            field = %result.field,
                            blockers = result.blockers.len(),
                            error = code,
                            "approved structure change was blocked when it ran; not executed"
                        );
                        return Err(AppError::Conflict(code));
                    }
                    return Ok(Dispatched::Executed(
                        serde_json::to_value(&result).map_err(AppError::internal)?,
                    ));
                }
            };
            if !response.status().is_success() {
                // The update path's only non-2xx `Ok` answer is a blocked
                // rename (`structure_response`); fail rather than record it.
                tracing::warn!(
                    request_id = %request.id,
                    status = response.status().as_u16(),
                    "approved field update was blocked when it ran; not executed"
                );
                return Err(AppError::Conflict(
                    "the approved field change was blocked when it ran and was not applied; dry-run it to see the blockers, clear them, then retry execution",
                ));
            }
            response_json_body(response).await?
        }
        crate::bundle::ACTION_BUNDLE_APPLY => {
            // P-environment-promotion: the plan row was inserted by
            // `import?mode=plan` before the approval was submitted, so the
            // payload carries its id (plus the hashes, for the approver's
            // eyes — the worker re-checks `basis_hash` itself when it claims
            // the row). Same `do_apply_plan` the ungated route calls:
            // `planned -> queued` recording THIS request as the authorizing
            // approval, then the dedup-keyed durable job.
            #[derive(serde::Deserialize)]
            struct BundleApplyPayload {
                plan_id: Uuid,
            }
            let payload: BundleApplyPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let accepted =
                crate::bundle::do_apply_plan(state, payload.plan_id, Some(request.id)).await?;
            serde_json::to_value(&accepted).map_err(AppError::internal)?
        }
        crate::changeset::ACTION_CHANGESET_APPLY => {
            // Solution 7 (design §5.3): the payload is the apply request the
            // route validated and submitted; `do_apply` re-checks it against
            // the ledger (rows may have moved while the request waited),
            // then queues the rows recording THIS request as the authorizing
            // approval and enqueues `EngineJob::ApplyChangesets` — the same
            // path the ungated route takes.
            let body: crate::changeset::apply_routes::ApplyChangesetsBody =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let accepted =
                crate::changeset::apply_routes::do_apply(state, &body, Some(request.id)).await?;
            serde_json::to_value(&accepted).map_err(AppError::internal)?
        }
        ACTION_DASHBOARD_PUBLISH => {
            // `approver_id`, not `request.requested_by`: `do_publish_dashboard`
            // stamps `dashboard_version.published_by`, and under four-eyes
            // that is the deciding admin — same reasoning as retention's
            // `approved_by`/erasure's destroyer identity above, not the
            // original submitter.
            //
            // D-521: a rollback (`activate`) rides this same gate, so a
            // deployment that requires four-eyes on publish cannot roll back
            // without it either. Its payload names the version to make live.
            #[derive(serde::Deserialize)]
            struct DashboardPublishPayload {
                dashboard_id: Uuid,
                row_version: i64,
                #[serde(default)]
                version_id: Option<Uuid>,
                /// Phase 3.5 (E-03): the resolved definition the approver
                /// reviewed. Absent on requests submitted before it existed.
                #[serde(default)]
                publication_fingerprint: Option<String>,
            }
            let payload: DashboardPublishPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            match payload.version_id {
                Some(version_id) => {
                    let (row_version, version_number) =
                        attome_dashboard::lifecycle::do_activate_version(
                            state,
                            payload.dashboard_id,
                            version_id,
                            payload.row_version,
                            approver_id,
                        )
                        .await?;
                    serde_json::json!({
                        "dashboard_id": payload.dashboard_id,
                        "row_version": row_version,
                        "live_version_id": version_id,
                        "live_version_number": version_number,
                    })
                }
                None => {
                    let outcome = attome_dashboard::lifecycle::do_publish_dashboard_checked(
                        state,
                        payload.dashboard_id,
                        payload.row_version,
                        approver_id,
                        payload.publication_fingerprint.as_deref(),
                    )
                    .await?;
                    let (row_version, version_id, version_number) = match outcome {
                        attome_dashboard::lifecycle::PublishOutcome::Published(r, v, n) => {
                            (r, v, n)
                        }
                        // The draft or a resolved dependency changed after the
                        // request: the approver did not review this content.
                        // Terminal, like an invalidated agent action: the
                        // claimed (`executing`) request closes as invalidated.
                        attome_dashboard::lifecycle::PublishOutcome::DefinitionChanged => {
                            return Ok(Dispatched::Invalidated {
                                reason: "the dashboard changed after this approval was requested",
                            });
                        }
                    };
                    serde_json::json!({
                        "dashboard_id": payload.dashboard_id,
                        "row_version": row_version,
                        "version_id": version_id,
                        "version_number": version_number,
                    })
                }
            }
        }
        crate::bundle::ACTION_BREAK_GLASS => {
            // `approver_id`, not `request.requested_by`: opening the window
            // grants authoring rights on production for its whole TTL, and
            // the audit event must name who authorized that, not who asked.
            #[derive(serde::Deserialize)]
            struct BreakGlassPayload {
                ttl_minutes: u32,
            }
            let payload: BreakGlassPayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let opened = crate::bundle::break_glass::do_open_break_glass(
                state,
                payload.ttl_minutes,
                approver_id,
            )
            .await?;
            serde_json::to_value(&opened).map_err(AppError::internal)?
        }
        crate::duplicates_admin::ACTION_MDM_AUTO_MERGE => {
            // D-432 / M13 — submitted by the matching job itself
            // (`duplicates_match::submit_auto_merge_request`), never by a
            // human, so there is no "original requester" identity worth
            // attributing this to — `approver_id` (the deciding admin) is
            // the only real person in this flow, same reasoning
            // retention's `approved_by`/erasure's destroyer identity use.
            #[derive(serde::Deserialize)]
            struct AutoMergePayload {
                entity: String,
                canonical_id: Uuid,
                duplicate_id: Uuid,
            }
            let payload: AutoMergePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let admin_ctx = attome_records::entity_crud::admin_security_context(approver_id);
            let outcome = attome_records::entity_crud::do_merge_core(
                state,
                &admin_ctx,
                &payload.entity,
                payload.canonical_id,
                payload.duplicate_id,
                approver_id,
                None,
            )
            .await?;
            // The candidate row names its `approval_request_id` but not the
            // reverse — close it out here rather than teaching
            // `do_merge_core` about approval-request bookkeeping, which
            // belongs to this gated path only, not the merge contract every
            // caller shares.
            sqlx::query(
                "UPDATE duplicate_candidate \
                    SET status = 'merged', resolved_at = NOW(), resolved_by = $1, \
                        row_version = row_version + 1 \
                  WHERE approval_request_id = $2 AND status = 'open'",
            )
            .bind(approver_id)
            .bind(request.id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            serde_json::to_value(attome_records::entity_crud::MergeResponse::from_outcome(
                outcome,
            ))
            .map_err(AppError::internal)?
        }
        attome_project::change_request::ACTION_CHANGE_REQUEST_DECIDE => {
            // `approver_id`, not `request.requested_by`: `do_decide_change_request`
            // stamps `modified_by` with whoever is deciding, and under
            // four-eyes that is the deciding admin — same reasoning as
            // retention's `approved_by`/dashboard publish's `published_by`
            // above, not whoever merely called `approve`/`reject`.
            #[derive(serde::Deserialize)]
            struct ChangeRequestDecidePayload {
                change_request_id: Uuid,
                to_state: String,
            }
            let payload: ChangeRequestDecidePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let response = attome_project::change_request::do_decide_change_request(
                state,
                payload.change_request_id,
                &payload.to_state,
                approver_id,
            )
            .await?;
            serde_json::to_value(&response).map_err(AppError::internal)?
        }
        attome_project::timesheet::ACTION_TIMESHEET_DECIDE => {
            // Same reasoning as the change-request arm above.
            #[derive(serde::Deserialize)]
            struct TimesheetDecidePayload {
                timesheet_id: Uuid,
                to_state: String,
            }
            let payload: TimesheetDecidePayload =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            let response = attome_project::timesheet::do_decide_timesheet(
                state,
                payload.timesheet_id,
                "submitted",
                &payload.to_state,
                approver_id,
            )
            .await?;
            serde_json::to_value(&response).map_err(AppError::internal)?
        }
        // The one dynamic family here — every other arm above is a single
        // fixed action_type. `attome-ai/invoke:{action_id}` is
        // `attome_ai::approval::request_approval`'s namespace for every
        // Consequential agent action (`ACTION_TYPE_PREFIX`), so this is a
        // prefix match, not an equality one. Closes the gap `attome-ai`'s
        // M98 plan named as the top open item: an approved agent action
        // previously had `attome_approval::decide` mark it approved and
        // nothing ever ran it.
        action if action.starts_with(attome_ai::approval::ACTION_TYPE_PREFIX) => {
            let payload: attome_ai::approval::AgentActionRequest =
                serde_json::from_value(request.payload.clone()).map_err(AppError::internal)?;
            match attome_ai::execute::dispatch_approved_agent_action_under(
                state,
                &payload,
                Some(request.id),
            )
            .await?
            {
                attome_ai::execute::ApprovedExecution::Executed(result) => result,
                // Execution-time revalidation refused it (the requester lost a
                // privilege, the session was killed, the licence or kill-switch
                // changed). Terminal, not retryable: `execute_approved` marks it
                // `invalidated`, which is what stops `retry-execution` from
                // running it later once the condition is undone — the approver
                // approved the action under the old state, not whatever state
                // comes next.
                attome_ai::execute::ApprovedExecution::Invalidated { reason } => {
                    return Ok(Dispatched::Invalidated { reason });
                }
                // D-502: "not now", not "never" — the requesting agent session
                // is paused, or (D-512) its daily write total is used up.
                // Nothing ran; `execute_approved` releases the claim so the
                // request is `approved` again for `retry-execution`.
                attome_ai::execute::ApprovedExecution::Deferred { reason } => {
                    return Ok(Dispatched::Deferred { reason });
                }
            }
        }
        // M07 Phase F (D-770): a state transition that required approval.
        // `attome_state::approval` moves the record from its pending state to
        // the requested one through the one write path, as the policy actor,
        // naming this request and `approver_id` on the audit event. A record
        // that changed underneath (row_version) is refused: `execute_approved`
        // invalidates the request and the record stays pending.
        attome_core::ACTION_STATE_TRANSITION => {
            match attome_state::approval::execute_approved_transition(state, request, approver_id)
                .await?
            {
                attome_state::approval::ExecutedTransition::Executed(result) => result,
                attome_state::approval::ExecutedTransition::Invalidated(reason) => {
                    return Ok(Dispatched::Invalidated { reason });
                }
            }
        }
        other => {
            return Err(AppError::internal(format!(
                "no execution handler registered for approved action_type {other:?} — see this \
                 module's doc comment for how to wire one"
            )));
        }
    };

    // D-518: this used to also finalize `approved -> executed` here (with its
    // D-541/D-062 audit hook) — moved to `execute_approved`, the only caller,
    // which now does that generically for every `Dispatched::Executed` via
    // `complete_execution_with` after the claim this function itself does not
    // take. See `execute_approved`.
    Ok(Dispatched::Executed(result))
}

/// The `decide` handler's [`attome_db::BeforeCommit`] hook: the decision's
/// `Approved`/`Rejected` event and its M58 decision digest (grant signature
/// plus `DecisionDigest` event) commit in the same transaction as the grant
/// row and status change (audit plan 3.6, D-062). Before this, both were
/// separate transactions after `decide()` committed and a failure was only
/// logged.
///
/// BAP-15 / BAP-F11: the same hook is also handed the request when the
/// decision found it past `expires_at` and flipped it to `expired`
/// (`attome_approval::decide_with`/`decide_step_with`). Nothing was decided
/// then — no grant row, no signature — so the event is the expiry itself;
/// asking `record_decision_digest_in_tx` for a digest of a grant that does
/// not exist is what turned this path into a 500.
struct DecisionAudit<'s> {
    state: &'s EngineState,
    decider_id: Uuid,
    decision: Decision,
    decision_word: &'s str,
    /// The approver's normalized decision comment, when they gave one —
    /// carried into the event's comment so the audit trail shows it next to
    /// the decision it explains.
    comment: Option<&'s str>,
}

impl attome_db::BeforeCommit<ApprovalRequest> for DecisionAudit<'_> {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        request: &'a ApprovalRequest,
    ) -> attome_db::HookFuture<'a> {
        Box::pin(async move {
            if request.status == ApprovalStatus::Expired {
                // The decision never happened: `decide_with` flipped an
                // already-expired request and is about to return `Conflict`.
                // Record the expiry (D-545's whole point on this path), and
                // skip the digest — there is no grant to digest.
                attome_audit::security::write_security_event(
                    tx,
                    &audit_service(self.state),
                    SecurityEvent::new(
                        MandatoryCategory::Security,
                        AuditOperation::Closed,
                        self.decider_id,
                        "approval_request",
                        Some(request.id),
                    )
                    .named(request.action_type.clone())
                    .comment(format!(
                        "four-eyes approval request {} expired before a {} decision could be recorded (past its backstop TTL)",
                        request.id, self.decision_word
                    )),
                )
                .await?;
                return Ok(());
            }
            let operation = match self.decision {
                Decision::Approve => AuditOperation::Approved,
                Decision::Reject => AuditOperation::Rejected,
            };
            attome_audit::security::write_security_event(
                tx,
                &audit_service(self.state),
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    operation,
                    self.decider_id,
                    "approval_request",
                    Some(request.id),
                )
                .named(request.action_type.clone())
                .comment(match self.comment {
                    Some(comment) => format!(
                        "four-eyes approval request {} step {} decided: {} (overall status: {}); comment: {comment}",
                        request.id, request.step, self.decision_word, request.status
                    ),
                    None => format!(
                        "four-eyes approval request {} step {} decided: {} (overall status: {})",
                        request.id, request.step, self.decision_word, request.status
                    ),
                }),
            )
            .await?;
            attome_audit::signoff::record_decision_digest_in_tx(
                tx,
                self.state,
                request,
                self.decider_id,
                self.decision,
            )
            .await?;
            Ok(())
        })
    }
}

// ── HTTP surface ─────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct ApprovalRequestView {
    id: Uuid,
    action_type: String,
    payload: Value,
    requested_by: Uuid,
    requested_at: DateTime<Utc>,
    status: String,
    required_approvals: i32,
    row_version: i64,
    expires_at: DateTime<Utc>,
    executed_at: Option<DateTime<Utc>>,
    /// D-421 — `Some` only for a request a policy (or a workflow approval
    /// node consulting one) supplied a multi-step plan for; `None` means
    /// this request still runs the original flat `required_approvals`
    /// model, decided via `POST .../decide` exactly as before.
    plan: Option<attome_approval::ApprovalPlan>,
    step: i32,
    step_started_at: Option<DateTime<Utc>>,
    escalated_at: Option<DateTime<Utc>>,
    policy_id: Option<Uuid>,
}

impl From<ApprovalRequest> for ApprovalRequestView {
    fn from(r: ApprovalRequest) -> Self {
        Self {
            id: r.id,
            action_type: r.action_type,
            payload: r.payload,
            requested_by: r.requested_by,
            requested_at: r.requested_at,
            status: r.status.to_string(),
            required_approvals: r.required_approvals,
            row_version: r.row_version,
            expires_at: r.expires_at,
            executed_at: r.executed_at,
            plan: r.plan,
            step: r.step,
            step_started_at: r.step_started_at,
            escalated_at: r.escalated_at,
            policy_id: r.policy_id,
        }
    }
}

#[derive(Deserialize, IntoParams)]
struct ListQuery {
    action_type: Option<String>,
    /// Comma-separated status filter, in the request's own vocabulary
    /// (`pending`, `approved`, `executing`, `rejected`, `expired`,
    /// `executed`, `cancelled`, `invalidated`). Defaults to `pending` —
    /// today's behavior. BAP-10: `approved` and `executing` are how an
    /// operator finds an approved-but-unexecuted action and a claim whose
    /// holder died; neither was listable before. An unknown name is `422`.
    status: Option<String>,
    /// One-based — the first page is `page=1` (D-347).
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/approvals` — `system.admin` only. Lists requests,
/// newest-first, optionally filtered to one `action_type` and to one or more
/// `status` values (default `pending`).
#[utoipa::path(
    get,
    path = "/api/v1/admin/approvals",
    tag = "admin",
    params(ListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ApprovalRequestView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_approvals(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ListQuery>,
) -> Result<Json<PaginatedResponse<ApprovalRequestView>>, AppError> {
    // Absent or empty means `pending`, exactly what this route always
    // listed; anything else is an explicit filter (BAP-10).
    let statuses = match q.status.as_deref().map(str::trim) {
        None | Some("") => vec![ApprovalStatus::Pending],
        Some(raw) => {
            let mut parsed = Vec::new();
            for name in raw.split(',') {
                let name = name.trim();
                if !name.is_empty() {
                    parsed.push(ApprovalStatus::parse_wire(name)?);
                }
            }
            if parsed.is_empty() {
                return Err(AppError::Validation(
                    "status must name at least one approval status".to_string(),
                ));
            }
            parsed
        }
    };
    // BAP-17: `page` is clamped (to `attome_types::MAX_PAGE`) as well as
    // `page_size`, so the route never hands the crate an offset it would have
    // to reject; `attome_approval::list_by_status` still guards its own
    // arithmetic for direct callers.
    let PageWindow {
        page, page_size, ..
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let (items, total) = attome_approval::list_by_status(
        &state.base.db,
        &statuses,
        q.action_type.as_deref(),
        page,
        page_size,
    )
    .await?;
    let items = items.into_iter().map(ApprovalRequestView::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// `GET /api/v1/admin/approvals/{id}` — `system.admin` reads any request;
/// the fleet console's rollout credential (`metadata.rollout`, D-792) reads
/// only a request it submitted itself (the `metadata.changeset_apply`
/// request its apply opened), so the console can follow it. Another
/// principal's request is `404`, never `403`, so the route does not confirm
/// that a request id exists. Read-only: no route that decides, cancels,
/// retries or delegates accepts the rollout credential.
#[utoipa::path(
    get,
    path = "/api/v1/admin/approvals/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = ApprovalRequestView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such request, or (rollout credential) a request it did not submit", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_approval(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalRequestView>, AppError> {
    let request = attome_approval::get(&state.base.db, id).await?;
    if !own_request_visible(ctx.is_admin, ctx.user_id, request.requested_by) {
        return Err(AppError::NotFound);
    }
    Ok(Json(request.into()))
}

/// D-792: an administrator sees every request; anyone else who passed the
/// `metadata.rollout` policy sees only the requests they submitted.
fn own_request_visible(is_admin: bool, caller: Uuid, requested_by: Uuid) -> bool {
    is_admin || caller == requested_by
}

#[derive(Deserialize, ToSchema)]
struct CancelBody {
    row_version: i64,
}

/// `POST /api/v1/admin/approvals/{id}/cancel` — `system.admin` only, and
/// further restricted to the request's own `requested_by` by
/// `attome_approval::cancel` itself (`Forbidden` otherwise) — the inverse of
/// `decide()`'s separation-of-duties check. Lets an admin withdraw a request
/// they no longer want decided (submitted in error, superseded, etc.)
/// without waiting out the full `approval.ttl_hours` for it to expire.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approvals/{id}/cancel",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Cancelled)])))),
    request_body = CancelBody,
    responses(
        (status = 200, description = "Success", body = ApprovalRequestView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_approval(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<CancelBody>,
) -> Result<Json<ApprovalRequestView>, AppError> {
    // Audit plan 3.6 / D-062: the cancellation and its event commit together.
    let audit = AuditHook::new(audit_service(&state), |request: &ApprovalRequest| {
        vec![HookEvent::Security(
            SecurityEvent::new(
                MandatoryCategory::Security,
                AuditOperation::Cancelled,
                ctx.user_id,
                "approval_request",
                Some(request.id),
            )
            .named(request.action_type.clone())
            .comment(format!(
                "four-eyes approval request {} cancelled by its own requester",
                request.id
            )),
        )]
    });
    // C10-A amendment: a conversation tool call gated on this request is
    // resolved in the cancellation's own transaction
    // (`approval.resolved{cancelled}`, `tool.call.failed{rejected}`).
    let hook = attome_db::Chain(
        &audit,
        &attome_ai::conversation_event::ApprovalConversationHook,
    );
    let request =
        attome_approval::cancel_with(&state.base.db, id, ctx.user_id, body.row_version, &hook)
            .await?;
    // M07 Phase F: a cancelled state-transition approval returns its record
    // to the origin state (a no-op for every other action type).
    attome_state::approval::settle_after_close(&state, &request, ctx.user_id, None).await;

    Ok(Json(request.into()))
}

#[derive(Deserialize, ToSchema)]
struct DecideBody {
    /// `"approve"` or `"reject"` — any other value is `422 Validation`.
    decision: String,
    row_version: i64,
    /// Optional note explaining the decision, stored on the decision's
    /// `approval_grant` row and in its audit event. Trimmed; blank
    /// is no comment; more than 2000 characters is `422 Validation`.
    #[serde(default)]
    #[schema(max_length = 2000)]
    comment: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct DecideResponse {
    id: Uuid,
    status: String,
    /// Present only when this decision closed the request as `Approved` and
    /// its action was executed in the same call — see `execute_approved`.
    executed: Option<Value>,
}

/// `POST /api/v1/admin/approvals/{id}/decide` — `system.admin` only.
/// `attome_approval::decide` enforces the separation-of-duties invariant
/// (`ctx.user_id` cannot be the request's own `requested_by`) and the
/// `row_version` CAS; see that function's doc comment. On `Approve` closing
/// the request (today's callers all use `required_approvals = 1`, so a
/// single approval always closes it), this call also executes the approved
/// action inline and returns its result in `executed` — the client does not
/// need a second call.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approvals/{id}/decide",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Approved),
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::DecisionDigest),
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute),
    ])))),
    request_body = DecideBody,
    responses(
        (status = 200, description = "Success", body = DecideResponse),
        (status = 409, description = "Stale row_version, or the request is already decided, expired, or being decided", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn decide_approval(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecideBody>,
) -> Result<Json<DecideResponse>, AppError> {
    do_decide(&state, ctx.user_id, id, body, RequirePlan::EitherKind)
        .await
        .map(Json)
}

/// The most requests one batch decides.
const MAX_BATCH: usize = 100;

/// One request of a batch, at the version the administrator looked at.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BatchItem {
    id: Uuid,
    row_version: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BatchDecideBody {
    /// `"approve"` or `"reject"`, for every request.
    decision: String,
    /// At most 100 requests, typically similar ones the administrator
    /// reviewed a sample of (`GET /api/v1/admin/approvals?action_type=...`).
    items: Vec<BatchItem>,
    #[serde(default)]
    #[schema(max_length = 2000)]
    comment: Option<String>,
}

/// One request's outcome in a batch.
#[derive(Serialize, ToSchema)]
struct BatchOutcome {
    id: Uuid,
    /// The request's status after the decision, or `null` when it failed.
    status: Option<String>,
    /// Why this one was not decided (stale version, already decided, the
    /// administrator's own request, ...); `null` on success.
    error: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct BatchDecideResponse {
    decided: usize,
    failed: usize,
    items: Vec<BatchOutcome>,
}

/// `POST /api/v1/admin/approvals/batch-decide` — decide many requests the
/// same way (roadmap N30-T6). Each is decided on its own through the exact
/// path a single decision takes ([`do_decide`]): its own row-version check,
/// separation of duties, transaction, audit events and, for an approval
/// that closes it, execution. One failing never stops the others; the
/// response says what happened to each.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approvals/batch-decide",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("do_decide"),
        "each request is decided through the single-decision path, which writes its own \
         Approved/Rejected event and decision digest in its own transaction"
    )))),
    request_body = BatchDecideBody,
    responses(
        (status = 200, description = "Each request's outcome", body = BatchDecideResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown decision, no items, more than 100, or a comment too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn batch_decide(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<BatchDecideBody>,
) -> Result<Json<BatchDecideResponse>, AppError> {
    if !matches!(body.decision.as_str(), "approve" | "reject") {
        return Err(AppError::Validation(format!(
            "decision must be \"approve\" or \"reject\", got {:?}",
            body.decision
        )));
    }
    if body.items.is_empty() || body.items.len() > MAX_BATCH {
        return Err(AppError::Validation(format!(
            "a batch decides 1 to {MAX_BATCH} requests"
        )));
    }
    let mut items = Vec::with_capacity(body.items.len());
    for item in &body.items {
        let decided = do_decide(
            &state,
            ctx.user_id,
            item.id,
            DecideBody {
                decision: body.decision.clone(),
                row_version: item.row_version,
                comment: body.comment.clone(),
            },
            RequirePlan::EitherKind,
        )
        .await;
        items.push(match decided {
            Ok(response) => BatchOutcome {
                id: item.id,
                status: Some(response.status),
                error: None,
            },
            Err(error) => BatchOutcome {
                id: item.id,
                status: None,
                error: Some(match &error {
                    AppError::Validation(m) => m.clone(),
                    AppError::FieldValidation(errors) => {
                        attome_types::types::FieldError::summary(errors)
                    }
                    AppError::Conflict(m) => (*m).to_string(),
                    AppError::Forbidden => "not allowed to decide this request".to_owned(),
                    AppError::NotFound => "no such request".to_owned(),
                    _ => "could not be decided".to_owned(),
                }),
            },
        });
    }
    let failed = items.iter().filter(|i| i.error.is_some()).count();
    Ok(Json(BatchDecideResponse {
        decided: items.len() - failed,
        failed,
        items,
    }))
}

/// Dashboard 10/10 Phase 6 prerequisite: whether the caller reached
/// [`do_decide`] through the admin route (any request) or the non-admin one
/// (plan-bearing only — a flat request has no eligible-approver concept
/// other than `system.admin`, so it stays admin-only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequirePlan {
    EitherKind,
    PlanOnly,
}

/// Shared body of [`decide_approval`] (admin, any request) and
/// [`decide_approval_eligible`] (any authenticated caller, plan-bearing
/// requests only). Eligibility for a plan-bearing request is enforced by
/// `attome_approval::decide_step_with` itself (`allowed_decider_ids.contains`,
/// checked unconditionally for every caller — see that function), so the
/// non-admin route needs no separate authorization check of its own beyond
/// [`RequirePlan::PlanOnly`]'s up-front kind check.
async fn do_decide(
    state: &EngineState,
    decider_id: Uuid,
    id: Uuid,
    body: DecideBody,
    require: RequirePlan,
) -> Result<DecideResponse, AppError> {
    let decision = match body.decision.as_str() {
        "approve" => Decision::Approve,
        "reject" => Decision::Reject,
        other => {
            return Err(AppError::Validation(format!(
                "decision must be \"approve\" or \"reject\", got {other:?}"
            )));
        }
    };

    // D-421 — a plan-bearing request is decided through
    // attome_audit::approval::decide_request_step (which resolves this step's
    // eligible approvers, including delegation, then calls
    // attome_approval::decide_step); every other request keeps using
    // attome_approval::decide exactly as before. A cheap read first, rather
    // than trying decide() and falling back, because the two entry points
    // need different arguments (decide_step needs the resolved eligible-id
    // list decide() has no use for) — there's no single call that could
    // serve both.
    // Rejected before any read, with the same rule the decision path
    // applies again inside its own transaction.
    let comment = attome_approval::normalize_decision_comment(body.comment.as_deref())?;

    let existing = attome_approval::get(&state.base.db, id).await?;
    if require == RequirePlan::PlanOnly && existing.plan.is_none() {
        return Err(AppError::Forbidden);
    }
    // Every successful decision (D-421: including an Approve that only
    // advances a step) writes its Approved/Rejected event and M58 decision
    // digest inside the decision's own transaction (audit plan 3.6).
    let audit = DecisionAudit {
        state,
        decider_id,
        decision,
        decision_word: body.decision.as_str(),
        comment: comment.as_deref(),
    };
    // C10-A: a conversation tool call gated on this request resolves in the
    // decision's own transaction (`approval.resolved`, and a rejection's
    // terminal `tool.call.failed`). A no-op for every other request.
    let hook = attome_db::Chain(
        &audit,
        &attome_ai::conversation_event::ApprovalConversationHook,
    );
    let request = if existing.plan.is_some() {
        attome_audit::approval::decide_request_step_with(
            state,
            &existing,
            decider_id,
            decision,
            body.row_version,
            comment.as_deref(),
            &hook,
        )
        .await?
    } else {
        attome_approval::decide_with(
            &state.base.db,
            id,
            decider_id,
            decision,
            body.row_version,
            comment.as_deref(),
            &hook,
        )
        .await?
    };

    // M07 Phase F (D-770): a rejected state-transition approval sends its
    // record to the transition's `on_reject_state`, with the rejection
    // comment on the record's audit event (a no-op for any other request).
    if request.status == ApprovalStatus::Rejected {
        attome_state::approval::settle_after_close(state, &request, decider_id, comment.as_deref())
            .await;
    }

    // D-518: the action runs only under this call's claim. A concurrent
    // `retry-execution` that claimed first runs it instead; this decision
    // still stands, so the response succeeds with no `executed` result. A
    // request with no dispatch arm is carried out by the engine that owns it
    // (D-551) and is never claimed here: it stays `approved` for that engine.
    let executed = if request.status == ApprovalStatus::Approved
        && has_execution_handler(&request.action_type)
    {
        match attome_approval::claim_execution(
            &state.base.db,
            request.id,
            request.row_version,
            decider_id,
        )
        .await
        {
            Ok(claimed) => Some(
                execute_approved(state, &claimed, decider_id)
                    .await?
                    .into_result()?,
            ),
            Err(AppError::Conflict(_) | AppError::VersionConflict) => None,
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    Ok(DecideResponse {
        id: request.id,
        status: request.status.to_string(),
        executed,
    })
}

/// `POST /api/v1/approvals/{id}/decide` — any authenticated caller (Dashboard
/// 10/10 Phase 6 prerequisite). Refuses a flat (non-plan) request with 403
/// before ever reaching `decide_step_with` — a flat request has no eligible-
/// approver concept other than `system.admin`, so it stays reachable only
/// through the admin route above. For a plan-bearing request, eligibility
/// (named approver, resolved role/team/position member, or an active
/// delegate of one) is enforced by `decide_step_with` itself; the caller
/// otherwise gets exactly the same 403 an ineligible admin would.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}/decide",
    tag = "approvals",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Approved),
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::DecisionDigest),
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute),
    ])))),
    request_body = DecideBody,
    responses(
        (status = 200, description = "Success", body = DecideResponse),
        (status = 409, description = "Stale row_version, or the request is already decided, expired, or being decided", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The request is flat (not plan-bearing), or the caller is not an eligible approver for its current step", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn decide_approval_eligible(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecideBody>,
) -> Result<Json<DecideResponse>, AppError> {
    do_decide(&state, ctx.user_id, id, body, RequirePlan::PlanOnly)
        .await
        .map(Json)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RetryExecutionParams {
    /// D-518 — only for a request whose earlier execution attempt passed its
    /// claim lease without finishing, so whether its action ran is unknown.
    /// Pass `true` after checking the action's effect: the action runs again,
    /// and the takeover is audited. Ignored in every other state.
    #[serde(default)]
    acknowledge_unknown_outcome: bool,
}

/// `POST /api/v1/admin/approvals/{id}/retry-execution` — `system.admin`
/// only. Recovery path for the gap `decide_approval` above has no answer
/// for: if execution fails AFTER `attome_approval::decide` already committed
/// `status = 'approved'`, the request could never be re-decided (`decide()`
/// only ever accepts a `Pending` request) and, before this endpoint existed,
/// had no way back to `executed` either — a permanently stuck
/// four-eyes-approved action.
///
/// **One execution per approval (D-518).** This claims the request
/// (`approved -> executing`) before running anything, as `decide_approval`
/// does, so two retries, or a retry racing the deciding call, never both run
/// the action; the loser gets `409`. By state:
/// - `approved` with no `executed_at`: claim, then run.
/// - `executing` inside the claim lease: `409`, another call is running it.
/// - `executing` past the lease: the earlier attempt died or hung, or its
///   close-out failed, and whether its action ran is unknown. `409` unless
///   `acknowledge_unknown_outcome=true`, which an admin passes only after
///   checking the action's effect; the takeover is audited before the action
///   runs again.
/// - anything else: `409`.
///
/// **Known limitation.** An executor error releases the claim, so a retry
/// re-runs that `do_*` from scratch. That is safe for a `do_*` that failed
/// outright (a transient DB/network error, so nothing was applied), not for
/// one that partially applied its effect and then failed. None of the
/// action_types wired today are known to do this (each is a single bounded
/// write or a single job-enqueue), but that has not been verified per
/// action_type.
///
/// Uses the retrying admin's own identity as `approver_id` for whatever the
/// executed action attributes it to (see `dispatch_approved`'s doc comment)
/// — the original approving admin's decision is already the `Approved`
/// audit event `decide_approval` wrote; this call's own audit event below
/// records who actually caused execution to run.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approvals/{id}/retry-execution",
    tag = "admin",
    params(("id" = Uuid, Path), RetryExecutionParams),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
    responses(
        (status = 200, description = "Success", body = DecideResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The request is not stuck approved, another call is executing it, or an unknown outcome was not acknowledged", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn retry_execution(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(params): Query<RetryExecutionParams>,
) -> Result<Json<DecideResponse>, AppError> {
    let request = attome_approval::get(&state.base.db, id).await?;
    let (claimed, taken_over) = match request.status {
        ApprovalStatus::Approved if request.executed_at.is_none() => {
            ensure_dispatchable(&request.action_type)?;
            let claimed = attome_approval::claim_execution(
                &state.base.db,
                request.id,
                request.row_version,
                ctx.user_id,
            )
            .await?;
            (claimed, None)
        }
        ApprovalStatus::Executing => {
            let Some(claim) = attome_approval::execution_claim(&state.base.db, request.id).await?
            else {
                // Closed or released between the read and now.
                return Err(AppError::VersionConflict);
            };
            if !claim.stale {
                return Err(AppError::Conflict(
                    "this request is being executed by another call; retry after its execution \
                     claim lease has passed",
                ));
            }
            if !params.acknowledge_unknown_outcome {
                return Err(AppError::Conflict(
                    "an earlier execution attempt of this request did not finish, so whether its \
                     action ran is unknown; check the action's effect, then retry with \
                     acknowledge_unknown_outcome=true",
                ));
            }
            ensure_dispatchable(&request.action_type)?;
            let claimed = attome_approval::take_over_stale_execution(
                &state.base.db,
                request.id,
                request.row_version,
                ctx.user_id,
            )
            .await?;
            tracing::warn!(
                request_id = %request.id,
                action_type = %request.action_type,
                previous_claimant = %claim.claimed_by,
                claimed_at = %claim.claimed_at,
                retrying_admin = %ctx.user_id,
                "stale execution claim taken over after the admin acknowledged an unknown \
                 outcome; the action runs again"
            );
            write_retry_audit(
                &state,
                ctx.user_id,
                &request,
                format!(
                    "four-eyes approval request {} execution claim taken over: the claim {} held \
                     since {} passed its lease without finishing, and the retrying admin \
                     acknowledged that its outcome is unknown",
                    request.id, claim.claimed_by, claim.claimed_at
                ),
            )
            .await;
            (claimed, Some(claim))
        }
        _ => {
            return Err(AppError::Conflict(
                "this request is not in a stuck approved-but-unexecuted state",
            ));
        }
    };

    let executed = execute_approved(&state, &claimed, ctx.user_id)
        .await?
        .into_result()?;

    let comment = match taken_over {
        None => format!(
            "four-eyes approval request {} execution retried and completed",
            request.id
        ),
        Some(claim) => format!(
            "four-eyes approval request {} execution retried and completed, after taking over \
             the unfinished claim {} held since {}",
            request.id, claim.claimed_by, claim.claimed_at
        ),
    };
    write_retry_audit(&state, ctx.user_id, &request, comment).await;

    Ok(Json(DecideResponse {
        id: request.id,
        status: request.status.to_string(),
        executed: Some(executed),
    }))
}

/// `retry_execution`'s audit event. Same known-gap posture as `gate()`'s
/// Submitted event: not atomic with the request's own commit, logged rather
/// than failing the response. (`decide_approval`'s own decision audit is now
/// atomic via its `DecisionAudit` hook — this one is not, since it records a
/// distinct event, "execution retried", separate from any decision.)
async fn write_retry_audit(
    state: &EngineState,
    admin_id: Uuid,
    request: &ApprovalRequest,
    comment: String,
) {
    let (user_ctx, organization_ref) =
        attome_records::entity_crud::fetch_audit_ctx(state, admin_id).await;
    let event = attome_audit::AuditEvent {
        organization_ref,
        category: attome_audit::AuditCategory::Security,
        entity_name: None,
        record_id: Some(request.id),
        operation: AuditOperation::Approved,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: attome_audit::AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(request.action_type.clone()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    };
    if let Err(e) = audit_service(state).write(event).await {
        tracing::error!(
            request_id = %request.id,
            error = %e,
            "failed to write approval-execution-retried audit event (see gate()'s known-gap doc comment)",
        );
    }
}

#[derive(Deserialize, ToSchema)]
struct DelegateBody {
    to_user_id: Uuid,
    /// Defaults to this request's own `expires_at` when omitted — see
    /// `attome_audit::approval::create_request_delegation`'s doc comment.
    valid_to: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct DelegateResponse {
    delegation_id: Uuid,
}

/// `POST /api/v1/admin/approvals/{id}/delegate` — `system.admin` only, D-421
/// / M10. Lets `ctx.user_id` (who must actually be one of the *named*
/// approvers on this request's current plan step — `create_request_delegation`
/// checks that, `Forbidden` otherwise) hand their standing on this request's
/// `action_type` to another user, for the rest of this request's window
/// unless `valid_to` narrows it. Only valid on a plan-bearing (policy-driven)
/// request — the original flat `required_approvals` model has no per-step
/// eligibility to delegate.
#[utoipa::path(
    post,
    path = "/api/v1/admin/approvals/{id}/delegate",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
    request_body = DelegateBody,
    responses(
        (status = 200, description = "Success", body = DelegateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delegate_approval(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<DelegateBody>,
) -> Result<Json<DelegateResponse>, AppError> {
    let request = attome_approval::get(&state.base.db, id).await?;
    let delegation_id = attome_audit::approval::create_request_delegation(
        &state,
        &request,
        ctx.user_id,
        body.to_user_id,
        body.valid_to,
    )
    .await?;
    // `create_request_delegation` writes the `Access` + `Grant` event in the
    // delegation's own transaction (audit plan 3.6).

    Ok(Json(DelegateResponse { delegation_id }))
}

#[derive(Deserialize, ToSchema)]
struct OutOfOfficeBody {
    /// Who decides your approvals while you are away.
    to_user: Uuid,
    valid_from: DateTime<Utc>,
    valid_to: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct OutOfOfficeResponse {
    delegation_id: Uuid,
}

#[derive(Serialize, ToSchema)]
struct OutOfOfficeEnded {
    /// How many current or future out-of-office delegations were ended.
    ended: u64,
}

/// `PUT /api/v1/approvals/out-of-office` (Z10-T7) — the signed-in user hands
/// their approval standing to another user while they are away. Acts only on
/// the caller's own id; an overlapping earlier out-of-office delegation is
/// replaced. `attome_audit::approval::upsert_absence_delegation` checks the
/// window and the delegate and writes the `Access` + `Grant` event with the
/// delegation.
#[utoipa::path(
    put,
    path = "/api/v1/approvals/out-of-office",
    tag = "approvals",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Grant)])))),
    request_body = OutOfOfficeBody,
    responses(
        (status = 200, description = "Success", body = OutOfOfficeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Delegating to yourself, an empty window, or an inactive delegate", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_out_of_office(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<OutOfOfficeBody>,
) -> Result<Json<OutOfOfficeResponse>, AppError> {
    let delegation_id = attome_audit::approval::upsert_absence_delegation(
        &state,
        ctx.user_id,
        body.to_user,
        body.valid_from,
        body.valid_to,
        "out_of_office",
    )
    .await?;
    Ok(Json(OutOfOfficeResponse { delegation_id }))
}

/// `DELETE /api/v1/approvals/out-of-office` (Z10-T7) — ends the signed-in
/// user's current and future out-of-office delegations.
#[utoipa::path(
    delete,
    path = "/api/v1/approvals/out-of-office",
    tag = "approvals",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Revoke)])))),
    responses(
        (status = 200, description = "Success", body = OutOfOfficeEnded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_out_of_office(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<OutOfOfficeEnded>, AppError> {
    let ended =
        attome_audit::approval::end_absence_delegation(&state, ctx.user_id, "out_of_office")
            .await?;
    Ok(Json(OutOfOfficeEnded { ended }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/approvals", get(list_approvals))
        .route("/api/v1/admin/approvals/{id}", get(get_approval))
        .route("/api/v1/admin/approvals/{id}/decide", post(decide_approval))
        .route("/api/v1/admin/approvals/batch-decide", post(batch_decide))
        .route("/api/v1/admin/approvals/{id}/cancel", post(cancel_approval))
        .route(
            "/api/v1/admin/approvals/{id}/retry-execution",
            post(retry_execution),
        )
        .route(
            "/api/v1/admin/approvals/{id}/delegate",
            post(delegate_approval),
        )
        .route(
            "/api/v1/approvals/{id}/decide",
            post(decide_approval_eligible),
        )
        .route(
            "/api/v1/approvals/out-of-office",
            axum::routing::put(put_out_of_office).delete(delete_out_of_office),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_approvals,
        get_approval,
        cancel_approval,
        decide_approval,
        batch_decide,
        retry_execution,
        delegate_approval,
        decide_approval_eligible,
        put_out_of_office,
        delete_out_of_office
    ),
    components(schemas(
        BatchItem,
        BatchDecideBody,
        BatchOutcome,
        BatchDecideResponse,
        OutOfOfficeBody,
        OutOfOfficeResponse,
        OutOfOfficeEnded
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rollout_credential_reads_only_its_own_request() {
        let me = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(own_request_visible(false, me, me));
        assert!(!own_request_visible(false, me, other));
        assert!(own_request_visible(true, me, other));
    }
}

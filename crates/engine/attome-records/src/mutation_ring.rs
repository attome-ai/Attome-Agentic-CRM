//! C-10 (M01 §7 Block B) — one orchestration helper for the sequence every
//! entity mutation needs after the row itself is written: the D-133 (2)
//! creator-share grant (create only), the `attome_document` file-field mirror
//! (D-36x), the audit header+detail write, the commit, and the post-commit
//! cache invalidation + sticky-primary rw-pin.
//!
//! Before this module existed, that sequence — plus the 4-line
//! `AuditService` constructor's `.new(..).with_ingest_capture(..)
//! .with_chainer_enabled(..).with_erasure_key(..)` builder and the 17-field
//! `AuditEvent` literal — was copy-pasted at every mutation call site in this crate
//! (`entity_crud/mutations.rs` ×6, `upsert.rs`, `related.rs` ×2, `merge.rs`)
//! plus `attome-server::communication` and `attome-workflow::scheduler`. Because
//! "grant the creator share" was one of those copy-pasted steps rather than
//! something the mutation primitive itself guaranteed, the workflow
//! scheduler's Create Record node (`attome-workflow/src/scheduler.rs::
//! execute_entity_write`) skipped it entirely — a record a workflow creates
//! was invisible to the user `instance.started_by` names, because nobody
//! ever wrote the `record_share` row `grant_creator_share` exists
//! for. That same call site also never wrote an audit event, never
//! invalidated any cache, and never took the sticky-primary rw-pin —
//! `commit_mutation` closes all four gaps structurally, the same way every
//! caller of `entity_mutation::create_one` already gets validation/
//! autovalue/rules for free rather than having to remember to ask for them.
//!
//! `commit_mutation` covers the common one-row-one-audit-event shape
//! (create, update, delete, restore, hard-delete, upsert, a relationship
//! link/unlink, the workflow scheduler's entity-write node,
//! `communication.rs`'s compose). [`MutationRing::commit_events`] covers the
//! one exception in scope for this item — `merge.rs`, which commits two
//! audit events (canonical + duplicate) in one transaction and has no
//! `MutationResult` of its own to give `commit_mutation`.
//!
//! `attome-workflow::scheduler::commit_checkpoint` also used to duplicate the
//! `AuditService` constructor's `new(...)` builder, but its shape (a loop writing one audit
//! event per dirty workflow node run, plus a conditional rollback on a lost
//! CAS) does not fit `MutationResult`/`Committed` at all — no row created or
//! updated by the generic entity engine, no share grant, no file mirror, no
//! privilege-grant/audit-user cache to invalidate. That site now calls
//! [`attome_audit::audit_service`] directly instead — the same canonical
//! builder this module uses internally — rather than being forced through a
//! ring shaped for a different kind of mutation.

use attome_audit::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext, AuditSource,
    AuditUserContext,
};
use attome_core::{AttrInfo, EngineState};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::Utc;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::entity_crud::{
    grant_creator_share, invalidate_audit_user_if_systemuser, invalidate_privilege_grant_target,
    invalidate_privilege_grant_user, sync_file_field_documents,
};
use crate::entity_mutation::MutationResult;

/// Who performed the mutation, bundled with the audit context every write
/// needs — the same `(AuditUserContext, Uuid)` pair `attome_audit::fetch_audit_ctx`
/// already returns, plus the acting user's id itself, so a caller builds this
/// once per request and hands it to every `commit_mutation`/`commit_events`
/// call the request makes.
pub struct MutationActor {
    pub acting_user_id: Uuid,
    pub user_context: AuditUserContext,
    pub org_ref: Uuid,
}

impl std::fmt::Debug for MutationActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationActor").finish_non_exhaustive()
    }
}

impl MutationActor {
    pub async fn fetch(state: &EngineState, acting_user_id: Uuid) -> Self {
        let (user_context, org_ref) = attome_audit::fetch_audit_ctx(state, acting_user_id).await;
        Self {
            acting_user_id,
            user_context,
            org_ref,
        }
    }
}

/// The caller-specific slice of the `AuditEvent` `commit_mutation` writes —
/// everything it cannot derive from the `MutationResult`, `AuditOperation`
/// and `MutationActor` alone. `category` defaults to `Entity`
/// ([`MutationAudit::new`]); `link_related`/`unlink_related` are the only
/// callers that override it to `Relationship`. `source` defaults to `Api`;
/// the workflow scheduler's entity-write node is the one caller in scope for
/// this item that overrides it to `Workflow`, matching every other audit
/// event that scheduler already writes (`commit_checkpoint`'s node-run
/// events).
pub struct MutationAudit {
    pub category: AuditCategory,
    pub source: AuditSource,
    pub event_name: Option<String>,
    pub event_comment: Option<String>,
    pub changed_fields: Vec<AuditFieldChange>,
    pub snapshot_json: Option<Value>,
}

impl std::fmt::Debug for MutationAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationAudit").finish_non_exhaustive()
    }
}

impl MutationAudit {
    pub fn new() -> Self {
        Self {
            category: AuditCategory::Entity,
            source: AuditSource::Api,
            event_name: None,
            event_comment: None,
            changed_fields: Vec::new(),
            snapshot_json: None,
        }
    }
}

impl Default for MutationAudit {
    fn default() -> Self {
        Self::new()
    }
}

/// Which of the two "only some mutations need this" steps `commit_mutation`
/// should run. Independent booleans, not derived from `AuditOperation`,
/// because `link_related`/`unlink_related` reuse `AuditOperation::Create`/
/// `SoftDelete` for something that is neither a row creation nor a row
/// deletion (see their own doc comments) — inferring from the operation
/// would hand a relationship join row a creator share, or a file-field
/// mirror pass, it has no use for.
#[derive(Clone, Copy, Default)]
pub struct MutationSideEffects {
    /// D-133 (2): the implicit `record_share` grant that makes a
    /// freshly created record visible to the user who created it. `true`
    /// for every genuine row creation (`create_one`'s result, an upsert's
    /// insert branch, `communication.rs`'s compose, the workflow
    /// scheduler's Create Record node) — never for update/delete/restore/
    /// relationship writes.
    pub grant_creator_share: bool,
    /// D-36x: reconcile this write's file-typed columns into the
    /// `attome_document` mirror. `true` only for interactive create/update of
    /// an entity through `entity_crud::mutations` — unchanged from before
    /// this module existed: upsert, the workflow scheduler and
    /// `communication.rs` never called this either, and C-10 is about
    /// deduplicating the orchestration these call sites already had, not
    /// adding new behavior to sites that never had it.
    pub mirror_file_fields: bool,
}

impl std::fmt::Debug for MutationSideEffects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationSideEffects")
            .finish_non_exhaustive()
    }
}

/// How `commit_mutation` should invalidate a cached direct-privilege-grant
/// row (`user_account_mm_privilege`) after commit — see
/// `entity_crud::invalidate_privilege_grant_target`'s own doc comment for why
/// a hard delete needs the `ByUser` variant instead of `ByRow`: its row is
/// physically gone from the table by the time this runs, so there is nothing
/// left for `ByRow`'s live-table fallback SELECT to find.
pub enum GrantInvalidation<'a> {
    /// Read `user_ref` from the given row when present, else fall back to a
    /// live-table SELECT by `record_id`. Pass the mutation's own `new_row`
    /// for create/update/restore, `None` for a soft delete (row still
    /// exists — only `is_active` flipped).
    ByRow(Option<&'a Value>),
    /// `user_ref`, already resolved by the caller from a pre-delete
    /// snapshot — the hard-delete case, whose row is gone from the table.
    ByUser(Option<Uuid>),
    /// This mutation cannot touch the privilege-grant entity (a relationship
    /// link/unlink, or any non-generic-entity write) — skip the check.
    Skip,
}

impl std::fmt::Debug for GrantInvalidation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantInvalidation").finish_non_exhaustive()
    }
}

/// The outcome of a committed ring call: the same [`MutationResult`] the
/// mutation primitive produced, plus the audit header id `write_in_tx`
/// returned, for a caller that wants to correlate the two.
pub struct Committed {
    pub result: MutationResult,
    /// `None` when plan 5.1's policy resolver gated this operation out (no
    /// ordinary event was written) — the mandatory `audit_config` change
    /// event, if any, still committed regardless (plan 5.2).
    pub audit_header_id: Option<Uuid>,
}

impl std::fmt::Debug for Committed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Committed").finish_non_exhaustive()
    }
}

/// C-10 — see this module's doc comment. Cheap to build (one borrow), so a
/// caller constructs one per request rather than holding it across requests.
pub struct MutationRing<'a> {
    state: &'a EngineState,
}

impl std::fmt::Debug for MutationRing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationRing").finish_non_exhaustive()
    }
}

impl<'a> MutationRing<'a> {
    pub fn new(state: &'a EngineState) -> Self {
        Self { state }
    }

    /// Commits one mutation: grants the creator share (if `effects` says
    /// to), mirrors file-typed fields into `attome_document` (if `effects` says
    /// to and the mutation produced a row), writes the audit header+detail
    /// in the same transaction, commits, then runs the post-commit cache
    /// invalidation and the sticky-primary rw-pin.
    ///
    /// `tx` is consumed either way: a failure at any step before the commit
    /// call rolls the whole mutation back (an uncommitted `Transaction`
    /// rolls back when sqlx drops it), and every step after commit is the
    /// documented best-effort, degrade-don't-fail posture the pre-ring call
    /// sites already had (see `invalidate_audit_user_if_systemuser`'s and
    /// `pin_write_with_current_lsn`'s own doc comments).
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_mutation(
        &self,
        mut tx: Transaction<'_, Postgres>,
        ctx: &SecurityContext,
        entity_id: Uuid,
        entity_name: &str,
        attrs: &[AttrInfo],
        actor: &MutationActor,
        operation: AuditOperation,
        effects: MutationSideEffects,
        grant_invalidation: GrantInvalidation<'_>,
        audit: MutationAudit,
        rw_pin_label: &str,
        result: MutationResult,
    ) -> Result<Committed, AppError> {
        if effects.grant_creator_share {
            grant_creator_share(&mut tx, entity_id, result.record_id, actor.acting_user_id).await?;
        }

        if effects.mirror_file_fields
            && let Some(row) = result.new_row.as_ref()
        {
            sync_file_field_documents(
                &mut tx,
                self.state,
                ctx,
                actor.acting_user_id,
                actor.org_ref,
                entity_name,
                result.record_id,
                attrs,
                row,
            )
            .await?;
        }

        // Plan 5.1: `commit_mutation` never carries a mandatory-category
        // event (those are written through `attome_audit::security`'s own
        // `SecurityTx`/`write_security_event`, never through here — the only
        // category any caller in this crate ever overrides `MutationAudit`'s
        // `Entity` default to is `Relationship`) — so the policy resolver
        // always applies to what this function writes, per I4/plan 5.2.
        let policy =
            attome_audit::policy_resolver::resolve_in(self.state, &mut tx, entity_name).await;

        // Plan 5.2: a change to `audit_config` itself is always a
        // mandatory `Configuration` event, in the same transaction, never
        // subject to the resolver above (which only gates the ordinary
        // `Entity` event below) — closing the gap where disabling audit on
        // the audit config entity would hide the disabling itself.
        if entity_name == attome_audit::AUDIT_CONFIG_ENTITY {
            let config_event = attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                operation,
                actor.acting_user_id,
                entity_name,
                Some(result.record_id),
            )
            .organization(actor.org_ref);
            attome_audit::security::write_security_event(
                &mut tx,
                &attome_audit::audit_service(self.state),
                config_event,
            )
            .await?;
        }

        // M07 Phase A (§4.1): the `state_transition` marker is written by
        // every update that moves a governed state field — a generic PATCH,
        // `/transition` (a thin caller of the same path), upsert — not only
        // by the retired `/transition` fast path. A caller's own event name
        // wins.
        let event_name = audit.event_name.or_else(|| {
            matches!(operation, AuditOperation::Update)
                .then(|| {
                    crate::entity_mutation::state_transition_event_name(
                        self.state,
                        entity_name,
                        result.old_row.as_ref(),
                        result.new_row.as_ref(),
                    )
                })
                .flatten()
        });

        let audit_header_id = if policy.permits(operation) {
            let changed_fields = audit
                .changed_fields
                .into_iter()
                .filter(|f| !policy.field_excluded(&f.field_name))
                .collect();
            let event = AuditEvent {
                organization_ref: actor.org_ref,
                category: audit.category,
                entity_name: Some(entity_name.to_owned()),
                record_id: Some(result.record_id),
                operation,
                version_before: None,
                version_after: None,
                user_context: actor.user_context.clone(),
                changed_on: Utc::now(),
                source: audit.source,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name,
                event_comment: audit.event_comment,
                changed_fields,
                snapshot_json: if policy.capture_snapshot {
                    audit.snapshot_json
                } else {
                    None
                },
            };
            Some(
                attome_audit::audit_service(self.state)
                    .write_in_tx(&mut tx, event)
                    .await?,
            )
        } else {
            None
        };

        attome_db::tx::commit(tx).await?;

        if entity_name == attome_audit::AUDIT_CONFIG_ENTITY {
            // The config row's own `entity_name`/`field_name` columns name
            // *which* entity's policy just changed — not necessarily this
            // one (this branch's `entity_name` is always the literal string
            // `"audit_config"`, the config table itself). Invalidate
            // broadly rather than parsing the mutated row here: this write
            // is rare (an admin editing audit rules), so an
            // over-invalidation is cheap, and a targeted invalidation that
            // silently missed the wrong row would leave a stale, wrong
            // policy cached for up to the TTL.
            if let Some(row) = result.new_row.as_ref()
                && let Some(target) = row.get("entity_name").and_then(Value::as_str)
            {
                attome_audit::policy_resolver::invalidate(self.state, target).await;
            }
        }

        invalidate_audit_user_if_systemuser(self.state, entity_name, result.record_id).await;
        match grant_invalidation {
            GrantInvalidation::ByRow(row) => {
                invalidate_privilege_grant_target(self.state, entity_name, result.record_id, row)
                    .await;
            }
            GrantInvalidation::ByUser(user_id) => {
                invalidate_privilege_grant_user(self.state, user_id).await;
            }
            GrantInvalidation::Skip => {}
        }

        crate::rw_pin::pin_write_with_current_lsn(self.state, ctx.user_id, rw_pin_label).await;

        Ok(Committed {
            result,
            audit_header_id,
        })
    }

    /// The merge shape: several audit events (`merge.rs` writes two — the
    /// canonical record's `Update` and the retired duplicate's
    /// `SoftDelete`) committed together in the caller's already-open
    /// transaction, with one shared rw-pin afterward. No share grant, no
    /// file mirror, no privilege-grant/audit-user invalidation: a merge
    /// neither creates a row nor touches a file-typed column for either
    /// participant, and today's merge path has never invalidated either
    /// cache (not a gap this item closes — see the M01 §7 remediation list
    /// for that class of fix, if one is ever found for merge specifically).
    pub async fn commit_events(
        &self,
        mut tx: Transaction<'_, Postgres>,
        events: Vec<AuditEvent>,
        rw_pin_user_id: Uuid,
        rw_pin_label: &str,
    ) -> Result<Vec<Uuid>, AppError> {
        let audit_service = attome_audit::audit_service(self.state);
        let mut header_ids = Vec::with_capacity(events.len());
        for event in events {
            header_ids.push(audit_service.write_in_tx(&mut tx, event).await?);
        }
        attome_db::tx::commit(tx).await?;
        crate::rw_pin::pin_write_with_current_lsn(self.state, rw_pin_user_id, rw_pin_label).await;
        Ok(header_ids)
    }
}

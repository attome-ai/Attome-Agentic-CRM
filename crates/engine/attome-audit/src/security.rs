//! The mandatory security writer (audit plan items 3.2 and 3.3; D-541 rule 4,
//! D-542 rule 4).
//!
//! Every `Security`, `Credential`, `Access`, `License`, `Configuration` and
//! `Ai` event goes through [`write_security_event`]. It:
//!
//! - takes a [`SecurityEvent`], whose constructor only accepts a
//!   [`MandatoryCategory`], so an `Entity` event cannot be routed here;
//! - writes inside the caller's transaction (D-062), so the mutation and its
//!   event commit or roll back together;
//! - never reads `audit_config` or attribute `is_audited` — those govern
//!   record and field data capture only (D-541 rule 4);
//! - writes hash v2 through [`AuditService`], including the outcome and count
//!   columns (D-541 rule 3).
//!
//! [`SecurityTx`] is the compile-time half of D-542 rule 4 for handlers that
//! run their own SQL: the only way to obtain the audited transaction is to
//! hand it the event up front, and [`SecurityTx::commit`] writes that event
//! before committing. A mutation that forgets its event therefore does not
//! compile against this type, and one that errors out rolls back with no
//! event, never a dangling one.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use attome_config::KeyRing;
use attome_core::{AuditSigner, EngineState};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::Utc;
use sqlx::Postgres;
use uuid::Uuid;

use crate::initiator::Attribution;
use crate::model::{
    AuditCategory, AuditEvent, AuditOperation, AuditOutcome, AuditRequestContext, AuditSource,
    AuditUserContext, EventExtras,
};
use crate::service::AuditService;

/// The categories of invariant I4 — the only ones [`SecurityEvent`] accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandatoryCategory {
    /// Authentication (login, logout, failed login, account state), erasure,
    /// and access to the audit trail itself.
    Security,
    Credential,
    Access,
    License,
    Configuration,
    Ai,
}

impl MandatoryCategory {
    pub const fn category(self) -> AuditCategory {
        match self {
            Self::Security => AuditCategory::Security,
            Self::Credential => AuditCategory::Credential,
            Self::Access => AuditCategory::Access,
            Self::License => AuditCategory::License,
            Self::Configuration => AuditCategory::Configuration,
            Self::Ai => AuditCategory::Ai,
        }
    }
}

impl AuditCategory {
    /// Whether D-541 rule 4 makes this category mandatory (invariant I4).
    pub const fn is_mandatory(self) -> bool {
        matches!(
            self,
            Self::Security
                | Self::Credential
                | Self::Access
                | Self::License
                | Self::Configuration
                | Self::Ai
        )
    }
}

/// The `x-audit` OpenAPI extension value for a handler (D-542 rule 1), built
/// from compile-checked enum variants:
///
/// ```ignore
/// #[utoipa::path(post, path = "...",
///     extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
///         (AuditCategory::Access, AuditOperation::Create),
///     ])))),
/// )]
/// ```
///
/// `policy` is derived, so it can never contradict the categories: mandatory
/// when any event's category is, `entity_policy` otherwise.
pub fn x_audit(events: &[(AuditCategory, AuditOperation)]) -> serde_json::Value {
    let mandatory = events.iter().any(|(c, _)| c.is_mandatory());
    serde_json::json!({
        "events": events
            .iter()
            .map(|(c, o)| serde_json::json!({
                "category": c.wire_name(),
                "operation": o.wire_name(),
            }))
            .collect::<Vec<_>>(),
        "policy": if mandatory { "mandatory" } else { "entity_policy" },
    })
}

/// The closed D-542 rule 1 set of `x-audit-exempt` reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExemptReason {
    /// Non-GET method, no persistent state change.
    ReadOnly,
    /// Computes and returns a plan or estimate; writes nothing.
    DryRun,
    /// The state change and its event happen elsewhere (`via`).
    Delegated,
    /// Client telemetry with no business or security effect.
    Telemetry,
    /// The caller's own UI state, with no security, sharing or business effect.
    UserPreference,
    /// Dev-only tooling gated off in production, writes to the local
    /// filesystem only, never touches customer data or metadata (D-542
    /// amendment, 2026-09-18).
    DevTooling,
}

impl ExemptReason {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::DryRun => "dry_run",
            Self::Delegated => "delegated",
            Self::Telemetry => "telemetry",
            Self::UserPreference => "user_preference",
            Self::DevTooling => "dev_tooling",
        }
    }
}

/// The `x-audit-exempt` OpenAPI extension value (D-542 rule 1). Every use is
/// reviewed by hand (the exemptions file went with the coverage script, D-768).
pub fn x_audit_exempt(reason: ExemptReason, via: Option<&str>, note: &str) -> serde_json::Value {
    serde_json::json!({
        "reason": reason.wire_name(),
        "via": via,
        "note": note,
    })
}

/// One mandatory-category audit event. Build it with [`SecurityEvent::new`]
/// and the chained setters, then hand it to [`write_security_event`] or
/// [`SecurityTx::begin`].
#[must_use = "a SecurityEvent does nothing until it is written"]
#[derive(Clone, Debug)]
pub struct SecurityEvent {
    category: MandatoryCategory,
    operation: AuditOperation,
    actor_user_id: Uuid,
    entity_name: String,
    record_id: Option<Uuid>,
    organization_ref: Option<Uuid>,
    event_name: Option<String>,
    event_comment: Option<String>,
    source: AuditSource,
    request_context: AuditRequestContext,
    attribution: Option<Attribution>,
    extras: EventExtras,
}

impl SecurityEvent {
    /// `actor_user_id` is the authenticated caller, or `Uuid::nil()` for an
    /// unauthenticated one (a failed login, D-541 rule 6). `entity_name` is
    /// the security table the event is about; `record_id` the row, when known.
    pub fn new(
        category: MandatoryCategory,
        operation: AuditOperation,
        actor_user_id: Uuid,
        entity_name: impl Into<String>,
        record_id: Option<Uuid>,
    ) -> Self {
        Self {
            category,
            operation,
            actor_user_id,
            entity_name: entity_name.into(),
            record_id,
            organization_ref: None,
            event_name: None,
            event_comment: None,
            source: AuditSource::Api,
            request_context: AuditRequestContext::default(),
            attribution: None,
            extras: EventExtras::default(),
        }
    }

    /// A short machine-readable label (for example the provider of a
    /// federated sign-in, or the window bounds of a coalesced failure).
    pub fn named(mut self, event_name: impl Into<String>) -> Self {
        self.event_name = Some(event_name.into());
        self
    }

    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.event_comment = Some(comment.into());
        self
    }

    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.extras.outcome = Some(outcome);
        self
    }

    /// C19: the provider model id an AI action ran under.
    pub fn ai_model(mut self, model_id: impl Into<String>) -> Self {
        self.extras.ai_model_id = Some(model_id.into());
        self
    }

    /// C19: the approval request an AI action was executed under.
    pub fn approval_request(mut self, approval_request_id: Uuid) -> Self {
        self.extras.approval_request_ref = Some(approval_request_id);
        self
    }

    pub fn occurrence_count(mut self, count: i32) -> Self {
        self.extras.occurrence_count = Some(count);
        self
    }

    pub fn source(mut self, source: AuditSource) -> Self {
        self.source = source;
        self
    }

    /// Overrides the organization, which otherwise comes from the actor's
    /// `user_account` row (or the root organization for a nil actor).
    pub fn organization(mut self, organization_ref: Uuid) -> Self {
        self.organization_ref = Some(organization_ref);
        self
    }

    /// An agent- or system-initiated action (C19). Defaults to the actor as a
    /// plain user.
    /// Makes a web portal user the actor (D-576 item 6): `actor_user_id` is
    /// the `webportal_user` id and the attribution is
    /// `Initiator::PortalUser`, so no reader can take the id for a staff user.
    pub fn portal_actor(mut self, webportal_user_id: Uuid) -> Self {
        self.actor_user_id = webportal_user_id;
        self.attribution = Some(Attribution::portal_user(webportal_user_id));
        self
    }

    /// The inbound request's client address and browser (web portal plan
    /// G-7). Defaults to empty, as it always has for callers that don't set it.
    pub fn with_request_context(mut self, request_context: AuditRequestContext) -> Self {
        self.request_context = request_context;
        self
    }

    pub fn attributed(mut self, attribution: Attribution) -> Self {
        self.attribution = Some(attribution);
        self
    }

    /// For a mutation whose row id is only known after its insert.
    pub fn set_record_id(&mut self, record_id: Uuid) {
        self.record_id = Some(record_id);
    }

    /// For a comment that depends on what the mutation found.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.event_comment = Some(comment.into());
    }

    pub fn set_event_name(&mut self, event_name: impl Into<String>) {
        self.event_name = Some(event_name.into());
    }

    pub fn set_operation(&mut self, operation: AuditOperation) {
        self.operation = operation;
    }

    pub fn set_outcome(&mut self, outcome: AuditOutcome) {
        self.extras.outcome = Some(outcome);
    }

    pub fn category(&self) -> AuditCategory {
        self.category.category()
    }

    pub fn operation(&self) -> AuditOperation {
        self.operation
    }

    pub fn record_id(&self) -> Option<Uuid> {
        self.record_id
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct ActorRow {
    pub(crate) user_name: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) organization_ref: Option<Uuid>,
}

/// Reads the actor's display fields inside `tx`, so an event names its actor
/// as of the mutation. `None` for a nil (unauthenticated) actor or an
/// unknown id.
pub(crate) async fn read_actor(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    actor_user_id: Uuid,
) -> Result<Option<ActorRow>, AppError> {
    if actor_user_id.is_nil() {
        return Ok(None);
    }
    sqlx::query_as::<_, ActorRow>(
        "SELECT user_name, email, organization_ref FROM user_account WHERE id = $1",
    )
    .bind(actor_user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Writes one mandatory-category event in `tx`. Never consults
/// `audit_config` (D-541 rule 4). The actor's display fields are read
/// inside the same transaction, so the event names the actor as of the
/// mutation.
pub async fn write_security_event(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    audit: &AuditService<'_>,
    event: SecurityEvent,
) -> Result<Uuid, AppError> {
    // A portal user is not a staff user: never look their id up in
    // `user_account` (D-576 item 6). Display fields are not hashed.
    let is_portal_actor = event
        .attribution
        .as_ref()
        .is_some_and(|a| a.initiator == crate::initiator::Initiator::PortalUser);
    let actor = if is_portal_actor {
        None
    } else {
        read_actor(tx, event.actor_user_id).await?
    };

    let organization_ref = event
        .organization_ref
        .or_else(|| actor.as_ref().and_then(|a| a.organization_ref))
        .unwrap_or(attome_core::ROOT_ORGANIZATION_ID);
    let (user_name, user_email) = actor
        .map(|a| (a.user_name.unwrap_or_default(), a.email.unwrap_or_default()))
        .unwrap_or_default();

    let attribution = event
        .attribution
        .unwrap_or_else(|| Attribution::user(event.actor_user_id));

    let audit_event = AuditEvent {
        organization_ref,
        category: event.category.category(),
        entity_name: Some(event.entity_name),
        record_id: event.record_id,
        operation: event.operation,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: event.actor_user_id,
            user_name: user_name.clone(),
            user_display_name: user_name,
            user_email,
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: event.source,
        request_context: event.request_context,
        correlation_id: None,
        batch_id: None,
        event_name: event.event_name,
        event_comment: event.event_comment,
        changed_fields: vec![],
        snapshot_json: None,
    };

    audit
        .write_in_tx_with_extras(tx, audit_event, attribution, event.extras)
        .await
}

/// One event an [`AuditHook`] writes.
#[derive(Clone, Debug)]
pub enum HookEvent {
    Security(SecurityEvent),
    Business(crate::business::BusinessEvent),
}

/// A [`attome_db::BeforeCommit`] hook that writes audit events inside a
/// base-layer transaction, just before it commits (D-062). `build` maps the
/// value the base function is about to return to the events to write; an
/// empty list writes nothing, and a failed write rolls the base mutation back.
///
/// This is how an `xrm-*` caller audits a mutation owned by a `base-*` crate
/// that cannot depend on this one (layer guard): for example
/// `attome_approval::decide_with(.., &AuditHook::new(audit, |request| ..))`.
pub struct AuditHook<'s, F> {
    audit: AuditService<'s>,
    build: F,
}

impl<'s, F> std::fmt::Debug for AuditHook<'s, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditHook").finish_non_exhaustive()
    }
}

impl<'s, F> AuditHook<'s, F> {
    pub fn new(audit: AuditService<'s>, build: F) -> Self {
        Self { audit, build }
    }
}

impl<T, F> attome_db::BeforeCommit<T> for AuditHook<'_, F>
where
    T: ?Sized + Sync,
    F: Fn(&T) -> Vec<HookEvent> + Send + Sync,
{
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        committed: &'a T,
    ) -> attome_db::HookFuture<'a> {
        let events = (self.build)(committed);
        Box::pin(async move {
            for event in events {
                match event {
                    HookEvent::Security(e) => {
                        write_security_event(tx, &self.audit, e).await?;
                    }
                    HookEvent::Business(e) => {
                        crate::business::write_business_event_in_tx(tx, &self.audit, e).await?;
                    }
                }
            }
            Ok(())
        })
    }
}

/// The common [`AuditHook`] for a base-layer account mutation: one event whose
/// actor and record are the account id the base function committed for
/// (self-service MFA, sign-in, logout, password reset, email verification).
pub fn account_event_hook<'s>(
    audit: AuditService<'s>,
    category: MandatoryCategory,
    operation: AuditOperation,
    entity_name: &'static str,
    event_name: impl Into<String>,
) -> AuditHook<'s, impl Fn(&Uuid) -> Vec<HookEvent> + Send + Sync> {
    let event_name = event_name.into();
    AuditHook::new(audit, move |user_id: &Uuid| {
        vec![HookEvent::Security(
            SecurityEvent::new(category, operation, *user_id, entity_name, Some(*user_id))
                .named(event_name.clone()),
        )]
    })
}

/// An owned handle on everything [`AuditService`] needs, for callers that hold
/// a base `AppState` rather than an `EngineState` (the `crates/server` auth
/// routes receive it as an `Extension`).
#[derive(Clone)]
pub struct SecurityAuditor {
    db: DbPool,
    signer: Option<Arc<AuditSigner>>,
    erasure_key: Option<KeyRing>,
    ingest_capture_enabled: bool,
    chainer_enabled: bool,
}

impl std::fmt::Debug for SecurityAuditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityAuditor").finish_non_exhaustive()
    }
}

impl SecurityAuditor {
    pub fn from_state(state: &EngineState) -> Self {
        Self {
            db: state.base.db.clone(),
            signer: state.audit_signer.clone(),
            erasure_key: state.audit_erasure_key.clone(),
            ingest_capture_enabled: state.base.config.audit.ingest_capture_enabled,
            chainer_enabled: state.base.config.audit.chainer_enabled,
        }
    }

    pub fn service(&self) -> AuditService<'_> {
        AuditService::new(&self.db, self.signer.as_deref())
            .with_ingest_capture(self.ingest_capture_enabled)
            .with_chainer_enabled(self.chainer_enabled)
            .with_erasure_key(self.erasure_key.clone())
    }

    /// Opens an audited transaction on this auditor's pool.
    pub async fn begin(&self, event: SecurityEvent) -> Result<SecurityTx<'_>, AppError> {
        SecurityTx::begin_with(self.service(), &self.db, event).await
    }

    /// Writes one event in its own transaction. For an event that records
    /// something the base layer already committed (a session issued by
    /// `attome-auth`, which cannot depend on this crate), or an event with no
    /// mutation of its own (a failed login).
    pub async fn write(&self, event: SecurityEvent) -> Result<Uuid, AppError> {
        let mut tx = attome_db::tx::begin(&self.db).await?;
        let id = write_security_event(&mut tx, &self.service(), event).await?;
        attome_db::tx::commit(tx).await?;
        Ok(id)
    }
}

/// A transaction that cannot commit without writing its [`SecurityEvent`].
///
/// Dereferences to the connection, so a handler runs its mutation with
/// `.execute(&mut *stx)` exactly as it would against a plain transaction.
/// Dropping it without [`commit`](Self::commit) rolls back the mutation and
/// writes nothing.
pub struct SecurityTx<'a> {
    audit: AuditService<'a>,
    tx: attome_db::Tx<'a>,
    event: SecurityEvent,
}

impl std::fmt::Debug for SecurityTx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityTx").finish_non_exhaustive()
    }
}

impl<'a> SecurityTx<'a> {
    /// Opens an audited transaction on `state`'s primary pool.
    pub async fn begin(state: &'a EngineState, event: SecurityEvent) -> Result<Self, AppError> {
        Self::begin_with(crate::user_ctx::audit_service(state), &state.base.db, event).await
    }

    pub async fn begin_with(
        audit: AuditService<'a>,
        db: &'a DbPool,
        event: SecurityEvent,
    ) -> Result<Self, AppError> {
        let tx = attome_db::tx::begin(db).await?;
        Ok(Self { audit, tx, event })
    }

    /// The event this transaction will write, for details only known after
    /// the mutation (an inserted row's id, the operation a branch took).
    pub fn event_mut(&mut self) -> &mut SecurityEvent {
        &mut self.event
    }

    /// The underlying transaction, for helpers that take `&mut Transaction`.
    pub fn tx(&mut self) -> &mut attome_db::Tx<'a> {
        &mut self.tx
    }

    /// Writes the event in this transaction, then commits both.
    pub async fn commit(mut self) -> Result<Uuid, AppError> {
        let id = write_security_event(&mut self.tx, &self.audit, self.event).await?;
        attome_db::tx::commit(self.tx).await?;
        Ok(id)
    }
}

impl Deref for SecurityTx<'_> {
    type Target = sqlx::PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for SecurityTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mandatory_category_maps_to_its_d541_value() {
        use MandatoryCategory as M;
        let expected = [
            (M::Security, 1),
            (M::Credential, 5),
            (M::Access, 6),
            (M::License, 8),
            (M::Configuration, 7),
            (M::Ai, 9),
        ];
        for (m, value) in expected {
            assert_eq!(m.category() as i32, value, "{m:?}");
        }
    }

    #[test]
    fn x_audit_derives_policy_from_the_categories() {
        let v = x_audit(&[(AuditCategory::Access, AuditOperation::Grant)]);
        assert_eq!(
            v,
            serde_json::json!({
                "events": [{"category": "access", "operation": "grant"}],
                "policy": "mandatory",
            })
        );
        let v = x_audit(&[(AuditCategory::Entity, AuditOperation::Create)]);
        assert_eq!(v["policy"], "entity_policy");
    }

    #[test]
    fn builder_carries_outcome_and_occurrence_count() {
        let mut e = SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::FailedLogin,
            Uuid::nil(),
            "user_account",
            None,
        )
        .outcome(AuditOutcome::Failed)
        .occurrence_count(3)
        .named("failed_login");
        e.set_record_id(Uuid::nil());
        assert_eq!(e.extras.outcome, Some(AuditOutcome::Failed));
        assert_eq!(e.extras.occurrence_count, Some(3));
        assert_eq!(e.category(), AuditCategory::Security);
        assert_eq!(e.record_id(), Some(Uuid::nil()));
    }
}

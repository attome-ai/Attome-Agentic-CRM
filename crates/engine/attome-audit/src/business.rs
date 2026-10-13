//! The in-transaction `BusinessEvent` writer (audit plan item 3.6, D-062).
//!
//! [`crate::write_business_event`] predates this module: it opens its own
//! transaction after the caller's mutation committed and only logs a failed
//! write, so a mutation can commit with no event. New call sites, and every
//! side path the plan names (3.6), write through [`write_business_event_in_tx`]
//! instead, in the mutation's own transaction, so a failed audit append rolls
//! the mutation back.
//!
//! `BusinessEvent` is not a mandatory category (D-541 rule 4), but it is not
//! governed by `audit_config` either, so this writer never consults it.

use chrono::Utc;
use sqlx::Postgres;
use uuid::Uuid;

use attome_types::AppError;

use crate::initiator::Attribution;
use crate::model::{
    AuditCategory, AuditEvent, AuditOperation, AuditOutcome, AuditRequestContext, AuditSource,
    AuditUserContext, EventExtras,
};
use crate::security::read_actor;
use crate::service::AuditService;

/// One `BusinessEvent`-category audit event. Build it with
/// [`BusinessEvent::new`] and the chained setters, then hand it to
/// [`write_business_event_in_tx`].
#[must_use = "a BusinessEvent does nothing until it is written"]
#[derive(Clone, Debug)]
pub struct BusinessEvent {
    entity_name: String,
    record_id: Uuid,
    operation: AuditOperation,
    event_name: String,
    actor_user_id: Uuid,
    version_before: Option<i64>,
    version_after: Option<i64>,
    comment: Option<String>,
    source: AuditSource,
    attribution: Option<Attribution>,
    extras: EventExtras,
}

impl BusinessEvent {
    pub fn new(
        entity_name: impl Into<String>,
        record_id: Uuid,
        operation: AuditOperation,
        event_name: impl Into<String>,
        actor_user_id: Uuid,
    ) -> Self {
        Self {
            entity_name: entity_name.into(),
            record_id,
            operation,
            event_name: event_name.into(),
            actor_user_id,
            version_before: None,
            version_after: None,
            comment: None,
            source: AuditSource::Api,
            attribution: None,
            extras: EventExtras::default(),
        }
    }

    pub fn versions(mut self, before: Option<i64>, after: Option<i64>) -> Self {
        self.version_before = before;
        self.version_after = after;
        self
    }

    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    pub fn source(mut self, source: AuditSource) -> Self {
        self.source = source;
        self
    }

    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.extras.outcome = Some(outcome);
        self
    }

    /// An agent- or system-initiated action (C19). Defaults to the actor as a
    /// plain user.
    pub fn attributed(mut self, attribution: Attribution) -> Self {
        self.attribution = Some(attribution);
        self
    }
}

/// Writes one `BusinessEvent` in `tx`, so it commits or rolls back with the
/// mutation it records (D-062). The actor's display fields are read inside
/// the same transaction.
pub async fn write_business_event_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    audit: &AuditService<'_>,
    event: BusinessEvent,
) -> Result<Uuid, AppError> {
    let actor = read_actor(tx, event.actor_user_id).await?;
    let organization_ref = actor
        .as_ref()
        .and_then(|a| a.organization_ref)
        .unwrap_or(attome_core::ROOT_ORGANIZATION_ID);
    let (user_name, user_email) = actor
        .map(|a| (a.user_name.unwrap_or_default(), a.email.unwrap_or_default()))
        .unwrap_or_default();
    let attribution = event
        .attribution
        .unwrap_or_else(|| Attribution::user(event.actor_user_id));

    let audit_event = AuditEvent {
        organization_ref,
        category: AuditCategory::BusinessEvent,
        entity_name: Some(event.entity_name),
        record_id: Some(event.record_id),
        operation: event.operation,
        version_before: event.version_before,
        version_after: event.version_after,
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
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event.event_name),
        event_comment: event.comment,
        changed_fields: vec![],
        snapshot_json: None,
    };
    audit
        .write_in_tx_with_extras(tx, audit_event, attribution, event.extras)
        .await
}

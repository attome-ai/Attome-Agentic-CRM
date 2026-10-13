//! Ambient per-request audit context (Phase 4 item 4.1).
//!
//! `AuditEvent`/`AuditRequestContext` are constructed as full struct literals
//! at ~50 call sites across the workspace (`correlation_id: None`,
//! `request_context: AuditRequestContext::default()`, ...), each too deep in
//! the engine layer to hold an HTTP request. Rather than thread a request
//! context parameter through every one of those signatures,
//! `AuditService::write_in_tx_with_extras` (the one function every writer
//! funnels through) backfills any event whose caller left
//! `correlation_id`/`request_context` at their all-`None` defaults from
//! `attome_server::current_request_meta()` — the ambient per-request task-local
//! `attome-server`'s `request_meta` middleware already populates (same
//! `tokio::task_local!` shape `attome_profiler::scope` uses). `attome-server`
//! owns that task-local because it, not `attome-audit`, has the
//! `RequestId`/`ConnectInfo` machinery to fill it (CLAUDE.md's layer
//! direction: `xrm-*` depends on `base-*`, never the reverse) — this module
//! is just the adapter that reads it and shapes it for an `AuditEvent`. A
//! no-op outside an active request (job workers, tests, boot-time code),
//! same as `attome_profiler`.
//!
//! **Known gaps, not implemented here:**
//! - `session_id`: the header table has no column for it, and adding one on
//!   the partitioned, hash-v2-canonicalized `audit_header`/
//!   `audit_ingest` schema needs its own migration and hash-version
//!   review (D-539 ruling 4 — the digest covers exactly what gets stored)
//!   rather than being folded into this change.
//! - `device_type` (0=Desktop/1=Tablet/2=Mobile): no user-agent sniffing
//!   exists anywhere in this codebase to derive it from; stays `None`.
//! - A well-formed but non-UUID client-supplied `x-request-id`
//!   (`drop_unsafe_request_id`'s doc: a value matching
//!   `[A-Za-z0-9._-]{1,64}` survives even if the client sent it, not just the
//!   server-generated `MakeRequestUuid` default) does not parse as a `Uuid`
//!   and so does not populate `correlation_id` for that request.

use uuid::Uuid;

/// Fills `correlation_id`/`ip_address`/`browser` on `event` from
/// `attome_server::current_request_meta()`, but only where the caller left the
/// all-`None` default — never overwrites a value a caller explicitly set
/// (Phase 3.10's `batch_id`-linked parent events, the workflow scheduler's
/// instance-id correlation, and any test fixture that pins a specific
/// request context all keep exactly what they set). A no-op outside an
/// active request.
pub(crate) fn backfill(event: &mut crate::model::AuditEvent) {
    let meta = attome_server::current_request_meta();
    if event.correlation_id.is_none()
        && let Some(request_id) = &meta.request_id
        && let Ok(parsed) = Uuid::parse_str(request_id)
    {
        event.correlation_id = Some(parsed);
    }
    if event.request_context.ip_address.is_none() {
        event.request_context.ip_address = meta.ip_address;
    }
    if event.request_context.browser.is_none() {
        event.request_context.browser = meta.user_agent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource,
        AuditUserContext,
    };
    use attome_server::RequestMeta;

    fn bare_event() -> AuditEvent {
        AuditEvent {
            organization_ref: Uuid::nil(),
            category: AuditCategory::BusinessEvent,
            entity_name: None,
            record_id: None,
            operation: AuditOperation::Create,
            version_before: None,
            version_after: None,
            user_context: AuditUserContext {
                user_id: Uuid::nil(),
                user_name: String::new(),
                user_display_name: String::new(),
                user_email: String::new(),
                user_job_ref: None,
                user_job_name: None,
            },
            changed_on: chrono::Utc::now(),
            source: AuditSource::Api,
            request_context: AuditRequestContext::default(),
            correlation_id: None,
            batch_id: None,
            event_name: None,
            event_comment: None,
            changed_fields: vec![],
            snapshot_json: None,
        }
    }

    #[tokio::test]
    async fn no_op_outside_a_scope() {
        let mut event = bare_event();
        backfill(&mut event);
        assert!(event.correlation_id.is_none());
        assert!(event.request_context.ip_address.is_none());
    }

    #[tokio::test]
    async fn fills_correlation_id_and_request_context_from_the_ambient_scope() {
        let request_id = Uuid::now_v7();
        let meta = RequestMeta {
            request_id: Some(request_id.to_string()),
            ip_address: Some("203.0.113.7".to_string()),
            user_agent: Some("curl/8.0".to_string()),
        };
        attome_server::request_meta_scope_for_test(meta, async {
            let mut event = bare_event();
            backfill(&mut event);
            assert_eq!(event.correlation_id, Some(request_id));
            assert_eq!(
                event.request_context.ip_address.as_deref(),
                Some("203.0.113.7")
            );
            assert_eq!(event.request_context.browser.as_deref(), Some("curl/8.0"));
        })
        .await;
    }

    #[tokio::test]
    async fn never_overwrites_a_caller_supplied_correlation_id() {
        let pinned = Uuid::now_v7();
        let meta = RequestMeta {
            request_id: Some(Uuid::now_v7().to_string()),
            ip_address: None,
            user_agent: None,
        };
        attome_server::request_meta_scope_for_test(meta, async {
            let mut event = bare_event();
            event.correlation_id = Some(pinned);
            backfill(&mut event);
            assert_eq!(event.correlation_id, Some(pinned));
        })
        .await;
    }

    #[tokio::test]
    async fn a_non_uuid_client_supplied_request_id_does_not_populate_correlation_id() {
        let meta = RequestMeta {
            request_id: Some("my-custom-request-123".to_string()),
            ip_address: None,
            user_agent: None,
        };
        attome_server::request_meta_scope_for_test(meta, async {
            let mut event = bare_event();
            backfill(&mut event);
            assert!(event.correlation_id.is_none());
        })
        .await;
    }
}

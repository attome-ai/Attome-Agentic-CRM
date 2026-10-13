//! Web chat channel adapter (M53 Phase 1, D-474) — the first real
//! implementation of `ConnectorKind::Channel` (until now routed to the
//! `MailboxAdapter` stub alongside every other not-yet-built kind).
//!
//! Web chat is deliberately **not** shaped like a third-party connector: per
//! the module plan's own §3, it is "the one channel that is not a third-party
//! adapter" — there is no external provider API, no webhook signature to
//! verify, and no `credential_ref` to resolve. `attome_api::omnichannel_public`
//! is itself the public-facing surface (a bypass-listed, rate-limited route
//! mirroring `content_public.rs`'s posture, not `attome-integration`'s own
//! `/api/v1/integrations/{system}/webhook`).
//!
//! **This adapter is not on that route's live call path.** `attome-integration`
//! has a real (non-dev) dependency on `attome-api` (`webhook.rs` reuses
//! `entity_crud::create_record_for`) — a reverse edge from `attome-api` back
//! into `attome-integration` would cycle, so `omnichannel_public.rs` cannot
//! literally call `connector_for(ConnectorKind::Channel)`. It normalizes the
//! widget's request body into the M59 §3 shape inline instead. What this file
//! provides is the real, compilable, independently-tested shape of the
//! `channel` kind's contract — the one a genuine third-party channel adapter
//! (SMS, WhatsApp) will implement identically, satisfying "channels are
//! connectors" (D-474) as an architectural catalogue entry rather than a
//! runtime call `omnichannel_public` makes.
//!
//! `push`/`pull`/`health` are real (documented no-ops), not `not_implemented`
//! stubs like `MailboxAdapter`'s: unlike mailbox/esign/calendar/file_drop,
//! this kind genuinely has its first adapter. There is simply nothing
//! external to push a reply to (the widget polls `communication`
//! directly, so the reply already exists the moment
//! `communication::write_communication` commits it), nothing to pull from,
//! and nothing to health-check outside this deployment's own `/health` route.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

use crate::connector::{Connector, HealthResult, PullResult, PushResult, WebhookEvent};
use crate::system::IntegrationSystem;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// The raw body `attome_api::omnichannel_public`'s public POST route hands to
/// `webhook()` below — not the M59 §3 normalized shape itself (that is the
/// `WebhookEvent::payload` this method produces), but this adapter's own
/// narrow input contract.
#[derive(Debug, Deserialize)]
pub struct WebChatInbound {
    /// The bearer's public half (`agent_session_token.agent_session_id`,
    /// stringified) when resuming an existing conversation. `None` for a
    /// brand-new one. Deciding which case this is — minting a fresh session
    /// versus verifying an existing bearer's secret — is
    /// `omnichannel_public`'s job, not this adapter's: by the time this
    /// method runs, that decision (and, for a resume, the secret
    /// verification) has already happened, so this field is carried through
    /// only so the normalized `external_thread_id` can be populated.
    pub session_token: Option<String>,
    pub body: String,
}

#[derive(Debug)]
pub struct WebChatAdapter;

impl Connector for WebChatAdapter {
    fn pull<'a>(
        &'a self,
        _system: &'a IntegrationSystem,
        _credential: Option<&'a str>,
        _cursor: Option<&'a str>,
    ) -> BoxFuture<'a, PullResult> {
        // A web-chat message always arrives through `webhook()` below (the
        // widget POSTs directly) — there is no external system to poll for
        // new messages, so this always reports "nothing new" rather than
        // erroring, the same "forward-compatible, no caller invokes this yet"
        // posture the trait doc documents for the REST adapter's own `pull`.
        Box::pin(async move {
            Ok(PullResult {
                records: Vec::new(),
                next_cursor: None,
            })
        })
    }

    fn push<'a>(
        &'a self,
        _system: &'a IntegrationSystem,
        _credential: Option<&'a str>,
        _event: &'a Value,
    ) -> BoxFuture<'a, PushResult> {
        // Web chat has no outbound transport of its own: an outbound reply
        // IS the `communication` row `omnichannel_public` already wrote —
        // the widget's poll reads it directly. This exists only so the
        // three-method contract is genuinely implemented for this kind
        // rather than silently missing a case a future caller might invoke.
        Box::pin(async move {
            Ok(PushResult {
                ok: true,
                detail: Some(
                    "web chat has no external transport — the reply is served by the \
                     widget's poll reading communication directly"
                        .to_string(),
                ),
            })
        })
    }

    fn webhook<'a>(
        &'a self,
        _system: &'a IntegrationSystem,
        _credential: Option<&'a str>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Vec<WebhookEvent>> {
        Box::pin(async move {
            let inbound: WebChatInbound = serde_json::from_slice(body)
                .map_err(|e| AppError::Validation(format!("invalid web chat message body: {e}")))?;
            let text = inbound.body.trim();
            if text.is_empty() {
                return Err(AppError::Validation("body is required".into()));
            }
            // The M59 §3 normalized shape: `{channel, external_thread_id,
            // from, body, attachments}`. `from` stays `null` in Phase 1 — an
            // anonymous web-chat visitor has no named identity beyond the
            // session bearer itself (see `agent_session_token`,
            // migration 0456); `attachments` is always empty (M55, not built).
            let payload = serde_json::json!({
                "channel": "web_chat",
                "external_thread_id": inbound.session_token,
                "from": Value::Null,
                "body": text,
                "attachments": Value::Array(Vec::new()),
            });
            Ok(vec![WebhookEvent {
                event_type: "webchat.message".to_string(),
                payload,
            }])
        })
    }

    fn health<'a>(
        &'a self,
        _system: &'a IntegrationSystem,
        _credential: Option<&'a str>,
    ) -> BoxFuture<'a, HealthResult> {
        // No external dependency to probe — the widget's own reachability is
        // this deployment's own `/health` route, not a connector concern.
        Box::pin(async move {
            Ok(HealthResult {
                ok: true,
                detail: Some("web chat has no external dependency to probe".to_string()),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_system() -> IntegrationSystem {
        IntegrationSystem {
            id: uuid::Uuid::nil(),
            name: "Web Chat".into(),
            kind: "channel".into(),
            base_url: String::new(),
            auth_type: "none".into(),
            credential_ref: None,
            rate_limit: None,
            status: "active".into(),
            health_last_ok_at: None,
            health_last_error: None,
            service_principal_ref: uuid::Uuid::nil().to_string(),
            config: None,
            row_version: 0,
        }
    }

    #[tokio::test]
    async fn webhook_decodes_a_new_conversations_first_message() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        let body =
            serde_json::to_vec(&serde_json::json!({"body": "hello, is anyone there?"})).unwrap();

        let events = adapter.webhook(&system, None, &body).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "webchat.message");
        assert_eq!(events[0].payload["channel"], "web_chat");
        assert!(events[0].payload["external_thread_id"].is_null());
        assert_eq!(events[0].payload["body"], "hello, is anyone there?");
        assert!(
            events[0].payload["attachments"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn webhook_carries_the_session_token_through_as_external_thread_id() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        let body = serde_json::to_vec(&serde_json::json!({
            "session_token": "11111111-1111-7111-8111-111111111111",
            "body": "still there?"
        }))
        .unwrap();

        let events = adapter.webhook(&system, None, &body).await.unwrap();
        assert_eq!(
            events[0].payload["external_thread_id"],
            "11111111-1111-7111-8111-111111111111"
        );
    }

    #[tokio::test]
    async fn webhook_rejects_an_empty_body() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        let body = serde_json::to_vec(&serde_json::json!({"body": "   "})).unwrap();
        assert!(adapter.webhook(&system, None, &body).await.is_err());
    }

    #[tokio::test]
    async fn webhook_rejects_malformed_json() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        assert!(adapter.webhook(&system, None, b"not json").await.is_err());
    }

    #[tokio::test]
    async fn push_and_health_succeed_with_no_external_call() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        let push = adapter
            .push(&system, None, &serde_json::json!({}))
            .await
            .unwrap();
        assert!(push.ok);
        let health = adapter.health(&system, None).await.unwrap();
        assert!(health.ok);
    }

    #[tokio::test]
    async fn pull_reports_nothing_new_rather_than_erroring() {
        let adapter = WebChatAdapter;
        let system = stub_system();
        let result = adapter.pull(&system, None, None).await.unwrap();
        assert!(result.records.is_empty());
        assert!(result.next_cursor.is_none());
    }
}

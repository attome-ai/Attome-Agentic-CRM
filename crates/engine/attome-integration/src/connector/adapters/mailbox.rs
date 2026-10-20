//! Mailbox adapter. J2-T1: `pull` on a `kind = "mailbox"` system reads its
//! mailbox ([`super::mail`]: IMAP, Microsoft Graph or Gmail) from the
//! cursor. Everything else, and every method of the other not-yet-built
//! kinds routed here by `connector::connector_for` (esign, calendar,
//! file_drop), returns a clear "not implemented" error rather than silently
//! no-op'ing, so such a system fails loudly at first use instead of looking
//! like a working, always-empty connector.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde_json::Value;

use crate::connector::{Connector, HealthResult, PullResult, PushResult, WebhookEvent};
use crate::system::IntegrationSystem;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

fn not_implemented(system: &IntegrationSystem) -> AppError {
    AppError::Validation(format!(
        "'{}' connector adapter (kind = {}) is not implemented in M59 Phase 1 — \
         only kind = 'rest' has a working adapter",
        system.name, system.kind
    ))
}

#[derive(Debug)]
pub struct MailboxAdapter;

impl Connector for MailboxAdapter {
    fn pull<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a crate::credential::Credential>,
        cursor: Option<&'a str>,
    ) -> BoxFuture<'a, PullResult> {
        Box::pin(async move {
            if system.kind == "mailbox" {
                super::mail::pull(system, credential, cursor).await
            } else {
                Err(not_implemented(system))
            }
        })
    }

    fn push<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        _credential: Option<&'a crate::credential::Credential>,
        _event: &'a Value,
    ) -> BoxFuture<'a, PushResult> {
        Box::pin(async move { Err(not_implemented(system)) })
    }

    fn webhook<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        _credential: Option<&'a crate::credential::Credential>,
        _body: &'a [u8],
    ) -> BoxFuture<'a, Vec<WebhookEvent>> {
        Box::pin(async move { Err(not_implemented(system)) })
    }

    fn health<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        _credential: Option<&'a crate::credential::Credential>,
    ) -> BoxFuture<'a, HealthResult> {
        Box::pin(async move { Err(not_implemented(system)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_system() -> IntegrationSystem {
        IntegrationSystem {
            id: uuid::Uuid::nil(),
            name: "Test E-signature".into(),
            kind: "esign".into(),
            base_url: "https://example.com".into(),
            auth_type: "api_key".into(),
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
    async fn every_method_fails_closed_with_a_clear_message() {
        let adapter = MailboxAdapter;
        let system = stub_system();

        let err = adapter.pull(&system, None, None).await.unwrap_err();
        assert!(err.to_string().contains("not implemented"));

        let err = adapter
            .push(&system, None, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not implemented"));

        let err = adapter.webhook(&system, None, b"{}").await.unwrap_err();
        assert!(err.to_string().contains("not implemented"));

        let err = adapter.health(&system, None).await.unwrap_err();
        assert!(err.to_string().contains("not implemented"));
    }

    #[tokio::test]
    async fn mailbox_pull_needs_its_reader_and_credential() {
        let adapter = MailboxAdapter;
        let mut system = stub_system();
        system.kind = "mailbox".into();
        let err = adapter.pull(&system, None, None).await.unwrap_err();
        assert!(err.to_string().contains("credential"), "{err}");
        system.config = Some(r#"{"mail":"pop3"}"#.into());
        let err = adapter
            .pull(
                &system,
                Some(&crate::credential::Credential::new("secret".into())),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("imap, graph or gmail"), "{err}");
    }
}

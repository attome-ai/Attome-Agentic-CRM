//! Pluggable service seams the engine layer calls out through.
//!
//! Only `NotificationService` lives here now. The `AiService`/`NoopAi` pair
//! that used to sit beside it was deleted (T3-7, closes review item 3.17):
//! `attome-inference` is D-360's single model transport (invariant I-11), so an
//! engine-layer `complete`/`embed` trait was a dead second seam — nothing in
//! the workspace ever called it, and its noop returned an empty string/vector
//! as a *success*, which is exactly the silent-degradation shape D-360 rules
//! out.

use std::future::Future;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type ServiceError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Pluggable notification backend (email, SMS, push, webhook, etc.)
/// Implement this trait and pass `Arc<dyn NotificationService>` to EngineSystem::builder.
pub trait NotificationService: Send + Sync + 'static {
    fn send<'a>(
        &'a self,
        recipient: &'a str,
        subject: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>>;

    /// `true` only for the placeholder backend that has no provider behind
    /// it (`NoopNotifications`). Dispatch (`attome_notification::dispatch::
    /// send_via_service`) consults this so a channel with no wired provider
    /// fails visibly (`AppError::CapabilityUnavailable`) instead of the noop
    /// reporting a delivery that never happened. A real provider keeps the
    /// default.
    fn is_noop(&self) -> bool {
        false
    }
}

// ── No-op default ──────────────────────────────────────────────────────────────

/// Logs and discards all notifications. Swap for a real provider in production.
///
/// `send` still resolves `Ok(())` for any caller that reaches it directly, but
/// `is_noop()` is `true`, and the dispatch path checks that first — see the
/// trait method's doc comment.
#[derive(Debug)]
pub struct NoopNotifications;

impl NotificationService for NoopNotifications {
    fn send<'a>(
        &'a self,
        recipient: &'a str,
        subject: &'a str,
        _body: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        tracing::debug!(%recipient, %subject, "notification suppressed (noop)");
        Box::pin(async move { Ok(()) })
    }

    fn is_noop(&self) -> bool {
        true
    }
}

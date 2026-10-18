//! Y8-T6: a builder sees their own metadata write on every node. After a
//! successful metadata write (a mutating request under
//! `METADATA_AUTHORING_PREFIXES`), the writer is pinned for a minute to the
//! change-log watermark their write reached: Redis key
//! `attome-server:meta-pin:{user_id}`. On their next request on any node,
//! a node whose registry is behind the pin catches up first, waiting at most
//! two seconds; still behind, it answers 503 so the client retries, and the
//! next node it reaches has usually caught up.
//!
//! Runs after `authz`, where `SessionClaims` names the user. The engine
//! supplies the two things this layer cannot know ([`MetadataHooks`]): how to
//! read the change-log watermark, and how to start a catch-up. Without them,
//! or on the in-process store (one server is one node), it does nothing. A
//! Redis error or timeout skips the pin: this is a freshness aid, and
//! failing open serves what the node has, as before.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use attome_auth::session::SessionClaims;
use attome_cache::Store;
use attome_types::AppError;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::state::AppState;

/// How long a pin lasts.
pub const PIN_TTL: Duration = Duration::from_secs(60);

/// How long a request waits for its node to catch up to its pin.
pub const CATCH_UP_WAIT: Duration = Duration::from_secs(2);

/// The change-log watermark, read from the database.
pub type WatermarkFuture = Pin<Box<dyn Future<Output = Result<i64, AppError>> + Send>>;

/// What the engine lends this layer.
pub struct MetadataHooks {
    /// Reads the metadata change log's highest committed id.
    pub watermark: Box<dyn Fn() -> WatermarkFuture + Send + Sync>,
    /// Starts this node's debounced metadata catch-up.
    pub catch_up: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for MetadataHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataHooks").finish_non_exhaustive()
    }
}

fn pin_key(user_id: Uuid) -> String {
    format!("attome-server:meta-pin:{user_id}")
}

fn is_mutation(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

/// The pin `user_id` holds, if any; `None` on any Redis trouble.
async fn read_pin(redis: &Store, user_id: Uuid) -> Option<i64> {
    match tokio::time::timeout(
        attome_cache::timeouts::REQUEST_PATH,
        redis.get(&pin_key(user_id)),
    )
    .await
    {
        Ok(Ok(Some(text))) => text.parse().ok(),
        _ => None,
    }
}

/// Pins `user_id` to the current watermark, best effort.
async fn write_pin(state: &AppState, hooks: &MetadataHooks, user_id: Uuid) {
    let watermark = match (hooks.watermark)().await {
        Ok(watermark) => watermark,
        Err(error) => {
            tracing::warn!(%error, "metadata pin: watermark unreadable; not pinned");
            return;
        }
    };
    let set = tokio::time::timeout(
        attome_cache::timeouts::BACKGROUND,
        state
            .redis
            .set(&pin_key(user_id), &watermark.to_string(), Some(PIN_TTL)),
    )
    .await;
    if !matches!(set, Ok(Ok(_))) {
        tracing::warn!(%user_id, "metadata pin: could not be written");
    }
}

/// The layer itself; see the module doc.
pub async fn metadata_pin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(hooks) = state.metadata_hooks.get() else {
        return next.run(req).await;
    };
    if !matches!(state.redis, Store::Redis(_)) {
        return next.run(req).await;
    }
    let Some(user_id) = req.extensions().get::<SessionClaims>().map(|c| c.sub) else {
        return next.run(req).await;
    };

    if let Some(wanted) = read_pin(&state.redis, user_id).await
        && state.metadata_version.load(Ordering::Acquire) < wanted
    {
        (hooks.catch_up)();
        let started = tokio::time::Instant::now();
        while state.metadata_version.load(Ordering::Acquire) < wanted {
            if started.elapsed() >= CATCH_UP_WAIT {
                metrics::counter!("metadata_pin_unavailable_total").increment(1);
                return AppError::Overloaded("metadata").into_response();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    let writes_metadata = is_mutation(req.method())
        && crate::middleware::authoring_gate::is_metadata_authoring_path(req.uri().path());
    let response = next.run(req).await;
    if writes_metadata && response.status().is_success() {
        write_pin(&state, hooks, user_id).await;
    }
    response
}

/// Sets the hooks once, at engine start; `false` when already set.
pub fn install(state: &AppState, hooks: MetadataHooks) -> bool {
    state.metadata_hooks.set(Arc::new(hooks)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_per_user_and_only_writes_pin() {
        let user = Uuid::nil();
        assert_eq!(
            pin_key(user),
            "attome-server:meta-pin:00000000-0000-0000-0000-000000000000"
        );
        assert!(is_mutation(&axum::http::Method::POST));
        assert!(is_mutation(&axum::http::Method::PATCH));
        assert!(!is_mutation(&axum::http::Method::GET));
    }
}

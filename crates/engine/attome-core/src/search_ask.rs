//! A25-T7: the seam the search route asks in words through. Search sits
//! below the AI engine, so it cannot call a model action itself;
//! `attome-api` registers `attome-ai`'s one implementation on the
//! `EngineSystem` builder. `None` on a bare state: `mode=ask` then answers
//! that asking is unavailable, never as a silent plain search.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::state::EngineState;

/// What an asker answers with.
pub type AskFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>>;

/// Implemented once, by `attome-ai`.
pub trait SearchAsker: Send + Sync + 'static {
    /// The query as a QuerySpec `{entity, where}` the caller's metadata
    /// allows: `{"status": "parsed", "filter": {...}}`, or
    /// `{"status": "declined", "reason": ...}`.
    fn parse_filter<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: Arc<SecurityContext>,
        query: &'a str,
    ) -> AskFuture<'a>;

    /// A grounded answer to `question` from `records` (entity, id), each
    /// read as the caller: `{"answer": ..., "citations": [...]}`, or
    /// `{"answer": null, "reason": ...}`.
    fn answer<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: Arc<SecurityContext>,
        question: &'a str,
        records: &'a [(String, Uuid)],
    ) -> AskFuture<'a>;
}

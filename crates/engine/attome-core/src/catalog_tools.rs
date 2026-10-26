//! L4-T7: the seam the data catalogue's agent tools reach the catalogue
//! through. The catalogue engine lives in `attome-api` (beside its index),
//! above the AI engine, so `attome-api` registers its one implementation on
//! the `EngineSystem` builder. `None` on a bare state: the tools then answer
//! as unavailable, never as a silent empty result.

use std::future::Future;
use std::pin::Pin;

use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::state::EngineState;

/// What a catalogue call answers with: the route's own JSON shape.
pub type CatalogFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>>;

/// Implemented once, by `attome-api`. Every call is as `ctx`, with the same
/// privilege (`metadata.read`) and visibility the catalogue routes apply.
pub trait CatalogTools: Send + Sync + 'static {
    /// The visible assets the words (and kind) select, at most `limit`.
    fn search<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        q: Option<&'a str>,
        kind: Option<&'a str>,
        limit: i64,
    ) -> CatalogFuture<'a>;

    /// One visible asset's page.
    fn describe<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        asset: Uuid,
    ) -> CatalogFuture<'a>;

    /// Proposes a description at `row_version`; it is a draft until a
    /// builder approves it.
    fn draft_description<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        asset: Uuid,
        row_version: i64,
        description_en: Option<&'a str>,
        description_ar: Option<&'a str>,
    ) -> CatalogFuture<'a>;
}

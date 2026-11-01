//! W1-T5: an engine's save-time check that reads the database.
//!
//! A [`crate::model::RecordValidator`] is a synchronous function over the
//! submitted body and the metadata registry, so it cannot read related
//! records. A [`RecordCheck`] can: the generic engine runs every check an
//! engine declared for an entity (`EngineModel::record_checks`) on create
//! and update, after the validators, inside the save's own transaction, so
//! it reads what the save sees and its own writes commit or roll back with
//! the save. Same declare/collect/enforce shape as `record_validators`:
//! `ModelRegistry` collects them into `EngineState::record_checks` at boot
//! and `attome_records::entity_mutation` runs them.
//!
//! A check may refuse the save (`Err`, usually `AppError::Validation`, a
//! 422) or return values for engine-managed attributes of the record being
//! saved, which the engine merges into the body before writing. It must not
//! do external I/O (guidelines §4: no HTTP, Redis or storage inside a
//! transaction) or call a model.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde_json::{Map, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::state::EngineState;

/// What a check returns: `Some(values)` to merge into the saved body (only
/// engine-managed attributes of the saved record), `None` to leave it.
pub type RecordCheckFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Map<String, Value>>, AppError>> + Send + 'a>>;

/// The save a check judges.
#[derive(Debug, Clone, Copy)]
pub struct RecordSave<'a> {
    pub entity: &'a str,
    /// The record's id on update; `None` on create, before the row exists.
    pub record_id: Option<Uuid>,
    /// The submitted fields after the engine's own fills: the full body on
    /// create, the changed fields on update.
    pub body: &'a Map<String, Value>,
}

/// One engine's save-time check of one entity.
pub trait RecordCheck: Send + Sync + 'static {
    fn check<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        state: &'a EngineState,
        save: RecordSave<'a>,
    ) -> RecordCheckFuture<'a>;
}

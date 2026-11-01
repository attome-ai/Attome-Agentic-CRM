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
    /// The staff user saving it; `None` for a portal user or a system write.
    pub actor: Option<Uuid>,
    /// The submitted fields after the engine's own fills: the full body on
    /// create, the changed fields on update.
    pub body: &'a Map<String, Value>,
}

tokio::task_local! {
    /// E7-T9: the codes the request confirmed (`Attome-Confirm`).
    static CONFIRMED: Vec<String>;
}

/// Runs `work` with the codes the request confirmed: a check that refuses
/// a risky save with a code (`list.in_use`) lets it through when the
/// request sent that code in its `Attome-Confirm` header.
pub async fn with_confirmations<F: Future>(codes: Vec<String>, work: F) -> F::Output {
    CONFIRMED.scope(codes, work).await
}

/// Whether the request being served confirmed `code`.
pub fn confirmed(code: &str) -> bool {
    CONFIRMED
        .try_with(|codes| codes.iter().any(|c| c == code))
        .unwrap_or(false)
}

/// The codes of an `Attome-Confirm` header value: comma separated, at most
/// eight. Pure.
pub fn confirm_codes(header: Option<&str>) -> Vec<String> {
    header
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .take(8)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_codes_split_and_trim() {
        assert_eq!(
            confirm_codes(Some(" list.in_use , ,other")),
            vec!["list.in_use".to_owned(), "other".to_owned()]
        );
        assert!(confirm_codes(None).is_empty());
        assert!(
            !confirmed("list.in_use"),
            "nothing confirmed outside a request"
        );
    }
}

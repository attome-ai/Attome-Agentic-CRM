//! AH1-T2: everything one agent session wrote, the input to undoing a run.
//!
//! - [`collect_session_changes`]: the record changes, from the audit headers
//!   tagged with the session (`audit_header.agent_session_id`, written for
//!   every agent-initiated change) and their field details, newest first.
//! - [`collect_external_effects`]: what reached outside the deployment or a
//!   person, from the invocation ledger (`action_invocation`): every
//!   completed call of an action whose effect is external or that sends a
//!   message (the same rule the agent limits count by,
//!   [`crate::descriptor::is_message_send`]). These cannot be undone, only
//!   reported.
//!
//! **Values.** A field's old and new values are restorable only when the
//! audit kept them readably: with crypto-shredding off they are plain text;
//! with it on they are opened with the record's key
//! ([`attome_audit::erasure::read_dek`]), and a record whose key was
//! destroyed has none. A sensitive field (`value_mode` Restricted) or a
//! credential column (NotCaptured) is never read here: it is marked not
//! restorable, and its values are left out.

use std::collections::HashMap;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::descriptor::{Effect, is_message_send};

/// Most headers one collection reads.
pub const MAX_CHANGES: i64 = 5_000;

/// `audit_detail.value_mode` as stored (`attome_audit::value_mode`).
const MODE_ENCRYPTED: i16 = 0;

/// One field of one change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    /// False when the audit did not keep the value readably.
    pub restorable: bool,
}

/// One record change the session made.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunChange {
    pub entity: String,
    pub record_id: Uuid,
    pub audit_header_id: Uuid,
    /// `None` for an operation that is not an entity change.
    #[serde(skip)]
    pub operation: Option<AuditOperation>,
    pub operation_code: i32,
    pub changed_on: DateTime<Utc>,
    pub version_after: Option<i64>,
    pub fields: Vec<FieldChange>,
}

/// One call that reached outside the deployment or a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalEffect {
    pub invocation_id: Uuid,
    pub action_id: String,
    pub outcome: String,
    pub at: DateTime<Utc>,
}

/// The entity operation a stored code names. Pure.
pub fn operation_of(code: i32) -> Option<AuditOperation> {
    Some(match code {
        0 => AuditOperation::Create,
        1 => AuditOperation::Update,
        2 => AuditOperation::SoftDelete,
        3 => AuditOperation::HardDelete,
        4 => AuditOperation::Restore,
        5 => AuditOperation::Merge,
        6 => AuditOperation::Clone,
        7 => AuditOperation::Import,
        8 => AuditOperation::Export,
        _ => return None,
    })
}

/// Whether a detail's values may be read for a restore: only those kept
/// in the default mode (or before modes existed). Pure.
pub fn readable_mode(value_mode: Option<i16>, is_sensitive: bool) -> bool {
    match value_mode {
        Some(mode) => mode == MODE_ENCRYPTED,
        None => !is_sensitive,
    }
}

type HeaderRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<i32>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<i64>,
);

type DetailRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i16>,
    bool,
);

/// Opens one stored value with the record's key, or returns it as stored
/// when the audit keeps plain text.
fn open_value(
    key: Option<&[u8; 32]>,
    encrypted: bool,
    stored: Option<String>,
) -> Result<Option<String>, ()> {
    match (stored, encrypted, key) {
        (None, _, _) => Ok(None),
        (Some(v), false, _) => Ok(Some(v)),
        (Some(v), true, Some(k)) => attome_audit::erasure::decrypt_field(k, &v)
            .map(Some)
            .map_err(|_| ()),
        (Some(_), true, None) => Err(()),
    }
}

/// The record changes `session` made, newest first.
pub async fn collect_session_changes(
    state: &EngineState,
    session: Uuid,
) -> Result<Vec<RunChange>, AppError> {
    let db = &state.base.db;
    let headers: Vec<HeaderRow> = sqlx::query_as(
        "SELECT id, entity_name, record_id, operation, changed_on, created_at, version_after \
           FROM audit_header \
          WHERE agent_session_id = $1 AND initiator = 1 AND record_id IS NOT NULL \
            AND entity_name IS NOT NULL \
          ORDER BY COALESCE(changed_on, created_at) DESC, id DESC LIMIT $2",
    )
    .bind(session)
    .bind(MAX_CHANGES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = headers.iter().map(|h| h.0).collect();
    let details: Vec<DetailRow> = sqlx::query_as(
        "SELECT audit_ref, field_name, old_value, new_value, value_mode, is_sensitive \
           FROM audit_detail WHERE audit_ref = ANY($1) ORDER BY audit_ref, id",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_header: HashMap<Uuid, Vec<&DetailRow>> = HashMap::new();
    for detail in &details {
        by_header.entry(detail.0).or_default().push(detail);
    }
    let master = state.audit_erasure_key.as_ref();
    let mut keys: HashMap<Uuid, Option<[u8; 32]>> = HashMap::new();
    let mut out = Vec::with_capacity(headers.len());
    for (id, entity, record, operation, changed_on, created_at, version_after) in headers {
        let (Some(entity), Some(record)) = (entity, record) else {
            continue;
        };
        let key = match master {
            Some(ring) => match keys.get(&record) {
                Some(known) => *known,
                None => {
                    let dek = attome_audit::erasure::read_dek(db, ring, record).await?;
                    keys.insert(record, dek);
                    dek
                }
            },
            None => None,
        };
        let fields = by_header
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|(_, field, old, new, mode, sensitive)| {
                let field = field.clone()?;
                if !readable_mode(*mode, *sensitive) {
                    return Some(FieldChange {
                        field,
                        old_value: None,
                        new_value: None,
                        restorable: false,
                    });
                }
                let encrypted = master.is_some();
                let old = open_value(key.as_ref(), encrypted, old.clone());
                let new = open_value(key.as_ref(), encrypted, new.clone());
                Some(match (old, new) {
                    (Ok(old_value), Ok(new_value)) => FieldChange {
                        field,
                        old_value,
                        new_value,
                        restorable: true,
                    },
                    _ => FieldChange {
                        field,
                        old_value: None,
                        new_value: None,
                        restorable: false,
                    },
                })
            })
            .collect();
        let code = operation.unwrap_or(-1);
        out.push(RunChange {
            entity,
            record_id: record,
            audit_header_id: id,
            operation: operation_of(code),
            operation_code: code,
            changed_on: changed_on.unwrap_or(created_at),
            version_after,
            fields,
        });
    }
    Ok(out)
}

/// The calls `session` made that reached outside the deployment or a
/// person, newest first.
pub async fn collect_external_effects(
    state: &EngineState,
    session: Uuid,
) -> Result<Vec<ExternalEffect>, AppError> {
    let rows: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, action_id, outcome, created_at FROM action_invocation \
          WHERE agent_session_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(session)
    .bind(MAX_CHANGES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter(|(_, action, outcome, _)| {
            outcome == "completed"
                && crate::engine::REGISTRY
                    .resolve(action)
                    .is_some_and(|d| d.effect == Effect::External || is_message_send(action))
        })
        .map(|(id, action_id, outcome, at)| ExternalEffect {
            invocation_id: id,
            action_id,
            outcome,
            at,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undo_reads_only_values_kept_readably() {
        assert!(readable_mode(Some(0), false));
        assert!(!readable_mode(Some(1), true), "a sensitive field is restricted");
        assert!(!readable_mode(Some(2), false), "a credential column is not captured");
        assert!(readable_mode(None, false), "before modes, a plain field");
        assert!(!readable_mode(None, true), "before modes, a sensitive field");
    }

    #[test]
    fn undo_opens_plain_values_and_refuses_ciphertext_without_a_key() {
        assert_eq!(open_value(None, false, Some("a".into())), Ok(Some("a".into())));
        assert_eq!(open_value(None, false, None), Ok(None));
        assert_eq!(open_value(None, true, Some("c2VjcmV0".into())), Err(()));
        assert_eq!(open_value(None, true, None), Ok(None));
    }

    #[test]
    fn undo_maps_entity_operations() {
        assert_eq!(operation_of(0), Some(AuditOperation::Create));
        assert_eq!(operation_of(2), Some(AuditOperation::SoftDelete));
        assert_eq!(operation_of(8), Some(AuditOperation::Export));
        assert_eq!(operation_of(9), None, "a login is not an entity change");
        assert_eq!(operation_of(-1), None);
    }

    #[test]
    fn undo_reports_message_sends_as_external() {
        assert!(is_message_send("email.send"));
        assert!(is_message_send("lead.send_message"));
        assert!(!is_message_send("record.update"));
    }
}

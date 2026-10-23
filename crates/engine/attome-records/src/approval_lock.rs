//! M9-T1: a record held by a pending approval process takes only the
//! process's editable attributes.
//!
//! Submitting a record to an `approval_process` with `lock_record` files an
//! `approval_request` (action type [`APPROVAL_PROCESS_ACTION`], regarding the
//! record, `payload.process_id`). While that request is pending, an ordinary
//! update (`MutationMode::Strict`) that names any other attribute is refused
//! by name (`AttributeNotWritable`), so the approvers decide on the values
//! the requester submitted. The lock ends with the request: approved,
//! rejected, recalled, expired. One indexed probe per update
//! (`approval_request_pending_process_idx`, migration 0210).

use attome_types::AppError;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// The action type of an approval process's requests.
pub const APPROVAL_PROCESS_ACTION: &str = "approval_process";

/// The first attribute of `obj` that `editable` does not allow, if any.
pub fn first_locked_attribute<'a>(
    obj: &'a serde_json::Map<String, Value>,
    editable: &[String],
) -> Option<&'a str> {
    obj.keys()
        .map(String::as_str)
        .find(|key| !editable.iter().any(|e| e == key))
}

/// Refuses `obj` when the record is held by a pending, locking process
/// request and names an attribute the process does not leave editable.
pub async fn refuse_locked(
    conn: &mut PgConnection,
    entity_name: &str,
    record_id: Uuid,
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let editable: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT p.editable_attributes \
           FROM approval_request r \
           JOIN approval_process p ON p.id = (r.payload ->> 'process_id')::uuid \
          WHERE r.regarding_entity = $1 AND r.regarding_id = $2 \
            AND r.status = 'pending' AND r.action_type = $3 AND p.lock_record \
          LIMIT 1",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(APPROVAL_PROCESS_ACTION)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)?;
    match editable {
        Some(editable) => match first_locked_attribute(obj, &editable) {
            Some(attr) => Err(AppError::AttributeNotWritable(attr.to_owned())),
            None => Ok(()),
        },
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_process_lock_allows_only_the_editable_attributes() {
        let body = |keys: &[&str]| {
            keys.iter()
                .map(|k| ((*k).to_owned(), Value::Null))
                .collect::<serde_json::Map<String, Value>>()
        };
        let editable = vec!["notes".to_owned()];
        assert_eq!(first_locked_attribute(&body(&["notes"]), &editable), None);
        assert_eq!(
            first_locked_attribute(&body(&["notes", "amount"]), &editable),
            Some("amount")
        );
        assert_eq!(
            first_locked_attribute(&body(&["amount"]), &[]),
            Some("amount")
        );
    }
}

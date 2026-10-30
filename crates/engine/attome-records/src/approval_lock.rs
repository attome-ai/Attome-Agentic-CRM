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
//!
//! M9-T2: a process that starts on `change` watches chosen attributes. An
//! ordinary update that changes one of them, on a record meeting the
//! process's entry condition (judged on the record as the update would
//! leave it), is held: the watched attributes keep their stored values, the
//! rest of the update is written, and the held values wait in an approval
//! request (action type [`APPROVAL_CHANGE_ACTION`], regarding the record,
//! `payload.changes`). Approval writes them through the same update path
//! (`MutationMode::HeldChange`); rejection leaves the record as it is.
//! While a change is pending, a second change to the same attributes is
//! refused. One indexed probe per update for entities with no such process
//! (`approval_process_change_idx`, migration 0212).

use attome_core::{AttrInfo, EngineState};
use attome_rules::{Budgets, Context, LanguageVersion, Schema, Type, Value as RValue};
use attome_types::AppError;
use serde_json::Value;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// The action type of an approval process's requests.
pub const APPROVAL_PROCESS_ACTION: &str = "approval_process";

/// M9-T2: the action type of a held change to watched attributes.
pub const APPROVAL_CHANGE_ACTION: &str = "approval_process.change";

/// M9-T2: what an update held for approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldChange {
    pub request_id: Uuid,
    /// The watched attributes the update asked to change, in name order.
    pub attributes: Vec<String>,
}

/// A `change` process for the entity whose watched attributes the update
/// names.
#[derive(sqlx::FromRow)]
struct ChangeProcess {
    id: Uuid,
    name: String,
    entry_condition: Option<String>,
    watched_attributes: Vec<String>,
    plan: Value,
}

/// M9-T2: the attributes of `obj` that `watched` names and whose value
/// differs from `stored`, in name order. Writing a value a record already
/// holds needs no approval.
pub fn changed_watched<'a>(
    obj: &'a serde_json::Map<String, Value>,
    watched: &[String],
    stored: &serde_json::Map<String, Value>,
) -> Vec<&'a str> {
    let mut changed: Vec<&str> = obj
        .iter()
        .filter(|(key, value)| {
            watched.iter().any(|w| w == *key)
                && !same_value(stored.get(*key).unwrap_or(&Value::Null), value)
        })
        .map(|(key, _)| key.as_str())
        .collect();
    changed.sort_unstable();
    changed
}

/// Two JSON values as stored values: numbers compare by value (`20` and
/// `20.0` are the same discount, and a decimal column reads back as text).
fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Number(x), Value::String(y)) | (Value::String(y), Value::Number(x)) => {
            y.parse::<f64>().ok() == x.as_f64()
        }
        _ => a == b,
    }
}

/// M9-T2: whether `condition` (V2 rule text over the record's fields)
/// holds for `record`; no condition admits every record, and one that does
/// not compile or evaluate admits none.
pub fn condition_holds(condition: Option<&str>, record: &serde_json::Map<String, Value>) -> bool {
    let Some(src) = condition.filter(|c| !c.trim().is_empty()) else {
        return true;
    };
    let mut schema = Schema::new();
    let mut ctx = Context::new(chrono::Utc::now());
    for (name, value) in record {
        let (ty, value) = rule_value(value);
        schema = schema.with_field(name.clone(), ty);
        ctx = ctx.with_field(name.clone(), value);
    }
    match attome_rules::compile_versioned(src, &schema, LanguageVersion::V2, Budgets::default()) {
        Ok(compiled) => matches!(compiled.eval(&ctx), Ok(RValue::Bool(true))),
        Err(error) => {
            tracing::warn!(code = error.code(), %error, "approval process entry condition did not compile against the record; the change is not held");
            false
        }
    }
}

/// A stored value as a rule value: a number held as text (a decimal column
/// read back through JSON) reads as a number.
fn rule_value(v: &Value) -> (Type, RValue) {
    match v {
        Value::Bool(b) => (Type::Bool, RValue::Bool(*b)),
        Value::Number(n) => match n.as_f64().filter(|f| f.is_finite()) {
            Some(f) => (Type::Number, RValue::Number(f)),
            None => (Type::Null, RValue::Null),
        },
        Value::String(s) => match s.parse::<f64>() {
            Ok(f) if f.is_finite() => (Type::Number, RValue::Number(f)),
            _ => (Type::Text, RValue::Text(s.clone())),
        },
        _ => (Type::Null, RValue::Null),
    }
}

/// M9-T2: holds the watched attributes of an update for approval. Returns
/// `None` when no `change` process applies; otherwise the body to write
/// (the held attributes set back to their stored values) and the request
/// opened in this transaction. `requester` is the staff user writing; a
/// portal user's change to a watched attribute is refused by name.
#[allow(clippy::too_many_arguments)]
pub async fn hold_watched_changes(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    requester: Option<Uuid>,
) -> Result<Option<(serde_json::Map<String, Value>, HeldChange)>, AppError> {
    let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    let processes: Vec<ChangeProcess> = sqlx::query_as(
        "SELECT id, name, entry_condition, watched_attributes, plan            FROM approval_process           WHERE entity_logicalname = $1 AND starts_on = 'change' AND is_active             AND NOT is_deleted AND watched_attributes && $2::text[]           ORDER BY created_at, id",
    )
    .bind(entity_name)
    .bind(&keys)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if processes.is_empty() {
        return Ok(None);
    }
    let Some(stored) =
        crate::entity_mutation::fetch_stored_record(tx, entity_name, record_id, attrs).await?
    else {
        // No live row: the update itself answers NotFound.
        return Ok(None);
    };
    let mut effective = stored.clone();
    for (k, v) in obj {
        effective.insert(k.clone(), v.clone());
    }
    for process in processes {
        let changed = changed_watched(obj, &process.watched_attributes, &stored);
        if changed.is_empty() || !condition_holds(process.entry_condition.as_deref(), &effective) {
            continue;
        }
        let Some(requester) = requester else {
            return Err(AppError::AttributeNotWritable(changed[0].to_owned()));
        };
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM approval_request                              WHERE regarding_entity = $1 AND regarding_id = $2                                AND status = 'pending' AND action_type = $3                                AND payload ->> 'process_id' = $4)",
        )
        .bind(entity_name)
        .bind(record_id)
        .bind(APPROVAL_CHANGE_ACTION)
        .bind(process.id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if pending {
            return Err(AppError::Conflict(
                "a change to these attributes already waits for approval",
            ));
        }
        let plan: attome_approval::ApprovalPlan = serde_json::from_value(process.plan.clone())
            .map_err(|e| AppError::internal(format!("stored approval process plan: {e}")))?;
        let changes: serde_json::Map<String, Value> = changed
            .iter()
            .map(|k| ((*k).to_owned(), obj[*k].clone()))
            .collect();
        let previous: serde_json::Map<String, Value> = changed
            .iter()
            .map(|k| {
                (
                    (*k).to_owned(),
                    stored.get(*k).cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        let payload = serde_json::json!({
            "process_id": process.id,
            "process_name": process.name,
            "entity": entity_name,
            "record_id": record_id,
            "changes": changes,
            "previous": previous,
        });
        let backstop_ttl = attome_audit::approval::plan_backstop_ttl(&plan);
        let request = attome_approval::submit_with_plan_regarding_in_tx(
            tx,
            APPROVAL_CHANGE_ACTION,
            payload,
            requester,
            plan,
            backstop_ttl,
            None,
            Some((entity_name, record_id)),
        )
        .await?;
        attome_audit::security::write_security_event(
            tx,
            &attome_audit::audit_service(state),
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Security,
                attome_audit::AuditOperation::Submitted,
                requester,
                "approval_request",
                Some(request.id),
            )
            .named("approval_process.change_held")
            .comment(format!(
                "change to {} of {entity_name} {record_id} held for approval process {}",
                changed.join(", "),
                process.name
            )),
        )
        .await?;
        let mut body = obj.clone();
        for key in &changed {
            body.insert(
                (*key).to_owned(),
                stored.get(*key).cloned().unwrap_or(Value::Null),
            );
        }
        let attributes = changed.iter().map(|k| (*k).to_owned()).collect();
        return Ok(Some((
            body,
            HeldChange {
                request_id: request.id,
                attributes,
            },
        )));
    }
    Ok(None)
}

/// M9-T2: the record's current row version, for applying an approved change.
pub async fn current_row_version(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(&format!(
        "SELECT row_version FROM {table} WHERE id = $1 AND is_active = true",
        table = attome_core::quote_ident(entity_name)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

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

    #[test]
    fn approval_on_change_holds_only_changed_watched_attributes() {
        let map = |v: Value| v.as_object().unwrap().clone();
        let stored = map(serde_json::json!({ "discount": "10.00", "notes": "a" }));
        let watched = vec!["discount".to_owned()];
        let obj = map(serde_json::json!({ "discount": 25, "notes": "b" }));
        assert_eq!(changed_watched(&obj, &watched, &stored), vec!["discount"]);
        let same = map(serde_json::json!({ "discount": 10, "notes": "b" }));
        assert!(changed_watched(&same, &watched, &stored).is_empty());
        let mut effective = stored.clone();
        effective.insert("discount".into(), serde_json::json!(25));
        assert!(condition_holds(Some("discount > 20"), &effective));
        effective.insert("discount".into(), serde_json::json!("15.5"));
        assert!(!condition_holds(Some("discount > 20"), &effective));
        assert!(condition_holds(None, &effective));
    }
}

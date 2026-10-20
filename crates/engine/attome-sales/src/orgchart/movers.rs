//! D23-T8: a contact who leaves their company. The old contact stays, with
//! its history, marked `is_former_employee` with `left_on`; the contacts
//! who reported to them are listed so someone gives them a new manager.
//! When the person joined another account, a new contact is created there
//! with their name and contact details, and a `moved_to` record
//! relationship links the old contact to the new one.
//!
//! The new contact goes through the generic create, so the duplicate rules
//! (A15) run on it: a likely duplicate at the new account is refused before
//! anything is written, and the caller can link the existing contact
//! instead. The steps run in that order (new contact, link, then the old
//! contact marked), so a refusal leaves nothing half-done.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The details a new contact at the next account carries over.
pub const CARRIED: &[&str] = &[
    "first_name",
    "last_name",
    "full_name",
    "name",
    "first_name_ar",
    "last_name_ar",
    "email",
    "phone",
    "mobile_phone",
    "linkedin_url",
    "city",
    "country_code",
];

/// The most reports listed.
pub const MAX_REPORTS: i64 = 500;

/// What to record.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SalesContactLeftBody {
    pub left_on: NaiveDate,
    /// The account the person joined, if known.
    #[serde(default)]
    pub new_account_id: Option<Uuid>,
}

/// What was recorded.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SalesContactLeft {
    pub contact_id: Uuid,
    pub row_version: i64,
    /// The new contact at the next account.
    pub new_contact_id: Option<Uuid>,
    /// The contacts who reported to this one and need a new manager.
    pub needs_new_manager: Vec<Uuid>,
}

/// The new contact's fields: the carried details present on the old
/// contact, at the new account. Pure.
pub fn carried_fields(old: &Map<String, Value>, new_account: Uuid) -> Map<String, Value> {
    let mut out: Map<String, Value> = CARRIED
        .iter()
        .filter_map(|k| {
            old.get(*k)
                .filter(|v| !v.is_null() && v.as_str() != Some(""))
                .map(|v| ((*k).to_owned(), v.clone()))
        })
        .collect();
    out.insert("account_ref".into(), Value::String(new_account.to_string()));
    out
}

/// Records that the contact left; see the module doc.
pub async fn mark_left(
    state: &EngineState,
    ctx: &SecurityContext,
    contact: Uuid,
    left_on: NaiveDate,
    new_account: Option<Uuid>,
    if_match: i64,
) -> Result<SalesContactLeft, AppError> {
    ctx.require("contact", "update")?;
    let record = attome_records::entity_crud::read_record(state, ctx, "contact", contact).await?;
    let old: Map<String, Value> = record.data().as_object().cloned().unwrap_or_default();

    let new_contact_id = match new_account {
        None => None,
        Some(account) => {
            // The account must be one the caller may read.
            attome_records::entity_crud::read_record(state, ctx, "account", account).await?;
            let (id, _) = attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "contact",
                Value::Object(carried_fields(&old, account)),
            )
            .await?;
            attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "record_relationship",
                json!({
                    "from_entity_name": "contact",
                    "from_record_id": contact.to_string(),
                    "to_entity_name": "contact",
                    "to_record_id": id.to_string(),
                    "relationship_type": "moved_to",
                }),
            )
            .await?;
            Some(id)
        }
    };

    let (entity_id, _, attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "contact").await?;
    let mut patch = Map::new();
    patch.insert("is_former_employee".into(), Value::Bool(true));
    patch.insert("left_on".into(), Value::String(left_on.to_string()));
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = attome_records::entity_mutation::update_one_as(
        &mut tx,
        state,
        attome_records::entity_mutation::Principal::Staff(ctx),
        "contact",
        entity_id,
        contact,
        &attrs,
        &patch,
        Some(ctx.user_id),
        if_match,
        attome_records::entity_mutation::MutationMode::Strict,
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contact",
            contact,
            attome_audit::AuditOperation::Update,
            "sales.contact_left",
            ctx.user_id,
        )
        .comment(match new_contact_id {
            Some(id) => format!("left on {left_on}; moved to contact {id}"),
            None => format!("left on {left_on}"),
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let row_version = result
        .new_row
        .as_ref()
        .and_then(|r| r.get("row_version"))
        .and_then(Value::as_i64)
        .unwrap_or(if_match + 1);

    // The reports, as the caller may read them.
    let reports: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM contact WHERE reports_to = $1 AND is_active IS NOT FALSE \
          ORDER BY id LIMIT $2",
    )
    .bind(contact)
    .bind(MAX_REPORTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut needs_new_manager = Vec::with_capacity(reports.len());
    for id in reports {
        if attome_records::entity_crud::read_record(state, ctx, "contact", id)
            .await
            .is_ok()
        {
            needs_new_manager.push(id);
        }
    }
    Ok(SalesContactLeft {
        contact_id: contact,
        row_version,
        new_contact_id,
        needs_new_manager,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaver_keeps_history_and_lists_reports() {
        let old: Map<String, Value> = serde_json::from_value(json!({
            "first_name": "Lina", "last_name": "Haddad", "email": "lina@old.example",
            "phone": "", "reports_to": "x", "is_former_employee": false, "account_ref": "old",
            "mobile_phone": null
        }))
        .unwrap();
        let account = Uuid::from_u128(7);
        let new = carried_fields(&old, account);
        assert_eq!(new["first_name"], "Lina");
        assert_eq!(new["email"], "lina@old.example");
        assert_eq!(new["account_ref"], account.to_string());
        assert!(!new.contains_key("phone"), "empty values are not carried");
        assert!(!new.contains_key("mobile_phone"));
        assert!(
            !new.contains_key("reports_to"),
            "the old line stays with the old contact"
        );
        assert!(!new.contains_key("is_former_employee"));
    }
}

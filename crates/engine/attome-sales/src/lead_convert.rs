//! D3-T2: converting a qualified lead into an account, a contact and an
//! opportunity.
//!
//! - `GET /api/v1/sales/leads/{id}/convert` previews it: the values each
//!   record would get from the conversion map, and the existing accounts and
//!   contacts the duplicate rules (A15, `duplicate_check::find_any`) say the
//!   new ones would repeat, so the person can link one instead.
//! - `POST /api/v1/sales/leads/{id}/convert` (the lead's `row_version` in
//!   `If-Match`) creates or links the account, creates, links or skips the
//!   contact, creates or skips the opportunity, moves the lead's activities
//!   and notes to the contact (else the account), and moves the lead to
//!   `converted` with links to all three.
//! - `POST /api/v1/sales/lead-conversions/{id}/undo`, by the person who
//!   converted, within [`UNDO_HOURS`] hours and only while every record it
//!   created is unchanged: activities and notes move back, the lead returns
//!   to `qualified` and the created records are deleted (to the bin).
//!
//! **The map** is the setting `sales.lead_conversion_map`: per target entity,
//! target field to lead field (`@email_domain` is the lead's work-email
//! domain). A field either side lacks is left out. Without the setting,
//! [`default_map`] applies.
//!
//! **Writes.** Every record is written through the record engine as the
//! caller, so access, validation, numbering, record rules and audit apply.
//! The engine commits each write itself, so the conversion is not one
//! transaction: a `lead_conversion` row (migration 0302) is claimed first,
//! which also refuses a second or concurrent conversion of the lead (one
//! live row per lead), and a failure part way undoes what was done before
//! the error is returned.

use std::collections::HashSet;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_records::duplicate_check::{DuplicateMatch, find_any};
use attome_records::entity_mutation::{DeleteKind, DeleteOrigin};
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::{Json, http::header::IF_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The setting holding the conversion map.
pub const MAP_SETTING: &str = "sales.lead_conversion_map";
/// How long a conversion can be undone.
pub const UNDO_HOURS: i64 = 24;
/// Activities or notes moved per conversion, each.
const MAX_MOVED: i64 = 500;

/// The map used without the setting: target field ← lead field.
pub fn default_map() -> Value {
    json!({
        "account": {
            "name": "company_name",
            "phone": "phone",
            "email_domain": "@email_domain",
        },
        "contact": {
            "full_name": "name",
            "email": "email",
            "phone": "phone",
            "mobile_phone": "mobile_phone",
            "department": "department",
            "city": "city",
            "country_code": "country_code",
            "linkedin_url": "linkedin_url",
        },
        "opportunity": {
            "name": "company_name",
            "amount": "budget",
        },
    })
}

/// A lead value worth copying (not null, not blank).
fn present(value: &Value) -> Option<Value> {
    match value {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        other => Some(other.clone()),
    }
}

/// The values `target` gets from `lead` under `map`, keeping only fields
/// the target has. Pure.
pub fn mapped(
    map: &Value,
    target: &str,
    lead: &Value,
    target_fields: &HashSet<String>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(pairs) = map.get(target).and_then(Value::as_object) else {
        return out;
    };
    for (to, from) in pairs {
        let Some(from) = from.as_str() else { continue };
        if !target_fields.contains(to) {
            continue;
        }
        let value = if from == "@email_domain" {
            lead.get("email")
                .and_then(Value::as_str)
                .and_then(crate::enrichment::domain::work_domain)
                .map(Value::String)
        } else {
            lead.get(from).and_then(present)
        };
        if let Some(value) = value {
            out.insert(to.clone(), value);
        }
    }
    out
}

/// What to do with one target record.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct ConvertTarget {
    /// `create` (default), `link` (to `id`) or `skip` (not for the account).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub id: Option<Uuid>,
}

/// A conversion's choices; every target defaults to `create`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct LeadConvertBody {
    #[serde(default)]
    pub account: ConvertTarget,
    #[serde(default)]
    pub contact: ConvertTarget,
    #[serde(default)]
    pub opportunity: ConvertTarget,
}

/// One target's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Link(Uuid),
    Skip,
}

/// Reads a target's choice; `skip` only where `may_skip`. Pure.
pub fn mode_of(target: &ConvertTarget, name: &str, may_skip: bool) -> Result<Mode, AppError> {
    match target.mode.as_deref().map(str::trim).unwrap_or("create") {
        "create" => Ok(Mode::Create),
        "link" => target.id.map(Mode::Link).ok_or_else(|| {
            AppError::Validation(format!("{name}: link needs the id of the record to link"))
        }),
        "skip" if may_skip => Ok(Mode::Skip),
        other => Err(AppError::Validation(format!(
            "{name}: mode is create, link{}, not {other:?}",
            if may_skip { " or skip" } else { "" }
        ))),
    }
}

/// The preview of a conversion.
#[derive(Debug, Serialize, ToSchema)]
pub struct LeadConvertPreview {
    pub lead_id: Uuid,
    #[schema(value_type = Object)]
    pub account: Map<String, Value>,
    #[schema(value_type = Object)]
    pub contact: Map<String, Value>,
    #[schema(value_type = Object)]
    pub opportunity: Map<String, Value>,
    /// Existing accounts the new one would repeat, that the caller may read.
    pub account_matches: Vec<DuplicateMatch>,
    pub contact_matches: Vec<DuplicateMatch>,
    /// Matches the caller may not read.
    pub hidden_matches: i64,
}

/// A conversion done.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LeadConverted {
    pub conversion_id: Uuid,
    pub lead_id: Uuid,
    pub account_id: Uuid,
    pub contact_id: Option<Uuid>,
    pub opportunity_id: Option<Uuid>,
    /// Activities and notes moved off the lead.
    pub moved: usize,
}

/// A conversion undone.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LeadConversionUndone {
    pub conversion_id: Uuid,
    pub lead_id: Uuid,
    /// Records deleted.
    pub removed: usize,
}

/// A record an activity or note was moved off the lead onto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moved {
    /// `activity` or `note`.
    pub entity: String,
    pub id: Uuid,
}

fn fields_of(state: &EngineState, entity: &str) -> HashSet<String> {
    state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.iter().map(|a| a.logicalname.clone()).collect())
        .unwrap_or_default()
}

fn conversion_map(state: &EngineState) -> Value {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(MAP_SETTING)
        .map(|d| store.resolve(d, None, None).0)
        .filter(|v| v.as_object().is_some_and(|o| !o.is_empty()))
        .unwrap_or_else(default_map)
}

async fn require(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let (entity_id, _, _, _) = attome_records::entity_crud::resolve_entity(state, entity).await?;
    attome_records::entity_crud::require_record_access(state, ctx, entity_id, entity, id, action)
        .await
}

async fn read_lead(state: &EngineState, lead: Uuid) -> Result<Value, AppError> {
    sqlx::query_scalar(
        "SELECT to_jsonb(l) FROM lead l WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(lead)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn version_of(state: &EngineState, entity: &str, id: Uuid) -> Result<Option<i64>, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT row_version FROM {} WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        attome_core::quote_ident(entity)
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The preview (see the module doc).
pub async fn preview(
    state: &EngineState,
    ctx: &SecurityContext,
    lead_id: Uuid,
) -> Result<LeadConvertPreview, AppError> {
    require(state, ctx, "lead", lead_id, RecordAction::Read).await?;
    let lead = read_lead(state, lead_id).await?;
    let map = conversion_map(state);
    let account = mapped(&map, "account", &lead, &fields_of(state, "account"));
    let contact = mapped(&map, "contact", &lead, &fields_of(state, "contact"));
    let opportunity = mapped(&map, "opportunity", &lead, &fields_of(state, "opportunity"));
    let (account_id, _, _, _) =
        attome_records::entity_crud::resolve_entity(state, "account").await?;
    let (contact_id, _, _, _) =
        attome_records::entity_crud::resolve_entity(state, "contact").await?;
    let accounts = find_any(state, ctx, account_id, "account", None, &account).await?;
    let contacts = find_any(state, ctx, contact_id, "contact", None, &contact).await?;
    Ok(LeadConvertPreview {
        lead_id,
        account,
        contact,
        opportunity,
        hidden_matches: accounts.hidden + contacts.hidden,
        account_matches: accounts.visible,
        contact_matches: contacts.visible,
    })
}

/// What a conversion has done so far, for undoing it on a failure.
#[derive(Debug, Default)]
struct Done {
    account: Option<Uuid>,
    contact: Option<Uuid>,
    opportunity: Option<Uuid>,
    moved: Vec<Moved>,
}

/// Moves the lead's activities and notes onto `to`.
async fn move_children(
    state: &EngineState,
    ctx: &SecurityContext,
    lead: Uuid,
    to_entity: &str,
    to: Uuid,
    done: &mut Done,
) -> Result<(), AppError> {
    for (entity, kind_field, id_field) in [
        ("activity", "regarding_entity", "regarding_id"),
        ("note", "entity_name", "record_id"),
    ] {
        let fields = fields_of(state, entity);
        if !fields.contains(kind_field) || !fields.contains(id_field) {
            continue;
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(&format!(
            "SELECT id, row_version FROM {} WHERE {} = 'lead' AND {}::text = $1 \
               AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $2",
            attome_core::quote_ident(entity),
            attome_core::quote_ident(kind_field),
            attome_core::quote_ident(id_field),
        ))
        .bind(lead.to_string())
        .bind(MAX_MOVED)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for (id, version) in rows {
            let mut patch = Map::new();
            patch.insert(kind_field.to_owned(), json!(to_entity));
            patch.insert(id_field.to_owned(), json!(to.to_string()));
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                entity,
                id,
                version,
                Value::Object(patch),
            )
            .await?;
            done.moved.push(Moved {
                entity: entity.to_owned(),
                id,
            });
        }
    }
    Ok(())
}

/// Moves `moved` back onto the lead.
async fn move_back(
    state: &EngineState,
    ctx: &SecurityContext,
    lead: Uuid,
    moved: &[Moved],
) -> Result<(), AppError> {
    for m in moved {
        let (kind_field, id_field) = if m.entity == "note" {
            ("entity_name", "record_id")
        } else {
            ("regarding_entity", "regarding_id")
        };
        let Some(version) = version_of(state, &m.entity, m.id).await? else {
            continue;
        };
        let mut patch = Map::new();
        patch.insert(kind_field.to_owned(), json!("lead"));
        patch.insert(id_field.to_owned(), json!(lead.to_string()));
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            &m.entity,
            m.id,
            version,
            Value::Object(patch),
        )
        .await?;
    }
    Ok(())
}

async fn delete(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    origin: &DeleteOrigin,
) -> Result<(), AppError> {
    attome_records::entity_crud::delete_record_for(
        state,
        ctx,
        ctx.user_id,
        entity,
        id,
        None,
        origin,
    )
    .await
}

/// Undoes a failed conversion's writes, best effort, newest first.
async fn compensate(state: &EngineState, ctx: &SecurityContext, lead: Uuid, done: &Done) {
    if let Err(error) = move_back(state, ctx, lead, &done.moved).await {
        tracing::warn!(%lead, %error, "lead conversion: activities not moved back");
    }
    let origin = DeleteOrigin::new(DeleteKind::Request).reason(Some("lead conversion failed"));
    for (entity, id) in [
        ("opportunity", done.opportunity),
        ("contact", done.contact),
        ("account", done.account),
    ] {
        if let Some(id) = id
            && let Err(error) = delete(state, ctx, entity, id, &origin).await
        {
            tracing::warn!(%lead, entity, %id, %error, "lead conversion: record not removed");
        }
    }
}

async fn create(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    values: Map<String, Value>,
) -> Result<Uuid, AppError> {
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        entity,
        Value::Object(values),
    )
    .await
    .map(|(id, _)| id)
}

/// Converts a lead (see the module doc).
pub async fn convert(
    state: &EngineState,
    ctx: &SecurityContext,
    lead_id: Uuid,
    expected_version: i64,
    body: &LeadConvertBody,
) -> Result<LeadConverted, AppError> {
    let account_mode = mode_of(&body.account, "account", false)?;
    let contact_mode = mode_of(&body.contact, "contact", true)?;
    let opportunity_mode = mode_of(&body.opportunity, "opportunity", true)?;
    require(state, ctx, "lead", lead_id, RecordAction::Update).await?;
    let lead = read_lead(state, lead_id).await?;
    if lead.get("row_version").and_then(Value::as_i64) != Some(expected_version) {
        return Err(AppError::Conflict("the lead changed since it was read"));
    }
    let status = lead
        .get("lead_status")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if status.as_deref() != Some("qualified") {
        return Err(AppError::Validation(
            "only a qualified lead can be converted".into(),
        ));
    }
    let claimed: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO lead_conversion (lead_id, previous_status, converted_by) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(lead_id)
    .bind(&status)
    .bind(ctx.user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(conversion) = claimed else {
        return Err(AppError::Conflict(
            "the lead is already converted or being converted",
        ));
    };

    let mut done = Done::default();
    match run(
        state,
        ctx,
        &lead,
        lead_id,
        account_mode,
        contact_mode,
        opportunity_mode,
        &mut done,
    )
    .await
    {
        Ok(result) => {
            finish(state, conversion, &done, &result).await?;
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                attome_audit::BusinessEvent::new(
                    "lead",
                    lead_id,
                    AuditOperation::Update,
                    "sales.lead.converted",
                    ctx.user_id,
                )
                .comment(format!("lead conversion {conversion}")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(LeadConverted {
                conversion_id: conversion,
                lead_id,
                account_id: result.account,
                contact_id: result.contact,
                opportunity_id: result.opportunity,
                moved: done.moved.len(),
            })
        }
        Err(error) => {
            compensate(state, ctx, lead_id, &done).await;
            sqlx::query("DELETE FROM lead_conversion WHERE id = $1 AND status = 'running'")
                .bind(conversion)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            Err(error)
        }
    }
}

/// The records a conversion ended with.
#[derive(Debug, Clone, Copy)]
struct Outcome {
    account: Uuid,
    contact: Option<Uuid>,
    opportunity: Option<Uuid>,
}

#[allow(clippy::too_many_arguments)]
async fn run(
    state: &EngineState,
    ctx: &SecurityContext,
    lead: &Value,
    lead_id: Uuid,
    account_mode: Mode,
    contact_mode: Mode,
    opportunity_mode: Mode,
    done: &mut Done,
) -> Result<Outcome, AppError> {
    let map = conversion_map(state);
    let account = match account_mode {
        Mode::Link(id) => {
            require(state, ctx, "account", id, RecordAction::Read).await?;
            id
        }
        _ => {
            let values = mapped(&map, "account", lead, &fields_of(state, "account"));
            let id = create(state, ctx, "account", values).await?;
            done.account = Some(id);
            id
        }
    };
    let contact = match contact_mode {
        Mode::Skip => None,
        Mode::Link(id) => {
            require(state, ctx, "contact", id, RecordAction::Read).await?;
            Some(id)
        }
        Mode::Create => {
            let mut values = mapped(&map, "contact", lead, &fields_of(state, "contact"));
            if fields_of(state, "contact").contains("account_ref") {
                values.insert("account_ref".into(), json!(account.to_string()));
            }
            let id = create(state, ctx, "contact", values).await?;
            done.contact = Some(id);
            Some(id)
        }
    };
    let opportunity = match opportunity_mode {
        Mode::Skip => None,
        Mode::Link(id) => {
            require(state, ctx, "opportunity", id, RecordAction::Read).await?;
            Some(id)
        }
        Mode::Create => {
            let mut values = mapped(&map, "opportunity", lead, &fields_of(state, "opportunity"));
            values.insert("account_ref".into(), json!(account.to_string()));
            if !values.contains_key("name") {
                let name = lead
                    .get("name")
                    .and_then(present)
                    .unwrap_or_else(|| json!("Converted lead"));
                values.insert("name".into(), name);
            }
            let id = create(state, ctx, "opportunity", values).await?;
            done.opportunity = Some(id);
            Some(id)
        }
    };
    let (target_entity, target) = match contact {
        Some(c) => ("contact", c),
        None => ("account", account),
    };
    move_children(state, ctx, lead_id, target_entity, target, done).await?;

    let lead_fields = fields_of(state, "lead");
    let mut patch = Map::new();
    patch.insert("lead_status".into(), json!("converted"));
    for (field, id) in [
        ("converted_account_ref", Some(account)),
        ("converted_contact_ref", contact),
        ("converted_opportunity_ref", opportunity),
    ] {
        if let Some(id) = id
            && lead_fields.contains(field)
        {
            patch.insert(field.into(), json!(id.to_string()));
        }
    }
    let version = version_of(state, "lead", lead_id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "lead",
        lead_id,
        version,
        Value::Object(patch),
    )
    .await?;
    Ok(Outcome {
        account,
        contact,
        opportunity,
    })
}

async fn finish(
    state: &EngineState,
    conversion: Uuid,
    done: &Done,
    out: &Outcome,
) -> Result<(), AppError> {
    let account_version = match done.account {
        Some(id) => version_of(state, "account", id).await?,
        None => None,
    };
    let contact_version = match done.contact {
        Some(id) => version_of(state, "contact", id).await?,
        None => None,
    };
    let opportunity_version = match done.opportunity {
        Some(id) => version_of(state, "opportunity", id).await?,
        None => None,
    };
    let moved = serde_json::to_value(&done.moved).map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE lead_conversion SET status = 'done', \
             account_id = $2, account_created = $3, account_version = $4, \
             contact_id = $5, contact_created = $6, contact_version = $7, \
             opportunity_id = $8, opportunity_created = $9, opportunity_version = $10, \
             moved = $11 \
         WHERE id = $1",
    )
    .bind(conversion)
    .bind(out.account)
    .bind(done.account.is_some())
    .bind(account_version)
    .bind(out.contact)
    .bind(done.contact.is_some())
    .bind(contact_version)
    .bind(out.opportunity)
    .bind(done.opportunity.is_some())
    .bind(opportunity_version)
    .bind(moved)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One stored conversion, for undoing it.
type ConversionRow = (
    Uuid,
    String,
    Uuid,
    bool,
    Option<Uuid>,
    Option<i64>,
    Option<Uuid>,
    Option<i64>,
    Option<Uuid>,
    Option<i64>,
    Value,
    bool,
);

/// Whether every created record still has the version the conversion left
/// (`None` stored means it was linked, not created). Pure.
pub fn unchanged(stored: &[(Option<i64>, Option<i64>)]) -> bool {
    stored
        .iter()
        .all(|(then, now)| then.is_none() || then == now)
}

/// Undoes a conversion (see the module doc).
pub async fn undo(
    state: &EngineState,
    ctx: &SecurityContext,
    conversion: Uuid,
) -> Result<LeadConversionUndone, AppError> {
    let row: Option<ConversionRow> = sqlx::query_as(
        "SELECT lead_id, status, converted_by, \
                converted_at > now() - make_interval(hours => $2::int), \
                CASE WHEN account_created THEN account_id END, account_version, \
                CASE WHEN contact_created THEN contact_id END, contact_version, \
                CASE WHEN opportunity_created THEN opportunity_id END, opportunity_version, \
                moved, undone_at IS NULL \
           FROM lead_conversion WHERE id = $1",
    )
    .bind(conversion)
    .bind(UNDO_HOURS as i32)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((
        lead,
        status,
        by,
        recent,
        account,
        account_v,
        contact,
        contact_v,
        opportunity,
        opportunity_v,
        moved,
        open,
    )) = row
    else {
        return Err(AppError::NotFound);
    };
    if by != ctx.user_id {
        return Err(AppError::NotFound);
    }
    if status != "done" || !open {
        return Err(AppError::Conflict(
            "the conversion is not done or was already undone",
        ));
    }
    if !recent {
        return Err(AppError::Validation(format!(
            "a conversion can be undone within {UNDO_HOURS} hours"
        )));
    }
    let mut now = Vec::new();
    for (entity, id, then) in [
        ("account", account, account_v),
        ("contact", contact, contact_v),
        ("opportunity", opportunity, opportunity_v),
    ] {
        let current = match id {
            Some(id) => version_of(state, entity, id).await?,
            None => None,
        };
        now.push((id.and(then), current));
    }
    if !unchanged(&now) {
        return Err(AppError::Conflict(
            "a record the conversion made has changed since; it cannot be undone",
        ));
    }
    let claimed = sqlx::query(
        "UPDATE lead_conversion SET status = 'undone', undone_at = now() \
          WHERE id = $1 AND status = 'done'",
    )
    .bind(conversion)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        return Err(AppError::Conflict("the conversion is already being undone"));
    }

    let moved: Vec<Moved> = serde_json::from_value(moved).unwrap_or_default();
    move_back(state, ctx, lead, &moved).await?;
    let lead_fields = fields_of(state, "lead");
    let mut patch = Map::new();
    patch.insert("lead_status".into(), json!("qualified"));
    for field in [
        "converted_account_ref",
        "converted_contact_ref",
        "converted_opportunity_ref",
    ] {
        if lead_fields.contains(field) {
            patch.insert(field.into(), Value::Null);
        }
    }
    if let Some(version) = version_of(state, "lead", lead).await? {
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            "lead",
            lead,
            version,
            Value::Object(patch),
        )
        .await?;
    }
    let origin = DeleteOrigin::new(DeleteKind::Request).reason(Some("lead conversion undone"));
    let mut removed = 0;
    for (entity, id) in [
        ("opportunity", opportunity),
        ("contact", contact),
        ("account", account),
    ] {
        if let Some(id) = id {
            delete(state, ctx, entity, id, &origin).await?;
            removed += 1;
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "lead",
            lead,
            AuditOperation::Update,
            "sales.lead.conversion_undone",
            ctx.user_id,
        )
        .comment(format!("lead conversion {conversion} undone")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(LeadConversionUndone {
        conversion_id: conversion,
        lead_id: lead,
        removed,
    })
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" of the lead is required".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/sales/leads/{id}/convert",
    operation_id = "get_sales_lead_convert_preview",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The lead")),
    responses(
        (status = 200, description = "What converting the lead would create, and the existing records it would repeat", body = LeadConvertPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such lead the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Preview a lead's conversion.
///
/// The values the account, contact and opportunity would get from the
/// conversion map, and the existing accounts and contacts the duplicate
/// rules match, so one can be linked instead.
pub(crate) async fn get_sales_lead_convert_preview(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(lead): Path<Uuid>,
) -> Result<Json<LeadConvertPreview>, AppError> {
    preview(&state, &ctx, lead).await.map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/leads/{id}/convert",
    operation_id = "post_sales_lead_convert",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The lead"),
        ("If-Match" = String, Header, description = "The lead's row_version"),
    ),
    request_body = LeadConvertBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The lead is converted", body = LeadConverted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the lead or create the records", body = ErrorResponse),
        (status = 404, description = "No such lead, or a linked record the caller may not read", body = ErrorResponse),
        (status = 409, description = "Changed since read, or already converted", body = ErrorResponse),
        (status = 422, description = "Not qualified, a bad choice, or If-Match missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Convert a qualified lead.
///
/// Creates or links the account, creates, links or skips the contact and
/// the opportunity, moves the lead's activities and notes to the contact
/// (else the account) and marks the lead converted. Send the lead's
/// `row_version` in `If-Match`.
pub(crate) async fn post_sales_lead_convert(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(lead): Path<Uuid>,
    headers: HeaderMap,
    body: Option<Json<LeadConvertBody>>,
) -> Result<Json<LeadConverted>, AppError> {
    let expected = if_match(&headers)?;
    let body = body.map(|b| b.0).unwrap_or_default();
    convert(&state, &ctx, lead, expected, &body).await.map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/lead-conversions/{id}/undo",
    operation_id = "post_sales_lead_conversion_undo",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The conversion")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The conversion is undone", body = LeadConversionUndone),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such conversion of the caller's", body = ErrorResponse),
        (status = 409, description = "Already undone, or a record it made has changed", body = ErrorResponse),
        (status = 422, description = "Older than 24 hours", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Undo a lead conversion.
///
/// Within 24 hours, by the person who converted, while every record it
/// made is unchanged: moves activities and notes back, returns the lead to
/// qualified and deletes the records it made.
pub(crate) async fn post_sales_lead_conversion_undo(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(conversion): Path<Uuid>,
) -> Result<Json<LeadConversionUndone>, AppError> {
    undo(&state, &ctx, conversion).await.map(Json)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_sales_lead_convert_preview,
        post_sales_lead_convert,
        post_sales_lead_conversion_undo
    ),
    components(schemas(
        ConvertTarget,
        LeadConvertBody,
        LeadConvertPreview,
        LeadConverted,
        LeadConversionUndone
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn the_map_copies_present_values_the_target_has() {
        let lead = json!({
            "company_name": "Acme",
            "name": "Sara",
            "email": "sara@acme.sa",
            "phone": "  ",
            "budget": 5000,
        });
        let map = default_map();
        let account = mapped(
            &map,
            "account",
            &lead,
            &set(&["name", "phone", "email_domain"]),
        );
        assert_eq!(account.get("name"), Some(&json!("Acme")));
        assert_eq!(account.get("email_domain"), Some(&json!("acme.sa")));
        assert!(
            !account.contains_key("phone"),
            "a blank value is not copied"
        );
        let contact = mapped(&map, "contact", &lead, &set(&["full_name", "email"]));
        assert_eq!(contact.get("full_name"), Some(&json!("Sara")));
        assert!(
            !contact.contains_key("mobile_phone"),
            "a field the target lacks is left out"
        );
        let opportunity = mapped(&map, "opportunity", &lead, &set(&["name", "amount"]));
        assert_eq!(opportunity.get("amount"), Some(&json!(5000)));
    }

    #[test]
    fn modes_read_create_link_and_skip() {
        let id = Uuid::now_v7();
        let target = |mode: Option<&str>, id: Option<Uuid>| ConvertTarget {
            mode: mode.map(str::to_owned),
            id,
        };
        assert_eq!(
            mode_of(&target(None, None), "account", false).unwrap(),
            Mode::Create
        );
        assert_eq!(
            mode_of(&target(Some("link"), Some(id)), "account", false).unwrap(),
            Mode::Link(id)
        );
        assert!(mode_of(&target(Some("link"), None), "account", false).is_err());
        assert!(mode_of(&target(Some("skip"), None), "account", false).is_err());
        assert_eq!(
            mode_of(&target(Some("skip"), None), "contact", true).unwrap(),
            Mode::Skip
        );
    }

    #[test]
    fn undo_needs_every_created_record_unchanged() {
        assert!(unchanged(&[(Some(1), Some(1)), (None, Some(7))]));
        assert!(!unchanged(&[(Some(1), Some(2))]));
        assert!(
            !unchanged(&[(Some(1), None)]),
            "a deleted record has changed"
        );
    }
}

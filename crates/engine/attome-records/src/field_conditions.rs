//! Q15-T3: conditional field reads. A field-security grant may carry a read
//! condition, a rule expression over the record's own fields
//! ([`SecurityContext::field_read_conditions`]): its holder sees the field in
//! full on the records that meet it, and elsewhere as before (hidden, or
//! masked when another grant masks it).
//!
//! Two interactive surfaces apply it. A record read checks its one record
//! ([`widened_for_record`]) and reads it with the field granted, so masking,
//! decryption and the view log all treat it as any granted field. A record
//! list adds the field's value to the rows that meet the condition
//! ([`reveal_in_rows`]); an encrypted field stays hidden there, since a list
//! never decrypts. Every other surface (bulk reads, exports, reports, query
//! paths, AI context) keeps the field hidden: the condition widens nothing it
//! does not check. A check that cannot run reveals nothing (fails closed).

use std::collections::{HashMap, HashSet};

use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::field_gate::{self, Surface};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// The attributes of `entity` that `ctx` reads only under a condition: read
/// gated, not otherwise readable, named by a conditional grant.
fn conditional_attrs<'a>(
    ctx: &SecurityContext,
    entity: &str,
    attrs: &'a [AttrInfo],
) -> Vec<&'a AttrInfo> {
    if ctx.is_admin || ctx.field_read_conditions.is_empty() {
        return Vec::new();
    }
    attrs
        .iter()
        .filter(|attr| attr.is_read_gated())
        .filter(|attr| {
            ctx.field_read_conditions
                .contains_key(&format!("{entity}.{}", attr.logicalname))
        })
        .filter(|attr| !field_gate::readable(ctx, entity, attr, None, Surface::Interactive))
        .filter(|attr| {
            attome_core::agent_scope::current().is_none() || !field_gate::hidden_from_ai(attr)
        })
        .collect()
}

/// The fields among `candidates` whose condition `record_id` meets.
async fn fields_met(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    candidates: &[&AttrInfo],
    record_id: Uuid,
) -> Vec<String> {
    let mut met = Vec::new();
    for attr in candidates {
        let Some(condition) = attome_security::conditions::field_condition_predicate(
            ctx,
            entity,
            &attr.logicalname,
            attrs,
            "t",
            2,
        ) else {
            continue;
        };
        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM {} t WHERE t.id = $1 AND ({}))",
            quote_ident(entity),
            condition.sql
        );
        let mut query = sqlx::query_scalar::<_, bool>(&sql).bind(record_id);
        for bind in &condition.binds {
            query = query.bind(bind);
        }
        match query.fetch_one(&state.base.db).await {
            Ok(true) => met.push(attr.logicalname.clone()),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                entity = %entity,
                field = %attr.logicalname,
                %error,
                "records: a conditional field read could not be checked; the field stays hidden"
            ),
        }
    }
    met
}

/// `ctx` with every conditional field of `entity` that `record_id` meets
/// granted, or `None` when there is none (read with `ctx` itself).
pub(crate) async fn widened_for_record(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
) -> Option<SecurityContext> {
    let candidates = conditional_attrs(ctx, entity, attrs);
    if candidates.is_empty() {
        return None;
    }
    let met = fields_met(state, ctx, entity, attrs, &candidates, record_id).await;
    if met.is_empty() {
        return None;
    }
    Some(ctx.with_field_grants(met.into_iter().map(|field| format!("{entity}.{field}"))))
}

/// Adds to `rows` (each with an `id`) the value of every conditional field
/// of `entity` whose condition that row meets, replacing a masked value.
/// Encrypted fields are left out: a list returns no decrypted value. A
/// revealed Financial or Health value is logged as a full read (Q15-T5).
pub(crate) async fn reveal_in_rows(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    rows: &mut [Map<String, Value>],
) -> Result<(), AppError> {
    let candidates: Vec<&AttrInfo> = conditional_attrs(ctx, entity, attrs)
        .into_iter()
        .filter(|attr| crate::attr_crypto::mode_for(attr).is_none())
        .collect();
    if candidates.is_empty() || rows.is_empty() {
        return Ok(());
    }
    let logged: HashSet<&str> = candidates
        .iter()
        .filter(|attr| attome_security::view_log::is_logged(attr))
        .map(|attr| attr.logicalname.as_str())
        .collect();
    let ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let mut revealed: HashMap<(Uuid, String), Value> = HashMap::new();
    for attr in candidates {
        let Some(condition) = attome_security::conditions::field_condition_predicate(
            ctx,
            entity,
            &attr.logicalname,
            attrs,
            "t",
            2,
        ) else {
            continue;
        };
        let sql = format!(
            "SELECT t.id, to_jsonb(t.{}) FROM {} t WHERE t.id = ANY($1) AND ({})",
            quote_ident(&attr.logicalname),
            quote_ident(entity),
            condition.sql
        );
        let mut query = sqlx::query_as::<_, (Uuid, Option<Value>)>(&sql).bind(&ids);
        for bind in &condition.binds {
            query = query.bind(bind);
        }
        match query.fetch_all(&state.base.db).await {
            Ok(found) => {
                for (id, value) in found {
                    revealed.insert((id, attr.logicalname.clone()), value.unwrap_or(Value::Null));
                }
            }
            Err(error) => tracing::warn!(
                entity = %entity,
                field = %attr.logicalname,
                %error,
                "records: a conditional field read could not be checked; the field stays hidden"
            ),
        }
    }
    if revealed.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let views = revealed
        .iter()
        .filter(|((_, field), value)| logged.contains(field.as_str()) && !value.is_null())
        .map(
            |((record_id, field), _)| attome_security::view_log::ViewEntry {
                user_id: ctx.user_id,
                entity: entity.to_owned(),
                record_id: *record_id,
                attribute: field.clone(),
                viewed_at: now,
            },
        )
        .collect();
    attome_security::view_log::record(&state.base.db, views).await?;
    for row in rows.iter_mut() {
        let Some(id) = row
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            continue;
        };
        for ((record, field), value) in &revealed {
            if *record == id {
                row.insert(field.clone(), value.clone());
            }
        }
    }
    Ok(())
}

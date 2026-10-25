//! `?expand=` (roadmap S1-T4): a record read carries the records its lookup
//! fields point at, inline under `expanded`, keyed by the lookup attribute.
//! One query per expanded lookup, filtered by the target entity's own
//! record-level access and field security; a target the caller may not
//! read is simply absent (hidden reads as missing, as for lookup names).

use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value};
use utoipa::IntoParams;
use uuid::Uuid;

/// The most lookups one request expands.
pub(super) const MAX_EXPAND: usize = 5;

/// `?expand=a,b`: lookup attributes whose targets to return inline.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExpandParam {
    /// Comma-separated lookup attributes (at most 5); each target comes back
    /// under `expanded.<attribute>` when the caller may read it.
    pub expand: Option<String>,
}

/// The lookup attributes `raw` names. Only lookups; one level deep.
pub(super) fn parse_expand<'a>(
    raw: &str,
    attrs: &'a [AttrInfo],
) -> Result<Vec<&'a AttrInfo>, AppError> {
    let mut out: Vec<&AttrInfo> = Vec::new();
    for name in raw.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if name.contains('.') {
            return Err(AppError::Validation("expand depth limited to 1".into()));
        }
        let attr = attrs
            .iter()
            .find(|a| a.logicalname == name && a.lookup_entity_ref.is_some())
            .ok_or_else(|| AppError::Validation(format!("unknown attribute: {name}")))?;
        if !out.iter().any(|a| a.logicalname == attr.logicalname) {
            out.push(attr);
        }
    }
    if out.len() > MAX_EXPAND {
        return Err(AppError::Validation(format!(
            "expand takes at most {MAX_EXPAND} lookups"
        )));
    }
    Ok(out)
}

/// The target record `id` of one lookup, as the caller may see it, or
/// `None` when it is hidden, missing or deleted.
async fn read_target(
    state: &EngineState,
    ctx: &SecurityContext,
    target_entity_id: Uuid,
    id: Uuid,
) -> Result<Option<Value>, AppError> {
    let Some((table, attrs)) = ({
        let registry = state.entities.load();
        registry
            .get_by_id(target_entity_id)
            .map(|m| (m.logicalname.clone(), m.attrs.clone()))
    }) else {
        return Ok(None);
    };
    if ctx.require(&table, "read").is_err() {
        return Ok(None);
    }
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        target_entity_id,
        &table,
        RecordAction::Read,
    )
    .await?;
    let pred = attome_security::rls_predicate(
        ctx,
        target_entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );
    let columns = attome_core::select_columns_filtered(&attrs, |a| {
        ctx.has_field_read_grant(&table, &a.logicalname)
    });
    let predicate = pred.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {columns} FROM {} \
          WHERE id = $1 AND (is_active IS NULL OR is_active = TRUE) {predicate}) t",
        quote_ident(&table)
    );
    let sql = attome_db::tag_dynamic("entity.expand", &sql);
    let mut query = sqlx::query_scalar::<_, Value>(&sql).bind(id);
    if let Some(p) = &pred {
        query = query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    query
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// The `expanded` object for one record's `data`.
pub(super) async fn expand_record(
    state: &EngineState,
    ctx: &SecurityContext,
    data: &Value,
    lookups: &[&AttrInfo],
) -> Result<Map<String, Value>, AppError> {
    let mut expanded = Map::new();
    for attr in lookups {
        let Some(target) = attr.lookup_entity_ref else {
            continue;
        };
        let Some(id) = data
            .get(&attr.logicalname)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        if let Some(row) = read_target(state, ctx, target, id).await? {
            expanded.insert(attr.logicalname.clone(), row);
        }
    }
    Ok(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::meta_registry::{DataClassification, OnTargetDelete};

    fn attr(name: &str, lookup: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: if lookup { 11 } else { 1 },
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: lookup.then(Uuid::now_v7),
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    #[test]
    fn parse_expand_accepts_lookups_only() {
        let attrs = vec![attr("parentcustomerid", true), attr("name", false)];
        let got = parse_expand("parentcustomerid", &attrs).expect("lookup");
        assert_eq!(got.len(), 1);
        assert!(parse_expand("name", &attrs).is_err(), "not a lookup");
        assert!(parse_expand("nope", &attrs).is_err());
        assert_eq!(
            parse_expand("parentcustomerid, parentcustomerid", &attrs)
                .expect("dedup")
                .len(),
            1
        );
    }

    #[test]
    fn parse_expand_rejects_dotted_names() {
        let attrs = vec![attr("parentcustomerid", true)];
        let err = parse_expand("parentcustomerid.ownerid", &attrs).expect_err("dotted");
        assert!(
            err.to_string().contains("expand depth limited to 1"),
            "{err}"
        );
    }
}

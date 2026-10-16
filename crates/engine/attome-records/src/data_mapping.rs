//! M12/D-408 field-mapping application — relocated here by D-477 (T3-2)
//! from `attome-server`'s `data_mapping_admin.rs`. `apply_mapping_to_record`
//! and `load_mapping` are called only by [`crate::bulk`]'s staged import
//! (`mapping_ref`), and `apply_mapping_to_record` already took
//! `&mut crate::bulk::BulkRecordEnvelope` — a type native to this crate — so
//! they belong here, not in the CRUD-routes file that stayed behind.
//!
//! `attome-server`'s `data_mapping_admin.rs` keeps the `/api/v1/admin/data/
//! mappings*` CRUD routes unchanged, and imports [`DataMappingField`] back
//! from here for its own request/response bodies (the safe direction:
//! `attome-server` already depends on this crate).
//!
//! `fields[].transform` is a nullable free-text M45 (attome-rules) expression
//! column, never evaluated here — see D-408. An unset or set-but-
//! unevaluated `transform` is identity/passthrough either way.

use std::collections::HashMap;

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::import_choice_match::ChoiceMatcher;

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct DataMappingField {
    pub source: String,
    pub target: String,
    /// Nullable M45 expression — see this file's module doc. Never
    /// evaluated anywhere in this worktree.
    #[serde(default)]
    pub transform: Option<String>,
    /// `"by_id"` (default) | `"by_natural_key"` | `"by_label"`.
    #[serde(default = "default_lookup_resolution")]
    pub lookup_resolution: String,
    /// Required (and only meaningful) when `lookup_resolution` is
    /// `"by_natural_key"` — the attribute on the *referenced* lookup entity
    /// to match the source value against.
    #[serde(default)]
    pub lookup_match_field: Option<String>,
}

fn default_lookup_resolution() -> String {
    "by_id".to_string()
}

async fn resolve_lookup_value(
    db: &attome_db::DbPool,
    target_attrs: &[attome_core::AttrInfo],
    field: &DataMappingField,
    value: &Value,
) -> Result<Value, AppError> {
    let attr = target_attrs
        .iter()
        .find(|a| a.logicalname == field.target)
        .ok_or_else(|| {
            AppError::Validation(format!("unknown mapped target field: {}", field.target))
        })?;
    let Some(lookup_entity_id) = attr.lookup_entity_ref else {
        return Err(AppError::Validation(format!(
            "field {} is not a lookup field; lookup_resolution requires a lookup field",
            field.target
        )));
    };
    let lookup_entity_name: Option<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(lookup_entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let lookup_entity_name = lookup_entity_name.ok_or_else(|| {
        AppError::Validation(format!(
            "{}'s lookup target entity no longer exists",
            field.target
        ))
    })?;

    let raw = value.as_str().ok_or_else(|| {
        AppError::Validation(format!("{} lookup value must be a string", field.target))
    })?;
    let match_col = match field.lookup_resolution.as_str() {
        "by_natural_key" => field.lookup_match_field.clone().ok_or_else(|| {
            AppError::Validation("lookup_match_field is required for by_natural_key".into())
        })?,
        // No metadata-declared "primary display field" concept exists on
        // this platform today (D-408) — "name" is the documented
        // convention every seeded entity happens to follow, not an
        // enforced flag.
        "by_label" => "name".to_string(),
        other => {
            return Err(AppError::Validation(format!(
                "unsupported lookup_resolution: {other}"
            )));
        }
    };
    let quoted_table = attome_core::quote_ident(&lookup_entity_name);
    let quoted_col = attome_core::quote_ident(&match_col);
    let sql = format!(
        "SELECT id FROM {quoted_table} WHERE {quoted_col} = $1 AND (is_active IS NULL OR is_active = true) LIMIT 2"
    );
    let matches: Vec<Uuid> = sqlx::query_scalar(&sql)
        .bind(raw)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    match matches.as_slice() {
        [id] => Ok(Value::String(id.to_string())),
        [] => Err(AppError::Validation(format!(
            "no {} matches {} = {:?}",
            lookup_entity_name, match_col, raw
        ))),
        _ => Err(AppError::Validation(format!(
            "{} matches are ambiguous for {} = {:?}",
            lookup_entity_name, match_col, raw
        ))),
    }
}

/// Renames `source` keys to `target` attribute names, and resolves a
/// lookup field's value when `lookup_resolution` isn't the `by_id`
/// default. `transform` is deliberately never evaluated — see this file's
/// module doc / D-408; an unset or set transform is identity either way.
///
/// A field absent from the record's `data` is skipped (not an error) —
/// the mapping declares what *can* be translated, not that every mapped
/// field must be present on every record.
pub(crate) async fn apply_mapping_to_record(
    db: &attome_db::DbPool,
    target_attrs: &[attome_core::AttrInfo],
    fields: &[DataMappingField],
    choices: &ChoiceMatchers,
    record: &mut crate::bulk::BulkRecordEnvelope,
) -> Result<(), AppError> {
    let source_obj = record
        .data
        .as_object()
        .ok_or_else(|| AppError::Validation("record data must be a JSON object".into()))?
        .clone();
    let mut mapped = serde_json::Map::new();
    for field in fields {
        let Some(raw_value) = source_obj.get(&field.source) else {
            continue;
        };
        let value = if field.lookup_resolution == "by_id" {
            raw_value.clone()
        } else {
            resolve_lookup_value(db, target_attrs, field, raw_value).await?
        };
        let value = match choices.get(&field.target) {
            Some((matcher, multi)) => match_choice_value(matcher, *multi, &field.target, value)?,
            None => value,
        };
        mapped.insert(field.target.clone(), value);
    }
    record.data = Value::Object(mapped);
    Ok(())
}

/// A6-T3: the matcher and multi-select flag of each mapped choice attribute,
/// by attribute name.
pub(crate) type ChoiceMatchers = HashMap<String, (ChoiceMatcher, bool)>;

/// A mapped choice attribute: its name, options and inline labels.
type WantedChoice = (String, attome_field::ChoiceOptions, Vec<(String, String)>);

/// Builds a [`ChoiceMatcher`] for every mapped target attribute that is a
/// choice field with a closed list, from its stored values, the labels kept
/// in its options (`option_labels`) and every translated `choice_option`
/// label in `metadata_label`. One query for the whole import, none when no
/// mapped attribute is a choice.
pub(crate) async fn load_choice_matchers(
    db: &attome_db::DbPool,
    entity_name: &str,
    target_attrs: &[attome_core::AttrInfo],
    fields: &[DataMappingField],
) -> Result<ChoiceMatchers, AppError> {
    let mut wanted: Vec<WantedChoice> = Vec::new();
    for field in fields {
        let Some(attr) = target_attrs.iter().find(|a| a.logicalname == field.target) else {
            continue;
        };
        if attome_core::FieldType::from_int(attr.field_type_int)
            != Some(attome_core::FieldType::Choice)
        {
            continue;
        }
        let Some(options) = attr.options.as_ref() else {
            continue;
        };
        let Ok(parsed) = serde_json::from_value::<attome_field::ChoiceOptions>(options.clone())
        else {
            continue;
        };
        if parsed.choices.is_empty() || wanted.iter().any(|w| w.0 == field.target) {
            continue;
        }
        let inline: Vec<(String, String)> = options
            .get("option_labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        wanted.push((field.target.clone(), parsed, inline));
    }
    if wanted.is_empty() {
        return Ok(HashMap::new());
    }
    let refs: Vec<String> = wanted
        .iter()
        .flat_map(|(attr, opts, _)| {
            opts.choices
                .iter()
                .map(move |value| format!("{entity_name}.{attr}.{value}"))
        })
        .collect();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT object_ref, display_name FROM metadata_label \
         WHERE object_kind = 'choice_option' AND is_deleted = false AND object_ref = ANY($1)",
    )
    .bind(&refs)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = HashMap::new();
    for (attr, opts, mut labels) in wanted {
        let prefix = format!("{entity_name}.{attr}.");
        labels.extend(rows.iter().filter_map(|(object_ref, label)| {
            object_ref
                .strip_prefix(&prefix)
                .map(|value| (value.to_owned(), label.clone()))
        }));
        out.insert(
            attr,
            (ChoiceMatcher::new(&opts.choices, &labels), opts.multi),
        );
    }
    Ok(out)
}

/// Maps a cell to the stored choice value(s) it names; a value already in
/// stored form passes through unchanged. An empty cell is null; non-text
/// cells are left for the field validator.
fn match_choice_value(
    matcher: &ChoiceMatcher,
    multi: bool,
    attr: &str,
    value: Value,
) -> Result<Value, AppError> {
    let invalid = |e: crate::import_choice_match::ChoiceMatchError| {
        AppError::Validation(format!("{attr}: {e}"))
    };
    match value {
        Value::String(text) if text.trim().is_empty() => Ok(Value::Null),
        Value::String(text) if multi => Ok(Value::Array(
            matcher
                .match_many(&text)
                .map_err(invalid)?
                .into_iter()
                .map(Value::String)
                .collect(),
        )),
        Value::String(text) => Ok(Value::String(
            matcher.match_one(&text).map_err(invalid)?.to_owned(),
        )),
        Value::Array(items) if multi => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(text) => out.push(Value::String(
                        matcher.match_one(&text).map_err(invalid)?.to_owned(),
                    )),
                    other => out.push(other),
                }
            }
            Ok(Value::Array(out))
        }
        other => Ok(other),
    }
}

/// Loaded by `bulk::staged_import` when the caller passes `mapping_ref`.
pub async fn load_mapping(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<(String, Vec<DataMappingField>)>, AppError> {
    let row: Option<(String, Value)> = sqlx::query_as(
        "SELECT target_entity, fields FROM data_mapping WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match row {
        None => Ok(None),
        Some((target_entity, fields_json)) => {
            let fields: Vec<DataMappingField> =
                serde_json::from_value(fields_json).map_err(AppError::internal)?;
            Ok(Some((target_entity, fields)))
        }
    }
}

//! A23-T4: validating a staged import (a dry run). [`validate`] reads the
//! job's staged rows in batches of [`VALIDATE_BATCH`] and, for each row:
//!
//! 1. applies the job's mapping (`import_job.mapping`, [`ImportMapping`]):
//!    rename, skip, split, constant;
//! 2. turns each cell's text into the target field's type (numbers and dates
//!    with Western digits, booleans, choice labels through the A6-T3
//!    matcher) and runs the generic create's own validator
//!    ([`crate::entity_mutation::validate_body`]);
//! 3. resolves lookups by id, name, code or external key with one query per
//!    lookup field per batch (`= ANY($1)`), caching every answer for the
//!    whole job; a value that matches no record or several is a row error,
//!    or, with `create_missing`, a value marked for creation;
//! 4. matches existing records by the job's `match_columns` (or a mapped
//!    `id`) with one query per batch and sets the row's action from the
//!    job's `match_mode`: `create` skips a row that exists, `update` skips one
//!    that does not, `upsert` does both;
//! 5. runs the A15 duplicate check for each row it would create, as the job's
//!    creator, and notes a row whose match key repeats an earlier row of the
//!    file.
//!
//! Each row's mapped values, status (`valid`/`invalid`), action, matched
//! record and errors are written back to `import_stage`; the counts
//! `{create, update, skip, invalid, duplicates}` go to `import_job.counts`
//! and the job becomes `validated`. Nothing here writes an entity table:
//! validation is the dry run. Running it again recomputes every row, and the
//! counts are read back from the stage, so a rerun converges.
//!
//! A file exported with `id` and `row_version` reads back as updates that
//! expect the exported version (A23-T14): a record changed in between is
//! refused when the import applies, never overwritten.
//!
//! Matching existing records reads every live record, whatever the creator
//! may see: an import is an administrator's tool, and the apply step writes
//! with the creator's own security.

use std::collections::{HashMap, HashSet};

use attome_core::{AttrInfo, EngineState, FieldType, quote_ident};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::data_mapping::{
    ChoiceMatchers, DataMappingField, load_choice_matchers, match_choice_value,
};

/// Staged rows read, checked and written back per round.
pub const VALIDATE_BATCH: i64 = 2_000;

/// How a staged file's columns become record fields. An empty `columns`
/// list maps every column to the field of the same name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportMapping {
    #[serde(default)]
    pub columns: Vec<ColumnMap>,
    /// How each lookup field's cell names its record; a lookup without an
    /// entry is matched by the target's `name`.
    #[serde(default)]
    pub lookups: HashMap<String, LookupMap>,
    /// A lookup value no record holds is marked for creation instead of
    /// being an error.
    #[serde(default)]
    pub create_missing: bool,
}

/// One column rule: `source` to `target` (the source name by default),
/// `skip`, `split` into several fields, or a `constant` for `target`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnMap {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub skip: bool,
    #[serde(default)]
    pub split: Option<SplitMap>,
    #[serde(default)]
    pub constant: Option<Value>,
}

/// Splits a cell at `separator` into `targets`, in order; the last target
/// keeps the rest of the text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitMap {
    pub separator: String,
    pub targets: Vec<String>,
}

/// What a lookup cell holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupBy {
    /// The record's id.
    Id,
    /// A display name (`field`, `name` by default).
    #[default]
    Name,
    /// A code (`field`, `code` by default); a hierarchy's parent by its code.
    Code,
    /// An external id (`field` must be an external-id attribute, A29).
    Key,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupMap {
    #[serde(default)]
    pub by: LookupBy,
    /// The target attribute the cell is matched against.
    #[serde(default)]
    pub field: Option<String>,
}

impl LookupMap {
    fn match_field(&self) -> Option<&str> {
        match (self.by, self.field.as_deref()) {
            (LookupBy::Id, _) => None,
            (_, Some(field)) => Some(field),
            (LookupBy::Name, None) => Some("name"),
            (LookupBy::Code, None) => Some("code"),
            (LookupBy::Key, None) => Some(""),
        }
    }
}

/// One problem with one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowError {
    pub field: String,
    pub code: String,
    /// The i18n key the screen shows, `import.error.<code>`.
    pub message_key: String,
}

impl RowError {
    fn new(field: &str, code: &str) -> Self {
        Self {
            field: field.to_owned(),
            code: code.to_owned(),
            message_key: format!("import.error.{code}"),
        }
    }
}

/// What applying a valid row would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    Skip,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Skip => "skip",
        }
    }

    /// The action for a row under `match_mode`, given whether it matched.
    pub fn for_mode(match_mode: &str, matched: bool) -> Self {
        match (match_mode, matched) {
            ("create", true) | ("update", false) => Self::Skip,
            ("create", false) | ("upsert", false) => Self::Create,
            _ => Self::Update,
        }
    }
}

/// The job's counts after validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ValidateCounts {
    pub create: i64,
    pub update: i64,
    pub skip: i64,
    pub invalid: i64,
    pub duplicates: i64,
}

impl ImportMapping {
    /// Checks the rules' shape against the entity's fields: every target is
    /// a field, a constant and a split name their targets.
    pub fn check(&self, attrs: &[AttrInfo]) -> Result<(), AppError> {
        let known: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
        let field = |name: &str| -> Result<(), AppError> {
            if known.contains(name) {
                Ok(())
            } else {
                Err(AppError::Validation(format!(
                    "mapping: {name} is not a field of this entity"
                )))
            }
        };
        for (i, column) in self.columns.iter().enumerate() {
            if column.skip {
                continue;
            }
            match (&column.constant, &column.split) {
                (Some(_), Some(_)) => {
                    return Err(AppError::Validation(format!(
                        "mapping column {i}: a constant cannot also split"
                    )));
                }
                (Some(_), None) => {
                    field(column.target.as_deref().ok_or_else(|| {
                        AppError::Validation(format!(
                            "mapping column {i}: a constant needs a target"
                        ))
                    })?)?;
                }
                (None, Some(split)) => {
                    if column.source.is_none()
                        || split.targets.is_empty()
                        || split.separator.is_empty()
                    {
                        return Err(AppError::Validation(format!(
                            "mapping column {i}: a split needs a source, a separator and targets"
                        )));
                    }
                    for target in &split.targets {
                        field(target)?;
                    }
                }
                (None, None) => {
                    let source = column.source.as_deref().ok_or_else(|| {
                        AppError::Validation(format!("mapping column {i}: give a source"))
                    })?;
                    field(column.target.as_deref().unwrap_or(source))?;
                }
            }
        }
        for name in self.lookups.keys() {
            let attr = attrs.iter().find(|a| &a.logicalname == name);
            if attr.is_none_or(|a| a.field_type() != FieldType::Lookup) {
                return Err(AppError::Validation(format!(
                    "mapping.lookups: {name} is not a lookup field"
                )));
            }
        }
        Ok(())
    }

    /// The row as field name to cell (or constant) value. Pure.
    pub fn apply(&self, raw: &Map<String, Value>) -> Map<String, Value> {
        if self.columns.is_empty() {
            return raw.clone();
        }
        let mut out = Map::new();
        for column in &self.columns {
            if column.skip {
                continue;
            }
            if let Some(constant) = &column.constant {
                if let Some(target) = &column.target {
                    out.insert(target.clone(), constant.clone());
                }
                continue;
            }
            let Some(source) = column.source.as_deref() else {
                continue;
            };
            let Some(cell) = raw.get(source) else {
                continue;
            };
            match &column.split {
                Some(split) => {
                    let text = cell.as_str().unwrap_or_default();
                    let parts = text.splitn(split.targets.len(), split.separator.as_str());
                    for (target, part) in split.targets.iter().zip(parts) {
                        out.insert(target.clone(), Value::String(part.trim().to_owned()));
                    }
                }
                None => {
                    let target = column.target.as_deref().unwrap_or(source);
                    out.insert(target.to_owned(), cell.clone());
                }
            }
        }
        out
    }
}

/// An attribute with only a name and a type: the `id` column a match by id
/// compares, and test fixtures.
fn plain_attr(name: &str, field_type: FieldType) -> AttrInfo {
    AttrInfo {
        logicalname: name.to_owned(),
        field_type_int: field_type.to_int(),
        is_required: false,
        max_length: None,
        is_sensitive: false,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity_ref: None,
        on_target_delete: Default::default(),
        data_classification: Default::default(),
        sensitivity: Default::default(),
        sensitivity_confirmed: false,
        options: None,
    }
}

/// A boolean cell: English and Arabic yes/no, `1`/`0`. Pure.
fn parse_bool(text: &str) -> Option<bool> {
    match attome_field::western_digits(text)
        .trim()
        .to_lowercase()
        .as_str()
    {
        "true" | "yes" | "y" | "1" | "نعم" => Some(true),
        "false" | "no" | "n" | "0" | "لا" => Some(false),
        _ => None,
    }
}

/// A non-lookup cell as its field's value: `None` for an empty cell. The
/// value still goes through the create validator after this. Pure.
pub fn convert_cell(
    attr: &AttrInfo,
    cell: &Value,
    choices: &ChoiceMatchers,
) -> Result<Option<Value>, RowError> {
    let text = match cell {
        Value::Null => return Ok(None),
        Value::String(s) => s.trim().to_owned(),
        // A mapping constant may already be typed.
        other => return Ok(Some(other.clone())),
    };
    if text.is_empty() {
        return Ok(None);
    }
    let name = attr.logicalname.as_str();
    let ft = attr.field_type();
    let options = attr.options.as_ref();
    let value = match ft {
        FieldType::Bool => {
            Value::Bool(parse_bool(&text).ok_or_else(|| RowError::new(name, "invalid_bool"))?)
        }
        FieldType::Number | FieldType::Currency => {
            attome_field::normalize(&ft, &Value::String(text), options)
                .ok_or_else(|| RowError::new(name, "invalid_number"))?
        }
        FieldType::Choice => match choices.get(name) {
            Some((matcher, multi)) => {
                match_choice_value(matcher, *multi, name, Value::String(text))
                    .map_err(|_| RowError::new(name, "invalid_choice"))?
            }
            None => Value::String(text),
        },
        FieldType::Date | FieldType::DateTime | FieldType::Time => {
            Value::String(attome_field::western_digits(&text))
        }
        FieldType::File | FieldType::Image | FieldType::Formula => {
            return Err(RowError::new(name, "not_importable"));
        }
        // A2-T3: a json cell is JSON text; a point is `lat,lng` (normalised below).
        FieldType::Json => {
            serde_json::from_str(&text).map_err(|_| RowError::new(name, "invalid_json"))?
        }
        _ => {
            let value = Value::String(text);
            attome_field::normalize(&ft, &value, options).unwrap_or(value)
        }
    };
    Ok(Some(value))
}

/// A mapped value as the text a match or lookup compares. Pure.
fn key_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The match key of `values` over `columns`, when every column has a value.
/// Pure.
pub fn match_key(columns: &[String], values: &Map<String, Value>) -> Option<String> {
    let parts: Option<Vec<String>> = columns
        .iter()
        .map(|c| values.get(c).and_then(key_text))
        .collect();
    parts.map(|p| p.join("\u{1f}"))
}

/// What a lookup cell resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    Found(Uuid),
    Missing,
    Ambiguous,
}

/// One lookup field of the job: where it points and how its cells match.
struct LookupTarget {
    field: String,
    table: String,
    /// `None` matches by id.
    column: Option<AttrInfo>,
}

/// The job, as validation reads it.
#[derive(sqlx::FromRow)]
struct JobRow {
    entity_logicalname: String,
    mapping: Value,
    match_mode: String,
    match_columns: Vec<String>,
    status: String,
    created_by: Uuid,
}

/// Prepares one lookup field: its target table and the column its cells
/// match.
async fn lookup_target(
    state: &EngineState,
    attr: &AttrInfo,
    rule: &LookupMap,
) -> Result<LookupTarget, AppError> {
    let target_ref = attr.lookup_entity_ref.ok_or_else(|| {
        AppError::Validation(format!(
            "{}: the lookup has no target entity",
            attr.logicalname
        ))
    })?;
    let target: String = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(target_ref)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "{}: the lookup's target entity is gone",
            attr.logicalname
        ))
    })?;
    let (_, table, target_attrs, _) = crate::entity_crud::resolve_entity(state, &target).await?;
    let column = match rule.match_field() {
        None => None,
        Some(field) => {
            let found = target_attrs
                .into_iter()
                .find(|a| a.logicalname == field)
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "mapping.lookups.{}: {table} has no field {field:?}",
                        attr.logicalname
                    ))
                })?;
            if rule.by == LookupBy::Key
                && attome_field::external_id_system(found.options.as_ref()).is_none()
            {
                return Err(AppError::Validation(format!(
                    "mapping.lookups.{}: {field} is not an external id of {table}",
                    attr.logicalname
                )));
            }
            Some(found)
        }
    };
    Ok(LookupTarget {
        field: attr.logicalname.clone(),
        table,
        column,
    })
}

/// Resolves every not-yet-cached text of one lookup field with one query.
async fn resolve_lookup_batch(
    state: &EngineState,
    target: &LookupTarget,
    texts: Vec<String>,
    cache: &mut HashMap<(String, String), Resolved>,
) -> Result<(), AppError> {
    let wanted: Vec<String> = texts
        .into_iter()
        .filter(|t| !cache.contains_key(&(target.field.clone(), t.clone())))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let rows: Vec<(String, Uuid)> = match &target.column {
        None => {
            let ids: Vec<Uuid> = wanted
                .iter()
                .filter_map(|t| Uuid::parse_str(t).ok())
                .collect();
            sqlx::query_as(&format!(
                "SELECT id::text, id FROM {} WHERE is_active = TRUE AND id = ANY($1::uuid[])",
                quote_ident(&target.table)
            ))
            .bind(&ids)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
        }
        Some(column) => {
            // A text column compares as is, so its index serves the lookup.
            let compared = if column.field_type() == FieldType::Text {
                quote_ident(&column.logicalname)
            } else {
                format!("{}::text", quote_ident(&column.logicalname))
            };
            sqlx::query_as(&format!(
                "SELECT {compared}, id FROM {} WHERE is_active = TRUE AND {compared} = ANY($1::text[])",
                quote_ident(&target.table)
            ))
            .bind(&wanted)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
        }
    };
    let mut hits: HashMap<String, Vec<Uuid>> = HashMap::new();
    for (text, id) in rows {
        hits.entry(text).or_default().push(id);
    }
    for text in wanted {
        let resolved = match hits.get(&text).map(Vec::as_slice) {
            Some([id]) => Resolved::Found(*id),
            Some([]) | None => Resolved::Missing,
            Some(_) => Resolved::Ambiguous,
        };
        cache.insert((target.field.clone(), text), resolved);
    }
    Ok(())
}

/// The existing live records matching each key, by key, in one query.
async fn match_existing(
    state: &EngineState,
    table: &str,
    columns: &[AttrInfo],
    keys: &[Vec<String>],
) -> Result<HashMap<usize, Vec<(Uuid, i64)>>, AppError> {
    if keys.is_empty() || columns.is_empty() {
        return Ok(HashMap::new());
    }
    let arrays: Vec<String> = (1..=columns.len())
        .map(|i| format!("${i}::text[]"))
        .collect();
    let names: Vec<String> = (0..columns.len()).map(|i| format!("k{i}")).collect();
    let on: Vec<String> = columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "t.{} = u.k{i}{}",
                quote_ident(&c.logicalname),
                crate::entity_mutation::sql_cast(c)
            )
        })
        .collect();
    let sql = format!(
        "SELECT u.ord, t.id, t.row_version \
           FROM unnest({}) WITH ORDINALITY AS u({}, ord) \
           JOIN {} t ON t.is_active = TRUE AND {}",
        arrays.join(", "),
        names.join(", "),
        quote_ident(table),
        on.join(" AND ")
    );
    let mut query = sqlx::query_as::<_, (i64, Uuid, i64)>(&sql);
    for i in 0..columns.len() {
        let column: Vec<String> = keys.iter().map(|k| k[i].clone()).collect();
        query = query.bind(column);
    }
    let rows = query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let mut out: HashMap<usize, Vec<(Uuid, i64)>> = HashMap::new();
    for (ord, id, row_version) in rows {
        let index = usize::try_from(ord - 1).map_err(AppError::internal)?;
        out.entry(index).or_default().push((id, row_version));
    }
    Ok(out)
}

/// Runs the generic create's validator over a row's values and records its
/// failures as row errors: every failure, or with `required_only` (the
/// second pass, for a row that would create) only the missing required
/// fields. A lookup marked for creation is not missing.
fn check_body(
    attrs: &[AttrInfo],
    outcome: &mut RowOutcome,
    required_only: bool,
) -> Result<(), AppError> {
    let mut body = outcome.mapped.clone();
    body.remove("id");
    body.remove("row_version");
    match crate::entity_mutation::validate_body(attrs, &body, required_only) {
        Ok(()) => Ok(()),
        Err(AppError::FieldValidation(failures)) => {
            for f in failures {
                let wanted = !required_only || f.code == "required";
                if wanted && !outcome.create_missing.contains(&f.field) {
                    outcome.errors.push(RowError::new(&f.field, &f.code));
                }
            }
            Ok(())
        }
        Err(other) => Err(other),
    }
}

/// One row's outcome, as written back to the stage.
struct RowOutcome {
    row_no: i32,
    mapped: Map<String, Value>,
    errors: Vec<RowError>,
    action: Option<Action>,
    record: Option<(Uuid, i64)>,
    duplicates: Vec<Uuid>,
    in_file_row: Option<i32>,
    create_missing: Vec<String>,
}

impl RowOutcome {
    fn error_json(&self) -> Option<String> {
        if self.errors.is_empty()
            && self.duplicates.is_empty()
            && self.in_file_row.is_none()
            && self.create_missing.is_empty()
        {
            return None;
        }
        Some(
            serde_json::json!({
                "errors": self.errors,
                "duplicates": self.duplicates,
                "duplicate_of_row": self.in_file_row,
                "create_missing": self.create_missing,
            })
            .to_string(),
        )
    }
}

async fn write_back(
    state: &EngineState,
    job_id: Uuid,
    rows: &[RowOutcome],
) -> Result<(), AppError> {
    let row_nos: Vec<i32> = rows.iter().map(|r| r.row_no).collect();
    let mapped: Vec<String> = rows
        .iter()
        .map(|r| Value::Object(r.mapped.clone()).to_string())
        .collect();
    let status: Vec<&str> = rows
        .iter()
        .map(|r| {
            if r.errors.is_empty() {
                "valid"
            } else {
                "invalid"
            }
        })
        .collect();
    let action: Vec<Option<&str>> = rows
        .iter()
        .map(|r| r.action.filter(|_| r.errors.is_empty()).map(Action::as_str))
        .collect();
    let record_id: Vec<Option<Uuid>> = rows.iter().map(|r| r.record.map(|(id, _)| id)).collect();
    let record_rv: Vec<Option<i64>> = rows.iter().map(|r| r.record.map(|(_, rv)| rv)).collect();
    let error: Vec<Option<String>> = rows.iter().map(RowOutcome::error_json).collect();
    sqlx::query(
        "UPDATE import_stage s \
            SET mapped = u.mapped::jsonb, status = u.status, action = u.action, \
                record_id = u.record_id, record_row_version = u.record_rv, \
                error = u.error::jsonb \
           FROM unnest($2::int[], $3::text[], $4::text[], $5::text[], $6::uuid[], \
                       $7::int8[], $8::text[]) \
                AS u(row_no, mapped, status, action, record_id, record_rv, error) \
          WHERE s.job_id = $1 AND s.row_no = u.row_no",
    )
    .bind(job_id)
    .bind(&row_nos)
    .bind(&mapped)
    .bind(&status)
    .bind(&action)
    .bind(&record_id)
    .bind(&record_rv)
    .bind(&error)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The counts the stage now holds.
async fn read_counts(state: &EngineState, job_id: Uuid) -> Result<ValidateCounts, AppError> {
    let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'valid' AND action = 'create'), \
                COUNT(*) FILTER (WHERE status = 'valid' AND action = 'update'), \
                COUNT(*) FILTER (WHERE status = 'valid' AND action = 'skip'), \
                COUNT(*) FILTER (WHERE status = 'invalid'), \
                COUNT(*) FILTER (WHERE error IS NOT NULL AND \
                    (jsonb_array_length(COALESCE(error->'duplicates', '[]'::jsonb)) > 0 \
                     OR error->'duplicate_of_row' <> 'null'::jsonb)) \
           FROM import_stage WHERE job_id = $1",
    )
    .bind(job_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(ValidateCounts {
        create: row.0,
        update: row.1,
        skip: row.2,
        invalid: row.3,
        duplicates: row.4,
    })
}

/// Validates job `job_id` (see the module doc). The job must be `staged` or
/// already `validated`; it ends `validated` with its counts.
pub async fn validate(state: &EngineState, job_id: Uuid) -> Result<ValidateCounts, AppError> {
    let job: JobRow = sqlx::query_as(
        "SELECT entity_logicalname, mapping, match_mode, match_columns, status, created_by \
           FROM import_job WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if job.status != "staged" && job.status != "validated" {
        return Err(AppError::Conflict("only a staged import can be validated"));
    }
    let mapping: ImportMapping = serde_json::from_value(job.mapping.clone())
        .map_err(|e| AppError::Validation(format!("mapping: {e}")))?;
    let (entity_id, table, attrs, _) =
        crate::entity_crud::resolve_entity(state, &job.entity_logicalname).await?;
    mapping.check(&attrs)?;
    let attr_of = |name: &str| attrs.iter().find(|a| a.logicalname == name);

    let match_attrs: Vec<AttrInfo> = job
        .match_columns
        .iter()
        .map(|c| {
            attr_of(c).cloned().ok_or_else(|| {
                AppError::Validation(format!("match_columns: {c} is not a field of this entity"))
            })
        })
        .collect::<Result<_, _>>()?;

    // Choice matchers for every choice field a row can reach.
    let choice_fields: Vec<DataMappingField> = attrs
        .iter()
        .filter(|a| a.field_type() == FieldType::Choice)
        .map(|a| DataMappingField {
            source: a.logicalname.clone(),
            target: a.logicalname.clone(),
            transform: None,
            lookup_resolution: "by_id".into(),
            lookup_match_field: None,
        })
        .collect();
    let choices = load_choice_matchers(&state.base.db, &table, &attrs, &choice_fields).await?;

    let mut targets = Vec::new();
    for attr in attrs.iter().filter(|a| a.field_type() == FieldType::Lookup) {
        let rule = mapping
            .lookups
            .get(&attr.logicalname)
            .cloned()
            .unwrap_or_default();
        targets.push(lookup_target(state, attr, &rule).await?);
    }

    let ctx: SecurityContext =
        attome_security::resolve_uncached(&state.base.db, job.created_by).await?;
    let mut lookup_cache: HashMap<(String, String), Resolved> = HashMap::new();
    let mut seen_keys: HashMap<String, i32> = HashMap::new();
    let key_columns: Vec<String> = if job.match_columns.is_empty() {
        vec!["id".to_owned()]
    } else {
        job.match_columns.clone()
    };

    let mut after = 0_i32;
    loop {
        let batch: Vec<(i32, Value)> = sqlx::query_as(
            "SELECT row_no, raw FROM import_stage \
              WHERE job_id = $1 AND row_no > $2 ORDER BY row_no LIMIT $3",
        )
        .bind(job_id)
        .bind(after)
        .bind(VALIDATE_BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((last, _)) = batch.last() else {
            break;
        };
        after = *last;

        // Map and convert.
        let mut outcomes: Vec<RowOutcome> = Vec::with_capacity(batch.len());
        for (row_no, raw) in batch {
            let raw = raw.as_object().cloned().unwrap_or_default();
            let cells = mapping.apply(&raw);
            let mut mapped = Map::new();
            let mut errors = Vec::new();
            for (name, cell) in &cells {
                // A mapped `id` names the record to update; a mapped
                // `row_version` (an exported file read back, A23-T14) is the
                // version that update expects.
                if name == "id" || name == "row_version" {
                    if let Some(id) = key_text(cell) {
                        mapped.insert(name.clone(), Value::String(id));
                    }
                    continue;
                }
                let Some(attr) = attr_of(name) else {
                    continue;
                };
                if attr.field_type() == FieldType::Lookup {
                    mapped.insert(name.clone(), cell.clone());
                    continue;
                }
                match convert_cell(attr, cell, &choices) {
                    Ok(Some(value)) => {
                        mapped.insert(name.clone(), value);
                    }
                    Ok(None) => {}
                    Err(e) => errors.push(e),
                }
            }
            outcomes.push(RowOutcome {
                row_no,
                mapped,
                errors,
                action: None,
                record: None,
                duplicates: Vec::new(),
                in_file_row: None,
                create_missing: Vec::new(),
            });
        }

        // Lookups: one query per lookup field for the whole batch.
        for target in &targets {
            let texts: Vec<String> = outcomes
                .iter()
                .filter_map(|o| o.mapped.get(&target.field).and_then(key_text))
                .collect();
            resolve_lookup_batch(state, target, texts, &mut lookup_cache).await?;
            for outcome in &mut outcomes {
                let Some(text) = outcome.mapped.get(&target.field).and_then(key_text) else {
                    outcome.mapped.remove(&target.field);
                    continue;
                };
                match lookup_cache.get(&(target.field.clone(), text)) {
                    Some(Resolved::Found(id)) => {
                        outcome
                            .mapped
                            .insert(target.field.clone(), Value::String(id.to_string()));
                    }
                    Some(Resolved::Ambiguous) => {
                        outcome.mapped.remove(&target.field);
                        outcome
                            .errors
                            .push(RowError::new(&target.field, "ambiguous_lookup"));
                    }
                    Some(Resolved::Missing) | None => {
                        outcome.mapped.remove(&target.field);
                        if mapping.create_missing {
                            outcome.create_missing.push(target.field.clone());
                        } else {
                            outcome
                                .errors
                                .push(RowError::new(&target.field, "missing_lookup"));
                        }
                    }
                }
            }
        }

        // Match existing records.
        let mut keyed: Vec<(usize, Vec<String>)> = Vec::new();
        for (i, outcome) in outcomes.iter_mut().enumerate() {
            // The create validator's type checks first: a match compares
            // typed values, so a bad one never reaches the SQL.
            if outcome.errors.is_empty() {
                check_body(&attrs, outcome, false)?;
            }
            if !outcome.errors.is_empty() {
                continue;
            }
            if job.match_columns.is_empty()
                && let Some(id) = outcome.mapped.get("id").and_then(key_text)
                && Uuid::parse_str(&id).is_err()
            {
                outcome.errors.push(RowError::new("id", "invalid_id"));
                continue;
            }
            let values: Option<Vec<String>> = if job.match_columns.is_empty() {
                outcome
                    .mapped
                    .get("id")
                    .and_then(key_text)
                    .map(|id| vec![id])
            } else {
                job.match_columns
                    .iter()
                    .map(|c| outcome.mapped.get(c).and_then(key_text))
                    .collect()
            };
            if let Some(values) = values {
                keyed.push((i, values));
            }
        }
        let id_attr;
        let columns: &[AttrInfo] = if job.match_columns.is_empty() {
            id_attr = [plain_attr("id", FieldType::Lookup)];
            &id_attr
        } else {
            &match_attrs
        };
        let keys: Vec<Vec<String>> = keyed.iter().map(|(_, k)| k.clone()).collect();
        let matches = match_existing(state, &table, columns, &keys).await?;
        let mut matched_rows: HashMap<usize, Vec<(Uuid, i64)>> = HashMap::new();
        for (key_index, found) in matches {
            if let Some((row_index, _)) = keyed.get(key_index) {
                matched_rows.insert(*row_index, found);
            }
        }

        for (i, outcome) in outcomes.iter_mut().enumerate() {
            if !outcome.errors.is_empty() {
                continue;
            }
            let found = matched_rows.get(&i);
            if found.is_some_and(|f| f.len() > 1) {
                outcome
                    .errors
                    .push(RowError::new(&key_columns.join(","), "ambiguous_match"));
                continue;
            }
            outcome.record = found.and_then(|f| f.first().copied());
            // A23-T14: a file that carries the row version it was exported
            // at updates only a record still at that version.
            if let (Some((id, _)), Some(version)) = (
                outcome.record,
                outcome
                    .mapped
                    .get("row_version")
                    .and_then(key_text)
                    .and_then(|v| v.parse::<i64>().ok()),
            ) {
                outcome.record = Some((id, version));
            }
            let action = Action::for_mode(&job.match_mode, outcome.record.is_some());
            outcome.action = Some(action);

            // A created record needs every required field.
            if action == Action::Create {
                check_body(&attrs, outcome, true)?;
                if !outcome.errors.is_empty() {
                    continue;
                }
            }

            // The same key twice in the file.
            if let Some(key) = match_key(&key_columns, &outcome.mapped) {
                match seen_keys.get(&key) {
                    Some(first) => outcome.in_file_row = Some(*first),
                    None => {
                        seen_keys.insert(key, outcome.row_no);
                    }
                }
            }

            if action == Action::Create {
                let found = crate::duplicate_check::check(
                    state,
                    &ctx,
                    entity_id,
                    &table,
                    None,
                    &outcome.mapped,
                )
                .await?;
                outcome.duplicates = found.visible.iter().map(|m| m.record_id).collect();
            }
        }

        write_back(state, job_id, &outcomes).await?;
    }

    let counts = read_counts(state, job_id).await?;
    sqlx::query(
        "UPDATE import_job SET status = 'validated', \
                counts = counts || $2::jsonb, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(serde_json::to_value(counts).map_err(AppError::internal)?)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn mapping_renames_skips_splits_and_sets_constants() {
        let mapping: ImportMapping = serde_json::from_value(json!({"columns": [
            {"source": "Company", "target": "name"},
            {"source": "Notes", "skip": true},
            {"source": "Contact", "split": {"separator": " ", "targets": ["first", "last"]}},
            {"constant": "web", "target": "source"},
        ]}))
        .unwrap();
        let out = mapping.apply(&obj(json!({
            "Company": "Acme", "Notes": "x", "Contact": "Sara Al Harbi"
        })));
        assert_eq!(
            Value::Object(out),
            json!({"name": "Acme", "first": "Sara", "last": "Al Harbi", "source": "web"})
        );
        let identity = ImportMapping::default().apply(&obj(json!({"name": "a"})));
        assert_eq!(Value::Object(identity), json!({"name": "a"}));
    }

    #[test]
    fn the_action_follows_the_match_mode() {
        assert_eq!(Action::for_mode("create", false), Action::Create);
        assert_eq!(Action::for_mode("create", true), Action::Skip);
        assert_eq!(Action::for_mode("update", true), Action::Update);
        assert_eq!(Action::for_mode("update", false), Action::Skip);
        assert_eq!(Action::for_mode("upsert", true), Action::Update);
        assert_eq!(Action::for_mode("upsert", false), Action::Create);
    }

    #[test]
    fn cells_become_typed_values() {
        let choices = ChoiceMatchers::new();
        let number = plain_attr("level", FieldType::Number);
        assert_eq!(
            convert_cell(&number, &json!("١٢"), &choices).unwrap(),
            Some(json!(12.0))
        );
        assert_eq!(
            convert_cell(&number, &json!("twelve"), &choices)
                .unwrap_err()
                .code,
            "invalid_number"
        );
        let flag = plain_attr("active", FieldType::Bool);
        assert_eq!(
            convert_cell(&flag, &json!("نعم"), &choices).unwrap(),
            Some(json!(true))
        );
        assert_eq!(convert_cell(&flag, &json!(" "), &choices).unwrap(), None);
        assert_eq!(
            match_key(&["a".into(), "b".into()], &obj(json!({"a": "x", "b": 2}))),
            Some("x\u{1f}2".into())
        );
        assert_eq!(match_key(&["a".into()], &obj(json!({"a": ""}))), None);
    }
}

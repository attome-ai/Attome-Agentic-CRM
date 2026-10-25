//! D-528 / D-522 — the structured data definition of a Class A dashboard
//! widget (dashboard 10/10 Phase 2.1).
//!
//! One validated definition per data widget, stored under
//! `dashboard_widget.config.data` and snapshotted verbatim at publish, from
//! which both the widget's number (`attome-search` structured aggregation) and,
//! later, its records derive. It deliberately names only one entity: a Class A
//! metric is single-entity by construction, so record-level security wraps it
//! exactly (D-522 decision 5).
//!
//! The types live here rather than in `attome-dashboard` because `attome-search`
//! executes them and neither crate may depend on the other's owner.
//!
//! Two validation layers, both pure:
//!
//! - [`DataDefinition::validate_shape`] — bounds, closed enums, identifier
//!   shape and the combinations the executor refuses. No metadata needed.
//! - [`DataDefinition::validate_against`] — every named field exists on the
//!   source entity with a type the operation needs (numeric measures, date
//!   buckets, no multi-select grouping).
//!
//! Whether a binding names a declared dashboard parameter is the dashboard
//! crate's check: parameters are dashboard rows, not entity metadata.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::chart_view_metadata::DateBucket;
use crate::field_type::FieldType;
use crate::filter::Filter;
use crate::meta_registry::EntityMeta;

/// Upper bound on measures per definition.
pub const MAX_MEASURES: usize = 5;
/// Upper bound on static filters per definition.
pub const MAX_FILTERS: usize = 20;
/// Upper bound on bindings per definition.
pub const MAX_BINDINGS: usize = 20;
/// Upper bound on returned groups; mirrors `attome_search::aggregate::MAX_GROUP_BUCKETS`
/// (the platform `MAX_PAGE_SIZE`).
pub const MAX_GROUP_LIMIT: u32 = 200;
const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_LABEL_LEN: usize = 200;
const MIN_MOVING_AVERAGE_WINDOW: u32 = 2;
const MAX_MOVING_AVERAGE_WINDOW: u32 = 90;

/// The built-in values a binding may name, resolved server-side from the
/// caller's `SecurityContext` (`attome_dashboard::context::resolve_builtin_variables`).
pub const BUILTIN_NAMES: &[&str] = &[
    "@current_user",
    "@current_date",
    "@current_user_bu",
    "@current_user_team",
    "@current_record_id",
    "@current_entity",
];

/// Built-ins that resolve to an array and so need the `in` operator.
pub const ARRAY_BUILTIN_NAMES: &[&str] = &["@current_user_bu", "@current_user_team"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DataDefinition {
    /// The one entity logical name the widget aggregates.
    pub source: String,
    /// 1–5 measures, computed in one statement.
    pub measures: Vec<Measure>,
    /// No grouping (a single total), a field, or a time bucket over a date field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Grouping>,
    /// An optional second grouping field that splits each group into series.
    /// Requires `group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series: Option<String>,
    /// Static filters, part of the definition itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    /// How a declared parameter, a cross-filter variable or a built-in becomes
    /// a filter at execution time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub presentation: Presentation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeasureFn {
    Count,
    CountDistinct,
    Sum,
    Avg,
    Min,
    Max,
    Median,
}

impl MeasureFn {
    /// Whether the measure reads a field at all (`count` counts rows).
    pub fn needs_field(self) -> bool {
        self != Self::Count
    }

    /// Whether the measure's field must be numeric.
    pub fn needs_numeric_field(self) -> bool {
        matches!(
            self,
            Self::Sum | Self::Avg | Self::Min | Self::Max | Self::Median
        )
    }

    /// Whether summing this measure's per-bucket values reproduces the
    /// ungrouped value — true only for `count` and `sum`.
    pub fn is_additive(self) -> bool {
        matches!(self, Self::Count | Self::Sum)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::CountDistinct => "count_distinct",
            Self::Sum => "sum",
            Self::Avg => "avg",
            Self::Min => "min",
            Self::Max => "max",
            Self::Median => "median",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Measure {
    pub aggregation: MeasureFn,
    /// Required unless `aggregation` is `count`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Grouping {
    pub field: String,
    /// Present only for a time bucket; the field must then be a date field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<DateBucket>,
}

/// The PostgreSQL `date_trunc` unit for a bucket — a closed set, so the
/// executor may place it in SQL text.
pub fn date_trunc_unit(bucket: DateBucket) -> Option<&'static str> {
    match bucket {
        DateBucket::Day => Some("day"),
        DateBucket::Week => Some("week"),
        DateBucket::Month => Some("month"),
        DateBucket::Quarter => Some("quarter"),
        DateBucket::Year => Some("year"),
        // AG1-T4: Hijri periods come from the `hijri_month` table, not
        // `date_trunc`.
        DateBucket::HijriMonth | DateBucket::HijriYear => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindingSource {
    /// A declared `dashboard_parameter`, by name.
    Parameter,
    /// A cross-filter variable the widget listens to, by name.
    Variable,
    /// One of [`BUILTIN_NAMES`].
    Builtin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindingOp {
    Eq,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    In,
    /// A `date_range` parameter: `gte` the range start and `lt` the day after
    /// its end, both as instants in the resolved timezone.
    Range,
}

impl BindingOp {
    /// The `Filter.op` a non-range binding compiles to.
    pub fn filter_op(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Contains => "contains",
            Self::In => "in",
            Self::Range => "range",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub source: BindingSource,
    pub name: String,
    pub field: String,
    pub op: BindingOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    ValueDesc,
    ValueAsc,
    KeyAsc,
    KeyDesc,
}

/// Modifiers applied on the server over the computed buckets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    /// Defaults to `value_desc` for a field group and `key_asc` for a time
    /// bucket. Ties always break on the typed key, then the series key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<SortOrder>,
    /// 1–200 groups. Not combinable with `series`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Fold the groups past `limit` into one explicit Other bucket. Needs
    /// `limit` and a plain field group.
    #[serde(default)]
    pub other_bucket: bool,
    #[serde(default)]
    pub cumulative: bool,
    #[serde(default)]
    pub percent_of_total: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moving_average_window: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl Presentation {
    /// Whether any modifier rewrites computed values, so a response should
    /// also carry the raw values drill parity is checked against.
    pub fn rewrites_values(&self) -> bool {
        self.cumulative || self.percent_of_total || self.moving_average_window.is_some()
    }
}

/// A field's stored type as the executor needs it: the [`FieldType`] and
/// whether it is a multi-select (`TEXT[]`) column. Covers entity attributes
/// and the system columns every provisioned table carries, so a definition
/// can bucket by `created_at` or group by `owner_ref`.
pub fn field_type_of(meta: &EntityMeta, field: &str) -> Option<(FieldType, bool)> {
    if let Some(attr) = meta.attrs.iter().find(|attr| attr.logicalname == field) {
        // Storage type: a formula measures/groups as its result type, an
        // image is a file column (never a group key).
        let field_type = attr.storage_type();
        let multi = crate::filter::is_multi_choice_attr(attr);
        return Some((field_type, multi));
    }
    system_column_type(field).map(|field_type| (field_type, false))
}

/// The type of a system column (`sql_ident::ALL_SYSTEM_COLS`), or `None`.
pub fn system_column_type(field: &str) -> Option<FieldType> {
    Some(match field {
        "id" | "created_by" | "modified_by" | "organization_ref" | "owner_ref" => FieldType::Lookup,
        "created_at" | "modified_at" => FieldType::DateTime,
        "is_active" => FieldType::Bool,
        "row_version" | "owner_type" => FieldType::Number,
        _ => return None,
    })
}

/// The shared `attome_db::ident` logical-name validator (CLEANUP-REVIEW 3.4)
/// with this module's own 128-byte cap.
fn is_safe_identifier(value: &str) -> bool {
    attome_db::ident::valid_logical_name(value, MAX_IDENTIFIER_LEN)
}

const FILTER_OPS: &[&str] = &[
    "contains",
    "contains_any",
    "contains_all",
    "eq",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "is_null",
];

fn is_numeric(field_type: &FieldType) -> bool {
    matches!(field_type, FieldType::Number | FieldType::Currency)
}

impl DataDefinition {
    /// Parses and fully validates a definition against its source entity.
    pub fn parse(raw: &serde_json::Value, meta: &EntityMeta) -> Result<Self, Vec<String>> {
        let definition: Self = serde_json::from_value(raw.clone())
            .map_err(|e| vec![format!("data does not match the definition schema: {e}")])?;
        definition.validate_shape()?;
        definition.validate_against(meta)?;
        Ok(definition)
    }

    /// Bounds, identifiers and combinations; needs no metadata.
    pub fn validate_shape(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if !is_safe_identifier(&self.source) {
            errors.push("source must be an entity logical name".to_string());
        }
        if self.measures.is_empty() || self.measures.len() > MAX_MEASURES {
            errors.push(format!("measures must have 1-{MAX_MEASURES} entries"));
        }
        for (i, measure) in self.measures.iter().enumerate() {
            match (&measure.field, measure.aggregation.needs_field()) {
                (None, true) => errors.push(format!(
                    "measures[{i}].field is required for {}",
                    measure.aggregation.as_str()
                )),
                (Some(field), _) if !is_safe_identifier(field) => {
                    errors.push(format!("measures[{i}].field must be a field logical name"))
                }
                _ => {}
            }
            if measure
                .label
                .as_ref()
                .is_some_and(|label| label.chars().count() > MAX_LABEL_LEN)
            {
                errors.push(format!(
                    "measures[{i}].label must be at most {MAX_LABEL_LEN} characters"
                ));
            }
        }
        if let Some(group) = &self.group
            && !is_safe_identifier(&group.field)
        {
            errors.push("group.field must be a field logical name".to_string());
        }
        if let Some(series) = &self.series {
            if !is_safe_identifier(series) {
                errors.push("series must be a field logical name".to_string());
            }
            if self.group.is_none() {
                errors.push("series requires group".to_string());
            }
        }
        if self.filters.len() > MAX_FILTERS {
            errors.push(format!("filters must not exceed {MAX_FILTERS} entries"));
        }
        for (i, filter) in self.filters.iter().enumerate() {
            if !is_safe_identifier(&filter.field) {
                errors.push(format!("filters[{i}].field must be a field logical name"));
            }
            if !FILTER_OPS.contains(&filter.op.as_str()) {
                errors.push(format!("filters[{i}].op is not a known operator"));
            }
        }
        if self.bindings.len() > MAX_BINDINGS {
            errors.push(format!("bindings must not exceed {MAX_BINDINGS} entries"));
        }
        for (i, binding) in self.bindings.iter().enumerate() {
            if !is_safe_identifier(&binding.field) {
                errors.push(format!("bindings[{i}].field must be a field logical name"));
            }
            if binding.name.trim().is_empty() || binding.name.chars().count() > MAX_IDENTIFIER_LEN {
                errors.push(format!(
                    "bindings[{i}].name must be 1-{MAX_IDENTIFIER_LEN} characters"
                ));
            }
            if binding.source == BindingSource::Builtin {
                if !BUILTIN_NAMES.contains(&binding.name.as_str()) {
                    errors.push(format!(
                        "bindings[{i}].name is not a known built-in (expected one of {})",
                        BUILTIN_NAMES.join(", ")
                    ));
                }
                let is_array = ARRAY_BUILTIN_NAMES.contains(&binding.name.as_str());
                if is_array != (binding.op == BindingOp::In) {
                    errors.push(format!(
                        "bindings[{i}].op must be `in` exactly when the built-in resolves to a list"
                    ));
                }
            }
            if binding.op == BindingOp::Range && binding.source != BindingSource::Parameter {
                errors.push(format!(
                    "bindings[{i}].op `range` is only valid for a date_range parameter"
                ));
            }
        }
        let presentation = &self.presentation;
        if let Some(limit) = presentation.limit {
            if !(1..=MAX_GROUP_LIMIT).contains(&limit) {
                errors.push(format!(
                    "presentation.limit must be between 1 and {MAX_GROUP_LIMIT}"
                ));
            }
            if self.series.is_some() {
                errors.push("presentation.limit cannot be combined with series".to_string());
            }
        }
        if presentation.other_bucket {
            let plain_field_group = self.group.as_ref().is_some_and(|g| g.bucket.is_none());
            if presentation.limit.is_none() || !plain_field_group || self.series.is_some() {
                errors.push(
                    "presentation.other_bucket needs limit and a field group without a time \
                     bucket or series"
                        .to_string(),
                );
            }
        }
        if let Some(window) = presentation.moving_average_window
            && !(MIN_MOVING_AVERAGE_WINDOW..=MAX_MOVING_AVERAGE_WINDOW).contains(&window)
        {
            errors.push(format!(
                "presentation.moving_average_window must be between \
                 {MIN_MOVING_AVERAGE_WINDOW} and {MAX_MOVING_AVERAGE_WINDOW}"
            ));
        }
        if presentation
            .threshold
            .is_some_and(|value| !value.is_finite())
        {
            errors.push("presentation.threshold must be a finite number".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Every named field exists on `meta` with a usable type.
    pub fn validate_against(&self, meta: &EntityMeta) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if meta.logicalname != self.source {
            errors.push(format!("source {} does not match the entity", self.source));
        }
        let lookup = |field: &str, path: &str, errors: &mut Vec<String>| {
            let found = field_type_of(meta, field);
            if found.is_none() {
                errors.push(format!("{path}: unknown field {field}"));
            }
            found
        };
        for (i, measure) in self.measures.iter().enumerate() {
            let Some(field) = &measure.field else {
                continue;
            };
            if let Some((field_type, multi)) =
                lookup(field, &format!("measures[{i}].field"), &mut errors)
            {
                if measure.aggregation.needs_numeric_field() && !is_numeric(&field_type) {
                    errors.push(format!(
                        "measures[{i}].field {field} must be numeric for {}",
                        measure.aggregation.as_str()
                    ));
                }
                if multi {
                    errors.push(format!(
                        "measures[{i}].field {field} is a multi-select field"
                    ));
                }
            }
        }
        if let Some(group) = &self.group
            && let Some((field_type, multi)) = lookup(&group.field, "group.field", &mut errors)
        {
            if multi {
                errors.push("group.field cannot be a multi-select field".to_string());
            }
            if field_type == FieldType::File {
                errors.push("group.field cannot be a file field".to_string());
            }
            if group.bucket.is_some() && !field_type.is_temporal() {
                errors.push("group.bucket needs a date field".to_string());
            }
        }
        if let Some(series) = &self.series
            && let Some((field_type, multi)) = lookup(series, "series", &mut errors)
            && (multi || field_type == FieldType::File)
        {
            errors.push("series cannot be a multi-select or file field".to_string());
        }
        for (i, filter) in self.filters.iter().enumerate() {
            lookup(&filter.field, &format!("filters[{i}].field"), &mut errors);
        }
        for (i, binding) in self.bindings.iter().enumerate() {
            if let Some((field_type, _)) =
                lookup(&binding.field, &format!("bindings[{i}].field"), &mut errors)
                && binding.op == BindingOp::Range
                && !field_type.is_temporal()
            {
                errors.push(format!(
                    "bindings[{i}].field must be a date field for a range binding"
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta_registry::AttrInfo;
    use serde_json::json;

    fn attr(
        logicalname: &str,
        field_type_int: i32,
        options: Option<serde_json::Value>,
    ) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options,
        }
    }

    fn meta() -> EntityMeta {
        EntityMeta {
            entity_id: uuid::Uuid::nil(),
            logicalname: "deal".to_owned(),
            attrs: vec![
                attr("amount", 1, None),
                attr("status", 7, Some(json!({"choices": ["open", "won"]}))),
                attr("tags", 7, Some(json!({"choices": ["a"], "multi": true}))),
                attr("closed_on", 5, None),
                attr("name", 3, None),
            ],
            is_append_only: false,
            primary_name_attribute: Some("name".to_owned()),
        }
    }

    fn valid() -> serde_json::Value {
        json!({
            "source": "deal",
            "measures": [{"aggregation": "count"}, {"aggregation": "sum", "field": "amount"}],
            "group": {"field": "closed_on", "bucket": "month"},
            "series": "status",
            "filters": [{"field": "status", "op": "eq", "value": "open"}],
            "bindings": [
                {"source": "parameter", "name": "period", "field": "closed_on", "op": "range"},
                {"source": "builtin", "name": "@current_user", "field": "owner_ref", "op": "eq"},
                {"source": "builtin", "name": "@current_user_team", "field": "owner_ref", "op": "in"}
            ],
            "presentation": {"cumulative": true, "threshold": 10.5}
        })
    }

    #[test]
    fn a_full_definition_parses() {
        let parsed = DataDefinition::parse(&valid(), &meta());
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn createdon_is_bucketable_as_a_system_column() {
        let raw = json!({
            "source": "deal",
            "measures": [{"aggregation": "count"}],
            "group": {"field": "created_at", "bucket": "week"}
        });
        assert!(DataDefinition::parse(&raw, &meta()).is_ok());
    }

    #[test]
    fn unknown_keys_and_measure_functions_are_rejected() {
        let mut raw = valid();
        raw["extra"] = json!(true);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["measures"][0]["aggregation"] = json!("mode");
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn measures_are_bounded_and_numeric_where_required() {
        let mut raw = valid();
        raw["measures"] = json!([]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["measures"] = json!(vec![json!({"aggregation": "count"}); MAX_MEASURES + 1]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["measures"] = json!([{"aggregation": "sum", "field": "name"}]);
        let errors = DataDefinition::parse(&raw, &meta()).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("numeric")), "{errors:?}");
        let mut raw = valid();
        raw["measures"] = json!([{"aggregation": "avg"}]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn a_bucket_needs_a_date_field_and_grouping_refuses_multi_select() {
        let mut raw = valid();
        raw["group"] = json!({"field": "status", "bucket": "month"});
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["group"] = json!({"field": "tags"});
        raw["series"] = serde_json::Value::Null;
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn unknown_fields_are_named() {
        let mut raw = valid();
        raw["filters"] = json!([{"field": "ssn", "op": "eq", "value": "1"}]);
        let errors = DataDefinition::parse(&raw, &meta()).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("unknown field ssn")),
            "{errors:?}"
        );
    }

    #[test]
    fn series_needs_a_group_and_limit_refuses_series() {
        let mut raw = valid();
        raw["group"] = serde_json::Value::Null;
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["presentation"] = json!({"limit": 5});
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn other_bucket_needs_limit_and_a_plain_field_group() {
        let raw = json!({
            "source": "deal",
            "measures": [{"aggregation": "count"}],
            "group": {"field": "status"},
            "presentation": {"limit": 3, "other_bucket": true}
        });
        assert!(DataDefinition::parse(&raw, &meta()).is_ok());
        let mut bad = raw.clone();
        bad["presentation"] = json!({"other_bucket": true});
        assert!(DataDefinition::parse(&bad, &meta()).is_err());
        let mut bad = raw;
        bad["group"] = json!({"field": "closed_on", "bucket": "day"});
        assert!(DataDefinition::parse(&bad, &meta()).is_err());
    }

    #[test]
    fn builtin_bindings_are_closed_and_array_builtins_need_in() {
        let mut raw = valid();
        raw["bindings"] =
            json!([{"source": "builtin", "name": "@current_tenant", "field": "name", "op": "eq"}]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["bindings"] = json!([
            {"source": "builtin", "name": "@current_user_bu", "field": "organization_ref", "op": "eq"}
        ]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["bindings"] = json!([{"source": "builtin", "name": "@current_user", "field": "owner_ref", "op": "in"}]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn range_bindings_need_a_parameter_and_a_date_field() {
        let mut raw = valid();
        raw["bindings"] =
            json!([{"source": "variable", "name": "v", "field": "closed_on", "op": "range"}]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let mut raw = valid();
        raw["bindings"] =
            json!([{"source": "parameter", "name": "p", "field": "amount", "op": "range"}]);
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn presentation_bounds_are_checked() {
        let mut raw = valid();
        raw["presentation"] = json!({"moving_average_window": 1});
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
        let raw = json!({
            "source": "deal",
            "measures": [{"aggregation": "count"}],
            "group": {"field": "status"},
            "presentation": {"limit": 201}
        });
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn a_source_mismatch_is_rejected() {
        let mut raw = valid();
        raw["source"] = json!("other_entity");
        assert!(DataDefinition::parse(&raw, &meta()).is_err());
    }

    #[test]
    fn round_trips_through_serde_unchanged() {
        let parsed = DataDefinition::parse(&valid(), &meta()).unwrap();
        let back = serde_json::to_value(&parsed).unwrap();
        assert_eq!(DataDefinition::parse(&back, &meta()).unwrap(), parsed);
    }

    /// CLEANUP-REVIEW 3.4: accept/reject set unchanged by the move to
    /// `attome_db::ident` — first char a letter, no leading underscore, capped at MAX_IDENTIFIER_LEN (128).
    #[test]
    fn safe_identifier_accept_reject_set() {
        for ok in ["name", "a", "created_on", "x9_", "a__b"] {
            assert!(is_safe_identifier(ok), "{ok}");
        }
        for bad in [
            "", "_a", "_", "Name", "1a", "a-b", "a b", "a.b", "a\"b", "é",
        ] {
            assert!(!is_safe_identifier(bad), "{bad:?}");
        }
        assert!(is_safe_identifier(&"a".repeat(MAX_IDENTIFIER_LEN)));
        assert!(!is_safe_identifier(&"a".repeat(MAX_IDENTIFIER_LEN + 1)));
    }
}

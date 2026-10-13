//! The shared column-filter grammar used by any engine that lets a caller
//! filter validated-metadata columns without authoring SQL (guidelines §4:
//! identifiers/values from metadata, never interpolated). Originally lived
//! only in `attome-server::query_exec`; promoted here once `attome-search`'s
//! aggregation endpoint needed the exact same grammar and validators —
//! "shared XRM primitives belong in attome-core only when more than one
//! engine genuinely owns the concept" (coding-guidelines.md §1).
//!
//! C-15 (M01 §7): this module now also owns the `Filter` -> WHERE-fragment
//! compiler itself — [`compile`] — not only the data type and its scalar/
//! array value validators. Four independent hand-copies of the identical
//! operator match (`query_exec.rs`'s WHERE-loop, `attome-search::aggregate`'s
//! `push_filter_condition`, `attome-server::data_export`'s `plan_export` loop,
//! `attome-compliance::legal_matter_admin`'s `build_scope_predicate`) existed
//! before this, three of the four with their own further-duplicated
//! `field_type_int` -> cast table on top (C-16 territory, now routed through
//! [`FieldType`] via [`cast_for_attr`]/[`is_multi_choice_attr`] below).
//!
//! What stays per-caller, deliberately, is the *whitelist* — which fields
//! this caller's `Filter.field` may even name, and what each one's cast is —
//! since `query_exec.rs`'s `ColumnDef`/`table_definition`-derived whitelist
//! is not `attome-search`'s entity-attribute whitelist, and a caller's own
//! sensitive-field/allowed-fields masking has to run before this module ever
//! sees a field name. [`FilterSchema`] is that seam: one trait, implemented
//! once per caller against whatever whitelist it already has, so only the
//! *downstream* "field is known, here is its cast, render the comparison" is
//! shared now (same "one writer, adapters over it" shape C-14's
//! `attome-security::rls_fragment` uses for a different grammar).
//!
//! `attome-security::conditions::render_condition` is a related-looking but
//! genuinely different grammar (D-369's `GrantCondition`/`ConditionOperator`
//! — a typed operator enum with its own `In` array form and no `contains`
//! family at all) and is not migrated onto this compiler; see that module's
//! own doc comment.

use attome_types::AppError;
use serde_json::Value;
use utoipa::ToSchema;

use crate::field_type::FieldType;
use crate::meta_registry::AttrInfo;
use crate::sql_ident::quote_ident;

/// P-api-contract Phase 0 disclosure: the retired hand-written
/// `openapi/query-v1.json` declared `op` as a JSON-schema `enum` of the 8
/// operator strings in this doc comment. Reproducing an exact `enum`
/// constraint on a plain `String` field (as opposed to a real Rust enum)
/// needs utoipa's `schema_with` escape hatch, whose exact builder-call shape
/// this session could not verify against the installed utoipa version — no
/// Rust toolchain in this sandbox (see the `no-rust-toolchain` memory /
/// DECISIONS.md entry for this change). Left as a documented, lower-fidelity
/// field (doc comment + example) rather than guessing at unverified macro
/// internals; re-add the `enum` constraint via `schema_with` once a human
/// can compile-check it — tracked as a Phase 0 follow-up, not silently
/// dropped. Runtime validation is unaffected either way: every caller's own
/// `match f.op.as_str()` is untouched by this OpenAPI-only annotation.
#[derive(serde::Deserialize, serde::Serialize, ToSchema, Clone, Debug, PartialEq)]
pub struct Filter {
    pub field: String,
    /// One of: `contains`, `starts_with`, `ends_with`, `contains_any`,
    /// `contains_all`, `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`,
    /// `is_null`, `is_not_null`. `starts_with`/`ends_with` are text-only,
    /// like `contains`; `neq` excludes a stored NULL (SQL `<>`), exactly like
    /// every other comparison — `is_null` is the only way to match one. The
    /// four were added by D-607 (advanced find, B-R10 Phase A): the entity
    /// grid had offered them since C-28 while the server refused them. For a
    /// multi-select Choice:
    /// `contains` tests one option, `contains_any` matches any supplied
    /// option, and `contains_all` matches every supplied option. `in` matches
    /// any of a non-empty string array by typed equality (not valid for a
    /// multi-select Choice). `is_null` takes no value and matches a stored
    /// NULL — the only way to express a NULL bucket (dashboard 10/10 Phase 0
    /// spike S1).
    #[schema(example = "eq")]
    pub op: String,
    /// Scalar filters retain the v1 string contract. Multi-select Choice
    /// filters additionally accept a JSON string array for `contains_any`
    /// and `contains_all`; `in` takes a string array; `is_null` ignores it.
    pub value: Option<Value>,
}

/// D-078: single-select Choice columns are TEXT, not INTEGER — see
/// `attome-metadata::provision::pg_type_for`. Multi-select Choice columns are
/// handled by the explicit array operators, not this scalar-cast mapping.
pub fn parameter_cast(data_type: &str) -> Option<&'static str> {
    match data_type {
        "number" | "numeric" | "decimal" | "integer" | "currency" => Some("numeric"),
        "date" | "datetime" | "timestamp" => Some("timestamptz"),
        "bool" | "boolean" => Some("boolean"),
        // `icon`/`color` are text columns (a CSS glyph class, a `#rrggbb` hex
        // string) rather than prose — they cast and filter exactly like
        // `text`, and only differ in how the list renders the cell.
        // `rich_text` (sanitized HTML, D-605) and `image` (a file key) are
        // text columns too.
        "choice" | "icon" | "color" | "rich_text" | "image" => Some("text"),
        "lookup" | "uuid" => Some("uuid"),
        "text" | "file" | "string" => Some("text"),
        _ => None,
    }
}

pub fn scalar_filter_value(filter: &Filter) -> Result<&str, AppError> {
    filter
        .value
        .as_ref()
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "filter value must be a string for field: {}",
                filter.field
            ))
        })
}

/// Produces a PostgreSQL text-array literal for a bound parameter. It is never
/// interpolated into SQL; the explicit `::text[]` cast establishes its type.
pub fn text_array_literal(values: &[&str]) -> String {
    let escaped = values
        .iter()
        .map(|value| {
            format!(
                r#""{}""#,
                value.replace('\\', r#"\\"#).replace('"', r#"\""#)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{escaped}}}")
}

pub fn multi_choice_filter_values(filter: &Filter) -> Result<Vec<&str>, AppError> {
    let invalid = || {
        AppError::Validation(format!(
            "{} requires a non-empty array of strings for field: {}",
            filter.op, filter.field
        ))
    };
    let values = filter
        .value
        .as_ref()
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if values.is_empty() {
        return Err(invalid());
    }
    values
        .iter()
        .map(|value| value.as_str().ok_or_else(invalid))
        .collect()
}

// ── The shared compiler (C-15) ──────────────────────────────────────────────

/// Why [`FilterSchema::cast`] could not resolve a field to a usable
/// PostgreSQL cast — kept distinct (rather than collapsing to one "unknown
/// field" error) because every migrated caller already drew this exact
/// distinction to its own client: a field absent from the whitelist entirely
/// (including one that exists but the caller has no field-read grant for —
/// masked as absent, not as "forbidden", so its existence is never leaked)
/// vs. a field that IS on the whitelist but whose declared data type
/// [`parameter_cast`] doesn't recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCastError {
    Unknown,
    UnsupportedType,
}

/// One bound PostgreSQL text parameter, in the same text-with-explicit-cast
/// convention every migrated caller's own `Vec<String>` params already used
/// (`crate::sql_ident` identifiers are quoted separately; every filter
/// *value* still binds as text with an explicit `::type` cast at its use
/// site, never as a native Rust type — the cast comes from the caller's own
/// [`FilterSchema`], not from `serde_json::Value`'s shape).
pub type Bind = String;

/// A caller's field whitelist and cast/multi-choice knowledge, as
/// [`compile`] needs it — the one seam this module leaves per-caller (see
/// the module doc). Implement once per whitelist shape; `query_exec.rs`'s
/// `ColumnDef` list, `attome-search::aggregate`'s entity-attribute map, and
/// `AttrInfo`-backed callers ([`cast_for_attr`]/[`is_multi_choice_attr`])
/// each need a different lookup, but the trait itself is the same three
/// bits of information for all of them.
pub trait FilterSchema {
    /// `Err(FieldCastError::Unknown)` when `field` is not in this caller's
    /// whitelist at all (including "exists but caller can't read it" —
    /// never distinguish those two to the client). `Ok(cast)` otherwise,
    /// where `cast` is the same bare PostgreSQL type name [`parameter_cast`]
    /// returns (`"numeric"`, `"timestamptz"`, `"boolean"`, `"uuid"`,
    /// `"text"`).
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError>;

    /// Whether `field` is a multi-select Choice column (physically
    /// `TEXT[]`) — gates `contains`/`contains_any`/`contains_all`'s array-
    /// operator branch below. Only ever consulted for a field
    /// [`Self::cast`] already resolved; the default (`false`) is correct for
    /// any caller with no multi-select columns in its whitelist at all.
    fn is_multi_choice(&self, field: &str) -> bool {
        let _ = field;
        false
    }
}

/// The `field_type_int` -> cast lookup for any [`FilterSchema`] whose
/// whitelist is keyed by [`AttrInfo`] (every migrated caller except
/// `query_exec.rs`, which derives its casts from a `ColumnDef.data_type`
/// string instead — see that file's own adapter). Not a [`FilterSchema`]
/// impl itself: a caller's own whitelist-membership rule (an `allowed_fields`
/// masking set, `build_scope_predicate`'s bare `attrs.iter().find`, ...) has
/// to run first, since only the caller knows which fields even count as
/// "known" before this ever computes a cast for one.
///
/// [`FieldType::as_str`] always names one of `parameter_cast`'s recognized
/// data types, so this never returns `UnsupportedType` in practice — kept as
/// a `Result` anyway so a [`FilterSchema`] impl built on it has one honest
/// error type to propagate rather than a bare `unwrap`.
pub fn cast_for_attr(attr: &AttrInfo) -> Result<&'static str, FieldCastError> {
    // A formula filters as its result type, rich text as text, an image as
    // a file key (`FieldType::storage`).
    let field_type = attr.storage_type();
    parameter_cast(field_type.as_str()).ok_or(FieldCastError::UnsupportedType)
}

/// Whether `attr` is a multi-select Choice field — the `field_type_int ==
/// choice AND options.multi` test every migrated `AttrInfo`-based caller
/// hand-copied. Deliberately narrower than [`FieldType::is_multi_valued`]
/// (which also answers `true` for a multi-valued File field): a multi-file
/// column is `JSONB`, not `TEXT[]`, and the array operators [`compile`]'s
/// `contains`/`contains_any`/`contains_all` branch renders
/// (`@> ARRAY[..]`/`&&`/`@>`) are only ever correct against a `TEXT[]`
/// column.
pub fn is_multi_choice_attr(attr: &AttrInfo) -> bool {
    let field_type = FieldType::from_int(attr.field_type_int).unwrap_or(FieldType::Text);
    field_type == FieldType::Choice
        && field_type.is_multi_valued(attr.options.as_ref().unwrap_or(&Value::Null))
}

/// Compiles one [`Filter`] into a bound `WHERE` fragment plus its bind
/// value(s), against `schema`'s field whitelist/cast/multi-choice-ness.
/// `placeholder_start` is the next unused `$N` this call may use — normally
/// the caller's own `params.len() + 1` right before the call. Every branch
/// binds at most one value (`is_null` binds none), so callers must extend
/// their parameter list with the returned `Vec<Bind>` rather than assume its
/// length.
///
/// This is the exact operator set and error behavior `query_exec.rs`'s
/// WHERE-loop originally defined (the fullest of the four pre-C-15 copies —
/// `contains_any`/`contains_all`'s multi-select array operators included);
/// the other three callers' narrower grammars (no multi-select support) gain
/// that capability by migrating onto this rather than losing anything they
/// already had.
pub fn compile(
    filter: &Filter,
    schema: &dyn FilterSchema,
    placeholder_start: usize,
) -> Result<(String, Vec<Bind>), AppError> {
    let cast = schema.cast(&filter.field).map_err(|e| match e {
        FieldCastError::Unknown => {
            AppError::Validation(format!("unknown filter field: {}", filter.field))
        }
        FieldCastError::UnsupportedType => AppError::Validation(format!(
            "unsupported filter type for field: {}",
            filter.field
        )),
    })?;
    let is_multi_choice = schema.is_multi_choice(&filter.field);
    let field_sql = quote_ident(&filter.field);
    let n = placeholder_start;

    match filter.op.as_str() {
        "is_null" => Ok((format!("{field_sql} IS NULL"), Vec::new())),
        "is_not_null" => Ok((format!("{field_sql} IS NOT NULL"), Vec::new())),
        "in" if is_multi_choice => Err(AppError::Validation(format!(
            "in is not valid for a multi-select Choice field: {}; use contains_any",
            filter.field
        ))),
        "in" => {
            let invalid = || {
                AppError::Validation(format!(
                    "in requires a non-empty array of strings for field: {}",
                    filter.field
                ))
            };
            let values = filter
                .value
                .as_ref()
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty())
                .ok_or_else(invalid)?
                .iter()
                .map(|value| value.as_str().ok_or_else(invalid))
                .collect::<Result<Vec<&str>, AppError>>()?;
            Ok((
                format!("{field_sql} = ANY(${n}::{cast}[])"),
                vec![text_array_literal(&values)],
            ))
        }
        // A scalar membership test is convenient for checkbox/toggle UIs and
        // is deliberately distinct from text's substring `contains`
        // behavior. `is_multi_choice` guarantees the physical column is a
        // PostgreSQL `TEXT[]`.
        "contains" if is_multi_choice => {
            let value = scalar_filter_value(filter)?;
            Ok((
                format!("{field_sql} @> ARRAY[${n}::text]"),
                vec![value.to_owned()],
            ))
        }
        // Selection controls normally have OR semantics: show records
        // carrying at least one selected option. `contains_all` is also
        // available for the less common AND semantics, explicitly rather
        // than overloading `eq` with an array.
        "contains_any" | "contains_all" => {
            if !is_multi_choice {
                return Err(AppError::Validation(format!(
                    "{} is only valid for multi-select Choice fields: {}",
                    filter.op, filter.field
                )));
            }
            let values = multi_choice_filter_values(filter)?;
            let operator = if filter.op == "contains_any" {
                "&&"
            } else {
                "@>"
            };
            Ok((
                format!("{field_sql} {operator} ${n}::text[]"),
                vec![text_array_literal(&values)],
            ))
        }
        "starts_with" | "ends_with" if is_multi_choice => Err(AppError::Validation(format!(
            "{} is not valid for a multi-select Choice field: {}; use contains, contains_any, or contains_all",
            filter.op, filter.field
        ))),
        op @ ("contains" | "starts_with" | "ends_with") => {
            if cast != "text" {
                return Err(AppError::Validation(format!(
                    "{op} is only valid for text fields: {}",
                    filter.field
                )));
            }
            let value = scalar_filter_value(filter)?;
            let pattern = match op {
                "contains" => format!("%{value}%"),
                "starts_with" => format!("{value}%"),
                _ => format!("%{value}"),
            };
            Ok((format!("{field_sql} ILIKE ${n}"), vec![pattern]))
        }
        "eq" | "neq" | "gt" | "gte" | "lt" | "lte" if is_multi_choice => {
            Err(AppError::Validation(format!(
                "{} is not valid for a multi-select Choice field: {}; use contains, contains_any, or contains_all",
                filter.op, filter.field
            )))
        }
        op @ ("eq" | "neq" | "gt" | "gte" | "lt" | "lte") => {
            let value = scalar_filter_value(filter)?;
            let sql_op = match op {
                "eq" => "=",
                "neq" => "<>",
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                _ => "<=",
            };
            Ok((
                format!("{field_sql} {sql_op} ${n}::{cast}"),
                vec![value.to_owned()],
            ))
        }
        other => Err(AppError::Validation(format!(
            "unknown filter operator: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_cast_covers_every_known_data_type() {
        assert_eq!(parameter_cast("number"), Some("numeric"));
        assert_eq!(parameter_cast("date"), Some("timestamptz"));
        assert_eq!(parameter_cast("bool"), Some("boolean"));
        assert_eq!(parameter_cast("choice"), Some("text"));
        assert_eq!(parameter_cast("lookup"), Some("uuid"));
        assert_eq!(parameter_cast("text"), Some("text"));
        assert_eq!(parameter_cast("unknown"), None);
    }

    #[test]
    fn scalar_filter_value_rejects_a_non_string() {
        let f = Filter {
            field: "amount".into(),
            op: "eq".into(),
            value: Some(Value::from(42)),
        };
        assert!(scalar_filter_value(&f).is_err());
    }

    #[test]
    fn multi_choice_filter_values_rejects_an_empty_array() {
        let f = Filter {
            field: "tags".into(),
            op: "contains_any".into(),
            value: Some(Value::Array(vec![])),
        };
        assert!(multi_choice_filter_values(&f).is_err());
    }

    #[test]
    fn text_array_literal_escapes_quotes_and_backslashes() {
        assert_eq!(text_array_literal(&["a\"b", "c\\d"]), r#"{"a\"b","c\\d"}"#);
    }

    // ── compile() ────────────────────────────────────────────────────────

    /// A minimal test-double [`FilterSchema`] — a fixed field -> cast map
    /// plus a fixed multi-choice set, standing in for any real caller's
    /// whitelist.
    struct MapSchema {
        casts: std::collections::HashMap<&'static str, &'static str>,
        multi_choice: std::collections::HashSet<&'static str>,
    }

    impl FilterSchema for MapSchema {
        fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
            self.casts
                .get(field)
                .copied()
                .ok_or(FieldCastError::Unknown)
        }
        fn is_multi_choice(&self, field: &str) -> bool {
            self.multi_choice.contains(field)
        }
    }

    fn schema() -> MapSchema {
        MapSchema {
            casts: std::collections::HashMap::from([
                ("amount", "numeric"),
                ("closed_on", "timestamptz"),
                ("name", "text"),
                ("tags", "text"),
            ]),
            multi_choice: std::collections::HashSet::from(["tags"]),
        }
    }

    fn filter(field: &str, op: &str, value: Value) -> Filter {
        Filter {
            field: field.to_owned(),
            op: op.to_owned(),
            value: Some(value),
        }
    }

    #[test]
    fn compile_eq_casts_to_the_schema_type() {
        let (sql, binds) =
            compile(&filter("amount", "eq", Value::from("10")), &schema(), 3).unwrap();
        assert_eq!(sql, "\"amount\" = $3::numeric");
        assert_eq!(binds, vec!["10".to_owned()]);
    }

    #[test]
    fn compile_every_scalar_operator_renders_its_own_sql() {
        for (op, sql_op) in [("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")] {
            let (sql, _) = compile(&filter("amount", op, Value::from("1")), &schema(), 1).unwrap();
            assert_eq!(sql, format!("\"amount\" {sql_op} $1::numeric"));
        }
    }

    #[test]
    fn compile_contains_on_a_text_field_ilikes() {
        let (sql, binds) = compile(
            &filter("name", "contains", Value::from("ann")),
            &schema(),
            2,
        )
        .unwrap();
        assert_eq!(sql, "\"name\" ILIKE $2");
        assert_eq!(binds, vec!["%ann%".to_owned()]);
    }

    #[test]
    fn compile_contains_rejects_a_non_text_field() {
        let err = compile(
            &filter("amount", "contains", Value::from("1")),
            &schema(),
            1,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn compile_contains_any_and_all_render_distinct_array_operators() {
        let (any_sql, any_binds) = compile(
            &filter("tags", "contains_any", serde_json::json!(["a", "b"])),
            &schema(),
            1,
        )
        .unwrap();
        assert_eq!(any_sql, "\"tags\" && $1::text[]");
        assert_eq!(any_binds, vec![r#"{"a","b"}"#.to_owned()]);

        let (all_sql, _) = compile(
            &filter("tags", "contains_all", serde_json::json!(["a", "b"])),
            &schema(),
            1,
        )
        .unwrap();
        assert_eq!(all_sql, "\"tags\" @> $1::text[]");
    }

    #[test]
    fn compile_contains_on_a_multi_choice_field_uses_the_scalar_membership_operator() {
        let (sql, binds) =
            compile(&filter("tags", "contains", Value::from("a")), &schema(), 1).unwrap();
        assert_eq!(sql, "\"tags\" @> ARRAY[$1::text]");
        assert_eq!(binds, vec!["a".to_owned()]);
    }

    #[test]
    fn compile_contains_any_rejects_a_non_multi_choice_field() {
        let err = compile(
            &filter("name", "contains_any", serde_json::json!(["a"])),
            &schema(),
            1,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn compile_scalar_operators_reject_a_multi_choice_field() {
        for op in ["eq", "gt", "gte", "lt", "lte"] {
            let err = compile(&filter("tags", op, Value::from("a")), &schema(), 1).unwrap_err();
            assert!(matches!(err, AppError::Validation(_)), "op={op}");
        }
    }

    #[test]
    fn compile_neq_starts_with_ends_with_and_is_not_null_render_their_own_sql() {
        // D-607: the four operators the entity grid offered before the server
        // compiled them.
        let (sql, binds) =
            compile(&filter("amount", "neq", Value::from("5")), &schema(), 1).unwrap();
        assert_eq!(sql, "\"amount\" <> $1::numeric");
        assert_eq!(binds, vec!["5".to_owned()]);

        let (sql, binds) = compile(
            &filter("name", "starts_with", Value::from("an")),
            &schema(),
            2,
        )
        .unwrap();
        assert_eq!(sql, "\"name\" ILIKE $2");
        assert_eq!(binds, vec!["an%".to_owned()]);

        let (_, binds) = compile(
            &filter("name", "ends_with", Value::from("na")),
            &schema(),
            1,
        )
        .unwrap();
        assert_eq!(binds, vec!["%na".to_owned()]);

        let f = Filter {
            field: "closed_on".into(),
            op: "is_not_null".into(),
            value: None,
        };
        let (sql, binds) = compile(&f, &schema(), 3).unwrap();
        assert_eq!(sql, "\"closed_on\" IS NOT NULL");
        assert!(binds.is_empty());
    }

    #[test]
    fn compile_prefix_suffix_reject_non_text_and_multi_choice_fields() {
        for op in ["starts_with", "ends_with"] {
            assert!(compile(&filter("amount", op, Value::from("1")), &schema(), 1).is_err());
            assert!(compile(&filter("tags", op, Value::from("a")), &schema(), 1).is_err());
        }
        assert!(compile(&filter("tags", "neq", Value::from("a")), &schema(), 1).is_err());
    }

    #[test]
    fn compile_is_null_binds_nothing() {
        let f = Filter {
            field: "closed_on".into(),
            op: "is_null".into(),
            value: None,
        };
        let (sql, binds) = compile(&f, &schema(), 4).unwrap();
        assert_eq!(sql, "\"closed_on\" IS NULL");
        assert!(binds.is_empty());
    }

    #[test]
    fn compile_in_casts_an_array_to_the_schema_type() {
        let (sql, binds) = compile(
            &filter("amount", "in", serde_json::json!(["1", "2"])),
            &schema(),
            2,
        )
        .unwrap();
        assert_eq!(sql, "\"amount\" = ANY($2::numeric[])");
        assert_eq!(binds, vec![r#"{"1","2"}"#.to_owned()]);
    }

    #[test]
    fn compile_in_rejects_an_empty_array_and_a_multi_choice_field() {
        assert!(compile(&filter("amount", "in", serde_json::json!([])), &schema(), 1).is_err());
        assert!(
            compile(
                &filter("tags", "in", serde_json::json!(["a"])),
                &schema(),
                1
            )
            .is_err()
        );
    }

    #[test]
    fn compile_rejects_an_unknown_field() {
        let err = compile(&filter("ssn", "eq", Value::from("1")), &schema(), 1).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn compile_rejects_an_unknown_operator() {
        let err = compile(
            &filter("amount", "startswith", Value::from("1")),
            &schema(),
            1,
        )
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn compile_reports_unsupported_type_distinctly_from_unknown_field() {
        struct AlwaysUnsupported;
        impl FilterSchema for AlwaysUnsupported {
            fn cast(&self, _field: &str) -> Result<&'static str, FieldCastError> {
                Err(FieldCastError::UnsupportedType)
            }
        }
        let err = compile(&filter("x", "eq", Value::from("1")), &AlwaysUnsupported, 1).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unsupported filter type")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn compile_placeholder_start_is_used_verbatim() {
        let (sql, _) = compile(&filter("amount", "eq", Value::from("1")), &schema(), 7).unwrap();
        assert!(sql.contains("$7"));
    }

    // ── AttrInfo adapters ────────────────────────────────────────────────

    fn attr(field_type_int: i32, options: Option<Value>) -> AttrInfo {
        AttrInfo {
            logicalname: "f".to_owned(),
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
            options,
        }
    }

    #[test]
    fn cast_for_attr_agrees_with_field_type_as_str() {
        assert_eq!(cast_for_attr(&attr(1, None)), Ok("numeric")); // number
        assert_eq!(cast_for_attr(&attr(5, None)), Ok("timestamptz")); // date
        assert_eq!(cast_for_attr(&attr(6, None)), Ok("boolean")); // bool
        assert_eq!(cast_for_attr(&attr(7, None)), Ok("text")); // choice
        assert_eq!(cast_for_attr(&attr(11, None)), Ok("uuid")); // lookup
        assert_eq!(cast_for_attr(&attr(3, None)), Ok("text")); // text
    }

    /// U9: a formula filters as its result type; rich text and image as text.
    #[test]
    fn cast_for_attr_uses_the_storage_type_of_the_u9_types() {
        let num = serde_json::json!({"expression": "a * 2", "result_type": "number"});
        let date = serde_json::json!({"expression": "d", "result_type": "date"});
        assert_eq!(cast_for_attr(&attr(16, Some(num))), Ok("numeric"));
        assert_eq!(cast_for_attr(&attr(16, Some(date))), Ok("timestamptz"));
        assert_eq!(cast_for_attr(&attr(17, None)), Ok("text"));
        assert_eq!(cast_for_attr(&attr(18, None)), Ok("text"));
        assert_eq!(parameter_cast("rich_text"), Some("text"));
        assert_eq!(parameter_cast("image"), Some("text"));
    }

    #[test]
    fn is_multi_choice_attr_requires_both_choice_type_and_options_multi() {
        assert!(!is_multi_choice_attr(&attr(7, None)));
        assert!(!is_multi_choice_attr(&attr(
            7,
            Some(serde_json::json!({"multi": false}))
        )));
        assert!(is_multi_choice_attr(&attr(
            7,
            Some(serde_json::json!({"multi": true}))
        )));
        // A multi-valued File field is not "multi choice" — that's JSONB, not TEXT[].
        assert!(!is_multi_choice_attr(&attr(
            12,
            Some(serde_json::json!({"multi": true}))
        )));
    }
}

/// Property-based coverage for this module's pure filter/SQL-builder
/// functions — C-15 (M01 §7) moved these here from `attome-records`'s
/// `query_exec.rs::proptests` (`text_array_literal_round_trips_through_its_
/// own_escaping`, `scalar_filter_value_accepts_only_present_string_values`,
/// `multi_choice_filter_values_requires_non_empty_all_string_array`), since
/// the functions they exercise live here now, not there — `query_exec.rs`
/// keeps only the proptests for its own `ColumnDef`/table_definition-derived
/// whitelist machinery, which is genuinely still its own. Follows the same
/// "pure logic -> proptest in-crate" convention that file's own module doc
/// documents (`testing`).
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_string_pool() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-zA-Z0-9_]{0,10}",
            Just(String::new()),
            Just(r#"quote"inside"#.to_owned()),
            Just(r"back\slash".to_owned()),
            Just(r#"both\"kinds"#.to_owned()),
            Just("comma,delimited".to_owned()),
            Just("brace{ish}".to_owned()),
        ]
    }

    /// Mirrors Postgres's own text-array literal quoting so the round-trip
    /// property below can assert `text_array_literal` is actually invertible
    /// — i.e. no input string can make two different value-sets produce the
    /// same literal, which is exactly the injection-safety property that
    /// matters for a value that gets bound into a query as `::text[]`.
    fn parse_pg_text_array_literal(literal: &str) -> Vec<String> {
        let inner = literal
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .expect("text_array_literal always wraps output in {...}");
        if inner.is_empty() {
            return vec![];
        }
        let mut out = Vec::new();
        let mut chars = inner.chars().peekable();
        loop {
            assert_eq!(
                chars.next(),
                Some('"'),
                "each element is always quote-wrapped"
            );
            let mut cur = String::new();
            loop {
                match chars.next().expect("unterminated quoted element") {
                    '\\' => cur.push(chars.next().expect("dangling escape")),
                    '"' => break,
                    c => cur.push(c),
                }
            }
            out.push(cur);
            match chars.next() {
                Some(',') => continue,
                None => break,
                Some(c) => panic!("unexpected character after quoted element: {c}"),
            }
        }
        out
    }

    /// A [`FilterSchema`] parameterized by an arbitrary `(cast, is_multi_choice)`
    /// pair for one fixed field name — lets the properties below drive every
    /// combination `compile` can see without hand-writing a whitelist per
    /// case.
    struct OneFieldSchema {
        field: &'static str,
        cast: Option<&'static str>,
        is_multi_choice: bool,
    }

    impl FilterSchema for OneFieldSchema {
        fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
            if field != self.field {
                return Err(FieldCastError::Unknown);
            }
            self.cast.ok_or(FieldCastError::UnsupportedType)
        }
        fn is_multi_choice(&self, field: &str) -> bool {
            field == self.field && self.is_multi_choice
        }
    }

    proptest! {
        /// The load-bearing injection-safety property: whatever characters an
        /// input string contains (quotes, backslashes, commas, braces — every
        /// character that is syntactically meaningful in a Postgres array
        /// literal), `text_array_literal`'s escaping must be exactly
        /// invertible. If it weren't, two different input vectors could
        /// produce the same bound `::text[]` literal — the exact shape of bug
        /// this function's own doc comment ("never interpolated into SQL...
        /// explicit `::text[]` cast") is designed to avoid.
        #[test]
        fn text_array_literal_round_trips_through_its_own_escaping(
            values in prop::collection::vec(arb_string_pool(), 0..6),
        ) {
            let refs: Vec<&str> = values.iter().map(String::as_str).collect();
            let literal = text_array_literal(&refs);
            prop_assert!(
                literal.starts_with('{') && literal.ends_with('}'),
                "text array literal must be brace-delimited"
            );
            prop_assert_eq!(parse_pg_text_array_literal(&literal), values);
        }

        /// `scalar_filter_value` succeeds iff `filter.value` is present and a
        /// JSON string — never coerces a number/bool/array/null into a string.
        #[test]
        fn scalar_filter_value_accepts_only_present_string_values(
            value in prop::option::of(prop_oneof![
                any::<bool>().prop_map(Value::Bool),
                any::<i32>().prop_map(|n| serde_json::json!(n)),
                "[a-z]{0,8}".prop_map(Value::String),
                Just(Value::Null),
            ]),
        ) {
            let expect_ok = matches!(&value, Some(v) if v.is_string());
            let filter = Filter { field: "f".to_owned(), op: "eq".to_owned(), value };
            prop_assert_eq!(scalar_filter_value(&filter).is_ok(), expect_ok);
        }

        /// `multi_choice_filter_values` succeeds iff `filter.value` is a
        /// non-empty JSON array whose every element is a string — an empty
        /// array, a bare string, or an array containing a non-string element
        /// are all rejected.
        #[test]
        fn multi_choice_filter_values_requires_non_empty_all_string_array(
            candidates in prop::collection::vec(
                prop_oneof![
                    "[a-z]{0,6}".prop_map(Value::String),
                    any::<i32>().prop_map(|n| serde_json::json!(n)),
                ],
                0..5,
            ),
        ) {
            let expect_ok = !candidates.is_empty() && candidates.iter().all(|v| v.is_string());
            let filter = Filter {
                field: "f".to_owned(),
                op: "contains_any".to_owned(),
                value: Some(Value::Array(candidates)),
            };
            prop_assert_eq!(multi_choice_filter_values(&filter).is_ok(), expect_ok);
        }

        /// `compile` succeeds on a scalar operator if and only if the schema
        /// resolved a cast for the field and the field isn't flagged
        /// multi-choice — generalizes the hand-picked unit tests above over
        /// every scalar op and both `cast`/`is_multi_choice` outcomes.
        #[test]
        fn compile_scalar_op_succeeds_iff_cast_known_and_not_multi_choice(
            op in prop_oneof![
                Just("eq"), Just("neq"), Just("gt"), Just("gte"), Just("lt"), Just("lte"),
            ],
            cast in prop::option::of(prop_oneof![
                Just("numeric"), Just("timestamptz"), Just("boolean"), Just("uuid"), Just("text"),
            ]),
            is_multi_choice in any::<bool>(),
        ) {
            let schema = OneFieldSchema { field: "f", cast, is_multi_choice };
            let filter = Filter {
                field: "f".to_owned(),
                op: op.to_owned(),
                value: Some(Value::from("1")),
            };
            let expect_ok = cast.is_some() && !is_multi_choice;
            prop_assert_eq!(compile(&filter, &schema, 1).is_ok(), expect_ok);
        }

        /// A field name the schema never resolves (any name other than the
        /// one [`OneFieldSchema`] knows) is always rejected, for any operator
        /// — the whitelist half of `compile`'s contract (guidelines §4:
        /// identifiers only from validated metadata).
        #[test]
        fn compile_rejects_any_field_the_schema_does_not_know(
            probe in "[a-z_]{1,8}",
            op in prop_oneof![
                Just("eq"), Just("gt"), Just("gte"), Just("lt"), Just("lte"), Just("contains"),
            ],
        ) {
            prop_assume!(probe != "f");
            let schema = OneFieldSchema { field: "f", cast: Some("text"), is_multi_choice: false };
            let filter = Filter {
                field: probe,
                op: op.to_owned(),
                value: Some(Value::from("1")),
            };
            prop_assert!(compile(&filter, &schema, 1).is_err());
        }
    }
}

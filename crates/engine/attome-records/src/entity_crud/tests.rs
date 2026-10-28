// â”€â”€ Tests (P1.8 pure-logic units â€” the generic-CRUD SQL-shape helpers) â”€â”€â”€â”€â”€â”€â”€
// There is no separate SQL-builder module today: the dormant JSONB
// records model (store/builder/loader/query.rs, D-003) that the P1.8 plan's
// "latent ORDER BY injection at builder.rs:124" note originally referred to
// was already deleted by P1.6d. The live dynamic-SQL surface is these two
// pure functions plus the `entity_name`/column-name interpolation in
// create_record/update_record â€” both DB-sourced and validated (never
// request data), so there's no analogous ORDER BY (or any sort/filter)
// construction left to regress-test here; list/sort/page lives in
// query_exec.rs (already covered by attome-server/tests/query_exec.rs).
use super::*;

fn attr(field_type_int: i32, options: Option<Value>) -> AttrInfo {
    AttrInfo {
        logicalname: "f".to_owned(),
        field_type_int,
        is_required: false,
        max_length: None,
        is_sensitive: false,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity_ref: None,
        on_target_delete: OnTargetDelete::Orphan,
        data_classification: Default::default(),
        sensitivity: Default::default(),
        sensitivity_confirmed: false,
        options,
    }
}

#[test]
fn sql_cast_maps_numeric_family_types() {
    for t in [1, 2, 4, 9, 10] {
        assert_eq!(sql_cast(&attr(t, None)), "::numeric");
    }
}

#[test]
fn sql_cast_maps_date_bool_and_lookup() {
    assert_eq!(sql_cast(&attr(5, None)), "::timestamptz");
    assert_eq!(sql_cast(&attr(6, None)), "::boolean");
    assert_eq!(sql_cast(&attr(11, None)), "::uuid");
}

#[test]
fn sql_cast_defaults_to_no_cast_for_text_and_unknown_codes() {
    assert_eq!(sql_cast(&attr(3, None)), "");
    assert_eq!(sql_cast(&attr(999, None)), "");
}

#[test]
fn sql_cast_casts_multi_select_choice_to_text_array_single_select_to_none() {
    let single = attr(
        7,
        Some(serde_json::json!({"choices": ["a"], "multi": false})),
    );
    assert_eq!(sql_cast(&single), "");
    let multi = attr(
        7,
        Some(serde_json::json!({"choices": ["a"], "multi": true})),
    );
    assert_eq!(sql_cast(&multi), "::text[]");
    // No options at all (shape-only Choice) must not be mistaken for multi.
    assert_eq!(sql_cast(&attr(7, None)), "");
}

#[test]
fn json_to_str_formats_arrays_as_postgres_text_array_literals() {
    let multi_choice = attr(
        7,
        Some(serde_json::json!({"choices": ["red", "blue"], "multi": true})),
    );
    assert_eq!(
        json_to_str(
            &Value::Array(vec![
                Value::String("red".into()),
                Value::String("blue".into())
            ]),
            &multi_choice
        ),
        Some(r#"{"red","blue"}"#.to_owned())
    );
    // Internal quotes/backslashes are escaped, not left to break the literal.
    assert_eq!(
        json_to_str(
            &Value::Array(vec![Value::String(r#"a"b\c"#.into())]),
            &multi_choice
        ),
        Some(r#"{"a\"b\\c"}"#.to_owned())
    );
}

#[test]
fn json_to_str_formats_arrays_as_json_for_multi_file_fields() {
    let multi_file = attr(12, Some(serde_json::json!({"multi": true})));
    assert_eq!(
        json_to_str(
            &Value::Array(vec![Value::String("k1".into()), Value::String("k2".into())]),
            &multi_file
        ),
        Some(r#"["k1","k2"]"#.to_owned())
    );
    // A single-file field (no `multi`) keeps the plain string path, never
    // treated as an array in the first place.
    let single_file = attr(12, None);
    assert_eq!(sql_cast(&single_file), "");
}

#[test]
fn sql_cast_casts_multi_file_to_jsonb_single_file_to_none() {
    assert_eq!(sql_cast(&attr(12, None)), "");
    let multi = attr(12, Some(serde_json::json!({"multi": true})));
    assert_eq!(sql_cast(&multi), "::jsonb");
    // field_type_int 13 (the reserved "file, variant b" code some read paths
    // already accept) must resolve the same way.
    let multi_13 = attr(13, Some(serde_json::json!({"multi": true})));
    assert_eq!(sql_cast(&multi_13), "::jsonb");
}

#[test]
fn validation_rejects_unknown_missing_required_and_overlong_fields() {
    let mut required = attr(3, None);
    required.logicalname = "name".to_owned();
    required.is_required = true;
    required.max_length = Some(4);
    let codes = |result: Result<(), AppError>| match result {
        Err(AppError::FieldValidation(failures)) => failures
            .into_iter()
            .map(|f| (f.field, f.code))
            .collect::<Vec<_>>(),
        other => panic!("expected FieldValidation, got {other:?}"),
    };

    let missing = serde_json::Map::new();
    assert_eq!(
        codes(validate_body(&[required.clone()], &missing, true)),
        [("name".to_owned(), "required".to_owned())]
    );

    let unknown = serde_json::json!({"name": "ok", "typo": 1})
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        codes(validate_body(&[required.clone()], &unknown, true)),
        [("typo".to_owned(), "unknown_field".to_owned())]
    );

    let long = serde_json::json!({"name": "abcde"})
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        codes(validate_body(&[required], &long, true)),
        [("name".to_owned(), "too_long".to_owned())]
    );
}

/// A3-T1: a record with three bad fields hears about all three at once.
#[test]
fn validation_reports_every_failing_field_at_once() {
    let mut name = attr(3, None);
    name.logicalname = "name".to_owned();
    name.is_required = true;
    let mut code = attr(3, None);
    code.logicalname = "code".to_owned();
    code.max_length = Some(2);
    let body = serde_json::json!({"code": "abc", "typo": 1})
        .as_object()
        .unwrap()
        .clone();
    let Err(AppError::FieldValidation(failures)) = validate_body(&[name, code], &body, true) else {
        panic!("expected every failure at once");
    };
    let mut fields: Vec<_> = failures.iter().map(|f| f.field.as_str()).collect();
    fields.sort_unstable();
    assert_eq!(fields, ["code", "name", "typo"]);
    let error = AppError::FieldValidation(failures);
    assert!(
        error.to_string().contains("name: field is required"),
        "{error}"
    );
}

#[test]
fn update_requires_if_match() {
    // D-079: PATCH requires If-Match unconditionally â€” a missing header
    // is a 422, not an unguarded last-write-wins update.
    let headers = axum::http::HeaderMap::new();
    assert!(matches!(
        expected_row_version(&headers),
        Err(AppError::Validation(_))
    ));
}

#[test]
fn if_none_match_parses_bare_quoted_and_weak_forms_and_never_errors() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_static("\"3\""),
    );
    assert_eq!(if_none_match_row_version(&headers), Some(3));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_static("W/\"3\""),
    );
    assert_eq!(if_none_match_row_version(&headers), Some(3));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_static("3"),
    );
    assert_eq!(if_none_match_row_version(&headers), Some(3));

    // Missing header: no short-circuit, never an error.
    assert_eq!(
        if_none_match_row_version(&axum::http::HeaderMap::new()),
        None
    );

    // Malformed values (e.g. a real client's `*` or a corrupted proxy
    // cache) degrade to "always do the full read", not a request failure
    // â€” this header is a caching optimization, not a concurrency guard.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_static("*"),
    );
    assert_eq!(if_none_match_row_version(&headers), None);
}

#[test]
fn row_version_etag_is_weak_and_round_trips_through_the_if_none_match_parser() {
    assert_eq!(row_version_etag(3), "W/\"3\"");

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_str(&row_version_etag(7)).unwrap(),
    );
    assert_eq!(if_none_match_row_version(&headers), Some(7));
}

#[test]
fn upsert_version_parser_accepts_only_non_negative_json_integers() {
    let absent = serde_json::Map::new();
    assert_eq!(expected_upsert_row_version(&absent).unwrap(), None);

    let valid = serde_json::from_value::<Value>(serde_json::json!(0)).unwrap();
    let mut body = serde_json::Map::new();
    body.insert("row_version".to_owned(), valid);
    assert_eq!(expected_upsert_row_version(&body).unwrap(), Some(0));

    for value in [
        serde_json::json!("0"),
        serde_json::json!(0.5),
        serde_json::json!(-1),
        Value::Null,
    ] {
        let mut body = serde_json::Map::new();
        body.insert("row_version".to_owned(), value);
        assert!(matches!(
            expected_upsert_row_version(&body),
            Err(AppError::Validation(_))
        ));
    }
}

#[test]
fn json_to_str_converts_each_json_scalar_type() {
    let text = attr(3, None);
    assert_eq!(json_to_str(&Value::Null, &text), None);
    assert_eq!(
        json_to_str(&Value::Bool(true), &text),
        Some("true".to_owned())
    );
    assert_eq!(
        json_to_str(&Value::Bool(false), &text),
        Some("false".to_owned())
    );
    assert_eq!(
        json_to_str(&serde_json::json!(42), &text),
        Some("42".to_owned())
    );
    assert_eq!(
        json_to_str(&Value::String("hi".into()), &text),
        Some("hi".to_owned())
    );
}

#[test]
fn json_to_str_formats_arrays_as_pg_literals_and_stringifies_objects_rather_than_failing() {
    // D-078: arrays are the multi-select Choice case â€” a Postgres array
    // literal now, not JSON (see json_to_str_formats_arrays_as_postgres_text_array_literals
    // for the string-element case this function actually receives in
    // practice; this covers non-string elements too, for completeness).
    let non_file = attr(3, None);
    let arr = serde_json::json!([1, 2, 3]);
    assert_eq!(
        json_to_str(&arr, &non_file),
        Some(r#"{"1","2","3"}"#.to_owned())
    );
    // Objects have no meaning as a bindable SQL value in this codebase
    // today â€” falling through to JSON stringification rather than
    // panicking is a deliberate "don't crash" default, not a supported shape.
    let obj = serde_json::json!({"a": 1});
    assert_eq!(json_to_str(&obj, &non_file), Some(obj.to_string()));
}

/// S1-T5: the whole record unless `return=minimal` is asked for, in any case.
#[test]
fn return_pref_defaults_to_representation() {
    use super::response::{ReturnPref, return_pref};
    let headers = axum::http::HeaderMap::new();
    assert_eq!(return_pref(&headers), ReturnPref::Representation);
    let mut other = axum::http::HeaderMap::new();
    other.insert("prefer", "respond-async".parse().unwrap());
    assert_eq!(return_pref(&other), ReturnPref::Representation);
}

#[test]
fn return_pref_reads_minimal_case_insensitively() {
    use super::response::{ReturnPref, return_pref};
    for value in [
        "return=minimal",
        "Return=Minimal",
        "respond-async, return=minimal",
        "return=minimal; strict",
    ] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("prefer", value.parse().unwrap());
        assert_eq!(return_pref(&headers), ReturnPref::Minimal, "{value}");
    }
}

/// A2-T3: the geolocation and json field types end to end below the
/// database: how values bind, how `within_km` compiles, and the schema check.
mod geo_json_types {
    use super::*;
    use attome_core::FieldType;
    use attome_core::filter::{FieldCastError, Filter, FilterSchema};
    use serde_json::json;

    #[test]
    fn json_and_points_bind_as_json_text() {
        let doc = attr(22, None);
        assert_eq!(sql_cast(&doc), "::jsonb");
        assert_eq!(
            json_to_str(&json!("plain"), &doc).as_deref(),
            Some("\"plain\"")
        );
        assert_eq!(json_to_str(&json!([1, 2]), &doc).as_deref(), Some("[1,2]"));
        assert_eq!(json_to_str(&Value::Null, &doc), None);
        let point = attr(21, None);
        assert_eq!(sql_cast(&point), "::jsonb");
        assert_eq!(
            json_to_str(&json!({"lat": 24.5, "lng": 46.25}), &point).as_deref(),
            Some(r#"{"lat":24.5,"lng":46.25}"#)
        );
    }

    struct Geo;
    impl FilterSchema for Geo {
        fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
            match field {
                "site" | "doc" => Ok("jsonb"),
                _ => Err(FieldCastError::Unknown),
            }
        }
        fn is_geolocation(&self, field: &str) -> bool {
            field == "site"
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
    fn within_km_compiles_a_box_and_a_distance() {
        let (sql, binds) = attome_core::filter::compile(
            &filter("site", "within_km", json!("24.7,46.7,10")),
            &Geo,
            3,
        )
        .unwrap();
        assert!(
            sql.contains("<@ box(point($6::float8, $7::float8)"),
            "{sql}"
        );
        assert!(sql.contains("<= $5::float8"), "{sql}");
        assert_eq!(binds.len(), 7);
        assert_eq!(&binds[..3], ["24.7", "46.7", "10"]);
        // the object form compiles the same
        let object = json!({"lat": 24.7, "lng": 46.7, "km": 10});
        assert!(
            attome_core::filter::compile(&filter("site", "within_km", object), &Geo, 1).is_ok()
        );
    }

    #[test]
    fn a_point_takes_only_within_km_and_null_checks() {
        for (op, value) in [("eq", json!("1,2")), ("gt", json!("1"))] {
            assert!(attome_core::filter::compile(&filter("site", op, value), &Geo, 1).is_err());
        }
        assert!(
            attome_core::filter::compile(&filter("site", "is_null", Value::Null), &Geo, 1).is_ok()
        );
        // within_km needs a point field, a radius above 0 and coordinates in range
        assert!(
            attome_core::filter::compile(&filter("doc", "within_km", json!("1,2,3")), &Geo, 1)
                .is_err()
        );
        for bad in ["1,2,0", "91,2,5", "1,181,5", "1,2", "a,b,c"] {
            assert!(
                attome_core::filter::compile(&filter("site", "within_km", json!(bad)), &Geo, 1)
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn nearest_sort_reads_a_point_and_the_box_holds_the_radius() {
        assert_eq!(
            attome_core::filter::near_point("24.7, 46.7"),
            Some((24.7, 46.7))
        );
        assert_eq!(attome_core::filter::near_point("24.7"), None);
        assert_eq!(attome_core::filter::near_point("95,46.7"), None);
        let sql = attome_core::filter::geo_distance_km_to("t.\"site\"", 24.7, -46.7);
        assert!(
            sql.contains("(24.7::float8)") && sql.contains("(-46.7::float8)"),
            "{sql}"
        );
        // 111 km is about one degree of latitude.
        let (min_lat, _, max_lat, _) = attome_core::filter::bounding_box(0.0, 0.0, 111.195);
        assert!((max_lat - 1.0).abs() < 1e-3 && (min_lat + 1.0).abs() < 1e-3);
    }

    #[test]
    fn a_json_schema_refuses_a_document_that_does_not_match() {
        let options = json!({"schema": {
            "type": "object",
            "required": ["sku"],
            "additionalProperties": false,
            "properties": {"sku": {"type": "string"}, "qty": {"type": "integer", "minimum": 1}}
        }});
        let ok = json!({"sku": "A-1", "qty": 2});
        assert!(attome_field::validate(&FieldType::Json, &ok, Some(&options)).is_ok());
        for bad in [
            json!({"qty": 2}),
            json!({"sku": "A-1", "qty": 0}),
            json!({"sku": "A-1", "colour": "red"}),
            json!([1]),
        ] {
            assert!(
                attome_field::validate(&FieldType::Json, &bad, Some(&options)).is_err(),
                "{bad}"
            );
        }
        // without a schema any document is taken
        assert!(attome_field::validate(&FieldType::Json, &json!([1, "a"]), None).is_ok());
    }

    #[test]
    fn a_point_is_normalised_and_range_checked() {
        let stored = attome_field::normalize(&FieldType::Geolocation, &json!("٢٤.٥, 46.25"), None);
        assert_eq!(stored, Some(json!({"lat": 24.5, "lng": 46.25})));
        assert!(
            attome_field::validate(
                &FieldType::Geolocation,
                &json!({"lat": 24.5, "lng": 46.25}),
                None
            )
            .is_ok()
        );
        assert!(
            attome_field::validate(&FieldType::Geolocation, &json!({"lat": 99, "lng": 1}), None)
                .is_err()
        );
        assert!(attome_field::validate(&FieldType::Geolocation, &json!("24.5"), None).is_err());
    }
}

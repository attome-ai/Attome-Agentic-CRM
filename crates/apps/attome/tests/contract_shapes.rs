//! Z14-T7: every route's error and list shapes match the standard, read from
//! the generated `openapi.json`. An error response (4xx/5xx) carries the
//! `ErrorResponse` body; a list answer is a `PaginatedResponse` or
//! `CursorPage`, never a bare JSON array.
//!
//! The routes that predate the rule are listed below with what they break.
//! The lists only shrink: a new violation fails, and so does an entry whose
//! route has since been fixed (remove it).

use std::collections::BTreeSet;

/// `(operation_id, status)` of error responses without the `ErrorResponse` body.
const ERROR_SHAPE_EXEMPT: &[(&str, &str)] = &[
    ("aggregate", "422"),
    ("bottlenecks", "501"),
    ("change_attribute_type", "409"),
    ("confirm_tool_call", "409"),
    ("confirm_tool_call", "429"),
    ("conformance", "501"),
    ("create_api_key", "401"),
    ("delete_attribute", "409"),
    ("execute", "422"),
    ("findings", "501"),
    ("health_ready", "503"),
    ("health_startup", "503"),
    ("identity_link_google", "401"),
    ("mcp_endpoint", "503"),
    // D6-T11: the conflict answer carries both line sets for the user to choose.
    ("post_sales_quote_sync", "409"),
    ("reject_tool_call", "409"),
    ("rename_attribute", "409"),
    // B16-T8: more than one record holds the code; the answer lists them to pick from.
    ("scan_act", "409"),
    // D16-T1: a browser follows the tracked link; a bad token is a bare 404, no JSON.
    ("track_click", "404"),
];

/// Operations whose 200 answer is a bare JSON array.
const BARE_ARRAY_EXEMPT: &[&str] = &[
    "assign_entities",
    "candidates_for_record",
    "deactivate_sidebar_item",
    "describe_query",
    "get_ancestors",
    "get_related_pages",
    "get_sidebar",
    "get_space_templates",
    "identity_links",
    "item_actions",
    "list_active_offerings",
    "list_available_apps",
    "list_available_views",
    "list_conditions",
    "list_exceptions",
    "list_holidays",
    "list_labels",
    "list_offerings",
    "list_permissions",
    "list_spaces",
    "list_templates",
    "list_webcrawl_target_pages",
    "list_widget_types",
    "lookup_users",
    "mfa_coverage_summary",
    "oidc_providers",
    "portal_list_sessions",
    "set_related_pages",
    "set_space_templates",
    "stats",
    "trace",
];

fn openapi() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../openapi.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse openapi.json: {e}"))
}

/// The error responses without `ErrorResponse` and the bare-array 200s.
fn violations(doc: &serde_json::Value) -> (BTreeSet<(String, String)>, BTreeSet<String>) {
    let mut errors = BTreeSet::new();
    let mut arrays = BTreeSet::new();
    let Some(paths) = doc["paths"].as_object() else {
        return (errors, arrays);
    };
    for methods in paths.values() {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, op) in methods {
            if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                continue;
            }
            let id = op["operationId"].as_str().unwrap_or_default().to_owned();
            let Some(responses) = op["responses"].as_object() else {
                continue;
            };
            for (status, response) in responses {
                let schema = &response["content"]["application/json"]["schema"];
                if status.starts_with('4') || status.starts_with('5') {
                    if !schema.to_string().contains("ErrorResponse") {
                        errors.insert((id.clone(), status.clone()));
                    }
                } else if status == "200" && schema["type"] == "array" {
                    arrays.insert(id.clone());
                }
            }
        }
    }
    (errors, arrays)
}

#[test]
fn every_route_has_the_standard_error_and_list_shapes() {
    let doc = openapi();
    assert!(
        doc["paths"].as_object().is_some_and(|p| p.len() > 100),
        "openapi.json has its routes"
    );
    let (errors, arrays) = violations(&doc);

    let exempt_errors: BTreeSet<(String, String)> = ERROR_SHAPE_EXEMPT
        .iter()
        .map(|(id, status)| ((*id).to_owned(), (*status).to_owned()))
        .collect();
    let new_errors: Vec<_> = errors.difference(&exempt_errors).collect();
    assert!(
        new_errors.is_empty(),
        "these error responses do not carry the ErrorResponse body: {new_errors:?}"
    );
    let fixed_errors: Vec<_> = exempt_errors.difference(&errors).collect();
    assert!(
        fixed_errors.is_empty(),
        "these are fixed now; remove them from ERROR_SHAPE_EXEMPT: {fixed_errors:?}"
    );

    let exempt_arrays: BTreeSet<String> = BARE_ARRAY_EXEMPT
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    let new_arrays: Vec<_> = arrays.difference(&exempt_arrays).collect();
    assert!(
        new_arrays.is_empty(),
        "these lists answer a bare array; use PaginatedResponse or CursorPage: {new_arrays:?}"
    );
    let fixed_arrays: Vec<_> = exempt_arrays.difference(&arrays).collect();
    assert!(
        fixed_arrays.is_empty(),
        "these are fixed now; remove them from BARE_ARRAY_EXEMPT: {fixed_arrays:?}"
    );
}

#[test]
fn the_detector_flags_a_bare_array_and_a_plain_error() {
    let doc = serde_json::json!({
        "paths": {
            "/x": {
                "get": {
                    "operationId": "list_x",
                    "responses": {
                        "200": {"content": {"application/json": {"schema": {"type": "array"}}}},
                        "404": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "409": {"description": "no body"}
                    }
                }
            }
        }
    });
    let (errors, arrays) = violations(&doc);
    assert_eq!(
        errors.into_iter().collect::<Vec<_>>(),
        vec![("list_x".to_owned(), "409".to_owned())]
    );
    assert_eq!(
        arrays.into_iter().collect::<Vec<_>>(),
        vec!["list_x".to_owned()]
    );
}

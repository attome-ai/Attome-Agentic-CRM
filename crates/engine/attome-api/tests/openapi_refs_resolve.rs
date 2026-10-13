//! BTY-12: every `$ref` in attome-api's OpenAPI document resolves to a
//! component. `npm run generate:api` refuses a document that fails this, and a
//! `CursorPage` published through a type alias did exactly that. No database.
//!
//! ```powershell
//! cargo test -p attome-api --test openapi_refs_resolve
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

fn collect_refs(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                if k == "$ref"
                    && let Some(s) = x.as_str()
                {
                    out.push(s.to_string());
                }
                collect_refs(x, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

#[test]
fn every_ref_in_the_xrm_document_resolves() {
    let doc = serde_json::to_value(attome_api::openapi_document()).expect("serialize");
    let schemas = &doc["components"]["schemas"];
    let mut refs = Vec::new();
    collect_refs(&doc, &mut refs);
    let mut broken: Vec<String> = refs
        .into_iter()
        .filter(|r| {
            r.strip_prefix("#/components/schemas/")
                .is_none_or(|name| schemas.get(name).is_none())
        })
        .collect();
    broken.sort();
    broken.dedup();
    assert!(broken.is_empty(), "unresolvable $refs: {broken:?}");
}

/// The Angular client reads `Schemas['MyWorkPage']` and `Schemas['MyWorkItem']`.
#[test]
fn my_work_components_keep_their_names() {
    let doc = serde_json::to_value(attome_api::openapi_document()).expect("serialize");
    for name in ["MyWorkPage", "MyWorkItem", "MyWorkAction"] {
        assert!(
            doc["components"]["schemas"].get(name).is_some(),
            "{name} is missing from components.schemas"
        );
    }
}

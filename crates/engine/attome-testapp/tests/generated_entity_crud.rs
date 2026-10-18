//! AC5-T8: every entity in the registry goes through the generic record API:
//! create, read, update with `If-Match`, a stale update refused with 409
//! `version_conflict`, delete; and a create missing each required attribute
//! refused with 422. Entities come from the registry, never a hard-coded
//! list. Engine-owned entities the generic route refuses (403 or 405 on a
//! write), and entities whose required lookups a fixture cannot invent, are
//! skipped and listed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "test helpers: a failed setup step should panic with its message; the skip list is printed"
)]

use attome_core::{AttrInfo, EntityMeta};
use attome_testapp::TestApp;
use attome_testapp::fixtures::{Seeded, record_for, value_for};
use axum::http::{Method, StatusCode};
use serde_json::{Map, Value};

const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
];

/// Logs errors to the output, so a 500 names its cause.
fn log_errors() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .with_test_writer()
        .try_init();
}

async fn install(app: &TestApp) {
    attome_api::changeset::boot::apply_platform_changesets(&app.state)
        .await
        .expect("platform changesets");
    for pack in PACKS {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

/// The row version a record answer carries.
fn row_version(body: &Value) -> Option<i64> {
    body["row_version"]
        .as_i64()
        .or_else(|| body["data"]["row_version"].as_i64())
}

/// Optional attributes a caller may write and a fixture can fill.
fn writable(meta: &EntityMeta) -> impl Iterator<Item = &AttrInfo> {
    meta.attrs.iter().filter(|a| {
        !a.is_required
            && !a.is_sensitive
            && !a.is_write_restricted
            && !matches!(
                a.logicalname.as_str(),
                "id" | "row_version"
                    | "owner_ref"
                    | "owner_type"
                    | "created_by"
                    | "modified_by"
                    | "organization_ref"
                    | "is_active"
            )
    })
}

/// Why an entity is skipped.
type Skip = String;

/// One entity through the round trip; the failures found, or why it was
/// skipped.
async fn round_trip(app: &TestApp, meta: &EntityMeta, seed: u64) -> Result<Vec<String>, Skip> {
    let entity = meta.logicalname.as_str();
    let token = format!("ac5-{seed}");
    let mut body = record_for(meta, seed, &token);
    let required: Vec<&str> = meta
        .attrs
        .iter()
        .filter(|a| a.is_required)
        .map(|a| a.logicalname.as_str())
        .collect();
    if required.iter().any(|r| !body.contains_key(*r)) {
        return Err(
            "a required attribute a fixture cannot invent (a lookup, file or formula)".into(),
        );
    }
    // Nothing required: one optional value, so the body is never empty.
    let mut rng = Seeded::new(seed);
    let optional: Vec<(String, Value)> = writable(meta)
        .filter_map(|a| value_for(a, seed, &mut rng, &token).map(|v| (a.logicalname.clone(), v)))
        .collect();
    let mut failures = Vec::new();

    // Create, trying optional attributes one at a time when nothing is
    // required, until the engine takes one as writable.
    let mut created = Value::Null;
    let mut accepted = false;
    let attempts: Vec<Map<String, Value>> = if body.is_empty() {
        optional
            .iter()
            .take(5)
            .map(|(k, v)| Map::from_iter([(k.clone(), v.clone())]))
            .collect()
    } else {
        vec![body.clone()]
    };
    for attempt in attempts {
        let (status, answer) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(Value::Object(attempt.clone())),
            )
            .await;
        if status == StatusCode::FORBIDDEN || status == StatusCode::METHOD_NOT_ALLOWED {
            return Err(format!("the generic route refuses creates ({status})"));
        }
        if status.is_success() {
            body = attempt;
            created = answer;
            accepted = true;
            break;
        }
        // A server error is always a defect, never a fixture's limit.
        if status.is_server_error() {
            failures.push(format!("create: {status} {answer}"));
            return Ok(failures);
        }
        created = answer;
        if !body.is_empty() {
            // Every required attribute was given: the entity's own
            // validation refused a value the fixture invented.
            if status == StatusCode::UNPROCESSABLE_ENTITY {
                return Err(format!(
                    "its validation refuses the fixture's values: {created}"
                ));
            }
            failures.push(format!("create: {status} {created}"));
            return Ok(failures);
        }
    }
    if !accepted {
        return Err(format!(
            "no attribute a fixture can fill is writable by the generic route: {created}"
        ));
    }
    let Some(id) = created["id"].as_str().map(str::to_owned) else {
        failures.push(format!("create returned no id: {created}"));
        return Ok(failures);
    };

    // Read.
    let (status, read) = app
        .request(Method::GET, &format!("/api/v1/{entity}/{id}"), None)
        .await;
    if status != StatusCode::OK {
        failures.push(format!("read: {status} {read}"));
    }
    let Some(version) = row_version(&read).or_else(|| row_version(&created)) else {
        failures.push(format!("no row_version in {read}"));
        return Ok(failures);
    };

    // Update: the first attribute the engine takes as writable. A writable
    // field passes validation and then meets the version check; one it does
    // not take fails validation first.
    let mut rng = Seeded::new(seed.wrapping_add(1));
    let candidates: Vec<Map<String, Value>> = body
        .keys()
        .filter_map(|k| meta.attrs.iter().find(|a| &a.logicalname == k))
        .chain(writable(meta))
        .filter_map(|a| {
            value_for(a, seed.wrapping_add(1), &mut rng, &format!("{token}u"))
                .map(|v| Map::from_iter([(a.logicalname.clone(), v)]))
        })
        .take(5)
        .collect();
    let current = format!("\"{version}\"");
    let mut updated = false;
    for patch in candidates {
        let (status, answer) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{entity}/{id}"),
                &[("if-match", current.as_str())],
                Some(Value::Object(patch.clone())),
            )
            .await;
        if status == StatusCode::FORBIDDEN || status == StatusCode::METHOD_NOT_ALLOWED {
            return Err(format!("the generic route refuses updates ({status})"));
        }
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            continue;
        }
        if !status.is_success() {
            failures.push(format!("update: {status} {answer}"));
            break;
        }
        updated = true;
        // The same version again is stale now.
        let (status, stale) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{entity}/{id}"),
                &[("if-match", current.as_str())],
                Some(Value::Object(patch)),
            )
            .await;
        if status != StatusCode::CONFLICT || stale["error"] != "version_conflict" {
            failures.push(format!("stale update: {status} {stale}"));
        }
        break;
    }
    if !updated && failures.is_empty() {
        failures.push("no attribute could be updated".into());
    }

    // Delete.
    let (status, deleted) = app
        .request(Method::DELETE, &format!("/api/v1/{entity}/{id}"), None)
        .await;
    if status == StatusCode::FORBIDDEN || status == StatusCode::METHOD_NOT_ALLOWED {
        return Err(format!("the generic route refuses deletes ({status})"));
    }
    if !status.is_success() {
        failures.push(format!("delete: {status} {deleted}"));
    }

    // Each required attribute left out.
    for attr in required {
        let mut without = body.clone();
        without.remove(attr);
        let (status, answer) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(Value::Object(without)),
            )
            .await;
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            failures.push(format!("create without {attr}: {status} {answer}"));
        }
    }
    Ok(failures)
}

/// Defects this test found that wait for an owner's decision (V2-D508):
/// each must still fail, so the list only shrinks; fixing one means
/// removing it here.
const KNOWN_DEFECTS: &[(&str, &str)] = &[
    // A generic create reaches the partitioned log table, which has no
    // `is_active` column: 500. Refuse generic writes, or not?
    ("s2s_access_log", "create: 500"),
    // `email` is NOT NULL in the table but not required in metadata, so a
    // generic create without it is a 500, not a 422.
    ("user_account", "create: 500"),
];

// feature: A1, A16
#[test]
fn every_entity_crud_round_trip() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        log_errors();
        install(&app).await;
        let registry = app.state.entities.load();
        let mut metas: Vec<EntityMeta> = registry.iter().cloned().collect();
        metas.sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
        let mut skipped = Vec::new();
        let mut failed = Vec::new();
        let mut tried = 0;
        for (n, meta) in metas.iter().enumerate() {
            match round_trip(&app, meta, n as u64 + 1).await {
                Ok(failures) => {
                    tried += 1;
                    for failure in failures {
                        failed.push(format!("{}: {failure}", meta.logicalname));
                    }
                }
                Err(why) => skipped.push(format!("{}: {why}", meta.logicalname)),
            }
        }
        println!("skipped {} entities:", skipped.len());
        for skip in &skipped {
            println!("  {skip}");
        }
        println!("round-tripped {tried} entities, {} failures", failed.len());
        for failure in &failed {
            println!("  {failure}");
        }
        assert!(tried > 0, "no entity was tried");
        let is_known = |f: &String| {
            KNOWN_DEFECTS
                .iter()
                .any(|(entity, stage)| f.starts_with(&format!("{entity}: {stage}")))
        };
        let unknown: Vec<&String> = failed.iter().filter(|f| !is_known(f)).collect();
        let gone: Vec<&(&str, &str)> = KNOWN_DEFECTS
            .iter()
            .filter(|(entity, stage)| {
                !failed
                    .iter()
                    .any(|f| f.starts_with(&format!("{entity}: {stage}")))
            })
            .collect();
        assert!(
            unknown.is_empty(),
            "{} failures:\n{}",
            unknown.len(),
            unknown
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(
            gone.is_empty(),
            "fixed, so remove from KNOWN_DEFECTS: {gone:?}"
        );
    });
}

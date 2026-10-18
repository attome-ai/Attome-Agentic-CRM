//! Z15-T8: every seeded role sees and changes exactly what its privileges
//! say. For each role (read through the admin API, with its grants) a user
//! holding only that role lists every entity (200 with `{entity}.read`, 403
//! without), creates a record (403 without `{entity}.create`), and never
//! sees a sensitive attribute its role has no field profile for.
//!
//! A role reading or creating where it has no privilege is a leak: it fails
//! the test and is reported as a security defect, never accepted.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "test helpers: a failed setup step should panic with its message; the summary is printed"
)]

use std::collections::{BTreeMap, BTreeSet};

use attome_core::EntityMeta;
use attome_testapp::fixtures::record_for;
use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
];

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

/// Every page of an admin list.
async fn all_pages(app: &TestApp, path: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for page in 1.. {
        let (status, body) = app
            .request(
                Method::GET,
                &format!("{path}?page={page}&page_size=200"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let items = body["items"].as_array().cloned().unwrap_or_default();
        let total = body["total"].as_u64().unwrap_or(0) as usize;
        out.extend(items);
        if out.len() >= total || page > 100 {
            break;
        }
    }
    out
}

/// A user holding only `role`.
async fn user_with_role(app: &TestApp, role: Uuid) -> TestUser {
    let user = attome_testapp::seed_user(app.db(), "perm").await;
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .expect("grant the role");
    user
}

// feature: Q10, Q15
#[test]
fn every_role_matches_its_privileges() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;

        let roles = all_pages(&app, "/api/v1/admin/security/roles").await;
        let grants = all_pages(&app, "/api/v1/admin/security/role-grants").await;
        let mut privileges: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
        for grant in &grants {
            let (Some(role), Some(key)) = (
                grant["role_id"].as_str().and_then(|r| r.parse().ok()),
                grant["privilege_key"].as_str(),
            ) else {
                continue;
            };
            privileges.entry(role).or_default().insert(key.to_owned());
        }
        // Roles holding any field profile: their sensitive reads are the
        // profiles' business, checked by the field security tests.
        let profiled: BTreeSet<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT role_ref FROM role_mm_field_security_profile WHERE is_deleted = false",
        )
        .fetch_all(app.db())
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

        let registry = app.state.entities.load();
        let mut metas: Vec<EntityMeta> = registry.iter().cloned().collect();
        metas.sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
        // One record per entity the administrator can create, for the
        // sensitive-attribute check.
        let mut records: BTreeMap<String, String> = BTreeMap::new();
        for meta in metas
            .iter()
            .filter(|m| m.attrs.iter().any(|a| a.is_sensitive))
        {
            let body = record_for(meta, 1, "perm");
            let (status, created) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{}", meta.logicalname),
                    Some(Value::Object(body)),
                )
                .await;
            if status.is_success()
                && let Some(id) = created["id"].as_str()
            {
                records.insert(meta.logicalname.clone(), id.to_owned());
            }
        }

        let mut leaks = Vec::new();
        let mut mismatches = Vec::new();
        let mut checks = 0usize;
        for role in &roles {
            let Some(role_id) = role["id"].as_str().and_then(|r| r.parse::<Uuid>().ok()) else {
                continue;
            };
            let name = role["name"].as_str().unwrap_or("?").to_owned();
            let held = privileges.get(&role_id).cloned().unwrap_or_default();
            if held.contains("system.admin") {
                continue;
            }
            let user = user_with_role(&app, role_id).await;
            for meta in &metas {
                let entity = meta.logicalname.as_str();
                // Read: the entity's list, through its default query.
                let (status, _) = app
                    .request_as(
                        &user.cookie,
                        Method::POST,
                        "/api/v1/query/execute",
                        Some(serde_json::json!({ "entity": entity, "page_size": 1 })),
                    )
                    .await;
                // No default query, or not on the generic path: nothing to check.
                if status == StatusCode::NOT_FOUND
                    || status == StatusCode::METHOD_NOT_ALLOWED
                    || status == StatusCode::UNPROCESSABLE_ENTITY
                {
                    continue;
                }
                checks += 1;
                let may_read = held.contains(&format!("{entity}.read"));
                match (may_read, status) {
                    (true, StatusCode::OK) | (false, StatusCode::FORBIDDEN) => {}
                    (false, StatusCode::OK) => {
                        leaks.push(format!("{name} lists {entity} with no {entity}.read"))
                    }
                    (expected, actual) => mismatches.push(format!(
                        "{name} on {entity}: read={expected}, list answered {actual}"
                    )),
                }
                // Create, where the role may not.
                if !held.contains(&format!("{entity}.create")) {
                    let body = record_for(meta, 2, "perm");
                    let (status, answer) = app
                        .request_as(
                            &user.cookie,
                            Method::POST,
                            &format!("/api/v1/{entity}"),
                            Some(Value::Object(body)),
                        )
                        .await;
                    checks += 1;
                    if status.is_success() {
                        leaks.push(format!(
                            "{name} created {entity} with no {entity}.create: {answer}"
                        ));
                    } else if status != StatusCode::FORBIDDEN
                        && status != StatusCode::METHOD_NOT_ALLOWED
                    {
                        mismatches.push(format!(
                            "{name} creating {entity} without the privilege: {status}"
                        ));
                    }
                }
                // Sensitive attributes, for a role with no field profile.
                if may_read
                    && !profiled.contains(&role_id)
                    && let Some(id) = records.get(entity)
                {
                    let (status, read) = app
                        .request_as(
                            &user.cookie,
                            Method::GET,
                            &format!("/api/v1/{entity}/{id}"),
                            None,
                        )
                        .await;
                    if status == StatusCode::OK {
                        for attr in meta.attrs.iter().filter(|a| a.is_sensitive) {
                            checks += 1;
                            let shown = read["data"]
                                .get(&attr.logicalname)
                                .is_some_and(|v| !v.is_null());
                            if shown {
                                leaks.push(format!(
                                    "{name} reads the sensitive {entity}.{} with no field profile",
                                    attr.logicalname
                                ));
                            }
                        }
                    }
                }
            }
        }
        println!(
            "{} roles, {} entities, {checks} checks, {} leaks, {} mismatches",
            roles.len(),
            metas.len(),
            leaks.len(),
            mismatches.len()
        );
        for line in leaks.iter().chain(mismatches.iter()) {
            println!("  {line}");
        }
        assert!(checks > 0, "nothing was checked");
        assert!(leaks.is_empty(), "SECURITY DEFECT:\n{}", leaks.join("\n"));
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    });
}

//! Z5-T3: every route resolves to a policy, and a route's own body limit is
//! read from the API document.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::route_policy::RoutePolicyTable;

const GLOBAL: usize = 10 * 1024 * 1024;

fn table() -> RoutePolicyTable {
    let document = serde_json::to_value(&*attome::openapi::document()).expect("serialises");
    RoutePolicyTable::from_document(&document, GLOBAL).expect("every route resolves")
}

#[test]
fn every_route_has_resolvable_policy() {
    let table = table();
    assert!(table.len() > 100, "{} routes", table.len());
    let login = table
        .get("POST", "/api/v1/auth/login")
        .expect("login is listed");
    assert_eq!(login.auth, "public");
    assert_eq!(login.body_limit, GLOBAL);
}

#[test]
fn per_route_body_limit_is_enforced() {
    let table = table();
    let upload = table
        .get("POST", "/api/v1/{entity}/{id}/files/{field}/upload-session")
        .expect("the upload-session route is listed");
    assert_eq!(upload.body_limit, 65_536, "its own, lower limit");
}

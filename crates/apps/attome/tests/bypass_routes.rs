//! Z5-T2: the authentication bypass list agrees with the routes. Every exact
//! bypass path is a documented route, and every documented route a bypass
//! rule covers (exact, subtree prefix or integration webhook) declares no
//! security requirement — so a prefix can never swallow a protected route
//! added under it later. Reads the OpenAPI document the server serves; needs
//! no database.

use attome_server::middleware::bypass::{EXACT_BYPASS_PATHS, is_bypass};

fn paths() -> serde_json::Map<String, serde_json::Value> {
    let document = serde_json::to_value(&*attome::openapi::document()).expect("OpenAPI serialises");
    document["paths"]
        .as_object()
        .cloned()
        .expect("the document has paths")
}

#[test]
fn every_exact_bypass_path_is_a_documented_route() {
    let paths = paths();
    let missing: Vec<&str> = EXACT_BYPASS_PATHS
        .iter()
        .copied()
        .filter(|path| !paths.contains_key(*path))
        .collect();
    assert!(
        missing.is_empty(),
        "bypass paths with no route (remove them, or register the route): {missing:?}"
    );
}

#[test]
fn no_bypass_rule_covers_a_protected_route() {
    let mut covered_but_secured = Vec::new();
    for (path, operations) in paths() {
        if !is_bypass(&path) {
            continue;
        }
        let Some(operations) = operations.as_object() else {
            continue;
        };
        for (method, operation) in operations {
            let secured = operation["security"]
                .as_array()
                .is_some_and(|requirements| {
                    requirements
                        .iter()
                        .any(|r| r.as_object().is_some_and(|r| !r.is_empty()))
                });
            if secured {
                covered_but_secured.push(format!("{} {path}", method.to_uppercase()));
            }
        }
    }
    assert!(
        covered_but_secured.is_empty(),
        "routes a bypass rule exempts from sign-in but that declare a security requirement \
         (narrow the bypass rule, or make the route's contract public): {covered_but_secured:?}"
    );
}

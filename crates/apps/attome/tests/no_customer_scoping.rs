//! Y5-T1: one deployment serves one customer (guidelines §8, V2-D470), so no
//! table carries a customer-scoping column. A `tenant_id` added "just in
//! case" is the first step towards mixing customers' data in one database;
//! this test refuses it in the migrations (infrastructure tables) and in the
//! platform changesets (metadata entities).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::PathBuf;

/// Column names that scope rows to a customer.
const FORBIDDEN: &[&str] = &[
    "tenant",
    "tenant_id",
    "tenant_ref",
    "tenant_key",
    "customer_tenant",
    "deployment_tenant",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

/// The identifiers in `text`: runs of letters, digits and underscores.
fn identifiers(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
}

#[test]
fn no_migration_adds_a_customer_scoping_column() {
    let dir = root().join("crates/apps/attome/migrations");
    let mut offenders = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("migrations dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("--").next().unwrap_or_default();
            if let Some(word) = identifiers(code).find(|w| FORBIDDEN.contains(&w.as_str())) {
                offenders.push(format!("{}:{}: {word}", path.display(), n + 1));
            }
        }
    }
    assert!(files > 10, "found only {files} migrations under {dir:?}");
    assert!(
        offenders.is_empty(),
        "customer-scoping columns: {offenders:#?}"
    );
}

#[test]
fn no_platform_changeset_adds_a_customer_scoping_field() {
    let dir = root().join("changesets/platform");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("changesets dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for op in doc["operations"].as_array().into_iter().flatten() {
            let field = op["target"]["field"].as_str().unwrap_or_default();
            if FORBIDDEN.contains(&field.to_ascii_lowercase().as_str()) {
                offenders.push(format!("{}: {field}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "customer-scoping fields: {offenders:#?}"
    );
}

#[test]
fn the_identifier_split_finds_whole_words_only() {
    let words: Vec<String> = identifiers("ADD COLUMN tenant_id uuid, tenants_note text").collect();
    assert!(words.contains(&"tenant_id".to_owned()));
    assert!(!FORBIDDEN.contains(&"tenants_note"));
}

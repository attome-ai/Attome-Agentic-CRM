//! Q18-T3: every credential-like column a migration creates is either
//! encrypted and registered (`attome_auth::encrypted_columns::ENCRYPTED_COLUMNS`),
//! a one-way hash or fingerprint, or a reviewed plain column
//! (`PLAIN_BY_DESIGN`). A new `api_token text` column fails here until it is
//! encrypted and registered, or hashed.

use attome_auth::encrypted_columns::{ENCRYPTED_COLUMNS, accounted_for, looks_like_credential};

/// `(table, column)` for every column created or added by a migration.
fn migration_columns() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let sql = std::fs::read_to_string(&file).unwrap_or_default();
        let mut table: Option<String> = None;
        for line in sql.lines() {
            let trimmed = line.trim();
            let upper = trimmed.to_ascii_uppercase();
            if let Some(rest) = upper
                .strip_prefix("CREATE TABLE IF NOT EXISTS ")
                .or_else(|| upper.strip_prefix("CREATE TABLE "))
            {
                let name = rest.split([' ', '(']).next().unwrap_or("");
                table = Some(name.trim_matches('"').to_ascii_lowercase());
                continue;
            }
            if let Some(rest) = upper.strip_prefix("ALTER TABLE ") {
                let name = rest
                    .trim_start_matches("IF EXISTS ")
                    .trim_start_matches("ONLY ")
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                table = Some(name.trim_matches('"').to_ascii_lowercase());
                continue;
            }
            if trimmed.starts_with(");") {
                continue;
            }
            let Some(current) = &table else { continue };
            let body = trimmed
                .trim_start_matches("ADD COLUMN IF NOT EXISTS ")
                .trim_start_matches("add column if not exists ");
            let mut words = body.split_whitespace();
            let (Some(column), Some(kind)) = (words.next(), words.next()) else {
                continue;
            };
            let column = column.trim_matches('"').trim_end_matches(',');
            let is_column = column
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !column.is_empty()
                && !matches!(
                    column,
                    "constraint" | "primary" | "unique" | "check" | "foreign" | "references"
                )
                && kind.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
            if is_column {
                out.push((current.clone(), column.to_owned()));
            }
        }
    }
    out
}

#[test]
fn every_credential_like_column_is_encrypted_hashed_or_reviewed() {
    let columns = migration_columns();
    assert!(columns.len() > 100, "the migration scan found the columns");
    let mut unaccounted: Vec<String> = columns
        .iter()
        .filter(|(t, c)| looks_like_credential(c) && !accounted_for(t, c))
        .map(|(t, c)| format!("{t}.{c}"))
        .collect();
    unaccounted.sort();
    unaccounted.dedup();
    assert!(
        unaccounted.is_empty(),
        "credential-like columns outside the encrypted-column registry \
         (encrypt and register them, hash them, or review them into PLAIN_BY_DESIGN): \
         {unaccounted:?}"
    );
}

#[test]
fn every_registered_column_exists() {
    let columns = migration_columns();
    for c in ENCRYPTED_COLUMNS {
        assert!(
            columns
                .iter()
                .any(|(t, col)| t == c.table && col == c.column),
            "{}.{} is registered but no migration creates it",
            c.table,
            c.column
        );
    }
}

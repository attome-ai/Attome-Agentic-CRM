//! Every OpenAPI schema has its own name. utoipa names a schema after its
//! Rust type, and two types called `ValidateResponse` in different crates
//! merge into one component, so the generated TypeScript silently takes one
//! shape for both (the business-rule editor lost its `warnings` that way).
//! A type that shares a name gives itself another with `#[schema(as = ...)]`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name == "tests" || name == "target" || name.starts_with('.') {
                continue;
            }
            walk(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// The schema names a source file declares: each `#[derive(.., ToSchema, ..)]`
/// type's name, or its `#[schema(as = ..)]` alias.
fn schema_names(source: &str) -> Vec<String> {
    let code = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source);
    let mut names = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find("#[derive(") {
        let after = &rest[at..];
        let Some(end) = after.find(")]") else { break };
        let derive = &after[..end];
        let mut tail = &after[end + 2..];
        rest = tail;
        if !derive.contains("ToSchema") {
            continue;
        }
        let mut alias: Option<String> = None;
        loop {
            tail = tail.trim_start();
            if tail.starts_with("//") {
                tail = tail.split_once('\n').map_or("", |(_, r)| r);
            } else if tail.starts_with("#[") {
                let Some(close) = tail.find("]\n").or_else(|| tail.find(']')) else {
                    break;
                };
                let attribute = &tail[..close];
                if attribute.starts_with("#[schema(")
                    && let Some(pos) = attribute
                        .find(" as = ")
                        .map(|p| p + 1)
                        .or_else(|| attribute.find("(as = ").map(|p| p + 1))
                {
                    let value = attribute[pos..]
                        .trim_start_matches("as")
                        .trim_start_matches([' ', '='])
                        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                        .next()
                        .unwrap_or_default();
                    alias = value.rsplit("::").next().map(str::to_owned);
                }
                tail = &tail[close + 1..];
            } else {
                break;
            }
        }
        let decl = tail
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub(super) ")
            .trim_start_matches("pub ");
        let Some(item) = decl
            .strip_prefix("struct ")
            .or_else(|| decl.strip_prefix("enum "))
        else {
            continue;
        };
        let ident: String = item
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        names.push(alias.unwrap_or(ident));
    }
    names
}

#[test]
fn schema_names_are_unique() {
    let mut files = Vec::new();
    walk(&root().join("crates"), &mut files);
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for name in schema_names(&text) {
            seen.entry(name)
                .or_default()
                .push(file.display().to_string());
        }
    }
    assert!(seen.len() > 300, "found only {} schemas", seen.len());
    let duplicates: Vec<_> = seen.iter().filter(|(_, files)| files.len() > 1).collect();
    assert!(
        duplicates.is_empty(),
        "give one of each a distinct `#[schema(as = ...)]`: {duplicates:#?}"
    );
}

#[test]
fn the_scanner_reads_names_and_aliases() {
    let source = "#[derive(Debug, Serialize, ToSchema)]\n/// doc\n#[serde(rename_all = \"snake_case\")]\npub struct One { a: u8 }\n\
                  #[derive(Serialize, utoipa::ToSchema)]\n#[schema(as = OtherName)]\nstruct Two;\n\
                  #[derive(Debug)]\nstruct NotASchema;\n";
    assert_eq!(schema_names(source), ["One", "OtherName"]);
}

//! Dependency intake (roadmap AC7-T9): a dependency added since the previous
//! release needs a reviewed entry in `docs/dependencies/intake.json` saying
//! why it is needed, its licence, how well it is maintained and whether it
//! builds natively on Windows (V2-D471: no Linux-only parts).
//!
//! New means a package *name* that the previous release's lock file did not
//! have; a version bump of an existing package is not new. Rust packages come
//! from `Cargo.lock` (registry packages only: the workspace's own crates are
//! not intake), npm packages from `web/package-lock.json` (production ones).
//! A Rust package marked `windows_native: false` fails the step, since every
//! Rust dependency ends up in the server, the CLI or the installer.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

pub const INTAKE: &str = "docs/dependencies/intake.json";

/// Registry package names in a `Cargo.lock`.
pub fn cargo_names(lock: &str) -> BTreeSet<String> {
    crate::sbom::parse_lock(lock)
        .into_iter()
        .filter(|package| package.source.is_some())
        .map(|package| package.name)
        .collect()
}

/// Production package names in a `package-lock.json`.
pub fn npm_names(lock: &Value) -> BTreeSet<String> {
    lock["packages"]
        .as_object()
        .map(|packages| {
            packages
                .iter()
                .filter(|(path, package)| {
                    path.contains("node_modules/")
                        && package["dev"].as_bool() != Some(true)
                        && package["link"].as_bool() != Some(true)
                })
                .filter_map(|(path, _)| path.rsplit("node_modules/").next().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Every problem: a new name without an intake entry, or a Rust dependency
/// that is not Windows-native.
pub fn problems(
    new_cargo: &BTreeSet<String>,
    new_npm: &BTreeSet<String>,
    intake: &Value,
) -> Vec<String> {
    let entries = intake["dependencies"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let find = |ecosystem: &str, name: &str| {
        entries
            .iter()
            .find(|e| e["ecosystem"] == ecosystem && e["name"] == name)
            .cloned()
    };
    let mut out = Vec::new();
    for name in new_cargo {
        match find("cargo", name) {
            None => out.push(format!(
                "cargo package `{name}` is new and has no intake entry"
            )),
            Some(entry) if entry["windows_native"] != Value::Bool(true) => out.push(format!(
                "cargo package `{name}` is not marked windows_native: true (V2-D471)"
            )),
            Some(_) => {}
        }
    }
    for name in new_npm {
        if find("npm", name).is_none() {
            out.push(format!(
                "npm package `{name}` is new and has no intake entry"
            ));
        }
    }
    out
}

fn git_show(root: &Path, spec: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["show", spec])
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `dependency_intake` gate step.
pub fn step(root: &Path, previous_tag: Option<&str>) -> Result<(), String> {
    let Some(tag) = previous_tag else {
        crate::say("    dependency_intake: no previous release tag; nothing to compare");
        return Ok(());
    };
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).map_err(|error| format!("{rel}: {error}"))
    };
    let old_cargo = cargo_names(&git_show(root, &format!("{tag}:Cargo.lock")).unwrap_or_default());
    let new_cargo: BTreeSet<String> = cargo_names(&read("Cargo.lock")?)
        .difference(&old_cargo)
        .cloned()
        .collect();
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
    let old_npm = npm_names(&parse(
        &git_show(root, &format!("{tag}:web/package-lock.json")).unwrap_or_default(),
    ));
    let new_npm: BTreeSet<String> = npm_names(&parse(&read("web/package-lock.json")?))
        .difference(&old_npm)
        .cloned()
        .collect();
    let intake = parse(&std::fs::read_to_string(root.join(INTAKE)).unwrap_or_default());
    let problems = problems(&new_cargo, &new_npm, &intake);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "dependencies added since {tag} need an entry in {INTAKE} (name, ecosystem, reason, \
             licence, maintenance, windows_native):\n  {}",
            problems.join("\n  ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lock(names: &[(&str, &str)]) -> String {
        names
            .iter()
            .map(|(name, version)| {
                format!(
                    "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n"
                )
            })
            .collect()
    }

    #[test]
    fn new_crate_without_entry_fails() {
        let old = cargo_names(&lock(&[("serde", "1.0.0")]));
        let new = cargo_names(&lock(&[("serde", "1.0.0"), ("left-pad", "0.1.0")]));
        let added: BTreeSet<String> = new.difference(&old).cloned().collect();
        let empty = json!({ "dependencies": [] });
        assert_eq!(
            problems(&added, &BTreeSet::new(), &empty),
            ["cargo package `left-pad` is new and has no intake entry"]
        );
        let linux_only = json!({ "dependencies": [
            { "name": "left-pad", "ecosystem": "cargo", "reason": "r", "licence": "MIT",
              "maintenance": "m", "windows_native": false }
        ]});
        assert!(problems(&added, &BTreeSet::new(), &linux_only)[0].contains("windows_native"));
        let fine = json!({ "dependencies": [
            { "name": "left-pad", "ecosystem": "cargo", "reason": "r", "licence": "MIT",
              "maintenance": "m", "windows_native": true }
        ]});
        assert!(problems(&added, &BTreeSet::new(), &fine).is_empty());
    }

    #[test]
    fn transitive_bump_is_not_new() {
        let old = cargo_names(&lock(&[("serde", "1.0.0")]));
        let new = cargo_names(&lock(&[("serde", "1.0.200")]));
        assert!(new.difference(&old).next().is_none());
        let npm_old =
            npm_names(&json!({ "packages": { "node_modules/a": { "version": "1.0.0" } } }));
        let npm_new = npm_names(&json!({ "packages": {
            "node_modules/a": { "version": "1.2.0" },
            "node_modules/t": { "version": "1.0.0", "dev": true }
        }}));
        assert!(
            npm_new.difference(&npm_old).next().is_none(),
            "bumps and dev packages are not new"
        );
    }
}

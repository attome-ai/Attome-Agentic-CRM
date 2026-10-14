//! Line coverage per crate on request (roadmap Z15-T10): `attome test
//! --coverage` runs each `cargo test` command through `cargo llvm-cov` and
//! prints the covered share of lines per crate. There is no coverage
//! threshold: the number informs, it does not gate.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The install hint when `cargo llvm-cov` is missing.
pub const INSTALL_HINT: &str = "cargo install cargo-llvm-cov --locked";

/// Whether `cargo llvm-cov` is installed.
pub fn available() -> bool {
    Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// A `cargo test ...` argument list rewritten to run under `cargo llvm-cov`,
/// writing its JSON report to `output`.
pub fn wrap(args: &[String], output: &Path) -> Vec<String> {
    let mut wrapped = vec!["llvm-cov".to_owned()];
    let rest = args.strip_prefix(&["test".to_owned()]).unwrap_or(args);
    let split = rest
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(rest.len());
    wrapped.extend(rest[..split].iter().cloned());
    wrapped.extend([
        "--json".to_owned(),
        "--output-path".to_owned(),
        output.display().to_string(),
    ]);
    wrapped.extend(rest[split..].iter().cloned());
    wrapped
}

/// Covered and total lines per crate from an llvm-cov JSON export, files
/// grouped by the crate that owns them (files outside the workspace, such as
/// dependencies, are left out).
pub fn per_crate(report: &Value, root: &Path) -> BTreeMap<String, (u64, u64)> {
    let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let files = report["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|data| data["files"].as_array())
        .flatten();
    for file in files {
        let Some(name) = file["filename"].as_str() else {
            continue;
        };
        let path = Path::new(name);
        let relative = path.strip_prefix(root).unwrap_or(path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        let Some(package) = crate::test_cmd::owning_crate(root, &relative) else {
            continue;
        };
        let lines = &file["summary"]["lines"];
        let entry = totals.entry(package).or_default();
        entry.0 += lines["covered"].as_u64().unwrap_or(0);
        entry.1 += lines["count"].as_u64().unwrap_or(0);
    }
    totals
}

/// The per-crate table `attome test --coverage` prints.
pub fn render(totals: &BTreeMap<String, (u64, u64)>) -> String {
    let mut out = String::from("line coverage per crate:\n");
    for (package, (covered, count)) in totals {
        let percent = if *count == 0 {
            0.0
        } else {
            // Line counts are far below 2^52, so the conversion is exact.
            *covered as f64 / *count as f64 * 100.0
        };
        out.push_str(&format!(
            "  {package:<32} {percent:>6.1}%  ({covered}/{count})\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn groups_files_by_crate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf();
        let file = |rel: &str, covered: u64, count: u64| {
            json!({
                "filename": root.join(rel).display().to_string(),
                "summary": { "lines": { "covered": covered, "count": count } }
            })
        };
        let report = json!({ "data": [{ "files": [
            file("crates/apps/attome-release/src/lib.rs", 50, 100),
            file("crates/apps/attome-release/src/slo.rs", 30, 50),
            file("crates/engine/attome-api/src/lib.rs", 1, 4),
            { "filename": "/home/x/.cargo/registry/src/serde/lib.rs",
              "summary": { "lines": { "covered": 9, "count": 9 } } }
        ]}]});
        let totals = per_crate(&report, &root);
        assert_eq!(totals.get("attome-release"), Some(&(80, 150)));
        assert_eq!(totals.get("attome-api"), Some(&(1, 4)));
        assert_eq!(totals.len(), 2, "dependencies are left out");
        assert!(render(&totals).contains("25.0%"));

        let wrapped = wrap(
            &["test", "-p", "x", "--lib", "--", "--skip", "y"].map(str::to_owned),
            Path::new("cov.json"),
        );
        assert_eq!(
            wrapped.join(" "),
            "llvm-cov -p x --lib --json --output-path cov.json -- --skip y"
        );
    }
}

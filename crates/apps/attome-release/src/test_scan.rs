//! The test tag scanner (roadmap AC5-T1).
//!
//! Every test may carry tags in the comment lines just above it:
//!
//! ```text
//! // feature: A1, A2        the feature ids it proves (docs/features.json)
//! // op: createRecord       the API operations it calls (operationId, or `POST /api/v1/x`)
//! // negative: createRecord the operations whose refusal path it checks
//! // regression: D-123      the defect or decision it guards
//! ```
//!
//! The scanner walks `crates/`, `web/projects/`, `web/src/` and `e2e/tests/`
//! (skipping `target`, `node_modules` and `dist`), finds Rust tests
//! (`#[test]`, `#[tokio::test]`) and TypeScript tests (`it(`, `test(`,
//! `test.describe(`), and gives each a tier from its path.

use std::path::{Path, PathBuf};

/// A test's tier, from where it lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Unit,
    Integration,
    Contract,
    Component,
    Browser,
    Performance,
}

impl Tier {
    /// Every tier, in report order.
    pub const ALL: [Self; 6] = [
        Self::Unit,
        Self::Integration,
        Self::Contract,
        Self::Component,
        Self::Browser,
        Self::Performance,
    ];

    /// The tier's name in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Integration => "integration",
            Self::Contract => "contract",
            Self::Component => "component",
            Self::Browser => "browser",
            Self::Performance => "performance",
        }
    }
}

/// One test and its tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRef {
    /// Relative to the workspace root, with forward slashes.
    pub file: String,
    /// One-based line of the test's attribute or call.
    pub line: u32,
    pub name: String,
    pub tier: Tier,
    pub features: Vec<String>,
    pub ops: Vec<String>,
    pub negative_ops: Vec<String>,
    pub regressions: Vec<String>,
}

const ROOTS: [&str; 4] = ["crates", "web/projects", "web/src", "e2e/tests"];
const SKIPPED_DIRS: [&str; 3] = ["target", "node_modules", "dist"];

/// The tier of a test file, or `None` when the path holds no tests the map
/// counts.
pub fn tier_of(relative: &str) -> Option<Tier> {
    let file_name = relative.rsplit('/').next().unwrap_or(relative);
    if relative.starts_with("crates/") && relative.ends_with(".rs") {
        if relative.contains("/benches/") {
            Some(Tier::Performance)
        } else if relative.contains("/tests/") {
            if file_name.contains("contract") {
                Some(Tier::Contract)
            } else {
                Some(Tier::Integration)
            }
        } else if relative.contains("/src/") {
            Some(Tier::Unit)
        } else {
            None
        }
    } else if relative.ends_with(".spec.ts") {
        if relative.starts_with("e2e/tests/") {
            Some(Tier::Browser)
        } else if relative.starts_with("web/") {
            Some(Tier::Component)
        } else {
            None
        }
    } else {
        None
    }
}

/// Splits the tags in the (up to five) lines above a test into its lists.
fn tags(above: &[&str]) -> [Vec<String>; 4] {
    let mut out: [Vec<String>; 4] = Default::default();
    for line in above {
        let Some(comment) = line.trim_start().strip_prefix("//") else {
            continue;
        };
        let comment = comment.trim_start_matches('/').trim();
        let Some((key, value)) = comment.split_once(':') else {
            continue;
        };
        let slot = match key.trim() {
            "feature" => 0,
            "op" => 1,
            "negative" => 2,
            "regression" => 3,
            _ => continue,
        };
        out[slot].extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned),
        );
    }
    out
}

fn rust_test_name(line: &str) -> Option<String> {
    let after = line.split_once("fn ")?.1;
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn ts_test_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = ["test.describe(", "describe(", "it(", "test("]
        .iter()
        .find_map(|call| trimmed.strip_prefix(call))?;
    let rest = rest.trim_start();
    let quote = rest
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let body = &rest[quote.len_utf8()..];
    Some(body.split(quote).next().unwrap_or_default().to_owned())
}

/// The tests in one file's text.
pub fn scan_text(relative: &str, text: &str) -> Vec<TestRef> {
    let Some(tier) = tier_of(relative) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let rust = relative.ends_with(".rs");
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let name = if rust {
            if !(trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test")) {
                continue;
            }
            match lines[index + 1..]
                .iter()
                .take(12)
                .copied()
                .find_map(rust_test_name)
            {
                Some(name) => name,
                None => continue,
            }
        } else {
            match ts_test_name(line) {
                Some(name) => name,
                None => continue,
            }
        };
        let above = &lines[index.saturating_sub(5)..index];
        let [features, ops, negative_ops, regressions] = tags(above);
        found.push(TestRef {
            file: relative.to_owned(),
            line: u32::try_from(index + 1).unwrap_or(u32::MAX),
            name,
            tier,
            features,
            ops,
            negative_ops,
            regressions,
        });
    }
    found
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIPPED_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                continue;
            }
            walk(&path, out);
        } else if name.ends_with(".rs") || name.ends_with(".spec.ts") {
            out.push(path);
        }
    }
}

/// Every test under the scanned roots of `root`, sorted by file and line.
pub fn scan(root: &Path) -> Vec<TestRef> {
    let mut files = Vec::new();
    for dir in ROOTS {
        walk(&root.join(dir), &mut files);
    }
    let mut tests = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if let Ok(text) = std::fs::read_to_string(&file) {
            tests.extend(scan_text(&relative, &text));
        }
    }
    tests.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    tests
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("attome-scan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn rust_test_with_feature_tag_is_found() {
        let text = "\
// feature: A1, A2
// negative: createRecord
#[tokio::test]
async fn creating_without_a_name_is_refused() {}

#[test]
fn untagged() {}
";
        let tests = scan_text("crates/engine/attome-x/tests/records.rs", text);
        assert_eq!(tests.len(), 2);
        assert_eq!(tests[0].name, "creating_without_a_name_is_refused");
        assert_eq!(tests[0].tier, Tier::Integration);
        assert_eq!(tests[0].features, ["A1", "A2"]);
        assert_eq!(tests[0].negative_ops, ["createRecord"]);
        assert_eq!(tests[0].line, 3);
        assert!(tests[1].features.is_empty());
        assert_eq!(
            tier_of("crates/engine/attome-x/tests/api_contract.rs"),
            Some(Tier::Contract)
        );
        assert_eq!(
            tier_of("crates/engine/attome-x/src/lib.rs"),
            Some(Tier::Unit)
        );
    }

    #[test]
    fn ts_spec_tier_is_component() {
        let text = "\
describe('record form', () => {
  // feature: A5
  it('shows the required marker', () => {});
});
";
        let tests = scan_text("web/projects/xrm/core/form.spec.ts", text);
        assert_eq!(tests.len(), 2);
        assert!(tests.iter().all(|t| t.tier == Tier::Component));
        assert_eq!(tests[1].name, "shows the required marker");
        assert_eq!(tests[1].features, ["A5"]);
    }

    #[test]
    fn e2e_spec_tier_is_browser() {
        let tests = scan_text(
            "e2e/tests/sign-in.spec.ts",
            "test(\"signs in\", async ({ page }) => {});\n",
        );
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].tier, Tier::Browser);
        assert_eq!(tests[0].name, "signs in");
    }

    #[test]
    fn paths_under_target_are_skipped() {
        let root = scratch("skip");
        write(&root, "crates/a/src/lib.rs", "#[test]\nfn kept() {}\n");
        write(
            &root,
            "crates/a/target/debug/build/x.rs",
            "#[test]\nfn skipped() {}\n",
        );
        write(
            &root,
            "web/projects/x/node_modules/y/z.spec.ts",
            "it('skipped', () => {});\n",
        );
        let names: Vec<String> = scan(&root).into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["kept"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}

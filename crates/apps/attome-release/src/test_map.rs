//! The test coverage map (roadmap AC5-T2, AC5-T3): `attome test map`.
//!
//! Joins the scanned tests ([`crate::test_scan`]) with the feature list
//! (`docs/features.json`) and the API operations (`openapi.json`), and writes
//! `target/coverage-map/map.json` and a static `index.html`:
//!
//! - per feature, the tagged tests by tier; a feature with none is a gap;
//! - per operation, whether a test tags it with `// op:`, and for a mutating
//!   operation (POST, PUT, PATCH, DELETE) whether one tags it with
//!   `// negative:`. Only the tags count; test names are never guessed from.
//!
//! The page loads nothing from outside: no scripts, fonts or styles.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::test_scan::{TestRef, Tier};

/// A feature from `docs/features.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feature {
    pub id: String,
    pub name: String,
}

/// Reads the feature list.
pub fn features(text: &str) -> Result<Vec<Feature>, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|error| format!("docs/features.json: {error}"))?;
    let list = value["features"]
        .as_array()
        .ok_or("docs/features.json has no `features` list")?;
    Ok(list
        .iter()
        .filter_map(|item| {
            Some(Feature {
                id: item["id"].as_str()?.to_owned(),
                name: item["name"].as_str()?.to_owned(),
            })
        })
        .collect())
}

/// One feature's tests by tier.
#[derive(Debug, Clone)]
pub struct FeatureCoverage {
    pub id: String,
    pub name: String,
    pub by_tier: BTreeMap<Tier, Vec<TestRef>>,
}

impl FeatureCoverage {
    /// No test in any tier.
    pub fn is_gap(&self) -> bool {
        self.by_tier.values().all(Vec::is_empty)
    }
}

/// Each feature with the tests that tag it.
pub fn coverage(features: &[Feature], tests: &[TestRef]) -> Vec<FeatureCoverage> {
    features
        .iter()
        .map(|feature| {
            let mut by_tier: BTreeMap<Tier, Vec<TestRef>> = BTreeMap::new();
            for test in tests.iter().filter(|t| t.features.contains(&feature.id)) {
                by_tier.entry(test.tier).or_default().push(test.clone());
            }
            FeatureCoverage {
                id: feature.id.clone(),
                name: feature.name.clone(),
                by_tier,
            }
        })
        .collect()
}

/// One API operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// `operationId`, or `METHOD /path` when there is none.
    pub id: String,
    pub method: String,
    pub path: String,
}

impl Operation {
    fn mutating(&self) -> bool {
        matches!(self.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
    }

    /// The names a tag may use for this operation.
    fn names(&self) -> [String; 2] {
        [self.id.clone(), format!("{} {}", self.method, self.path)]
    }
}

/// Every operation in an OpenAPI document.
pub fn operations(openapi: &Value) -> Vec<Operation> {
    let mut out = Vec::new();
    let Some(paths) = openapi["paths"].as_object() else {
        return out;
    };
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for (method, op) in item {
            let method = method.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                continue;
            }
            let id = op["operationId"]
                .as_str()
                .map_or_else(|| format!("{method} {path}"), str::to_owned);
            out.push(Operation {
                id,
                method,
                path: path.clone(),
            });
        }
    }
    out
}

/// Operations with no `op` tag, and mutating ones with no `negative` tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpGaps {
    pub total: usize,
    pub mutating: usize,
    pub untested: Vec<String>,
    pub no_negative: Vec<String>,
}

/// Joins the operations with the tests' `op` and `negative` tags.
pub fn op_gaps(ops: &[Operation], tests: &[TestRef]) -> OpGaps {
    let tagged: BTreeSet<&str> = tests
        .iter()
        .flat_map(|t| t.ops.iter().map(String::as_str))
        .collect();
    let negative: BTreeSet<&str> = tests
        .iter()
        .flat_map(|t| t.negative_ops.iter().map(String::as_str))
        .collect();
    let mut gaps = OpGaps {
        total: ops.len(),
        mutating: ops.iter().filter(|op| op.mutating()).count(),
        ..OpGaps::default()
    };
    for op in ops {
        let names = op.names();
        if !names.iter().any(|name| tagged.contains(name.as_str())) {
            gaps.untested.push(op.id.clone());
        }
        if op.mutating() && !names.iter().any(|name| negative.contains(name.as_str())) {
            gaps.no_negative.push(op.id.clone());
        }
    }
    gaps
}

fn test_json(test: &TestRef) -> Value {
    json!({ "file": test.file, "line": test.line, "name": test.name })
}

/// `map.json`'s content.
pub fn map_json(coverage: &[FeatureCoverage], tests: &[TestRef], gaps: &OpGaps) -> Value {
    let mut totals = serde_json::Map::new();
    for tier in Tier::ALL {
        let count = tests.iter().filter(|t| t.tier == tier).count();
        totals.insert(tier.as_str().to_owned(), json!(count));
    }
    let features: Vec<Value> = coverage
        .iter()
        .map(|feature| {
            let mut by_tier = serde_json::Map::new();
            for (tier, list) in &feature.by_tier {
                by_tier.insert(
                    tier.as_str().to_owned(),
                    Value::Array(list.iter().map(test_json).collect()),
                );
            }
            json!({
                "id": feature.id,
                "name": feature.name,
                "gap": feature.is_gap(),
                "by_tier": by_tier,
            })
        })
        .collect();
    json!({
        "format": "attome-coverage-map/v1",
        "tests": tests.len(),
        "untagged_tests": tests.iter().filter(|t| t.features.is_empty()).count(),
        "totals": totals,
        "features": features,
        "feature_gaps": coverage.iter().filter(|f| f.is_gap()).count(),
        "operations": {
            "total": gaps.total,
            "mutating": gaps.mutating,
            "untested": gaps.untested,
            "no_negative": gaps.no_negative,
        },
    })
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `index.html`: one static page, no external resources.
pub fn map_html(coverage: &[FeatureCoverage], tests: &[TestRef], gaps: &OpGaps) -> String {
    let mut rows = String::new();
    for feature in coverage {
        let class = if feature.is_gap() {
            " class=\"gap\""
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr{class}><td>{}</td><td>{}</td>",
            escape(&feature.id),
            escape(&feature.name)
        ));
        for tier in Tier::ALL {
            let count = feature.by_tier.get(&tier).map_or(0, Vec::len);
            rows.push_str(&format!("<td>{count}</td>"));
        }
        rows.push_str("</tr>\n");
    }
    let header: String = Tier::ALL
        .iter()
        .map(|tier| format!("<th>{}</th>", tier.as_str()))
        .collect();
    let list = |items: &[String]| -> String {
        items
            .iter()
            .map(|item| format!("<li><code>{}</code></li>", escape(item)))
            .collect()
    };
    let gaps_count = coverage.iter().filter(|f| f.is_gap()).count();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Test coverage map</title>\n<style>\n\
body {{ font-family: system-ui, sans-serif; margin: 16px; color: #1b1b1b; background: #fff; }}\n\
table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}\n\
th, td {{ border: 1px solid #ccc; padding: 4px 6px; text-align: left; }}\n\
tr.gap td {{ background: #fdecea; }}\n\
@media (prefers-color-scheme: dark) {{ body {{ color: #eee; background: #161616; }} \
th, td {{ border-color: #444; }} tr.gap td {{ background: #4a1f1c; }} }}\n\
.wrap {{ overflow-x: auto; }}\n</style>\n</head>\n<body>\n\
<h1>Test coverage map</h1>\n\
<p>{} tests, {} without a feature tag. {} of {} features have no test.</p>\n\
<div class=\"wrap\"><table>\n<thead><tr><th>Feature</th><th>Name</th>{header}</tr></thead>\n\
<tbody>\n{rows}</tbody>\n</table></div>\n\
<h2>API operations</h2>\n\
<p>{} operations, {} mutating. {} have no <code>// op:</code> test; {} mutating ones have no \
<code>// negative:</code> test.</p>\n\
<details><summary>Untested operations</summary><ul>{}</ul></details>\n\
<details><summary>Mutating operations without a negative test</summary><ul>{}</ul></details>\n\
</body>\n</html>\n",
        tests.len(),
        tests.iter().filter(|t| t.features.is_empty()).count(),
        gaps_count,
        coverage.len(),
        gaps.total,
        gaps.mutating,
        gaps.untested.len(),
        gaps.no_negative.len(),
        list(&gaps.untested),
        list(&gaps.no_negative),
    )
}

/// `attome test map [--scan-only]`: scans, then (unless `scan_only`)
/// writes the map and returns the paths written.
pub fn run(root: &Path, scan_only: bool) -> Result<Vec<PathBuf>, String> {
    let tests = crate::test_scan::scan(root);
    if scan_only {
        for tier in Tier::ALL {
            let count = tests.iter().filter(|t| t.tier == tier).count();
            crate::say(&format!("{:<12} {count}", tier.as_str()));
        }
        crate::say(&format!("{:<12} {}", "total", tests.len()));
        return Ok(Vec::new());
    }
    let feature_text = std::fs::read_to_string(root.join("docs/features.json"))
        .map_err(|error| format!("docs/features.json: {error}"))?;
    let features = features(&feature_text)?;
    let openapi: Value = std::fs::read_to_string(root.join("openapi.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    let coverage = coverage(&features, &tests);
    let gaps = op_gaps(&operations(&openapi), &tests);

    let out = root.join("target").join("coverage-map");
    std::fs::create_dir_all(&out).map_err(|error| format!("{}: {error}", out.display()))?;
    let json_path = out.join("map.json");
    let text = serde_json::to_string_pretty(&map_json(&coverage, &tests, &gaps))
        .map_err(|error| format!("cannot serialise the map: {error}"))?;
    std::fs::write(&json_path, text + "\n")
        .map_err(|error| format!("{}: {error}", json_path.display()))?;
    let html_path = out.join("index.html");
    std::fs::write(&html_path, map_html(&coverage, &tests, &gaps))
        .map_err(|error| format!("{}: {error}", html_path.display()))?;
    Ok(vec![json_path, html_path])
}

/// The repository's test targets (roadmap AC5-T10), checked by
/// `attome test map --check-targets` and the gate's `test_targets` step.
pub const TARGETS_FILE: &str = "docs/test-targets.json";

/// The share of mutating operations a `negative:` test tags, in whole
/// percent rounded down; 100 when there are none.
pub fn negative_pct(map: &Value) -> u64 {
    let mutating = map["operations"]["mutating"].as_u64().unwrap_or(0);
    let missing = map["operations"]["no_negative"]
        .as_array()
        .map_or(0, Vec::len) as u64;
    if mutating == 0 {
        return 100;
    }
    mutating.saturating_sub(missing) * 100 / mutating
}

/// Every target `map` misses, each naming the target, its floor and the
/// measured value; empty when all are met. A target the map cannot measure
/// (an unknown key, or a mutation score with no result) is a miss too, so a
/// typo never passes silently.
pub fn check_targets(map: &Value, targets: &Value) -> Vec<String> {
    let mut misses = Vec::new();
    let Some(targets) = targets.as_object() else {
        return vec!["the targets file is not a JSON object".to_owned()];
    };
    for (key, floor) in targets {
        if key.starts_with('$') || key == "format" {
            continue;
        }
        match key.as_str() {
            "mutating_ops_with_negative_pct" | "browser_journeys_min" => {
                let Some(floor) = floor.as_u64() else {
                    misses.push(format!("{key}: the target is not a whole number"));
                    continue;
                };
                let measured = if key == "browser_journeys_min" {
                    map["totals"]["browser"].as_u64().unwrap_or(0)
                } else {
                    negative_pct(map)
                };
                if measured < floor {
                    misses.push(format!("{key}: {measured} is below the target {floor}"));
                }
            }
            "mutation_score_min" => {
                for (krate, floor) in floor.as_object().into_iter().flatten() {
                    let floor = floor.as_f64().unwrap_or(f64::INFINITY);
                    match map["mutation"][krate.as_str()].as_f64() {
                        Some(score) if score >= floor => {}
                        Some(score) => misses.push(format!(
                            "mutation_score_min.{krate}: {score} is below the target {floor}"
                        )),
                        None => misses.push(format!(
                            "mutation_score_min.{krate}: no mutation score was measured"
                        )),
                    }
                }
            }
            other => misses.push(format!("{other}: not a target the map measures")),
        }
    }
    misses
}

/// `attome test map --check-targets <file>`: writes the map, then checks it
/// against the targets. `Ok` with the misses (empty when every target is met).
pub fn run_check(root: &Path, targets_file: &Path) -> Result<Vec<String>, String> {
    run(root, false)?;
    let map_path = root.join("target").join("coverage-map").join("map.json");
    let map: Value = std::fs::read_to_string(&map_path)
        .map_err(|error| format!("{}: {error}", map_path.display()))
        .and_then(|text| {
            serde_json::from_str(&text).map_err(|error| format!("{}: {error}", map_path.display()))
        })?;
    let targets: Value = std::fs::read_to_string(targets_file)
        .map_err(|error| format!("{}: {error}", targets_file.display()))
        .and_then(|text| {
            serde_json::from_str(&text)
                .map_err(|error| format!("{}: {error}", targets_file.display()))
        })?;
    Ok(check_targets(&map, &targets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_target_fails_check() {
        let map = json!({
            "totals": { "browser": 7 },
            "operations": { "mutating": 10, "no_negative": ["a", "b", "c", "d"] },
        });
        assert_eq!(negative_pct(&map), 60);
        let met = json!({ "mutating_ops_with_negative_pct": 60, "browser_journeys_min": 6 });
        assert!(check_targets(&map, &met).is_empty());

        let missed = json!({
            "mutating_ops_with_negative_pct": 61,
            "browser_journeys_min": 8,
            "mutation_score_min": { "attome-security": 0.5 },
            "mutating_ops_negative": 1,
        });
        let misses = check_targets(&map, &missed);
        assert_eq!(misses.len(), 4, "{misses:?}");
        assert!(
            misses
                .iter()
                .any(|m| m.starts_with("browser_journeys_min: 7")),
            "{misses:?}"
        );
        assert!(misses.iter().any(|m| m.contains("no mutation score")));
        assert!(misses.iter().any(|m| m.contains("not a target")));
        assert!(
            misses
                .iter()
                .any(|m| m.contains("60 is below the target 61"))
        );
    }

    fn tref(name: &str, tier: Tier, features: &[&str], ops: &[&str], negative: &[&str]) -> TestRef {
        let owned = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect();
        TestRef {
            file: "f.rs".to_owned(),
            line: 1,
            name: name.to_owned(),
            tier,
            features: owned(features),
            ops: owned(ops),
            negative_ops: owned(negative),
            regressions: Vec::new(),
        }
    }

    #[test]
    fn feature_ids_parsed_from_headings() {
        let list = features(
            r#"{"features": [{"id": "A1", "name": "Custom entities"}, {"id": "B2", "name": "Views"}]}"#,
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].id, "B2");
        // The checked-in list parses and is not empty.
        let real = features(include_str!("../../../../docs/features.json")).unwrap();
        assert!(real.len() > 100);
    }

    #[test]
    fn feature_without_tests_is_gap() {
        let features = vec![
            Feature {
                id: "A1".to_owned(),
                name: "One".to_owned(),
            },
            Feature {
                id: "A2".to_owned(),
                name: "Two".to_owned(),
            },
        ];
        let tests = vec![tref("t", Tier::Unit, &["A1"], &[], &[])];
        let coverage = coverage(&features, &tests);
        assert!(!coverage[0].is_gap());
        assert!(coverage[1].is_gap());
        let map = map_json(&coverage, &tests, &OpGaps::default());
        assert_eq!(map["feature_gaps"], 1);
        assert!(map_html(&coverage, &tests, &OpGaps::default()).contains("class=\"gap\""));
    }

    fn openapi() -> Value {
        json!({ "paths": {
            "/api/v1/things": {
                "get": { "operationId": "listThings" },
                "post": { "operationId": "createThing" }
            },
            "/api/v1/things/{id}": { "delete": {} }
        }})
    }

    #[test]
    fn mutating_op_without_negative_is_listed() {
        let ops = operations(&openapi());
        let tests = vec![tref(
            "t",
            Tier::Integration,
            &[],
            &["createThing", "DELETE /api/v1/things/{id}"],
            &["createThing"],
        )];
        let gaps = op_gaps(&ops, &tests);
        assert_eq!(gaps.total, 3);
        assert_eq!(gaps.mutating, 2);
        assert_eq!(gaps.untested, ["listThings"]);
        assert_eq!(gaps.no_negative, ["DELETE /api/v1/things/{id}"]);
    }

    #[test]
    fn get_op_needs_no_negative() {
        let ops = operations(&openapi());
        let tests = vec![tref("t", Tier::Integration, &[], &["listThings"], &[])];
        let gaps = op_gaps(&ops, &tests);
        assert!(!gaps.no_negative.contains(&"listThings".to_owned()));
        assert!(!gaps.untested.contains(&"listThings".to_owned()));
    }
}

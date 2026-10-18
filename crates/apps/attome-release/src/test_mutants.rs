//! `attome test mutants` (roadmap AC5-T9): mutation testing of the core
//! engines, scoped by `.cargo/mutants.toml` to the security engine, the rules
//! engine and the record engine's access plan and query execution.
//!
//! It runs `cargo mutants` (never in place: it copies the tree, so the
//! source is never edited) into `target/mutants`, reads
//! `mutants.out/outcomes.json`, and scores each crate as caught over caught
//! plus missed; unviable and timed-out mutants are listed but not counted.
//! A missed mutant that is not in the baseline (`docs/testing/
//! mutants-baseline.json`) fails the command with exit code 2: a test got
//! weaker, or new code arrived untested. `--write-baseline` records the run
//! as the new baseline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where the run writes its results.
const OUTPUT_DIR: &str = "target/mutants";

/// The baseline of accepted missed mutants.
pub const BASELINE: &str = "docs/testing/mutants-baseline.json";

/// One mutant's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub package: String,
    /// A stable name: file, line and what was replaced with what.
    pub name: String,
    pub result: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Caught,
    Missed,
    Unviable,
    Timeout,
}

/// A crate's score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub caught: usize,
    pub missed: usize,
    pub unviable: usize,
    pub timeout: usize,
    /// caught / (caught + missed); 1.0 with nothing to catch.
    pub score: f64,
}

/// The stored baseline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub scores: BTreeMap<String, Score>,
    /// Missed mutants accepted when the baseline was written.
    pub missed: BTreeSet<String>,
}

/// The outcomes in a cargo-mutants `outcomes.json` (the baseline run and
/// anything that is not a mutant are left out).
pub fn parse_outcomes(json: &str) -> Result<Vec<Outcome>, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("outcomes.json does not read: {e}"))?;
    let outcomes = value["outcomes"]
        .as_array()
        .ok_or("outcomes.json has no outcomes list")?;
    let mut out = Vec::new();
    for outcome in outcomes {
        let Some(mutant) = outcome["scenario"].get("Mutant") else {
            continue;
        };
        let result = match outcome["summary"].as_str().unwrap_or_default() {
            "CaughtMutant" => Kind::Caught,
            "MissedMutant" => Kind::Missed,
            "Unviable" => Kind::Unviable,
            "Timeout" => Kind::Timeout,
            _ => continue,
        };
        let file = mutant["file"].as_str().unwrap_or("?").replace('\\', "/");
        let line = mutant["span"]["start"]["line"].as_u64().unwrap_or(0);
        let function = mutant["function"]["function_name"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let replacement = mutant["replacement"].as_str().unwrap_or("");
        let genre = mutant["genre"].as_str().unwrap_or("");
        out.push(Outcome {
            package: mutant["package"].as_str().unwrap_or("?").to_owned(),
            name: format!("{file}:{line}: {genre} in {function} -> {replacement}"),
            result,
        });
    }
    Ok(out)
}

/// The score of each crate.
pub fn scores(outcomes: &[Outcome]) -> BTreeMap<String, Score> {
    let mut by_crate: BTreeMap<String, Score> = BTreeMap::new();
    for outcome in outcomes {
        let score = by_crate.entry(outcome.package.clone()).or_default();
        match outcome.result {
            Kind::Caught => score.caught += 1,
            Kind::Missed => score.missed += 1,
            Kind::Unviable => score.unviable += 1,
            Kind::Timeout => score.timeout += 1,
        }
    }
    for score in by_crate.values_mut() {
        let counted = score.caught + score.missed;
        score.score = if counted == 0 {
            1.0
        } else {
            score.caught as f64 / counted as f64
        };
    }
    by_crate
}

/// Missed mutants the baseline does not accept.
pub fn new_missed<'a>(outcomes: &'a [Outcome], baseline: &Baseline) -> Vec<&'a Outcome> {
    outcomes
        .iter()
        .filter(|o| o.result == Kind::Missed && !baseline.missed.contains(&o.name))
        .collect()
}

fn read_baseline(root: &Path) -> Result<Baseline, String> {
    let path = root.join(BASELINE);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| format!("{} does not read: {e}", path.display())),
        Err(_) => Ok(Baseline::default()),
    }
}

fn outcomes_path(root: &Path) -> PathBuf {
    root.join(OUTPUT_DIR)
        .join("mutants.out")
        .join("outcomes.json")
}

/// `attome test mutants [--write-baseline]`: 0 when no new mutant survives,
/// 2 when one does, 1 when the run itself fails.
pub fn run(root: &Path, write_baseline: bool) -> ExitCode {
    let status = Command::new("cargo")
        .args(["mutants", "--output", OUTPUT_DIR])
        .current_dir(root)
        .status();
    match status {
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "attome test mutants: cannot run cargo mutants (cargo install cargo-mutants --locked): {e}"
            );
            return ExitCode::FAILURE;
        }
    }
    let text = match std::fs::read_to_string(outcomes_path(root)) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("attome test mutants: no outcomes.json: {e}");
            return ExitCode::FAILURE;
        }
    };
    let outcomes = match parse_outcomes(&text) {
        Ok(outcomes) => outcomes,
        Err(e) => {
            eprintln!("attome test mutants: {e}");
            return ExitCode::FAILURE;
        }
    };
    let scores = scores(&outcomes);
    for (package, score) in &scores {
        crate::say(&format!(
            "{package}: {:.1}% ({} caught, {} missed; {} unviable and {} timed out, not counted)",
            score.score * 100.0,
            score.caught,
            score.missed,
            score.unviable,
            score.timeout
        ));
    }
    for outcome in outcomes
        .iter()
        .filter(|o| matches!(o.result, Kind::Unviable | Kind::Timeout))
    {
        crate::say(&format!(
            "  not counted ({:?}): {}",
            outcome.result, outcome.name
        ));
    }
    if write_baseline {
        let baseline = Baseline {
            scores,
            missed: outcomes
                .iter()
                .filter(|o| o.result == Kind::Missed)
                .map(|o| o.name.clone())
                .collect(),
        };
        let path = root.join(BASELINE);
        let written = std::fs::create_dir_all(path.parent().unwrap_or(root))
            .map_err(|e| e.to_string())
            .and_then(|()| serde_json::to_string_pretty(&baseline).map_err(|e| e.to_string()))
            .and_then(|text| std::fs::write(&path, text + "\n").map_err(|e| e.to_string()));
        return match written {
            Ok(()) => {
                crate::say(&format!("wrote {}", path.display()));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("attome test mutants: cannot write the baseline: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let baseline = match read_baseline(root) {
        Ok(baseline) => baseline,
        Err(e) => {
            eprintln!("attome test mutants: {e}");
            return ExitCode::FAILURE;
        }
    };
    let new = new_missed(&outcomes, &baseline);
    if new.is_empty() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "attome test mutants: {} mutant(s) survive that the baseline does not accept:",
            new.len()
        );
        for outcome in new {
            eprintln!("  {}", outcome.name);
        }
        ExitCode::from(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTCOMES: &str = r#"{
      "outcomes": [
        { "scenario": "Baseline", "summary": "Success" },
        { "scenario": { "Mutant": { "package": "attome-rules", "file": "crates\\foundation\\attome-rules\\src\\eval.rs",
            "function": { "function_name": "add" }, "span": { "start": { "line": 10, "column": 5 } },
            "replacement": "0", "genre": "FnValue" } }, "summary": "CaughtMutant" },
        { "scenario": { "Mutant": { "package": "attome-rules", "file": "crates/foundation/attome-rules/src/eval.rs",
            "function": { "function_name": "sub" }, "span": { "start": { "line": 20, "column": 5 } },
            "replacement": "1", "genre": "FnValue" } }, "summary": "MissedMutant" },
        { "scenario": { "Mutant": { "package": "attome-rules", "file": "crates/foundation/attome-rules/src/eval.rs",
            "function": { "function_name": "mul" }, "span": { "start": { "line": 30, "column": 5 } },
            "replacement": "Default::default()", "genre": "FnValue" } }, "summary": "Unviable" },
        { "scenario": { "Mutant": { "package": "attome-rules", "file": "crates/foundation/attome-rules/src/eval.rs",
            "function": { "function_name": "div" }, "span": { "start": { "line": 40, "column": 5 } },
            "replacement": "1", "genre": "FnValue" } }, "summary": "Timeout" }
      ]
    }"#;

    #[test]
    fn score_ignores_unviable() {
        let outcomes = parse_outcomes(OUTCOMES).unwrap_or_default();
        assert_eq!(outcomes.len(), 4, "the baseline run is not a mutant");
        let scores = scores(&outcomes);
        let rules = &scores["attome-rules"];
        assert_eq!(
            (rules.caught, rules.missed, rules.unviable, rules.timeout),
            (1, 1, 1, 1)
        );
        assert!((rules.score - 0.5).abs() < f64::EPSILON, "{}", rules.score);
    }

    #[test]
    fn new_missed_mutant_fails() {
        let outcomes = parse_outcomes(OUTCOMES).unwrap_or_default();
        let missed = "crates/foundation/attome-rules/src/eval.rs:20: FnValue in sub -> 1";
        assert_eq!(new_missed(&outcomes, &Baseline::default()).len(), 1);
        assert_eq!(new_missed(&outcomes, &Baseline::default())[0].name, missed);
        let accepted = Baseline {
            missed: [missed.to_owned()].into_iter().collect(),
            ..Baseline::default()
        };
        assert!(new_missed(&outcomes, &accepted).is_empty());
    }
}

//! Release parity (roadmap AC4-T5): a release is tagged only from a commit
//! whose gate reports from **both** Windows and Linux are present, made from
//! that commit, and green (every step passed or overridden by name).
//!
//! Each machine writes `target/release-gate/gate-<os>.json`; the report made
//! on the other operating system is brought over with
//! `attome release import-report <path>`, which refuses a report from another
//! commit.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The operating systems a release must pass on (V2-D471).
pub const RELEASE_OSES: [&str; 2] = ["windows", "linux"];

/// Why a commit cannot be tagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParityError {
    /// No report from this operating system.
    Missing(String),
    /// The report was made from another commit.
    CommitMismatch {
        os: String,
        report: String,
        head: String,
    },
    /// A step neither passed nor was overridden.
    Red { os: String, steps: Vec<String> },
    /// The report could not be read.
    Unreadable { os: String, error: String },
}

impl std::fmt::Display for ParityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(os) => write!(
                f,
                "no {os} gate report (run the gate on {os}, then import it)"
            ),
            Self::CommitMismatch { os, report, head } => write!(
                f,
                "the {os} gate report is from commit {report}, not {head}"
            ),
            Self::Red { os, steps } => {
                write!(f, "the {os} gate report is red: {}", steps.join(", "))
            }
            Self::Unreadable { os, error } => write!(f, "the {os} gate report: {error}"),
        }
    }
}

/// The path of `os`'s report in `dir`.
pub fn report_path(dir: &Path, os: &str) -> PathBuf {
    dir.join(format!("gate-{os}.json"))
}

/// The commit a report records.
pub fn report_commit(report: &Value) -> Option<&str> {
    report.get("commit").and_then(Value::as_str)
}

/// Steps in a report that neither passed nor were overridden.
fn red_steps(report: &Value) -> Vec<String> {
    report
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter(|step| {
                    !matches!(
                        step.get("status").and_then(Value::as_str),
                        Some("passed" | "overridden")
                    )
                })
                .map(|step| {
                    step.get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("<unnamed>")
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_else(|| vec!["<no steps>".to_owned()])
}

/// Every reason `head` cannot be tagged from the reports in `dir`; empty when
/// it can.
pub fn check(dir: &Path, head: &str) -> Vec<ParityError> {
    let mut problems = Vec::new();
    for os in RELEASE_OSES {
        let path = report_path(dir, os);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => {
                problems.push(ParityError::Missing(os.to_owned()));
                continue;
            }
        };
        let report: Value = match serde_json::from_str(&text) {
            Ok(report) => report,
            Err(error) => {
                problems.push(ParityError::Unreadable {
                    os: os.to_owned(),
                    error: error.to_string(),
                });
                continue;
            }
        };
        match report_commit(&report) {
            Some(commit) if commit == head => {}
            other => problems.push(ParityError::CommitMismatch {
                os: os.to_owned(),
                report: other.unwrap_or("<none>").to_owned(),
                head: head.to_owned(),
            }),
        }
        let red = red_steps(&report);
        if !red.is_empty() {
            problems.push(ParityError::Red {
                os: os.to_owned(),
                steps: red,
            });
        }
    }
    problems
}

/// Copies a report made on another machine into `dir` under its own OS's
/// name, after checking it was made from `head`. Returns where it landed.
pub fn import(dir: &Path, source: &Path, head: &str) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    let report: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not a gate report: {error}", source.display()))?;
    let os = report
        .get("os")
        .and_then(Value::as_str)
        .filter(|os| RELEASE_OSES.contains(os))
        .ok_or_else(|| format!("{} names no release OS", source.display()))?;
    match report_commit(&report) {
        Some(commit) if commit == head => {}
        other => {
            return Err(format!(
                "{} is from commit {}, not {head}",
                source.display(),
                other.unwrap_or("<none>")
            ));
        }
    }
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let target = report_path(dir, os);
    std::fs::write(&target, text)
        .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attome-release-parity-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, os: &str, commit: &str, statuses: &[(&str, &str)]) {
        let steps: Vec<Value> = statuses
            .iter()
            .map(|(id, status)| json!({ "id": id, "status": status }))
            .collect();
        let report = json!({ "os": os, "commit": commit, "steps": steps });
        std::fs::write(report_path(dir, os), report.to_string()).unwrap();
    }

    #[test]
    fn parity_same_commit_both_green_ok() {
        let dir = scratch("ok");
        write(
            &dir,
            "windows",
            "abc",
            &[("format", "passed"), ("tests", "overridden")],
        );
        write(
            &dir,
            "linux",
            "abc",
            &[("format", "passed"), ("tests", "passed")],
        );
        assert!(check(&dir, "abc").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parity_commit_mismatch_errors() {
        let dir = scratch("mismatch");
        write(&dir, "windows", "abc", &[("format", "passed")]);
        write(&dir, "linux", "old", &[("format", "passed")]);
        let problems = check(&dir, "abc");
        assert_eq!(problems.len(), 1);
        assert!(matches!(&problems[0], ParityError::CommitMismatch { os, .. } if os == "linux"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parity_missing_os_errors() {
        let dir = scratch("missing");
        write(&dir, "linux", "abc", &[("format", "passed")]);
        assert_eq!(
            check(&dir, "abc"),
            vec![ParityError::Missing("windows".to_owned())]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_red_step_blocks_the_tag() {
        let dir = scratch("red");
        write(&dir, "windows", "abc", &[("tests", "failed")]);
        write(&dir, "linux", "abc", &[("tests", "passed")]);
        let problems = check(&dir, "abc");
        assert_eq!(
            problems,
            vec![ParityError::Red {
                os: "windows".to_owned(),
                steps: vec!["tests".to_owned()]
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_refuses_another_commit_and_files_by_os() {
        let source_dir = scratch("import-src");
        let dir = scratch("import-dst");
        write(&source_dir, "windows", "abc", &[("format", "passed")]);
        let source = report_path(&source_dir, "windows");
        assert!(import(&dir, &source, "other").is_err());
        let landed = import(&dir, &source, "abc").unwrap();
        assert_eq!(landed, report_path(&dir, "windows"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&source_dir);
    }
}

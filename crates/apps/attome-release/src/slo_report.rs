//! The SLO release report (roadmap AA13-T6): what the load-test matrix
//! measured per SLO class against the catalogue's targets, on which machine.
//!
//! `loadtest/scripts/run-matrix.ps1` writes `matrix-summary-<tag>.json`; each
//! row may carry `classes: {S1: {p50_ms, p95_ms, p99_ms}, ...}`, read from
//! k6's `http_req_duration{slo_class:...}` submetrics. Only single-node rows
//! (`nodes: 1`) count, since the targets are the Solo profile's; when several
//! rows measured a class, the worst value of each percentile is kept.
//!
//! A class with no measurement is `met: null` and printed as "not measured";
//! it is never written as met. A missed class does not fail the gate: it is
//! reported, and the release notes cannot claim it.
//!
//! The report is unsigned until the release signing key exists (AC4-T9):
//! `signature` is `null` and the notes say so.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::slo::{Catalogue, Class};

/// A class's measured percentiles, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Measured {
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

/// One class's verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub id: String,
    pub name: String,
    pub measured: Option<Measured>,
    /// `None` when not measured.
    pub met: Option<bool>,
    /// The percentiles over target, e.g. `["p99"]`.
    pub missed: Vec<&'static str>,
}

fn worse(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// The worst single-node measurement of `class_id` across the matrix rows.
pub fn measured(matrix: &Value, class_id: &str) -> Option<Measured> {
    let rows = matrix.as_array()?;
    let mut found: Option<Measured> = None;
    for row in rows {
        if row.get("nodes").and_then(Value::as_u64) != Some(1) {
            continue;
        }
        let Some(entry) = row.get("classes").and_then(|c| c.get(class_id)) else {
            continue;
        };
        let read = |key: &str| entry.get(key).and_then(Value::as_f64);
        let this = Measured {
            p50_ms: read("p50_ms"),
            p95_ms: read("p95_ms"),
            p99_ms: read("p99_ms"),
        };
        if this.p50_ms.is_none() && this.p95_ms.is_none() && this.p99_ms.is_none() {
            continue;
        }
        found = Some(match found {
            None => this,
            Some(prev) => Measured {
                p50_ms: worse(prev.p50_ms, this.p50_ms),
                p95_ms: worse(prev.p95_ms, this.p95_ms),
                p99_ms: worse(prev.p99_ms, this.p99_ms),
            },
        });
    }
    found
}

/// Judges one class. A target percentile with no matching measurement makes
/// the class not measured rather than met. A class with no latency targets
/// (a gauge or browser class) is not something the load test measures, so it
/// is always "not measured" here.
pub fn verdict(class: &Class, matrix: &Value) -> Verdict {
    let Some(target) = class.solo() else {
        return Verdict {
            id: class.id.clone(),
            name: class.name_en.clone(),
            measured: None,
            met: None,
            missed: Vec::new(),
        };
    };
    let measured = measured(matrix, &class.id);
    let (met, missed) = match measured {
        None => (None, Vec::new()),
        Some(m) => {
            let pairs = [
                ("p50", Some(target.p50_ms), m.p50_ms),
                ("p95", Some(target.p95_ms), m.p95_ms),
                ("p99", target.p99_ms, m.p99_ms),
            ];
            if pairs
                .iter()
                .any(|(_, goal, value)| goal.is_some() && value.is_none())
            {
                (None, Vec::new())
            } else {
                let missed: Vec<&'static str> = pairs
                    .iter()
                    .filter_map(|(name, goal, value)| match (goal, value) {
                        (Some(goal), Some(value)) if value > goal => Some(*name),
                        _ => None,
                    })
                    .collect();
                (Some(missed.is_empty()), missed)
            }
        }
    };
    Verdict {
        id: class.id.clone(),
        name: class.name_en.clone(),
        measured,
        met,
        missed,
    }
}

/// The machine the measurement ran on. Values the platform does not expose
/// cheaply are `null`, never guessed.
pub fn machine() -> Value {
    let cores = std::thread::available_parallelism()
        .ok()
        .map(std::num::NonZeroUsize::get);
    let (cpu, ram_bytes) = if cfg!(target_os = "linux") {
        let cpu = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_owned())
        });
        let ram = std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        });
        (cpu, ram)
    } else {
        (std::env::var("PROCESSOR_IDENTIFIER").ok(), None)
    };
    json!({
        "cpu": cpu,
        "cores": cores,
        "ram_bytes": ram_bytes,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}

fn measured_json(m: Option<Measured>) -> Value {
    m.map_or(
        Value::Null,
        |m| json!({ "p50_ms": m.p50_ms, "p95_ms": m.p95_ms, "p99_ms": m.p99_ms }),
    )
}

/// `slo-report.json`'s content.
pub fn report(
    catalogue: &Catalogue,
    matrix: &Value,
    source: &str,
    commit: Option<&str>,
    generated_at: u64,
    machine: Value,
) -> (Value, Vec<Verdict>) {
    let verdicts: Vec<Verdict> = catalogue
        .classes
        .iter()
        .map(|class| verdict(class, matrix))
        .collect();
    let classes: Vec<Value> = catalogue
        .classes
        .iter()
        .zip(&verdicts)
        .map(|(class, v)| {
            let target = class.solo().map_or(
                Value::Null,
                |t| json!({ "p50_ms": t.p50_ms, "p95_ms": t.p95_ms, "p99_ms": t.p99_ms }),
            );
            json!({
                "id": v.id,
                "name": v.name,
                "target": target,
                "measured": measured_json(v.measured),
                "met": v.met,
                "missed": v.missed,
            })
        })
        .collect();
    let body = json!({
        "format": "attome-slo-report/v1",
        "commit": commit,
        "generated_at_unix": generated_at,
        "catalogue_version": catalogue.version,
        "profile": "solo",
        "source": source,
        "machine": machine,
        "classes": classes,
        "signature": Value::Null,
    });
    (body, verdicts)
}

/// The release-notes fragment: met, missed and not measured classes.
pub fn notes(verdicts: &[Verdict]) -> String {
    let list = |pick: &dyn Fn(&Verdict) -> bool, detail: &dyn Fn(&Verdict) -> String| {
        let items: Vec<String> = verdicts
            .iter()
            .filter(|v| pick(v))
            .map(|v| format!("- {} {}{}", v.id, v.name, detail(v)))
            .collect();
        if items.is_empty() {
            "- none\n".to_owned()
        } else {
            items.join("\n") + "\n"
        }
    };
    format!(
        "## Service-level objectives\n\n\
         Measured on one node against the Solo targets in `observability/slo-catalogue.json`.\n\
         This report is not signed yet (the release signing key, AC4-T9, does not exist).\n\n\
         ### Met\n\n{}\n### Missed\n\n{}\n### Not measured\n\n{}",
        list(&|v| v.met == Some(true), &|_| String::new()),
        list(&|v| v.met == Some(false), &|v| format!(
            " (over target: {})",
            v.missed.join(", ")
        )),
        list(&|v| v.met.is_none(), &|_| String::new()),
    )
}

/// `attome slo report <matrix-summary.json>`: writes `slo-report.json` and
/// `slo.md` into `out`, returning their paths.
pub fn write(
    root: &Path,
    matrix_path: &Path,
    out: &Path,
    commit: Option<&str>,
    generated_at: u64,
) -> Result<Vec<PathBuf>, String> {
    let catalogue_text = std::fs::read_to_string(root.join("observability/slo-catalogue.json"))
        .map_err(|error| format!("observability/slo-catalogue.json: {error}"))?;
    let catalogue = crate::slo::parse(&catalogue_text)?;
    let matrix_text = std::fs::read_to_string(matrix_path)
        .map_err(|error| format!("{}: {error}", matrix_path.display()))?;
    // PowerShell's Set-Content -Encoding utf8 writes a byte-order mark.
    let matrix: Value = serde_json::from_str(matrix_text.trim_start_matches('\u{feff}'))
        .map_err(|error| format!("{} is not JSON: {error}", matrix_path.display()))?;
    let (body, verdicts) = report(
        &catalogue,
        &matrix,
        &matrix_path.display().to_string(),
        commit,
        generated_at,
        machine(),
    );
    std::fs::create_dir_all(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let report_path = out.join("slo-report.json");
    let text = serde_json::to_string_pretty(&body)
        .map_err(|error| format!("cannot serialise the SLO report: {error}"))?;
    std::fs::write(&report_path, text + "\n")
        .map_err(|error| format!("{}: {error}", report_path.display()))?;
    let notes_path = out.join("slo.md");
    std::fs::write(&notes_path, notes(&verdicts))
        .map_err(|error| format!("{}: {error}", notes_path.display()))?;
    Ok(vec![report_path, notes_path])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> Catalogue {
        crate::slo::parse(include_str!("../../../../observability/slo-catalogue.json")).unwrap()
    }

    fn class<'a>(catalogue: &'a Catalogue, id: &str) -> &'a Class {
        catalogue.classes.iter().find(|c| c.id == id).unwrap()
    }

    /// S4 targets: p50 15, p95 40, p99 100.
    fn matrix() -> Value {
        json!([
            { "scenario": "crud_read", "nodes": 1,
              "classes": { "S4": { "p50_ms": 12.0, "p95_ms": 30.0, "p99_ms": 90.0 } } },
            { "scenario": "crud_read", "nodes": 4,
              "classes": { "S4": { "p50_ms": 99.0, "p95_ms": 999.0, "p99_ms": 9999.0 } } },
            { "scenario": "mutating_write", "nodes": 1,
              "classes": { "S6": { "p50_ms": 20.0, "p95_ms": 90.0, "p99_ms": 250.0 } } },
            { "scenario": "list_query", "nodes": 1,
              "classes": { "S5": { "p50_ms": 20.0, "p95_ms": null, "p99_ms": 100.0 } } }
        ])
    }

    #[test]
    fn missing_class_is_not_met() {
        let catalogue = catalogue();
        let v = verdict(class(&catalogue, "S1"), &matrix());
        assert_eq!(v.met, None);
        assert!(notes(&[v]).contains("### Not measured\n\n- S1 "));
        // A measured class missing a targeted percentile is not measured either.
        assert_eq!(verdict(class(&catalogue, "S5"), &matrix()).met, None);
    }

    #[test]
    fn p99_over_target_is_missed() {
        let catalogue = catalogue();
        let s6 = verdict(class(&catalogue, "S6"), &matrix());
        assert_eq!(s6.met, Some(false));
        assert_eq!(s6.missed, vec!["p99"]);
        // Only single-node rows count: S4's N=4 row does not make it miss.
        let s4 = verdict(class(&catalogue, "S4"), &matrix());
        assert_eq!(s4.met, Some(true));
        let (body, _) = report(&catalogue, &matrix(), "m.json", Some("abc"), 1, json!({}));
        assert_eq!(body["signature"], Value::Null);
        assert_eq!(
            body["classes"].as_array().unwrap().len(),
            catalogue.classes.len()
        );
    }
}

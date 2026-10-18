//! `attome perf record|compare` (roadmap AA14-T5): a release's performance
//! next to the previous release's, on the same hardware.
//!
//! **Record.** `attome perf record --release <v> [<matrix-summary.json>...]`
//! writes `docs/perf-history/<v>.json` (format `attome-perf/v1`): the release,
//! the commit, the machine (`slo_report::machine`, the hardware fingerprint),
//! each SLO class's p95 from every load-test matrix given (one value per run;
//! the default is `loadtest/results/matrix-summary-release.json`), and every
//! criterion benchmark's mean under `target/criterion` (`*/new/estimates.json`).
//!
//! **Compare.** `attome perf compare [--base <v>] [--current <v>]` compares
//! two records (by default the newest and the newest earlier one with the
//! same fingerprint). A class regresses when the median of its p95 runs grew
//! by more than its threshold: the catalogue class's
//! `regression_threshold_pct`, 10 when unset. Benchmarks are reported, never
//! failed on: a micro-benchmark's noise is larger than a request's. Records
//! from different machines are never compared (exit 2).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The record format tag.
pub const FORMAT: &str = "attome-perf/v1";

/// The p95 growth that fails a class when the catalogue sets none.
pub const DEFAULT_THRESHOLD_PCT: f64 = 10.0;

/// Where records live, from the workspace root.
pub const HISTORY_DIR: &str = "docs/perf-history";

/// The machine a record was made on. Two records compare only when these
/// are equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub cpu: Option<String>,
    pub cores: Option<u64>,
    pub ram_bytes: Option<u64>,
    pub os: String,
    pub arch: String,
}

impl Fingerprint {
    /// From `slo_report::machine()`'s JSON.
    pub fn from_machine(machine: &Value) -> Self {
        Self {
            cpu: machine["cpu"].as_str().map(|s| s.trim().to_owned()),
            cores: machine["cores"].as_u64(),
            ram_bytes: machine["ram_bytes"].as_u64(),
            os: machine["os"].as_str().unwrap_or_default().to_owned(),
            arch: machine["arch"].as_str().unwrap_or_default().to_owned(),
        }
    }
}

/// One release's performance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfRecord {
    pub format: String,
    pub release: String,
    pub commit: Option<String>,
    /// Unix seconds.
    pub recorded_at: u64,
    pub machine: Fingerprint,
    /// Per SLO class, its p95 in milliseconds from each run.
    pub classes: BTreeMap<String, Vec<f64>>,
    /// Per criterion benchmark id, its mean in nanoseconds.
    pub benchmarks: BTreeMap<String, f64>,
}

/// The median of `values` (`None` when empty).
pub fn median(values: &[f64]) -> Option<f64> {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    Some(if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    })
}

/// One class's change.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassChange {
    pub class: String,
    pub base_p95_ms: f64,
    pub current_p95_ms: f64,
    pub change_pct: f64,
    pub threshold_pct: f64,
    pub regressed: bool,
}

/// What a comparison found.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    pub classes: Vec<ClassChange>,
    /// Classes measured in only one of the two records.
    pub unmatched: Vec<String>,
    /// Benchmark id, base mean, current mean (ns), change %.
    pub benchmarks: Vec<(String, f64, f64, f64)>,
}

impl Comparison {
    pub fn regressions(&self) -> Vec<&ClassChange> {
        self.classes.iter().filter(|c| c.regressed).collect()
    }
}

fn pct(base: f64, current: f64) -> f64 {
    if base > 0.0 {
        (current - base) / base * 100.0
    } else {
        0.0
    }
}

/// Compares `current` with `base`; `threshold(class)` is that class's
/// allowed p95 growth in percent. `Err` when the machines differ.
pub fn compare(
    base: &PerfRecord,
    current: &PerfRecord,
    threshold: impl Fn(&str) -> f64,
) -> Result<Comparison, String> {
    if base.machine != current.machine {
        return Err(format!(
            "{} and {} were measured on different machines; compare records from the same hardware",
            base.release, current.release
        ));
    }
    let mut classes = Vec::new();
    let mut unmatched = Vec::new();
    for (class, runs) in &current.classes {
        match (
            base.classes.get(class).and_then(|r| median(r)),
            median(runs),
        ) {
            (Some(was), Some(now)) => {
                let change_pct = pct(was, now);
                let threshold_pct = threshold(class);
                classes.push(ClassChange {
                    class: class.clone(),
                    base_p95_ms: was,
                    current_p95_ms: now,
                    change_pct,
                    threshold_pct,
                    regressed: change_pct > threshold_pct,
                });
            }
            _ => unmatched.push(class.clone()),
        }
    }
    for class in base.classes.keys() {
        if !current.classes.contains_key(class) {
            unmatched.push(class.clone());
        }
    }
    let benchmarks = current
        .benchmarks
        .iter()
        .filter_map(|(id, now)| {
            let was = *base.benchmarks.get(id)?;
            Some((id.clone(), was, *now, pct(was, *now)))
        })
        .collect();
    Ok(Comparison {
        classes,
        unmatched,
        benchmarks,
    })
}

/// The catalogue's per-class thresholds (`regression_threshold_pct`).
pub fn thresholds(catalogue: &Value) -> BTreeMap<String, f64> {
    catalogue["classes"]
        .as_array()
        .map(|classes| {
            classes
                .iter()
                .filter_map(|c| {
                    Some((
                        c["id"].as_str()?.to_owned(),
                        c["regression_threshold_pct"].as_f64()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Each class's p95 from one matrix summary (`slo_report::measured`).
pub fn p95s(matrix: &Value) -> BTreeMap<String, f64> {
    let mut ids: Vec<String> = matrix
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("classes")?.as_object())
        .flat_map(|classes| classes.keys().cloned())
        .collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .filter_map(|id| {
            let p95 = crate::slo_report::measured(matrix, &id)?.p95_ms?;
            Some((id, p95))
        })
        .collect()
}

/// Every `*/new/estimates.json` under `criterion_dir`: the benchmark id (its
/// directory path, `/`-separated) and its mean in nanoseconds.
pub fn criterion_means(criterion_dir: &Path) -> BTreeMap<String, f64> {
    let mut found = BTreeMap::new();
    let mut stack = vec![criterion_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path.file_name().is_some_and(|n| n == "new") {
                let estimates = path.join("estimates.json");
                let mean = std::fs::read_to_string(&estimates)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .and_then(|v| v["mean"]["point_estimate"].as_f64());
                if let (Some(mean), Some(bench)) = (mean, path.parent()) {
                    let id = bench
                        .strip_prefix(criterion_dir)
                        .unwrap_or(bench)
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/");
                    found.insert(id, mean);
                }
            } else if path
                .file_name()
                .is_some_and(|n| n != "report" && n != "base")
            {
                stack.push(path);
            }
        }
    }
    found
}

/// A version is a release name: letters, digits, `.`, `-` and `_` only, so
/// it is a safe file name.
fn valid_release(release: &str) -> bool {
    !release.is_empty()
        && release.len() <= 64
        && release
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn read_record(path: &Path) -> Result<PerfRecord, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let record: PerfRecord =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if record.format != FORMAT {
        return Err(format!("{} is not an {FORMAT} record", path.display()));
    }
    Ok(record)
}

/// Every record in the history, oldest first.
pub fn history(root: &Path) -> Result<Vec<PerfRecord>, String> {
    let dir = root.join(HISTORY_DIR);
    let mut records = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(records);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            records.push(read_record(&path)?);
        }
    }
    records.sort_by_key(|r| r.recorded_at);
    Ok(records)
}

/// The pair to compare: `current` (default the newest record) and `base`
/// (default the newest earlier record on the same machine).
pub fn pick<'a>(
    records: &'a [PerfRecord],
    base: Option<&str>,
    current: Option<&str>,
) -> Result<(&'a PerfRecord, &'a PerfRecord), String> {
    let current = match current {
        Some(name) => records
            .iter()
            .find(|r| r.release == name)
            .ok_or_else(|| format!("no perf record for {name}"))?,
        None => records
            .last()
            .ok_or("no perf records yet; run `attome perf record --release <v>`")?,
    };
    let base = match base {
        Some(name) => records
            .iter()
            .find(|r| r.release == name)
            .ok_or_else(|| format!("no perf record for {name}"))?,
        None => records
            .iter()
            .rev()
            .find(|r| {
                r.release != current.release
                    && r.recorded_at <= current.recorded_at
                    && r.machine == current.machine
            })
            .ok_or_else(|| {
                format!(
                    "no earlier perf record on the same machine as {}",
                    current.release
                )
            })?,
    };
    Ok((base, current))
}

/// `attome perf record`: writes the record and returns its path.
pub fn record(
    root: &Path,
    release: &str,
    matrices: &[PathBuf],
    commit: Option<String>,
    now: u64,
) -> Result<PathBuf, String> {
    if !valid_release(release) {
        return Err(format!("{release:?} is not a release name"));
    }
    let defaults = [root.join("loadtest/results/matrix-summary-release.json")];
    let matrices = if matrices.is_empty() {
        &defaults[..]
    } else {
        matrices
    };
    let mut classes: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for path in matrices {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let matrix: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for (class, p95) in p95s(&matrix) {
            classes.entry(class).or_default().push(p95);
        }
    }
    let record = PerfRecord {
        format: FORMAT.into(),
        release: release.into(),
        commit,
        recorded_at: now,
        machine: Fingerprint::from_machine(&crate::slo_report::machine()),
        classes,
        benchmarks: criterion_means(&root.join("target/criterion")),
    };
    let dir = root.join(HISTORY_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{release}.json"));
    let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(&path, text + "\n").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// The comparison as text, one line per class and benchmark.
pub fn render(base: &PerfRecord, current: &PerfRecord, comparison: &Comparison) -> String {
    let mut out = format!("perf: {} against {}\n", current.release, base.release);
    for c in &comparison.classes {
        out.push_str(&format!(
            "  {:<6} p95 {:>9.1} ms -> {:>9.1} ms  {:>+7.1}%  (limit +{:.0}%){}\n",
            c.class,
            c.base_p95_ms,
            c.current_p95_ms,
            c.change_pct,
            c.threshold_pct,
            if c.regressed { "  REGRESSED" } else { "" }
        ));
    }
    for class in &comparison.unmatched {
        out.push_str(&format!("  {class:<6} measured in only one of the two\n"));
    }
    for (id, was, now, change) in &comparison.benchmarks {
        out.push_str(&format!(
            "  bench {id}: {was:.0} ns -> {now:.0} ns  {change:+.1}%\n"
        ));
    }
    out
}

/// `attome perf compare`: prints the comparison; true when no class
/// regressed, `Err` when there is nothing comparable.
pub fn compare_cmd(root: &Path, base: Option<&str>, current: Option<&str>) -> Result<bool, String> {
    let records = history(root)?;
    let (base, current) = pick(&records, base, current)?;
    let catalogue_path = root.join("observability/slo-catalogue.json");
    let catalogue: Value = std::fs::read_to_string(&catalogue_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let limits = thresholds(&catalogue);
    let comparison = compare(base, current, |class| {
        limits.get(class).copied().unwrap_or(DEFAULT_THRESHOLD_PCT)
    })?;
    crate::say(render(base, current, &comparison).trim_end());
    Ok(comparison.regressions().is_empty())
}

/// The gate step `perf_compare`: the newest record against the previous one
/// on the same machine.
pub fn step(root: &Path) -> Result<(), String> {
    if compare_cmd(root, None, None)? {
        Ok(())
    } else {
        Err("a class's p95 grew past its threshold; see the comparison above".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PerfRecord {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/perf")
            .join(name);
        read_record(&path).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn the_median_of_runs_is_compared() {
        assert_eq!(median(&[30.0, 10.0, 20.0]), Some(20.0));
        assert_eq!(median(&[10.0, 20.0]), Some(15.0));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn a_p95_past_its_threshold_regresses() {
        let base = fixture("0.1.0.json");
        let current = fixture("0.2.0.json");
        let comparison = compare(
            &base,
            &current,
            |class| if class == "S2" { 30.0 } else { 10.0 },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let s1 = comparison
            .classes
            .iter()
            .find(|c| c.class == "S1")
            .unwrap_or_else(|| panic!("S1"));
        // Median 20 -> 23: +15%, over the default 10%.
        assert!((s1.change_pct - 15.0).abs() < 1e-9);
        assert!(s1.regressed);
        // S2 grew 20%, under its own 30%.
        let s2 = comparison
            .classes
            .iter()
            .find(|c| c.class == "S2")
            .unwrap_or_else(|| panic!("S2"));
        assert!(!s2.regressed);
        assert_eq!(comparison.regressions().len(), 1);
        assert_eq!(comparison.unmatched, vec!["S9".to_owned()]);
        assert_eq!(comparison.benchmarks.len(), 1);
        assert!(render(&base, &current, &comparison).contains("REGRESSED"));
    }

    #[test]
    fn different_machines_are_not_compared() {
        let base = fixture("0.1.0.json");
        let mut current = fixture("0.2.0.json");
        current.machine.cores = Some(64);
        assert!(compare(&base, &current, |_| 10.0).is_err());
    }

    #[test]
    fn the_base_is_the_newest_earlier_record_on_the_same_machine() {
        let older = fixture("0.1.0.json");
        let current = fixture("0.2.0.json");
        let mut elsewhere = fixture("0.1.0.json");
        elsewhere.release = "0.1.5".into();
        elsewhere.recorded_at = older.recorded_at + 10;
        elsewhere.machine.cpu = Some("another".into());
        let records = vec![older, elsewhere, current];
        let (base, now) = pick(&records, None, None).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(base.release, "0.1.0");
        assert_eq!(now.release, "0.2.0");
        assert!(pick(&records[..1], None, None).is_err(), "nothing earlier");
    }

    #[test]
    fn p95s_come_from_single_node_rows() {
        let matrix = serde_json::json!([
            { "nodes": 1, "classes": { "S1": { "p50_ms": 5, "p95_ms": 20, "p99_ms": 40 } } },
            { "nodes": 4, "classes": { "S1": { "p95_ms": 90 } } }
        ]);
        assert_eq!(p95s(&matrix).get("S1"), Some(&20.0));
        assert!(!valid_release("../x"));
        assert!(valid_release("0.2.0-rc.1"));
    }

    #[test]
    fn thresholds_read_from_the_catalogue() {
        let catalogue = serde_json::json!({ "classes": [
            { "id": "S1" }, { "id": "S2", "regression_threshold_pct": 25 }
        ]});
        let limits = thresholds(&catalogue);
        assert_eq!(limits.get("S2"), Some(&25.0));
        assert!(!limits.contains_key("S1"));
    }
}

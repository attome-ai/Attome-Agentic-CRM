//! M17-T4: an extension's dependencies are checked against the RustSec
//! advisory database before `attome dev` uploads a build, and a
//! high-severity advisory refuses the upload.
//!
//! - The check is `cargo audit --json` over the extension's `Cargo.lock`
//!   (cargo-audit reads the RustSec database, the source the workspace's own
//!   `cargo deny check advisories` uses). Its report is read by
//!   [`findings`]; each advisory's CVSS v3 vector is scored by
//!   [`cvss3_base_score`].
//! - [`blocking`]: an advisory scoring 7.0 or more (high or critical), or
//!   with no score at all (unknown counts as high), refuses the build unless
//!   `--allow-advisory <ID>=<reason>` names it with a reason of at least 20
//!   characters. Informational notices (unmaintained, unsound) and lower
//!   scores are printed, never blocking.
//! - Without cargo-audit installed the check cannot run, and the build is
//!   refused unless `--skip-audit <reason>` says why (at least 20
//!   characters); the reason is printed with every upload.
//!
//! JavaScript extensions (Javy, Y10-T7) are not built yet, so npm's audit
//! data is not read here.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

/// The lowest CVSS v3 base score that blocks a build.
pub const BLOCKING_SCORE: f64 = 7.0;
/// The shortest reason an override takes.
pub const MIN_REASON: usize = 20;

/// One advisory against one locked package.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: String,
    pub package: String,
    pub version: String,
    pub title: String,
    /// The CVSS v3 base score, when the advisory has a vector.
    pub score: Option<f64>,
}

impl Finding {
    /// Whether it blocks a build when nothing allows it.
    pub fn is_high(&self) -> bool {
        self.score.is_none_or(|score| score >= BLOCKING_SCORE)
    }

    /// One line for the console.
    pub fn line(&self) -> String {
        let score = self
            .score
            .map_or_else(|| "no score".to_owned(), |s| format!("CVSS {s:.1}"));
        format!(
            "{} in {} {} ({score}): {}",
            self.id, self.package, self.version, self.title
        )
    }
}

/// The vulnerabilities in a `cargo audit --json` report. Pure.
pub fn findings(report: &Value) -> Vec<Finding> {
    report["vulnerabilities"]["list"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| {
            let advisory = &item["advisory"];
            Finding {
                id: advisory["id"].as_str().unwrap_or("unknown").to_owned(),
                package: item["package"]["name"]
                    .as_str()
                    .or_else(|| advisory["package"].as_str())
                    .unwrap_or("unknown")
                    .to_owned(),
                version: item["package"]["version"].as_str().unwrap_or("").to_owned(),
                title: advisory["title"].as_str().unwrap_or("").to_owned(),
                score: advisory["cvss"].as_str().and_then(cvss3_base_score),
            }
        })
        .collect()
}

/// `ID=reason` overrides, each reason at least [`MIN_REASON`] characters.
/// Pure.
pub fn parse_allowed(pairs: &[String]) -> Result<BTreeMap<String, String>, String> {
    pairs
        .iter()
        .map(|pair| {
            let (id, reason) = pair
                .split_once('=')
                .ok_or_else(|| format!("`{pair}` is not <advisory id>=<reason>"))?;
            let (id, reason) = (id.trim(), reason.trim());
            if id.is_empty() || reason.chars().count() < MIN_REASON {
                return Err(format!(
                    "`{pair}`: an advisory id and a reason of at least {MIN_REASON} characters"
                ));
            }
            Ok((id.to_owned(), reason.to_owned()))
        })
        .collect()
}

/// The findings that refuse the build: high (or unscored) and not allowed.
/// Pure.
pub fn blocking<'a>(
    findings: &'a [Finding],
    allowed: &BTreeMap<String, String>,
) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.is_high() && !allowed.contains_key(&f.id))
        .collect()
}

/// The CVSS v3.0/v3.1 base score of a vector such as
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8), or `None` when it
/// is not a complete v3 vector. Pure.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    let version = parts.next()?;
    if version != "CVSS:3.0" && version != "CVSS:3.1" {
        return None;
    }
    let metrics: BTreeMap<&str, &str> = parts.filter_map(|p| p.split_once(':')).collect();
    let get = |k: &str| metrics.get(k).copied();
    let changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| match get(k)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(round_up(raw))
}

/// CVSS v3.1's round-up to one decimal. Pure.
fn round_up(value: f64) -> f64 {
    let int = (value * 100_000.0).round() as i64;
    if int % 10_000 == 0 {
        int as f64 / 100_000.0
    } else {
        ((int / 10_000) + 1) as f64 / 10.0
    }
}

/// How a build's check ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Nothing blocks; the findings are printed.
    Pass(Vec<Finding>),
    /// These block the upload.
    Refused(Vec<Finding>),
}

/// Runs `cargo audit --json` in the extension's folder. `Err` when it
/// could not run (not installed, no `Cargo.lock`) or its report does not
/// read.
pub fn audit(folder: &Path) -> Result<Vec<Finding>, String> {
    if !folder.join("Cargo.lock").is_file() {
        return Err("no Cargo.lock: build once so cargo writes it".to_owned());
    }
    let output = std::process::Command::new("cargo")
        .args(["audit", "--json", "--file", "Cargo.lock"])
        .current_dir(folder)
        .output()
        .map_err(|e| format!("cargo did not start: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(if stderr.contains("no such command") {
            "cargo-audit is not installed (`cargo install cargo-audit`)".to_owned()
        } else {
            format!("cargo audit gave no report: {}", stderr.trim())
        });
    }
    let report: Value =
        serde_json::from_str(&stdout).map_err(|e| format!("cargo audit's report: {e}"))?;
    Ok(findings(&report))
}

/// The check before an upload: audited and judged, or skipped with a
/// reason. `Err` when it neither ran nor was skipped.
pub fn check(
    folder: &Path,
    allowed: &BTreeMap<String, String>,
    skip_reason: Option<&str>,
) -> Result<Verdict, String> {
    match audit(folder) {
        Ok(all) => {
            let refused: Vec<Finding> = blocking(&all, allowed).into_iter().cloned().collect();
            Ok(if refused.is_empty() {
                Verdict::Pass(all)
            } else {
                Verdict::Refused(refused)
            })
        }
        Err(error) => match skip_reason {
            Some(reason) if reason.trim().chars().count() >= MIN_REASON => {
                Ok(Verdict::Pass(Vec::new()))
            }
            _ => Err(format!(
                "the dependency check did not run: {error}; or pass --skip-audit <reason of at least {MIN_REASON} characters>"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;
    use serde_json::json;

    /// The shape of a `cargo audit --json` report with one critical, one
    /// medium and one unscored advisory.
    fn fixture() -> Value {
        json!({
            "database": { "advisory-count": 900 },
            "lockfile": { "dependency-count": 42 },
            "vulnerabilities": {
                "found": true,
                "count": 3,
                "list": [
                    {
                        "advisory": { "id": "RUSTSEC-2099-0001", "package": "hyperbad",
                            "title": "Remote code execution in request parsing",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
                        "package": { "name": "hyperbad", "version": "0.9.1" }
                    },
                    {
                        "advisory": { "id": "RUSTSEC-2099-0002", "package": "slowparse",
                            "title": "Unbounded recursion on deep input",
                            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" },
                        "package": { "name": "slowparse", "version": "1.2.0" }
                    },
                    {
                        "advisory": { "id": "RUSTSEC-2099-0003", "package": "oldcrypt",
                            "title": "Weak key derivation", "cvss": null },
                        "package": { "name": "oldcrypt", "version": "0.1.0" }
                    }
                ]
            },
            "warnings": {}
        })
    }

    #[test]
    fn extension_scan_scores_cvss_vectors() {
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
            Some(5.3)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Some(6.1)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
        assert_eq!(cvss3_base_score("CVSS:2.0/AV:N"), None);
        assert_eq!(cvss3_base_score("CVSS:3.1/AV:N/AC:L"), None);
    }

    #[test]
    fn extension_scan_refuses_high_and_unscored_advisories() {
        let found = findings(&fixture());
        assert_eq!(found.len(), 3);
        let refused: Vec<&str> = blocking(&found, &BTreeMap::new())
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(refused, ["RUSTSEC-2099-0001", "RUSTSEC-2099-0003"]);
        assert!(found[1].line().contains("CVSS 5.3"));
    }

    #[test]
    fn extension_scan_takes_overrides_only_with_a_reason() {
        let allowed = parse_allowed(&[
            "RUSTSEC-2099-0001=not reachable: we never parse untrusted requests".to_owned(),
        ])
        .unwrap();
        let found = findings(&fixture());
        let refused: Vec<&str> = blocking(&found, &allowed)
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(refused, ["RUSTSEC-2099-0003"]);
        assert!(parse_allowed(&["RUSTSEC-2099-0001=too short".to_owned()]).is_err());
        assert!(parse_allowed(&["no equals sign".to_owned()]).is_err());
    }

    #[test]
    fn extension_scan_without_a_lockfile_needs_a_skip_reason() {
        let dir = std::env::temp_dir().join(format!("attome-scan-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(check(&dir, &BTreeMap::new(), None).is_err());
        assert!(check(&dir, &BTreeMap::new(), Some("short")).is_err());
        assert_eq!(
            check(
                &dir,
                &BTreeMap::new(),
                Some("offline laptop, checked by CI on push")
            ),
            Ok(Verdict::Pass(Vec::new()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

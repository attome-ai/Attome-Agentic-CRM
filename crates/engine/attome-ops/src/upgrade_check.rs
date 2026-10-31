//! AB8-T2: what `attome upgrade check` judges, as pure functions over what
//! it read: the version path, the free disk against the largest table, the
//! last proven backup, and the manifest's deprecated features.
//!
//! The report is stable JSON (`--json`): one finding per check, each `pass`,
//! `warn` or `fail`. Any `fail` refuses the upgrade.

use serde::Serialize;

use crate::freshness::Freshness;
use crate::release_manifest::ReleaseManifest;

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub check: String,
    pub verdict: Verdict,
    pub detail: String,
}

impl Finding {
    pub fn new(check: &str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_owned(),
            verdict,
            detail: detail.into(),
        }
    }
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub from_version: String,
    pub to_version: String,
    pub requires_pause: bool,
    pub pause_estimate_seconds: Option<u32>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether nothing refuses the upgrade.
    pub fn passes(&self) -> bool {
        self.findings.iter().all(|f| f.verdict != Verdict::Fail)
    }
}

fn parts(version: &str) -> Option<Vec<u64>> {
    version
        .split(['-', '+'])
        .next()?
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// Whether `current` may upgrade to the manifest's release.
pub fn version_path(current: &str, manifest: &ReleaseManifest) -> Finding {
    let check = "version_path";
    match (parts(current), parts(&manifest.min_from_version)) {
        (Some(from), Some(min)) if from >= min => Finding::new(
            check,
            Verdict::Pass,
            format!("{current} may upgrade to {}", manifest.version),
        ),
        (Some(_), Some(_)) => Finding::new(
            check,
            Verdict::Fail,
            format!(
                "{current} is older than {}, the oldest version {} upgrades from",
                manifest.min_from_version, manifest.version
            ),
        ),
        _ => Finding::new(
            check,
            Verdict::Fail,
            format!(
                "cannot compare {current} with {}",
                manifest.min_from_version
            ),
        ),
    }
}

/// Free disk must be at least twice the largest table; the free space is
/// `None` when this machine cannot see the database volume.
pub fn disk(free_bytes: Option<u64>, largest_table_bytes: u64) -> Finding {
    let check = "disk";
    let needed = largest_table_bytes.saturating_mul(2);
    match free_bytes {
        None => Finding::new(
            check,
            Verdict::Warn,
            format!("pass --free-bytes for the database volume; {needed} bytes are needed"),
        ),
        Some(free) if free >= needed => Finding::new(
            check,
            Verdict::Pass,
            format!("{free} bytes free, {needed} needed"),
        ),
        Some(free) => Finding::new(
            check,
            Verdict::Fail,
            format!("{free} bytes free, {needed} needed (twice the largest table)"),
        ),
    }
}

/// The restore drill's evidence stands for the backup: a backup is proven by
/// restoring it, and v2 deploys no pgBackRest to ask.
pub fn backup(restore: &Freshness) -> Finding {
    let check = "backup_freshness";
    if restore.status == "fresh" {
        return Finding::new(
            check,
            Verdict::Pass,
            format!("restore proven within {} days", restore.period_days),
        );
    }
    Finding::new(
        check,
        Verdict::Fail,
        format!(
            "the last restore drill is {}; run `attome drill restore` first",
            restore.status
        ),
    )
}

/// One deprecated feature's finding: `in_use` is `None` when this binary has
/// no check of that name.
pub fn deprecated(feature: &str, removed_in: &str, in_use: Option<bool>) -> Finding {
    let check = "deprecated";
    match in_use {
        Some(false) => Finding::new(check, Verdict::Pass, format!("{feature} is not in use")),
        Some(true) => Finding::new(
            check,
            Verdict::Fail,
            format!("{feature} is in use and is removed in {removed_in}"),
        ),
        None => Finding::new(
            check,
            Verdict::Warn,
            format!("{feature} (removed in {removed_in}) has no check here; look by hand"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ReleaseManifest {
        serde_json::from_value(serde_json::json!({
            "schema": "attome-release-manifest/v1",
            "version": "2.0.0",
            "min_from_version": "1.4.0",
            "max_skip_minor": 2,
            "requires_pause": true,
            "pause_estimate_seconds": 30,
            "deprecated": [],
            "contract_sql": [],
            "artifacts": [],
            "impact": []
        }))
        .expect("a manifest")
    }

    fn restore(status: &str) -> Freshness {
        Freshness {
            kind: "restore".to_owned(),
            status: status.to_owned(),
            last_run_at: None,
            last_ok_run_at: None,
            period_days: 31,
            failing_checks: Vec::new(),
        }
    }

    #[test]
    fn older_than_min_from_version_fails() {
        assert_eq!(version_path("1.3.9", &manifest()).verdict, Verdict::Fail);
        assert_eq!(version_path("1.4.0", &manifest()).verdict, Verdict::Pass);
        assert_eq!(version_path("1.10.0", &manifest()).verdict, Verdict::Pass);
        assert_eq!(version_path("one", &manifest()).verdict, Verdict::Fail);
    }

    #[test]
    fn stale_backup_fails() {
        assert_eq!(backup(&restore("fresh")).verdict, Verdict::Pass);
        for status in ["stale", "failed", "never"] {
            assert_eq!(backup(&restore(status)).verdict, Verdict::Fail);
        }
    }

    #[test]
    fn disk_needs_twice_the_largest_table() {
        assert_eq!(disk(Some(200), 100).verdict, Verdict::Pass);
        assert_eq!(disk(Some(199), 100).verdict, Verdict::Fail);
        assert_eq!(disk(None, 100).verdict, Verdict::Warn);
    }

    #[test]
    fn a_feature_in_use_refuses() {
        assert_eq!(deprecated("x", "2.0", Some(true)).verdict, Verdict::Fail);
        assert_eq!(deprecated("x", "2.0", Some(false)).verdict, Verdict::Pass);
        assert_eq!(deprecated("x", "2.0", None).verdict, Verdict::Warn);
    }

    #[test]
    fn json_output_is_stable() {
        let report = Report {
            from_version: "1.4.0".to_owned(),
            to_version: "2.0.0".to_owned(),
            requires_pause: true,
            pause_estimate_seconds: Some(30),
            findings: vec![Finding::new("disk", Verdict::Warn, "unknown")],
        };
        assert!(report.passes());
        assert_eq!(
            serde_json::to_string(&report).expect("json"),
            r#"{"from_version":"1.4.0","to_version":"2.0.0","requires_pause":true,"pause_estimate_seconds":30,"findings":[{"check":"disk","verdict":"warn","detail":"unknown"}]}"#
        );
    }
}

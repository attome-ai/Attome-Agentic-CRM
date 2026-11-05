//! `attome drill chaos suite --key <file> --out <dir> [run flags]`
//! (roadmap AB9-T4): every fault of the catalogue in turn, against a test
//! rig, each written as one signed `chaos` evidence report.
//!
//! - The flags after `suite` are `chaos run`'s (the services, the steady
//!   state, `--database-url`, ...), given once for every fault; `--duration`
//!   applies to every fault, else each fault's default.
//! - A fault that needs network administration (`ai-slow` and
//!   `network-delay`, tc/netem) is left out without `--allow-net-admin`.
//! - A fault the flags cannot plan (a service it names is missing) is still
//!   written: its `fault_injected` check is skipped with the reason, so the
//!   evidence is not ok and the gap shows in the drill history.
//! - Each report (`chaos-drill-evidence-<date>-<fault>.json` in `--out`)
//!   carries the fault's checks ([`super::chaos::FaultOutcome`]) and
//!   `extra.fault`; upload it like any drill evidence
//!   (`POST /api/v1/ops/drills/evidence`).
//! - Never production: `--production` is refused, and so is a deployment
//!   whose own profile is production.
//!
//! Exit 0 when every report is ok, 3 when one is not, 1 on a usage error.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;

use attome_ops::evidence::{self, Evidence, EvidenceKind};
use attome_release::chaos::{CATALOGUE, FaultSpec};
use serde_json::{Map, json};

use super::chaos::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, FaultOutcome, Os};
use crate::cmd::output::{take_flag, take_value};

/// The faults the suite runs, in catalogue order: those needing network
/// administration only with `allow_net_admin`. Pure.
pub fn suite_faults(allow_net_admin: bool) -> Vec<&'static FaultSpec> {
    CATALOGUE
        .iter()
        .filter(|spec| allow_net_admin || !spec.needs_net_admin)
        .collect()
}

/// The report's file name. Pure.
pub fn evidence_file_name(fault: &str, date: chrono::NaiveDate) -> String {
    format!(
        "chaos-drill-evidence-{}-{fault}.json",
        date.format("%Y-%m-%d")
    )
}

/// The evidence for one fault's run. Pure.
pub fn fault_evidence(
    spec: &FaultSpec,
    outcome: FaultOutcome,
    started_at: chrono::DateTime<chrono::Utc>,
    finished_at: chrono::DateTime<chrono::Utc>,
) -> Evidence {
    let mut extra = Map::new();
    extra.insert("fault".into(), json!(spec.name));
    extra.insert("proves".into(), json!(spec.proves));
    let mut evidence = Evidence {
        schema: evidence::SCHEMA.to_owned(),
        kind: EvidenceKind::Chaos,
        drill_id: uuid::Uuid::now_v7(),
        started_at,
        finished_at,
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        image_digest: None,
        deployment_id: None,
        checks: outcome.checks,
        rpo_seconds: None,
        rto_seconds: None,
        data_size_bytes: None,
        restore_ok: false,
        provenance_ok: false,
        overall_ok: false,
        extra,
    };
    evidence.compute_overall();
    evidence
}

/// `attome drill chaos suite ...` (the arguments after `suite`).
pub async fn run(args: &[String]) -> u8 {
    let mut args = args.to_vec();
    let key_path = match take_value(&mut args, "--key") {
        Ok(Some(path)) => PathBuf::from(path),
        Ok(None) => {
            eprintln!("attome drill chaos suite: --key <drill signing key file> is required");
            return EXIT_USAGE;
        }
        Err(message) => {
            eprintln!("attome drill chaos suite: {message}");
            return EXIT_USAGE;
        }
    };
    let out = match take_value(&mut args, "--out") {
        Ok(Some(dir)) => PathBuf::from(dir),
        Ok(None) => {
            eprintln!("attome drill chaos suite: --out <folder for the reports> is required");
            return EXIT_USAGE;
        }
        Err(message) => {
            eprintln!("attome drill chaos suite: {message}");
            return EXIT_USAGE;
        }
    };
    if args
        .iter()
        .any(|a| a == "--production" || a == "--approval-id")
    {
        eprintln!(
            "attome drill chaos suite: the suite runs on a test rig only; a production game day is one approved `chaos run`"
        );
        return EXIT_USAGE;
    }
    if args.iter().any(|a| a == "--fault") {
        eprintln!("attome drill chaos suite: the suite runs every fault; leave out --fault");
        return EXIT_USAGE;
    }
    let allow_net_admin = take_flag(&mut args, "--allow-net-admin");
    let key = match evidence::read_signing_key(&key_path) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("attome drill chaos suite: {}: {error}", key_path.display());
            return EXIT_USAGE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&out) {
        eprintln!("attome drill chaos suite: {}: {error}", out.display());
        return EXIT_USAGE;
    }
    let (steady, rest) = match super::chaos_steady::take_args(&args) {
        Ok(split) => split,
        Err(message) => {
            eprintln!("attome drill chaos suite: {message}");
            return EXIT_USAGE;
        }
    };
    let own = attome_config::AppConfig::from_file().ok().map(|config| {
        (
            config.app.deployment_profile.clone(),
            format!(
                "{}:{}/{}",
                config.database.host, config.database.port, config.database.dbname
            ),
        )
    });

    let mut all_ok = true;
    for spec in suite_faults(allow_net_admin) {
        let mut fault_args = rest.clone();
        fault_args.extend(["--fault".to_owned(), spec.name.to_owned()]);
        if allow_net_admin {
            fault_args.push("--allow-net-admin".to_owned());
        }
        let parsed = match super::chaos::parse_args(&fault_args) {
            Ok(parsed) => parsed,
            Err(message) => {
                eprintln!("attome drill chaos suite: {message}");
                return EXIT_USAGE;
            }
        };
        let refused = match &own {
            Some((profile, database)) => {
                super::chaos::refusal(&parsed, profile, Some(database.as_str()))
            }
            None => super::chaos::refusal(&parsed, "", None),
        };
        if let Some(reason) = refused {
            eprintln!("attome drill chaos suite: {reason}");
            return EXIT_USAGE;
        }
        println!("== {}", spec.name);
        let started_at = chrono::Utc::now();
        let outcome = match super::chaos::plan(&parsed, Os::current()) {
            Ok(plan) => match super::chaos::run_plan(&parsed, steady.as_ref(), plan).await {
                Ok(outcome) => outcome,
                Err(message) => {
                    eprintln!("attome drill chaos suite: {message}");
                    return EXIT_USAGE;
                }
            },
            Err(reason) => {
                println!("not run: {reason}");
                let mut outcome = FaultOutcome::default();
                outcome.record("fault_injected", None, format!("not run: {reason}"));
                outcome
            }
        };
        let report = fault_evidence(spec, outcome, started_at, chrono::Utc::now());
        let path = out.join(evidence_file_name(
            spec.name,
            chrono::Utc::now().date_naive(),
        ));
        match evidence::write_signed(&path, &report, &key) {
            Ok(hash) => println!(
                "{}: {} (wrote {}, sha256 {hash})",
                spec.name,
                if report.overall_ok { "ok" } else { "not ok" },
                path.display()
            ),
            Err(error) => {
                eprintln!("attome drill chaos suite: {}: {error}", path.display());
                return EXIT_FAILED;
            }
        }
        all_ok &= report.overall_ok;
    }
    if all_ok { EXIT_OK } else { EXIT_FAILED }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_skips_net_admin_faults_without_flag() {
        let without: Vec<&str> = suite_faults(false).iter().map(|s| s.name).collect();
        let with: Vec<&str> = suite_faults(true).iter().map(|s| s.name).collect();
        assert_eq!(with.len(), CATALOGUE.len());
        for spec in CATALOGUE {
            assert_eq!(
                without.contains(&spec.name),
                !spec.needs_net_admin,
                "{}",
                spec.name
            );
        }
        assert!(
            without.len() < with.len(),
            "ai-slow and network-delay need net admin"
        );
    }

    #[test]
    fn a_fault_evidence_is_chaos_with_its_fault_and_checks() {
        let spec = &CATALOGUE[0];
        let mut outcome = FaultOutcome::default();
        outcome.record("fault_injected", Some(true), "");
        outcome.record("fault_undone", Some(true), "");
        let at = chrono::Utc::now();
        let ok = fault_evidence(spec, outcome, at, at);
        assert_eq!(ok.kind, EvidenceKind::Chaos);
        assert_eq!(ok.extra["fault"], json!(spec.name));
        assert!(ok.overall_ok);

        let mut skipped = FaultOutcome::default();
        skipped.record("fault_injected", None, "not run: --service is missing");
        assert!(!skipped.failed(), "a skipped check is not a failure");
        let not_ok = fault_evidence(spec, skipped, at, at);
        assert!(!not_ok.overall_ok, "a fault not run is not ok evidence");
        assert_eq!(
            evidence_file_name("redis-down", at.date_naive()),
            format!(
                "chaos-drill-evidence-{}-redis-down.json",
                at.format("%Y-%m-%d")
            )
        );
    }
}

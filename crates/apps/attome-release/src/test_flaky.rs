//! Flaky tests and the quarantine (roadmap Z15-T11).
//!
//! After a failed `cargo test` command, `attome test` reruns each failing
//! test once on its own. A test that passes on the rerun is FLAKY: it is
//! printed and written to `target/attome-test/flaky.json`, and the command
//! still fails, because a pass on retry is not a pass.
//!
//! `tests/quarantine.json` lists tests that are skipped while someone fixes
//! them, each with an owner, a reason and an `until` date; an entry past its
//! date fails the run, so a quarantine cannot quietly become permanent.

use std::path::Path;

use serde::Deserialize;

/// `tests/quarantine.json`.
#[derive(Debug, Default, Deserialize)]
pub struct Quarantine {
    pub tests: Vec<Entry>,
}

/// One quarantined test.
#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    /// `<crate>::<test binary>`, the binary being `lib` for unit tests.
    pub target: String,
    pub name: String,
    pub owner: String,
    /// `YYYY-MM-DD`; the last day the entry is honoured.
    pub until: String,
    pub reason: String,
}

impl Entry {
    /// The crate half of `target`.
    pub fn package(&self) -> &str {
        self.target.split("::").next().unwrap_or_default()
    }
}

/// Reads `tests/quarantine.json`; an absent file is an empty quarantine.
pub fn load(root: &Path) -> Result<Quarantine, String> {
    let path = root.join("tests").join("quarantine.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Quarantine::default()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Entries whose `until` date is before `today` (both `YYYY-MM-DD`, which
/// compare correctly as strings), or whose date or owner is missing.
pub fn expired<'a>(quarantine: &'a Quarantine, today: &str) -> Vec<&'a Entry> {
    quarantine
        .tests
        .iter()
        .filter(|entry| {
            entry.until.len() != 10 || entry.owner.trim().is_empty() || entry.until.as_str() < today
        })
        .collect()
}

/// Today's UTC date as `YYYY-MM-DD`, from a Unix time in seconds.
pub fn date_from_unix(seconds: u64) -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX) + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// A failing test found in a `cargo test` log: the binary it ran in (`lib`
/// for unit tests, the file stem for an integration target) and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub binary: String,
    pub name: String,
}

/// The failing tests in a `cargo test` log, from its `Running ...` headers
/// and `test <name> ... FAILED` lines.
pub fn parse_failed(log: &str) -> Vec<Failed> {
    let mut binary = String::from("lib");
    let mut failed = Vec::new();
    for line in log.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Running ") {
            let source = rest.split_whitespace().next().unwrap_or_default();
            let source = source.replace('\\', "/");
            binary = if source.starts_with("unittests") || source.ends_with("src/lib.rs") {
                "lib".to_owned()
            } else {
                Path::new(&source)
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "lib".to_owned())
            };
        } else if let Some(rest) = line.strip_prefix("test ")
            && let Some(name) = rest.strip_suffix(" ... FAILED")
        {
            failed.push(Failed {
                binary: binary.clone(),
                name: name.trim().to_owned(),
            });
        }
    }
    failed
}

/// The `cargo test` arguments that rerun one failed test of `package`.
pub fn rerun_args(package: &str, failed: &Failed) -> Vec<String> {
    let mut args = vec!["test".to_owned(), "-p".to_owned(), package.to_owned()];
    if failed.binary == "lib" {
        args.push("--lib".to_owned());
    } else {
        args.push("--test".to_owned());
        args.push(failed.binary.clone());
    }
    args.extend(["--".to_owned(), failed.name.clone(), "--exact".to_owned()]);
    args
}

/// Appends `--skip <name>` for each quarantined test of `package` to a
/// `cargo test` argument list, after its `--` (added when missing).
pub fn apply_skips(args: &mut Vec<String>, package: &str, quarantine: &Quarantine) {
    let skips: Vec<&Entry> = quarantine
        .tests
        .iter()
        .filter(|entry| entry.package() == package)
        .collect();
    if skips.is_empty() {
        return;
    }
    if !args.iter().any(|arg| arg == "--") {
        args.push("--".to_owned());
    }
    for entry in skips {
        args.push("--skip".to_owned());
        args.push(entry.name.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_test_names() {
        let log = "\
     Running unittests src\\lib.rs (target\\debug\\deps\\attome_x-1.exe)
test a::ok ... ok
test a::bad ... FAILED
     Running tests\\budget.rs (target\\debug\\deps\\budget-2.exe)
test shared_budget_holds ... FAILED
test result: FAILED. 0 passed; 1 failed";
        assert_eq!(
            parse_failed(log),
            vec![
                Failed {
                    binary: "lib".to_owned(),
                    name: "a::bad".to_owned()
                },
                Failed {
                    binary: "budget".to_owned(),
                    name: "shared_budget_holds".to_owned()
                },
            ]
        );
        assert_eq!(
            rerun_args("attome-x", &parse_failed(log)[1]).join(" "),
            "test -p attome-x --test budget -- shared_budget_holds --exact"
        );
    }

    #[test]
    fn expired_quarantine_fails() {
        let quarantine: Quarantine = serde_json::from_str(
            r#"{"tests": [
                {"target": "attome-x::lib", "name": "a", "owner": "Sam", "until": "2026-10-01", "reason": "r"},
                {"target": "attome-x::lib", "name": "b", "owner": "Sam", "until": "2026-12-31", "reason": "r"},
                {"target": "attome-y::lib", "name": "c", "owner": "", "until": "2026-12-31", "reason": "r"}
            ]}"#,
        )
        .unwrap();
        let names: Vec<&str> = expired(&quarantine, "2026-10-14")
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["a", "c"], "past its date, or nobody owns it");

        let mut args = vec!["test".to_owned(), "-p".to_owned(), "attome-x".to_owned()];
        apply_skips(&mut args, "attome-x", &quarantine);
        assert_eq!(args.join(" "), "test -p attome-x -- --skip a --skip b");
    }

    #[test]
    fn unix_seconds_become_a_utc_date() {
        assert_eq!(date_from_unix(0), "1970-01-01");
        assert_eq!(date_from_unix(951_782_400), "2000-02-29");
        assert_eq!(date_from_unix(1_791_936_000), "2026-10-14");
    }
}

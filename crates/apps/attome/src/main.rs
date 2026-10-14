//! `attome`: the Attome command-line tool.
//!
//! It runs the server (`attome serve`) and the processes and tools around
//! it, and the release gate (`attome release --check`). The install and
//! cluster commands (`cluster`, `scale`, `build`, `pack`, `publish`) arrive
//! with their roadmap tasks; `init` installs Solo.
// Deep async call graphs (an agent turn runs actions that run turns)
// overflow the default query depth.
#![recursion_limit = "512"]

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
attome: the Attome command-line tool

Usage:
  attome init                   Install Solo: write a config, apply the schema
  attome bundle offline|verify  Make or check an offline bundle for an
                                air-gapped install
  attome model export --out <dir> | import --dir <dir> [--url <url>] [--api-key <key>]
                                Move metadata objects as one text file each;
                                import saves drafts and never publishes
  attome sovereignty report [--json]
                                Where copies of data live and where data is
                                sent, each marked inside or outside
  attome service install|uninstall [--dir <dir>] [--dry-run]
                                Run attome serve as a Windows service or a
                                systemd unit, from the directory with config.json
  attome serve                  Run the server (flags: --print-openapi,
                                --bootstrap-admin <email>)
  attome worker                 Run the job worker only
  attome migrate                Apply database migrations and exit
  attome healthcheck            Exit 0 when the local server is healthy
  attome preflight              Check configuration and dependencies
  attome audit-chainer          Run the audit hash chainer
  attome verify-audit-chain     Verify the audit hash chain
  attome changeset-replay       Replay changesets against a database
  attome release --check [--web] [--slo-evidence] [--override <step>=<reason> --by <name>]
                                Run the release gate: format, clippy, tests, the
                                API contract, SLO outputs, Prometheus rules (and
                                the web app with --web)
  attome release import-report <path>
                                Bring in the other OS's gate report
  attome release tag <version>  Tag this commit when both OS reports are green
  attome slo generate [--check]
                                Regenerate the SLO rules, k6 thresholds and table
                                from observability/slo-catalogue.json
  attome test [--tier unit|db|contract|security|browser|all] [--changed] [--release] [--dry-run] [--no-stack] [--coverage]
                                Run the tests a tier needs (--changed scopes them
                                to the change; --release fails instead of skipping)
  attome test map [--scan-only]
                                Map tests to features and API operations
                                (target/coverage-map/)
  attome slo report <matrix-summary.json>
                                Write the SLO release report from a load-test run
  attome version           Print the version
  attome help              Print this help
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["help" | "--help" | "-h"] => {
            say(USAGE);
            ExitCode::SUCCESS
        }
        ["version" | "--version" | "-V"] => {
            say(&format!("attome {}", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        ["release", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome_release::dispatch(&rest).unwrap_or_else(|| {
                eprintln!("attome release: unknown arguments\n\n{USAGE}");
                ExitCode::from(2)
            })
        }
        ["slo" | "test", ..] => {
            let all: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            attome_release::dispatch(&all).unwrap_or_else(|| {
                eprintln!("attome slo/test: unknown arguments\n\n{USAGE}");
                ExitCode::from(2)
            })
        }
        ["init", ..] => outcome(attome::cmd::init::run()),
        ["service", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::service::run(&rest).map_err(Into::into))
        }
        ["bundle", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::bundle_offline::run(&rest).map_err(Into::into))
        }
        ["model", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::model_files::run(&rest).map_err(Into::into))
        }
        ["sovereignty", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::sovereignty::run(&rest).map_err(Into::into))
        }
        ["service-run", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::service::service_run(&rest).map_err(Into::into))
        }
        ["serve", ..] => outcome(attome::serve::run()),
        ["worker", ..] => outcome(attome::cmd::worker::run()),
        ["migrate", ..] => outcome(attome::cmd::migrate::run()),
        ["audit-chainer", ..] => outcome(attome::cmd::audit_chainer::run()),
        ["healthcheck", ..] => attome::cmd::healthcheck::run(),
        ["preflight", ..] => attome::cmd::preflight::run(),
        ["changeset-replay", ..] => attome::cmd::changeset_replay::run(),
        ["verify-audit-chain", ..] => {
            attome::cmd::verify_audit_chain::run();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("attome: unknown command `{}`\n\n{USAGE}", other.join(" "));
            ExitCode::from(2)
        }
    }
}

/// Maps a command's result to an exit code, printing the error.
fn outcome(result: Result<(), Box<dyn std::error::Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("attome: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Writes one line to standard output. A closed pipe is not an error worth
/// failing a command over, so the write result is ignored.
pub(crate) fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

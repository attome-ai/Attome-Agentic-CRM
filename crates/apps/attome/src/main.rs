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
  attome supervise --token-file <path> [--listen <addr>]
                                Run the server on a socket it keeps, with
                                zero-downtime restarts over POST /restart
  attome worker                 Run the job worker only
  attome migrate                Apply database migrations and exit
  attome healthcheck            Exit 0 when the local server is healthy
  attome preflight              Check configuration and dependencies
  attome doctor                 The same checks, with what to do about each failure
  attome backup now             Write a database backup now (pg_dump custom format,
                                plus the file store's files)
  attome backup drill           Restore the newest backup into a throwaway database,
                                check it, drop it, and record the result
  attome restore <archive|latest> --yes
                                Put the database back to a backup (stop the server
                                first; the current database is backed up before)
  attome secrets generate|rotate <VAR> --env-file <path> | rewrap <domain>
                                Fill the secrets an install generates, rotate a
                                key ring (old key kept readable), start a rewrap
  attome drill keygen --out <dir> | verify <file> [--public-key <file>] | readiness
                                Recovery drill keys, signed evidence checks and
                                readiness (exit 2 bad signature, 3 failed, 4 not ready)
  attome runbook [<Alert>]      Print an alert's runbook filled with this
                                deployment's addresses (no name: list the alerts)
  attome status [--url <url>]...
                                Each node's version, schema, and whether it has
                                started and is ready
  attome settings list|get <key>|set <key> <json> --url <server>
                                Read or change a setting (the API key is read
                                from ATTOME_API_KEY)
  attome cluster plan --profile <solo|team|ha|scale> [--target native|compose|helm]
                                Print the deployment files of a profile (systemd
                                units and a config overlay, compose, or Helm values)
  attome status-page --url <server> --out <dir>
                                Write a server's public status page as static
                                HTML and JSON into a directory
  attome storage migrate --from <config.json> --to <config.json> [--state <file>]
                                Copy every file to another storage backend,
                                verify each, and resume where a stop left off
  attome upgrade --plan <nodes.json>
                                Upgrade nodes one at a time, watching each
                                and rolling back the first that gets worse
  attome sla probe --url <server> --out <probes.jsonl>
                                Probe a server's readiness every minute and
                                append the answers
  attome sla report --probes <probes.jsonl> --month <YYYY-MM> --out <report.html>
                                The month's availability, without agreed
                                maintenance (--maintenance <windows.json>)
  attome audit-chainer          Run the audit hash chainer
  attome verify-audit-chain     Verify the audit hash chain
  attome changeset-replay       Replay changesets against a database
  attome release --check [--web] [--slo-evidence] [--perf] [--override <step>=<reason> --by <name>]
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
  attome perf record --release <v> [<matrix-summary.json>...]
                                Record a release's p95 per SLO class and benchmark
                                means (docs/perf-history/<v>.json)
  attome perf compare [--base <v>] [--current <v>]
                                Compare with the previous release on the same machine
  attome sdk generate <deployment.json> [--out <dir>]
                                Typed Rust structs and TypeScript interfaces for
                                this deployment's entities
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
        ["slo" | "test" | "perf" | "sdk", ..] => {
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
        ["supervise", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            outcome(attome::cmd::supervise::run(&rest).map_err(Into::into))
        }
        ["serve", ..] => outcome(attome::serve::run()),
        ["worker", ..] => outcome(attome::cmd::worker::run()),
        ["migrate", ..] => outcome(attome::cmd::migrate::run()),
        ["audit-chainer", ..] => outcome(attome::cmd::audit_chainer::run()),
        ["healthcheck", ..] => attome::cmd::healthcheck::run(),
        ["preflight", ..] => attome::cmd::preflight::run(),
        ["doctor", ..] => attome::cmd::preflight::run_doctor(),
        ["backup", "now"] => attome::backup::run_now(),
        ["scratch", rest @ ..] => {
            attome::scratch::run(rest.iter().map(|arg| (*arg).to_owned()).collect())
        }
        ["backup", "drill"] => attome::backup::run_drill_now(),
        ["restore", rest @ ..] => {
            attome::backup::run_restore(rest.iter().map(|arg| (*arg).to_owned()).collect())
        }
        ["secrets", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::secrets::run(&rest)
        }
        ["drill", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::drill::run(&rest)
        }
        ["runbook", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::runbook::run(&rest)
        }
        ["settings", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::settings::run(&rest)
        }
        ["upgrade", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::upgrade::run(&rest)
        }
        ["sla", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::sla_report::run(&rest)
        }
        ["storage", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::storage_migrate::run(&rest)
        }
        ["cluster", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::cluster::run(&rest)
        }
        ["status-page", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::status_page::run(&rest)
        }
        ["status", rest @ ..] => {
            let rest: Vec<String> = rest.iter().map(|arg| (*arg).to_owned()).collect();
            attome::cmd::status::run(&rest)
        }
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

//! `attome`: the Attome command-line tool.
//!
//! It runs the server (`attome serve`) and the processes and tools around
//! it, and the release gate (`attome release --check`). The install and
//! cluster commands (`cluster`, `scale`, `build`, `pack`, `publish`) arrive
//! with their roadmap tasks; `init` installs Solo.

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
attome: the Attome command-line tool

Usage:
  attome init                   Install Solo: write a config, apply the schema
  attome serve                  Run the server (flags: --print-openapi,
                                --bootstrap-admin <email>)
  attome worker                 Run the job worker only
  attome migrate                Apply database migrations and exit
  attome healthcheck            Exit 0 when the local server is healthy
  attome preflight              Check configuration and dependencies
  attome audit-chainer          Run the audit hash chainer
  attome verify-audit-chain     Verify the audit hash chain
  attome changeset-replay       Replay changesets against a database
  attome release --check        Run the release gate: format, clippy, tests
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
        ["release", "--check"] => attome_release::check(),
        ["init", ..] => outcome(attome::cmd::init::run()),
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

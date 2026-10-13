//! `attome`: the Attome command-line tool.
//!
//! Today it carries the release gate (`attome release --check`). The other
//! commands (`init`, `cluster`, `scale`, `build`, `pack`, `publish`) arrive
//! with their roadmap tasks.

use std::io::Write;
use std::process::ExitCode;

mod release;

const USAGE: &str = "\
attome: the Attome command-line tool

Usage:
  attome release --check   Run the release gate: format, clippy, tests
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
        ["release", "--check"] => release::check(),
        other => {
            eprintln!("attome: unknown command `{}`\n\n{USAGE}", other.join(" "));
            ExitCode::from(2)
        }
    }
}

/// Writes one line to standard output. A closed pipe is not an error worth
/// failing a command over, so the write result is ignored.
pub(crate) fn say(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

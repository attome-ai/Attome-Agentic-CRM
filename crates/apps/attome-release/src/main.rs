//! `attome-release`: the release gate on its own, so CI can run it before
//! (and whether or not) the rest of the workspace compiles. `attome release`
//! runs the same functions.

use std::process::ExitCode;

const USAGE: &str = "\
usage:
  attome-release --check [--web] [--override <step>=<reason>]... [--by <name>]
  attome-release import-report <path>
  attome-release tag <version>
  attome-release slo generate [--check]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    attome_release::dispatch(&args).unwrap_or_else(|| {
        eprintln!("{USAGE}");
        ExitCode::from(2)
    })
}

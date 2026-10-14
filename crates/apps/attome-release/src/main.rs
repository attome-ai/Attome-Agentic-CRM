//! `attome-release --check`: the release gate on its own, so CI can run it
//! before (and whether or not) the rest of the workspace compiles. `attome
//! release --check` runs the same function.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--check"] => attome_release::check(),
        ["--check", "--web"] | ["--web", "--check"] => {
            attome_release::check_with(attome_release::Options { web: true })
        }
        _ => {
            eprintln!("usage: attome-release --check [--web]");
            ExitCode::from(2)
        }
    }
}

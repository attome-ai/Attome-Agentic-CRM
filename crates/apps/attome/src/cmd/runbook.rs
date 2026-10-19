//! `attome runbook [<Alert>]` (roadmap AB10-T3): prints an alert's runbook
//! filled with this deployment's addresses, read from the configuration file
//! (`attome_server::runbooks`). Without a name it lists every alert that has
//! one. No secret reaches the output.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;

use attome_config::AppConfig;
use attome_server::runbooks::{self, RunbookValues};

const USAGE: &str = "usage: attome runbook [<Alert>]";

/// The alert names, one per line.
pub fn list() -> String {
    let mut out = String::new();
    for (name, _) in runbooks::RUNBOOKS {
        out.push_str(name);
        out.push('\n');
    }
    out
}

pub fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print!("{}", list());
            ExitCode::SUCCESS
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        [name] => {
            if runbooks::template(name).is_none() {
                eprintln!("attome runbook: no alert named `{name}`; `attome runbook` lists them");
                return ExitCode::from(2);
            }
            let config = match AppConfig::from_file() {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("attome runbook: the configuration did not load: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let node = attome_server::metrics_store::node_name(config.app.port);
            let values = RunbookValues::from_config(&config, &node);
            match runbooks::render(name, &values) {
                Some(text) => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
                None => ExitCode::from(2),
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_names_every_alert() {
        let list = list();
        assert!(list.lines().any(|l| l == "BackupTooOld"), "{list}");
        assert_eq!(list.lines().count(), runbooks::RUNBOOKS.len());
    }
}

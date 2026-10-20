//! `attome status-page --url <server> --out <dir>` (roadmap H8-T2): reads a
//! server's public status page (`GET /api/v1/status`, no sign-in) and
//! writes it as a static `index.html` (English and Arabic) and
//! `status.json` into a directory, for a host the server cannot write to.
//! Run it from a timer on that host; the server also writes the same files
//! to its own object store whenever a status record changes
//! (`attome_service::status_static`).

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use attome_service::status_page::StatusPage;

const USAGE: &str = "usage: attome status-page --url <server> --out <dir>";
const TIMEOUT: Duration = Duration::from_secs(15);

/// The command's options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub url: String,
    pub out: PathBuf,
}

/// Reads `--url` and `--out`; both are required.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut url = None;
    let mut out = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--url" => url = Some(it.next().ok_or("--url needs a value")?.clone()),
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a value")?)),
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown option `{other}`\n{USAGE}")),
        }
    }
    match (url, out) {
        (Some(url), Some(out)) => Ok(Options {
            url: url.trim_end_matches('/').to_owned(),
            out,
        }),
        _ => Err(USAGE.to_owned()),
    }
}

/// `attome status-page`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(2);
        }
    };
    // Q21-T1: the server is the operator's own, named on the command line.
    let purpose = attome_outbound::http::Purpose::public("cli-status-page")
        .with_private_urls(std::iter::once(options.url.as_str()));
    let Ok(client) = attome_outbound::http::client(purpose, |b| b.timeout(TIMEOUT)) else {
        println!("could not build the HTTP client");
        return ExitCode::FAILURE;
    };
    let response = match client
        .get(format!("{}/api/v1/status", options.url))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            println!("{} answered {}", options.url, r.status());
            return ExitCode::FAILURE;
        }
        Err(error) => {
            println!("{} did not answer: {error}", options.url);
            return ExitCode::FAILURE;
        }
    };
    let page: StatusPage = match response.json().await {
        Ok(page) => page,
        Err(error) => {
            println!("the status page could not be read: {error}");
            return ExitCode::FAILURE;
        }
    };
    let html = attome_service::status_static::render_html(&page);
    let json = match serde_json::to_vec_pretty(&page) {
        Ok(json) => json,
        Err(error) => {
            println!("the status page could not be written: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&options.out)
        .and_then(|()| std::fs::write(options.out.join("index.html"), html))
        .and_then(|()| std::fs::write(options.out.join("status.json"), json))
    {
        println!("could not write to {}: {error}", options.out.display());
        return ExitCode::FAILURE;
    }
    println!(
        "status page written to {} ({})",
        options.out.display(),
        page.overall
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn url_and_out_are_required() {
        let parsed = parse(&args(&["--url", "https://crm.example/", "--out", "site"]));
        assert_eq!(
            parsed,
            Ok(Options {
                url: "https://crm.example".into(),
                out: PathBuf::from("site"),
            })
        );
        assert!(parse(&args(&["--url", "https://crm.example"])).is_err());
        assert!(parse(&args(&["--bogus"])).is_err());
    }
}

//! `attome settings list|get <key>|set <key> <json>` (roadmap U10-T2): the
//! registered settings from the command line, a thin client of
//! `/api/v1/admin/settings`. The server is `--url`; the API key is read from
//! `ATTOME_API_KEY` (`<public>:<secret>`), never from an argument, so it does
//! not land in the shell's history. `set` writes the deployment value; the
//! server validates it exactly as for the admin console.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;
use std::time::Duration;

use serde_json::Value;

const USAGE: &str = "usage: attome settings list --url <server>\n       \
                     attome settings get <key> --url <server>\n       \
                     attome settings set <key> <json value> --url <server>\n\
                     The API key is read from ATTOME_API_KEY (<public>:<secret>).";
const TIMEOUT: Duration = Duration::from_secs(15);

/// The environment variable the API key is read from.
pub const API_KEY_VAR: &str = "ATTOME_API_KEY";

/// What to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    List,
    Get(String),
    Set(String, Value),
}

/// The command and its server.
#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub command: Command,
    pub url: String,
}

/// Whether `key` has a setting's shape: `{module}.{name}`, lower case.
fn key_shape_ok(key: &str) -> bool {
    key.split_once('.').is_some_and(|(module, name)| {
        !module.is_empty()
            && !name.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
    })
}

/// Reads the command, its key and value, and `--url`.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut url = None;
    let mut words = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--url" => url = Some(it.next().ok_or("--url needs a value")?.clone()),
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other if other.starts_with("--") => {
                return Err(format!("unknown option `{other}`\n{USAGE}"));
            }
            other => words.push(other.to_owned()),
        }
    }
    let url = url
        .ok_or_else(|| USAGE.to_owned())?
        .trim_end_matches('/')
        .to_owned();
    let key = |k: &str| {
        if key_shape_ok(k) {
            Ok(k.to_owned())
        } else {
            Err(format!("`{k}` is not a setting key ({{module}}.{{name}})"))
        }
    };
    let command = match words.as_slice() {
        [w] if w == "list" => Command::List,
        [w, k] if w == "get" => Command::Get(key(k)?),
        [w, k, v] if w == "set" => {
            let value = serde_json::from_str(v)
                .map_err(|_| format!("the value must be JSON (a string is \"quoted\"): {v}"))?;
            Command::Set(key(k)?, value)
        }
        _ => return Err(USAGE.to_owned()),
    };
    Ok(Options { command, url })
}

/// `attome settings`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            println!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(api_key) = std::env::var(API_KEY_VAR) else {
        println!("set {API_KEY_VAR} to an administrator's API key (<public>:<secret>)");
        return ExitCode::FAILURE;
    };
    // Q21-T1: the server is the operator's own, named on the command line.
    let purpose = attome_outbound::http::Purpose::public("cli-settings")
        .with_private_urls(std::iter::once(options.url.as_str()));
    let Ok(client) = attome_outbound::http::client(purpose, |b| b.timeout(TIMEOUT)) else {
        println!("could not build the HTTP client");
        return ExitCode::FAILURE;
    };
    let auth = format!("ApiKey {api_key}");
    let list_url = format!("{}/api/v1/admin/settings", options.url);
    let request = match &options.command {
        Command::List | Command::Get(_) => client.get(&list_url),
        Command::Set(key, value) => client
            .request(reqwest::Method::PUT, format!("{list_url}/{key}"))
            .json(&serde_json::json!({ "scope": "deployment", "scope_ref": null, "value": value })),
    };
    let response = match request.header("Authorization", auth).send().await {
        Ok(r) => r,
        Err(error) => {
            println!("{} did not answer: {error}", options.url);
            return ExitCode::FAILURE;
        }
    };
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let message = body["message"].as_str().unwrap_or("");
        println!("{} answered {status} {message}", options.url);
        return ExitCode::FAILURE;
    }
    match &options.command {
        Command::List => {
            for item in body["items"].as_array().into_iter().flatten() {
                println!(
                    "{}\t{}\t{}",
                    item["key"].as_str().unwrap_or_default(),
                    item["value"],
                    item["source"].as_str().unwrap_or_default()
                );
            }
        }
        Command::Get(key) => {
            let found = body["items"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|item| item["key"].as_str() == Some(key.as_str()));
            match found {
                Some(item) => println!("{}", item["value"]),
                None => {
                    println!(
                        "no setting `{key}` (a boot-time setting is in the configuration file)"
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
        Command::Set(key, _) => println!("{key} = {}", body["value"]),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn settings_commands_parse() {
        let url = "https://crm.example/";
        assert_eq!(
            parse(&args(&["list", "--url", url])).map(|o| o.command),
            Ok(Command::List)
        );
        assert_eq!(
            parse(&args(&["get", "core.locale", "--url", url])).map(|o| o.command),
            Ok(Command::Get("core.locale".into()))
        );
        assert_eq!(
            parse(&args(&["set", "core.list_page_size", "50", "--url", url])).map(|o| o.command),
            Ok(Command::Set(
                "core.list_page_size".into(),
                serde_json::json!(50)
            ))
        );
        assert_eq!(
            parse(&args(&["list", "--url", url])).map(|o| o.url),
            Ok("https://crm.example".into())
        );
    }

    #[test]
    fn settings_commands_refuse_bad_input() {
        let url = "https://crm.example";
        assert!(parse(&args(&["list"])).is_err(), "--url is required");
        assert!(parse(&args(&["get", "Locale", "--url", url])).is_err());
        assert!(parse(&args(&["set", "core.locale", "ar-SA", "--url", url])).is_err());
        assert!(parse(&args(&["set", "core.locale", "\"ar-SA\"", "--url", url])).is_ok());
        assert!(parse(&args(&["delete", "core.locale", "--url", url])).is_err());
        assert!(parse(&args(&["list", "--key", "x", "--url", url])).is_err());
    }
}

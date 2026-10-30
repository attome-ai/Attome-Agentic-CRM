//! T6-T4: `attome flags list|get <name>|set <name> on|off|off-now <name>` —
//! customer flags from the command line, a thin client of
//! `/api/v1/admin/customer-flags` with its permission (`admin.deployment`).
//! It runs as the signed-in person (`--target`, T4-T1) or with an API key
//! (`--url`, `ATTOME_API_KEY`). `set` and `off-now` change the deployment, so
//! they need `--yes` (and `--confirm-target` on a production target, T4-T5);
//! every change is audited by the API. `--json` prints the versioned object.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use serde_json::{Value, json};

use crate::cmd::login::{Auth, credentials};
use crate::cmd::output::{confirm, envelope, take_flag, take_value};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const USAGE: &str = "usage: attome flags list\n       attome flags get <name>\n       attome flags set <name> on|off [--description <text>]\n       attome flags off-now <name>\n  each with [--target <name> | --url <url>] [--json]; set and off-now need --yes";

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagsCommand {
    List,
    Get(String),
    Set {
        name: String,
        value: bool,
        description: Option<String>,
    },
    OffNow(String),
}

/// A flag name: lower-case letters, digits and `_`, starting with a letter. Pure.
fn name(text: &str) -> Result<String, String> {
    if attome_core::customer_flags::valid_name(text) {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "`{text}` is not a flag name (lower case, digits, _)"
        ))
    }
}

/// Parses the words after `attome flags` (flags already taken out). Pure.
pub fn parse(words: &[String], description: Option<String>) -> Result<FlagsCommand, String> {
    match words {
        [verb] if verb == "list" => Ok(FlagsCommand::List),
        [verb, flag] if verb == "get" => Ok(FlagsCommand::Get(name(flag)?)),
        [verb, flag, value] if verb == "set" => Ok(FlagsCommand::Set {
            name: name(flag)?,
            value: match value.as_str() {
                "on" | "true" => true,
                "off" | "false" => false,
                other => return Err(format!("a flag is on or off, not `{other}`")),
            },
            description,
        }),
        [verb, flag] if verb == "off-now" => Ok(FlagsCommand::OffNow(name(flag)?)),
        _ => Err(USAGE.to_owned()),
    }
}

/// Runs `attome flags ...`.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let json = take_flag(&mut args, "--json");
    let yes = take_flag(&mut args, "--yes");
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    let target = take_value(&mut args, "--target")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let description = take_value(&mut args, "--description")?;
    if let Some(unknown) = args.iter().find(|a| a.starts_with("--")) {
        return Err(format!("unknown flag `{unknown}`\n{USAGE}"));
    }
    let command = parse(&args, description)?;
    if matches!(command, FlagsCommand::Set { .. } | FlagsCommand::OffNow(_)) {
        let named = target
            .as_deref()
            .map(|t| (t, crate::cmd::login::is_production(Some(t))));
        confirm("changing a flag", yes, confirm_target.as_deref(), named)?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) =
            credentials(url.trim_end_matches('/').to_owned(), api_key, target).await?;
        let answer = match command {
            FlagsCommand::List => {
                let page = send(&url, &auth, reqwest::Method::GET, "", None).await?;
                json!({ "flags": page["items"] })
            }
            FlagsCommand::Get(flag) => {
                let page = send(&url, &auth, reqwest::Method::GET, "", None).await?;
                let found = page["items"]
                    .as_array()
                    .and_then(|items| items.iter().find(|f| f["name"] == flag.as_str()))
                    .cloned()
                    .ok_or_else(|| format!("no flag `{flag}`"))?;
                json!({ "flag": found })
            }
            FlagsCommand::Set {
                name,
                value,
                description,
            } => {
                // A change to an existing flag carries its row version.
                let page = send(&url, &auth, reqwest::Method::GET, "", None).await?;
                let row_version = page["items"]
                    .as_array()
                    .and_then(|items| items.iter().find(|f| f["name"] == name.as_str()))
                    .and_then(|f| f["row_version"].as_i64());
                let flag = send(
                    &url,
                    &auth,
                    reqwest::Method::PUT,
                    &format!("/{name}"),
                    Some(json!({ "value": value, "description": description, "row_version": row_version })),
                )
                .await?;
                json!({ "flag": flag })
            }
            FlagsCommand::OffNow(name) => {
                let flag = send(
                    &url,
                    &auth,
                    reqwest::Method::POST,
                    &format!("/{name}/emergency-off"),
                    Some(json!({})),
                )
                .await?;
                json!({ "flag": flag })
            }
        };
        if json {
            println!("{}", envelope("flags", answer));
        } else if let Some(flags) = answer["flags"].as_array() {
            for flag in flags {
                println!("{}", line(flag));
            }
        } else {
            println!("{}", line(&answer["flag"]));
        }
        Ok(())
    })
}

/// One flag for a person: `name  on|off  (emergency off)  description`. Pure.
pub fn line(flag: &Value) -> String {
    let mut out = format!(
        "{}\t{}",
        flag["name"].as_str().unwrap_or_default(),
        if flag["on"].as_bool().unwrap_or(false) {
            "on"
        } else {
            "off"
        }
    );
    if flag["emergency_off"].as_bool().unwrap_or(false) {
        out.push_str("\t(emergency off)");
    }
    if let Some(description) = flag["description"].as_str() {
        out.push('\t');
        out.push_str(description);
    }
    out
}

/// `url` is the operator's own deployment, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-flags").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(30)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

async fn send(
    url: &str,
    auth: &Auth,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request =
        client(url)?.request(method, format!("{url}/api/v1/admin/customer-flags{path}"));
    if let Some(value) = auth {
        request = request.header("authorization", value);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("the server answered {status}: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn flag_commands_parse() {
        assert_eq!(parse(&words(&["list"]), None), Ok(FlagsCommand::List));
        assert_eq!(
            parse(
                &words(&["set", "new_checkout", "on"]),
                Some("New checkout".into())
            ),
            Ok(FlagsCommand::Set {
                name: "new_checkout".into(),
                value: true,
                description: Some("New checkout".into()),
            })
        );
        assert!(parse(&words(&["set", "New-Checkout", "on"]), None).is_err());
        assert!(parse(&words(&["set", "x", "maybe"]), None).is_err());
        assert_eq!(
            parse(&words(&["off-now", "x"]), None),
            Ok(FlagsCommand::OffNow("x".into()))
        );
    }

    #[test]
    fn a_flag_reads_as_one_line() {
        let flag =
            json!({ "name": "beta", "on": false, "emergency_off": true, "description": "Beta" });
        assert_eq!(line(&flag), "beta\toff\t(emergency off)\tBeta");
    }
}

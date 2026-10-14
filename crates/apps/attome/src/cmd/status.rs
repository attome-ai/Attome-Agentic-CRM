//! `attome status [--url <url>]...` (roadmap U4-T3): one line per node with
//! its version, schema version, and whether it has started and is ready.
//!
//! Solo is one node, read at `http://127.0.0.1:<port>` (the port from the
//! configuration file when there is one, else 7865). A deployment with
//! several nodes names each with `--url`. Every endpoint read is one a load
//! balancer already polls without signing in (`/version`, `/health/startup`,
//! `/health/ready`), so status needs no credentials; a node that does not
//! answer is reported as unreachable rather than failing the command.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;
use std::time::Duration;

use serde_json::Value;

const USAGE: &str = "usage: attome status [--url <url>]...";
const TIMEOUT: Duration = Duration::from_secs(5);

/// One node's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub url: String,
    pub reachable: bool,
    pub version: Option<String>,
    pub schema: Option<String>,
    pub started: Option<bool>,
    pub ready: Option<bool>,
}

/// The node URLs to read: those given, else this machine's server.
pub fn parse(args: &[String], default_port: u16) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--url" => {
                let url = it.next().ok_or("--url needs a value")?;
                urls.push(url.trim_end_matches('/').to_owned());
            }
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown option `{other}`\n{USAGE}")),
        }
    }
    if urls.is_empty() {
        urls.push(format!("http://127.0.0.1:{default_port}"));
    }
    Ok(urls)
}

/// One line per node, aligned.
pub fn render(nodes: &[NodeStatus]) -> String {
    let flag = |value: Option<bool>| match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "-",
    };
    let mut out = format!(
        "{:<32} {:<10} {:<8} {:<8} {:<6}\n",
        "node", "version", "schema", "started", "ready"
    );
    for node in nodes {
        if !node.reachable {
            out.push_str(&format!("{:<32} unreachable\n", node.url));
            continue;
        }
        out.push_str(&format!(
            "{:<32} {:<10} {:<8} {:<8} {:<6}\n",
            node.url,
            node.version.as_deref().unwrap_or("-"),
            node.schema.as_deref().unwrap_or("-"),
            flag(node.started),
            flag(node.ready),
        ));
    }
    out
}

async fn read(client: &reqwest::Client, url: &str) -> NodeStatus {
    let get = |path: &'static str| {
        let request = client.get(format!("{url}{path}"));
        async move { request.send().await.ok() }
    };
    let (version, startup, ready) = tokio::join!(
        get("/version"),
        get("/health/startup"),
        get("/health/ready")
    );
    let Some(version) = version else {
        return NodeStatus {
            url: url.to_owned(),
            reachable: false,
            version: None,
            schema: None,
            started: None,
            ready: None,
        };
    };
    let body: Value = version.json().await.unwrap_or(Value::Null);
    let text = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    NodeStatus {
        url: url.to_owned(),
        reachable: true,
        version: text(&body["application_version"]),
        schema: text(&body["schema_version"]),
        // A node too old to have /health/startup answers 404: unknown.
        started: startup.and_then(|r| match r.status().as_u16() {
            200 => Some(true),
            503 => Some(false),
            _ => None,
        }),
        ready: ready.map(|r| r.status().is_success()),
    }
}

/// `attome status`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let port = attome_config::AppConfig::from_file()
        .map(|config| config.app.port)
        .unwrap_or(7865);
    let urls = match parse(args, port) {
        Ok(urls) => urls,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(2);
        }
    };
    let Ok(client) = reqwest::Client::builder().timeout(TIMEOUT).build() else {
        println!("attome status: could not build an HTTP client");
        return ExitCode::FAILURE;
    };
    let mut nodes = Vec::with_capacity(urls.len());
    for url in &urls {
        nodes.push(read(&client, url).await);
    }
    print!("{}", render(&nodes));
    if nodes.iter().all(|n| n.reachable && n.ready == Some(true)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_node_is_this_machine() {
        assert_eq!(parse(&[], 7865).unwrap(), ["http://127.0.0.1:7865"]);
        let urls = parse(
            &[
                "--url".into(),
                "http://a:7865/".into(),
                "--url".into(),
                "http://b:7865".into(),
            ],
            1,
        )
        .unwrap();
        assert_eq!(urls, ["http://a:7865", "http://b:7865"]);
        assert!(parse(&["--url".into()], 1).is_err());
        assert!(parse(&["--nope".into()], 1).is_err());
    }

    #[test]
    fn nodes_render_one_line_each() {
        let out = render(&[
            NodeStatus {
                url: "http://a:7865".into(),
                reachable: true,
                version: Some("0.1.0".into()),
                schema: Some("19".into()),
                started: Some(true),
                ready: Some(false),
            },
            NodeStatus {
                url: "http://b:7865".into(),
                reachable: false,
                version: None,
                schema: None,
                started: None,
                ready: None,
            },
        ]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("0.1.0") && lines[1].contains("yes") && lines[1].contains("no"));
        assert!(lines[2].contains("unreachable"));
    }
}

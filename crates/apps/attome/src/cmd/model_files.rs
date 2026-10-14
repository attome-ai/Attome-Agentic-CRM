//! `attome model export --out <dir>` and `attome model import --dir <dir>`
//! (roadmap Y1-T10): move metadata objects between deployments as one
//! readable text file per object, through the running server's admin API.
//!
//! Export writes `<dir>/<kind>/<app>/<name>.json`. Import reads every `.json`
//! file under the directory and saves each as a draft; it never publishes.
//! The server is `--url` (or `ATTOME_URL`, default `http://127.0.0.1:7865`)
//! and the caller authenticates with an administrator API key, `--api-key`
//! (or `ATTOME_API_KEY`) in the `<public>:<secret>` form.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";

/// A parsed `attome model` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelCommand {
    Export {
        url: String,
        api_key: Option<String>,
        out: PathBuf,
    },
    Import {
        url: String,
        api_key: Option<String>,
        dir: PathBuf,
    },
}

const USAGE: &str = "usage: attome model export --out <dir> [--url <url>] [--api-key <key>]\n       attome model import --dir <dir> [--url <url>] [--api-key <key>]";

/// Parses the arguments after `attome model`.
pub fn parse(args: &[String]) -> Result<ModelCommand, String> {
    let (verb, rest) = args.split_first().ok_or_else(|| USAGE.to_owned())?;
    let mut url = std::env::var("ATTOME_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned());
    let mut api_key = std::env::var("ATTOME_API_KEY").ok();
    let mut dir: Option<PathBuf> = None;
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match (verb.as_str(), flag.as_str()) {
            (_, "--url") => url = value()?,
            (_, "--api-key") => api_key = Some(value()?),
            ("export", "--out") | ("import", "--dir") => dir = Some(PathBuf::from(value()?)),
            _ => return Err(format!("unknown flag `{flag}`\n{USAGE}")),
        }
    }
    let url = url.trim_end_matches('/').to_owned();
    match verb.as_str() {
        "export" => Ok(ModelCommand::Export {
            url,
            api_key,
            out: dir.ok_or_else(|| format!("--out is required\n{USAGE}"))?,
        }),
        "import" => Ok(ModelCommand::Import {
            url,
            api_key,
            dir: dir.ok_or_else(|| format!("--dir is required\n{USAGE}"))?,
        }),
        _ => Err(USAGE.to_owned()),
    }
}

/// Runs `attome model ...`.
pub fn run(args: &[String]) -> Result<(), String> {
    let command = parse(args)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        match command {
            ModelCommand::Export { url, api_key, out } => export(&url, api_key, &out).await,
            ModelCommand::Import { url, api_key, dir } => import(&url, api_key, &dir).await,
        }
    })
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|error| format!("build the HTTP client: {error}"))
}

fn authorised(request: reqwest::RequestBuilder, api_key: Option<&str>) -> reqwest::RequestBuilder {
    match api_key {
        Some(key) => request.header("authorization", format!("ApiKey {key}")),
        None => request,
    }
}

async fn answer(response: reqwest::Response) -> Result<Value, String> {
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

/// A relative path with only normal components, so a file can never land
/// outside the export directory.
fn safe_relative(path: &str) -> Option<PathBuf> {
    let candidate = Path::new(path);
    candidate
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
        .then(|| candidate.to_path_buf())
}

async fn export(url: &str, api_key: Option<String>, out: &Path) -> Result<(), String> {
    let response = authorised(
        client()?.get(format!("{url}/api/v1/admin/model/export")),
        api_key.as_deref(),
    )
    .send()
    .await
    .map_err(|error| format!("reach {url}: {error}"))?;
    let body = answer(response).await?;
    let files = body["files"].as_array().cloned().unwrap_or_default();
    for file in &files {
        let (Some(path), Some(text)) = (file["path"].as_str(), file["text"].as_str()) else {
            return Err("the server sent a file without a path or text".into());
        };
        let relative = safe_relative(path).ok_or_else(|| format!("unsafe file path `{path}`"))?;
        let target = out.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        std::fs::write(&target, text.replace("\r\n", "\n"))
            .map_err(|error| format!("write {}: {error}", target.display()))?;
    }
    println!("exported {} object(s) to {}", files.len(), out.display());
    Ok(())
}

/// Every `.json` file under `dir`, as (path relative to `dir` with `/`
/// separators, text), sorted by path.
fn read_tree(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|error| format!("read {}: {error}", current.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("read {}: {error}", current.display()))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                let relative = path
                    .strip_prefix(dir)
                    .map_err(|error| error.to_string())?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .map_err(|error| format!("read {}: {error}", path.display()))?;
                found.push((relative, text));
            }
        }
    }
    found.sort();
    Ok(found)
}

async fn import(url: &str, api_key: Option<String>, dir: &Path) -> Result<(), String> {
    let files: Vec<Value> = read_tree(dir)?
        .into_iter()
        .map(|(path, text)| json!({ "path": path, "text": text }))
        .collect();
    let count = files.len();
    let response = authorised(
        client()?
            .post(format!("{url}/api/v1/admin/model/import"))
            .json(&json!({ "files": files })),
        api_key.as_deref(),
    )
    .send()
    .await
    .map_err(|error| format!("reach {url}: {error}"))?;
    let body = answer(response).await?;
    let drafts = body["drafts"].as_array().map_or(0, Vec::len);
    println!("imported {count} file(s) as {drafts} draft(s); publish them to make them live");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn metadata_subcommands_parse() {
        let export = parse(&args(&[
            "export",
            "--out",
            "meta",
            "--url",
            "http://host:1/",
            "--api-key",
            "p:s",
        ]))
        .expect("export parses");
        assert_eq!(
            export,
            ModelCommand::Export {
                url: "http://host:1".into(),
                api_key: Some("p:s".into()),
                out: PathBuf::from("meta"),
            }
        );
        let import =
            parse(&args(&["import", "--dir", "meta", "--url", "http://h"])).expect("import parses");
        assert!(matches!(import, ModelCommand::Import { ref dir, .. } if dir == Path::new("meta")));
        assert!(parse(&args(&["export"])).is_err(), "--out is required");
        assert!(
            parse(&args(&["import", "--out", "x"])).is_err(),
            "import takes --dir"
        );
        assert!(parse(&args(&["publish"])).is_err());
    }

    #[test]
    fn unsafe_paths_are_refused() {
        assert!(safe_relative("form/customer/a.json").is_some());
        assert!(safe_relative("../etc/passwd").is_none());
        assert!(safe_relative("/abs/a.json").is_none());
    }
}

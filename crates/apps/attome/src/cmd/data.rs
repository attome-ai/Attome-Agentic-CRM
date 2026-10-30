//! T4-T4: `attome data query|export|import` — records through a deployment's
//! API as the signed-in person (`--target`, T4-T1) or an API key (`--url`,
//! `--api-key`), with the same access as anywhere else.
//!
//! - `attome data query <entity> [--where field=value]... [--fields a,b]
//!   [--limit N] [--format table|csv|json]` runs `POST /api/v1/query/execute`
//!   and prints the rows. `--format json` prints
//!   `{"schema_version": 1, "columns": [...], "rows": [...], "total": N}`.
//! - `attome data export <entity> --out <file> [--format csv|xlsx|json|parquet]
//!   [--where field=value]...` asks for an export (`POST /api/v1/{entity}/export`),
//!   waits for it and downloads the file.
//! - `attome data import <entity> --file <csv|xlsx>` uploads a file to
//!   `POST /api/v1/{entity}/imports`, which stages it; the import is then
//!   reviewed and applied in the app or its API.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::cmd::login::{Auth, credentials};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
/// The schema version of `--format json` output (T4-T5).
pub const JSON_SCHEMA_VERSION: u32 = 1;
const MAX_LIMIT: u32 = 1_000;

const USAGE: &str = "usage: attome data query <entity> [--where field=value]... [--fields a,b] [--limit N] [--format table|csv|json]\n       attome data export <entity> --out <file> [--format csv|xlsx|json|parquet] [--where field=value]...\n       attome data import <entity> --file <csv|xlsx>\n  each with [--target <name> | --url <url> [--api-key <key>]]";

/// How rows are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Csv,
    Json,
}

/// A parsed `attome data` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCommand {
    Query {
        entity: String,
        filters: Vec<(String, String)>,
        fields: Vec<String>,
        limit: u32,
        format: Format,
    },
    Export {
        entity: String,
        filters: Vec<(String, String)>,
        out: PathBuf,
        format: String,
    },
    Import {
        entity: String,
        file: PathBuf,
    },
}

/// Where and as whom a command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub url: String,
    pub api_key: Option<String>,
    pub target: Option<String>,
}

fn logical(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parses the arguments after `attome data`. Pure.
pub fn parse(args: &[String]) -> Result<(DataCommand, Connection), String> {
    let (verb, rest) = args.split_first().ok_or_else(|| USAGE.to_owned())?;
    let (entity, rest) = rest.split_first().ok_or_else(|| USAGE.to_owned())?;
    if !logical(entity) {
        return Err(format!("`{entity}` is not an entity name\n{USAGE}"));
    }
    let mut connection = Connection {
        url: std::env::var("ATTOME_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned()),
        api_key: std::env::var("ATTOME_API_KEY").ok(),
        target: None,
    };
    let mut filters = Vec::new();
    let mut fields = Vec::new();
    let mut limit = 100;
    let mut format: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut file: Option<PathBuf> = None;
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match (verb.as_str(), flag.as_str()) {
            (_, "--url") => connection.url = value()?,
            (_, "--api-key") => connection.api_key = Some(value()?),
            (_, "--target") => connection.target = Some(value()?),
            ("query" | "export", "--where") => {
                let pair = value()?;
                let (field, wanted) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--where takes field=value, not `{pair}`"))?;
                if !logical(field) {
                    return Err(format!("`{field}` is not a field name"));
                }
                filters.push((field.to_owned(), wanted.to_owned()));
            }
            ("query", "--fields") => {
                fields = value()?
                    .split(',')
                    .map(|f| f.trim().to_owned())
                    .filter(|f| !f.is_empty())
                    .collect();
                if let Some(bad) = fields.iter().find(|f| !logical(f)) {
                    return Err(format!("`{bad}` is not a field name"));
                }
            }
            ("query", "--limit") => {
                limit = value()?
                    .parse::<u32>()
                    .map_err(|_| "--limit is a number".to_owned())?
                    .clamp(1, MAX_LIMIT);
            }
            ("query" | "export", "--format") => format = Some(value()?),
            ("export", "--out") => out = Some(PathBuf::from(value()?)),
            ("import", "--file") => file = Some(PathBuf::from(value()?)),
            _ => return Err(format!("unknown flag `{flag}`\n{USAGE}")),
        }
    }
    connection.url = connection.url.trim_end_matches('/').to_owned();
    let entity = entity.clone();
    let command = match verb.as_str() {
        "query" => DataCommand::Query {
            entity,
            filters,
            fields,
            limit,
            format: match format.as_deref().unwrap_or("table") {
                "table" => Format::Table,
                "csv" => Format::Csv,
                "json" => Format::Json,
                other => return Err(format!("--format is table, csv or json, not `{other}`")),
            },
        },
        "export" => {
            let format = format.unwrap_or_else(|| "csv".to_owned());
            if !matches!(format.as_str(), "csv" | "xlsx" | "json" | "parquet") {
                return Err(format!(
                    "--format is csv, xlsx, json or parquet, not `{format}`"
                ));
            }
            DataCommand::Export {
                entity,
                filters,
                out: out.ok_or_else(|| format!("--out is required\n{USAGE}"))?,
                format,
            }
        }
        "import" => DataCommand::Import {
            entity,
            file: file.ok_or_else(|| format!("--file is required\n{USAGE}"))?,
        },
        _ => return Err(USAGE.to_owned()),
    };
    Ok((command, connection))
}

/// The `query/execute` request for a query command. Pure.
pub fn query_body(entity: &str, filters: &[(String, String)], limit: u32) -> Value {
    json!({
        "entity": entity,
        "page": 1,
        "page_size": limit,
        "search": "",
        "order_by": "",
        "order_dir": "asc",
        "filters": filters
            .iter()
            .map(|(field, value)| json!({ "field": field, "op": "eq", "value": value }))
            .collect::<Vec<_>>(),
        "include_total": true,
    })
}

/// The columns to print: `fields` when given, else the answer's own
/// (`data.columns[].name`), else the first row's keys. Pure.
pub fn columns_of(answer: &Value, fields: &[String]) -> Vec<String> {
    if !fields.is_empty() {
        return fields.to_vec();
    }
    let named: Vec<String> = answer["data"]["columns"]
        .as_array()
        .map(|cols| {
            cols.iter()
                .filter_map(|c| c["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if !named.is_empty() {
        return named;
    }
    answer["data"]["records"][0]
        .as_object()
        .map(|row| row.keys().cloned().collect())
        .unwrap_or_default()
}

/// A cell as text: strings as they are, null as empty, the rest as JSON. Pure.
fn cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A CSV field, quoted when it holds a comma, quote or line break (RFC 4180). Pure.
fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// `answer`'s rows in `format`. Pure.
pub fn render(answer: &Value, columns: &[String], format: Format) -> String {
    let rows: Vec<&Value> = answer["data"]["records"]
        .as_array()
        .map(|r| r.iter().collect())
        .unwrap_or_default();
    match format {
        Format::Json => {
            let rows: Vec<Value> = rows
                .iter()
                .map(|row| {
                    let mut object = serde_json::Map::new();
                    for c in columns {
                        object.insert(c.clone(), row[c].clone());
                    }
                    Value::Object(object)
                })
                .collect();
            json!({
                "schema_version": JSON_SCHEMA_VERSION,
                "columns": columns,
                "rows": rows,
                "total": answer["data"]["total"],
            })
            .to_string()
        }
        Format::Csv => {
            let mut out = columns
                .iter()
                .map(|c| csv_field(c))
                .collect::<Vec<_>>()
                .join(",");
            for row in rows {
                out.push('\n');
                out.push_str(
                    &columns
                        .iter()
                        .map(|c| csv_field(&cell(&row[c])))
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            out
        }
        Format::Table => {
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| {
                    columns
                        .iter()
                        .map(|c| cell(&row[c]).replace(['\n', '\r', '\t'], " "))
                        .collect()
                })
                .collect();
            let widths: Vec<usize> = columns
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    cells
                        .iter()
                        .map(|r| r[i].chars().count())
                        .chain(std::iter::once(c.chars().count()))
                        .max()
                        .unwrap_or(0)
                        .min(60)
                })
                .collect();
            let line = |values: Vec<String>| {
                values
                    .iter()
                    .zip(&widths)
                    .map(|(v, w)| {
                        let shown: String = v.chars().take(*w).collect();
                        format!("{shown:<w$}", w = *w)
                    })
                    .collect::<Vec<_>>()
                    .join("  ")
                    .trim_end()
                    .to_owned()
            };
            let mut out = line(columns.to_vec());
            for row in cells {
                out.push('\n');
                out.push_str(&line(row));
            }
            out
        }
    }
}

/// A `multipart/form-data` body with one `file` part. Pure.
pub fn multipart(boundary: &str, filename: &str, content_type: &str, bytes: &[u8]) -> Vec<u8> {
    let safe_name: String = filename
        .chars()
        .filter(|c| !matches!(c, '"' | '\r' | '\n' | '\\'))
        .collect();
    let mut body = Vec::with_capacity(bytes.len() + 256);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// Runs `attome data ...`.
pub fn run(args: &[String]) -> Result<(), String> {
    let (command, connection) = parse(args)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        let (url, auth) =
            credentials(connection.url, connection.api_key, connection.target).await?;
        match command {
            DataCommand::Query {
                entity,
                filters,
                fields,
                limit,
                format,
            } => {
                let answer = send(
                    &url,
                    &auth,
                    reqwest::Method::POST,
                    "/api/v1/query/execute",
                    Some(query_body(&entity, &filters, limit)),
                )
                .await?;
                let columns = columns_of(&answer, &fields);
                println!("{}", render(&answer, &columns, format));
                Ok(())
            }
            DataCommand::Export {
                entity,
                filters,
                out,
                format,
            } => export(&url, &auth, &entity, &filters, &out, &format).await,
            DataCommand::Import { entity, file } => import(&url, &auth, &entity, &file).await,
        }
    })
}

/// `url` is the operator's own deployment, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-data").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(120)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

fn with_auth(request: reqwest::RequestBuilder, auth: &Auth) -> reqwest::RequestBuilder {
    match auth {
        Some(value) => request.header("authorization", value),
        None => request,
    }
}

async fn send(
    url: &str,
    auth: &Auth,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = with_auth(client(url)?.request(method, format!("{url}{path}")), auth);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("the server answered {status}: {body}"))
    }
}

async fn export(
    url: &str,
    auth: &Auth,
    entity: &str,
    filters: &[(String, String)],
    out: &std::path::Path,
    format: &str,
) -> Result<(), String> {
    let filter: Vec<Value> = filters
        .iter()
        .map(|(field, value)| json!({ "field": field, "op": "eq", "value": value }))
        .collect();
    let started = send(
        url,
        auth,
        reqwest::Method::POST,
        &format!("/api/v1/{entity}/export"),
        Some(json!({ "filter": filter, "format": format })),
    )
    .await?;
    let id = started["id"]
        .as_str()
        .ok_or("the server sent no export id")?;
    println!(
        "export {id} accepted: {} row(s)",
        started["matching_rows"].as_i64().unwrap_or(0)
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30 * 60);
    let download = loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let state = send(
            url,
            auth,
            reqwest::Method::GET,
            &format!("/api/v1/{entity}/export/{id}"),
            None,
        )
        .await?;
        match state["status"].as_str() {
            Some("completed" | "done" | "succeeded") => {
                break state["download_url"]
                    .as_str()
                    .ok_or("the export finished without a download link")?
                    .to_owned();
            }
            Some("failed" | "cancelled") => {
                return Err(format!(
                    "the export failed: {}",
                    state["error"].as_str().unwrap_or("no reason given")
                ));
            }
            _ if std::time::Instant::now() > deadline => {
                return Err(format!(
                    "the export did not finish in 30 minutes; check `/api/v1/{entity}/export/{id}`"
                ));
            }
            _ => {}
        }
    };
    // A presigned link carries its own authority; a deployment-local one
    // (`/api/v1/storage/local`) is on the same server.
    let link = if download.starts_with('/') {
        format!("{url}{download}")
    } else {
        download
    };
    let bytes = client(url)?
        .get(&link)
        .send()
        .await
        .map_err(|error| format!("download the export: {error}"))?
        .error_for_status()
        .map_err(|error| format!("download the export: {error}"))?
        .bytes()
        .await
        .map_err(|error| format!("download the export: {error}"))?;
    std::fs::write(out, &bytes).map_err(|error| format!("write {}: {error}", out.display()))?;
    println!("wrote {} ({} bytes)", out.display(), bytes.len());
    Ok(())
}

async fn import(
    url: &str,
    auth: &Auth,
    entity: &str,
    file: &std::path::Path,
) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|error| format!("read {}: {error}", file.display()))?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "import.csv".to_owned());
    let content_type = if name.to_ascii_lowercase().ends_with(".xlsx") {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    } else {
        "text/csv"
    };
    let boundary = format!("attome-{}", uuid::Uuid::now_v7().simple());
    let response = with_auth(
        client(url)?
            .post(format!("{url}/api/v1/{entity}/imports"))
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(multipart(&boundary, &name, content_type, &bytes)),
        auth,
    )
    .send()
    .await
    .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    if !status.is_success() {
        return Err(format!("the server answered {status}: {body}"));
    }
    println!(
        "import {} {}: review and apply it in the app, or at /api/v1/{entity}/imports/{}",
        body["id"].as_str().unwrap_or("?"),
        body["status"].as_str().unwrap_or("accepted"),
        body["id"].as_str().unwrap_or("?"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn data_commands_parse() {
        let (command, connection) = parse(&args(&[
            "query",
            "account",
            "--where",
            "industry=retail",
            "--fields",
            "name,industry",
            "--limit",
            "5000",
            "--format",
            "json",
            "--target",
            "prod",
        ]))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            command,
            DataCommand::Query {
                entity: "account".into(),
                filters: vec![("industry".into(), "retail".into())],
                fields: vec!["name".into(), "industry".into()],
                limit: MAX_LIMIT,
                format: Format::Json,
            }
        );
        assert_eq!(connection.target.as_deref(), Some("prod"));
        assert!(parse(&args(&["query", "Account; drop"])).is_err());
        assert!(parse(&args(&["query", "account", "--where", "nofield"])).is_err());
        assert!(
            parse(&args(&["export", "account"])).is_err(),
            "--out is required"
        );
        assert!(
            parse(&args(&[
                "export", "account", "--out", "a", "--format", "pdf"
            ]))
            .is_err()
        );
        assert!(matches!(
            parse(&args(&["import", "lead", "--file", "leads.csv"])),
            Ok((DataCommand::Import { .. }, _))
        ));
    }

    #[test]
    fn rows_print_as_a_table_csv_or_versioned_json() {
        let answer = json!({ "data": {
            "columns": [{ "name": "name" }, { "name": "note" }],
            "records": [{ "name": "Acme", "note": "a, \"b\"" }, { "name": "Globex", "note": null }],
            "total": 2
        } });
        let columns = columns_of(&answer, &[]);
        assert_eq!(columns, vec!["name", "note"]);
        assert_eq!(
            render(&answer, &columns, Format::Csv),
            "name,note\nAcme,\"a, \"\"b\"\"\"\nGlobex,"
        );
        let table = render(&answer, &columns, Format::Table);
        assert!(table.starts_with("name    note"), "{table}");
        let parsed: Value =
            serde_json::from_str(&render(&answer, &columns, Format::Json)).unwrap_or(Value::Null);
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["rows"][1]["name"], "Globex");
        assert_eq!(parsed["total"], 2);
        assert_eq!(
            query_body("account", &[("a".into(), "1".into())], 5)["filters"][0]["op"],
            "eq"
        );
    }

    #[test]
    fn an_upload_is_one_file_part() {
        let body = multipart("b1", "le\"ads.csv", "text/csv", b"name\nA");
        let text = String::from_utf8_lossy(&body);
        assert!(text.starts_with(
            "--b1\r\nContent-Disposition: form-data; name=\"file\"; filename=\"leads.csv\""
        ));
        assert!(text.ends_with("name\nA\r\n--b1--\r\n"));
    }
}

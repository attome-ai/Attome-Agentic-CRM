//! AB3-T9 (V2-D1933): `attome drill recover compare` and `copy-back`, what a
//! side-copy recovery (`drill recover --side-copy`) is for: see which records
//! differ from live, and put chosen ones back through the API.
//!
//! ```text
//! attome drill recover compare   --side-copy <database> --entity <name> --live-url <url>
//!                                --api-key-file <path> --out <csv> [--config <path>]
//! attome drill recover copy-back --side-copy <database> --entity <name> --ids <file>
//!                                --live-url <url> --api-key-file <path> [--config <path>]
//! ```
//!
//! The side copy is read with SQL (it is a throwaway database, not the
//! deployment's); the live deployment is only ever reached through its HTTP
//! API (API-first): a paged read of `id` and `row_version`, and
//! `POST /api/v1/{entity}/bulk`, 500 records at a time, each batch with an
//! `Idempotency-Key` that is the same on a retry.
//!
//! The side database is named (`--side-copy`) and opened with the
//! configuration's own server and credentials, as part 1 did, rather than
//! taking a database URL with a password on the command line (V2-D1933).
//!
//! `compare` lists, in the CSV (`id,kind,side_row_version,live_row_version`),
//! `changed` (both sides, different `row_version`), `missing_in_live` (in the
//! side copy only) and `new_in_live` (in live only; never touched).
//!
//! `copy-back` handles exactly the ids of `--ids` (one per line, or a compare
//! CSV): a `changed` record is sent as an `update` with the live row version
//! as `expected_row_version`, so it fails rather than overwrite a newer edit; a
//! `missing_in_live` record is sent as a `create`. The bulk route cannot create
//! with a given id (V2-D1933), so a re-created record has a new id. System
//! columns and hidden `__bidx` columns are not sent; a sealed attribute's
//! stored value is not a plain value and is left out too.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome drill recover compare --side-copy <database> --entity <name> --live-url <url> --api-key-file <path> --out <csv> [--config <path>]\n       attome drill recover copy-back --side-copy <database> --entity <name> --ids <file> --live-url <url> --api-key-file <path> [--config <path>]";

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_FAILED: u8 = 3;

/// Records per bulk request (the route's own limit).
pub const BATCH: usize = 500;
/// Records per page of the live read.
const PAGE_SIZE: usize = 100;
/// A guard on the live read: pages, not records.
const MAX_PAGES: usize = 100_000;

/// What the two sides disagree about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// Both sides, different `row_version`: `(id, side, live)`.
    pub changed: Vec<(Uuid, i64, i64)>,
    /// In the side copy only: `(id, side)`.
    pub missing_in_live: Vec<(Uuid, i64)>,
    /// In live only: `(id, live)`.
    pub new_in_live: Vec<(Uuid, i64)>,
}

/// Classifies each id by where it is and whether its `row_version` differs.
/// Sorted by id. Pure.
pub fn classify(side: &[(Uuid, i64)], live: &[(Uuid, i64)]) -> Diff {
    let side: BTreeMap<Uuid, i64> = side.iter().copied().collect();
    let live: BTreeMap<Uuid, i64> = live.iter().copied().collect();
    let mut diff = Diff::default();
    for (id, s) in &side {
        match live.get(id) {
            Some(l) if l != s => diff.changed.push((*id, *s, *l)),
            Some(_) => {}
            None => diff.missing_in_live.push((*id, *s)),
        }
    }
    for (id, l) in &live {
        if !side.contains_key(id) {
            diff.new_in_live.push((*id, *l));
        }
    }
    diff
}

/// The compare CSV. Pure.
pub fn diff_csv(diff: &Diff) -> String {
    let mut out = String::from("id,kind,side_row_version,live_row_version\n");
    for (id, s, l) in &diff.changed {
        out.push_str(&format!("{id},changed,{s},{l}\n"));
    }
    for (id, s) in &diff.missing_in_live {
        out.push_str(&format!("{id},missing_in_live,{s},\n"));
    }
    for (id, l) in &diff.new_in_live {
        out.push_str(&format!("{id},new_in_live,,{l}\n"));
    }
    out
}

/// The ids of an ids file: the first field of each line that is a UUID (so a
/// compare CSV works, its header and blank lines are skipped), once each, in
/// file order. `new_in_live` rows of a compare CSV are left out: there is
/// nothing to copy back. Pure.
pub fn parse_ids(text: &str) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(',').map(str::trim);
        let Some(first) = fields.next() else { continue };
        if fields.next() == Some("new_in_live") {
            continue;
        }
        if let Ok(id) = Uuid::parse_str(first)
            && seen.insert(id)
        {
            ids.push(id);
        }
    }
    ids
}

/// One batch's `Idempotency-Key`: the same ids of the same entity give the
/// same key, so a retry of a half-done copy-back is not applied twice. Pure.
pub fn batch_key(entity: &str, operation: &str, ids: &[Uuid]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entity.as_bytes());
    hasher.update([0]);
    hasher.update(operation.as_bytes());
    for id in ids {
        hasher.update([0]);
        hasher.update(id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    format!("drill-copy-back-{}", Uuid::from_bytes(bytes))
}

/// A side-copy row as the bulk route takes it: the row object without system
/// columns and hidden `__bidx` columns. Pure.
pub fn record_data(row: &Value) -> Value {
    let mut data = serde_json::Map::new();
    if let Some(map) = row.as_object() {
        for (key, value) in map {
            if attome_core::ALL_SYSTEM_COLS.contains(&key.as_str())
                || key == "row_version"
                || key.ends_with("__bidx")
            {
                continue;
            }
            data.insert(key.clone(), value.clone());
        }
    }
    Value::Object(data)
}

/// The bulk request bodies for the ids to copy back: updates for ids live
/// still holds (with live's row version), creates for the rest, each at most
/// [`BATCH`] records. Never holds an id that was not asked for. Pure.
pub fn bulk_batches(
    entity: &str,
    ids: &[Uuid],
    side_rows: &BTreeMap<Uuid, Value>,
    live: &BTreeMap<Uuid, i64>,
) -> Vec<(String, Value, usize)> {
    let mut updates: Vec<(Uuid, Value)> = Vec::new();
    let mut creates: Vec<(Uuid, Value)> = Vec::new();
    for id in ids {
        let Some(row) = side_rows.get(id) else {
            continue;
        };
        match live.get(id) {
            Some(version) => updates.push((
                *id,
                json!({ "id": id, "expected_row_version": version, "data": record_data(row) }),
            )),
            None => creates.push((*id, json!({ "data": record_data(row) }))),
        }
    }
    let mut batches = Vec::new();
    for (operation, records) in [("update", updates), ("create", creates)] {
        for chunk in records.chunks(BATCH) {
            let chunk_ids: Vec<Uuid> = chunk.iter().map(|(id, _)| *id).collect();
            let body = json!({
                "operation": operation,
                "batch_mode": "partial",
                "records": chunk.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>(),
            });
            batches.push((batch_key(entity, operation, &chunk_ids), body, chunk.len()));
        }
    }
    batches
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    side_copy: String,
    entity: String,
    live_url: String,
    api_key_file: PathBuf,
    out: Option<PathBuf>,
    ids: Option<PathBuf>,
    config: Option<String>,
}

fn parse_args(args: &[String], copy_back: bool) -> Result<Args, String> {
    let mut args = args.to_vec();
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required"));
    let side_copy = need(take_value(&mut args, "--side-copy")?, "--side-copy")?;
    let entity = need(take_value(&mut args, "--entity")?, "--entity")?;
    let live_url = need(take_value(&mut args, "--live-url")?, "--live-url")?;
    let api_key_file = need(take_value(&mut args, "--api-key-file")?, "--api-key-file")?;
    let out = take_value(&mut args, "--out")?;
    let ids = take_value(&mut args, "--ids")?;
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    if !attome_db::ident::is_identifier(&entity) {
        return Err(format!(
            "--entity {entity}: letters, digits and underscores only"
        ));
    }
    if !attome_db::ident::is_identifier(&side_copy) {
        return Err(format!(
            "--side-copy {side_copy}: letters, digits and underscores only"
        ));
    }
    if copy_back && ids.is_none() {
        return Err("--ids is required".into());
    }
    if !copy_back && out.is_none() {
        return Err("--out is required".into());
    }
    Ok(Args {
        side_copy,
        entity,
        live_url: live_url.trim_end_matches('/').to_owned(),
        api_key_file: PathBuf::from(api_key_file),
        out: out.map(PathBuf::from),
        ids: ids.map(PathBuf::from),
        config,
    })
}

fn read_key(path: &Path) -> Result<String, String> {
    let key = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = key.trim().to_owned();
    if key.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(key)
}

fn client(base: &str) -> Result<reqwest::Client, String> {
    attome_outbound::http::client(
        attome_outbound::http::Purpose::public("drill_copy_back").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(60)),
    )
    .map_err(|e| e.to_string())
}

/// `(id, row_version)` of every record live holds, paged through the API.
async fn live_versions(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    entity: &str,
) -> Result<Vec<(Uuid, i64)>, String> {
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let response = client
            .get(format!(
                "{base}/api/v1/{entity}?page={page}&page_size={PAGE_SIZE}"
            ))
            .header("authorization", format!("ApiKey {key}"))
            .send()
            .await
            .map_err(|e| format!("read {entity}: {e}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!("reading {entity} page {page} answered {status}"));
        }
        let body: Value = response.json().await.map_err(|e| e.to_string())?;
        let items = body["items"].as_array().cloned().unwrap_or_default();
        for item in &items {
            if let (Some(id), Some(version)) = (
                item["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()),
                item["row_version"].as_i64(),
            ) {
                out.push((id, version));
            }
        }
        let total = body["total"].as_u64().unwrap_or(0) as usize;
        if items.is_empty() || out.len() >= total {
            break;
        }
    }
    Ok(out)
}

async fn side_pool(args: &Args) -> Result<(attome_db::DbPool, attome_config::AppConfig), String> {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(attome_config::AppConfig::config_file_path);
    let config = crate::secret_sources::load_config_from(config_path)
        .await
        .map_err(|e| format!("load the configuration: {e}"))?;
    if args.side_copy == config.database.dbname {
        return Err("--side-copy is the configured (live) database".into());
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(crate::backup::connect_options(&config, &args.side_copy))
        .await
        .map_err(|e| format!("open the side copy: {e}"))?;
    Ok((pool, config))
}

async fn compare(args: Args) -> Result<(), String> {
    let key = read_key(&args.api_key_file)?;
    let (pool, _) = side_pool(&args).await?;
    let table = attome_core::quote_ident(&args.entity);
    let side: Vec<(Uuid, i64)> =
        sqlx::query_as(&format!("SELECT id, row_version FROM {table} ORDER BY id"))
            .fetch_all(&pool)
            .await
            .map_err(|e| format!("read the side copy: {e}"))?;
    pool.close().await;
    let http = client(&args.live_url)?;
    let live = live_versions(&http, &args.live_url, &key, &args.entity).await?;
    let diff = classify(&side, &live);
    let out = args.out.as_ref().ok_or("--out is required")?;
    std::fs::write(out, diff_csv(&diff)).map_err(|e| format!("{}: {e}", out.display()))?;
    println!(
        "{}: {} changed, {} missing in live, {} new in live; wrote {}",
        args.entity,
        diff.changed.len(),
        diff.missing_in_live.len(),
        diff.new_in_live.len(),
        out.display()
    );
    Ok(())
}

async fn copy_back(args: Args) -> Result<(), String> {
    let key = read_key(&args.api_key_file)?;
    let ids_path = args.ids.as_ref().ok_or("--ids is required")?;
    let ids = parse_ids(
        &std::fs::read_to_string(ids_path).map_err(|e| format!("{}: {e}", ids_path.display()))?,
    );
    if ids.is_empty() {
        return Err(format!("{} lists no record id", ids_path.display()));
    }
    let (pool, _) = side_pool(&args).await?;
    let table = attome_core::quote_ident(&args.entity);
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
        "SELECT id, to_jsonb(t) FROM {table} t WHERE id = ANY($1)"
    ))
    .bind(&ids)
    .fetch_all(&pool)
    .await
    .map_err(|e| format!("read the side copy: {e}"))?;
    pool.close().await;
    let side_rows: BTreeMap<Uuid, Value> = rows.into_iter().collect();
    let absent = ids.iter().filter(|id| !side_rows.contains_key(id)).count();
    let http = client(&args.live_url)?;
    let live: BTreeMap<Uuid, i64> = live_versions(&http, &args.live_url, &key, &args.entity)
        .await?
        .into_iter()
        .collect();
    let batches = bulk_batches(&args.entity, &ids, &side_rows, &live);
    let mut sent = 0usize;
    for (idempotency_key, body, count) in batches {
        let response = http
            .post(format!("{}/api/v1/{}/bulk", args.live_url, args.entity))
            .header("authorization", format!("ApiKey {key}"))
            .header("idempotency-key", &idempotency_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("send a batch: {e}"))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(format!(
                "a batch of {count} {} answered {status}; {sent} records were sent before it (rerun with the same ids: sent batches are not applied twice)",
                body["operation"].as_str().unwrap_or("")
            ));
        }
        let answer: Value = response.json().await.unwrap_or(Value::Null);
        println!(
            "{} {count} records: operation {} ({})",
            body["operation"].as_str().unwrap_or(""),
            answer["id"].as_str().unwrap_or("-"),
            answer["status"].as_str().unwrap_or("-")
        );
        sent += count;
    }
    println!(
        "{} sent, {absent} of the listed ids are not in the side copy and were skipped",
        sent
    );
    Ok(())
}

/// `attome drill recover compare|copy-back ...`.
#[tokio::main]
pub async fn run(args: &[String]) -> u8 {
    let (copy_back_mode, rest) = match args.split_first() {
        Some((first, rest)) if first == "compare" => (false, rest),
        Some((first, rest)) if first == "copy-back" => (true, rest),
        _ => {
            eprintln!("attome drill recover: compare or copy-back expected\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let parsed = match parse_args(rest, copy_back_mode) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("attome drill recover: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let result = if copy_back_mode {
        copy_back(parsed).await
    } else {
        compare(parsed).await
    };
    match result {
        Ok(()) => EXIT_OK,
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn compare_classifies_changed_missing_new() {
        let side = [(id(1), 3), (id(2), 5), (id(3), 1)];
        let live = [(id(1), 3), (id(2), 7), (id(4), 2)];
        let d = classify(&side, &live);
        assert_eq!(d.changed, vec![(id(2), 5, 7)]);
        assert_eq!(d.missing_in_live, vec![(id(3), 1)]);
        assert_eq!(d.new_in_live, vec![(id(4), 2)]);
        let csv = diff_csv(&d);
        assert!(csv.starts_with("id,kind,side_row_version,live_row_version\n"));
        assert!(csv.contains(&format!("{},changed,5,7", id(2))));
        assert!(csv.contains(&format!("{},missing_in_live,1,", id(3))));
        assert!(csv.contains(&format!("{},new_in_live,,2", id(4))));
    }

    #[test]
    fn copy_back_sends_only_the_listed_ids() {
        // A compare CSV works as the ids file; new_in_live rows are skipped.
        let csv = format!(
            "id,kind,side_row_version,live_row_version\n{},changed,5,7\n{},new_in_live,,2\n{},missing_in_live,1,\n{}\n",
            id(2),
            id(4),
            id(3),
            id(2)
        );
        let ids = parse_ids(&csv);
        assert_eq!(ids, vec![id(2), id(3)]);
        let rows: BTreeMap<Uuid, Value> = [
            (id(1), json!({ "id": id(1), "name": "unlisted" })),
            (
                id(2),
                json!({ "id": id(2), "row_version": 5, "name": "b", "created_at": "x", "email__bidx": "h" }),
            ),
            (id(3), json!({ "id": id(3), "name": "c" })),
        ]
        .into_iter()
        .collect();
        let live: BTreeMap<Uuid, i64> = [(id(1), 1), (id(2), 7)].into_iter().collect();
        let batches = bulk_batches("account", &ids, &rows, &live);
        assert_eq!(batches.len(), 2);
        let (_, update, n) = &batches[0];
        assert_eq!((update["operation"].as_str(), *n), (Some("update"), 1));
        assert_eq!(update["records"][0]["expected_row_version"], 7);
        assert_eq!(update["records"][0]["data"], json!({ "name": "b" }));
        let (_, create, _) = &batches[1];
        assert_eq!(create["operation"], "create");
        assert!(create["records"][0].get("id").is_none());
        let sent: usize = batches.iter().map(|(_, _, n)| n).sum();
        assert_eq!(sent, 2, "the unlisted id is never sent");
    }

    #[test]
    fn batches_are_500_and_their_keys_are_stable() {
        let ids: Vec<Uuid> = (1..=1200u128).map(id).collect();
        let rows: BTreeMap<Uuid, Value> =
            ids.iter().map(|i| (*i, json!({ "name": "x" }))).collect();
        let none = BTreeMap::new();
        let a = bulk_batches("account", &ids, &rows, &none);
        let b = bulk_batches("account", &ids, &rows, &none);
        assert_eq!(
            a.iter().map(|x| x.2).collect::<Vec<_>>(),
            vec![500, 500, 200]
        );
        assert_eq!(
            a.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
            b.iter().map(|x| x.0.clone()).collect::<Vec<_>>()
        );
        let keys: BTreeSet<&String> = a.iter().map(|x| &x.0).collect();
        assert_eq!(keys.len(), 3, "each batch has its own key");
    }

    #[test]
    fn side_copy_may_not_be_live_and_arguments_are_checked() {
        let words = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let ok = parse_args(
            &words("--side-copy rec --entity account --live-url http://h/ --api-key-file k --out o.csv"),
            false,
        )
        .unwrap();
        assert_eq!(ok.live_url, "http://h");
        assert!(
            parse_args(
                &words("--side-copy rec --entity account --live-url u --api-key-file k"),
                false
            )
            .is_err()
        );
        assert!(
            parse_args(
                &words("--side-copy rec --entity a;b --live-url u --api-key-file k --out o"),
                false
            )
            .is_err()
        );
        assert!(
            parse_args(
                &words("--side-copy rec --entity account --live-url u --api-key-file k"),
                true
            )
            .is_err()
        );
    }
}

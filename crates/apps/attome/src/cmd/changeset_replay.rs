//! Solution 7 Phase 1 (D-785, design `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §6, plan 1.6) — the replay check: an empty database, every platform
//! changeset, then every product/project changeset in the given folders, in
//! order, and the resulting metadata compared with a reference deployment's
//! export. A mismatch blocks a release (`/release-and-deploy`).
//!
//! ```text
//! changeset_replay --changesets <dir> [--changesets <dir> ...]
//!                  [--reference <export.json>] [--export-out <file>]
//!                  [--redis-host <host>] [--redis-port <port>]
//!                  [--maintenance-db <name>] [--keep-database]
//! ```
//!
//! **What it does**
//!
//! 1. Reads every `*.json` under each `--changesets` folder (recursively),
//!    checks each document (`changeset::plan::parse_document`, the Rust
//!    mirror of `scripts/changesets/validate.mjs`) and orders them
//!    (`apply_order`, the mirror of `applyOrder`). Nothing is created when a
//!    document is malformed or the order has a cycle.
//! 2. Creates a throwaway database `attome_replay_<id>` on the configured
//!    PostgreSQL server (never the configured database itself), boots the
//!    platform against it through the real `attome::boot::init` with
//!    (boot applies the compiled platform changesets), and applies every
//!    compiled platform changeset.
//! 3. Plans and applies the folders' changesets through the changeset ledger,
//!    expand then contract, `source = 'replay'`, with the same owner-layer
//!    and dependency checks an admin apply gets (no approval: the database is
//!    thrown away). A blocked operation fails the run with its reason.
//! 4. Exports the scratch database (`bundle::export_bundle`, canonical) and,
//!    with `--reference`, compares it per component and logical key with the
//!    reference deployment's export: `missing` (only in the reference),
//!    `extra` (only in the replay) and `different` (with the differing
//!    properties). `is_customized` is normalised away and `settings` are not
//!    compared (deployment state, §6 "Not compared").
//! 5. Drops the throwaway database (unless `--keep-database`).
//!
//! **The reference is read through the API** (API-first, guidelines §4): it
//! is the body of `GET /api/v1/admin/metadata/export` from the deployment
//! being checked, saved to a file, e.g.
//! `curl -fsS -H "Authorization: ApiKey $ATTOME_API_KEY" https://<host>/api/v1/admin/metadata/export > reference.json`
//! (`ATTOME_API_KEY` = `<atk_pub_…>:<atk_sec_…>`, see `/xrm-access`).
//! The tool never connects to the reference deployment's database.
//!
//! **Environment.** Configuration is read like `server`/`migrate`
//! (`CONFIG_FILE`, or `config.json` / `config.debug.json` under
//! `APP_ENV=debug`). `database.user` must be allowed to `CREATE DATABASE`.
//! `DATABASE_URL` must be unset (under `APP_ENV=debug` it would override the
//! scratch database). The scratch boot uses its own Redis
//! (`--redis-host`/`--redis-port`, defaulting to `TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, e.g. the `test` compose profile's 6380): the metadata
//! registry and its invalidation channels are keyed by name, not by database,
//! so sharing the configured Redis would let the scratch boot overwrite a
//! running server's caches. The tool refuses the configured Redis endpoint.
//!
//! **Not compared yet** (reported on every run): owner layers and the
//! reference rows named by `upsert_record` operations — the export carries
//! neither (design §6 step 5 adds `?include=owner_layers` and a
//! `query/execute` read of the rows).
//!
//! Exit status: 0 no difference (or no `--reference`), 1 differences found,
//! 2 the replay itself failed, 64 bad arguments.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use attome_api::changeset::apply::{self, RunOutcome};
use attome_api::changeset::ledger::{self, ApplySource};
use attome_api::changeset::plan::{self, MAX_PLAN_DOCUMENTS, PlanContext};
use attome_config::AppConfig;
use attome_core::EngineState;
use serde_json::Value;
use sqlx::Connection;

type BoxError = Box<dyn std::error::Error>;

const USAGE: &str = "usage: changeset_replay --changesets <dir> [--changesets <dir> ...] \
     [--reference <export.json>] [--export-out <file>] [--redis-host <host>] \
     [--redis-port <port>] [--maintenance-db <name>] [--keep-database]";

// ── Arguments ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
struct Args {
    changesets: Vec<PathBuf>,
    reference: Option<PathBuf>,
    export_out: Option<PathBuf>,
    redis_host: Option<String>,
    redis_port: Option<u16>,
    maintenance_db: String,
    keep_database: bool,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut out = Args {
        changesets: Vec::new(),
        reference: None,
        export_out: None,
        redis_host: None,
        redis_port: None,
        maintenance_db: "postgres".to_owned(),
        keep_database: false,
    };
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .filter(|v| !v.starts_with("--"))
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "--changesets" => out.changesets.push(PathBuf::from(value("--changesets")?)),
            "--reference" => out.reference = Some(PathBuf::from(value("--reference")?)),
            "--export-out" => out.export_out = Some(PathBuf::from(value("--export-out")?)),
            "--redis-host" => out.redis_host = Some(value("--redis-host")?),
            "--redis-port" => {
                let raw = value("--redis-port")?;
                out.redis_port = Some(
                    raw.parse()
                        .map_err(|_| format!("--redis-port: {raw:?} is not a port"))?,
                );
            }
            "--maintenance-db" => out.maintenance_db = value("--maintenance-db")?,
            "--keep-database" => out.keep_database = true,
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    if out.changesets.is_empty() {
        return Err(format!(
            "at least one --changesets folder is required\n{USAGE}"
        ));
    }
    Ok(out)
}

// ── Reading and ordering the changesets ─────────────────────────────────────

/// Every `*.json` under `dir`, recursively, sorted by path.
fn json_files(dir: &Path, into: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("read {}: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            json_files(&path, into)?;
        } else if path.extension().is_some_and(|ext| ext == "json") {
            into.push(path);
        }
    }
    Ok(())
}

/// Reads, checks and orders every changeset document under `dirs`. Returns
/// the documents' JSON in apply order.
fn ordered_documents(dirs: &[PathBuf]) -> Result<Vec<Value>, String> {
    let mut files = Vec::new();
    for dir in dirs {
        json_files(dir, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err("no *.json changeset files under the given --changesets folders".into());
    }
    let mut values = Vec::with_capacity(files.len());
    let mut docs = Vec::with_capacity(files.len());
    let mut problems = Vec::new();
    for file in &files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("{}: {e}", file.display()));
                continue;
            }
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                problems.push(format!("{}: not JSON: {e}", file.display()));
                continue;
            }
        };
        match plan::parse_document(&value) {
            Ok(doc) => {
                docs.push(doc);
                values.push(value);
            }
            Err(errs) => {
                problems.extend(errs.into_iter().map(|e| format!("{}: {e}", file.display())))
            }
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    let order = plan::apply_order(&docs)?;
    Ok(order.into_iter().map(|i| values[i].clone()).collect())
}

// ── Comparing exports ───────────────────────────────────────────────────────

/// The logical key of each exported component, by bundle section (D-374
/// identity rules). A section missing here fails the comparison loudly
/// (and `every_bundle_section_has_a_key_or_is_not_compared` fails first).
const SECTION_KEYS: &[(&str, &[&str])] = &[
    ("entities", &["logicalname"]),
    ("queries", &["entity", "name"]),
    ("views", &["entity", "name"]),
    ("calendars", &["name"]),
    ("sidebar", &["path"]),
    ("roles", &["name"]),
    ("privileges", &["key"]),
    ("field_security_profiles", &["name"]),
    ("record_sets", &["entity"]),
    ("state_models", &["entity_logicalname"]),
    ("labels", &["object_kind", "object_ref", "locale"]),
    ("relationships", &["name"]),
    ("apps", &["name"]),
    ("rules", &["entity_logicalname", "name"]),
    ("attribute_patches", &["entity", "attribute"]),
];

/// Bundle sections that are deployment state, not configuration (design §6
/// "Not compared").
const NOT_COMPARED: &[&str] = &["settings"];

/// The component name entity attributes are compared under (split out of
/// their entity, so one changed field reads as one difference).
const ATTRIBUTES: &str = "attributes";

/// One difference between the replay and the reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Diff {
    /// In the reference, not produced by the replay.
    Missing { component: String, key: String },
    /// Produced by the replay, not in the reference.
    Extra { component: String, key: String },
    /// In both, with these top-level properties differing.
    Different {
        component: String,
        key: String,
        properties: Vec<String>,
    },
}

impl std::fmt::Display for Diff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { component, key } => write!(f, "missing   {component} {key}"),
            Self::Extra { component, key } => write!(f, "extra     {component} {key}"),
            Self::Different {
                component,
                key,
                properties,
            } => write!(f, "different {component} {key}: {}", properties.join(", ")),
        }
    }
}

fn key_part(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "*".to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|p| key_part(Some(p)))
            .collect::<Vec<_>>()
            .join("/"),
        // An attribute patch's key field is its attribute's logical name.
        Some(Value::Object(o)) => key_part(o.get("logicalname")),
        Some(other) => other.to_string(),
    }
}

fn key_of(item: &Value, fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| key_part(item.get(*f)))
        .collect::<Vec<_>>()
        .join(".")
}

/// Removes `is_customized` everywhere (Phase 3 retires it; design §6).
fn normalise(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("is_customized");
            for v in map.values_mut() {
                normalise(v);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalise),
        _ => {}
    }
}

type Components = BTreeMap<(String, String), Value>;

fn insert_unique(out: &mut Components, component: &str, key: String, item: Value) {
    let mut k = key.clone();
    let mut n = 1;
    while out.contains_key(&(component.to_owned(), k.clone())) {
        n += 1;
        k = format!("{key}#{n}");
    }
    out.insert((component.to_owned(), k), item);
}

/// Every comparable component of an `attome-bundle/v1` export, by
/// `(component, logical key)`.
fn components(export: &Value) -> Result<Components, String> {
    let object = export
        .as_object()
        .ok_or("the export is not a JSON object")?;
    if object.get("format").and_then(Value::as_str) != Some("attome-bundle/v1") {
        return Err("the export is not an attome-bundle/v1 document \
                    (GET /api/v1/admin/metadata/export)"
            .into());
    }
    let mut out = Components::new();
    for (section, items) in object {
        let Some(items) = items.as_array() else {
            continue;
        };
        if NOT_COMPARED.contains(&section.as_str()) {
            continue;
        }
        let fields = SECTION_KEYS
            .iter()
            .find(|(name, _)| name == section)
            .map(|(_, fields)| *fields)
            .ok_or_else(|| {
                format!(
                    "the export has a section `{section}` changeset_replay does not know; \
                     add its logical key to SECTION_KEYS (or NOT_COMPARED)"
                )
            })?;
        for item in items {
            let mut item = item.clone();
            normalise(&mut item);
            let key = key_of(&item, fields);
            if section == "entities"
                && let Some(Value::Array(attrs)) =
                    item.as_object_mut().and_then(|o| o.remove(ATTRIBUTES))
            {
                for attr in attrs {
                    let attr_key = format!("{key}.{}", key_part(attr.get("logicalname")));
                    insert_unique(&mut out, ATTRIBUTES, attr_key, attr);
                }
            }
            insert_unique(&mut out, section, key, item);
        }
    }
    Ok(out)
}

/// The top-level properties whose values differ between two components.
fn differing_properties(a: &Value, b: &Value) -> Vec<String> {
    match (a.as_object(), b.as_object()) {
        (Some(a), Some(b)) => {
            let mut names: Vec<&String> = a.keys().chain(b.keys()).collect();
            names.sort();
            names.dedup();
            names
                .into_iter()
                .filter(|n| a.get(*n) != b.get(*n))
                .cloned()
                .collect()
        }
        _ => vec!["(value)".to_owned()],
    }
}

/// Compares the replay's export with the reference's (design §6 step 6).
fn compare(replayed: &Value, reference: &Value) -> Result<Vec<Diff>, String> {
    let ours = components(replayed)?;
    let theirs = components(reference)?;
    let mut diffs = Vec::new();
    for ((component, key), want) in &theirs {
        match ours.get(&(component.clone(), key.clone())) {
            None => diffs.push(Diff::Missing {
                component: component.clone(),
                key: key.clone(),
            }),
            Some(got) if got != want => diffs.push(Diff::Different {
                component: component.clone(),
                key: key.clone(),
                properties: differing_properties(got, want),
            }),
            Some(_) => {}
        }
    }
    for (component, key) in ours.keys() {
        if !theirs.contains_key(&(component.clone(), key.clone())) {
            diffs.push(Diff::Extra {
                component: component.clone(),
                key: key.clone(),
            });
        }
    }
    diffs.sort();
    Ok(diffs)
}

// ── The scratch database ────────────────────────────────────────────────────

fn scratch_name() -> String {
    let hex = uuid::Uuid::now_v7().simple().to_string();
    format!("attome_replay_{}", &hex[hex.len() - 12..])
}

/// A generated database name: a bare lowercase identifier (it is
/// interpolated into `CREATE`/`DROP DATABASE`, which cannot bind it).
fn is_scratch_name(name: &str) -> bool {
    name.starts_with("attome_replay_")
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A connection to `dbname` on the configured server, as the bootstrap
/// identity.
async fn connect_to(config: &AppConfig, dbname: &str) -> Result<sqlx::PgConnection, BoxError> {
    let mut target = config.clone();
    target.database.dbname = dbname.to_owned();
    target.database.direct_url = None;
    Ok(sqlx::PgConnection::connect(&target.direct_database_url()).await?)
}

async fn create_database(
    config: &AppConfig,
    maintenance_db: &str,
    name: &str,
) -> Result<(), BoxError> {
    if !is_scratch_name(name) {
        return Err(format!("refusing a scratch database name {name:?}").into());
    }
    let mut conn = connect_to(config, maintenance_db).await?;
    // Interpolated: a database name cannot be a bind parameter;
    // `is_scratch_name` pins it to a generated bare identifier.
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&mut conn)
        .await?;
    conn.close().await?;
    Ok(())
}

async fn drop_database(
    config: &AppConfig,
    maintenance_db: &str,
    name: &str,
) -> Result<(), BoxError> {
    if !is_scratch_name(name) {
        return Err(format!("refusing to drop {name:?}: not a scratch database").into());
    }
    let mut conn = connect_to(config, maintenance_db).await?;
    // Interpolated for the same reason as `create_database`.
    sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
        .execute(&mut conn)
        .await?;
    conn.close().await?;
    Ok(())
}

/// The deployment's configuration, pointed at the scratch database and the
/// scratch Redis, booting platform definitions from changesets.
fn scratch_config(
    base: &AppConfig,
    dbname: &str,
    redis_host: &str,
    redis_port: u16,
) -> Result<AppConfig, String> {
    if redis_host == base.cache.host && redis_port == base.cache.port {
        return Err(format!(
            "the scratch boot needs its own Redis: {redis_host}:{redis_port} is the configured \
             cache, and the scratch boot would overwrite a running server's metadata caches \
             (pass --redis-host/--redis-port, e.g. the test profile's 6380)"
        ));
    }
    let mut config = base.clone();
    config.database.dbname = dbname.to_owned();
    config.database.direct_url = None;
    config.database.migrate_on_boot = true;
    config.cache.host = redis_host.to_owned();
    config.cache.port = redis_port;
    config.cache.password = String::new();
    config.cache.tls_enabled = false;
    config.cache.sentinel = None;
    config.cache.roles = Default::default();
    Ok(config)
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// Every module on, in this process only. The scratch database is never
/// served; which modules a deployment switches on is deployment state the
/// replay does not compare (design §6), so a changeset's
/// `requires.modules` must not block it here.
fn every_module(state: &EngineState) {
    state
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
}

/// Plans, queues and applies `chunk` (already in apply order): expand rows,
/// then contract rows.
async fn apply_chunk(state: &EngineState, chunk: &[Value]) -> Result<(usize, usize), BoxError> {
    let ctx = PlanContext {
        source: ApplySource::Replay,
        requested_by: None,
        trusted: false,
    };
    let mut planned = plan::plan(state, chunk, ctx).await?;
    if !planned.plan.applicable {
        let mut reasons = Vec::new();
        for cs in &planned.plan.changesets {
            for b in &cs.blocked {
                reasons.push(format!("{}: {b}", cs.changeset_ref));
            }
            for phase in &cs.phases {
                for op in phase.operations.iter().filter(|o| o.action == "blocked") {
                    reasons.push(format!(
                        "{} #{} {} {}: {}",
                        cs.changeset_ref,
                        op.seq,
                        op.op,
                        op.target,
                        op.reason.as_deref().unwrap_or("blocked")
                    ));
                }
            }
        }
        return Err(format!("the replay plan is blocked:\n  {}", reasons.join("\n  ")).into());
    }
    let already = planned
        .plan
        .changesets
        .iter()
        .filter(|c| c.status == "already_applied")
        .count();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    plan::persist(&mut tx, &mut planned, ctx).await?;
    let ids: Vec<uuid::Uuid> = planned
        .plan
        .apply_ids
        .iter()
        .chain(&planned.plan.contract_apply_ids)
        .copied()
        .collect();
    ledger::mark_queued(&mut tx, &ids, None, None).await?;
    attome_db::tx::commit(tx).await?;
    for id in &ids {
        match apply::run_one(state, *id).await? {
            RunOutcome::Applied(_) => {}
            RunOutcome::NotClaimed => {
                return Err(format!("ledger row {id} could not be claimed").into());
            }
        }
    }
    Ok((ids.len(), already))
}

/// Boots the scratch database, applies everything, and returns its export.
async fn replay_into(
    config: &AppConfig,
    dbname: &str,
    documents: &[Value],
) -> Result<Value, BoxError> {
    let boot = attome::boot::init(config).await?;
    let state = boot.system.state().clone();
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(&state.base.db)
        .await?;
    if current != dbname {
        return Err(format!(
            "the scratch boot is connected to {current:?}, not {dbname:?}; refusing to go on"
        )
        .into());
    }
    every_module(&state);
    attome_api::changeset::boot::apply_platform_changesets(&state).await?;
    println!(
        "platform: {} compiled changesets applied",
        attome_api::changeset::platform_index::PLATFORM_CHANGESETS.len()
    );
    let mut rows = 0;
    for chunk in documents.chunks(MAX_PLAN_DOCUMENTS) {
        let (applied, already) = apply_chunk(&state, chunk).await?;
        rows += applied;
        if already > 0 {
            println!("{already} changeset(s) were already applied (platform folder passed?)");
        }
    }
    println!(
        "replayed {} changeset(s), {rows} ledger row(s) applied",
        documents.len()
    );
    let bundle = attome_api::bundle::export_bundle(&state.base.db).await?;
    let export: Value = serde_json::from_slice(&attome_api::bundle::canonical_json(&bundle))?;
    Ok(export)
}

async fn replay(args: Args) -> Result<bool, BoxError> {
    if std::env::var_os("DATABASE_URL").is_some() {
        return Err(
            "unset DATABASE_URL: under APP_ENV=debug it overrides the database the \
                    replay creates for itself"
                .into(),
        );
    }
    let documents = ordered_documents(&args.changesets)?;
    println!(
        "{} changeset document(s) checked and ordered",
        documents.len()
    );
    let reference = match &args.reference {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            let value: Value = serde_json::from_str(&text)
                .map_err(|e| format!("{}: not JSON: {e}", path.display()))?;
            // Fail on a bad reference before any database exists.
            components(&value).map_err(|e| format!("{}: {e}", path.display()))?;
            Some(value)
        }
        None => None,
    };

    let base = AppConfig::from_file()?;
    base.validate()?;
    let redis_host = args
        .redis_host
        .clone()
        .or_else(|| std::env::var("TEST_REDIS_HOST").ok())
        .unwrap_or_else(|| "localhost".to_owned());
    let redis_port = match args.redis_port {
        Some(p) => p,
        None => std::env::var("TEST_REDIS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .ok_or(
                "pass --redis-port (or set TEST_REDIS_PORT): the scratch boot needs its own Redis",
            )?,
    };
    let dbname = scratch_name();
    let config = scratch_config(&base, &dbname, &redis_host, redis_port)?;

    create_database(&base, &args.maintenance_db, &dbname).await?;
    println!("scratch database {dbname} created");
    let replayed = replay_into(&config, &dbname, &documents).await;
    if args.keep_database {
        println!("scratch database {dbname} kept (--keep-database)");
    } else if let Err(e) = drop_database(&base, &args.maintenance_db, &dbname).await {
        eprintln!("warning: could not drop scratch database {dbname}: {e}");
    }
    let replayed = replayed?;

    if let Some(path) = &args.export_out {
        std::fs::write(path, serde_json::to_vec_pretty(&replayed)?)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("replayed export written to {}", path.display());
    }
    println!(
        "not compared: owner layers and upsert_record reference rows (the export carries \
         neither yet)"
    );
    let Some(reference) = reference else {
        println!("no --reference given: nothing compared");
        return Ok(true);
    };
    let diffs = compare(&replayed, &reference)?;
    if diffs.is_empty() {
        println!("replay check: PASS — the replay equals the reference");
        return Ok(true);
    }
    for d in &diffs {
        println!("{d}");
    }
    println!("replay check: FAIL — {} difference(s)", diffs.len());
    Ok(false)
}

pub fn run() -> ExitCode {
    let args = match parse_args(std::env::args().skip(2)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(64);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    // The boot future is too large for a default thread stack in a debug
    // build (`serve::run` runs on the same 64 MiB stack for the same reason).
    let worker = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("could not start the async runtime: {e}");
                    return ExitCode::from(2);
                }
            };
            match runtime.block_on(replay(args)) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(1),
                Err(e) => {
                    eprintln!("replay failed: {e}");
                    ExitCode::from(2)
                }
            }
        });
    match worker.map(|handle| handle.join()) {
        Ok(Ok(code)) => code,
        _ => {
            eprintln!("the replay thread could not run to completion");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn export(sections: Value) -> Value {
        let mut v = json!({
            "format": "attome-bundle/v1",
            "requires": { "platform_version": ">=0.0.0", "schema_version": 0 },
        });
        for (k, s) in sections.as_object().expect("object") {
            v[k] = s.clone();
        }
        v
    }

    #[test]
    fn every_bundle_section_has_a_key_or_is_not_compared() {
        let minimal = json!({
            "format": "attome-bundle/v1",
            "requires": { "platform_version": ">=0.0.0", "schema_version": 0 }
        });
        let bundle: attome_api::bundle::Bundle =
            serde_json::from_value(minimal).expect("a minimal bundle deserializes");
        let value = serde_json::to_value(&bundle).expect("serializes");
        for (name, v) in value.as_object().expect("object") {
            if v.is_array() {
                assert!(
                    SECTION_KEYS.iter().any(|(s, _)| s == name)
                        != NOT_COMPARED.contains(&name.as_str()),
                    "bundle section `{name}` needs exactly one of a SECTION_KEYS entry or NOT_COMPARED"
                );
            }
        }
        for (name, _) in SECTION_KEYS {
            assert!(
                value.get(*name).is_some_and(Value::is_array),
                "SECTION_KEYS names `{name}`, not a bundle section"
            );
        }
    }

    #[test]
    fn identical_exports_have_no_difference() {
        let a = export(json!({
            "entities": [{ "logicalname": "acme_contract", "display_name": "Contract",
                           "attributes": [{ "logicalname": "title", "field_type": "text" }] }],
            "views": [{ "entity": "acme_contract", "name": "All", "icon": "list" }],
        }));
        assert_eq!(compare(&a, &a.clone()), Ok(vec![]));
    }

    #[test]
    fn missing_extra_and_different_are_reported_per_logical_key() {
        let reference = export(json!({
            "entities": [{ "logicalname": "acme_contract", "display_name": "Contract",
                           "attributes": [
                               { "logicalname": "title", "field_type": "text", "is_required": true },
                               { "logicalname": "amount", "field_type": "decimal" }
                           ] }],
            "roles": [{ "name": "Sales" }],
        }));
        let replayed = export(json!({
            "entities": [{ "logicalname": "acme_contract", "display_name": "Contracts",
                           "attributes": [
                               { "logicalname": "title", "field_type": "text", "is_required": false }
                           ] }],
            "apps": [{ "name": "acme" }],
        }));
        let diffs = compare(&replayed, &reference).expect("compares");
        assert_eq!(
            diffs,
            vec![
                Diff::Missing {
                    component: "attributes".into(),
                    key: "acme_contract.amount".into()
                },
                Diff::Missing {
                    component: "roles".into(),
                    key: "Sales".into()
                },
                Diff::Extra {
                    component: "apps".into(),
                    key: "acme".into()
                },
                Diff::Different {
                    component: "attributes".into(),
                    key: "acme_contract.title".into(),
                    properties: vec!["is_required".into()],
                },
                Diff::Different {
                    component: "entities".into(),
                    key: "acme_contract".into(),
                    properties: vec!["display_name".into()],
                },
            ]
        );
    }

    #[test]
    fn is_customized_and_settings_are_not_compared() {
        let a = export(json!({
            "sidebar": [{ "path": ["Sales", "Contracts"], "is_customized": true }],
            "settings": [{ "key": "ui.theme", "value": "dark" }],
        }));
        let b = export(json!({
            "sidebar": [{ "path": ["Sales", "Contracts"], "is_customized": false }],
            "settings": [{ "key": "ui.theme", "value": "light" }],
        }));
        assert_eq!(compare(&a, &b), Ok(vec![]));
    }

    #[test]
    fn composite_and_null_keys_are_stable() {
        let item = json!({ "entity": null, "name": "Open cases" });
        assert_eq!(key_of(&item, &["entity", "name"]), "*.Open cases");
        let item = json!({ "path": ["A", "B"] });
        assert_eq!(key_of(&item, &["path"]), "A/B");
        let patch =
            json!({ "entity": "service_ticket", "attribute": { "logicalname": "asset_ref" } });
        assert_eq!(
            key_of(&patch, &["entity", "attribute"]),
            "service_ticket.asset_ref"
        );
    }

    #[test]
    fn an_unknown_section_or_format_is_refused() {
        let unknown = export(json!({ "gadgets": [{ "name": "x" }] }));
        assert!(components(&unknown).unwrap_err().contains("gadgets"));
        assert!(components(&json!({ "format": "other" })).is_err());
    }

    #[test]
    fn arguments_parse_and_refuse() {
        let args = parse_args(
            [
                "--changesets",
                "a",
                "--changesets",
                "b",
                "--reference",
                "r.json",
                "--redis-port",
                "6380",
                "--keep-database",
            ]
            .map(String::from),
        )
        .expect("parses");
        assert_eq!(
            args.changesets,
            vec![PathBuf::from("a"), PathBuf::from("b")]
        );
        assert_eq!(args.reference, Some(PathBuf::from("r.json")));
        assert_eq!(args.redis_port, Some(6380));
        assert!(args.keep_database);
        assert_eq!(args.maintenance_db, "postgres");
        assert!(parse_args(Vec::<String>::new()).is_err());
        assert!(parse_args(["--changesets"].map(String::from)).is_err());
        assert!(parse_args(["--changesets", "a", "--redis-port", "x"].map(String::from)).is_err());
        assert!(parse_args(["--bogus"].map(String::from)).is_err());
    }

    #[test]
    fn only_generated_scratch_names_are_created_or_dropped() {
        let name = scratch_name();
        assert!(is_scratch_name(&name), "{name}");
        assert!(!is_scratch_name("attomedb"));
        assert!(!is_scratch_name(
            "attome_replay_x\"; DROP DATABASE attomedb; --"
        ));
    }

    #[test]
    fn the_scratch_config_refuses_the_configured_redis() {
        let mut base: AppConfig = serde_json::from_value(minimal_config()).expect("config");
        base.cache.host = "localhost".into();
        base.cache.port = 6379;
        assert!(scratch_config(&base, "attome_replay_0", "localhost", 6379).is_err());
        let cfg = scratch_config(&base, "attome_replay_0", "localhost", 6380).expect("ok");
        assert_eq!(cfg.database.dbname, "attome_replay_0");
        assert!(cfg.database.direct_url.is_none());
        assert_eq!(cfg.cache.port, 6380);
    }

    #[test]
    fn the_fixture_changesets_check_and_order() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/changesets/fixtures/valid");
        let docs = ordered_documents(&[root]).expect("the valid fixtures check and order");
        assert!(!docs.is_empty());
    }

    fn minimal_config() -> Value {
        json!({
            "app": {
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "attomedb",
                "user": "u", "password": "p", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            },
            "cache": {
                "host": "localhost", "port": 6379, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            },
            "storage": {
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "t", "s3_secret_key": "t",
                "s3_bucket": "b", "s3_use_path_style": true, "s3_verify_ssl": false
            },
            "auth": {
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            },
            "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
            "observability": {
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            },
            "email": {
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "t@t.local",
                "smtp_from_name": "t", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            },
            "google_ai": {
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            },
            "llm_api": {},
            "external_api": {},
            "s2s": { "enabled": false },
            "security": { "bootstrap_admin_email": null }
        })
    }
}

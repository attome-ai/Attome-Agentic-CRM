//! The upgrade rehearsal (roadmap AC4-T7): the previous release's schema,
//! upgraded by this commit's migrations, must boot.
//!
//! Opt-in by `ATTOME_REHEARSAL_SERVER_URL`, a PostgreSQL URL whose role may
//! create databases (the `test` compose profile's server, never a shared
//! one). The step then:
//!
//! 1. finds the previous release tag (the nearest tag before `HEAD`);
//! 2. creates `attomedb_test_rehearsal_<label>` on that server;
//! 3. checks the tag out into a detached worktree under
//!    `target/release-gate/rehearsal/prev`, builds its `attome` and runs its
//!    `attome init` against the throwaway database (the previous schema);
//! 4. runs this commit's `attome init` against the same database (the
//!    upgrade: schema bootstrap and every new migration) and asserts it
//!    exits 0;
//! 5. boots this commit's server on it and waits for `/health/ready`.
//!
//! The database is dropped and the worktree removed on every exit path
//! ([`Cleanup`]). Loading sample data between steps 3 and 4 waits for the
//! AB8 fixture. Without the variable, or without a previous tag, the step
//! says so and passes.
//!
//! **Customer tests (AC5-T11).** With `--customer-tests <dir>` (or
//! `ATTOME_REHEARSAL_CUSTOMER_TESTS`), a folder outside the repository with
//! one subfolder per opted-in customer, each customer then gets its own
//! throwaway database on the same server: this commit's `attome init`
//! (with a rehearsal administrator), its server booted with a throwaway
//! development API key, the customer's configuration pushed from
//! `<customer>/config` (an `attome config pull` folder) and its tests
//! imported from `<customer>/tests.json` (the customer-tests export), then
//! `POST /api/v1/admin/customer-tests/run-all`. A failed test the export
//! marks `blocking` fails the step; any other failure becomes a line in
//! `target/release-gate/<commit>/upgrade-notes.md`. Each database is dropped
//! after its customer's run.

use std::collections::BTreeSet;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::say;

/// The variable naming the server the rehearsal runs on.
pub const SERVER_URL_VAR: &str = "ATTOME_REHEARSAL_SERVER_URL";
/// Every throwaway database's name starts with this.
pub const DATABASE_PREFIX: &str = "attomedb_test_rehearsal_";
/// The port the rehearsed server listens on.
const PORT: &str = "17866";
const READY_WITHIN: Duration = Duration::from_secs(120);
/// AC5-T11: the variable naming the opted-in customers' folder, when
/// `--customer-tests` does not.
pub const CUSTOMER_TESTS_VAR: &str = "ATTOME_REHEARSAL_CUSTOMER_TESTS";
/// The administrator a customer's rehearsal database is created with.
const REHEARSAL_ADMIN: &str = "rehearsal@example.com";
/// The public half of the throwaway API key the customer runs use.
const REHEARSAL_KEY: &str = "atk_pub_rehearsal";

static CUSTOMER_TESTS: OnceLock<PathBuf> = OnceLock::new();

/// AC5-T11: `--customer-tests <dir>`, the opted-in customers' folder.
pub fn set_customer_tests(dir: PathBuf) {
    let _ = CUSTOMER_TESTS.set(dir);
}

fn customer_tests_dir() -> Option<PathBuf> {
    CUSTOMER_TESTS.get().cloned().or_else(|| {
        std::env::var(CUSTOMER_TESTS_VAR)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
    })
}

/// `url` with its database replaced by `database`. Pure.
pub fn with_database(url: &str, database: &str) -> Option<String> {
    let (base, query) = match url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (url, None),
    };
    let scheme_end = base.find("://")? + 3;
    let slash = base[scheme_end..].find('/').map(|i| i + scheme_end);
    let host_part = match slash {
        Some(i) => &base[..i],
        None => base,
    };
    Some(match query {
        Some(query) => format!("{host_part}/{database}?{query}"),
        None => format!("{host_part}/{database}"),
    })
}

/// `name` as a quoted PostgreSQL identifier: in double quotes, with every
/// double quote inside doubled. Pure.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The throwaway database's name for `label` (lowercase letters, digits and
/// underscores only). Pure.
pub fn database_name(label: &str) -> String {
    let clean: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(30)
        .collect();
    format!("{DATABASE_PREFIX}{clean}")
}

fn exe(dir: &Path) -> PathBuf {
    dir.join("debug").join(if cfg!(windows) {
        "attome.exe"
    } else {
        "attome"
    })
}

fn psql(server_url: &str, sql: &str) -> Result<(), String> {
    let status = Command::new("psql")
        .args(["-v", "ON_ERROR_STOP=1", "-q", "-d", server_url, "-c", sql])
        .status()
        .map_err(|error| format!("could not start psql: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("psql exited with {status}"))
    }
}

/// Drops the throwaway database and removes the worktree when it goes out
/// of scope, whichever way the step ends.
struct Cleanup {
    root: PathBuf,
    server_url: String,
    database: String,
    worktree: Option<PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Err(error) = psql(
            &self.server_url,
            &format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote_ident(&self.database)
            ),
        ) {
            eprintln!(
                "    upgrade_rehearsal: could not drop {}: {error}",
                self.database
            );
        }
        if let Some(worktree) = &self.worktree {
            let removed = Command::new("git")
                .args(["worktree", "remove", "--force"])
                .arg(worktree)
                .current_dir(&self.root)
                .status();
            if !removed.is_ok_and(|s| s.success()) {
                eprintln!(
                    "    upgrade_rehearsal: could not remove the worktree {}",
                    worktree.display()
                );
            }
        }
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn run(command: &mut Command, what: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("could not start {what}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} exited with {status}"))
    }
}

fn init(exe: &Path, database_url: &str, out: &Path) -> Result<(), String> {
    init_with(exe, database_url, out, &[])
}

fn init_with(exe: &Path, database_url: &str, out: &Path, extra: &[&str]) -> Result<(), String> {
    run(
        Command::new(exe)
            .args([
                "init",
                "--database-url",
                database_url,
                "--out",
                &out.display().to_string(),
                "--port",
                PORT,
                "--force",
            ])
            .args(extra),
        &format!("{} init", exe.display()),
    )
}

/// Polls `/health/ready` until it answers or [`READY_WITHIN`] passes; an
/// exit of `server` first is an error naming `log`.
fn wait_ready(server: &mut Child, exe: &Path, log: &Path) -> Result<bool, String> {
    let address = format!("127.0.0.1:{PORT}");
    let deadline = Instant::now() + READY_WITHIN;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = server.try_wait() {
            return Err(format!(
                "the upgraded server exited during start-up ({status}); see {}",
                log.display()
            ));
        }
        let probe = Command::new(exe)
            .args(["healthcheck", address.as_str(), "/health/ready"])
            .output();
        if probe.is_ok_and(|out| out.status.success()) {
            return Ok(true);
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the release CLI's own synchronous poll loop"
        )]
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(false)
}

/// The gate step.
pub fn step(root: &Path) -> Result<(), String> {
    let Ok(server_url) = std::env::var(SERVER_URL_VAR) else {
        say(&format!(
            "    upgrade_rehearsal: {SERVER_URL_VAR} is not set; not run"
        ));
        return Ok(());
    };
    // The previous release: the nearest tag before HEAD.
    let Some(previous) = git(root, &["describe", "--tags", "--abbrev=0", "HEAD^"]) else {
        say("    upgrade_rehearsal: no earlier release tag; not run");
        return Ok(());
    };
    let head = git(root, &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "head".into());
    let database = database_name(&head);
    let database_url = with_database(&server_url, &database)
        .ok_or_else(|| format!("{SERVER_URL_VAR} is not a PostgreSQL URL"))?;
    let dir = root.join("target").join("release-gate").join("rehearsal");
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let worktree = dir.join("prev");

    psql(
        &server_url,
        &format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            quote_ident(&database)
        ),
    )?;
    psql(
        &server_url,
        &format!("CREATE DATABASE {}", quote_ident(&database)),
    )?;
    let mut cleanup = Cleanup {
        root: root.to_path_buf(),
        server_url: server_url.clone(),
        database: database.clone(),
        worktree: None,
    };

    // The previous schema, from the previous release's own binary.
    let _ = Command::new("git")
        .args(["worktree", "remove", "--force"])
        .arg(&worktree)
        .current_dir(root)
        .status();
    run(
        Command::new("git")
            .args(["worktree", "add", "--detach"])
            .arg(&worktree)
            .arg(&previous)
            .current_dir(root),
        "git worktree add",
    )?;
    cleanup.worktree = Some(worktree.clone());
    let prev_target = dir.join("prev-target");
    say(&format!("    upgrade_rehearsal: building {previous}"));
    run(
        Command::new("cargo")
            .args(["build", "-p", "attome", "--bin", "attome"])
            .env("CARGO_TARGET_DIR", &prev_target)
            .current_dir(&worktree),
        &format!("cargo build of {previous}"),
    )?;
    init(
        &exe(&prev_target),
        &database_url,
        &dir.join("prev-config.json"),
    )?;

    // The upgrade, with this commit's binary.
    run(
        Command::new("cargo")
            .args(["build", "-p", "attome", "--bin", "attome"])
            .current_dir(root),
        "cargo build -p attome",
    )?;
    let current = exe(&root.join("target"));
    let config = dir.join("config.json");
    init(&current, &database_url, &config)?;

    // It must boot.
    let log = std::fs::File::create(dir.join("serve.log"))
        .map_err(|error| format!("serve.log: {error}"))?;
    let err_log = log
        .try_clone()
        .map_err(|error| format!("serve.log: {error}"))?;
    let mut server = Command::new(&current)
        .arg("serve")
        .env("CONFIG_FILE", &config)
        .current_dir(root)
        .stdout(log)
        .stderr(err_log)
        .spawn()
        .map_err(|error| format!("cannot start attome serve: {error}"))?;
    let ready = wait_ready(&mut server, &current, &dir.join("serve.log"));
    let _ = server.kill();
    let _ = server.wait();
    drop(cleanup);
    if ready? {
        say(&format!(
            "    upgrade_rehearsal: {previous} upgraded to {head} and /health/ready answered 200"
        ));
        match customer_tests_dir() {
            Some(customers) => customer_runs(root, &server_url, &current, &head, &customers),
            None => Ok(()),
        }
    } else {
        Err(format!(
            "the upgraded server did not answer /health/ready within {} s; see {}",
            READY_WITHIN.as_secs(),
            dir.join("serve.log").display()
        ))
    }
}

/// AC5-T11: what one customer's run found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Blocking tests that failed: each fails the step.
    pub blocking: Vec<String>,
    /// Other failed tests, as upgrade-note lines.
    pub notes: Vec<String>,
}

/// Judges a run-all result (`{results: [{name, passed, failures}]}`)
/// against the customer's export (`{tests: [{name, blocking}]}`). Pure.
pub fn judge(customer: &str, export: &Value, run_all: &Value) -> Verdict {
    let blocking: BTreeSet<&str> = export["tests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t["blocking"].as_bool() == Some(true))
        .filter_map(|t| t["name"].as_str())
        .collect();
    let mut verdict = Verdict::default();
    for result in run_all["results"].as_array().into_iter().flatten() {
        if result["passed"].as_bool() == Some(true) {
            continue;
        }
        let name = result["name"].as_str().unwrap_or("(unnamed)");
        let why: Vec<&str> = result["failures"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let line = format!("{customer}: {name}: {}", why.join("; "));
        if blocking.contains(name) {
            verdict.blocking.push(line);
        } else {
            verdict.notes.push(line);
        }
    }
    verdict
}

/// Writes the non-blocking failures to `path` as Markdown, one bullet per
/// failed test; with none, removes a stale file.
pub fn write_upgrade_notes(path: &Path, notes: &[String]) -> Result<(), String> {
    if notes.is_empty() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let mut text = String::from(
        "# Upgrade notes\n\nCustomer tests that failed on the upgraded release without blocking it:\n\n",
    );
    for line in notes {
        text.push_str("- ");
        text.push_str(line);
        text.push('\n');
    }
    std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

/// 64 hex characters from the process's random hash keys: the throwaway
/// API key's secret, for one local run on a database dropped after it.
fn throwaway_secret() -> String {
    (0..4)
        .map(|n: u64| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u64(n);
            format!("{:016x}", hasher.finish())
        })
        .collect()
}

/// `curl` a JSON request to the rehearsed server; the status and the body.
fn curl(
    key: &str,
    method: &str,
    path: &str,
    body: Option<&Path>,
    out: &Path,
) -> Result<(u16, Value), String> {
    let mut command = Command::new("curl");
    command
        .args(["-sS", "-X", method, "-o"])
        .arg(out)
        .args(["-w", "%{http_code}", "-H"])
        .arg(format!("authorization: ApiKey {key}"))
        .args(["-H", "content-type: application/json"]);
    if let Some(body) = body {
        command
            .arg("--data-binary")
            .arg(format!("@{}", body.display()));
    } else {
        command.args(["--data-binary", "{}"]);
    }
    command.arg(format!("http://127.0.0.1:{PORT}{path}"));
    let output = command
        .output()
        .map_err(|error| format!("could not start curl: {error}"))?;
    let code: u16 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| {
            format!(
                "curl {path} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
    let text = std::fs::read_to_string(out).unwrap_or_default();
    Ok((code, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

/// AC5-T11: every customer subfolder of `customers`, each on its own
/// throwaway database; blocking failures fail the step, the rest go to the
/// upgrade notes.
fn customer_runs(
    root: &Path,
    server_url: &str,
    exe: &Path,
    head: &str,
    customers: &Path,
) -> Result<(), String> {
    let mut folders: Vec<PathBuf> = std::fs::read_dir(customers)
        .map_err(|error| format!("--customer-tests {}: {error}", customers.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("tests.json").is_file())
        .collect();
    folders.sort();
    if folders.is_empty() {
        return Err(format!(
            "--customer-tests {}: no subfolder holds a tests.json",
            customers.display()
        ));
    }
    let mut blocking = Vec::new();
    let mut notes = Vec::new();
    for (n, folder) in folders.iter().enumerate() {
        let name = folder
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let verdict = customer_run(
            root,
            server_url,
            exe,
            &format!("{head}_c{n}"),
            folder,
            &name,
        )?;
        say(&format!(
            "    upgrade_rehearsal: customer {name}: {} blocking failure(s), {} note(s)",
            verdict.blocking.len(),
            verdict.notes.len()
        ));
        blocking.extend(verdict.blocking);
        notes.extend(verdict.notes);
    }
    let notes_file = root
        .join("target")
        .join("release-gate")
        .join(head)
        .join("upgrade-notes.md");
    write_upgrade_notes(&notes_file, &notes)?;
    if !notes.is_empty() {
        say(&format!(
            "    upgrade_rehearsal: upgrade notes in {}",
            notes_file.display()
        ));
    }
    if blocking.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "blocking customer tests failed on the upgraded release:\n  {}",
            blocking.join("\n  ")
        ))
    }
}

fn customer_run(
    root: &Path,
    server_url: &str,
    exe: &Path,
    label: &str,
    folder: &Path,
    name: &str,
) -> Result<Verdict, String> {
    let export: Value = serde_json::from_str(
        &std::fs::read_to_string(folder.join("tests.json"))
            .map_err(|error| format!("{name}/tests.json: {error}"))?,
    )
    .map_err(|error| format!("{name}/tests.json: {error}"))?;
    let database = database_name(label);
    let database_url = with_database(server_url, &database)
        .ok_or_else(|| format!("{SERVER_URL_VAR} is not a PostgreSQL URL"))?;
    let dir = root
        .join("target")
        .join("release-gate")
        .join("rehearsal")
        .join(format!("customer-{label}"));
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    psql(
        server_url,
        &format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            quote_ident(&database)
        ),
    )?;
    psql(
        server_url,
        &format!("CREATE DATABASE {}", quote_ident(&database)),
    )?;
    let cleanup = Cleanup {
        root: root.to_path_buf(),
        server_url: server_url.to_owned(),
        database,
        worktree: None,
    };
    let config = dir.join("config.json");
    init_with(exe, &database_url, &config, &["--admin", REHEARSAL_ADMIN])?;

    let secret = throwaway_secret();
    let key = format!("{REHEARSAL_KEY}:{secret}");
    let log_path = dir.join("serve.log");
    let log = std::fs::File::create(&log_path).map_err(|error| format!("serve.log: {error}"))?;
    let err_log = log
        .try_clone()
        .map_err(|error| format!("serve.log: {error}"))?;
    let mut server = Command::new(exe)
        .arg("serve")
        .env("CONFIG_FILE", &config)
        .env("APP_ENV", "debug")
        .env("ATTOME_AGENT_API_SECRET", &secret)
        .env("ATTOME_AGENT_API_PUBLIC_KEY", REHEARSAL_KEY)
        .env("ATTOME_AGENT_API_USER_EMAIL", REHEARSAL_ADMIN)
        .current_dir(root)
        .stdout(log)
        .stderr(err_log)
        .spawn()
        .map_err(|error| format!("cannot start attome serve: {error}"))?;
    let outcome = customer_steps(&mut CustomerRun {
        server: &mut server,
        exe,
        log: &log_path,
        dir: &dir,
        folder,
        name,
        key: &key,
        export: &export,
    });
    let _ = server.kill();
    let _ = server.wait();
    drop(cleanup);
    outcome
}

/// One customer's server, once booted, and what its run reads.
struct CustomerRun<'a> {
    server: &'a mut Child,
    exe: &'a Path,
    log: &'a Path,
    dir: &'a Path,
    folder: &'a Path,
    name: &'a str,
    key: &'a str,
    export: &'a Value,
}

/// Waits for the customer's server, pushes its configuration, imports and
/// runs its tests, and judges them.
fn customer_steps(r: &mut CustomerRun<'_>) -> Result<Verdict, String> {
    let (exe, dir, folder, name, key, export) = (r.exe, r.dir, r.folder, r.name, r.key, r.export);
    let log_path = r.log;
    if !wait_ready(r.server, exe, log_path)? {
        return Err(format!(
            "{name}: the server did not become ready; see {}",
            log_path.display()
        ));
    }
    let configuration = folder.join("config");
    if configuration.is_dir() {
        run(
            Command::new(exe)
                .args(["config", "push", "--dir"])
                .arg(&configuration)
                .args(["--url", &format!("http://127.0.0.1:{PORT}"), "--yes"])
                .env("ATTOME_API_KEY", key),
            &format!("attome config push for {name}"),
        )?;
    }
    let out = dir.join("response.json");
    let (code, body) = curl(
        key,
        "POST",
        "/api/v1/admin/customer-tests/import",
        Some(&folder.join("tests.json")),
        &out,
    )?;
    if code != 200 {
        return Err(format!(
            "{name}: importing the tests answered {code}: {body}"
        ));
    }
    let (code, run_all) = curl(
        key,
        "POST",
        "/api/v1/admin/customer-tests/run-all",
        None,
        &out,
    )?;
    if code != 200 {
        return Err(format!(
            "{name}: running the tests answered {code}: {run_all}"
        ));
    }
    Ok(judge(name, export, &run_all))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_blocking_failure_writes_upgrade_note() {
        let export = serde_json::json!({ "tests": [
            { "name": "orders keep their total", "blocking": true },
            { "name": "lead score label", "blocking": false }
        ] });
        let run_all = serde_json::json!({ "results": [
            { "name": "orders keep their total", "passed": true, "failures": [] },
            { "name": "lead score label", "passed": false, "failures": ["score is 4, expected 5"] }
        ] });
        let verdict = judge("acme", &export, &run_all);
        assert!(verdict.blocking.is_empty());
        assert_eq!(
            verdict.notes,
            vec!["acme: lead score label: score is 4, expected 5"]
        );
        let dir = std::env::temp_dir().join(format!("attome-notes-{}", std::process::id()));
        let path = dir.join("upgrade-notes.md");
        write_upgrade_notes(&path, &verdict.notes).expect("written");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            text.contains("- acme: lead score label: score is 4, expected 5"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // A blocking failure is not a note.
        let failed = serde_json::json!({ "results": [
            { "name": "orders keep their total", "passed": false, "failures": ["total changed"] }
        ] });
        let verdict = judge("acme", &export, &failed);
        assert_eq!(verdict.blocking.len(), 1);
        assert!(verdict.notes.is_empty());
    }

    #[test]
    fn the_throwaway_database_is_named_and_swapped_into_the_url() {
        assert_eq!(database_name("a1B-2"), "attomedb_test_rehearsal_a1b_2");
        assert_eq!(
            with_database(
                "postgres://u:p@localhost:5556/postgres?sslmode=disable",
                "x"
            )
            .as_deref(),
            Some("postgres://u:p@localhost:5556/x?sslmode=disable")
        );
        assert_eq!(
            with_database("postgres://u:p@localhost:5556", "x").as_deref(),
            Some("postgres://u:p@localhost:5556/x")
        );
        assert_eq!(with_database("not a url", "x"), None);
    }
}

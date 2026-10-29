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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::say;

/// The variable naming the server the rehearsal runs on.
pub const SERVER_URL_VAR: &str = "ATTOME_REHEARSAL_SERVER_URL";
/// Every throwaway database's name starts with this.
pub const DATABASE_PREFIX: &str = "attomedb_test_rehearsal_";
/// The port the rehearsed server listens on.
const PORT: &str = "17866";
const READY_WITHIN: Duration = Duration::from_secs(120);

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
    run(
        Command::new(exe).args([
            "init",
            "--database-url",
            database_url,
            "--out",
            &out.display().to_string(),
            "--port",
            PORT,
            "--force",
        ]),
        &format!("{} init", exe.display()),
    )
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
    let address = format!("127.0.0.1:{PORT}");
    let deadline = Instant::now() + READY_WITHIN;
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = server.try_wait() {
            return Err(format!(
                "the upgraded server exited during start-up ({status}); see {}",
                dir.join("serve.log").display()
            ));
        }
        let probe = Command::new(&current)
            .args(["healthcheck", address.as_str(), "/health/ready"])
            .output();
        if probe.is_ok_and(|out| out.status.success()) {
            ready = true;
            break;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the release CLI's own synchronous poll loop"
        )]
        std::thread::sleep(Duration::from_secs(2));
    }
    let _ = server.kill();
    let _ = server.wait();
    drop(cleanup);
    if ready {
        say(&format!(
            "    upgrade_rehearsal: {previous} upgraded to {head} and /health/ready answered 200"
        ));
        Ok(())
    } else {
        Err(format!(
            "the upgraded server did not answer /health/ready within {} s; see {}",
            READY_WITHIN.as_secs(),
            dir.join("serve.log").display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

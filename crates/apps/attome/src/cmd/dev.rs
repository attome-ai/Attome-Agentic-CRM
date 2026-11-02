//! AE2-T2: `attome dev <folder>` — rebuilds an extension whenever its source
//! changes and uploads each good build as a new draft version
//! (`POST /api/v1/admin/extensions`), ready to test
//! (`.../versions/{v}/test`) or publish.
//!
//! The folder holds a Rust crate (`Cargo.toml`) that builds a plain
//! WebAssembly module for `wasm32-unknown-unknown` (the JSON calling
//! convention the hooks use) and `manifest.json` (its grants and hooks). The
//! extension's name is the crate's package name, or `--name`.
//!
//! - Watching polls the files' modification times twice a second with the
//!   standard library alone, on every platform; `target/` and `.git/` are
//!   left out. A change rebuilds once the files stop changing.
//! - A build that fails prints cargo's errors, each with its source lines,
//!   and uploads nothing.
//! - `--once` builds and uploads one time and stops.
//!
//! JavaScript extensions (Javy) are not built here: Y10-T7 is parked.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::Engine;
use serde_json::{Value, json};

use crate::cmd::login::credentials;
use crate::cmd::output::{take_flag, take_value};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const USAGE: &str =
    "usage: attome dev <folder> [--name <name>] [--once]\n         [--target <name> | --url <url>]";
/// How often the folder is looked at.
const POLL: Duration = Duration::from_millis(500);
/// The build target of a plain module.
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// Every file under `dir` with its modification time, `target/` and `.git/`
/// left out.
pub fn snapshot(dir: &Path) -> BTreeMap<PathBuf, SystemTime> {
    let mut files = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if name == "target" || name == ".git" {
                continue;
            }
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => stack.push(path),
                Ok(meta) => {
                    files.insert(path, meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
                }
                Err(_) => {}
            }
        }
    }
    files
}

/// The `[package]` name in a `Cargo.toml`. Pure.
pub fn package_name(cargo_toml: &str) -> Option<String> {
    let mut in_package = false;
    for line in cargo_toml.lines().map(str::trim) {
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package
            && let Some(rest) = line.strip_prefix("name")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return Some(value.trim().trim_matches('"').to_owned());
        }
    }
    None
}

/// Where cargo puts the release module of `crate_name`. Pure.
pub fn wasm_path(folder: &Path, crate_name: &str) -> PathBuf {
    folder
        .join("target")
        .join(WASM_TARGET)
        .join("release")
        .join(format!("{}.wasm", crate_name.replace('-', "_")))
}

/// The errors in cargo's output, each with the source lines cargo shows
/// under it, in order; warnings are left out. Pure.
pub fn build_errors(stderr: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in stderr.lines() {
        let starts = line.starts_with("error") || line.starts_with("warning");
        if (starts || line.trim().is_empty())
            && let Some(block) = current.take()
        {
            errors.push(block.join("\n"));
        }
        if line.starts_with("error") {
            current = Some(vec![line]);
        } else if !starts
            && !line.trim().is_empty()
            && let Some(block) = current.as_mut()
        {
            block.push(line);
        }
    }
    if let Some(block) = current {
        errors.push(block.join("\n"));
    }
    errors
}

struct Dev {
    folder: PathBuf,
    name: String,
    crate_name: String,
    url: String,
    target: Option<String>,
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let once = take_flag(&mut args, "--once");
    let name = take_value(&mut args, "--name")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let target = take_value(&mut args, "--target")?;
    let [folder] = args.as_slice() else {
        return Err(USAGE.to_owned());
    };
    let folder = PathBuf::from(folder);
    let cargo_toml = std::fs::read_to_string(folder.join("Cargo.toml"))
        .map_err(|e| format!("{}: no Cargo.toml: {e}", folder.display()))?;
    let crate_name = package_name(&cargo_toml).ok_or("Cargo.toml names no [package]")?;
    let dev = Dev {
        name: name.unwrap_or_else(|| crate_name.replace('-', "_")),
        crate_name,
        folder,
        url,
        target,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    let mut seen = snapshot(&dev.folder);
    dev.cycle(&runtime);
    if once {
        return Ok(());
    }
    println!("watching {} (Ctrl+C stops)", dev.folder.display());
    loop {
        pause();
        let now = snapshot(&dev.folder);
        if now == seen {
            continue;
        }
        // Let a save that touches several files finish first.
        let mut settled = now;
        loop {
            pause();
            let again = snapshot(&dev.folder);
            if again == settled {
                break;
            }
            settled = again;
        }
        seen = settled;
        dev.cycle(&runtime);
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the watch loop is the command's own thread, outside any async runtime"
)]
fn pause() {
    std::thread::sleep(POLL);
}

impl Dev {
    /// One build and, when it succeeds, one upload. Problems are printed;
    /// the watch goes on.
    fn cycle(&self, runtime: &tokio::runtime::Runtime) {
        println!("building {}", self.crate_name);
        let built = std::process::Command::new("cargo")
            .args(["build", "--release", "--target", WASM_TARGET])
            .current_dir(&self.folder)
            .output();
        let output = match built {
            Ok(output) => output,
            Err(error) => {
                println!("cargo did not start: {error}");
                return;
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let errors = build_errors(&stderr);
            if errors.is_empty() {
                println!("{stderr}");
            }
            for error in errors {
                println!("{error}\n");
            }
            println!("build failed; nothing uploaded");
            return;
        }
        match runtime.block_on(self.upload()) {
            Ok(version) => println!("uploaded {} version {version} as a draft", self.name),
            Err(error) => println!("upload failed: {error}"),
        }
    }

    async fn upload(&self) -> Result<Value, String> {
        let module = std::fs::read(wasm_path(&self.folder, &self.crate_name))
            .map_err(|e| format!("read the built module: {e}"))?;
        let manifest: Value = match std::fs::read_to_string(self.folder.join("manifest.json")) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("manifest.json: {e}"))?,
            Err(_) => json!({}),
        };
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) = credentials(
            self.url.trim_end_matches('/').to_owned(),
            api_key,
            self.target.clone(),
        )
        .await?;
        let body = json!({
            "name": self.name,
            "module_base64": base64::engine::general_purpose::STANDARD.encode(module),
            "manifest": manifest,
        });
        let stored = crate::cmd::package::send(
            &url,
            &auth,
            reqwest::Method::POST,
            "/api/v1/admin/extensions",
            Some(body),
        )
        .await?;
        Ok(stored["version"].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_watch_sees_a_change_and_leaves_target_out() {
        let dir = std::env::temp_dir().join(format!("attome-dev-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("target/wasm32-unknown-unknown")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "// one").unwrap();
        std::fs::write(dir.join("target/wasm32-unknown-unknown/x.wasm"), "x").unwrap();
        let first = snapshot(&dir);
        assert_eq!(first.len(), 1, "target/ is left out: {first:?}");
        std::fs::write(dir.join("src/more.rs"), "// two").unwrap();
        assert_ne!(snapshot(&dir), first);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dev_watch_build_errors_keep_their_source_lines() {
        let stderr = "   Compiling hook v0.1.0\n\
warning: unused variable: `x`\n --> src/lib.rs:2:9\n  |\n2 |     let x = 1;\n  |         ^\n\n\
error[E0308]: mismatched types\n --> src/lib.rs:5:5\n  |\n5 |     \"text\"\n  |     ^^^^^^ expected `i64`, found `&str`\n\n\
error: could not compile `hook` (lib) due to 1 previous error\n";
        let errors = build_errors(stderr);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("error[E0308]: mismatched types"));
        assert!(errors[0].contains("5 |     \"text\""));
        assert!(!errors[0].contains("unused variable"));
        assert!(errors[1].starts_with("error: could not compile"));
    }

    #[test]
    fn dev_watch_finds_the_crate_and_its_module() {
        let toml = "[package]\nname = \"erp-sync\"\nversion = \"0.1.0\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n";
        assert_eq!(package_name(toml).as_deref(), Some("erp-sync"));
        assert_eq!(package_name("[lib]\nname = \"x\"\n"), None);
        assert_eq!(
            wasm_path(Path::new("ext"), "erp-sync"),
            Path::new("ext/target/wasm32-unknown-unknown/release/erp_sync.wasm")
        );
    }
}

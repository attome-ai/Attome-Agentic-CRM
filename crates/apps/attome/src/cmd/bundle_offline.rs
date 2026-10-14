//! Offline bundles for air-gapped installs (roadmap U1-T4).
//!
//! ```text
//! attome bundle offline [--os windows|linux] [--binary <path>] [--web <dist dir>] [--out <dir>]
//! attome bundle verify <dir>
//! attome init --from-bundle <dir> --database-url ...
//! ```
//!
//! `bundle offline` writes a directory holding everything an install needs
//! without network access: the `attome` binary (this one, or `--binary` for
//! the other operating system), the built web app when `--web` points at it,
//! the configuration templates, the documentation and the observability
//! files, plus `manifest.json` with the SHA-256 of every file. The schema
//! travels inside the binary. PostgreSQL 18 with pgvector is not bundled: the
//! README in the bundle says where to get its installer for the target.
//!
//! `bundle verify` (and `init --from-bundle`) recompute every hash and refuse
//! a bundle with a missing, extra or changed file. The manifest is not signed
//! yet; signing waits for the release key (AC4-T9), and `signature` stays
//! `null` until then.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MANIFEST: &str = "manifest.json";
const FORMAT: &str = "attome-offline-bundle/v1";

const USAGE: &str = "\
attome bundle: offline bundles for air-gapped installs

Usage:
  attome bundle offline [--os windows|linux] [--binary <path>] [--web <dist dir>] [--out <dir>]
  attome bundle verify <dir>
";

/// Files copied from the source tree (relative to the workspace root), when present.
const TREE_FILES: [&str; 6] = [
    "README.md",
    "LICENSE",
    "NOTICE",
    "config.example.json",
    "config.production.example.json",
    "docs",
];
const TREE_DIRS: [&str; 1] = ["observability"];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Every file under `dir`, relative, with forward slashes, sorted.
fn files_under(dir: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|error| format!("{}: {error}", current.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(relative);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The manifest for the files in `dir` (the manifest itself excluded).
pub fn manifest(dir: &Path, os: &str) -> Result<Value, String> {
    let mut files = BTreeMap::new();
    for relative in files_under(dir)? {
        if relative == MANIFEST {
            continue;
        }
        let bytes =
            std::fs::read(dir.join(&relative)).map_err(|error| format!("{relative}: {error}"))?;
        files.insert(
            relative,
            json!({ "sha256": sha256_hex(&bytes), "bytes": bytes.len() }),
        );
    }
    Ok(json!({
        "format": FORMAT,
        "version": env!("CARGO_PKG_VERSION"),
        "os": os,
        "files": files,
        "signature": Value::Null,
    }))
}

/// Every problem with the bundle in `dir`; empty when it is intact.
pub fn verify(dir: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(dir.join(MANIFEST))
        .map_err(|error| format!("{}: {error}", dir.join(MANIFEST).display()))?;
    let recorded: Value =
        serde_json::from_str(&text).map_err(|error| format!("{MANIFEST}: {error}"))?;
    if recorded["format"] != FORMAT {
        return Ok(vec![format!("{MANIFEST} is not an {FORMAT} manifest")]);
    }
    let os = recorded["os"].as_str().unwrap_or_default();
    let actual = manifest(dir, os)?;
    let empty = serde_json::Map::new();
    let want = recorded["files"].as_object().unwrap_or(&empty);
    let have = actual["files"].as_object().unwrap_or(&empty);
    let mut problems = Vec::new();
    for (name, entry) in want {
        match have.get(name) {
            None => problems.push(format!("missing: {name}")),
            Some(found) if found["sha256"] != entry["sha256"] => {
                problems.push(format!("changed: {name}"));
            }
            Some(_) => {}
        }
    }
    for name in have.keys() {
        if !want.contains_key(name) {
            problems.push(format!("not in the manifest: {name}"));
        }
    }
    Ok(problems)
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    if from.is_dir() {
        for relative in files_under(from)? {
            let target = to.join(&relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", parent.display()))?;
            }
            std::fs::copy(from.join(&relative), &target)
                .map_err(|error| format!("{relative}: {error}"))?;
        }
    } else {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::copy(from, to).map_err(|error| format!("{}: {error}", from.display()))?;
    }
    Ok(())
}

fn bundle_readme(os: &str) -> String {
    let (postgres, binary) = if os == "windows" {
        (
            "the PostgreSQL 18 Windows installer (EDB) and the pgvector build for it",
            "attome.exe",
        )
    } else {
        (
            "PostgreSQL 18 and pgvector packages for your distribution (postgresql-18, \
             postgresql-18-pgvector)",
            "attome",
        )
    };
    format!(
        "# Attome offline bundle ({os})\n\n\
         1. Check the bundle: `bin/{binary} bundle verify .`\n\
         2. Install {postgres}, carried in separately; this bundle does not include them.\n\
         3. `bin/{binary} init --from-bundle . --database-url postgres://user:password@localhost:5432/attome`\n\
         4. `bin/{binary} service install --dir <directory with config.json>`\n\n\
         The web app, when included, is in `web/`; serve it from any static web server.\n"
    )
}

fn create(os: &str, binary: &Path, web: Option<&Path>, out: &Path) -> Result<(), String> {
    if out.exists() {
        return Err(format!(
            "{} already exists; choose an empty --out",
            out.display()
        ));
    }
    let root = workspace_root()?;
    let exe_name = if os == "windows" {
        "attome.exe"
    } else {
        "attome"
    };
    copy_tree(binary, &out.join("bin").join(exe_name))?;
    if let Some(web) = web {
        copy_tree(web, &out.join("web"))?;
    }
    for name in TREE_FILES.iter().chain(TREE_DIRS.iter()) {
        let from = root.join(name);
        if from.exists() {
            copy_tree(&from, &out.join(name))?;
        }
    }
    std::fs::write(out.join("INSTALL.md"), bundle_readme(os))
        .map_err(|error| format!("INSTALL.md: {error}"))?;
    let manifest = manifest(out, os)?;
    let text = serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    std::fs::write(out.join(MANIFEST), text + "\n")
        .map_err(|error| format!("{MANIFEST}: {error}"))?;
    say(&format!(
        "wrote {} ({} files)",
        out.display(),
        manifest["files"]
            .as_object()
            .map_or(0, serde_json::Map::len)
    ));
    Ok(())
}

/// The workspace root when run from a checkout, else the current directory.
fn workspace_root() -> Result<PathBuf, String> {
    let start = std::env::current_dir().map_err(|error| error.to_string())?;
    Ok(start
        .ancestors()
        .find(|dir| {
            std::fs::read_to_string(dir.join("Cargo.toml"))
                .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        })
        .map_or(start.clone(), Path::to_path_buf))
}

fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(), "{text}");
}

/// Verifies a bundle directory, printing each problem; `Err` when any.
pub fn verify_or_refuse(dir: &Path) -> Result<(), String> {
    let problems = verify(dir)?;
    if problems.is_empty() {
        say(&format!("{} is intact", dir.display()));
        return Ok(());
    }
    Err(format!(
        "the bundle at {} does not match its manifest:\n  {}",
        dir.display(),
        problems.join("\n  ")
    ))
}

/// `attome bundle ...`, from the arguments after `bundle`.
pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [verb, dir] if verb == "verify" => verify_or_refuse(Path::new(dir)),
        [verb, rest @ ..] if verb == "offline" => {
            let mut os = std::env::consts::OS.to_owned();
            let mut binary: Option<PathBuf> = None;
            let mut web: Option<PathBuf> = None;
            let mut out: Option<PathBuf> = None;
            let mut it = rest.iter();
            while let Some(arg) = it.next() {
                let mut value = || {
                    it.next()
                        .cloned()
                        .ok_or_else(|| format!("{arg} needs a value"))
                };
                match arg.as_str() {
                    "--os" => os = value()?,
                    "--binary" => binary = Some(PathBuf::from(value()?)),
                    "--web" => web = Some(PathBuf::from(value()?)),
                    "--out" => out = Some(PathBuf::from(value()?)),
                    _ => return Err(format!("unknown option `{arg}`\n\n{USAGE}")),
                }
            }
            if os != "windows" && os != "linux" {
                return Err(format!("--os must be windows or linux, not `{os}`"));
            }
            let binary = match binary {
                Some(path) => path,
                None if os == std::env::consts::OS => {
                    std::env::current_exe().map_err(|error| error.to_string())?
                }
                None => {
                    return Err(format!(
                        "this binary is for {}; pass --binary with an attome built for {os}",
                        std::env::consts::OS
                    ));
                }
            };
            let out = out.unwrap_or_else(|| {
                PathBuf::from(format!("attome-offline-{}-{os}", env!("CARGO_PKG_VERSION")))
            });
            create(&os, &binary, web.as_deref(), &out)
        }
        _ => Err(USAGE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("attome-bundle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_created_bundle_verifies_and_a_changed_file_does_not() {
        let source = scratch("src");
        std::fs::create_dir_all(source.join("dist/assets")).unwrap();
        std::fs::write(source.join("dist/index.html"), "<html></html>").unwrap();
        std::fs::write(source.join("dist/assets/app.js"), "x").unwrap();
        std::fs::write(source.join("attome"), b"\x7fELF").unwrap();
        let out = scratch("out");

        create(
            "linux",
            &source.join("attome"),
            Some(&source.join("dist")),
            &out,
        )
        .unwrap();
        assert!(out.join("bin/attome").is_file());
        assert!(out.join("web/assets/app.js").is_file());
        assert!(verify(&out).unwrap().is_empty(), "a fresh bundle is intact");

        std::fs::write(out.join("web/assets/app.js"), "tampered").unwrap();
        std::fs::write(out.join("extra.txt"), "x").unwrap();
        std::fs::remove_file(out.join("INSTALL.md")).unwrap();
        let problems = verify(&out).unwrap();
        assert!(problems.contains(&"changed: web/assets/app.js".to_owned()));
        assert!(problems.contains(&"not in the manifest: extra.txt".to_owned()));
        assert!(problems.contains(&"missing: INSTALL.md".to_owned()));
        assert!(verify_or_refuse(&out).is_err());

        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&source);
    }

    #[test]
    fn options_are_checked() {
        assert!(run(&[]).is_err());
        assert!(run(&["offline".into(), "--os".into(), "mac".into()]).is_err());
        assert!(run(&["offline".into(), "--nope".into()]).is_err());
    }
}

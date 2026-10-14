//! The reproducibility check (roadmap AC7-T7), opt-in with
//! `attome release --check --reproducible` because it builds the release
//! binary twice.
//!
//! Both builds use the commit's time as `SOURCE_DATE_EPOCH` and remap the
//! checkout and cargo home paths out of the binary, each into its own target
//! directory (`target/repro-a`, `target/repro-b`). The step passes when the
//! two `attome` binaries have the same SHA-256 and records both hashes in
//! `target/release-gate/repro.json`; a mismatch fails with the two hashes and
//! may be overridden with a reason, since the design asks for reproducible
//! builds where the toolchain allows.

use std::path::Path;
use std::process::Command;

use sha2_free::sha256_file;

/// The `RUSTFLAGS` the two builds share.
pub fn rustflags(repo: &Path, cargo_home: &Path) -> String {
    format!(
        "--remap-path-prefix={}=/src --remap-path-prefix={}=/cargo",
        repo.display(),
        cargo_home.display()
    )
}

fn cargo_home() -> std::path::PathBuf {
    std::env::var_os("CARGO_HOME").map_or_else(
        || {
            let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .unwrap_or_default();
            std::path::PathBuf::from(home).join(".cargo")
        },
        std::path::PathBuf::from,
    )
}

/// The gate step.
pub fn step(root: &Path) -> Result<(), String> {
    let epoch = crate::command_output(root, "git", &["log", "-1", "--format=%ct"])
        .ok_or("cannot read the commit time")?;
    let flags = rustflags(root, &cargo_home());
    let exe = if cfg!(windows) {
        "attome.exe"
    } else {
        "attome"
    };
    let mut hashes = Vec::new();
    for dir in ["repro-a", "repro-b"] {
        let target = root.join("target").join(dir);
        let status = Command::new("cargo")
            .args([
                "build",
                "--release",
                "--locked",
                "-p",
                "attome",
                "--bin",
                "attome",
            ])
            .env("SOURCE_DATE_EPOCH", &epoch)
            .env("RUSTFLAGS", &flags)
            .env("CARGO_TARGET_DIR", &target)
            .current_dir(root)
            .status()
            .map_err(|error| format!("cannot run cargo: {error}"))?;
        if !status.success() {
            return Err(format!("the {dir} release build failed ({status})"));
        }
        hashes.push(sha256_file(&target.join("release").join(exe))?);
    }
    let record = serde_json::json!({
        "source_date_epoch": epoch,
        "a": hashes[0],
        "b": hashes[1],
        "reproducible": hashes[0] == hashes[1],
    });
    let dir = crate::gate_dir(root);
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    std::fs::write(dir.join("repro.json"), record.to_string() + "\n")
        .map_err(|error| format!("repro.json: {error}"))?;
    if hashes[0] == hashes[1] {
        crate::say(&format!(
            "    reproducible: both builds hash to {}",
            hashes[0]
        ));
        Ok(())
    } else {
        Err(format!(
            "the two release builds differ: {} vs {}",
            hashes[0], hashes[1]
        ))
    }
}

/// SHA-256 without a crypto dependency in this tool: the gate shells out to
/// the platform's own hashing command.
mod sha2_free {
    use std::path::Path;
    use std::process::Command;

    pub fn sha256_file(path: &Path) -> Result<String, String> {
        let output = if cfg!(windows) {
            Command::new("certutil")
                .args(["-hashfile"])
                .arg(path)
                .arg("SHA256")
                .output()
        } else {
            Command::new("sha256sum").arg(path).output()
        }
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        if !output.status.success() {
            return Err(format!("cannot hash {}", path.display()));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .map(|line| line.trim().replace(' ', ""))
            .find(|line| line.len() >= 64 && line[..64].chars().all(|c| c.is_ascii_hexdigit()))
            .map(|line| line[..64].to_ascii_lowercase())
            .ok_or_else(|| format!("no SHA-256 in the output for {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustflags_include_remap_prefixes() {
        let flags = rustflags(Path::new("/work/attome"), Path::new("/home/u/.cargo"));
        assert_eq!(
            flags,
            "--remap-path-prefix=/work/attome=/src --remap-path-prefix=/home/u/.cargo=/cargo"
        );
    }
}

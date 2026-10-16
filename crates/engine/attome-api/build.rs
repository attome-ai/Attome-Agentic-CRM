//! AC7-T11: the bill of materials the server reports at
//! `GET /api/v1/admin/sbom`. A release build sets `ATTOME_EMBED_SBOM` to the
//! gate's CycloneDX file (`attome release` writes `sbom/rust.cdx.json`) and it
//! is embedded as is. Any other build embeds a CycloneDX document derived
//! from the workspace's `Cargo.lock`: every registry package with its version
//! and package URL, marked `attome:sbom = derived`.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "a build script talks to cargo on stdout and fails the build with a message when its inputs are missing"
)]

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=ATTOME_EMBED_SBOM");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("sbom.json");
    if let Ok(path) = env::var("ATTOME_EMBED_SBOM") {
        println!("cargo:rerun-if-changed={path}");
        let text = fs::read_to_string(&path).expect("read ATTOME_EMBED_SBOM");
        fs::write(&out, text).expect("write sbom.json");
        return;
    }
    let lock = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
        .join("../../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let text = fs::read_to_string(&lock).unwrap_or_default();
    fs::write(&out, derived(&text)).expect("write sbom.json");
}

/// A minimal CycloneDX 1.5 document from `Cargo.lock`'s registry packages.
fn derived(lock: &str) -> String {
    let mut components = Vec::new();
    let (mut name, mut version, mut registry) = (String::new(), String::new(), false);
    let mut flush = |name: &str, version: &str, registry: bool| {
        if registry && !name.is_empty() {
            components.push(format!(
                "{{\"type\":\"library\",\"name\":\"{name}\",\"version\":\"{version}\",\
                 \"purl\":\"pkg:cargo/{name}@{version}\"}}"
            ));
        }
    };
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&name, &version, registry);
            name.clear();
            version.clear();
            registry = false;
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            let value = value.trim().trim_matches('"');
            match key {
                "name" => name = value.to_owned(),
                "version" => version = value.to_owned(),
                "source" => registry = value.starts_with("registry+"),
                _ => {}
            }
        }
    }
    flush(&name, &version, registry);
    format!(
        "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\
         \"metadata\":{{\"component\":{{\"type\":\"application\",\"name\":\"attome\",\
         \"version\":\"{}\"}},\"properties\":[{{\"name\":\"attome:sbom\",\"value\":\"derived\"}}]}},\
         \"components\":[{}]}}",
        env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        components.join(",")
    )
}

//! M17-T2: `attome new extension <name> --kind hook|job|webhook` — a Rust
//! crate for one extension, in the shape `attome dev` builds and uploads:
//! `Cargo.toml` (a `cdylib` for `wasm32-unknown-unknown`, and an `rlib` so
//! `cargo test` runs natively), `src/lib.rs`, `manifest.json` (its grants,
//! and a hook's stage) and a README.
//!
//! `src/lib.rs` keeps the extension's logic in one pure function, `decide`,
//! which the generated unit tests call, and the calling convention around
//! it (`attome_extension::runtime`): `alloc(len) -> ptr` for the host to
//! write the input into, and the kind's export (`on_record`, `on_job`,
//! `on_webhook`) taking `(ptr, len)` and answering the output's pointer and
//! length packed into one `i64`.
//!
//! - `hook`: called at `before_save` on accounts; refuses a new account
//!   with no name and trims the name it is given.
//! - `job`: given `{"account_id", "website"}`, answers the account update.
//! - `webhook`: given an event `{"company", "website"}`, answers a new
//!   account.
//!
//! `--lang ts` is refused: JavaScript extensions need Javy (Y10-T7), which
//! is not built. `[--dir <folder>]` (default: the name) must be new or empty.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome new extension <name> --kind hook|job|webhook \
                     [--lang rust] [--dir <folder>]";

/// The kinds of extension a project can be made for.
pub const KINDS: [&str; 3] = ["hook", "job", "webhook"];

/// A valid extension name: what `POST /api/v1/admin/extensions` accepts
/// (lower case letters, digits and `_`, starting with a letter, at most 63).
/// Pure.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The kind's export, the manifest it starts with, its `decide`, its tests,
/// and what it answers when its input is not JSON.
struct KindTemplate {
    export: &'static str,
    manifest: Value,
    decide: &'static str,
    tests: &'static str,
    on_bad_input: &'static str,
    what: &'static str,
}

fn template(kind: &str) -> Option<KindTemplate> {
    Some(match kind {
        "hook" => KindTemplate {
            export: "on_record",
            manifest: json!({
                "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } },
                "hooks": [ { "entity": "account", "stage": "before_save" } ],
            }),
            decide: r#"/// What the hook answers for one account write: a new account with no
/// name is refused, a name with spaces around it is trimmed, anything else
/// goes on. Pure, so `cargo test` checks it without the server.
pub fn decide(input: &Value) -> Value {
    let name = input["values"]["name"].as_str();
    let is_create = input["is_create"].as_bool().unwrap_or(false);
    match name {
        None | Some("") if is_create => json!({ "reject": "A new account needs a name." }),
        Some(name) if name.trim() != name => json!({ "change": { "name": name.trim() } }),
        _ => json!("continue"),
    }
}
"#,
            tests: r#"    #[test]
    fn a_new_account_without_a_name_is_refused() {
        let input = json!({ "stage": "before_save", "entity": "account", "is_create": true, "values": {} });
        assert_eq!(decide(&input), json!({ "reject": "A new account needs a name." }));
    }

    #[test]
    fn a_name_is_trimmed_and_a_clean_one_goes_on() {
        let input = json!({ "stage": "before_save", "entity": "account", "values": { "name": "  Acme " } });
        assert_eq!(decide(&input), json!({ "change": { "name": "Acme" } }));
        let clean = json!({ "stage": "before_save", "entity": "account", "values": { "name": "Acme" } });
        assert_eq!(decide(&clean), json!("continue"));
    }
"#,
            on_bad_input: r#"json!({ "reject": format!("the input is not JSON: {error}") })"#,
            what: "a record hook: called at `before_save` on accounts (manifest.json's `hooks`)",
        },
        "job" => KindTemplate {
            export: "on_job",
            manifest: json!({
                "entities": { "account": { "read": true, "write": true, "attributes": ["website"] } },
            }),
            decide: r#"/// What the job answers for its input `{"account_id", "website"}`: the
/// account's website set, or nothing when either is missing. The server
/// makes the write as the user who queued the run, within the grants. Pure.
pub fn decide(input: &Value) -> Value {
    match (input["account_id"].as_str(), input["website"].as_str()) {
        (Some(id), Some(website)) if !id.is_empty() && !website.is_empty() => json!({
            "records": [ { "entity": "account", "id": id, "values": { "website": website } } ]
        }),
        _ => json!("continue"),
    }
}
"#,
            tests: r#"    #[test]
    fn the_job_updates_the_account_it_is_given() {
        let input = json!({ "account_id": "0190a0b0-0000-7000-8000-000000000001", "website": "https://acme.example" });
        let answer = decide(&input);
        assert_eq!(answer["records"][0]["entity"], "account");
        assert_eq!(answer["records"][0]["values"]["website"], "https://acme.example");
    }

    #[test]
    fn a_job_without_an_account_writes_nothing() {
        assert_eq!(decide(&json!({ "website": "https://acme.example" })), json!("continue"));
    }
"#,
            on_bad_input: r#"{
            let _ = error;
            json!("continue")
        }"#,
            what: "a job: run on demand (`POST /api/v1/admin/extensions/<name>/jobs`) or on a \
                   `schedule` in manifest.json",
        },
        "webhook" => KindTemplate {
            export: "on_webhook",
            manifest: json!({
                "entities": { "account": { "write": true, "attributes": ["name", "website"] } },
            }),
            decide: r#"/// What the webhook answers for an event `{"company", "website"}`: a new
/// account, or nothing when the event names no company. The server checks
/// the inbound hook's signature before calling it. Pure.
pub fn decide(event: &Value) -> Value {
    let Some(company) = event["company"].as_str().map(str::trim).filter(|c| !c.is_empty()) else {
        return json!("continue");
    };
    let mut values = serde_json::Map::new();
    values.insert("name".into(), json!(company));
    if let Some(website) = event["website"].as_str().filter(|w| !w.is_empty()) {
        values.insert("website".into(), json!(website));
    }
    json!({ "records": [ { "entity": "account", "values": values } ] })
}
"#,
            tests: r#"    #[test]
    fn an_event_with_a_company_creates_an_account() {
        let answer = decide(&json!({ "company": " Acme ", "website": "https://acme.example" }));
        assert_eq!(answer["records"][0]["values"]["name"], "Acme");
        assert!(answer["records"][0].get("id").is_none(), "a create, not an update");
    }

    #[test]
    fn an_event_without_a_company_writes_nothing() {
        assert_eq!(decide(&json!({ "website": "x" })), json!("continue"));
    }
"#,
            on_bad_input: r#"{
            let _ = error;
            json!("continue")
        }"#,
            what: "a webhook: called with an inbound hook's event whose handler is \
                   `{\"type\": \"extension\", \"name\": \"<name>\"}`",
        },
        _ => return None,
    })
}

const LIB_RS: &str = r#"//! {{NAME}}: an Attome extension, {{WHAT}}.
//!
//! `decide` is the extension; the rest is the calling convention the server
//! uses for a plain WebAssembly module: it writes the input JSON into memory
//! `alloc` hands it, calls `{{EXPORT}}` with its place and length, and reads
//! the answer from the place and length packed into the returned `i64`.

use serde_json::{Value, json};

{{DECIDE}}
/// Room for the host to write `len` bytes of input into.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: i32) -> i32 {
    let mut buffer = Vec::<u8>::with_capacity(usize::try_from(len).unwrap_or(0));
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr as i32
}

/// The export the server calls: the input at `ptr` (`len` bytes), the
/// answer's place in the high 32 bits of the result and its length in the
/// low 32. Every call runs in a fresh instance, so the answer is never freed.
#[unsafe(no_mangle)]
pub extern "C" fn {{EXPORT}}(ptr: i32, len: i32) -> i64 {
    // SAFETY: the host wrote exactly `len` bytes at `ptr`, a buffer `alloc`
    // returned for that length.
    let input = unsafe {
        std::slice::from_raw_parts(ptr as usize as *const u8, usize::try_from(len).unwrap_or(0))
    };
    let answer = match serde_json::from_slice::<Value>(input) {
        Ok(input) => decide(&input),
        Err(error) => {{ON_BAD_INPUT}},
    };
    let bytes = serde_json::to_vec(&answer).unwrap_or_else(|_| b"\"continue\"".to_vec());
    let out: &'static [u8] = bytes.leak();
    ((out.as_ptr() as usize as u32 as i64) << 32) | i64::from(out.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

{{TESTS}}}
"#;

/// The project's files, `(path, contents)`. Pure.
pub fn extension_project(name: &str, kind: &str) -> Result<Vec<(String, String)>, String> {
    if !valid_name(name) {
        return Err(format!(
            "{name} is not an extension name: lower case letters, digits and `_`, \
             starting with a letter, at most 63 characters"
        ));
    }
    let Some(t) = template(kind) else {
        return Err(format!("--kind is one of {}", KINDS.join(", ")));
    };
    let cargo_toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [lib]\n# cdylib: the WebAssembly module; rlib: so `cargo test` runs natively.\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\n\
         [dependencies]\nserde_json = \"1\"\n\n\
         [profile.release]\nopt-level = \"s\"\nlto = true\nstrip = true\n\n\
         # Its own workspace, so it builds wherever it is checked out.\n[workspace]\n"
    );
    let lib_rs = LIB_RS
        .replace("{{NAME}}", name)
        .replace("{{WHAT}}", t.what)
        .replace("{{EXPORT}}", t.export)
        .replace("{{DECIDE}}", t.decide)
        .replace("{{ON_BAD_INPUT}}", t.on_bad_input)
        .replace("{{TESTS}}", t.tests);
    let manifest = serde_json::to_string_pretty(&t.manifest).unwrap_or_default() + "\n";
    let readme = format!(
        "# {name}\n\n\
         An Attome extension: {what}.\n\n\
         - `src/lib.rs`: `decide` is the extension; the code under it is the calling convention.\n\
         - `manifest.json`: what it may touch (entities and attributes, secrets, hosts){hook}. An\n  \
         administrator approves these grants when the extension is published; it reaches nothing else.\n\n\
         ```\n\
         cargo test                                   # the logic, natively\n\
         rustup target add wasm32-unknown-unknown     # once\n\
         attome dev . --once --target <deployment>    # build and upload a draft version\n\
         ```\n\n\
         `attome dev .` without `--once` rebuilds and uploads on every change. Test a draft with\n\
         `POST /api/v1/admin/extensions/{name}/versions/<v>/test`, then publish it.\n",
        what = t.what,
        hook = if kind == "hook" {
            ", and the stage it runs at"
        } else {
            ""
        },
    );
    Ok(vec![
        ("Cargo.toml".into(), cargo_toml),
        ("src/lib.rs".into(), lib_rs),
        ("manifest.json".into(), manifest),
        ("README.md".into(), readme),
        (".gitignore".into(), "/target\n".into()),
    ])
}

/// `attome new extension …` (`args` after `new`).
pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let dir = take_value(&mut args, "--dir")?;
    let kind = take_value(&mut args, "--kind")?;
    let lang = take_value(&mut args, "--lang")?;
    let [what, name] = args.as_slice() else {
        return Err(USAGE.to_owned());
    };
    if what != "extension" {
        return Err(USAGE.to_owned());
    }
    match lang.as_deref() {
        None | Some("rust") => {}
        Some("ts") => {
            return Err(
                "TypeScript extensions need Javy (roadmap Y10-T7), which is not built \
                        yet; use --lang rust"
                    .to_owned(),
            );
        }
        Some(other) => return Err(format!("--lang is rust or ts, not {other}")),
    }
    let Some(kind) = kind else {
        return Err(USAGE.to_owned());
    };
    let files = extension_project(name, &kind)?;
    let dir = PathBuf::from(dir.unwrap_or_else(|| name.clone()));
    if std::fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(format!("{} exists and is not empty", dir.display()));
    }
    for (path, contents) in &files {
        let path = dir.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    println!(
        "wrote a {kind} extension in {} ({} files); `cargo test` there, then `attome dev .`",
        dir.display(),
        files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file<'a>(files: &'a [(String, String)], path: &str) -> &'a str {
        &files.iter().find(|(p, _)| p == path).unwrap().1
    }

    #[test]
    fn every_kind_makes_a_project_attome_dev_builds() {
        for kind in KINDS {
            let files = extension_project("erp_sync", kind).unwrap();
            let cargo = file(&files, "Cargo.toml");
            assert_eq!(
                crate::cmd::dev::package_name(cargo).as_deref(),
                Some("erp_sync")
            );
            assert!(cargo.contains("crate-type = [\"cdylib\", \"rlib\"]"));
            let lib = file(&files, "src/lib.rs");
            let export = template(kind).unwrap().export;
            assert!(lib.contains(&format!(
                "pub extern \"C\" fn {export}(ptr: i32, len: i32) -> i64"
            )));
            assert!(lib.contains("pub extern \"C\" fn alloc(len: i32) -> i32"));
            assert!(lib.contains("pub fn decide("));
            assert!(lib.contains("#[test]"));
            assert!(!lib.contains("{{"), "every placeholder is filled: {kind}");
            let manifest: attome_extension::Grants =
                serde_json::from_str(file(&files, "manifest.json")).unwrap();
            assert!(
                attome_extension::grants::check(&manifest).is_empty(),
                "{kind}: {:?}",
                attome_extension::grants::check(&manifest)
            );
            assert!(file(&files, "README.md").contains("attome dev ."));
        }
    }

    #[test]
    fn the_exports_are_the_ones_the_server_calls() {
        assert_eq!(
            template("hook").unwrap().export,
            attome_extension::HOOK_EXPORT
        );
        assert_eq!(
            template("job").unwrap().export,
            attome_extension::kinds::JOB_EXPORT
        );
        assert_eq!(
            template("webhook").unwrap().export,
            attome_extension::kinds::WEBHOOK_EXPORT
        );
    }

    #[test]
    fn a_bad_name_kind_or_language_is_refused() {
        assert!(extension_project("ErpSync", "hook").is_err());
        assert!(extension_project("erp-sync", "hook").is_err());
        assert!(extension_project("erp_sync", "trigger").is_err());
        let args: Vec<String> = ["extension", "x", "--kind", "job", "--lang", "ts"]
            .into_iter()
            .map(String::from)
            .collect();
        let ts = run(&args);
        assert!(ts.unwrap_err().contains("Javy"));
    }
}

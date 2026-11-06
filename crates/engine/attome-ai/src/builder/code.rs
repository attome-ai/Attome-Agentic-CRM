//! AD9-T1: the building agent's code skill — a hook extension written from
//! a description, with its tests, as the Rust crate `attome new extension
//! --kind hook` makes (M17-T2): `Cargo.toml`, `src/lib.rs` (the logic in one
//! pure `decide`, its unit tests, and the calling convention), a
//! `manifest.json` asking only for the grants the code uses, and a README.
//!
//! Adjusted (V2-D1917): the server has no WebAssembly build service, so the
//! skill does not compile anything. The files go to the person's Develop
//! workspace, where `attome dev <folder>` runs `cargo test`, the dependency
//! check (M17-T4), builds the module and uploads it as a draft version;
//! nothing is published without the owner's review (V2-D27).
//!
//! What is checked here, without a compiler:
//!
//! - every attribute the draft reads or writes exists on the entity; one that
//!   does not is left out of the grants and reported, never guessed;
//! - the code reaches no file, network, process or environment API and holds
//!   no `unsafe` of its own (the calling convention's one block is written
//!   here, not by the model);
//! - `decide` is defined and there is at least one test.
//!
//! Pure.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The stages a drafted hook may run at (the before stages can change or
/// refuse a write).
pub const STAGES: [&str; 4] = [
    "before_validation",
    "before_save",
    "after_save",
    "after_commit",
];

/// APIs a drafted extension may not name: the sandbox refuses them anyway,
/// and code that reaches for them was written for somewhere else.
pub const FORBIDDEN: [&str; 9] = [
    "unsafe",
    "std::fs",
    "std::net",
    "std::process",
    "std::env",
    "std::thread",
    "extern \"C\"",
    "#[no_mangle]",
    "include_bytes!",
];

/// The longest drafted `decide` or test code accepted.
pub const MAX_CODE_CHARS: usize = 20_000;

/// A hook drafted by the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftedHook {
    /// The extension's name (lower case, digits, `_`).
    pub name: String,
    pub stage: String,
    /// Attributes the hook reads.
    #[serde(default)]
    pub reads: Vec<String>,
    /// Attributes the hook may change (before stages).
    #[serde(default)]
    pub writes: Vec<String>,
    /// The Rust `pub fn decide(input: &Value) -> Value { ... }`.
    pub decide: String,
    /// Rust `#[test]` functions for `decide`.
    pub tests: String,
    /// Refusal messages by key: `{key: {"en": ..., "ar": ...}}`.
    #[serde(default)]
    pub messages: serde_json::Map<String, Value>,
}

/// The project for a drafted hook, and what was left out or refused.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HookProject {
    /// `(path, contents)`, in the shape `attome dev` builds.
    pub files: Vec<(String, String)>,
    /// The manifest, also in `files` as `manifest.json`.
    pub manifest: Value,
    /// Attributes the draft named that the entity does not have.
    pub left_out: Vec<String>,
}

/// Whether `name` is an extension name `POST /api/v1/admin/extensions`
/// accepts. Pure.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The forbidden APIs `code` names. Pure.
pub fn forbidden_in(code: &str) -> Vec<&'static str> {
    FORBIDDEN
        .iter()
        .copied()
        .filter(|api| code.contains(api))
        .collect()
}

const CALLING_CONVENTION: &str = r#"
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
pub extern "C" fn on_record(ptr: i32, len: i32) -> i64 {
    // SAFETY: the host wrote exactly `len` bytes at `ptr`, a buffer `alloc`
    // returned for that length.
    let input = unsafe {
        std::slice::from_raw_parts(ptr as usize as *const u8, usize::try_from(len).unwrap_or(0))
    };
    let answer = match serde_json::from_slice::<Value>(input) {
        Ok(input) => decide(&input),
        Err(error) => json!({ "reject": format!("the input is not JSON: {error}") }),
    };
    let bytes = serde_json::to_vec(&answer).unwrap_or_else(|_| b"\"continue\"".to_vec());
    let out: &'static [u8] = bytes.leak();
    ((out.as_ptr() as usize as u32 as i64) << 32) | i64::from(out.len() as u32)
}
"#;

/// The hook project for `drafted` on `entity`, whose attributes are
/// `attributes`; `Err` with every reason when the draft cannot become one.
/// Pure.
pub fn hook_project(
    entity: &str,
    attributes: &[String],
    drafted: &DraftedHook,
) -> Result<HookProject, Vec<String>> {
    let mut problems = Vec::new();
    let name = drafted.name.trim();
    if !valid_name(name) {
        problems.push(format!(
            "{name:?} is not an extension name: lower case letters, digits and `_`, starting with a letter"
        ));
    }
    if !STAGES.contains(&drafted.stage.as_str()) {
        problems.push(format!("the stage is one of {}", STAGES.join(", ")));
    }
    if !drafted.decide.contains("fn decide(") {
        problems.push("the code defines no `decide` function".into());
    }
    if !drafted.tests.contains("#[test]") {
        problems.push("the draft has no tests".into());
    }
    for (what, code) in [("decide", &drafted.decide), ("tests", &drafted.tests)] {
        if code.chars().count() > MAX_CODE_CHARS {
            problems.push(format!("{what} is longer than {MAX_CODE_CHARS} characters"));
        }
        for api in forbidden_in(code) {
            problems.push(format!("{what} uses {api}, which an extension may not"));
        }
    }
    if !drafted.writes.is_empty() && !drafted.stage.starts_with("before_") {
        problems.push("only a before stage can change values".into());
    }
    for (key, texts) in &drafted.messages {
        if texts["en"].as_str().is_none_or(|t| t.trim().is_empty()) {
            problems.push(format!("the message {key} has no English text"));
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut left_out = Vec::new();
    let known = |list: &[String], left_out: &mut Vec<String>| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for a in list {
            let a = a.trim();
            if attributes.iter().any(|known| known == a) {
                if !out.iter().any(|o| o == a) {
                    out.push(a.to_owned());
                }
            } else {
                left_out.push(format!("{entity}.{a}"));
            }
        }
        out
    };
    let writes = known(&drafted.writes, &mut left_out);
    let mut reads = known(&drafted.reads, &mut left_out);
    for w in &writes {
        if !reads.contains(w) {
            reads.push(w.clone());
        }
    }
    let mut grant = json!({ "read": true, "attributes": reads });
    if !writes.is_empty() {
        grant["write"] = json!(true);
    }
    let mut manifest = json!({
        "entities": { entity: grant },
        "hooks": [ { "entity": entity, "stage": drafted.stage, "order": 0 } ],
    });
    if !drafted.messages.is_empty() {
        manifest["messages"] = Value::Object(drafted.messages.clone());
    }

    let cargo = format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n\
         [lib]\n# cdylib: the WebAssembly module; rlib: so `cargo test` runs natively.\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\n\
         [dependencies]\nserde_json = \"1\"\n\n\
         [profile.release]\nopt-level = \"s\"\nlto = true\nstrip = true\n\n\
         # Its own workspace, so it builds wherever it is checked out.\n[workspace]\n"
    );
    let lib = format!(
        "//! {name}: an Attome hook on {entity} at {stage}, drafted by the building agent \
         (AD9-T1) for review.\n//!\n//! `decide` is the extension; the rest is the calling \
         convention.\n\nuse serde_json::{{Value, json}};\n\n{decide}\n{convention}\n\
         #[cfg(test)]\nmod tests {{\n    use super::*;\n\n{tests}\n}}\n",
        stage = drafted.stage,
        decide = drafted.decide.trim_end(),
        convention = CALLING_CONVENTION,
        tests = drafted.tests.trim_end(),
    );
    let readme = format!(
        "# {name}\n\nA hook on `{entity}` at `{stage}`, drafted by the building agent. Review \
         `src/lib.rs` and the grants in `manifest.json` before uploading.\n\n```\n\
         cargo test                                   # the drafted tests, natively\n\
         attome dev . --once --target <deployment>    # test, check dependencies, build, upload a draft\n\
         ```\n\nA draft version runs only when tested \
         (`POST /api/v1/admin/extensions/{name}/versions/<v>/test`) until it is published.\n",
        stage = drafted.stage,
    );
    let manifest_text = serde_json::to_string_pretty(&manifest).unwrap_or_default() + "\n";
    Ok(HookProject {
        files: vec![
            ("Cargo.toml".into(), cargo),
            ("src/lib.rs".into(), lib),
            ("manifest.json".into(), manifest_text),
            ("README.md".into(), readme),
            (".gitignore".into(), "/target\n".into()),
        ],
        manifest,
        left_out,
    })
}

/// AD9-T1 (AD10): a builder-suite task for the code skill: a description
/// and what a good hook draft holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookTask {
    pub description: String,
    pub entity: String,
    pub stage: String,
    /// Attributes the hook must read.
    #[serde(default)]
    pub must_read: Vec<String>,
    /// Attributes the hook must be allowed to change.
    #[serde(default)]
    pub must_write: Vec<String>,
    /// The fewest tests a good draft has.
    #[serde(default = "one")]
    pub min_tests: usize,
}

fn one() -> usize {
    1
}

/// Grades one hook draft against `task`: it becomes a project, at the
/// task's stage, with the grants the task needs and no needless write, and
/// enough tests. The reasons it fails; empty when it passes. Pure.
pub fn grade_hook(task: &HookTask, attributes: &[String], drafted: &DraftedHook) -> Vec<String> {
    let project = match hook_project(&task.entity, attributes, drafted) {
        Ok(project) => project,
        Err(problems) => return problems,
    };
    let mut reasons = Vec::new();
    if drafted.stage != task.stage {
        reasons.push(format!("runs at {}, not {}", drafted.stage, task.stage));
    }
    let grant = &project.manifest["entities"][task.entity.as_str()];
    let granted: Vec<&str> = grant["attributes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for a in task.must_read.iter().chain(&task.must_write) {
        if !granted.contains(&a.as_str()) {
            reasons.push(format!("does not read {a}"));
        }
    }
    if !task.must_write.is_empty() && grant["write"] != json!(true) {
        reasons.push("asks for no write".into());
    }
    if task.must_write.is_empty() && grant["write"] == json!(true) {
        reasons.push("asks to write though the task changes nothing".into());
    }
    let tests = drafted.tests.matches("#[test]").count();
    if tests < task.min_tests {
        reasons.push(format!("has {tests} tests, fewer than {}", task.min_tests));
    }
    if !project.left_out.is_empty() {
        reasons.push(format!(
            "names attributes that do not exist: {}",
            project.left_out.join(", ")
        ));
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drafted() -> DraftedHook {
        DraftedHook {
            name: "account_vat_check".into(),
            stage: "before_save".into(),
            reads: vec!["vat_number".into(), "country_code".into(), "nonexistent".into()],
            writes: vec!["vat_number".into()],
            decide: "pub fn decide(input: &Value) -> Value {\n    let _ = input;\n    json!(\"continue\")\n}\n".into(),
            tests: "    #[test]\n    fn goes_on() {\n        assert_eq!(decide(&json!({})), json!(\"continue\"));\n    }\n".into(),
            messages: serde_json::Map::new(),
        }
    }

    fn attrs() -> Vec<String> {
        vec!["name".into(), "vat_number".into(), "country_code".into()]
    }

    #[test]
    fn a_described_hook_becomes_a_project_with_only_its_grants() {
        let project = hook_project("account", &attrs(), &drafted()).unwrap();
        let grant = &project.manifest["entities"]["account"];
        assert_eq!(grant["write"], true);
        assert_eq!(grant["attributes"], json!(["vat_number", "country_code"]));
        assert_eq!(project.manifest["hooks"][0]["stage"], "before_save");
        assert_eq!(project.left_out, vec!["account.nonexistent".to_owned()]);
        let lib = &project
            .files
            .iter()
            .find(|(p, _)| p == "src/lib.rs")
            .unwrap()
            .1;
        assert!(lib.contains("pub fn decide("));
        assert!(lib.contains("pub extern \"C\" fn on_record(ptr: i32, len: i32) -> i64"));
        assert!(lib.contains("fn goes_on()"));
        let paths: Vec<&str> = project.files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            [
                "Cargo.toml",
                "src/lib.rs",
                "manifest.json",
                "README.md",
                ".gitignore"
            ]
        );
    }

    #[test]
    fn unsafe_io_and_untested_drafts_are_refused() {
        let mut d = drafted();
        d.decide
            .push_str("\nfn leak() { let _ = std::fs::read(\"/etc/passwd\"); }\n");
        d.tests = "    fn not_a_test() {}\n".into();
        let problems = hook_project("account", &attrs(), &d).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("std::fs")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("no tests")),
            "{problems:?}"
        );

        let mut late = drafted();
        late.stage = "after_commit".into();
        let problems = hook_project("account", &attrs(), &late).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("before stage")),
            "{problems:?}"
        );

        let mut named = drafted();
        named.name = "Account-Check".into();
        assert!(hook_project("account", &attrs(), &named).is_err());
    }

    #[test]
    fn a_read_only_hook_asks_for_no_write() {
        let mut d = drafted();
        d.writes.clear();
        d.stage = "after_save".into();
        let project = hook_project("account", &attrs(), &d).unwrap();
        assert!(
            project.manifest["entities"]["account"]
                .get("write")
                .is_none()
        );
    }

    /// The scripted builder-suite case: a recorded draft graded against its
    /// task.
    #[test]
    fn scripted_suite_case_vat_check_passes_and_a_bad_draft_fails() {
        let task = HookTask {
            description: "Refuse saving an account whose VAT number is not 15 digits".into(),
            entity: "account".into(),
            stage: "before_save".into(),
            must_read: vec!["vat_number".into()],
            must_write: vec![],
            min_tests: 1,
        };
        let mut recorded = drafted();
        recorded.reads = vec!["vat_number".into()];
        recorded.writes.clear();
        assert_eq!(grade_hook(&task, &attrs(), &recorded), Vec::<String>::new());

        let mut wrong = recorded.clone();
        wrong.stage = "after_save".into();
        wrong.reads = vec!["name".into()];
        let reasons = grade_hook(&task, &attrs(), &wrong);
        assert!(
            reasons.iter().any(|r| r.contains("runs at after_save")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("does not read vat_number")),
            "{reasons:?}"
        );
    }
}

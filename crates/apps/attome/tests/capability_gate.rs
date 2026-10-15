//! D-344 — a two-way census of the durability-capability gate's route
//! coverage.
//!
//! # Why a source scan rather than a live assertion
//!
//! Same reasoning as `route_authz.rs`, which this file is deliberately shaped
//! after: axum exposes no route-introspection API, and asserting a real 503
//! per route would need Postgres, Redis, an object store and a *stopped* one
//! of each — so it would skip in exactly the environments where someone is
//! most likely to have quietly dropped the gate. This runs anywhere, in
//! milliseconds, with no services.
//!
//! # What it pins, in both directions
//!
//! `attome_server::capability::Available<C>` makes the check impossible to
//! forget *inside* a handler that names it. It cannot make the handler name
//! it. Two failure modes live outside any handler body:
//!
//! 1. **A gate silently removed.** Deleting `_storage: Available<ObjectStorage>`
//!    from `create_upload_session` compiles, passes clippy, and passes every
//!    test that does not have a stopped object store — the route just goes
//!    back to handing out presigned URLs against a dead backend.
//!    [`every_expected_route_declares_its_capability`] fails instead.
//! 2. **A gate added without a decision.** The whole point of D-344's
//!    amendment to D-167 is that this mechanism stays *narrow* — it refuses
//!    individual operations that cannot durably complete, and is not a second
//!    readiness gate creeping across the router one handler at a time.
//!    [`no_undeclared_capability_gate_exists`] fails on any `Available<_>`
//!    this file does not know about, so widening the gate is a deliberate,
//!    reviewable edit here rather than a quiet one over there.
//!
//! # What it does not prove
//!
//! That the gate is *right*: that the capability named matches the dependency
//! the handler actually needs, and that the probe behind it reflects reality.
//! The first is a reading of the handler; the second is the live-outage drill
//! recorded in D-344. The decision-table half — thresholds, flap protection,
//! `Unknown` admitting — is unit-tested in `attome-server`'s own
//! `capability.rs`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every route the gate applies to, as (handler function, capability marker),
/// with the reason it cannot durably complete without that dependency.
///
/// Adding a row is how a route joins the gate. Removing one is how it leaves
/// — and both directions are asserted below, so neither can happen by
/// accident.
const GATED_HANDLERS: &[(&str, &str, &str)] = &[
    (
        "create_upload_session",
        "ObjectStorage",
        "Hands the caller a presigned PUT contract the object store has to honour. \
         Against a dead backend the failure lands in the browser, past this platform's reach.",
    ),
    (
        "finalize_upload_session",
        "ObjectStorage",
        "HEAD-verifies the quarantined object before promoting the session; an unreachable \
         store turns a diagnosable dependency outage into an opaque 500.",
    ),
    (
        "enqueue",
        "BatchJobs",
        "Returns 201 'durably accepted, applied later' for a batch job \
         (EngineJob::is_batch). With no live batch worker, 'later' is never.",
    ),
    (
        "bulk_edit",
        "BatchJobs",
        "Returns 202 for a bulk update the batch worker applies (B5-T1); with no worker the \
         edit is accepted and never applied.",
    ),
    (
        "enqueue_bulk_transform",
        "BatchJobs",
        "Returns 202 'durably accepted, applied later' for a bulk transform job. With no live batch worker, 'later' is never.",
    ),
    (
        "enqueue_export",
        "BatchJobs",
        "Returns 202 for a data export job the batch worker has to run; with no worker the caller polls a job that never starts.",
    ),
    (
        "enqueue_profile",
        "BatchJobs",
        "Returns 202 for a data-profile job the batch worker has to run; with no worker the caller polls a profile that never starts.",
    ),
    (
        "rollback_run",
        "BatchJobs",
        "Enqueues the rollback of a migration run as a batch job and reports it accepted; with no worker the run stays half-applied.",
    ),
    (
        "staged_import",
        "BatchJobs",
        "Same accept-now/apply-later contract as bulk enqueue, one approval step longer.",
    ),
    (
        "approve_staged_import",
        "BatchJobs",
        "Enqueues ApplyStagedImport and moves the import to 'approving', a state its own \
         WHERE status = 'pending_review' guard makes unrecoverable without a live worker.",
    ),
    (
        "resend_delivery",
        "Email",
        "Its entire purpose is to put a message on the relay.",
    ),
    (
        "resend_delivery",
        "FastJobs",
        "SendEmail is a fast-queue job, so a reachable relay with a dead default worker sends \
         nothing — and the resend mints a fresh single-use token first, invalidating the \
         recipient's previous link in exchange for one they never receive.",
    ),
];

/// Files that legitimately contain the token `Available<` without gating a
/// route: the mechanism's own definition and its unit tests.
const DEFINITION_SITES: &[&str] = &["attome-server/src/capability.rs"];

#[test]
fn every_expected_route_declares_its_capability() {
    let sources = collect_sources();
    let found = declared_gates(&sources);

    let mut missing = Vec::new();
    for (handler, marker, why) in GATED_HANDLERS {
        if !found.contains(&((*handler).to_string(), (*marker).to_string())) {
            missing.push(format!(
                "  {handler} must declare Available<{marker}>\n    why: {why}"
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "D-344: {} route(s) lost their durability gate. Each one now accepts work it \
         cannot complete, and returns 2xx for it:\n{}\n\nIf a route genuinely no longer \
         needs its capability (the handler stopped touching that dependency), delete its \
         row from GATED_HANDLERS in this file and say why in the commit — do not delete \
         the extractor alone.",
        missing.len(),
        missing.join("\n"),
    );
}

#[test]
fn no_undeclared_capability_gate_exists() {
    let sources = collect_sources();
    let expected: BTreeSet<(String, String)> = GATED_HANDLERS
        .iter()
        .map(|(h, m, _)| ((*h).to_string(), (*m).to_string()))
        .collect();

    let undeclared: Vec<String> = declared_gates(&sources)
        .difference(&expected)
        .map(|(h, m)| format!("  {h} declares Available<{m}>"))
        .collect();

    assert!(
        undeclared.is_empty(),
        "D-344 amends D-167 narrowly, and 'narrowly' is the load-bearing word: this gate \
         refuses individual operations that cannot durably complete, and must not spread \
         across the router into a second de-facto readiness gate one handler at a \
         time.\n{}\n\nAdd a row to GATED_HANDLERS in this file — with the reason that \
         route cannot durably complete without the dependency — so the decision is \
         reviewable where the others are.",
        undeclared.join("\n"),
    );
}

/// The marker names in `GATED_HANDLERS` have to be real capabilities, or both
/// tests above would happily agree with each other about a typo.
#[test]
fn every_named_marker_is_a_real_capability() {
    let known = ["ObjectStorage", "Email", "FastJobs", "BatchJobs"];
    for (handler, marker, _) in GATED_HANDLERS {
        assert!(
            known.contains(marker),
            "{handler} names Available<{marker}>, which is not a \
             attome_server::capability marker type ({known:?}) — if a capability was added, \
             extend this list and Capability::ALL together",
        );
    }
}

// ── Scanning ────────────────────────────────────────────────────────────────

/// Every `(handler_name, marker)` pair actually declared in the workspace's
/// sources.
///
/// A gate is attributed to the nearest `fn` header *preceding* it, which is
/// exactly right for an extractor: it can only appear in a parameter list.
fn declared_gates(sources: &[(String, String)]) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (file, text) in sources {
        if DEFINITION_SITES
            .iter()
            .any(|site| file.replace('\\', "/").ends_with(site))
        {
            continue;
        }
        for (idx, marker) in available_occurrences(text) {
            if let Some(handler) = enclosing_fn_name(text, idx) {
                out.insert((handler, marker));
            }
        }
    }
    out
}

/// Byte index and type argument of each `Available<Type>` in `text`.
fn available_occurrences(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(rel) = text[search..].find("Available<") {
        let at = search + rel;
        search = at + "Available<".len();
        // `Unavailable<`/`CapabilityUnavailable<` etc. must not match: require
        // the preceding character to be a non-identifier one.
        if at > 0 {
            let prev = bytes[at - 1] as char;
            if prev.is_alphanumeric() || prev == '_' {
                continue;
            }
        }
        let Some(end) = text[search..].find('>') else {
            continue;
        };
        let marker = text[search..search + end].trim().to_string();
        out.push((at, marker));
    }
    out
}

/// Name of the last `fn` header starting before `idx`.
fn enclosing_fn_name(text: &str, idx: usize) -> Option<String> {
    let before = &text[..idx];
    let start = before.rfind("fn ")? + "fn ".len();
    let rest = &text[start..];
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn collect_sources() -> Vec<(String, String)> {
    // CARGO_MANIFEST_DIR is crates/server; the workspace root is two up.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .join("crates");

    let mut out = Vec::new();
    walk(&root, &mut out);
    assert!(
        !out.is_empty(),
        "no .rs sources found under {root:?} — has the crate layout moved?",
    );
    for (_, text) in out.iter_mut() {
        *text = blank_comments(text);
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            // `target/` is build output; `tests/` holds fixture routers and
            // this very file, whose prose names every marker.
            if name.as_deref() == Some("target") || name.as_deref() == Some("tests") {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            out.push((path.display().to_string(), text));
        }
    }
}

/// Replaces comment bodies with spaces, preserving byte offsets so
/// `enclosing_fn_name`'s index arithmetic still lines up.
///
/// Necessary, not defensive: this module's own design requires doc comments
/// that discuss `Available<C>` and name concrete markers in prose (see
/// `attome-server/src/state.rs`, `attome-core/src/state.rs`,
/// `crates/server/src/main.rs`), and a scanner that counted those as
/// declarations would report a gate on whatever function happened to be
/// defined above the comment.
fn blank_comments(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    let mut block_depth = 0usize;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        if block_depth > 0 {
            if c == '/' && next == Some('*') {
                block_depth += 1;
                out.push_str("  ");
                i += 2;
                continue;
            }
            if c == '*' && next == Some('/') {
                block_depth -= 1;
                out.push_str("  ");
                i += 2;
                continue;
            }
            out.push(if c == '\n' { '\n' } else { ' ' });
            i += 1;
            continue;
        }

        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                    i += 2;
                    continue;
                }
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        match (c, next) {
            ('"', _) => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                block_depth = 1;
                out.push_str("  ");
                i += 2;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod scanner_tests {
    use super::*;

    #[test]
    fn a_gate_in_a_parameter_list_is_attributed_to_its_handler() {
        let src = "async fn upload(State(s): State<X>, _c: Available<ObjectStorage>) {}";
        let gates = available_occurrences(src);
        assert_eq!(gates.len(), 1);
        assert_eq!(gates[0].1, "ObjectStorage");
        assert_eq!(
            enclosing_fn_name(src, gates[0].0).as_deref(),
            Some("upload")
        );
    }

    #[test]
    fn prose_mentioning_a_marker_is_not_a_declaration() {
        let src = "// this route needs Available<ObjectStorage>\nasync fn upload() {}";
        assert!(available_occurrences(&blank_comments(src)).is_empty());
    }

    #[test]
    fn a_doc_comment_mentioning_a_marker_is_not_a_declaration() {
        let src = "/// see Available<BatchJobs>\n/** and Available<Email> */\nfn f() {}";
        assert!(available_occurrences(&blank_comments(src)).is_empty());
    }

    #[test]
    fn blanking_preserves_byte_offsets_so_fn_attribution_stays_correct() {
        let src = "async fn a() {}\n// noise\nasync fn b(_c: Available<Email>) {}";
        let blanked = blank_comments(src);
        assert_eq!(blanked.len(), src.len());
        let gates = available_occurrences(&blanked);
        assert_eq!(gates.len(), 1);
        assert_eq!(
            enclosing_fn_name(&blanked, gates[0].0).as_deref(),
            Some("b")
        );
    }

    /// A string literal containing `//` must not swallow the rest of the line
    /// — otherwise a URL in a handler would blank a real declaration after it.
    #[test]
    fn a_url_in_a_string_literal_does_not_start_a_comment() {
        let src = "fn f(_c: Available<Email>) { let u = \"https://x/y\"; }";
        assert_eq!(blank_comments(src), src);
    }

    #[test]
    fn a_longer_identifier_ending_in_available_does_not_match() {
        assert!(available_occurrences("Unavailable<Email>").is_empty());
    }
}

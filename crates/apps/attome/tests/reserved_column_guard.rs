//! SEC-3 — structural guard over every site that writes an entity attribute's
//! name into SQL, so the SEC-1 class of bug cannot recur silently.
//!
//! # The bug class
//!
//! Entity tables carry ten system columns (`attome_core::ALL_SYSTEM_COLS`:
//! `id`, `created_at`, `created_by`, `modified_at`, `modified_by`,
//! `organization_ref`, `is_active`, `row_version`, `owner_ref`,
//! `owner_type`). Every one is owned by the engine — spliced from the
//! authenticated caller's context, or supplied by a column default — and none
//! may ever be taken from a request body. `organization_ref` decides which
//! side of the RLS boundary a row sits on, `owner_ref`/`owner_type` are
//! ownership, `created_by`/`created_at` are audit provenance, `is_active` is the
//! soft-delete flag, `id` is the primary key.
//!
//! Nothing upstream stops a body from naming one. They can be — and on
//! `user_account` are — registered metadata attributes, so
//! `validate_body` (which only rejects names *absent* from metadata) passes
//! them, and `validate_field_write_grants` (which only gates `is_sensitive`
//! and `is_write_restricted` fields) passes them too. The only thing between a request body and one of
//! these columns is the exclusion applied where the SQL is built.
//!
//! # Why structural, and not only behavioural
//!
//! Behavioural coverage lives in
//! `attome-api/tests/reserved_column_entry_points.rs`, which drives each
//! mutation endpoint and asserts no system column moved. That proves the
//! endpoints that exist today are safe. It cannot fail for an endpoint that
//! does *not* exist yet — a new mutation path simply is not in it, and nothing
//! says it should be.
//!
//! This is the half that fails on arrival. The exclusion was originally on the
//! insert builder only; the update builder was written later, right next to
//! it, and never got one — nothing failed, because nothing was watching the
//! *shape* of the code. And when SEC-1 was fixed, a third site turned up by
//! hand in `upsert_record`'s `ON CONFLICT DO UPDATE` clause — in a file that
//! was already using the filtered builders, so any file-granularity check
//! would have missed it too. Hence the granularity here is (file, enclosing
//! function).
//!
//! # What it does
//!
//! Every `quote_ident(&<x>.logicalname)` under `crates/` — the one way an
//! attribute name becomes a SQL identifier — must be registered below with a
//! classification. A site in an unregistered function fails the test until
//! someone classifies it, which is the opt-in SEC-3 asks for.
//!
//! For `Classification::ExcludesSystemCols` the claim is *verified*, not
//! trusted: the enclosing function's own text must contain an exclusion
//! against `ALL_SYSTEM_COLS`. So the only way to register a new unfiltered
//! mutation builder is to label it `Projection` or `ServerConstructed` — a
//! deliberate written claim a reviewer can check, rather than an omission
//! nobody sees.
//!
//! # What it does not prove
//!
//! That the exclusion is applied to the *right* collection, or that the
//! statement is otherwise correct — only that the function performs one at
//! all. The behavioural file is what proves the values never land.
//!
//! Runs anywhere in milliseconds with no Postgres, Redis or S3, like
//! `route_authz.rs` next door and for the same reason: a guard that skips when
//! infrastructure is missing is a guard that skips in exactly the environment
//! where nobody notices.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// How a site that emits an attribute name into SQL is allowed to exist.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Classification {
    /// Builds a write (INSERT column list / UPDATE SET clause) from a
    /// caller-supplied body, and filters the system columns out. The test
    /// checks the enclosing function really does contain the exclusion.
    ExcludesSystemCols,
    /// Builds a read projection or a predicate — naming a system column here
    /// discloses nothing the caller may not already read, and writes nothing.
    Projection,
    /// Builds a write, but from data this process constructed, never from a
    /// request body. The reason must say where that data comes from.
    ServerConstructed,
}

use Classification::{ExcludesSystemCols, Projection, ServerConstructed};

/// Every function under `crates/` that turns an attribute logicalname into a
/// SQL identifier, and why it is safe. Sorted by path.
///
/// To add an entry you must state which of the three shapes the site is. If it
/// builds a write from a request body, the only correct answer is
/// `ExcludesSystemCols`, and the test will hold you to it.
const ATTRIBUTE_SQL_SITES: &[(&str, &str, Classification, &str)] = &[
    (
        "crates/engine/attome-core/src/crud.rs",
        "insert",
        ServerConstructed,
        "attome-audit's `audit_header` row, built from a json! template in \
         attome-audit/src/service.rs — the only caller. Never a request body.",
    ),
    (
        "crates/engine/attome-core/src/crud.rs",
        "insert_many",
        ServerConstructed,
        "attome-audit's `audit_detail` per-field rows: same json! template \
         and the same single caller as `insert` above.",
    ),
    (
        "crates/engine/attome-metadata/src/purge.rs",
        "scrub_record",
        ExcludesSystemCols,
        "P-data-protection-governance erasure. Filters ALL_SYSTEM_COLS \
         directly — the precedent this guard generalises: a full-row NULL \
         wipe reaching the system columns would destroy the provenance that \
         restore and on_target_delete still read.",
    ),
    (
        "crates/engine/attome-core/src/sql_ident.rs",
        "select_columns_filtered",
        Projection,
        "The shared SELECT/RETURNING projection builder — reads only.",
    ),
    (
        "crates/engine/attome-search/src/corpus/mod.rs",
        "project_record",
        Projection,
        "SELECT list of indexable attributes for the search corpus.",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/hierarchy.rs",
        "list_ancestors",
        Projection,
        "Recursive CTE over the hierarchy field; a read-only structural walk.",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/hierarchy.rs",
        "list_descendants",
        Projection,
        "Recursive CTE over the hierarchy field; a read-only structural walk.",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/upsert.rs",
        "upsert_record",
        ExcludesSystemCols,
        "The ON CONFLICT DO UPDATE branch — SEC-1's third site, found by hand \
         after the first two were fixed. The INSERT half delegates to \
         build_insert_binds; the SET clause is built here and needs its own \
         exclusion.",
    ),
    (
        "crates/engine/attome-records/src/entity_mutation.rs",
        "build_insert_binds",
        ExcludesSystemCols,
        "The shared INSERT column-list builder, reached by create, upsert, \
         bulk and staged import.",
    ),
    (
        "crates/engine/attome-records/src/entity_mutation.rs",
        "build_update_binds",
        ExcludesSystemCols,
        "The shared UPDATE SET-clause builder — SEC-1 itself. Reached by the \
         interactive update path, bulk, staged import and merge alike.",
    ),
    (
        "crates/engine/attome-records/src/entity_mutation.rs",
        "guard_hierarchy_cycles",
        Projection,
        "Reads the hierarchy field to walk for a cycle before a write; the \
         write itself is build_update_binds' job.",
    ),
];

/// Spellings that count as excluding the system columns. Both resolve to
/// `attome_core::ALL_SYSTEM_COLS`; the predicate is the preferred form and
/// `purge` predates it.
const EXCLUSION_SPELLINGS: &[&str] = &["is_system_managed_column", "ALL_SYSTEM_COLS"];

/// The marker whose appearance ends the scanned region of a file. Unit tests
/// legitimately build the same SQL shapes in order to assert on them
/// (`purge.rs`'s own `set_clauses_never_touch_a_system_column` is one) and are
/// not part of the running surface. Every `#[cfg(test)]` module in this
/// workspace is the last item in its file, so truncating there is exact rather
/// than heuristic.
const TEST_MODULE_MARKER: &str = "#[cfg(test)]";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/server; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            // `target/` is build output. `tests/` holds this file itself and
            // fixtures that deliberately model shapes the guard rejects.
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if matches!(
                name.as_deref(),
                Some("target") | Some("tests") | Some("benches")
            ) {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// One discovered site: repo-relative path, enclosing function, 1-based line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Site {
    file: String,
    function: String,
    line: usize,
}

/// Finds `quote_ident(&<x>.logicalname)` and attributes it to the nearest
/// preceding `fn` header.
///
/// A line-oriented scan, not a parse: this workspace writes one `fn` header
/// per line and never nests a function inside another, so "nearest preceding
/// `fn`" is the enclosing function. A closure inside a function is still
/// attributed to that function, which is what we want — all three `upsert`
/// sites sit inside `.map(...)` closures.
fn scan(source: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut current = "<module>".to_owned();
    for (idx, line) in source.lines().enumerate() {
        if line.trim_start().starts_with(TEST_MODULE_MARKER) {
            break;
        }
        if let Some(name) = fn_name(line) {
            current = name;
        }
        if emits_attribute_ident(line) {
            out.push((current.clone(), idx + 1));
        }
    }
    out
}

/// `[pub[(..)]] [async] fn <name>` at the start of a line (modulo indent).
fn fn_name(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    loop {
        let before = rest;
        for prefix in [
            "pub(crate) ",
            "pub(super) ",
            "pub(self) ",
            "pub ",
            "async ",
            "const ",
            "unsafe ",
        ] {
            if let Some(stripped) = rest.strip_prefix(prefix) {
                rest = stripped;
            }
        }
        if rest == before {
            break;
        }
    }
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// `quote_ident(&<ident>.logicalname)`, tolerating whitespace. Deliberately
/// narrow: `quote_ident(&entity_logicalname)` and friends name a *table*, not
/// an attribute, and are not this guard's concern.
fn emits_attribute_ident(line: &str) -> bool {
    let Some(at) = line.find("quote_ident(") else {
        return false;
    };
    let after = line[at + "quote_ident(".len()..].trim_start();
    let Some(after) = after.strip_prefix('&') else {
        return false;
    };
    let after = after.trim_start();
    let ident: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    !ident.is_empty()
        && after[ident.len()..]
            .trim_start()
            .starts_with(".logicalname")
}

/// Executable text of `function` within `source`, from its `fn` header to the
/// next one — enough to look for the exclusion call.
///
/// Comment lines are dropped, and that is the point rather than tidiness. The
/// functions this checks all *discuss* the exclusion in prose, so leaving
/// comments in would let a `see is_system_managed_column` line that outlived
/// the call it refers to keep the guard green after the filter itself was
/// gone — the exact rot this test exists to catch. The claim has to be backed
/// by code.
fn function_text(source: &str, function: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in source.lines() {
        if line.trim_start().starts_with(TEST_MODULE_MARKER) {
            break;
        }
        match fn_name(line) {
            Some(name) if name == function => inside = true,
            Some(_) if inside => break,
            _ => {}
        }
        if inside && !line.trim_start().starts_with("//") {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn discover() -> Vec<Site> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);
    files.sort();

    let mut sites = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path).expect("read source");
        let rel = path
            .strip_prefix(&root)
            .expect("path under workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        for (function, line) in scan(&source) {
            sites.push(Site {
                file: rel.clone(),
                function,
                line,
            });
        }
    }
    sites
}

#[test]
fn every_attribute_sql_site_is_classified() {
    let sites = discover();
    assert!(
        !sites.is_empty(),
        "found no `quote_ident(&x.logicalname)` sites at all — the scanner is \
         broken, or the workspace layout moved. A guard that finds nothing \
         passes for the wrong reason."
    );

    let registered: BTreeSet<(&str, &str)> = ATTRIBUTE_SQL_SITES
        .iter()
        .map(|(file, function, _, _)| (*file, *function))
        .collect();

    let unregistered: Vec<String> = sites
        .iter()
        .filter(|s| !registered.contains(&(s.file.as_str(), s.function.as_str())))
        .map(|s| format!("  {}:{} in `{}`", s.file, s.line, s.function))
        .collect();

    assert!(
        unregistered.is_empty(),
        "these functions write an entity attribute name into SQL but are not \
         classified in ATTRIBUTE_SQL_SITES:\n{}\n\nAdd each one. If it builds \
         an INSERT column list or an UPDATE SET clause from a request body it \
         must filter `attome_core::ALL_SYSTEM_COLS` (use \
         `entity_mutation::is_system_managed_column`) and be classified \
         ExcludesSystemCols — otherwise a caller can set organization_ref, \
         owner_ref/owner_type, created_by/created_at, is_active, row_version or \
         id straight from the body. See SEC-1.",
        unregistered.join("\n")
    );
}

#[test]
fn no_registry_entry_is_stale() {
    let sites = discover();
    let found: BTreeSet<(String, String)> = sites
        .iter()
        .map(|s| (s.file.clone(), s.function.clone()))
        .collect();

    let stale: Vec<String> = ATTRIBUTE_SQL_SITES
        .iter()
        .filter(|(file, function, _, _)| {
            !found.contains(&((*file).to_owned(), (*function).to_owned()))
        })
        .map(|(file, function, _, _)| format!("  {file} in `{function}`"))
        .collect();

    assert!(
        stale.is_empty(),
        "these ATTRIBUTE_SQL_SITES entries no longer match any site — the \
         function was renamed, moved or deleted. Remove or update them, so the \
         registry keeps describing the code instead of drifting into \
         decoration:\n{}",
        stale.join("\n")
    );
}

#[test]
fn every_excludes_system_cols_claim_is_backed_by_the_code() {
    let root = workspace_root();
    let mut unproven = Vec::new();

    for (file, function, classification, _) in ATTRIBUTE_SQL_SITES {
        if *classification != ExcludesSystemCols {
            continue;
        }
        let source =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let body = function_text(&source, function);
        assert!(
            !body.is_empty(),
            "{file}: could not locate `fn {function}` to verify its claim"
        );
        if !EXCLUSION_SPELLINGS.iter().any(|s| body.contains(s)) {
            unproven.push(format!("  {file} in `{function}`"));
        }
    }

    assert!(
        unproven.is_empty(),
        "these sites are registered ExcludesSystemCols but their function \
         contains no exclusion against ALL_SYSTEM_COLS (expected one of \
         {EXCLUSION_SPELLINGS:?}). Either the filter was removed — which \
         reopens SEC-1 on that path — or the classification is wrong:\n{}",
        unproven.join("\n")
    );
}

/// The registry is a security control, so it has to read as one.
#[test]
fn every_registry_entry_states_a_reason() {
    for (file, function, _, reason) in ATTRIBUTE_SQL_SITES {
        assert!(
            reason.len() >= 20,
            "{file} in `{function}`: the reason must say why this site is \
             safe, in enough words for a reviewer to disagree with it"
        );
    }
}

/// The scanner is the load-bearing part of this guard: if it stops matching,
/// every test above passes while checking nothing. These pin its behaviour
/// against the exact spellings the workspace uses today.
mod scanner {
    use super::{emits_attribute_ident, function_text, scan};

    #[test]
    fn matches_the_spellings_in_use() {
        assert!(emits_attribute_ident(
            "cols.push(quote_ident(&attr.logicalname));"
        ));
        assert!(emits_attribute_ident(
            "    let col = quote_ident(&a.logicalname);"
        ));
        assert!(emits_attribute_ident(
            ".map(|a| format!(\"{} = NULL\", quote_ident(&a.logicalname)))"
        ));
        assert!(emits_attribute_ident(
            "            quote_ident( & attr.logicalname ),"
        ));
    }

    #[test]
    fn ignores_table_identifiers_and_unrelated_calls() {
        assert!(!emits_attribute_ident(
            "let table = quote_ident(entity_logicalname);"
        ));
        assert!(!emits_attribute_ident(
            "let target_table = quote_ident(&target_logicalname);"
        ));
        assert!(!emits_attribute_ident(
            "let x = something(&attr.logicalname);"
        ));
    }

    #[test]
    fn attributes_a_site_to_its_enclosing_function() {
        let src = "pub fn alpha() {\n    let a = 1;\n}\n\npub(crate) fn beta(x: u8) -> u8 {\n    cols.push(quote_ident(&attr.logicalname));\n    x\n}\n";
        assert_eq!(scan(src), vec![("beta".to_owned(), 6)]);
    }

    #[test]
    fn stops_at_the_test_module() {
        let src = "pub fn alpha() {\n    let a = 1;\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn helper() {\n        cols.push(quote_ident(&attr.logicalname));\n    }\n}\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn function_text_stops_at_the_next_function() {
        let src = "fn alpha() {\n    is_system_managed_column(\"x\");\n}\n\nfn beta() {\n    let y = 1;\n}\n";
        assert!(function_text(src, "alpha").contains("is_system_managed_column"));
        assert!(!function_text(src, "beta").contains("is_system_managed_column"));
    }

    /// A comment that outlived the call it describes must not keep an
    /// ExcludesSystemCols claim green.
    #[test]
    fn function_text_ignores_comments() {
        let src = "fn alpha() {
    // see is_system_managed_column for why
    let y = 1;
}
";
        assert!(!function_text(src, "alpha").contains("is_system_managed_column"));
    }
}

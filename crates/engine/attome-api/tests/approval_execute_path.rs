//! BAP-11a / D-518 — the execute-path guard.
//!
//! D-518's invariant A3 says an approved action is dispatched by exactly one
//! caller: the one whose CAS moved the request `approved -> executing`. That
//! holds only while there is exactly one `claim -> dispatch -> close`
//! function (`approval_admin::execute_approved`) and every path that
//! dispatches reaches it *after* taking the claim. Both are structural
//! properties of the source, not of any one run, so this is a source-level
//! guard in the same shape as `entity_module_gate.rs`'s seed-file scans.
//!
//! Run with the rest of the approval suites:
//! `cargo test -p attome-api --test approval_execute_path`

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

const APPROVAL_ADMIN_SRC: &str = include_str!("../src/approval_admin.rs");

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

type Line = (usize, String);

fn lines() -> Vec<Line> {
    APPROVAL_ADMIN_SRC
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

/// Every line that *calls* `name(`, excluding comments and the function's own
/// definition (`fn name(` / `async fn name(`).
fn call_lines(all: &[Line], name: &str) -> Vec<Line> {
    let needle = format!("{name}(");
    let definition = format!("fn {name}");
    all.iter()
        .filter(|(_, l)| !is_comment(l))
        .filter(|(_, l)| l.contains(&needle))
        .filter(|(_, l)| !l.contains(&definition))
        .cloned()
        .collect()
}

/// The name of the function a line sits inside: the nearest `fn` line before
/// it. `None` for a comment.
fn enclosing_fn(all: &[Line], call_line: usize) -> Option<(usize, String)> {
    for (num, line) in all.iter().rev() {
        if *num >= call_line || is_comment(line) {
            continue;
        }
        let Some(idx) = line.find("fn ") else {
            continue;
        };
        let name: String = line[idx + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some((*num, name));
        }
    }
    None
}

/// The single dispatch function is reached from exactly three places: the
/// decide route (a human's approval closing the request), `retry-execution`
/// (an admin recovering a stuck request) and `execute_approved_request`
/// (BAP-11b, the job that carries out a policy auto-approval). A fourth
/// caller would be a new dispatch path nobody reviewed against D-518.
#[test]
fn execute_approved_has_exactly_three_call_sites() {
    let all = lines();
    let calls = call_lines(&all, "execute_approved");
    let owners: Vec<String> = calls
        .iter()
        .map(|(num, _)| {
            enclosing_fn(&all, *num)
                .unwrap_or_else(|| panic!("line {num} calls execute_approved outside any fn"))
                .1
        })
        .collect();
    assert_eq!(
        calls.len(),
        3,
        "execute_approved must have exactly three call sites, found {calls:?}"
    );
    let mut sorted = owners.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![
            "do_decide".to_string(),
            "execute_approved_request".to_string(),
            "retry_execution".to_string(),
        ],
        "the only dispatch paths are the decide route, retry-execution and the auto-approval job; found {owners:?}"
    );
}

/// Every call to the dispatch function happens after the caller has taken the
/// execution claim (`claim_execution`) or explicitly taken over a stale one
/// (`take_over_stale_execution`). Without this the guard above would still
/// pass for a caller that dispatched unclaimed — exactly the race D-518
/// closed.
#[test]
fn every_execute_approved_call_site_claims_first() {
    let all = lines();
    let calls = call_lines(&all, "execute_approved");
    assert!(!calls.is_empty(), "the guard must find the call sites");
    for (call_num, call_text) in &calls {
        let (fn_start, fn_name) = enclosing_fn(&all, *call_num)
            .unwrap_or_else(|| panic!("line {call_num} is not inside a function"));
        let claimed = all
            .iter()
            .filter(|(num, _)| *num > fn_start && *num < *call_num)
            .any(|(_, l)| {
                !is_comment(l)
                    && (l.contains("claim_execution(") || l.contains("take_over_stale_execution("))
            });
        assert!(
            claimed,
            "{fn_name} (line {fn_start}) dispatches at line {call_num} without taking the execution claim first: {call_text:?}"
        );
    }
}

/// BAP-11b's contract (3): a stale claim is taken over only by the
/// admin-acknowledged `retry-execution` path. The durable auto-execution job
/// (`execute_approved_request`) must never call `take_over_stale_execution` —
/// this guard is what keeps a new call site from quietly acquiring that power.
#[test]
fn take_over_stale_execution_has_one_call_site() {
    let all = lines();
    let calls = call_lines(&all, "take_over_stale_execution");
    assert_eq!(
        calls.len(),
        1,
        "only retry-execution may take over a stale claim, found {calls:?}"
    );
    let (num, _) = calls[0];
    let (_, owner) = enclosing_fn(&all, num).expect("the call site is inside a function");
    assert_eq!(owner, "retry_execution");
}

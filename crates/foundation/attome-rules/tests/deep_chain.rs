//! BRU-P2/BRU-P3 — the stack-depth proof for BRU-F2 (parse/nodes unbounded).
//!
//! Both tests run the real work in a **child process** so that a stack
//! overflow (which aborts, it does not unwind) fails the parent's assertion
//! instead of taking the test binary with it. The child runs this workspace's
//! own test binary with `--exact <name> --ignored`, and the work itself runs
//! on a **2 MiB thread** — the same stack size a tokio worker gets
//! (`tokio`'s default; `crates/server/src/main.rs` enlarges only the thread
//! that runs `block_on`), which is the smallest stack a real handler has.
//!
//! Run with:
//!
//! ```powershell
//! cargo test -p attome-rules --test deep_chain
//! cargo test -p attome-rules --release --test deep_chain
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{Context, Schema, Type, Value, compile, parse};

const CHILD_ENV: &str = "BASE_RULES_DEEP_CHAIN_CHILD";
const P2_CHILD: &str = "deep_chain_64kib_operator_chain_compiles_on_a_worker_sized_stack_child";
const P3_CHILD: &str = "largest_admissible_chain_evaluates_on_a_worker_sized_stack_child";

/// A tokio worker's default stack (2 MiB) — the stack a real request handler
/// has, and the one this test gives the thread that does the work.
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

/// `operand (op operand)*` — the source of a left-leaning operator chain.
fn chain(operand: &str, op: &str, count: usize) -> String {
    std::iter::repeat_n(operand, count)
        .collect::<Vec<_>>()
        .join(op)
}

/// Re-executes this test binary for exactly one ignored child test.
fn run_child(child: &str) -> std::process::ExitStatus {
    std::process::Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", child, "--ignored", "--nocapture"])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn the test binary for the child process")
}

#[test]
fn a_64_kib_operator_chain_compiles_on_a_worker_sized_stack() {
    assert!(
        std::env::var(CHILD_ENV).is_err(),
        "refusing to re-execute from inside the child process"
    );
    let status = run_child(P2_CHILD);
    assert!(
        status.success(),
        "a 64 KiB operator chain must return a typed result on a 2 MiB worker \
         stack, not overflow it (child exit status: {status})"
    );
}

#[test]
#[ignore = "child of a_64_kib_operator_chain_compiles_on_a_worker_sized_stack"]
fn deep_chain_64kib_operator_chain_compiles_on_a_worker_sized_stack_child() {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(|| {
            // Each source is <= HARD_MAX_SOURCE_BYTES (64 KiB).
            let arithmetic = chain("1", " + ", 16_384); // 65 533 bytes
            let boolean = chain("a", " and ", 10_923); // 65 533 bytes
            let product = chain("1", " * ", 16_384); // 65 533 bytes
            assert!(arithmetic.len() <= 64 * 1024);
            assert!(boolean.len() <= 64 * 1024);
            assert!(product.len() <= 64 * 1024);

            let bool_schema = Schema::new().with_field("a", Type::Bool);
            for (label, src, schema) in [
                ("arithmetic", &arithmetic, Schema::new()),
                ("product", &product, Schema::new()),
                ("boolean", &boolean, bool_schema),
            ] {
                let out = compile(src, &schema);
                // Never Debug-print the compiled tree: a deep AST's derived
                // Debug recurses per level, which is the thing under test.
                println!(
                    "BRU-P2 {label}: {bytes} bytes -> {result}",
                    bytes = src.len(),
                    result = if out.is_ok() { "compiled" } else { "rejected" }
                );
                drop(out);
            }

            for (label, src) in [
                ("arithmetic", &arithmetic),
                ("boolean", &boolean),
                ("product", &product),
            ] {
                let out = parse(src);
                println!(
                    "BRU-P2 parse {label}: {bytes} bytes -> {result}",
                    bytes = src.len(),
                    result = if out.is_ok() { "ok" } else { "err" }
                );
                drop(out);
            }
        })
        .expect("spawn a 2 MiB thread")
        .join()
        .expect("the 2 MiB worker-sized thread must not panic or overflow");
}

#[test]
fn the_largest_admissible_chain_evaluates_on_a_worker_sized_stack() {
    assert!(
        std::env::var(CHILD_ENV).is_err(),
        "refusing to re-execute from inside the child process"
    );
    let status = run_child(P3_CHILD);
    assert!(
        status.success(),
        "the largest admissible chain must evaluate on a 2 MiB worker stack \
         (child exit status: {status})"
    );
}

#[test]
#[ignore = "child of the_largest_admissible_chain_evaluates_on_a_worker_sized_stack"]
fn largest_admissible_chain_evaluates_on_a_worker_sized_stack_child() {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(|| {
            // The 1 999-node chain the default node budget alone would admit.
            // It must return a typed result (after BRU-A2 the depth ceiling
            // rejects it); it must never overflow this stack.
            let full = chain("1", " + ", 1_000); // 1 999 AST nodes
            let out = compile(&full, &Schema::new());
            println!(
                "BRU-P3 1999-node chain -> {}",
                if out.is_ok() { "compiled" } else { "rejected" }
            );
            drop(out);

            // The largest chain the depth ceiling admits, evaluated with the
            // trace on. 127 links -> 128 levels, 253 nodes.
            let admissible = chain("1", " + ", 127);
            let compiled = compile(&admissible, &Schema::new())
                .expect("a 127-link chain is inside the depth ceiling");
            let ctx = Context::new(chrono::Utc::now());
            let (value, trace) = compiled
                .eval_traced(&ctx)
                .expect("the admissible chain evaluates");
            assert!(matches!(value, Value::Number(_)));
            assert_eq!(trace.entries().len(), 253);
            println!(
                "BRU-P3 127-link chain: value={value} trace_entries={}",
                trace.entries().len()
            );
        })
        .expect("spawn a 2 MiB thread")
        .join()
        .expect("the 2 MiB worker-sized thread must not panic or overflow");
}

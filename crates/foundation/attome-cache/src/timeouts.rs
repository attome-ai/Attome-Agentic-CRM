//! Every Redis operation this crate issues is bounded by a constant defined
//! **here** and nowhere else (BCA-13, plan §2.1/§4.1).
//!
//! Before this module each concern carried its own private
//! OP_TIMEOUT = Duration::from_millis(300) (or 500), four operations carried
//! **no** bound at all (BCA-F3: pin_write, pin_write_with_lsn, redis_ping, the
//! subscriber), and the numbers could drift apart one module at a time with
//! nothing to notice.
//!
//! The constants are public (cleanup 3.3): a Redis call in another crate takes
//! its bound from here by class instead of re-declaring the number.
//!
//! The split is by call-site class, not by server:
//!
//! - [`REQUEST_PATH`] — a human (or a pre-auth limiter) is waiting. Rate
//!   limiting, the read-your-writes pin, the token window, and the
//!   write-coalescing `set`/`set_with_ttl`/`incr` every authenticated request
//!   awaits.
//! - [`BACKGROUND`] — a metrics tick, a flusher, or a supervising probe.
//!   Streams, the coalescing drain, the persistence/memory probes, and the
//!   readiness ping.
//! - [`CONNECT`] — one connection attempt by a pooled client, reconnects
//!   included.
//! - [`STREAM_BLOCK_SLACK`] — added to a consumer's own block_ms so the
//!   *client* deadline outlives the server-side BLOCK the caller asked for.
//!
//! These are deliberately **not** cache.timeout: that key is an operator knob
//! (2000 ms by default) and 0 meant "no timeout at all" until BCA-14 made boot
//! refuse it. A crate constant cannot be configured into unbounded.

use std::time::Duration;

/// Bound for an operation a request is waiting on: pre-auth rate limiting,
/// the rw-pin check, the token-window read/charge, the coalescing writes on
/// the authenticated path. 300 ms is the crate's
/// long-standing request-path number (D-208/D-251 observed one timeout against
/// Docker Desktop/WSL2 at exactly this bound).
pub const REQUEST_PATH: Duration = Duration::from_millis(300);

/// Bound for an operation on a tick, a flusher, or a probe — stream
/// add/read/ack/autoclaim, the coalescing drain, the persistence and
/// memory probes, and the readiness ping. 500 ms matches the value
/// stream_buffer and persistence have carried since they shipped.
pub const BACKGROUND: Duration = Duration::from_millis(500);

/// Extra client-side deadline a blocking stream read adds to its own block_ms
/// argument: a consumer legitimately waits **inside** Redis for up to
/// block_ms, so the client bound must exceed the server-side block, not merely
/// cover network latency.
pub const STREAM_BLOCK_SLACK: Duration = Duration::from_millis(500);

/// Bound for one connection attempt by a pooled client (fred's own default is
/// 10 s), so an attempt against a dead endpoint does not stall a reconnect
/// cycle.
pub const CONNECT: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan's numbers, pinned so a "small tweak" is a deliberate edit to
    /// this file and to the plan — not a private constant that reappears in a
    /// module.
    #[test]
    fn timeouts_are_the_values_the_plan_states() {
        assert_eq!(REQUEST_PATH, Duration::from_millis(300));
        assert_eq!(BACKGROUND, Duration::from_millis(500));
        assert_eq!(STREAM_BLOCK_SLACK, Duration::from_millis(500));
        assert_eq!(CONNECT, Duration::from_secs(2));
        assert!(
            BACKGROUND > REQUEST_PATH,
            "a background op may outlive a user-facing one"
        );
    }

    /// Every line of a module outside a `#[cfg(test)]` module (a column-0
    /// attribute followed by `mod`, skipped to its column-0 closing brace),
    /// comment lines dropped.
    fn production_lines(source: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut lines = source.lines().peekable();
        while let Some(line) = lines.next() {
            if line == "#[cfg(test)]"
                && lines
                    .peek()
                    .is_some_and(|next| next.starts_with("mod ") || next.starts_with("pub mod "))
            {
                for skipped in lines.by_ref() {
                    if skipped == "}" {
                        break;
                    }
                }
                continue;
            }
            if !line.trim_start().starts_with("//") {
                out.push(line);
            }
        }
        out
    }

    /// A line that picks a bound of its own: a `const`/`static` of any
    /// visibility holding a `Duration`, or a `Duration` built inline from a
    /// numeric literal. One built from a variable (a caller's block_ms, an
    /// entry TTL, a computed elapsed time) is not a bound this crate chose.
    fn defines_own_bound(line: &str) -> bool {
        let mut decl = line.trim();
        if let Some(rest) = decl.strip_prefix("pub") {
            decl = match rest.strip_prefix('(') {
                Some(scoped) => scoped.split_once(')').map_or(rest, |(_, after)| after),
                None => rest,
            }
            .trim_start();
        }
        if (decl.starts_with("const ") || decl.starts_with("static ")) && decl.contains("Duration")
        {
            return true;
        }
        line.match_indices("Duration::from_").any(|(at, needle)| {
            line[at + needle.len()..]
                .split_once('(')
                .and_then(|(_, arg)| arg.trim_start().chars().next())
                .is_some_and(|c| c.is_ascii_digit())
        })
    }

    #[test]
    fn the_bound_scan_catches_every_declaration_shape() {
        for line in [
            "const T: Duration = Duration::from_millis(300);",
            "pub const T: Duration = Duration::from_millis(300);",
            "pub(crate) const T: Duration = Duration::from_millis(300);",
            "pub(super) const T: std::time::Duration = std::time::Duration::from_secs(1);",
            "static T: Duration = Duration::from_millis(300);",
            "    tokio::time::timeout(Duration::from_millis(250), op).await;",
            "    c.connection_timeout = std::time::Duration::from_secs(2);",
        ] {
            assert!(defines_own_bound(line), "not caught: {line}");
        }
        for line in [
            "    .time_to_live(Duration::from_secs(ttl_secs))",
            "    let client_timeout = Duration::from_millis(block_ms) + STREAM_BLOCK_SLACK;",
            "    Duration::from_secs(((now_bucket - oldest) * width).max(0) as u64)",
            "    tokio::time::timeout(REQUEST_PATH, op).await;",
        ] {
            assert!(!defines_own_bound(line), "false positive: {line}");
        }
        let source = "fn a() {}\n#[cfg(test)]\nmod tests {\n    const T: Duration = Duration::from_millis(1);\n}\nfn b() {}\n";
        assert_eq!(production_lines(source), vec!["fn a() {}", "fn b() {}"]);
    }

    /// A module that picks its own bound is the exact drift BCA-13 removes.
    /// Scans the crate's own sources (compiled-in manifest path, not a
    /// hardcoded absolute one) so a future module is covered the moment it is
    /// added.
    #[test]
    fn no_module_outside_timeouts_defines_its_own_op_bound() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&src).expect("read src/") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name == "timeouts.rs" {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read module");
            checked += 1;
            for line in production_lines(&source) {
                assert!(
                    !defines_own_bound(line),
                    "{name} defines its own op bound; import it from crate::timeouts instead: {}",
                    line.trim()
                );
            }
        }
        assert!(
            checked >= 7,
            "expected to scan every Redis module, only saw {checked} files"
        );
    }

    /// Every module that issues a Redis call must take its bound from this
    /// module. Without this, the scan above passes trivially for a module that
    /// simply stopped bounding its calls.
    #[test]
    fn every_redis_module_uses_the_shared_bounds() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for name in [
            "redis_pool.rs",
            "rate_limit.rs",
            "sticky_primary.rs",
            "token_window.rs",
            "stream_buffer.rs",
            "write_coalesce.rs",
            "persistence.rs",
        ] {
            let source = std::fs::read_to_string(src.join(name)).expect("read module");
            assert!(
                source.contains("timeouts::"),
                "{name} issues Redis calls but never imports a bound from crate::timeouts"
            );
        }
    }
}

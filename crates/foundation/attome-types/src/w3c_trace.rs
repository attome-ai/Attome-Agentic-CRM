//! P-observability-completion — W3C Trace Context (`traceparent` header,
//! <https://www.w3.org/TR/trace-context/#traceparent-header>) format/parse
//! helpers, shared by every crate that needs to move a trace's identity
//! across a boundary the OTel SDK doesn't already instrument for us:
//! `attome_jobs::enqueue*` (capture the ambient span's context into a
//! `PlatformJob` envelope), `attome_auth::oidc` (inject it into an outbound
//! `reqwest` call), and `attome_server::middleware::trace_context` (extract an
//! inbound header into a real span parent, not just a logged string).
//!
//! Deliberately hand-rolled rather than routed through
//! `opentelemetry::global::get_text_map_propagator()` +
//! `opentelemetry_sdk::propagation::TraceContextPropagator`: the concrete W3C
//! propagator implementation lives in `opentelemetry_sdk`, and keeping that
//! crate (and its transitive exporter/runtime machinery) out of attome-jobs/
//! attome-auth/attome-server — confining it to `crates/server` only — is the same
//! "facade in the lower layers, implementation in the binary" split this
//! plan's design applies to the metrics stack (`metrics` facade vs.
//! `metrics-exporter-prometheus`). The format is simple and stable enough
//! (four dash-separated fields, unchanged since the spec's first stable
//! release) that hand-rolling it here is lower risk than adding a second
//! crate's worth of transitive dependencies to three lower-layer crates for
//! one function each.
//!
//! Compiled and tested 2026-08-24 (MAINT-10). This header previously read
//! "COMPILE-UNVERIFIED: written with no Rust toolchain available to `cargo
//! check` against", naming `TraceId`/`SpanId::from_hex`, `TraceFlags::new`/
//! `to_u8` and `SpanContext::new` as the signatures most likely to need a
//! follow-up patch. They did not: `cargo check -p attome-types` is clean and
//! this module's eight unit tests below pass. The constraint that produced
//! that caveat expired without anything re-examining it, which is the whole
//! of MAINT-10 — an unverified-status note is a claim with a shelf life, and
//! nothing expires it automatically.

use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};

/// Formats a `SpanContext` as a W3C `traceparent` header value, or `None`
/// when there's no valid ambient trace — the case for every span today while
/// `observability.enable_distributed_tracing = false`, since a `SpanContext`
/// with no backing `tracing-opentelemetry` layer is always invalid. Callers
/// (`attome_jobs::enqueue*`, `attome_auth::oidc`'s outbound calls) treat `None`
/// as "nothing to propagate," never an error.
pub fn format_traceparent(span_context: &SpanContext) -> Option<String> {
    if !span_context.is_valid() {
        return None;
    }
    Some(format!(
        "00-{}-{}-{:02x}",
        span_context.trace_id(),
        span_context.span_id(),
        span_context.trace_flags().to_u8()
    ))
}

/// Convenience wrapper: pulls the `SpanContext` off the current `tracing`
/// span (via `tracing_opentelemetry::OpenTelemetrySpanExt::context()`,
/// called by the caller since that trait/the `Context` extraction itself
/// lives in `tracing-opentelemetry`, not this crate) and formats it. Callers
/// pass `tracing::Span::current().context()` (an `opentelemetry::Context`);
/// this function only needs the span reference inside it.
pub fn format_current_traceparent(cx: &opentelemetry::Context) -> Option<String> {
    format_traceparent(cx.span().span_context())
}

/// Parses a W3C `traceparent` header value into a remote `SpanContext`
/// (`is_remote() == true`), or `None` if the value is malformed or carries an
/// all-zero trace/span id (explicitly invalid per the spec). A malformed or
/// absent header degrades to "no parent" rather than rejecting the
/// request/job — same posture `attome_server::middleware::trace_context`
/// already takes for a non-UTF8 header value.
/// True only for a non-empty run of lowercase hex digits. The spec's
/// `traceparent` fields are lowercase hex, and `TraceId::from_hex` alone is
/// too permissive to stand in: it is a bare `from_str_radix`, so it also
/// accepts Rust's `+` sign prefix and uppercase digits (BTY-F7).
fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn parse_traceparent(value: &str) -> Option<SpanContext> {
    let mut parts = value.trim().split('-');
    let version = parts.next()?;
    let trace_id_hex = parts.next()?;
    let span_id_hex = parts.next()?;
    let flags_hex = parts.next()?;
    let trailing = parts.next();

    // Version: exactly two lowercase hex digits. "ff" is reserved by the
    // spec as permanently invalid.
    if version.len() != 2 || !is_lower_hex(version) || version == "ff" {
        return None;
    }
    // A version-00 header is exactly four fields. A higher version may
    // append vendor fields this reader does not understand — per the spec it
    // must ignore them rather than reject the whole header.
    if version == "00" && trailing.is_some() {
        return None;
    }
    // Ids and flags are fixed-width lowercase hex; a short, signed or
    // uppercase field is malformed, not merely unusual.
    if trace_id_hex.len() != 32 || !is_lower_hex(trace_id_hex) {
        return None;
    }
    if span_id_hex.len() != 16 || !is_lower_hex(span_id_hex) {
        return None;
    }
    if flags_hex.len() != 2 || !is_lower_hex(flags_hex) {
        return None;
    }

    let trace_id = TraceId::from_hex(trace_id_hex).ok()?;
    let span_id = SpanId::from_hex(span_id_hex).ok()?;
    let flags = u8::from_str_radix(flags_hex, 16).ok()?;
    if trace_id == TraceId::INVALID || span_id == SpanId::INVALID {
        return None;
    }
    Some(SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::new(flags),
        true,
        TraceState::default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_returns_none_for_an_invalid_span_context() {
        assert!(format_traceparent(&SpanContext::empty_context()).is_none());
    }

    #[test]
    fn format_and_parse_round_trip() {
        let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let span_id = SpanId::from_hex("00f067aa0ba902b7").unwrap();
        let span_context = SpanContext::new(
            trace_id,
            span_id,
            TraceFlags::new(0x01),
            false,
            TraceState::default(),
        );

        let formatted = format_traceparent(&span_context).unwrap();
        assert_eq!(
            formatted,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );

        let parsed = parse_traceparent(&formatted).unwrap();
        assert_eq!(parsed.trace_id(), trace_id);
        assert_eq!(parsed.span_id(), span_id);
        assert_eq!(parsed.trace_flags().to_u8(), 0x01);
        assert!(parsed.is_remote());
    }

    #[test]
    fn parse_rejects_wrong_field_count() {
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7").is_none()
        );
    }

    #[test]
    fn parse_rejects_reserved_ff_version() {
        assert!(
            parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none()
        );
    }

    #[test]
    fn parse_rejects_all_zero_trace_id() {
        assert!(
            parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none()
        );
    }

    #[test]
    fn parse_rejects_all_zero_span_id() {
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none()
        );
    }

    #[test]
    fn parse_rejects_non_hex_garbage() {
        assert!(parse_traceparent("not-a-traceparent-header").is_none());
    }

    #[test]
    fn parse_ignores_surrounding_whitespace() {
        let parsed =
            parse_traceparent("  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01  ");
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_rejects_version_00_with_extra_field() {
        // Exactly four fields are allowed for version 00; a fifth is invalid
        // even though a *higher* version may append one.
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra")
                .is_none()
        );
    }

    #[test]
    fn parse_rejects_three_char_flags() {
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011").is_none()
        );
    }

    // ── BTY-P0.2 → BTY-F7 (S7): the inbound parse must be exact W3C ──────────
    //
    // TraceId/SpanId::from_hex are bare from_str_radix in the pinned
    // opentelemetry (0.32.0), so a +-prefixed, uppercase or short field
    // parses today; the version was only length-checked, so "zz" passed too.
    // A guessed or malformed trace id must never attach the caller to a span.

    #[test]
    fn parse_rejects_short_trace_id() {
        // 31 hex digits, one short of the required 32.
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01").is_none()
        );
    }

    #[test]
    fn parse_rejects_plus_prefixed_field() {
        // 32 characters, but the leading + is Rust's sign prefix for
        // from_str_radix, not a hex digit.
        assert!(
            parse_traceparent("00-+bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none()
        );
        // Same hole on the span id.
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-+0f067aa0ba902b7-01").is_none()
        );
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        assert!(
            parse_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").is_none()
        );
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00F067AA0BA902B7-01").is_none()
        );
        assert!(
            parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0A").is_none()
        );
    }

    #[test]
    fn parse_rejects_non_hex_version() {
        assert!(
            parse_traceparent("zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none()
        );
    }

    /// The module's own doc comment promises not to reject on version alone:
    /// a future version may add trailing fields, which a version-00-aware
    /// reader must ignore. parts.len() != 4 did reject them.
    #[test]
    fn parse_accepts_future_version_with_extra_field() {
        let parsed =
            parse_traceparent("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra");
        assert!(
            parsed.is_some(),
            "a higher version's trailing fields must be ignored, not rejected"
        );
    }
}

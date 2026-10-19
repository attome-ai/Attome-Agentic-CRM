//! SEC-10 part (a): pins which request headers the S2S signature does *not*
//! cover, so a third one cannot appear silently.
//!
//! # What the signature actually covers
//!
//! [`attome_s2s::crypto::canonical_message`] signs exactly five fields:
//!
//! ```text
//! method \n path_and_query \n body_sha256_hex \n timestamp_ms \n nonce
//! ```
//!
//! S1-T10 adds one more, only when present: `x-attome-act-as`'s value is a
//! sixth line ([`attome_s2s::crypto::canonical_message_with_act_as`]), so a
//! client cannot be made to act as a user it did not sign for. It is not in
//! the CORS allow-list below (a browser never sends it).
//!
//! **No other request header is covered by name.** `x-s2s-timestamp` and
//! `x-s2s-nonce` are safe because their *values* are two of those fields, and
//! `x-s2s-client-id`/`x-s2s-key-id` are safe because tampering with either
//! selects a different secret, so verification fails. Every other header a
//! handler reads is outside the signature.
//!
//! # Why this is a registry and not a scanner
//!
//! The obvious test — "assert no handler reads an uncovered header" — is a
//! test written to describe an intention rather than the code: two handlers
//! read uncovered headers today, so it would fail on arrival. The honest
//! inverse is to pin the set.
//!
//! A source scanner was tried first and rejected as unreliable. Header reads
//! go through module constants (`idempotency.rs`'s `const HEADER`,
//! `middleware.rs`'s `H_CLIENT_ID`…), so a lexical scan for `.get("literal")`
//! misses real reads while matching unrelated `HashMap::get` calls. It would
//! have produced confident, wrong coverage — the failure mode this file exists
//! to prevent.
//!
//! Instead this asserts against [`attome_server::app::allowed_request_headers`],
//! which is a genuine chokepoint: it is the CORS allow-list, so a header a
//! client cannot send is a header no handler can read from a real caller, and
//! it is a fixed-size array, so adding one is already a compile error at its
//! own definition. Its doc comment says as much — *"treat this list as part of
//! the request contract"*.
//!
//! # Scope
//!
//! This does not close the gap; it bounds it. Closing it means changing the
//! canonical message, which re-signs every deployed S2S client at once and is
//! a §12 public-contract change requiring a compatibility window. That is
//! escalated separately, not done here.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::app::allowed_request_headers;

/// How each allowed request header stands relative to the S2S signature.
#[derive(Debug, PartialEq, Eq)]
enum Coverage {
    /// Outside the signature, and tampering changes what a handler does.
    /// This is the set SEC-10 is about, and it must not grow silently.
    UnsignedAndBehavioural,
    /// Outside the signature, but tampering cannot change the outcome of a
    /// verified request — correlation/diagnostic values, or ones whose effect
    /// is already fail-closed.
    UnsignedButInert,
}

use Coverage::{UnsignedAndBehavioural, UnsignedButInert};

/// Every header `allowed_request_headers()` permits, classified, with the
/// reason recorded next to it. Adding a header to that list without adding it
/// here fails `every_allowed_request_header_is_classified`.
const CLASSIFIED: &[(&str, Coverage, &str)] = &[
    (
        "accept",
        UnsignedButInert,
        "response-shape negotiation; cannot alter a mutation's effect",
    ),
    (
        "accept-language",
        UnsignedButInert,
        "locale selection for response text only",
    ),
    (
        "authorization",
        UnsignedButInert,
        "an S2S request authenticates via the x-s2s-* headers; s2s_authn injects \
         SessionClaims itself, so a tampered bearer token does not widen \
         authority on the verified path",
    ),
    (
        "content-type",
        UnsignedButInert,
        "the body's bytes are signed via body_sha256_hex; axum's Json extractor \
         rejects a mismatched type, so tampering fails closed rather than \
         reinterpreting signed bytes",
    ),
    (
        "idempotency-key",
        UnsignedButInert,
        "the standard name of x-idempotency-key (S9-T1). The idempotency gate \
         does not read it on a request carrying x-s2s-client-id, so on the S2S \
         path only the classified x-idempotency-key counts: fail-closed",
    ),
    (
        "if-match",
        UnsignedAndBehavioural,
        "optimistic concurrency. D-079 makes it MANDATORY on PATCH, so stripping \
         it there is a 422 (fail-closed, availability only). The real exposure is \
         DELETE/restore, where DATA-7/CONC-1 made it optional: stripping it \
         silently downgrades a guarded delete to an unguarded one",
    ),
    (
        "if-match-merge",
        UnsignedButInert,
        "asks a stale PATCH to merge over attributes it does not send (A16-T2).          attome-records ignores it on any request carrying x-s2s-client-id          (merge_requested), so on the S2S path a stale version is the usual          409: fail-closed",
    ),
    (
        "traceparent",
        UnsignedButInert,
        "W3C correlation only; no authorization or data effect",
    ),
    (
        "x-attome-changeset",
        UnsignedButInert,
        "selects which open changeset records a metadata write (D-785). The \
         recorder refuses it on any request carrying x-s2s-client-id \
         (attome_core::changeset::extract), so on the S2S path it is rejected, \
         never honoured: fail-closed",
    ),
    (
        "x-idempotency-key",
        UnsignedAndBehavioural,
        "read by attome-server's idempotency middleware, which runs AFTER s2s_authn. \
         Altering it makes a retry execute again, or serves a cached response to a \
         different request. The S2S nonce still prevents wholesale replay",
    ),
    (
        "x-override-reason",
        UnsignedButInert,
        "lets a staff caller with the override privilege save past a refusing \
         business-rule check (A3-T4). The request-meta layer drops it on any \
         request carrying x-s2s-client-id, so on the S2S path the check refuses \
         as usual: fail-closed",
    ),
    (
        "x-request-id",
        UnsignedButInert,
        "client-supplied correlation id, echoed back; no authorization effect",
    ),
];

/// The two headers that are outside the signature *and* change behaviour.
/// If this assertion fails, either a new uncovered header was introduced or an
/// existing one was reclassified — both need review, not a test edit.
#[test]
fn unsigned_behavioural_headers_are_exactly_the_two_known() {
    let mut found: Vec<&str> = CLASSIFIED
        .iter()
        .filter(|(_, c, _)| *c == UnsignedAndBehavioural)
        .map(|(h, _, _)| *h)
        .collect();
    found.sort_unstable();

    assert_eq!(
        found,
        vec!["if-match", "x-idempotency-key"],
        "the set of behaviour-affecting headers outside the S2S canonical message \
         changed. This is SEC-10's whole subject: adding one silently widens the \
         signature's blind spot. Classify the new header in CLASSIFIED above with \
         its reason, and if it is behavioural, escalate — closing the gap means \
         changing the canonical message, which breaks every deployed S2S client \
         at once and needs a compatibility window."
    );
}

/// Guards against the registry going stale: a header allowed through CORS but
/// unclassified here has never been considered against the signature.
#[test]
fn every_allowed_request_header_is_classified() {
    for header in allowed_request_headers() {
        let name = header.as_str();
        assert!(
            CLASSIFIED.iter().any(|(h, _, _)| *h == name),
            "request header {name:?} is allowed by \
             attome_server::app::allowed_request_headers() but is not classified in \
             this file. Decide whether the S2S signature's not covering it is \
             harmless, and record which with the reason."
        );
    }
}

/// The reverse direction: a classification for a header that is no longer
/// accepted is dead weight that makes the registry look more thorough than it
/// is.
#[test]
fn no_classification_outlives_its_header() {
    let allowed: Vec<String> = allowed_request_headers()
        .iter()
        .map(|h| h.as_str().to_owned())
        .collect();
    for (name, _, _) in CLASSIFIED {
        assert!(
            allowed.iter().any(|a| a == name),
            "{name:?} is classified here but is no longer in \
             allowed_request_headers(); drop the entry so the registry keeps \
             describing the real contract."
        );
    }
}

/// Pins the canonical message itself. The classification above is only sound
/// while the signature still covers these five fields and no headers; a change
/// here silently invalidates every reason recorded in CLASSIFIED.
#[test]
fn canonical_message_still_covers_five_fields_and_no_headers() {
    let msg = attome_s2s::crypto::canonical_message("GET", "/api/v1/x", "hash", "100", "nonce");
    let text = String::from_utf8(msg).expect("canonical message is UTF-8");

    assert_eq!(
        text, "GET\n/api/v1/x\nhash\n100\nnonce",
        "the S2S canonical message changed shape. Every entry in CLASSIFIED \
         reasons about what the signature does and does not cover, so those \
         reasons are now unverified. Re-derive them, and note that changing this \
         format re-signs every deployed client."
    );
    assert_eq!(
        text.split('\n').count(),
        5,
        "canonical message should carry exactly five fields"
    );
}

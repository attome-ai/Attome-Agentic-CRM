//! Fuzzes `attome_s2s::crypto::{canonical_message, verify_hmac, sha256_hex}` —
//! the S2S request-signing path every inbound S2S call's `x-s2s-signature`
//! header is checked against (`middleware.rs`). Uses `arbitrary`'s derive to
//! split the fuzzer's raw bytes into the five canonical-message fields plus a
//! secret/signature pair, rather than fuzzing one flat byte string, so the
//! corpus actually explores the real multi-field shape (D-006) instead of
//! spending nearly all its budget on malformed single-string splits.
//!
//! Baseline contract only: must never panic for any combination of field
//! values, including secrets/signatures that aren't valid hex (`verify_hmac`
//! already documents returning `false` on a `hex::decode` failure — this
//! target's job is to prove that holds for every input the fuzzer finds, not
//! just the hand-picked cases `crypto.rs`'s own `#[cfg(test)]` module covers).
#![no_main]

use arbitrary::Arbitrary;
use attome_s2s::crypto::{canonical_message, sha256_hex, verify_hmac};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    method: String,
    path_and_query: String,
    body_sha256_hex: String,
    timestamp_ms: String,
    nonce: String,
    secret_hex: String,
    provided_sig_hex: String,
}

fuzz_target!(|input: FuzzInput| {
    let message = canonical_message(
        &input.method,
        &input.path_and_query,
        &input.body_sha256_hex,
        &input.timestamp_ms,
        &input.nonce,
    );
    let _ = verify_hmac(&input.secret_hex, &message, &input.provided_sig_hex);
    let _ = sha256_hex(&message);
});

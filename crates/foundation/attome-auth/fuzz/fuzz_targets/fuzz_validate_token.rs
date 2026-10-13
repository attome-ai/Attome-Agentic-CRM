//! Fuzzes `attome_auth::validate_token` (and transitively `jwt::decode_claims`)
//! against arbitrary bytes reinterpreted as a bearer/session-cookie token —
//! the exact attacker-controlled entry point every request's `Authorization`
//! header or session cookie feeds. Baseline contract only: this must never
//! panic. Deeper correctness properties (kid handling, iss/aud checks,
//! expiry) already have their own hand-written matrix in `jwt.rs`'s
//! `#[cfg(test)] mod tests` — this target's job is only to find an input
//! shape that makes the parser panic instead of returning `Err`.
#![no_main]

use attome_auth::validate_token;
use attome_config::KeyRing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    // A fixed, throwaway signing key — never a real secret (this file is
    // fuzzing the parser, not trying to forge a real token).
    let ring = KeyRing::single("fuzz-target-fixed-secret-not-a-real-key".to_owned());

    let _ = validate_token(token, &ring, "attome-fuzz-issuer", "attome-fuzz-audience");
});

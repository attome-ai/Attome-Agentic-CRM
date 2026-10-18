//! Z4-T11: fuzzes `attome_auth::jwt::validate_session_token_with` with an
//! Ed25519 ring beside the HS256 one, on arbitrary bytes read as a session
//! token. Contract: it never panics, whatever the header names (`alg`,
//! `kid`) or however the signature is mangled.
#![no_main]

use attome_auth::jwt::validate_session_token_with;
use attome_config::KeyRing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    // Fixed throwaway keys: the target fuzzes the parser, not a real key.
    let hs256 = KeyRing::single("fuzz-target-fixed-secret-not-a-real-key".to_owned());
    let eddsa = KeyRing {
        keys: std::iter::once(("ed-fuzz".to_owned(), "42".repeat(32))).collect(),
        active_key_id: "ed-fuzz".to_owned(),
    };
    let _ = validate_session_token_with(
        token,
        &hs256,
        Some(&eddsa),
        "attome-fuzz-issuer",
        "attome-fuzz-audience",
    );
});

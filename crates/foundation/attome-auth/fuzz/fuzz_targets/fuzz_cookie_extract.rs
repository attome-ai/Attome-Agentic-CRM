//! Fuzzes `attome_auth::cookie::{extract, extract_session, extract_refresh}`
//! against an arbitrary `Cookie` header value — the raw bytes a client
//! controls entirely. Baseline contract only: must never panic on any header
//! value `http::HeaderValue` itself accepts (the fuzz target relies on
//! `HeaderValue::from_str`'s own validation to skip bytes that could never
//! reach a real header anyway, e.g. embedded NUL/CR/LF).
#![no_main]

use attome_auth::cookie;
use http::{HeaderMap, HeaderValue, header::COOKIE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = HeaderValue::from_str(s) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, value);

    let _ = cookie::extract(&headers, "session_token");
    let _ = cookie::extract(&headers, "");
    let _ = cookie::extract_session(&headers, true);
    let _ = cookie::extract_session(&headers, false);
    let _ = cookie::extract_refresh(&headers, true);
    let _ = cookie::extract_refresh(&headers, false);
});

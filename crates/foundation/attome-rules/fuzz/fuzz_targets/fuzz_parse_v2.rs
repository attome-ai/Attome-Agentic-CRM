//! Fuzzes `attome_rules::parse` over arbitrary UTF-8: it returns a tree or a
//! typed error, never panics and never overflows the stack.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(src) = std::str::from_utf8(data) {
        let _ = attome_rules::parse(src);
    }
});

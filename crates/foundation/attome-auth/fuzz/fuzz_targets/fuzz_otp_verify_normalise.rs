//! Z4-T11: fuzzes `attome_auth::otp::normalize_digits`, which turns a
//! presented one-time code (ASCII, Arabic-Indic or Eastern Arabic-Indic
//! digits, with any separators) into ASCII digits. Contract: it never panics
//! and returns only ASCII digits, no more of them than the input has chars.
#![no_main]

use attome_auth::otp::normalize_digits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(presented) = std::str::from_utf8(data) else {
        return;
    };
    let digits = normalize_digits(presented);
    assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    assert!(digits.len() <= presented.chars().count());
});

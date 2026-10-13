//! RFC 8785 (JCS) canonical JSON and the `attome-changeset/v1` checksum
//! (design §5.2, D-785 rule 4).
//!
//! The reference is `canonicalize` in `scripts/changesets/lib.mjs`: object
//! members sorted by the UTF-16 code units of their names, no insignificant
//! whitespace, arrays in order, strings and numbers serialised the way
//! ECMAScript's `JSON.stringify` serialises them. A checksum computed here and
//! one computed by `write-closed.mjs` / `validate.mjs` over the same document
//! must agree byte for byte; `tests::fixture_checksums_match_the_node_tooling`
//! recomputes the committed fixtures to prove it.
//!
//! Not `bundle::canonical`: that writer prints serde's float form (`1.0` for
//! an f64 1.0), which the Node side prints as `1`, so the two would disagree
//! on any document carrying a float.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// The largest integer an IEEE double holds exactly (2^53). A JSON integer
/// beyond it is what `JSON.parse` would round, so it is canonicalised as the
/// double it becomes.
const MAX_SAFE: u64 = 1 << 53;

/// The canonical (JCS) text of `value`. Fails only on a non-finite number,
/// which `serde_json::Value` cannot hold, so in practice never.
pub fn canonicalize(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// `sha256:` + lowercase hex of the SHA-256 of `bytes`.
pub fn sha256_tagged(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// The document checksum: [`sha256_tagged`] over the canonical JSON of the
/// changeset without its `checksum` member (`computeChecksum` in `lib.mjs`).
pub fn document_checksum(document: &Value) -> Result<String, String> {
    let Value::Object(members) = document else {
        return Err("a changeset document must be a JSON object".into());
    };
    let mut rest = members.clone();
    rest.remove("checksum");
    Ok(sha256_tagged(
        canonicalize(&Value::Object(rest))?.as_bytes(),
    ))
}

fn write_value(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_text(n)?),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(members) => write_object(out, members)?,
    }
    Ok(())
}

fn write_object(out: &mut String, members: &Map<String, Value>) -> Result<(), String> {
    let mut keys: Vec<&String> = members.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        if let Some(value) = members.get(*key) {
            write_value(out, value)?;
        }
    }
    out.push('}');
    Ok(())
}

/// `JSON.stringify` for a string: `"` and `\` escaped, the five short
/// control escapes, every other control character as `\u00xx` (lowercase
/// hex), everything else (DEL, U+2028, non-ASCII) literal.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn number_text(n: &Number) -> Result<String, String> {
    if let Some(u) = n.as_u64()
        && u <= MAX_SAFE
    {
        return Ok(u.to_string());
    }
    if let Some(i) = n.as_i64()
        && i.unsigned_abs() <= MAX_SAFE
    {
        return Ok(i.to_string());
    }
    let f = n
        .as_f64()
        .ok_or_else(|| format!("number {n} has no double value"))?;
    es_number(f)
}

/// ECMAScript `Number::toString(10)` (ECMA-262 §6.1.6.1.20) for a finite
/// double: the shortest round-tripping digits, laid out plainly for decimal
/// exponents in `-6 < n <= 21` and in exponent form (`1e+21`, `1e-7`)
/// otherwise.
fn es_number(f: f64) -> Result<String, String> {
    if !f.is_finite() {
        return Err("a non-finite number cannot be canonicalized".into());
    }
    if f == 0.0 {
        return Ok("0".into());
    }
    if f < 0.0 {
        return Ok(format!("-{}", es_number(-f)?));
    }
    // Rust's `{:e}` prints the shortest round-tripping digits: `d[.ddd]e±x`.
    let sci = format!("{f:e}");
    let (mantissa, exponent) = sci
        .split_once('e')
        .ok_or_else(|| format!("unexpected float form {sci}"))?;
    let exponent: i32 = exponent
        .parse()
        .map_err(|_| format!("unexpected float exponent in {sci}"))?;
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = i32::try_from(digits.len()).map_err(|_| "too many digits".to_string())?;
    // value = 0.d1d2…dk × 10^n
    let n = exponent + 1;
    let text = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(n as usize);
        format!("{int}.{frac}")
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let (first, rest) = digits.split_at(1);
        if rest.is_empty() {
            format!("{first}e{sign}{}", e.abs())
        } else {
            format!("{first}.{rest}e{sign}{}", e.abs())
        }
    };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FIXTURES: &[(&str, &str)] = &[
        (
            "platform/0001-service-desk-priority.json",
            include_str!(
                "../../../../../scripts/changesets/fixtures/valid/platform/0001-service-desk-priority.json"
            ),
        ),
        (
            "project/acme/0001-acme-contracts.json",
            include_str!(
                "../../../../../scripts/changesets/fixtures/valid/project/acme/0001-acme-contracts.json"
            ),
        ),
    ];

    /// The committed fixtures carry checksums `write-closed.mjs` computed;
    /// this writer must reproduce each one byte for byte.
    #[test]
    fn fixture_checksums_match_the_node_tooling() {
        for (name, text) in FIXTURES {
            let document: Value = serde_json::from_str(text).expect("fixture parses");
            let stored = document["checksum"]
                .as_str()
                .expect("fixture has a checksum");
            assert_eq!(
                document_checksum(&document).expect("checksum"),
                stored,
                "{name}"
            );
        }
    }

    /// A vector built to hit every rule, canonicalised by `lib.mjs`'s
    /// `canonicalize` (Node 24) and hashed: floats that print as integers,
    /// both exponent forms, the 2^53 boundary, every string escape, DEL and
    /// U+2028 left literal, and member names whose UTF-16 order differs from
    /// their UTF-8 byte order (U+1F600 sorts before U+FF61).
    #[test]
    fn a_hard_vector_matches_the_node_canonical_form() {
        let text = r#"{"b":[1.0,1.5,-0.0,1e21,1e20,1e-7,0.000001,5e-324,1.7976931348623157e308,0.1,100,-2.5e-8,9007199254740993,12345.678e3,3e-6],"a":"q\"\\ \u0001\u001f\u007f   é 😀 \n\t\b\f\r /","é":1,"z":null,"😀":true,"｡":false,"A":{},"":[]}"#;
        let value: Value = serde_json::from_str(text).expect("vector parses");
        let canonical = canonicalize(&value).expect("canonical");
        assert!(canonical.starts_with(r#"{"":[],"A":{},"a":"q\"\\ \u0001\u001f"#));
        let numbers = canonicalize(&value["b"]).expect("numbers");
        assert_eq!(
            numbers,
            "[1,1.5,0,1e+21,100000000000000000000,1e-7,0.000001,5e-324,1.7976931348623157e+308,0.1,100,-2.5e-8,9007199254740992,12345678,0.000003]"
        );
        assert!(canonical.ends_with(r#""z":null,"é":1,"😀":true,"｡":false}"#));
        assert_eq!(
            sha256_tagged(canonical.as_bytes()),
            "sha256:9430455bb03894f2870ecf8dfc51f362ee7a86ac1db3f5c5935006cf3cc9c7a5"
        );
    }

    #[test]
    fn numbers_follow_ecmascript() {
        for (value, text) in [
            (1.0, "1"),
            (-1.0, "-1"),
            (0.5, "0.5"),
            (123.456, "123.456"),
            (1e21, "1e+21"),
            (1.5e21, "1.5e+21"),
            (1e-6, "0.000001"),
            (1.25e-7, "1.25e-7"),
            (f64::MIN_POSITIVE, "2.2250738585072014e-308"),
            // As a literal: serde_json's default (non-`float_roundtrip`)
            // parser reads this decimal one ULP low, so it is not in the
            // parsed vector above.
            (1.2345678901234568e20, "123456789012345680000"),
        ] {
            assert_eq!(es_number(value).expect("finite"), text, "{value}");
        }
        assert!(es_number(f64::NAN).is_err());
        assert_eq!(canonicalize(&json!(-5)).expect("int"), "-5");
        assert_eq!(
            canonicalize(&json!(u64::MAX)).expect("big"),
            "18446744073709552000"
        );
    }

    #[test]
    fn the_checksum_ignores_its_own_member_only() {
        let a = json!({ "id": "x", "operations": [1], "checksum": "sha256:old" });
        let b = json!({ "operations": [1], "id": "x" });
        assert_eq!(
            document_checksum(&a).expect("a"),
            document_checksum(&b).expect("b")
        );
        let c = json!({ "operations": [2], "id": "x" });
        assert_ne!(
            document_checksum(&b).expect("b"),
            document_checksum(&c).expect("c")
        );
        assert!(document_checksum(&json!([])).is_err());
    }
}

//! ETA's canonical serialization (roadmap AG3-T1): the text a document's
//! signature covers. Walking the document in its own key order:
//!
//! - a simple value is written quoted, as its JSON text (`"1000"`,
//!   `"Cairo"`), with no escaping;
//! - each property writes its name upper-cased and quoted, then its value;
//! - an object property writes its name, then its properties;
//! - an array property writes its name once, then each element preceded by
//!   the name again.
//!
//! The `signatures` property is left out: it holds what is computed from
//! the rest. The result is hashed with SHA-256 and signed as CAdES-BES by
//! the signer ([`super::signer`]).

use serde_json::Value;
use sha2::{Digest, Sha256};

fn simple(value: &Value) -> String {
    match value {
        Value::String(s) => format!("\"{s}\""),
        Value::Null => "\"\"".to_owned(),
        other => format!("\"{other}\""),
    }
}

fn walk(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            for (name, v) in map {
                if name == "signatures" {
                    continue;
                }
                let key = format!("\"{}\"", name.to_uppercase());
                match v {
                    Value::Array(items) => {
                        out.push_str(&key);
                        for item in items {
                            out.push_str(&key);
                            walk(item, out);
                        }
                    }
                    Value::Object(_) => {
                        out.push_str(&key);
                        walk(v, out);
                    }
                    _ => {
                        out.push_str(&key);
                        out.push_str(&simple(v));
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, out);
            }
        }
        other => out.push_str(&simple(other)),
    }
}

/// The canonical text of `document`. Pure.
pub fn canonical(document: &Value) -> String {
    let mut out = String::new();
    walk(document, &mut out);
    out
}

/// The SHA-256 of the canonical text, as lower-case hex. Pure.
pub fn digest_hex(document: &Value) -> String {
    Sha256::digest(canonical(document).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod eta_serialize {
    use super::*;
    use serde_json::json;

    #[test]
    fn follows_the_eta_rules() {
        // Keys are walked in the map's order, the order the JSON is written
        // in, so the signed text and the sent text agree. Written here in
        // sorted order, the same with or without serde_json's
        // `preserve_order`.
        let doc = json!({
            "invoiceLines": [
                { "quantity": 3, "taxableItems": [{ "rate": 14 }] },
                { "quantity": 1.5, "taxableItems": [] }
            ],
            "issuer": { "id": "100", "type": "B" },
            "signatures": [{ "signatureType": "I", "value": "x" }],
        });
        assert_eq!(
            canonical(&doc),
            concat!(
                "\"INVOICELINES\"",
                "\"INVOICELINES\"\"QUANTITY\"\"3\"\"TAXABLEITEMS\"\"TAXABLEITEMS\"\"RATE\"\"14\"",
                "\"INVOICELINES\"\"QUANTITY\"\"1.5\"\"TAXABLEITEMS\"",
                "\"ISSUER\"\"ID\"\"100\"\"TYPE\"\"B\"",
            )
        );
        assert_eq!(digest_hex(&doc).len(), 64);
    }
}

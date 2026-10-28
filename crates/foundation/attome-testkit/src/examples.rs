//! S2-T10: request and response examples captured from integration tests.
//!
//! A test's request helper calls [`capture_example`] after each call. Nothing
//! happens unless `ATTOME_CAPTURE_EXAMPLES` names a directory; then the call
//! is written there as `<METHOD>_<path>.json` (`{method, uri, request,
//! status, response}`), the first capture of a path winning. The API
//! generator (`web/scripts/generate-api-types.mjs`) matches each file to its
//! operation by method and path template and sets the operation's request
//! and response examples in `openapi.json`.
//!
//! Secrets never reach a file: every object key that names one (password,
//! secret, token, api_key, cookie, authorization, in any case and as part of
//! a longer key such as `webhook_secret`) has its value replaced, at every
//! depth, before anything is written.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

/// The environment variable naming the directory examples are written to.
pub const CAPTURE_ENV: &str = "ATTOME_CAPTURE_EXAMPLES";

/// What a redacted value is replaced with.
pub const REDACTED: &str = "<redacted>";

const SECRET_WORDS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "cookie",
    "authorization",
];

/// Whether `key` names a secret. Pure.
pub fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| key.contains(word))
}

/// `value` with every secret-named key's value replaced, at every depth. Pure.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if is_secret_key(k) {
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact(v)
                    };
                    (k.clone(), v)
                })
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        other => other.clone(),
    }
}

/// The file name for a call: the method, then the path (no query) with every
/// character outside `[A-Za-z0-9]` as `_`, at most 180 characters. Pure.
pub fn file_name(method: &str, uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or(uri);
    let mut name: String = format!("{}_{}", method.to_ascii_uppercase(), path)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    name.truncate(180);
    format!("{name}.json")
}

/// Writes one call into `dir` unless a file for its method and path is
/// there already. Returns the path written, if any.
pub fn write_example(
    dir: &Path,
    method: &str,
    uri: &str,
    request: Option<&Value>,
    status: u16,
    response: &Value,
) -> std::io::Result<Option<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name(method, uri));
    let body = json!({
        "method": method.to_ascii_uppercase(),
        "uri": uri,
        "request": request.map(redact),
        "status": status,
        "response": redact(response),
    });
    let text = serde_json::to_string_pretty(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(text.as_bytes())?;
            file.write_all(b"\n")?;
            Ok(Some(path))
        }
        // First write wins.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e),
    }
}

/// Captures one call when [`CAPTURE_ENV`] names a directory; otherwise does
/// nothing. A capture that cannot be written is reported on stderr and never
/// fails the test.
pub fn capture_example(
    method: &str,
    uri: &str,
    request: Option<&Value>,
    status: u16,
    response: &Value,
) {
    let Some(dir) = std::env::var_os(CAPTURE_ENV).filter(|d| !d.is_empty()) else {
        return;
    };
    if let Err(error) = write_example(Path::new(&dir), method, uri, request, status, response) {
        eprintln!("capture_example {method} {uri}: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_example_redacts_secrets() {
        let dir = std::env::temp_dir().join(format!("attome-examples-{}", uuid::Uuid::now_v7()));
        let request = json!({
            "name": "شركة الرياض",
            "Password": "hunter2",
            "nested": { "webhook_secret": "s", "items": [{ "api_key": "k", "kept": 1 }] },
        });
        let response = json!({ "access_token": "t", "Authorization": "Bearer x", "id": 7 });
        let path = write_example(
            &dir,
            "post",
            "/api/v1/things?x=1",
            Some(&request),
            201,
            &response,
        )
        .expect("written")
        .expect("a new file");
        let text = std::fs::read_to_string(&path).expect("read back");
        for secret in ["hunter2", "\"s\"", "\"k\"", "\"t\"", "Bearer x"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        let saved: Value = serde_json::from_str(&text).expect("json");
        assert_eq!(saved["request"]["name"], "شركة الرياض");
        assert_eq!(saved["request"]["nested"]["items"][0]["kept"], 1);
        assert_eq!(saved["response"]["id"], 7);
        assert_eq!(saved["status"], 201);
        assert_eq!(path.file_name().unwrap(), "POST__api_v1_things.json");
        // First write wins.
        assert!(
            write_example(&dir, "POST", "/api/v1/things", None, 200, &json!({}))
                .expect("ok")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

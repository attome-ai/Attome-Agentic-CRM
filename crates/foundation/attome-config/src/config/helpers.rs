//! Cross-section helpers: Redis URL construction, `${VAR}` placeholder
//! expansion (including the P-container-hardening `_FILE` fallback), the
//! small `default_*` functions shared by (or simply never grouped under) a
//! single section, and the dependency-free URL-encoding helper.
//!
//! Every `pub(crate)` item here is reached from at least one sibling module
//! (a `sections/*.rs` file's `#[serde(default = "...")]` attribute, or
//! `loader.rs`'s `impl AppConfig` block) — kept `pub(crate)`, not `pub`,
//! since none of this is part of the crate's public surface (see `lib.rs`'s
//! `pub use config::{...}` list, which names none of it).

use crate::config::sections::cache::CacheSentinelConfig;

/// `host:port`, bracketing a bare IPv6 literal (BCF-9). The `url` crate —
/// and fred, which parses with it — reads an unbracketed `fd00::1:6379` as a
/// malformed host, and every connection string this crate builds has to be
/// parseable by the client that consumes it.
pub(crate) fn host_port(host: &str, port: u16) -> String {
    let needs_brackets = !host.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok();
    if needs_brackets {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The one PostgreSQL URL builder (BCF-9) behind every `*_database_url`
/// accessor, so the five hand-copied format strings cannot drift apart again.
/// `userinfo` is already percent-encoded by the caller; the search_path
/// option is literal.
pub(crate) fn postgres_url(
    userinfo: &str,
    host: &str,
    port: u16,
    dbname: &str,
    schema: &str,
) -> String {
    format!(
        "postgres://{userinfo}@{}/{dbname}?options=-c%20search_path%3D{schema}%2Cpublic",
        host_port(host, port)
    )
}

pub(crate) fn build_redis_url(
    host: &str,
    port: u16,
    password: &str,
    db: i64,
    tls_enabled: bool,
) -> String {
    // P-datastore-tls: fred recognizes the `rediss://` scheme as its
    // TLS-enabled centralized-server URL form (requires the enable-rustls
    // cargo feature, compiled in unconditionally — see workspace Cargo.toml).
    let scheme = if tls_enabled { "rediss" } else { "redis" };
    let authority = host_port(host, port);
    if password.is_empty() {
        format!("{scheme}://{authority}/{db}")
    } else {
        // BCF-8 — fred percent-*decodes* userinfo (`urlencoding::decode`), so a
        // password containing `%`, `@`, `/`, `#` or `?` must be encoded
        // here or the client authenticates with a different string than the
        // operator configured.
        format!(
            "{scheme}://:{}@{authority}/{db}",
            urlencoding::encode(password)
        )
    }
}

/// Sentinel-mode URL (P-redis-sentinel-config) — fred's `redis-sentinel://`
/// scheme (`rediss-sentinel://` when TLS'd), matching `Config::from_url_sentinel`'s
/// documented format: `[r]ediss?-sentinel://[:password@]host:port/db?sentinelServiceName=X[&node=h:p]*`.
/// `host`/`port`/`password`/`db`/`tls_enabled` keep `build_redis_url`'s exact
/// meaning (the first sentinel node + the resolved master's auth); query
/// values are percent-encoded since `&`/`=` are structural there, as is the
/// master-auth password in the userinfo (BCF-8).
pub(crate) fn build_redis_sentinel_url(
    host: &str,
    port: u16,
    password: &str,
    db: i64,
    tls_enabled: bool,
    sentinel: &CacheSentinelConfig,
) -> String {
    let scheme = if tls_enabled {
        "rediss-sentinel"
    } else {
        "redis-sentinel"
    };
    let auth = if password.is_empty() {
        String::new()
    } else {
        // BCF-8 — same percent-encoding rule as `build_redis_url`: fred's
        // parser decodes the userinfo before authenticating.
        format!(":{}@", urlencoding::encode(password))
    };
    let mut url = format!(
        "{scheme}://{auth}{}/{db}?sentinelServiceName={}",
        host_port(host, port),
        urlencoding::encode(&sentinel.service_name)
    );
    if let Some(u) = &sentinel.sentinel_username {
        url.push_str(&format!("&sentinelUsername={}", urlencoding::encode(u)));
    }
    if let Some(p) = &sentinel.sentinel_password {
        url.push_str(&format!(
            "&sentinelPassword={}",
            urlencoding::encode(p.expose())
        ));
    }
    for node in &sentinel.nodes {
        url.push_str(&format!("&node={}", host_port(&node.host, node.port)));
    }
    url
}

/// Replaces `${VAR_NAME}` in `s` with `std::env::var("VAR_NAME")`.
/// Leaves the literal unchanged if the variable is not set and reports the
/// missing key in the second return value — `from_file` decides whether that
/// is fatal (non-debug) or tolerated (APP_ENV=debug).
///
/// P-container-hardening (D-186): before falling back to reporting `VAR_NAME`
/// unresolved, this also checks whether `VAR_NAME_FILE` is set and, if so,
/// reads that file's trimmed contents as the value — see
/// `resolve_placeholder`'s doc comment for the full rationale.
pub(crate) fn expand_env_vars(s: &str) -> (String, Vec<String>) {
    let mut out = String::with_capacity(s.len());
    let mut unresolved = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        if let Some(end) = rest.find('}') {
            let key = &rest[..end];
            match resolve_placeholder(key) {
                Some(val) => out.push_str(&val),
                None => {
                    unresolved.push(key.to_string());
                    out.push_str("${");
                    out.push_str(key);
                    out.push('}');
                }
            }
            rest = &rest[end + 1..];
        } else {
            out.push_str("${");
        }
    }
    out.push_str(rest);
    (out, unresolved)
}

/// BCF-6/BCF-D3 — expand `${VAR}` inside a parsed JSON document instead of
/// over the file's text. Only string values are touched, and only those whose
/// key path has no `_`-prefixed segment: a `_readme`/`_comment` value is
/// prose, so a literal `${VAR}` in it is neither expanded nor reported as a
/// required variable (BCF-F4b).
///
/// `unresolved` receives one `"KEY (at path)"` entry per placeholder that
/// resolved to nothing.
#[cfg(test)]
pub(crate) fn expand_env_vars_in_value(
    value: &mut serde_json::Value,
    unresolved: &mut Vec<String>,
) {
    expand_env_vars_tracking(value, unresolved, &mut Vec::new());
}

/// [`expand_env_vars_in_value`], also listing in `literals` the path of every
/// non-empty string written into the file as is (no `${VAR}` in it), so the
/// production profile can refuse a secret typed into the file (Z1-T5).
pub(crate) fn expand_env_vars_tracking(
    value: &mut serde_json::Value,
    unresolved: &mut Vec<String>,
    literals: &mut Vec<String>,
) {
    expand_value_at(value, &mut Vec::new(), unresolved, literals);
}

/// A path as dotted text, list positions glued on: `a.b[0].c`.
fn path_text(path: &[String]) -> String {
    let mut out = String::new();
    for segment in path {
        if !out.is_empty() && !segment.starts_with('[') {
            out.push('.');
        }
        out.push_str(segment);
    }
    out
}

/// Z1-T5: where a secret lives in the configuration. `*` stands for one key
/// (a provider name, an endpoint) and `[]` for any list position; a pattern
/// covers everything under it, so a key ring's `keys[n].secret` counts too.
const SECRET_PATHS: &[&str] = &[
    "auth.jwt_secret",
    "auth.jwt_signing_keys",
    "auth.mfa_encryption_key",
    "auth.oauth_google_client_secret",
    "auth.apikey_hash_pepper",
    "auth.apikey_hash_previous_peppers[].secret",
    "database.password",
    "database.direct_url",
    "database.readonly.password",
    "database.migrator.password",
    "database.runtime.password",
    "cache.password",
    "cache.sentinel.sentinel_password",
    "cache.roles.*.password",
    "cache.roles.*.sentinel.sentinel_password",
    "storage.s3_secret_key",
    "email.smtp_password",
    "google_ai.api_key",
    "s2s.key_encryption_key",
    "s2s.seeded_clients[].secret",
    "audit.signing_private_key",
    "audit.erasure_key_encryption_key",
    "audit.anchor_store.s3_secret_key",
    "events.webhook_signing_key",
    "integration.credential_encryption_key",
    "einvoice.key_encryption_key",
    "inference.provider_credential_key",
    "inference.*.api_key",
    "oidc.providers.*.client_secret",
    "portal.captcha.secret",
    "portal.oidc_providers.*.client_secret",
];

/// The segments of a dotted path, with every list index as `[]`.
fn path_segments(path: &str) -> Vec<&str> {
    path.split(['.', '['])
        .filter(|s| !s.is_empty())
        .map(|s| if s.ends_with(']') { "[]" } else { s })
        .collect()
}

/// Z1-T5: whether `path` (as [`expand_env_vars_tracking`] writes it) holds a
/// secret.
pub(crate) fn is_secret_path(path: &str) -> bool {
    let segments = path_segments(path);
    SECRET_PATHS.iter().any(|pattern| {
        let wanted = path_segments(pattern);
        wanted.len() <= segments.len()
            && wanted
                .iter()
                .zip(&segments)
                .all(|(w, s)| *w == "*" || w == s)
    })
}

fn expand_value_at(
    value: &mut serde_json::Value,
    path: &mut Vec<String>,
    unresolved: &mut Vec<String>,
    literals: &mut Vec<String>,
) {
    match value {
        serde_json::Value::String(text) => {
            if path.iter().any(|segment| segment.starts_with('_')) {
                return;
            }
            if !text.is_empty() && !text.contains("${") {
                literals.push(path_text(path));
            }
            let (expanded, missing) = expand_env_vars(text);
            if !missing.is_empty() {
                let location = if path.is_empty() {
                    "<root>".to_string()
                } else {
                    path.join(".")
                };
                for key in missing {
                    unresolved.push(format!("{key} (at {location})"));
                }
            }
            *text = expanded;
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                path.push(format!("[{index}]"));
                expand_value_at(item, path, unresolved, literals);
                path.pop();
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                expand_value_at(child, path, unresolved, literals);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Resolves one `${KEY}` placeholder: the `KEY` env var itself first, then
/// `KEY_FILE` — a Docker/Compose file-based secret whose trimmed contents
/// become the value, the same convention official Postgres/MySQL images use
/// for `POSTGRES_PASSWORD_FILE`. Written generically over any placeholder key
/// rather than hardcoded to one name, so any single-credential file-mount
/// need reuses this instead of a second implementation.
///
/// An unreadable `_FILE` path (missing file, permissions) returns `None`,
/// exactly like a missing plain env var — the caller's existing fail-closed
/// `UnresolvedPlaceholders` boot error (`from_file`) covers it too, so a
/// misconfigured secret mount is a startup failure, never a silent empty
/// secret.
fn resolve_placeholder(key: &str) -> Option<String> {
    if let Ok(val) = std::env::var(key) {
        return Some(val);
    }
    let file_path = std::env::var(format!("{key}_FILE")).ok()?;
    std::fs::read_to_string(file_path)
        .ok()
        .map(|contents| contents.trim().to_string())
}

// ── Serde defaults ────────────────────────────────────────────────────────────

pub(crate) fn default_server_host() -> String {
    "0.0.0.0".into()
}
pub(crate) fn default_max_body() -> usize {
    10 * 1024 * 1024
}
pub(crate) fn default_request_timeout() -> u64 {
    30
}
pub(crate) fn default_true() -> bool {
    true
}
pub(crate) fn default_s2s_failure_threshold() -> u32 {
    100
}
pub(crate) fn default_access_token_expiry_mins() -> u64 {
    15
}
pub(crate) fn default_refresh_token_expiry_days() -> u64 {
    30
}
pub(crate) fn default_refresh_absolute_lifetime_days() -> u64 {
    30
}
pub(crate) fn default_mfa_challenge_max_attempts() -> u32 {
    5
}

// ── URL encoding (tiny helper, avoids pulling in the `url` crate) ─────────────

pub(crate) mod urlencoding {
    pub fn encode(s: &str) -> std::borrow::Cow<'_, str> {
        let needs_escape = s
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"-_.~".contains(&b));
        if !needs_escape {
            return std::borrow::Cow::Borrowed(s);
        }
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                out.push(b as char);
            } else {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
        std::borrow::Cow::Owned(out)
    }
}

// ── Shipped-template secret denylist (BCF-3 / BCF-D1) ─────────────────────────

/// Substrings that identify a value copied verbatim from a shipped template, a
/// `.env.example`, or a local test fixture — all of them publicly known, so
/// none protects anything. Matched case-insensitively.
///
/// `check_secret`/`check_secret_ring` apply this under the production profile
/// only (the dev stack deliberately runs on `config.example.json`'s throwaway
/// values); `validate_production_profile` applies it to every credential the
/// `check_secret` family never sees.
pub(crate) const TEMPLATE_SECRET_MARKERS: &[&str] = &[
    "change_me",
    "changeme",
    "__TODO__",
    "your_",
    "test-only-throwaway",
    // The public development audit-erasure key config.example.json ships
    // (D-540). validate_production_profile also refuses it by equality.
    super::sections::audit::DEVELOPMENT_ERASURE_KEY,
];

/// The first marker in TEMPLATE_SECRET_MARKERS occurring in `value`
/// (case-insensitive), if any.
pub(crate) fn template_secret_marker(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    TEMPLATE_SECRET_MARKERS
        .iter()
        .copied()
        .find(|marker| lower.contains(&marker.to_ascii_lowercase()))
}

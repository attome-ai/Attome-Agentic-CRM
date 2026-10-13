//! `Set-Cookie` construction + `Cookie` header parsing shared by the authn
//! middleware and every website handler that issues/reads/clears a session or
//! refresh cookie — one place, so the flags can't drift between call sites.

use http::{HeaderMap, header::COOKIE};

/// Unprefixed cookie names. With `secure_cookies = false` (plain-http local
/// dev) these are the live names, because browsers refuse a `__Host-`/
/// `__Secure-` cookie without `Secure`. With `secure_cookies = true` they are
/// never read: an unprefixed cookie can be planted by a sibling subdomain or
/// an HTTP man-in-the-middle, which is exactly what the prefixes exist to stop
/// (security contract I1).
const PLAIN_SESSION_COOKIE: &str = "session_token";
const PLAIN_REFRESH_COOKIE: &str = "refresh_token";

/// The session cookie's name, browser-prefix-hardened when the deployment is
/// HTTPS. `__Host-` requires `Secure`, no `Domain`, and `Path=/` — this
/// platform's session cookie already satisfies all three (see `build`'s
/// asserts) whenever `secure` is true, so the prefix is unconditional in that
/// case. Plain-http local dev (`secure_cookies = false`) keeps the unprefixed
/// name — browsers silently refuse to set a `__Host-`/`__Secure-` cookie
/// without `Secure`, so prefixing there would just make dev cookies vanish.
pub fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-session_token"
    } else {
        PLAIN_SESSION_COOKIE
    }
}

/// The refresh cookie's name. Scoped to `Path=/api/v1/auth`, not `/`, so it
/// cannot take the `__Host-` prefix (`__Host-` hard-requires `Path=/`) — the
/// correct prefix for a `Secure`, no-`Domain`, non-root-path cookie is
/// `__Secure-` instead (RFC 6265bis §4.1.3).
pub fn refresh_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Secure-refresh_token"
    } else {
        PLAIN_REFRESH_COOKIE
    }
}

/// Reads cookie `name`'s value out of a request's `Cookie` header, if present.
pub fn extract(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|c| c.trim().strip_prefix(prefix.as_str()).map(str::to_owned))
        })
}

/// Reads the session cookie under this deployment's cookie name only. When
/// `secure` is true there is deliberately no fallback to the unprefixed name
/// (security contract I1); the dual-read window P-cookie-csrf-hardening opened
/// for sessions minted before the `__Host-` rename has closed.
pub fn extract_session(headers: &HeaderMap, secure: bool) -> Option<String> {
    extract(headers, session_cookie_name(secure))
}

/// Same single-name read as `extract_session`, for the refresh cookie.
pub fn extract_refresh(headers: &HeaderMap, secure: bool) -> Option<String> {
    extract(headers, refresh_cookie_name(secure))
}

/// Builds a `Set-Cookie` value. Always `HttpOnly; SameSite=Strict` (Plan 1.6a) —
/// `Secure` is gated on `secure` (from `config.auth.secure_cookies`) so plain-http
/// local dev keeps working; production defaults `true` regardless of `APP_ENV`.
///
/// Debug-only invariant checks (never compiled into a release build, so they
/// can't turn a bad call site into a production panic): a `__Host-`-prefixed
/// name must carry `Secure` and `Path=/`; a `__Secure-`-prefixed name must
/// carry `Secure`. Both are hard browser-enforced requirements — getting
/// either wrong doesn't error, it just makes the browser silently discard the
/// `Set-Cookie` line, which is a much harder bug to notice than a panic in dev/CI.
pub fn build(name: &str, value: &str, max_age_secs: u64, secure: bool, path: &str) -> String {
    debug_assert!(
        !name.starts_with("__Host-") || (secure && path == "/"),
        "__Host- cookie {name} requires Secure and Path=/, got secure={secure} path={path}"
    );
    debug_assert!(
        !name.starts_with("__Secure-") || secure,
        "__Secure- cookie {name} requires Secure"
    );
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; HttpOnly{secure_flag}; SameSite=Strict; Path={path}; Max-Age={max_age_secs}"
    )
}

/// Builds a `Set-Cookie` value that clears `name` immediately (`Max-Age=0`).
pub fn clear(name: &str, secure: bool, path: &str) -> String {
    build(name, "", 0, secure, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn no_cookie_ever_carries_a_domain_d585() {
        // D-585 item 4: every staff and portal cookie is host-only, so a
        // staff cookie is never sent to a portal host or the reverse. Both
        // audiences build through these two functions.
        for secure in [true, false] {
            for c in [
                build(session_cookie_name(secure), "v", 60, secure, "/"),
                build(refresh_cookie_name(secure), "v", 60, secure, "/api/v1/auth"),
                build("__Secure-wp_acme_session", "v", 60, true, "/acme/"),
                clear(session_cookie_name(secure), secure, "/"),
            ] {
                assert!(!c.to_ascii_lowercase().contains("domain="), "{c}");
            }
        }
    }

    #[test]
    fn extract_finds_the_named_cookie_among_several() {
        let headers = headers_with_cookie("a=1; session_token=abc123; b=2");
        assert_eq!(
            extract(&headers, "session_token"),
            Some("abc123".to_owned())
        );
    }

    #[test]
    fn extract_returns_none_when_the_cookie_is_absent() {
        let headers = headers_with_cookie("a=1; b=2");
        assert_eq!(extract(&headers, "session_token"), None);
    }

    #[test]
    fn extract_returns_none_when_there_is_no_cookie_header_at_all() {
        let headers = HeaderMap::new();
        assert_eq!(extract(&headers, "session_token"), None);
    }

    #[test]
    fn extract_does_not_match_a_cookie_whose_name_is_a_prefix_of_another() {
        // "session_token_extra=x" must not satisfy a lookup for "session_token".
        let headers = headers_with_cookie("session_token_extra=x");
        assert_eq!(extract(&headers, "session_token"), None);
    }

    #[test]
    fn build_sets_httponly_and_samesite_strict_unconditionally() {
        let value = build("session_token", "abc", 900, false, "/");
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Strict"));
        assert!(!value.contains("Secure"));
        assert!(value.contains("Max-Age=900"));
    }

    #[test]
    fn build_adds_secure_flag_only_when_requested() {
        let value = build("session_token", "abc", 900, true, "/");
        assert!(value.contains("; Secure"));
    }

    #[test]
    fn clear_sets_an_empty_value_and_zero_max_age() {
        let value = clear("session_token", true, "/");
        assert!(value.starts_with("session_token=;"));
        assert!(value.contains("Max-Age=0"));
    }

    // ── __Host-/__Secure- naming (P-cookie-csrf-hardening) ────────────────────

    #[test]
    fn session_cookie_name_is_host_prefixed_when_secure() {
        assert_eq!(session_cookie_name(true), "__Host-session_token");
    }

    #[test]
    fn session_cookie_name_is_unprefixed_when_not_secure() {
        // Plain-http local dev: browsers reject a __Host-/__Secure- cookie
        // without Secure, so keeping the unprefixed name is what makes it set at all.
        assert_eq!(session_cookie_name(false), "session_token");
    }

    #[test]
    fn refresh_cookie_name_is_secure_prefixed_when_secure() {
        // Not __Host- — the refresh cookie's Path is /api/v1/auth, not /,
        // and __Host- hard-requires Path=/.
        assert_eq!(refresh_cookie_name(true), "__Secure-refresh_token");
    }

    #[test]
    fn refresh_cookie_name_is_unprefixed_when_not_secure() {
        assert_eq!(refresh_cookie_name(false), "refresh_token");
    }

    #[test]
    #[should_panic(expected = "__Host- cookie")]
    fn build_panics_in_debug_when_host_prefixed_without_secure() {
        build("__Host-session_token", "abc", 900, false, "/");
    }

    #[test]
    #[should_panic(expected = "__Host- cookie")]
    fn build_panics_in_debug_when_host_prefixed_with_a_non_root_path() {
        build("__Host-session_token", "abc", 900, true, "/api/v1/auth");
    }

    #[test]
    #[should_panic(expected = "__Secure- cookie")]
    fn build_panics_in_debug_when_secure_prefixed_without_secure() {
        build("__Secure-refresh_token", "abc", 900, false, "/api/v1/auth");
    }

    #[test]
    fn build_allows_host_prefixed_name_when_secure_and_path_is_root() {
        let value = build("__Host-session_token", "abc", 900, true, "/");
        assert!(value.starts_with("__Host-session_token=abc;"));
    }

    #[test]
    fn extract_session_prefers_the_current_name_over_the_unprefixed_one() {
        let headers = headers_with_cookie("__Host-session_token=new; session_token=old");
        assert_eq!(extract_session(&headers, true), Some("new".to_owned()));
    }

    #[test]
    fn extract_session_ignores_the_unprefixed_name_when_secure() {
        // Contract I1: with secure cookies on, only __Host-session_token is
        // read. An unprefixed cookie can be planted by a sibling subdomain or
        // an HTTP man-in-the-middle, so it must never authenticate.
        let headers = headers_with_cookie("session_token=planted");
        assert_eq!(extract_session(&headers, true), None);
    }

    #[test]
    fn extract_session_reads_the_unprefixed_name_directly_when_not_secure() {
        let headers = headers_with_cookie("session_token=devvalue");
        assert_eq!(
            extract_session(&headers, false),
            Some("devvalue".to_owned())
        );
    }

    #[test]
    fn extract_refresh_prefers_the_current_name_over_the_unprefixed_one() {
        let headers = headers_with_cookie("__Secure-refresh_token=new; refresh_token=old");
        assert_eq!(extract_refresh(&headers, true), Some("new".to_owned()));
    }

    #[test]
    fn extract_refresh_ignores_the_unprefixed_name_when_secure() {
        let headers = headers_with_cookie("refresh_token=planted");
        assert_eq!(extract_refresh(&headers, true), None);
    }

    #[test]
    fn extract_uses_the_first_cookie_when_a_name_is_duplicated() {
        // Pins current behaviour: of two same-named cookies in one header,
        // the first wins. A sibling subdomain cannot set a __Host- cookie, so
        // a duplicate of one can only have come from this origin.
        let headers =
            headers_with_cookie("__Host-session_token=first; __Host-session_token=second");
        assert_eq!(extract_session(&headers, true), Some("first".to_owned()));
    }
}

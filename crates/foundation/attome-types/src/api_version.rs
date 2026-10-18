//! S8-T1: the API's dated versions. A request names the version it was
//! written against in the `Attome-Version` header; an API key or S2S client
//! that sends none is answered at the version it is pinned to
//! (`pinned_api_version`, set to the current version when it is created);
//! a browser session always gets the current version.

/// The version this server answers by default.
pub const CURRENT: &str = "2026-10";

/// Every version this server can answer, oldest first.
pub const SUPPORTED: &[&str] = &[CURRENT];

/// The request header that names a version.
pub const HEADER: &str = "attome-version";

/// The supported version spelled `version`, if any.
pub fn supported(version: &str) -> Option<&'static str> {
    let version = version.trim();
    SUPPORTED.iter().copied().find(|v| *v == version)
}

/// The version a request is answered at, set by the server's version layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiVersion(pub &'static str);

/// Why a version was refused: the one asked for, and what is supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedApiVersion {
    pub requested: String,
}

/// Resolves the version: a supported `header` wins; with none, a browser
/// session gets the current version and any other caller its `pinned`
/// version (current when the pin is missing or no longer supported).
pub fn resolve(
    header: Option<&str>,
    pinned: Option<&str>,
    browser_session: bool,
) -> Result<&'static str, UnsupportedApiVersion> {
    if let Some(requested) = header {
        return supported(requested).ok_or_else(|| UnsupportedApiVersion {
            requested: requested.trim().to_owned(),
        });
    }
    if browser_session {
        return Ok(CURRENT);
    }
    Ok(pinned.and_then(supported).unwrap_or(CURRENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_supported_header_wins() {
        assert_eq!(resolve(Some(CURRENT), Some("1999-01"), false), Ok(CURRENT));
        assert_eq!(resolve(Some(" 2026-10 "), None, true), Ok(CURRENT));
    }

    #[test]
    fn an_unknown_header_is_refused() {
        assert_eq!(
            resolve(Some("1999-01"), None, false),
            Err(UnsupportedApiVersion {
                requested: "1999-01".into()
            })
        );
    }

    #[test]
    fn without_a_header_the_pin_or_the_current_version_answers() {
        assert_eq!(resolve(None, Some(CURRENT), false), Ok(CURRENT));
        assert_eq!(
            resolve(None, Some("1999-01"), false),
            Ok(CURRENT),
            "a pin no longer supported reads as current"
        );
        assert_eq!(resolve(None, None, false), Ok(CURRENT));
        assert_eq!(
            resolve(None, Some("1999-01"), true),
            Ok(CURRENT),
            "a browser session is never pinned"
        );
    }
}

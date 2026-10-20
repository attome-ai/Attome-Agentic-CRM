//! Known crawler and automation user-agent fragments (E14-T5). A visit
//! whose user agent contains one of them, ignoring case, is not a person
//! and is never written.

/// Lower-case fragments; matching is a substring test on the lower-cased
/// user agent.
pub const BOT_SIGNATURES: &[&str] = &[
    "bot",
    "crawler",
    "spider",
    "slurp",
    "headless",
    "lighthouse",
    "pagespeed",
    "pingdom",
    "uptime",
    "monitor",
    "facebookexternalhit",
    "embedly",
    "preview",
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "java/",
    "okhttp",
    "httpclient",
    "axios/",
    "node-fetch",
    "phantomjs",
    "selenium",
    "puppeteer",
    "playwright",
];

/// True when `user_agent` (or a classified value such as `bot`) is a
/// crawler or a script. An empty user agent counts as one: browsers always
/// send it.
pub fn is_bot(user_agent: &str) -> bool {
    let ua = user_agent.trim().to_ascii_lowercase();
    ua.is_empty() || BOT_SIGNATURES.iter().any(|sig| ua.contains(sig))
}

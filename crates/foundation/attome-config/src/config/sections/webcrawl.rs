//! D-365 — Web Crawling for Knowledge Base. This crate carries no `xrm-*`
//! dependency and no engine behaviour (boundary ruling, attome-config plan
//! BCF-14) — `xrm-webcrawl` reads these plain-data fields directly off
//! `AppConfig.webcrawl`.
//!
//! `enabled` defaults `false`: the platform's first feature that makes an
//! outbound HTTP request to an arbitrary, user-supplied URL, and
//! `P-knowledge-base.md` §5 documents the air-gap posture such a feature
//! should ship with — config-gated, off by default, on only where a
//! deployment actually wants it. `POST /api/v1/webcrawl/targets` (and
//! `.../recrawl`) return 403 while this is `false`; every read endpoint
//! still works regardless, so previously-imported knowledge stays visible.
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct WebcrawlSection {
    pub enabled: bool,
    pub max_pages: u32,
    /// Default crawl depth when `POST /targets` doesn't specify one — each
    /// crawl can override this per request (clamped to a sane range by the
    /// handler), stored on its own `xrm_webcrawl_target.max_depth` row.
    pub max_depth: u32,
    pub request_timeout_secs: u64,
    pub max_page_bytes: usize,
}

impl Default for WebcrawlSection {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pages: 50,
            max_depth: 6,
            request_timeout_secs: 15,
            max_page_bytes: 5_000_000,
        }
    }
}

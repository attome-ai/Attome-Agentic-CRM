//! M57 Phase 1 (Document Generation, D-463). This crate carries no `xrm-*`
//! dependency and no engine behaviour (boundary ruling, attome-config plan
//! BCF-14); `xrm-docgen` reads these plain-data fields directly off
//! `AppConfig.docgen`.
//!
//! `render_service_url` names the isolated headless-Chrome render sidecar
//! (`pdf-service-dev` in `docker-compose.yml`'s `dev` profile;
//! `deploy/docgen-render-service.md` covers real-deployment placement) —
//! **internal network only**, never proxied to the internet (the plan's
//! render-isolation property, restated in `document/decisions/foundation/
//! D-463.md`). The default points at the dev compose service's published
//! port so a fresh clone works with no config file edit, mirroring
//! `WebcrawlSection`'s "sane defaults, no config.example.json entry needed"
//! precedent. `request_timeout_secs`/`max_response_bytes` are guidelines
//! §10's explicit-timeout-and-size-cap requirement for a render call: a
//! hung or malicious sidecar must fail the job closed, not hang the calling
//! worker or exhaust memory on an oversized response.
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct DocgenSection {
    pub render_service_url: String,
    pub request_timeout_secs: u64,
    /// Cap on the rendered PDF response read back from the sidecar.
    pub max_response_bytes: usize,
    /// Cap on the merged HTML document sent to the sidecar — bounds both the
    /// request body and the amount of markup the SSRF-shaped external-URL
    /// scan (`xrm_docgen::ssrf`) has to walk.
    pub max_html_bytes: usize,
}

impl Default for DocgenSection {
    fn default() -> Self {
        Self {
            render_service_url: "http://localhost:3000".to_string(),
            request_timeout_secs: 20,
            max_response_bytes: 25_000_000,
            max_html_bytes: 5_000_000,
        }
    }
}

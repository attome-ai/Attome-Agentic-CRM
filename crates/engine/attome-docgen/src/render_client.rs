//! HTTP client for the isolated render sidecar (`pdf-service-dev` in dev;
//! `deploy/docgen-render-service.md` for a real deployment) — internal
//! network only, never proxied to the internet or given secrets.
//!
//! Two guidelines §10 requirements this module exists to satisfy: an
//! **explicit timeout** on the outbound call (a hung sidecar must fail the
//! job, never block the worker thread indefinitely) and an explicit
//! **response-size cap**, enforced while streaming rather than trusted off
//! `Content-Length` (a malicious/misbehaving sidecar could omit or lie about
//! it) — a render that blows either bound fails closed with a clear error,
//! same "bounded, retriable, diagnosable" shape every other job worker in
//! this workspace follows.
use std::time::Duration;

use attome_types::AppError;
use futures_util::StreamExt;
use serde::Serialize;

/// A4/Letter, in inches — the two paper sizes `docgen_template.page_size`
/// allows (`seed.rs`'s `page_size_options`). Falls back to A4 for anything
/// else (an unset/unrecognized value), never an error — page size is a
/// cosmetic setting, not a security or correctness one.
fn paper_size_inches(page_size: &str) -> (f64, f64) {
    match page_size {
        "Letter" => (8.5, 11.0),
        _ => (8.27, 11.69), // A4
    }
}

#[derive(Serialize)]
struct RenderOptions {
    #[serde(rename = "paperWidthIn")]
    paper_width_in: f64,
    #[serde(rename = "paperHeightIn")]
    paper_height_in: f64,
    #[serde(rename = "marginTopIn")]
    margin_top_in: f64,
    #[serde(rename = "marginBottomIn")]
    margin_bottom_in: f64,
    #[serde(rename = "marginLeftIn")]
    margin_left_in: f64,
    #[serde(rename = "marginRightIn")]
    margin_right_in: f64,
    #[serde(rename = "printBackground")]
    print_background: bool,
}

#[derive(Serialize)]
struct RenderRequestBody<'a> {
    html: &'a str,
    options: RenderOptions,
}

/// Renders `html` to a PDF via the sidecar named by `config.render_service_url`.
/// `html` must already be merge-substituted and SSRF-screened
/// (`crate::ssrf::guard`) by the caller — this function performs no content
/// screening of its own.
pub async fn render_pdf(
    config: &attome_config::DocgenSection,
    html: &str,
    page_size: &str,
    margin_mm: Option<f64>,
) -> Result<Vec<u8>, AppError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()
        .map_err(|e| AppError::Internal(format!("failed to build render HTTP client: {e}")))?;

    let (paper_width_in, paper_height_in) = paper_size_inches(page_size);
    let margin_in = margin_mm.unwrap_or(10.0) / 25.4;

    let body = RenderRequestBody {
        html,
        options: RenderOptions {
            paper_width_in,
            paper_height_in,
            margin_top_in: margin_in,
            margin_bottom_in: margin_in,
            margin_left_in: margin_in,
            margin_right_in: margin_in,
            print_background: true,
        },
    };

    let url = format!("{}/render", config.render_service_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("render sidecar request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(500).collect();
        return Err(AppError::Internal(format!(
            "render sidecar returned {status}: {snippet}"
        )));
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| AppError::Internal(format!("render sidecar stream error: {e}")))?;
        bytes.extend_from_slice(&chunk);
        if bytes.len() > config.max_response_bytes {
            return Err(AppError::Validation(format!(
                "rendered document exceeds the {}-byte response cap",
                config.max_response_bytes
            )));
        }
    }
    if bytes.is_empty() {
        return Err(AppError::Internal(
            "render sidecar returned an empty response".into(),
        ));
    }
    Ok(bytes)
}

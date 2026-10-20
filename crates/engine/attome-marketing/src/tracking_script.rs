//! The website tracking script (roadmap E14-T4), served by the deployment
//! at `GET /api/v1/track/script.js?site=<site key>`.
//!
//! The script (`assets/track.js`) sends nothing until the visitor grants
//! the analytics consent category, stays anonymous under Global Privacy
//! Control, keeps a first-party visitor cookie (`atm_vid`, 13 months) and a
//! 30-minute session cookie (`atm_sid`), and batches events to the
//! deployment's own collect route. It never fingerprints a browser and
//! loads nothing from anywhere else.
//!
//! The route answers the script with the site's configuration in front
//! (its key and whether custom events are on) only when marketing is
//! licensed, the `marketing.tracking` flag is on, and the site is a
//! known, enabled `marketing_tracked_site`; every other case is the same
//! 404, so the route reveals nothing about a deployment.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;

/// The script, as shipped.
pub const SCRIPT: &str = include_str!("../assets/track.js");

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ScriptQuery {
    /// The tracked site's key.
    pub site: String,
}

/// The served body: the site's configuration, then the script. Pure.
pub fn body(site_key: &str, custom_events: bool) -> String {
    let config = serde_json::json!({ "site": site_key, "customEvents": custom_events }).to_string();
    // Safe inside a script whatever the key holds.
    let config = config
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    format!("window.__attomeTrack={config};\n{SCRIPT}")
}

#[utoipa::path(
    get,
    path = "/api/v1/track/script.js",
    operation_id = "get_tracking_script",
    tag = "marketing",
    params(ScriptQuery),
    responses(
        (status = 200, description = "The tracking script for the site", content_type = "application/javascript", body = String),
        (status = 404, description = "No such tracked site (the same answer for every reason)", body = ErrorResponse),
    ),
)]
/// The website tracking script.
///
/// The site's configuration and the script, cached for a day. Public: a
/// website loads it with a script tag.
async fn get_script(
    State(state): State<EngineState>,
    Query(q): Query<ScriptQuery>,
) -> Result<Response, AppError> {
    if state
        .modules
        .load()
        .require(attome_modules::MODULE_MARKETING)
        .is_err()
        || !state
            .feature_flags()
            .is_on_for_deployment("marketing.tracking")
    {
        return Err(AppError::NotFound);
    }
    let key = q.site.trim();
    if key.is_empty() || key.len() > 64 {
        return Err(AppError::NotFound);
    }
    let enabled: Option<Option<bool>> = sqlx::query_scalar(
        "SELECT enabled FROM marketing_tracked_site WHERE site_key = $1 AND is_active IS NOT FALSE",
    )
    .bind(key)
    .fetch_optional(&state.base.db)
    .await
    .map_err(|_| AppError::NotFound)?;
    if enabled.flatten() != Some(true) {
        return Err(AppError::NotFound);
    }
    let custom = state
        .feature_flags()
        .is_on_for_deployment("marketing.tracking_custom_events");
    let mut response = body(key, custom).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    Ok(response)
}

/// The public script route, merged with the other bypass-listed routes.
pub fn public_routes() -> Router<EngineState> {
    Router::new().route("/api/v1/track/script.js", get(get_script))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_script))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn script_is_under_10kb_gzipped() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(SCRIPT.as_bytes()).unwrap();
        let gzipped = encoder.finish().unwrap();
        assert!(gzipped.len() < 10_240, "{} bytes gzipped", gzipped.len());
    }

    #[test]
    fn script_has_no_fingerprinting_calls() {
        for word in ["canvas", "AudioContext", "deviceMemory", "plugins"] {
            assert!(!SCRIPT.contains(word), "the script mentions {word}");
        }
        assert!(
            !SCRIPT.contains("http://") && !SCRIPT.contains("https://"),
            "no other host"
        );
    }

    #[test]
    fn script_config_is_safe_inside_a_script() {
        let served = body("</script><x>", true);
        assert!(served.starts_with("window.__attomeTrack={"));
        assert!(!served[..60].contains("</script>"));
        assert!(served.contains("\"customEvents\":true"));
    }
}

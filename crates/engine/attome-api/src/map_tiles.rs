//! B15-T2: map tiles through the server. The page's Content-Security-Policy
//! allows images and fetches from the deployment only (`img-src 'self'`,
//! `connect-src 'self'`), so a map view asks this route for each tile and
//! the server fetches it from the tile server the `maps.tile_url` setting
//! names (OpenStreetMap's public tiles by default, or the customer's own).
//! The tile server never sees who is looking at which records.
//!
//! Only signed-in people may ask (no open proxy), only for a tile that
//! exists at its zoom, and only an image comes back. The setting is a
//! deployment-wide one an administrator sets, so the host it names may be
//! private (an in-house tile server) without opening the route to other
//! internal addresses. Tiles are cached by the browser for a day; nothing is
//! stored on the server.

use std::time::Duration;

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// The setting naming the tile server, `{z}`, `{x}` and `{y}` in it.
pub const TILE_URL_SETTING: &str = "maps.tile_url";
/// The deepest zoom a tile is asked for.
pub const MAX_ZOOM: u32 = 22;
/// The largest tile passed on.
const MAX_TILE_BYTES: usize = 2 * 1024 * 1024;
/// How long one tile may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The tile server's URL for tile (`z`, `x`, `y`), or why there is none.
/// Pure.
pub fn tile_url(template: &str, z: u32, x: u32, y: u32) -> Result<String, AppError> {
    if z > MAX_ZOOM {
        return Err(AppError::Validation(format!("zoom is at most {MAX_ZOOM}")));
    }
    let side = 1u64 << z;
    if u64::from(x) >= side || u64::from(y) >= side {
        return Err(AppError::Validation(
            "x and y must name a tile at that zoom".into(),
        ));
    }
    if !(template.starts_with("https://") || template.starts_with("http://"))
        || !template.contains("{z}")
    {
        return Err(AppError::CapabilityUnavailable("map_tiles"));
    }
    Ok(template
        .replace("{z}", &z.to_string())
        .replace("{x}", &x.to_string())
        .replace("{y}", &y.to_string()))
}

fn configured_template(state: &EngineState) -> Option<String> {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(TILE_URL_SETTING)
        .map(|d| store.resolve(d, None, None).0)
        .and_then(|v| v.as_str().map(str::to_owned))
}

/// A map tile
///
/// One raster tile of the map views, fetched from the configured tile server (`maps.tile_url`). Signed-in callers only; the browser keeps it for a day.
#[utoipa::path(
    get,
    path = "/api/v1/maps/tiles/{z}/{x}/{y}",
    tag = "entity",
    params(
        ("z" = u32, Path, description = "Zoom, 0 to 22"),
        ("x" = u32, Path, description = "Tile column at that zoom"),
        ("y" = u32, Path, description = "Tile row at that zoom"),
    ),
    responses(
        (status = 200, description = "The tile image", content_type = "image/png"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "No such tile at that zoom", body = ErrorResponse),
        (status = 503, description = "The tile server is not configured or did not answer with an image", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn map_tile(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path((z, x, y)): Path<(u32, u32, u32)>,
) -> Result<Response, AppError> {
    let template =
        configured_template(&state).ok_or(AppError::CapabilityUnavailable("map_tiles"))?;
    let target = tile_url(&template, z, x, y)?;
    let purpose = attome_outbound::http::Purpose::public("map_tiles")
        .with_private_urls(std::iter::once(template.as_str()))
        .no_redirects();
    let http = attome_outbound::http::client(purpose, |b| b.timeout(TIMEOUT))
        .map_err(|_| AppError::CapabilityUnavailable("map_tiles"))?;
    let answer = http
        .get(&target)
        .header(header::USER_AGENT, "Attome map tiles")
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, z, x, y, "map tile: the tile server did not answer");
            AppError::CapabilityUnavailable("map_tiles")
        })?;
    let content_type = answer
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    if !answer.status().is_success() || !content_type.starts_with("image/") {
        tracing::warn!(
            status = answer.status().as_u16(),
            z,
            x,
            y,
            "map tile: no image from the tile server"
        );
        return Err(AppError::CapabilityUnavailable("map_tiles"));
    }
    let body = answer.bytes().await.map_err(|error| {
        tracing::warn!(%error, z, x, y, "map tile: the tile could not be read");
        AppError::CapabilityUnavailable("map_tiles")
    })?;
    if body.len() > MAX_TILE_BYTES {
        return Err(AppError::CapabilityUnavailable("map_tiles"));
    }
    let mut response = body.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=86400"),
    );
    Ok(response)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/maps/tiles/{z}/{x}/{y}", get(map_tile))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(map_tile))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_tile_urls_name_only_real_tiles() {
        let osm = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
        assert_eq!(
            tile_url(osm, 3, 4, 5).unwrap(),
            "https://tile.openstreetmap.org/3/4/5.png"
        );
        assert!(tile_url(osm, 0, 0, 0).is_ok());
        assert!(tile_url(osm, 0, 1, 0).is_err(), "zoom 0 has one tile");
        assert!(tile_url(osm, 3, 8, 0).is_err());
        assert!(tile_url(osm, MAX_ZOOM + 1, 0, 0).is_err());
        assert!(tile_url("ftp://tiles/{z}/{x}/{y}", 1, 0, 0).is_err());
        assert!(tile_url("https://tiles.example/static.png", 1, 0, 0).is_err());
    }
}

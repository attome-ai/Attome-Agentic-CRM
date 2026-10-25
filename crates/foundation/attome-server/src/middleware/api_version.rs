//! S8-T1: which API version a request is answered at
//! (`attome_types::api_version`). Runs after authentication, so it knows the
//! caller: the `Attome-Version` header when supported, else the API key's or
//! S2S client's `pinned_api_version`, else the current version; a browser
//! session always gets the current version. An unknown version is a 400
//! `unsupported_api_version` naming the supported ones. The answer is put
//! in request extensions ([`ApiVersion`]) and echoed as `Attome-Version`.
//!
//! While the server supports one version, every pin is that version, so the
//! pin is not read.

use attome_types::api_version::{self, ApiVersion};
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::middleware::auth::{ApiKeyIdentity, CookieSession};
use crate::middleware::deprecation;
use crate::middleware::version_adapters;
use crate::state::AppState;

/// S8-T1: set by the S2S layer, naming the client whose pin applies.
#[derive(Debug, Clone, Copy)]
pub struct S2sClientRef(pub Uuid);

/// Where the caller's pin is kept, read before any await so the request is
/// not held across one.
fn pin_source(req: &Request) -> Option<(&'static str, Uuid)> {
    if api_version::SUPPORTED.len() < 2 {
        return None;
    }
    if let Some(key) = req.extensions().get::<ApiKeyIdentity>() {
        return Some((
            "SELECT pinned_api_version FROM api_key WHERE id = $1",
            key.0,
        ));
    }
    req.extensions().get::<S2sClientRef>().map(|client| {
        (
            "SELECT pinned_api_version FROM s2s_client WHERE id = $1",
            client.0,
        )
    })
}

async fn pinned(state: &AppState, (sql, id): (&'static str, Uuid)) -> Option<String> {
    match sqlx::query_scalar::<_, String>(sql)
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(pin) => pin,
        Err(error) => {
            tracing::warn!(%error, "api version: pin unreadable; answering at the current version");
            None
        }
    }
}

fn unsupported(requested: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "unsupported_api_version",
            "message": format!("API version {requested:?} is not supported"),
            "supported": api_version::SUPPORTED,
        })),
    )
        .into_response()
}

/// The layer itself; see the module doc.
pub async fn api_version(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let header = req
        .headers()
        .get(api_version::HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let browser = req.extensions().get::<CookieSession>().is_some();
    let source = if header.is_none() && !browser {
        pin_source(&req)
    } else {
        None
    };
    let pin = match source {
        Some(source) => pinned(&state, source).await,
        None => None,
    };
    let version = match api_version::resolve(header.as_deref(), pin.as_deref(), browser) {
        Ok(version) => version,
        Err(refused) => return unsupported(&refused.requested),
    };
    // S8-T3: a version past its sunset is refused; a deprecated one says so.
    let notice = deprecation::version_notice(version, chrono::Utc::now().timestamp());
    if let deprecation::VersionNotice::Sunset(entry) = notice {
        let mut response = (
            StatusCode::GONE,
            Json(serde_json::json!({
                "error": "api_version_sunset",
                "message": format!("API version {} was retired on {}", entry.version, entry.sunset),
                "supported": api_version::SUPPORTED,
            })),
        )
            .into_response();
        deprecation::apply_version_headers(entry, response.headers_mut());
        return response;
    }
    // S8-T4: count an API key's or S2S client's call by version and route;
    // a browser always gets the current version, so it is not counted.
    let caller = if browser {
        None
    } else if let Some(key) = req.extensions().get::<ApiKeyIdentity>() {
        Some(crate::api_version_usage::Caller::ApiKey(key.0))
    } else {
        req.extensions()
            .get::<S2sClientRef>()
            .map(|client| crate::api_version_usage::Caller::S2sClient(client.0))
    };
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str().to_owned());
    if let (Some(caller), Some(route)) = (caller, route) {
        let deprecated = matches!(notice, deprecation::VersionNotice::Deprecated(_))
            || deprecation::is_deprecated_path(req.uri().path());
        if let Err(error) = crate::api_version_usage::record(
            &state.redis_coordination,
            chrono::Utc::now().date_naive(),
            caller,
            version,
            &route,
            deprecated,
        )
        .await
        {
            tracing::warn!(%error, "api version usage: record failed");
        }
    }
    req.extensions_mut().insert(ApiVersion(version));
    // S8-T2: an older caller's request is rewritten up to the current
    // version, and its response back down, for the operations an adapter
    // names. Nothing is buffered otherwise.
    let operation = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| format!("{} {}", req.method(), path.as_str()))
        .filter(|op| version_adapters::chain().applies(version, op));
    if let Some(op) = &operation {
        let (parts, body) = req.into_parts();
        let body = version_adapters::rewrite_body(body, |value| {
            version_adapters::chain().upgrade_request(version, op, value)
        })
        .await;
        req = Request::from_parts(parts, body);
        req.headers_mut().remove(axum::http::header::CONTENT_LENGTH);
    }
    let mut response = next.run(req).await;
    if let Some(op) = &operation {
        response = version_adapters::rewrite_response(response, |value| {
            version_adapters::chain().downgrade_response(version, op, value)
        })
        .await;
    }
    response
        .headers_mut()
        .insert(api_version::HEADER, HeaderValue::from_static(version));
    if let deprecation::VersionNotice::Deprecated(entry) = notice {
        deprecation::apply_version_headers(entry, response.headers_mut());
    }
    response
}

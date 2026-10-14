//! The live channel (roadmap Y14-T3, first slice): `GET /api/v1/live`, a
//! Server-Sent Events stream a signed-in web app keeps open.
//!
//! Today it carries one notice, `model-version`, sent when the published
//! metadata changes, so the client drops its cached render plans and
//! revalidates them (Y14-T2). Record changes and presence join the same
//! stream later. SSE rather than a WebSocket: it passes every proxy that
//! passes HTTP, reconnects by itself, and the notices only flow one way.
//!
//! Each connection polls one cheap aggregate over the published versions
//! every [`POLL`] (no process-wide state, so it is right on any number of
//! servers) and ends after [`LIFETIME`]; the browser's `EventSource`
//! reconnects, and its first `hello` frame carries the current stamp.

use std::convert::Infallible;
use std::time::Duration;

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use serde_json::json;

/// How often a connection checks for a new published version.
pub const POLL: Duration = Duration::from_secs(10);
/// How long one connection stays open before the client reconnects.
pub const LIFETIME: Duration = Duration::from_secs(30 * 60);
const KEEPALIVE: Duration = Duration::from_secs(25);

/// The published model's stamp: the newest publish time and the number of
/// published versions. Any publish changes it.
async fn model_stamp(db: &attome_db::DbPool) -> Result<String, AppError> {
    let stamp: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(max(created_at)::text, '') || '/' || count(*)::text \
         FROM metadata_object_version WHERE state = 'published'",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(stamp.unwrap_or_default())
}

fn frame(name: &'static str, stamp: &str) -> Event {
    Event::default()
        .event(name)
        .data(json!({ "model_version": stamp }).to_string())
}

/// Opens the live channel.
#[utoipa::path(
    get,
    path = "/api/v1/live",
    tag = "model",
    responses(
        (status = 200, description = "Server-Sent Events: `hello` with the current model version, then `model-version` whenever published metadata changes; each `data` is `{model_version}`", content_type = "text/event-stream"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn live(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, AppError> {
    let db = state.base.db.clone();
    let first = model_stamp(&db).await?;
    let deadline = tokio::time::Instant::now() + LIFETIME;
    let stream = futures_util::stream::unfold(
        (db, first, true, deadline),
        |(db, last, hello, deadline)| async move {
            if hello {
                let event = frame("hello", &last);
                return Some((Ok(event), (db, last, false, deadline)));
            }
            loop {
                let wake = (tokio::time::Instant::now() + POLL).min(deadline);
                tokio::time::sleep_until(wake).await;
                if tokio::time::Instant::now() >= deadline {
                    return None;
                }
                match model_stamp(&db).await {
                    Ok(stamp) if stamp != last => {
                        let event = frame("model-version", &stamp);
                        return Some((Ok(event), (db, stamp, false, deadline)));
                    }
                    Ok(_) => {}
                    // Ends the stream; the client reconnects and is told the
                    // current version in its `hello`.
                    Err(error) => {
                        tracing::warn!(%error, "live channel: model version read failed");
                        return None;
                    }
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEPALIVE).text("keep-alive")))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/live", get(live))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(live))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

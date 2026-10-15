//! The live channel (roadmap Y14-T3, first slice): `GET /api/v1/live`, a
//! Server-Sent Events stream a signed-in web app keeps open.
//!
//! It carries `model-version`, sent when the published metadata changes, so
//! the client drops its cached render plans and revalidates them (Y14-T2),
//! and (A13-T4) `records`: the changes to records of the entities named in
//! `?entities=`, so an open view updates its rows in place. SSE rather than
//! a WebSocket: it passes every proxy that passes HTTP, reconnects by
//! itself, and the notices only flow one way.
//!
//! **Record changes.** Read from the `entity_change_event` outbox between two
//! transaction-id watermarks (`[low, xmin)`): every transaction below the
//! snapshot's `xmin` has finished, so each change is sent once and none is
//! skipped. A change is sent only for a record the caller can read under the
//! entity's record rules, and only for entities they hold `read` on, so the
//! channel never reveals a record the caller could not open. More than
//! [`MAX_CHANGES`] in one poll sends `overflow` instead: reload.
//!
//! Each connection polls one cheap aggregate over the published versions
//! every [`POLL`] (no process-wide state, so it is right on any number of
//! servers) and ends after [`LIFETIME`]; the browser's `EventSource`
//! reconnects, and its first `hello` frame carries the current stamp.

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use attome_core::{EngineState, quote_ident};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::IntoParams;
use uuid::Uuid;

/// How often a connection checks for a new published version.
pub const POLL: Duration = Duration::from_secs(10);
/// How long one connection stays open before the client reconnects.
pub const LIFETIME: Duration = Duration::from_secs(30 * 60);
const KEEPALIVE: Duration = Duration::from_secs(25);
/// How often a connection watching records checks for their changes.
pub const RECORD_POLL: Duration = Duration::from_secs(3);
/// Entities one connection may watch.
pub const MAX_WATCHED: usize = 10;
/// Record changes one `records` frame carries; more send `overflow`.
pub const MAX_CHANGES: i64 = 200;

/// Query string for `GET /api/v1/live`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LiveQuery {
    /// A13-T4: entities whose record changes to send, comma-separated, at
    /// most 10. Entities the caller cannot read are left out.
    pub entities: Option<String>,
}

/// One record change as a `records` frame lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordChange {
    pub entity: String,
    pub id: Uuid,
    /// `create`, `update`, `delete` or `restore`.
    pub op: String,
}

/// One watched entity.
struct Watched {
    name: String,
    id: Uuid,
    access: AccessLevel,
}

/// What a connection watches and how far it has read.
struct Watch {
    ctx: Arc<SecurityContext>,
    entities: Vec<Watched>,
    /// The `xid8` (as text) below which every change has been sent.
    low: String,
}

/// The finished transactions' bound: every transaction id below it has
/// committed or rolled back.
async fn xmin(db: &attome_db::DbPool) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT pg_snapshot_xmin(pg_current_snapshot())::text")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// The entities named in `?entities=` the caller may read, resolved once.
async fn watched_entities(
    state: &EngineState,
    ctx: &SecurityContext,
    raw: &str,
) -> Result<Vec<Watched>, AppError> {
    let mut names: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    names.dedup();
    if names.len() > MAX_WATCHED {
        return Err(AppError::Validation(format!(
            "watch at most {MAX_WATCHED} entities"
        )));
    }
    let mut out = Vec::new();
    for name in names {
        let Some(id) = state.entities.load().get(name).map(|meta| meta.entity_id) else {
            continue;
        };
        if ctx.require(name, "read").is_err() {
            continue;
        }
        let access = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            id,
            name,
            RecordAction::Read,
        )
        .await?;
        out.push(Watched {
            name: name.to_owned(),
            id,
            access,
        });
    }
    Ok(out)
}

/// The changes since the last poll to records the caller can read; `None`
/// when there were more than [`MAX_CHANGES`].
async fn record_changes(
    state: &EngineState,
    watch: &mut Watch,
) -> Result<Option<Vec<RecordChange>>, AppError> {
    let high = xmin(&state.base.db).await?;
    let names: Vec<&str> = watch.entities.iter().map(|w| w.name.as_str()).collect();
    let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
        "SELECT entity_logicalname, record_id, operation FROM entity_change_event \
         WHERE commit_xid >= $1::text::xid8 AND commit_xid < $2::text::xid8 \
           AND event_name IS NULL AND operation <> 'purge' AND entity_logicalname = ANY($3) \
         ORDER BY commit_xid, id LIMIT $4",
    )
    .bind(&watch.low)
    .bind(&high)
    .bind(&names)
    .bind(MAX_CHANGES + 1)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    watch.low = high;
    if rows.len() as i64 > MAX_CHANGES {
        return Ok(None);
    }
    let mut out: Vec<RecordChange> = Vec::new();
    for entity in &watch.entities {
        let ids: Vec<Uuid> = rows
            .iter()
            .filter(|(name, _, _)| *name == entity.name)
            .map(|(_, id, _)| *id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if ids.is_empty() {
            continue;
        }
        let pred = attome_security::rls_predicate(
            &watch.ctx,
            entity.id,
            "",
            entity.access,
            RecordAction::Read.share_capability(),
            2,
        );
        let sql = format!(
            "SELECT id FROM {} WHERE id = ANY($1) {}",
            quote_ident(&entity.name),
            pred.as_ref().map_or("", |p| p.sql.as_str())
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(&ids);
        if let Some(p) = &pred {
            q = attome_security::bind_rls_predicate(q, &p.binds);
        }
        let visible: HashSet<Uuid> = q
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
        for (name, id, op) in &rows {
            if *name != entity.name || !visible.contains(id) {
                continue;
            }
            // One entry per record: its latest change.
            out.retain(|c| !(c.entity == *name && c.id == *id));
            out.push(RecordChange {
                entity: name.clone(),
                id: *id,
                op: op.clone(),
            });
        }
    }
    Ok(Some(out))
}

/// A `records` frame.
fn records_frame(changes: Option<&[RecordChange]>) -> Event {
    let data = match changes {
        Some(changes) => json!({ "changes": changes }),
        None => json!({ "overflow": true }),
    };
    Event::default().event("records").data(data.to_string())
}

/// One connection's state between frames.
struct Live {
    state: EngineState,
    last: String,
    hello: bool,
    deadline: tokio::time::Instant,
    next_model: tokio::time::Instant,
    watch: Option<Watch>,
}

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
        (status = 200, description = "Server-Sent Events: `hello` with the current model version, then `model-version` whenever published metadata changes (each `data` is `{model_version}`), and `records` for changes to records of the watched entities (`{changes: [{entity, id, op}]}`, or `{overflow: true}` when there were too many)", content_type = "text/event-stream"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "More than 10 entities", body = ErrorResponse),
    ),
    params(LiveQuery),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn live(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<LiveQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, AppError> {
    let first = model_stamp(&state.base.db).await?;
    let ctx = ctx.into_inner();
    let watch = match query.entities.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let entities = watched_entities(&state, &ctx, raw).await?;
            if entities.is_empty() {
                None
            } else {
                Some(Watch {
                    ctx,
                    entities,
                    low: xmin(&state.base.db).await?,
                })
            }
        }
        _ => None,
    };
    let now = tokio::time::Instant::now();
    let start = Live {
        state,
        last: first,
        hello: true,
        deadline: now + LIFETIME,
        next_model: now + POLL,
        watch,
    };
    let stream = futures_util::stream::unfold(start, |mut live| async move {
        if live.hello {
            live.hello = false;
            let event = frame("hello", &live.last);
            return Some((Ok(event), live));
        }
        loop {
            let tick = if live.watch.is_some() {
                RECORD_POLL
            } else {
                POLL
            };
            let wake = (tokio::time::Instant::now() + tick)
                .min(live.next_model)
                .min(live.deadline);
            tokio::time::sleep_until(wake).await;
            let now = tokio::time::Instant::now();
            if now >= live.deadline {
                return None;
            }
            if now >= live.next_model {
                live.next_model = now + POLL;
                match model_stamp(&live.state.base.db).await {
                    Ok(stamp) if stamp != live.last => {
                        let event = frame("model-version", &stamp);
                        live.last = stamp;
                        return Some((Ok(event), live));
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
            let state = live.state.clone();
            if let Some(watch) = live.watch.as_mut() {
                match record_changes(&state, watch).await {
                    Ok(Some(changes)) if changes.is_empty() => {}
                    Ok(changes) => {
                        let event = records_frame(changes.as_deref());
                        return Some((Ok(event), live));
                    }
                    Err(error) => {
                        tracing::warn!(%error, "live channel: record change read failed");
                        return None;
                    }
                }
            }
        }
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_records_frame_lists_changes_or_says_overflow() {
        let id = Uuid::now_v7();
        let change = RecordChange {
            entity: "account".into(),
            id,
            op: "update".into(),
        };
        let listed = format!("{:?}", records_frame(Some(&[change])));
        assert!(listed.contains("records"), "{listed}");
        assert!(listed.contains(&id.to_string()), "{listed}");
        let overflow = format!("{:?}", records_frame(None));
        assert!(overflow.contains("overflow"), "{overflow}");
    }
}

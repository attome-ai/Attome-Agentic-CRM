//! `GET /api/v1/feed` (roadmap C3-T1): the caller's feed, built on read.
//!
//! **Sources**, each a [`FeedItemKind`]:
//! - `post` — `feed_post` records (the core follow bundle), read through the
//!   caller's own `feed_post.read` privilege and row-level security, exactly
//!   as a generic list reads them; a body the caller may not read (field
//!   security) is left out;
//! - `record_event` — creates, updates, deletes and restores of the records
//!   the caller follows (`follow`, C2-T1), from the change feed. Each is
//!   shown only while the caller may read that record now: one batched,
//!   row-security-checked lookup per entity on the page
//!   ([`super::resolve_visible`]), so a record that became hidden drops out.
//!   Business events (`event_name`) and purges are not feed items.
//!
//! **Paging.** A keyset over `(occurred_at DESC, kind ASC, id DESC)`, as the
//! record timeline pages (D-601): each source applies the keyset and fetches
//! `page_size + 1` rows, the merge keeps the first `page_size`, and
//! `next_cursor` is present exactly when more exist. The record-event read
//! check runs on the merged page, so a page can hold fewer than `page_size`
//! items while `next_cursor` is still set.

use std::collections::{BTreeMap, HashMap};

use attome_core::{EngineState, quote_ident};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::timeline::{
    SourceBind, decode_cursor, detail_object_sql, encode_cursor, run_source_query,
};

/// The posts entity.
pub const POST_ENTITY: &str = "feed_post";
/// The follows entity (C2-T1).
const FOLLOW_ENTITY: &str = "follow";
/// The default and largest page.
const DEFAULT_FEED_PAGE: i64 = 25;
const MAX_FEED_PAGE: i64 = 100;

/// What a feed item is. Ordered by wire name, as the keyset compares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedItemKind {
    Post,
    RecordEvent,
}

impl FeedItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::RecordEvent => "record_event",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "post" => Some(Self::Post),
            "record_event" => Some(Self::RecordEvent),
            _ => None,
        }
    }
}

/// One feed item.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FeedItem {
    pub kind: FeedItemKind,
    /// The post's id, or the change event's.
    pub id: Uuid,
    pub occurred_at: DateTime<Utc>,
    /// Who posted, or who made the change, when known.
    pub actor: Option<Uuid>,
    /// A post's text.
    pub body: Option<String>,
    /// A record event's entity, record and operation (`create`, `update`,
    /// `delete`, `restore`).
    pub entity: Option<String>,
    pub record_id: Option<Uuid>,
    pub operation: Option<String>,
    /// The record's primary name, when its entity declares one.
    pub record_name: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FeedQuery {
    /// The `next_cursor` of the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Items per page, 1 to 100 (default 25).
    #[serde(default)]
    pub page_size: Option<i64>,
    /// Only this kind of item.
    #[serde(default)]
    pub kind: Option<FeedItemKind>,
}

/// A decoded cursor: the last item's position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedCursor {
    pub micros: i64,
    pub kind: FeedItemKind,
    pub id: Uuid,
}

/// Decodes a feed cursor; a timeline cursor or garbage is a 422.
pub fn parse_cursor(raw: &str) -> Result<FeedCursor, AppError> {
    let (micros, tag, id) = decode_cursor(raw)?;
    let kind =
        FeedItemKind::parse(&tag).ok_or_else(|| AppError::Validation("malformed cursor".into()))?;
    Ok(FeedCursor { micros, kind, id })
}

/// The keyset condition for one source of kind `kind` after `cursor`, with
/// the timestamp at `$ts` and the id at `$idp`; the flag says whether the id
/// is bound. Pure.
pub fn keyset(
    cursor: Option<&FeedCursor>,
    kind: FeedItemKind,
    occ: &str,
    id: &str,
    ts: usize,
    idp: usize,
) -> Option<(String, bool)> {
    let cursor = cursor?;
    Some(match kind.cmp(&cursor.kind) {
        std::cmp::Ordering::Greater => (format!("AND {occ} <= ${ts}"), false),
        std::cmp::Ordering::Less => (format!("AND {occ} < ${ts}"), false),
        std::cmp::Ordering::Equal => (
            format!("AND ({occ} < ${ts} OR ({occ} = ${ts} AND {id} < ${idp}))"),
            true,
        ),
    })
}

/// Merges the sources newest first (then kind, then id newest first), keeps
/// `limit`, and gives the cursor for the next page when more exist. Pure.
pub fn merge_page(
    mut items: Vec<(i64, FeedItem)>,
    limit: usize,
) -> (Vec<(i64, FeedItem)>, Option<String>) {
    items.sort_by(|(am, a), (bm, b)| bm.cmp(am).then(a.kind.cmp(&b.kind)).then(b.id.cmp(&a.id)));
    let more = items.len() > limit;
    items.truncate(limit);
    let next = more
        .then(|| items.last())
        .flatten()
        .map(|(m, item)| encode_cursor(*m, item.kind.as_str(), item.id));
    (items, next)
}

fn cursor_binds(
    binds: &mut Vec<SourceBind>,
    cursor: Option<&FeedCursor>,
    keyset: &Option<(String, bool)>,
) -> Result<(), AppError> {
    if let (Some(c), Some((_, with_id))) = (cursor, keyset) {
        let at = DateTime::<Utc>::from_timestamp_micros(c.micros)
            .ok_or_else(|| AppError::Validation("malformed cursor".into()))?;
        binds.push(SourceBind::Ts(at));
        if *with_id {
            binds.push(SourceBind::Id(c.id));
        }
    }
    Ok(())
}

fn uuid_at(row: &Value, key: &str) -> Option<Uuid> {
    row.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// The caller's posts source.
async fn posts(
    state: &EngineState,
    ctx: &SecurityContext,
    cursor: Option<&FeedCursor>,
    limit: i64,
) -> Result<Vec<(i64, FeedItem)>, AppError> {
    let Some((entity_id, attrs, is_append_only)) = state
        .entities
        .load()
        .get(POST_ENTITY)
        .map(|m| (m.entity_id, m.attrs.clone(), m.is_append_only))
    else {
        return Ok(Vec::new());
    };
    if ctx.require(POST_ENTITY, "read").is_err() {
        return Ok(Vec::new());
    }
    let detail = detail_object_sql(ctx, POST_ENTITY, &attrs, &["body"]);
    let live = attome_core::live_row_predicate("t", is_append_only)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();
    let mut binds = vec![SourceBind::Int(limit + 1)];
    let ks = keyset(cursor, FeedItemKind::Post, "t.created_at", "t.id", 2, 3);
    cursor_binds(&mut binds, cursor, &ks)?;
    let sql = format!(
        "SELECT jsonb_build_object('id', t.id, \
                'micros', (EXTRACT(EPOCH FROM t.created_at) * 1000000)::bigint, \
                'created_by', t.created_by, 'detail', {detail}) \
         FROM {table} t \
         WHERE true {live} {ks} {{rls}} \
         ORDER BY t.created_at DESC, t.id DESC LIMIT $1",
        table = quote_ident(POST_ENTITY),
        ks = ks.as_ref().map_or("", |k| k.0.as_str()),
    );
    let rows = run_source_query(state, ctx, POST_ENTITY, entity_id, &attrs, &sql, binds).await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let id = uuid_at(row, "id")?;
            let micros = row.get("micros").and_then(Value::as_i64)?;
            Some((
                micros,
                FeedItem {
                    kind: FeedItemKind::Post,
                    id,
                    occurred_at: DateTime::<Utc>::from_timestamp_micros(micros)?,
                    actor: uuid_at(row, "created_by"),
                    body: row
                        .get("detail")
                        .and_then(|d| d.get("body"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    entity: None,
                    record_id: None,
                    operation: None,
                    record_name: None,
                },
            ))
        })
        .collect())
}

#[derive(Debug, sqlx::FromRow)]
struct EventRow {
    id: Uuid,
    entity_logicalname: String,
    record_id: Uuid,
    operation: String,
    micros: i64,
    actor: Option<String>,
}

/// Changes to the records the caller follows. Driven from the caller's
/// follows, so each followed record reads its own events by index.
async fn followed_events(
    state: &EngineState,
    ctx: &SecurityContext,
    cursor: Option<&FeedCursor>,
    limit: i64,
) -> Result<Vec<(i64, FeedItem)>, AppError> {
    if state.entities.load().get(FOLLOW_ENTITY).is_none() {
        return Ok(Vec::new());
    }
    let occ = "e.created_at";
    let ks = keyset(cursor, FeedItemKind::RecordEvent, occ, "e.id", 3, 4);
    let sql = format!(
        "SELECT e.id, e.entity_logicalname, e.record_id, e.operation, e.micros, e.actor \
           FROM follow f \
           CROSS JOIN LATERAL ( \
                SELECT e.id, e.entity_logicalname, e.record_id, e.operation, e.created_at, \
                       (EXTRACT(EPOCH FROM e.created_at) * 1000000)::bigint AS micros, \
                       e.after->>'modified_by' AS actor \
                  FROM entity_change_event e \
                 WHERE e.entity_logicalname = f.entity_name \
                   AND e.record_id = f.record_id::uuid \
                   AND e.event_name IS NULL \
                   AND e.operation IN ('create', 'update', 'delete', 'restore') {ks} \
                 ORDER BY {occ} DESC, e.id DESC LIMIT $2) e \
          WHERE f.user_id = $1 AND (f.is_active IS NULL OR f.is_active = true) \
            AND f.record_id ~* '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$' \
          ORDER BY e.created_at DESC, e.id DESC LIMIT $2",
        ks = ks.as_ref().map_or("", |k| k.0.as_str()),
    );
    let mut q = sqlx::query_as::<_, EventRow>(&sql)
        .bind(ctx.user_id)
        .bind(limit + 1);
    if let (Some(c), Some((_, with_id))) = (cursor, &ks) {
        let at = DateTime::<Utc>::from_timestamp_micros(c.micros)
            .ok_or_else(|| AppError::Validation("malformed cursor".into()))?;
        q = q.bind(at);
        if *with_id {
            q = q.bind(c.id);
        }
    }
    let rows = q
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some((
                r.micros,
                FeedItem {
                    kind: FeedItemKind::RecordEvent,
                    id: r.id,
                    occurred_at: DateTime::<Utc>::from_timestamp_micros(r.micros)?,
                    actor: r.actor.and_then(|a| Uuid::parse_str(&a).ok()),
                    body: None,
                    entity: Some(r.entity_logicalname),
                    record_id: Some(r.record_id),
                    operation: Some(r.operation),
                    record_name: None,
                },
            ))
        })
        .collect())
}

/// Keeps the record events whose record the caller may read now, naming
/// each; one row-security-checked lookup per entity.
async fn visible_events(
    state: &EngineState,
    ctx: &SecurityContext,
    items: Vec<(i64, FeedItem)>,
) -> Vec<(i64, FeedItem)> {
    let mut by_entity: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for (_, item) in &items {
        if let (FeedItemKind::RecordEvent, Some(entity), Some(record)) =
            (item.kind, item.entity.as_ref(), item.record_id)
        {
            by_entity.entry(entity.clone()).or_default().push(record);
        }
    }
    let mut visible: HashMap<(String, Uuid), Option<String>> = HashMap::new();
    for (entity, ids) in by_entity {
        if ctx.require(&entity, "read").is_err() {
            continue;
        }
        let Some(entity_id) = state.entities.load().get(&entity).map(|m| m.entity_id) else {
            continue;
        };
        for (id, found) in super::resolve_visible(state, ctx, entity_id, &ids).await {
            visible.insert((entity.clone(), id), found.name);
        }
    }
    items
        .into_iter()
        .filter_map(|(m, mut item)| {
            if item.kind == FeedItemKind::RecordEvent {
                let key = (item.entity.clone()?, item.record_id?);
                item.record_name = visible.get(&key)?.clone();
            }
            Some((m, item))
        })
        .collect()
}

/// The caller's feed page.
pub async fn feed(
    state: &EngineState,
    ctx: &SecurityContext,
    query: &FeedQuery,
) -> Result<CursorPage<FeedItem>, AppError> {
    let limit = query
        .page_size
        .unwrap_or(DEFAULT_FEED_PAGE)
        .clamp(1, MAX_FEED_PAGE);
    let cursor = query.cursor.as_deref().map(parse_cursor).transpose()?;
    let wants = |k: FeedItemKind| query.kind.is_none_or(|only| only == k);
    let mut items = Vec::new();
    if wants(FeedItemKind::Post) {
        items.extend(posts(state, ctx, cursor.as_ref(), limit).await?);
    }
    if wants(FeedItemKind::RecordEvent) {
        items.extend(followed_events(state, ctx, cursor.as_ref(), limit).await?);
    }
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let (page, next) = merge_page(items, limit);
    let page = visible_events(state, ctx, page).await;
    Ok(CursorPage::new(
        page.into_iter().map(|(_, item)| item).collect(),
        next,
    ))
}

/// My feed
///
/// C3-T1: the caller's feed — posts and changes to the records they follow,
/// newest first, each only if they may read it.
#[utoipa::path(
    get,
    path = "/api/v1/feed",
    tag = "entity",
    params(FeedQuery),
    responses(
        (status = 200, description = "Success", body = CursorPage<FeedItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Malformed cursor", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_feed(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(mut query): Query<FeedQuery>,
) -> Result<Json<CursorPage<FeedItem>>, AppError> {
    query.cursor = attome_types::cursor::open_opt(query.cursor.as_deref())?;
    Ok(Json(feed(&state, &ctx, &query).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_feed))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: FeedItemKind, id: u128) -> FeedItem {
        FeedItem {
            kind,
            id: Uuid::from_u128(id),
            occurred_at: DateTime::<Utc>::from_timestamp_micros(0).unwrap(),
            actor: None,
            body: None,
            entity: None,
            record_id: None,
            operation: None,
            record_name: None,
        }
    }

    #[test]
    fn feed_merges_newest_first_and_pages_by_keyset() {
        let items = vec![
            (10, item(FeedItemKind::RecordEvent, 1)),
            (30, item(FeedItemKind::Post, 2)),
            (20, item(FeedItemKind::Post, 3)),
            (20, item(FeedItemKind::RecordEvent, 4)),
        ];
        let (page, next) = merge_page(items, 3);
        let order: Vec<u128> = page.iter().map(|(_, i)| i.id.as_u128()).collect();
        // Same instant: post before record_event (kind order).
        assert_eq!(order, vec![2, 3, 4]);
        let cursor = parse_cursor(&next.unwrap()).unwrap();
        assert_eq!(
            cursor,
            FeedCursor {
                micros: 20,
                kind: FeedItemKind::RecordEvent,
                id: Uuid::from_u128(4)
            }
        );
        let (_, none) = merge_page(vec![(1, item(FeedItemKind::Post, 9))], 3);
        assert!(none.is_none());
    }

    #[test]
    fn feed_keyset_compares_kind_then_id() {
        let c = FeedCursor {
            micros: 5,
            kind: FeedItemKind::Post,
            id: Uuid::nil(),
        };
        let (post, post_id) = keyset(Some(&c), FeedItemKind::Post, "t", "i", 2, 3).unwrap();
        assert!(post.contains("t = $2 AND i < $3") && post_id);
        let (event, event_id) =
            keyset(Some(&c), FeedItemKind::RecordEvent, "t", "i", 3, 4).unwrap();
        assert_eq!((event.as_str(), event_id), ("AND t <= $3", false));
        assert!(keyset(None, FeedItemKind::Post, "t", "i", 2, 3).is_none());
        assert!(parse_cursor("not a cursor").is_err());
    }
}

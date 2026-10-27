//! `POST /api/v1/offline/pull` (roadmap B18-T5): a device's next page of its
//! offline profile.
//!
//! **Reading.** Every record comes through the stored query the profile
//! names (or the entity's default view), run as the caller by the ordinary
//! query executor: its privilege gate, record scope and field security apply,
//! and sensitive attributes are then dropped (B18-T4). Nothing is read with
//! SQL of its own.
//!
//! **Cursor.** The server keeps it, per device, in `offline_device_state`. A
//! *round* visits every profile entity once. For each entity, a *generation*
//! pages by `(modified_at, id)` over the rows changed at or after the start
//! of the entity's previous generation (everything, the first time), so a
//! page boundary never loses rows that share a timestamp; resuming continues
//! the keyset, so a page is never sent twice within a generation. A query
//! that does not return `modified_at` is read in full each generation.
//!
//! **Removals.** When an entity's generation ends, the ids the caller can
//! read now (same query, ids only) are compared with the device's manifest:
//! every manifest id outside that set (access lost, or the record left the
//! query's filter, or was deleted) is sent as a removal and leaves the
//! manifest. Entities no longer in the profile are removed whole.
//!
//! A new profile, or an administrator's forced refresh, restarts the device
//! from an empty manifest.

use std::collections::{BTreeMap, HashSet};

use attome_audit::security::{ExemptReason, x_audit_exempt};
use attome_core::EngineState;
use attome_records::query_exec::{ExecuteQueryRequest, execute_stored_query};
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::profile::{OfflineEntity, OfflineProfile};

/// Rows per page (the executor's largest page).
pub const PULL_PAGE: i64 = 200;
/// Ids per page when listing what the caller can read.
const ID_PAGE: i64 = 200;
/// Most manifest rows removed for a dropped entity in one pull.
const MAX_DROPPED: i64 = 5000;

/// `POST /api/v1/offline/pull`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PullBody {
    /// The registered device (B17-T4) pulling.
    pub device_id: Uuid,
}

/// A record to keep or update on the device.
#[derive(Debug, Serialize, ToSchema)]
pub struct PulledRecord {
    pub entity: String,
    /// The record's values, without sensitive attributes.
    #[schema(value_type = Object)]
    pub record: Value,
}

/// A record the device must drop.
#[derive(Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct Removal {
    pub entity: String,
    pub id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PullResult {
    pub upserts: Vec<PulledRecord>,
    pub removals: Vec<Removal>,
    /// `true` once every profile entity is up to date; pull again later.
    pub done: bool,
    /// The profile's bundle version (B18-T4): a different one means fetch the
    /// profile again.
    pub bundle_version: String,
}

/// One entity's place in the device's sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityCursor {
    /// Rows changed at or after this are read; none reads everything.
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    /// When the running generation started; the next `since`.
    #[serde(default)]
    pub generation_start: Option<DateTime<Utc>>,
    /// The last row sent in the running generation.
    #[serde(default)]
    pub after: Option<Uuid>,
    /// Whether a generation is running.
    #[serde(default)]
    pub active: bool,
    /// The query does not return `modified_at`: read in full.
    #[serde(default)]
    pub full: bool,
}

/// The device's whole cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCursor {
    #[serde(default)]
    pub entities: BTreeMap<String, EntityCursor>,
    /// Entities already brought up to date in the current round.
    #[serde(default)]
    pub round: Vec<String>,
}

impl EntityCursor {
    /// Starts a generation at `now` unless one is running. Pure.
    pub fn begin(&mut self, now: DateTime<Utc>) {
        if !self.active {
            self.active = true;
            self.after = None;
            self.generation_start = Some(now);
        }
    }

    /// Ends the running generation: the next reads from its start. Pure.
    pub fn finish(&mut self) {
        self.active = false;
        self.after = None;
        if !self.full {
            self.since = self.generation_start;
        }
    }
}

/// The next entity of the round, in profile order: the first not yet
/// brought up to date. `None` ends the round. Pure.
pub fn next_entity<'a>(
    profile: &'a [OfflineEntity],
    round: &[String],
) -> Option<&'a OfflineEntity> {
    profile.iter().find(|e| !round.contains(&e.entity))
}

/// The manifest ids outside what the caller can read now. Pure.
pub fn lost(manifest: &[Uuid], readable: &HashSet<Uuid>) -> Vec<Uuid> {
    manifest
        .iter()
        .copied()
        .filter(|id| !readable.contains(id))
        .collect()
}

/// A record without its sensitive attributes, and its id. Pure.
pub fn strip(record: Value, sensitive: &HashSet<String>) -> Option<(Uuid, Value)> {
    let Value::Object(map) = record else {
        return None;
    };
    let id = map
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let kept: Map<String, Value> = map
        .into_iter()
        .filter(|(k, _)| !sensitive.contains(k))
        .collect();
    Some((id, Value::Object(kept)))
}

fn query_id(entity: &OfflineEntity) -> Option<Uuid> {
    entity
        .stored_query
        .as_deref()
        .and_then(|q| Uuid::parse_str(q.trim()).ok())
}

fn is_missing_modified_at(e: &AppError) -> bool {
    matches!(e, AppError::Validation(m) if m.contains("modified_at"))
}

/// One page of `entity` after `cursor`, falling back to a full read when the
/// query has no `modified_at`. The rows and the next keyset id.
async fn page(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &OfflineEntity,
    cursor: &mut EntityCursor,
) -> Result<(Vec<Value>, Option<Uuid>), AppError> {
    let run = |full: bool, after: Option<Uuid>, since: Option<DateTime<Utc>>| {
        ExecuteQueryRequest::for_offline_pull(
            entity.entity.clone(),
            query_id(entity),
            if full { None } else { since },
            !full,
            PULL_PAGE,
            after,
            false,
        )
    };
    let response = match execute_stored_query(
        state,
        ctx,
        run(cursor.full, cursor.after, cursor.since),
    )
    .await
    {
        Err(e) if !cursor.full && is_missing_modified_at(&e) => {
            cursor.full = true;
            cursor.after = None;
            execute_stored_query(state, ctx, run(true, None, None)).await?
        }
        other => other?,
    };
    let page = response.into_cursor_page();
    let next = page
        .next_cursor
        .as_deref()
        .and_then(|c| Uuid::parse_str(c).ok());
    Ok((page.items, next))
}

/// Every id of `entity` the caller can read now, through the same query.
async fn readable_ids(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &OfflineEntity,
) -> Result<HashSet<Uuid>, AppError> {
    let mut out = HashSet::new();
    let mut after = None;
    loop {
        let request = ExecuteQueryRequest::for_offline_pull(
            entity.entity.clone(),
            query_id(entity),
            None,
            false,
            ID_PAGE,
            after,
            true,
        );
        let page = execute_stored_query(state, ctx, request)
            .await?
            .into_cursor_page();
        for row in &page.items {
            if let Some(id) = row
                .get("id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                out.insert(id);
            }
        }
        match page
            .next_cursor
            .as_deref()
            .and_then(|c| Uuid::parse_str(c).ok())
        {
            Some(next) => after = Some(next),
            None => return Ok(out),
        }
    }
}

/// One pull for the caller's device.
pub async fn pull(
    state: &EngineState,
    ctx: &SecurityContext,
    device_id: Uuid,
) -> Result<PullResult, AppError> {
    let db = &state.base.db;
    let device: Option<bool> = sqlx::query_scalar(
        "SELECT wipe_requested_at IS NOT NULL AND wiped_at IS NULL \
           FROM user_device WHERE id = $1 AND user_id = $2",
    )
    .bind(device_id)
    .bind(ctx.user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match device {
        None => return Err(AppError::NotFound),
        // A device told to wipe gets nothing more.
        Some(true) => return Err(AppError::Forbidden),
        Some(false) => {}
    }
    let profile: OfflineProfile = crate::profile::resolve(state, ctx)
        .await?
        .ok_or(AppError::NotFound)?;

    let saved: Option<(Uuid, Value, bool)> = sqlx::query_as(
        "SELECT profile_id, cursor, force_refresh FROM offline_device_state WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let restart = saved
        .as_ref()
        .is_none_or(|(profile_id, _, force)| *profile_id != profile.id || *force);
    let mut cursor: DeviceCursor = match (&saved, restart) {
        (Some((_, value, _)), false) => serde_json::from_value(value.clone()).unwrap_or_default(),
        _ => DeviceCursor::default(),
    };

    let mut upserts = Vec::new();
    let mut removals = Vec::new();
    let mut kept: Vec<(String, Uuid)> = Vec::new();
    let mut dropped: Vec<(String, Uuid)> = Vec::new();

    // Entities no longer in the profile leave the device.
    let in_profile: Vec<String> = profile.entities.iter().map(|e| e.entity.clone()).collect();
    if !restart {
        let gone: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT entity, record_id FROM offline_manifest \
              WHERE device_id = $1 AND NOT (entity = ANY($2)) LIMIT $3",
        )
        .bind(device_id)
        .bind(&in_profile)
        .bind(MAX_DROPPED)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        dropped.extend(gone);
    }
    cursor.entities.retain(|name, _| in_profile.contains(name));
    cursor.round.retain(|name| in_profile.contains(name));

    let now = Utc::now();
    let mut done = false;
    loop {
        let Some(entity) = next_entity(&profile.entities, &cursor.round) else {
            // The round is complete: the next pull starts another.
            cursor.round.clear();
            done = true;
            break;
        };
        let sensitive: HashSet<String> = state
            .entities
            .load()
            .get(&entity.entity)
            .map(|m| {
                m.attrs
                    .iter()
                    .filter(|a| a.is_read_gated())
                    .map(|a| a.logicalname.clone())
                    .collect()
            })
            .unwrap_or_default();
        let entry = cursor.entities.entry(entity.entity.clone()).or_default();
        entry.begin(now);
        let (rows, next) = page(state, ctx, entity, entry).await?;
        let sent = rows.len();
        for row in rows {
            if let Some((id, record)) = strip(row, &sensitive) {
                kept.push((entity.entity.clone(), id));
                upserts.push(PulledRecord {
                    entity: entity.entity.clone(),
                    record,
                });
            }
        }
        if let Some(next) = next {
            entry.after = Some(next);
            break;
        }
        // The generation ends: what the device holds but may no longer have.
        let readable = readable_ids(state, ctx, entity).await?;
        let manifest: Vec<Uuid> = sqlx::query_scalar(
            "SELECT record_id FROM offline_manifest WHERE device_id = $1 AND entity = $2",
        )
        .bind(device_id)
        .bind(&entity.entity)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let manifest: Vec<Uuid> = if restart { Vec::new() } else { manifest };
        for id in lost(&manifest, &readable) {
            dropped.push((entity.entity.clone(), id));
        }
        if let Some(entry) = cursor.entities.get_mut(&entity.entity) {
            entry.finish();
        }
        cursor.round.push(entity.entity.clone());
        if sent > 0 {
            break;
        }
    }

    let mut tx = attome_db::tx::begin(db).await?;
    if restart {
        sqlx::query("DELETE FROM offline_manifest WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    for (entity, id) in &dropped {
        sqlx::query(
            "DELETE FROM offline_manifest WHERE device_id = $1 AND entity = $2 AND record_id = $3",
        )
        .bind(device_id)
        .bind(entity)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        removals.push(Removal {
            entity: entity.clone(),
            id: *id,
        });
    }
    let (entities, ids): (Vec<String>, Vec<Uuid>) = kept.into_iter().unzip();
    if !ids.is_empty() {
        sqlx::query(
            "INSERT INTO offline_manifest (device_id, entity, record_id) \
             SELECT $1, e, r FROM unnest($2::text[], $3::uuid[]) AS m(e, r) \
             ON CONFLICT DO NOTHING",
        )
        .bind(device_id)
        .bind(&entities)
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "INSERT INTO offline_device_state (device_id, profile_id, cursor, last_pull_at, force_refresh) \
         VALUES ($1, $2, $3, now(), false) \
         ON CONFLICT (device_id) DO UPDATE \
            SET profile_id = EXCLUDED.profile_id, cursor = EXCLUDED.cursor, \
                last_pull_at = now(), force_refresh = false",
    )
    .bind(device_id)
    .bind(profile.id)
    .bind(serde_json::to_value(&cursor).map_err(AppError::internal)?)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    Ok(PullResult {
        upserts,
        removals,
        done,
        bundle_version: profile.bundle_version,
    })
}

/// B18-T5: the device's next page of its offline profile, with the records it
/// must drop.
#[utoipa::path(
    post,
    path = "/api/v1/offline/pull",
    tag = "offline",
    request_body = PullBody,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::UserPreference,
        None,
        "reads records through the query executor and keeps the device's own sync position"
    )))),
    responses(
        (status = 200, description = "Success", body = PullResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The device has been told to wipe itself", body = ErrorResponse),
        (status = 404, description = "Not the caller's device, or no offline profile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_pull(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<PullBody>,
) -> Result<Json<PullResult>, AppError> {
    Ok(Json(pull(&state, &ctx, body.device_id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(name: &str) -> OfflineEntity {
        OfflineEntity {
            entity: name.into(),
            stored_query: None,
            include_related: Vec::new(),
            include_files: false,
            max_rows: None,
            primary_name_attribute: None,
            attributes: Vec::new(),
            rules: Vec::new(),
            business_rules: Vec::new(),
            state_model: None,
        }
    }

    #[test]
    fn pull_generation_reads_from_the_previous_start() {
        let t0 = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        let t1 = DateTime::<Utc>::from_timestamp(2_000, 0).unwrap();
        let mut c = EntityCursor::default();
        c.begin(t0);
        assert_eq!(
            (c.since, c.generation_start, c.active),
            (None, Some(t0), true)
        );
        c.after = Some(Uuid::from_u128(5));
        // Resuming keeps the keyset and the start.
        c.begin(t1);
        assert_eq!(
            (c.after, c.generation_start),
            (Some(Uuid::from_u128(5)), Some(t0))
        );
        c.finish();
        assert_eq!((c.since, c.after, c.active), (Some(t0), None, false));
        c.begin(t1);
        assert_eq!((c.since, c.generation_start), (Some(t0), Some(t1)));
        // A query without modified_at keeps reading everything.
        let mut full = EntityCursor {
            full: true,
            ..EntityCursor::default()
        };
        full.begin(t0);
        full.finish();
        assert_eq!(full.since, None);
    }

    #[test]
    fn pull_rounds_visit_each_entity_once() {
        let profile = vec![entity("account"), entity("contact")];
        assert_eq!(
            next_entity(&profile, &[]).map(|e| e.entity.as_str()),
            Some("account")
        );
        assert_eq!(
            next_entity(&profile, &["account".into()]).map(|e| e.entity.as_str()),
            Some("contact")
        );
        assert!(next_entity(&profile, &["account".into(), "contact".into()]).is_none());
    }

    #[test]
    fn pull_removes_what_is_no_longer_readable_and_strips_sensitive_values() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let readable: HashSet<Uuid> = [a, c].into_iter().collect();
        assert_eq!(lost(&[a, b, c], &readable), vec![b]);
        let sensitive: HashSet<String> = ["salary".to_owned()].into_iter().collect();
        let (id, record) = strip(
            serde_json::json!({"id": a.to_string(), "name": "Ana", "salary": 10}),
            &sensitive,
        )
        .unwrap();
        assert_eq!(id, a);
        assert_eq!(
            record,
            serde_json::json!({"id": a.to_string(), "name": "Ana"})
        );
        assert!(strip(serde_json::json!({"name": "no id"}), &sensitive).is_none());
    }

    #[test]
    fn pull_cursor_survives_a_round_trip() {
        let mut cursor = DeviceCursor::default();
        cursor.entities.insert(
            "account".into(),
            EntityCursor {
                active: true,
                after: Some(Uuid::from_u128(9)),
                ..Default::default()
            },
        );
        cursor.round.push("contact".into());
        let back: DeviceCursor =
            serde_json::from_value(serde_json::to_value(&cursor).unwrap()).unwrap();
        assert_eq!(back, cursor);
    }
}

//! Z1-T8: the secret inventory over time (`secret_inventory`, migration
//! 0120). Each start records every secret that is set, with each of its key
//! ids, so the table knows when a key was first seen and since when it has
//! been the active one; a new active key id is a rotation. Administrators
//! list the inventory (`config_admin`), and a daily job reminds them of a
//! secret older than `security.secret_max_age_days`.
//!
//! No value, hash or fragment of a secret is ever stored or returned: the
//! rows hold the secret's configuration path and its operator-chosen key ids.
//! A plain secret (not a key ring) is recorded under the empty key id; its
//! age runs from when it was first set, since a changed value cannot be told
//! apart without keeping something derived from it.

use attome_config::secret_inventory::SecretState;
use attome_db::DbPool;
use attome_types::{AppError, PageWindow, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

/// The key id a plain secret is recorded under.
const PLAIN_KEY_ID: &str = "";

/// One secret, as an administrator sees it. There is no value field.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SecretInventoryRow {
    /// The configuration path, e.g. `auth.jwt_secret` or
    /// `oidc.providers.okta.client_secret`.
    pub name: String,
    /// The features that use it.
    pub used_by: Vec<String>,
    /// `key_ring` (a new key is added beside the old ones) or `replace`.
    pub rotation: String,
    /// Whether this node is configured with it.
    pub set: bool,
    /// A key ring's key ids; empty for a plain secret.
    pub key_ids: Vec<String>,
    /// A key ring's active key id.
    pub active_key_id: Option<String>,
    /// Since when the active key (or the plain secret) has been in use, as
    /// far as the recorded starts show.
    pub active_since: Option<DateTime<Utc>>,
    /// Whole days since `active_since`.
    pub age_days: Option<i64>,
    /// Older than `security.secret_max_age_days`.
    pub over_age: bool,
}

/// A secret older than the limit whose reminder this call claimed.
#[derive(Debug, Clone)]
pub struct DueSecret {
    pub name: String,
    pub used_by: &'static [&'static str],
    pub age_days: i64,
}

/// The key id under which `state`'s active material is recorded.
fn active_key(state: &SecretState) -> &str {
    state.active_key_id.as_deref().unwrap_or(PLAIN_KEY_ID)
}

/// Records this start's secrets: one row per (secret, key id) that is set,
/// `last_seen_at` refreshed, `active_since` stamped when a key becomes the
/// active one and cleared when it stops being so. One statement.
pub async fn record_boot(db: &DbPool, states: &[SecretState]) -> Result<u64, AppError> {
    let mut names = Vec::new();
    let mut key_ids = Vec::new();
    let mut actives = Vec::new();
    for state in states.iter().filter(|state| state.set) {
        if state.key_ids.is_empty() {
            names.push(state.name.clone());
            key_ids.push(PLAIN_KEY_ID.to_owned());
            actives.push(true);
        }
        for key_id in &state.key_ids {
            names.push(state.name.clone());
            key_ids.push(key_id.clone());
            actives.push(state.active_key_id.as_deref() == Some(key_id.as_str()));
        }
    }
    if names.is_empty() {
        return Ok(0);
    }
    let done = sqlx::query(
        "INSERT INTO secret_inventory (name, key_id, active_since) \
         SELECT name, key_id, CASE WHEN active THEN now() END \
         FROM UNNEST($1::text[], $2::text[], $3::bool[]) AS t(name, key_id, active) \
         ON CONFLICT (name, key_id) DO UPDATE SET \
             last_seen_at = now(), \
             active_since = CASE WHEN EXCLUDED.active_since IS NULL THEN NULL \
                                 ELSE COALESCE(secret_inventory.active_since, now()) END",
    )
    .bind(&names)
    .bind(&key_ids)
    .bind(&actives)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// The inventory this node is configured with, by name, with each active
/// key's recorded age.
pub async fn list(
    db: &DbPool,
    states: &[SecretState],
    max_age_days: u32,
    window: PageWindow,
) -> Result<PaginatedResponse<SecretInventoryRow>, AppError> {
    let mut states: Vec<&SecretState> = states.iter().collect();
    states.sort_by(|a, b| a.name.cmp(&b.name));
    let total = i64::try_from(states.len()).unwrap_or(i64::MAX);
    let offset = usize::try_from(window.offset).unwrap_or(usize::MAX);
    let size = usize::try_from(window.page_size).unwrap_or(0);
    let page: Vec<&SecretState> = states.into_iter().skip(offset).take(size).collect();

    let names: Vec<String> = page.iter().map(|state| state.name.clone()).collect();
    let keys: Vec<String> = page
        .iter()
        .map(|state| active_key(state).to_owned())
        .collect();
    let since: Vec<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT s.name, s.key_id, COALESCE(s.active_since, s.first_seen_at) \
         FROM secret_inventory s \
         JOIN UNNEST($1::text[], $2::text[]) AS t(name, key_id) \
           ON s.name = t.name AND s.key_id = t.key_id",
    )
    .bind(&names)
    .bind(&keys)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let now = Utc::now();
    let items = page
        .into_iter()
        .map(|state| {
            let active_since = state.set.then(|| {
                since
                    .iter()
                    .find(|(name, key, _)| *name == state.name && key == active_key(state))
                    .map(|(_, _, at)| *at)
            });
            let active_since = active_since.flatten();
            let age_days = active_since.map(|at| (now - at).num_days());
            SecretInventoryRow {
                name: state.name.clone(),
                used_by: state.used_by.iter().map(|u| (*u).to_owned()).collect(),
                rotation: state.rotation.as_str().to_owned(),
                set: state.set,
                key_ids: state.key_ids.clone(),
                active_key_id: state.active_key_id.clone(),
                active_since,
                age_days,
                over_age: max_age_days > 0
                    && age_days.is_some_and(|days| days > i64::from(max_age_days)),
            }
        })
        .collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// The secrets older than `max_age_days` not reminded of in the last 30
/// days, each claimed in the same statement (`reminded_at`), so two workers
/// never remind twice. `max_age_days = 0` turns the reminder off.
pub async fn claim_due_reminders(
    db: &DbPool,
    states: &[SecretState],
    max_age_days: u32,
) -> Result<Vec<DueSecret>, AppError> {
    if max_age_days == 0 {
        return Ok(Vec::new());
    }
    let set: Vec<&SecretState> = states.iter().filter(|state| state.set).collect();
    if set.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<String> = set.iter().map(|state| state.name.clone()).collect();
    let keys: Vec<String> = set
        .iter()
        .map(|state| active_key(state).to_owned())
        .collect();
    let days = i32::try_from(max_age_days).unwrap_or(i32::MAX);
    let claimed: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE secret_inventory s SET reminded_at = now() \
         FROM UNNEST($1::text[], $2::text[]) AS t(name, key_id) \
         WHERE s.name = t.name AND s.key_id = t.key_id \
           AND COALESCE(s.active_since, s.first_seen_at) < now() - make_interval(days => $3) \
           AND (s.reminded_at IS NULL OR s.reminded_at < now() - interval '30 days') \
         RETURNING s.name, COALESCE(s.active_since, s.first_seen_at)",
    )
    .bind(&names)
    .bind(&keys)
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    Ok(claimed
        .into_iter()
        .filter_map(|(name, since)| {
            let state = set.iter().find(|state| state.name == name)?;
            Some(DueSecret {
                name,
                used_by: state.used_by,
                age_days: (now - since).num_days(),
            })
        })
        .collect())
}

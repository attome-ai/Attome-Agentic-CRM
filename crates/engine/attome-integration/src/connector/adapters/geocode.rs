//! B15-T1: addresses get coordinates in the background. A change-feed
//! consumer (`geocode`, the D-358 cursor model) watches the entities the
//! `geocode.targets` setting names; when a record's address attributes
//! change, it looks the address up on the provider `geocode.base_url` names
//! (a self-hosted Nominatim, or any service answering Nominatim's
//! `/search?format=jsonv2` shape) and writes the point to the target's
//! geolocation attribute through the generic update path, as the record's
//! owner (validation, audit, row version and the change feed apply).
//!
//! Answers are cached by normalised address in `geocode_cache` (migration
//! 0327), so an address is asked for once whatever records carry it; an
//! address the provider does not know is cached too, as no point. With no
//! provider set the consumer does nothing. The call goes through the
//! SSRF-guarded client; a self-hosted provider on a private address needs
//! that address allowed for outbound calls.
//!
//! The coordinates the consumer writes change only the location attribute,
//! so the event they cause names no address attribute and is skipped: no
//! loop.

use attome_core::{EngineState, quote_ident};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::connector::sdk::{GuardedTransport, Request, Transport};

/// The setting naming the provider's base URL; empty is off.
pub const BASE_URL_SETTING: &str = "geocode.base_url";
/// The setting naming which attributes of which entities are geocoded.
pub const TARGETS_SETTING: &str = "geocode.targets";
/// The consumer's cursor name.
pub const CONSUMER: &str = "geocode";
/// Events read per batch, and batches per run.
const BATCH: i64 = 200;
const MAX_BATCHES: usize = 10;
/// Provider calls one run makes at most; the rest wait for the next run.
const MAX_LOOKUPS: usize = 100;
const TIMEOUT_SECS: u64 = 10;

/// One entity whose address is geocoded.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Target {
    pub entity: String,
    /// The address attributes, in the order they make the address.
    pub address: Vec<String>,
    /// The geolocation attribute the point is written to.
    pub location: String,
}

/// The targets of the setting's value; malformed entries are left out. Pure.
pub fn targets_of(setting: &Value) -> Vec<Target> {
    setting
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|v| serde_json::from_value::<Target>(v.clone()).ok())
                .filter(|t| !t.address.is_empty() && !t.location.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// An address as its cache key: lower case, punctuation as spaces, runs of
/// spaces as one. Pure.
pub fn normalise(address: &str) -> String {
    address
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The address the parts make, comma-separated, empty parts left out. Pure.
pub fn address_of(parts: &[Option<String>]) -> String {
    parts
        .iter()
        .flatten()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The provider's search URL for `address`. Pure.
pub fn search_url(base_url: &str, address: &str) -> Result<String, AppError> {
    let mut url = url::Url::parse(&format!("{}/search", base_url.trim_end_matches('/')))
        .map_err(|e| AppError::Validation(format!("{BASE_URL_SETTING}: {e}")))?;
    url.query_pairs_mut()
        .append_pair("q", address)
        .append_pair("format", "jsonv2")
        .append_pair("limit", "1");
    Ok(url.into())
}

/// The first match's point, from a Nominatim answer (an array of places
/// with `lat` and `lon` as strings). Pure.
pub fn parse_point(body: &str) -> Option<(f64, f64)> {
    let answer: Value = serde_json::from_str(body).ok()?;
    let first = answer.as_array()?.first()?;
    let number = |key: &str| -> Option<f64> {
        match first.get(key)? {
            Value::String(s) => s.trim().parse().ok(),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    };
    let (lat, lng) = (number("lat")?, number("lon")?);
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lng)).then_some((lat, lng))
}

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeocodeRun {
    pub events: u64,
    pub lookups: u64,
    pub located: u64,
}

fn setting(state: &EngineState, key: &str) -> Value {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .unwrap_or(Value::Null)
}

/// The cached point of `key`: `Some(None)` for an address known to have
/// none, `None` when it was never asked for.
async fn cached(db: &attome_db::DbPool, key: &str) -> Result<Option<Option<(f64, f64)>>, AppError> {
    let row: Option<(Option<f64>, Option<f64>)> =
        sqlx::query_as("SELECT lat, lng FROM geocode_cache WHERE address_key = $1")
            .bind(key)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(row.map(|(lat, lng)| lat.zip(lng)))
}

async fn remember(
    db: &attome_db::DbPool,
    key: &str,
    point: Option<(f64, f64)>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO geocode_cache (address_key, lat, lng) VALUES ($1, $2, $3) \
         ON CONFLICT (address_key) DO UPDATE SET lat = EXCLUDED.lat, lng = EXCLUDED.lng, \
             cached_at = now()",
    )
    .bind(key)
    .bind(point.map(|p| p.0))
    .bind(point.map(|p| p.1))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The point of `address`, from the cache or the provider; a provider
/// failure is an error (the event is retried next run), an unknown address
/// is `None` and cached.
async fn locate(
    db: &attome_db::DbPool,
    transport: &dyn Transport,
    base_url: &str,
    address: &str,
    lookups: &mut u64,
) -> Result<Option<(f64, f64)>, AppError> {
    let key = normalise(address);
    if let Some(known) = cached(db, &key).await? {
        return Ok(known);
    }
    *lookups += 1;
    let answer = transport
        .send(Request {
            method: "GET".into(),
            url: search_url(base_url, address)?,
            headers: vec![
                ("Accept".into(), "application/json".into()),
                ("User-Agent".into(), "Attome geocoding".into()),
            ],
            body: None,
        })
        .await?;
    if answer.status != 200 {
        return Err(AppError::internal(format!(
            "the geocoding provider answered {}",
            answer.status
        )));
    }
    let point = parse_point(&answer.body);
    remember(db, &key, point).await?;
    Ok(point)
}

/// Geocodes one record of `target` when its address gives a point.
async fn geocode_record(
    state: &EngineState,
    transport: &dyn Transport,
    base_url: &str,
    target: &Target,
    id: Uuid,
    lookups: &mut u64,
) -> Result<bool, AppError> {
    let columns: Vec<String> = target
        .address
        .iter()
        .map(|a| format!("{}::text", quote_ident(a)))
        .collect();
    let sql = format!(
        "SELECT owner_ref, row_version, ARRAY[{}] FROM {} WHERE id = $1",
        columns.join(", "),
        quote_ident(&target.entity)
    );
    let row: Option<(Option<Uuid>, i64, Vec<Option<String>>)> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let Some((Some(owner), row_version, parts)) = row else {
        return Ok(false);
    };
    let address = address_of(&parts);
    if address.is_empty() {
        return Ok(false);
    }
    let Some((lat, lng)) = locate(&state.base.db, transport, base_url, &address, lookups).await?
    else {
        return Ok(false);
    };
    let ctx = state.base.security.resolve(owner).await?;
    let mut patch = serde_json::Map::new();
    patch.insert(target.location.clone(), json!({ "lat": lat, "lng": lng }));
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        owner,
        &target.entity,
        id,
        row_version,
        Value::Object(patch),
    )
    .await?;
    Ok(true)
}

/// One run of the `geocode` consumer.
pub async fn run(state: &EngineState) -> Result<GeocodeRun, AppError> {
    let mut out = GeocodeRun::default();
    let base_url = setting(state, BASE_URL_SETTING)
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let targets: Vec<Target> = {
        let registry = state.entities.load();
        targets_of(&setting(state, TARGETS_SETTING))
            .into_iter()
            .filter(|t| {
                registry.get(&t.entity).is_some_and(|meta| {
                    let has = |name: &str| meta.attrs.iter().any(|a| a.logicalname == name);
                    has(&t.location) && t.address.iter().all(|a| has(a))
                })
            })
            .collect()
    };
    if base_url.is_empty() || targets.is_empty() {
        return Ok(out);
    }
    let client =
        attome_server::ssrf_guard::GuardedClient::new(TIMEOUT_SECS).map_err(AppError::internal)?;
    let transport = GuardedTransport(client);
    let db = &state.base.db;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        if events.is_empty() {
            break;
        }
        // The last event handled; the cursor never passes one that was not.
        let mut last = None;
        out.events += events.len() as u64;
        let mut seen = std::collections::BTreeSet::new();
        let mut stopped = false;
        for event in &events {
            let Some(target) = targets
                .iter()
                .find(|t| t.entity == event.entity_logicalname)
            else {
                last = Some(event);
                continue;
            };
            // Only a write that touched the address (or does not say).
            let touched = event.changed_attributes.is_empty()
                || event
                    .changed_attributes
                    .iter()
                    .any(|a| target.address.contains(a));
            if touched && seen.insert(event.record_id) {
                if out.lookups >= MAX_LOOKUPS as u64 {
                    stopped = true;
                    break;
                }
                match geocode_record(
                    state,
                    &transport,
                    &base_url,
                    target,
                    event.record_id,
                    &mut out.lookups,
                )
                .await
                {
                    Ok(true) => out.located += 1,
                    Ok(false) => {}
                    // A refused write (the owner may not change the field) is
                    // logged and passed; a provider failure stops the run so
                    // the event is read again next time.
                    Err(AppError::Forbidden | AppError::Validation(_)) => {
                        tracing::warn!(entity = %target.entity, record = %event.record_id, "geocode: the point could not be written");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "geocode: run stopped, retried next time");
                        stopped = true;
                        break;
                    }
                }
            }
            last = Some(event);
        }
        if let Some(last) = last {
            let mut conn = db.acquire().await.map_err(AppError::internal)?;
            attome_core::change_feed::advance(&mut conn, CONSUMER, last).await?;
        }
        if stopped || events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geocode_normalises_the_cache_key() {
        assert_eq!(
            normalise("  King Fahd Rd., Riyadh  "),
            normalise("king fahd rd riyadh")
        );
        assert_eq!(normalise("شارع الملك فهد، الرياض"), "شارع الملك فهد الرياض");
    }

    #[test]
    fn geocode_reads_the_first_place() {
        let body = r#"[{"lat": "24.7136", "lon": "46.6753", "display_name": "Riyadh"}]"#;
        assert_eq!(parse_point(body), Some((24.7136, 46.6753)));
        assert_eq!(parse_point("[]"), None);
        assert_eq!(parse_point(r#"[{"lat": "124", "lon": "1"}]"#), None);
        assert_eq!(parse_point("not json"), None);
    }

    #[test]
    fn geocode_builds_the_address_and_url() {
        let parts = vec![
            Some("King Fahd Rd".to_owned()),
            None,
            Some(" ".to_owned()),
            Some("Riyadh".to_owned()),
        ];
        assert_eq!(address_of(&parts), "King Fahd Rd, Riyadh");
        let url = search_url("http://geo.example/", "King Fahd Rd, Riyadh").unwrap();
        assert!(url.starts_with("http://geo.example/search?q=King+Fahd+Rd%2C+Riyadh"));
        assert!(url.contains("format=jsonv2") && url.contains("limit=1"));
    }

    #[test]
    fn geocode_targets_skip_malformed_entries() {
        let setting = json!([
            {"entity": "account", "address": ["street", "city"], "location": "geo"},
            {"entity": "lead", "address": [], "location": "geo"},
            {"entity": "contact"}
        ]);
        let targets = targets_of(&setting);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].entity, "account");
    }
}

//! Live segments (roadmap E7-T6): a segment list with `refresh_mode = live`
//! follows its people as their records change, re-checking only the people
//! a change touched, never the whole segment.
//!
//! **Eligibility.** A live list's stored query may read only its target
//! entity, the consent state, and entities one lookup away from the target
//! (so "contacts in Riyadh" or "contacts of accounts in retail" stay cheap
//! to re-check). What a query reads is its published version's
//! `relations` (the relations its plan touched); a version without them
//! (a bundle-published query) is not eligible. A record validator cannot
//! read the database, so eligibility is enforced here: a live list whose
//! query is not eligible is skipped with a warning, and the scheduled
//! refresh keeps it current instead.
//!
//! **The tick** ([`live_tick`], the `marketing_segment_live` job) reads a
//! batch of the entity change feed as consumer [`CONSUMER`], maps changed
//! records to people (the record itself, or the target records whose
//! lookup points at it), runs each live list's query as its owner
//! restricted to those people, and writes the differences with one
//! membership event each (reason `live`) under the list's lock. The
//! cursor moves only after every list's writes commit; a crash re-reads
//! the batch, and re-applying it changes nothing.

use std::collections::{BTreeMap, HashSet};

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-marketing/segment_live";
/// Events read per tick.
pub const BATCH: i64 = 500;
/// People re-checked per query call (one page of the query).
const CHECK_CHUNK: usize = 200;

/// Relations any live query may read besides its target and lookups.
const ALWAYS_ALLOWED: &[&str] = &["consent_current"];

/// Whether a query that read `relations` may run live for `target`, given
/// the entities one lookup away from it. Pure.
pub fn is_live_eligible(relations: &[String], target: &str, one_lookup_away: &[String]) -> bool {
    !relations.is_empty()
        && relations.iter().any(|r| r == target)
        && relations.iter().all(|r| {
            r == target
                || ALWAYS_ALLOWED.contains(&r.as_str())
                || one_lookup_away.iter().any(|e| e == r)
        })
}

/// Changed record ids by entity, each once. Pure.
pub fn group(events: &[(String, Uuid)]) -> BTreeMap<String, Vec<Uuid>> {
    let mut out: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for (entity, id) in events {
        let ids = out.entry(entity.clone()).or_default();
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    out
}

/// The entities the target's lookups point at, with the lookup columns.
fn lookups(state: &EngineState, target: &str) -> Vec<(String, String)> {
    let registry = state.entities.load();
    let Some(meta) = registry.get(target) else {
        return Vec::new();
    };
    meta.attrs
        .iter()
        .filter_map(|a| {
            let to = registry.get_by_id(a.lookup_entity_ref?)?;
            Some((to.logicalname.clone(), a.logicalname.clone()))
        })
        .collect()
}

type LiveList = (Uuid, String, String, Option<Uuid>);

/// One tick. Returns the membership changes written.
pub async fn live_tick(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let lists: Vec<LiveList> = sqlx::query_as(
        "SELECT id, COALESCE(target_entity, 'contact'), query_id, owner_ref FROM marketing_list \
          WHERE refresh_mode = 'live' AND COALESCE(kind, 'static') = 'segment' \
            AND (is_active IS NULL OR is_active = true) AND query_id IS NOT NULL",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap_or_default();
    let changed = group(
        &events
            .iter()
            .map(|e| (e.entity_logicalname.clone(), e.record_id))
            .collect::<Vec<_>>(),
    );
    let mut written = 0;
    for (list, target, query, owner) in lists {
        let (Ok(query), Some(owner)) = (Uuid::parse_str(query.trim()), owner) else {
            continue;
        };
        match refresh_people(state, list, &target, query, owner, &changed).await {
            Ok(n) => written += n,
            Err(error) => {
                // Not advancing past a failed list: the batch is read again.
                tracing::warn!(%list, %error, "live segment: list not updated");
                return Err(error);
            }
        }
    }
    attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(written)
}

async fn refresh_people(
    state: &EngineState,
    list: Uuid,
    target: &str,
    query: Uuid,
    owner: Uuid,
    changed: &BTreeMap<String, Vec<Uuid>>,
) -> Result<usize, AppError> {
    let db = &state.base.db;
    let relations: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT relations FROM sql_query_version WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(query)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let links = lookups(state, target);
    let away: Vec<String> = links.iter().map(|(e, _)| e.clone()).collect();
    if !is_live_eligible(&relations.unwrap_or_default(), target, &away) {
        tracing::warn!(%list, "live segment: its query reads more than live allows; left to the scheduled refresh");
        return Ok(0);
    }

    // The people the batch touched.
    let mut people: HashSet<Uuid> = changed
        .get(target)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    for (entity, column) in &links {
        let Some(ids) = changed.get(entity) else {
            continue;
        };
        let found: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {} WHERE {} = ANY($1)",
            attome_core::quote_ident(target),
            attome_core::quote_ident(column)
        ))
        .bind(ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        people.extend(found);
    }
    if people.is_empty() {
        return Ok(0);
    }
    let people: Vec<Uuid> = people.into_iter().collect();

    // Who of them the query returns now, as the list's owner.
    let ctx = attome_security::resolve_uncached(db, owner).await?;
    let mut matching: HashSet<Uuid> = HashSet::new();
    for chunk in people.chunks(CHECK_CHUNK) {
        let ids: Vec<String> = chunk.iter().map(Uuid::to_string).collect();
        let request: attome_records::query_exec::ExecuteQueryRequest =
            serde_json::from_value(json!({
                "query_id": query,
                "page": 1,
                "page_size": CHECK_CHUNK,
                "include_total": true,
                "filters": [{ "field": "id", "op": "in", "value": ids }],
            }))
            .map_err(AppError::internal)?;
        let response =
            attome_records::query_exec::execute_stored_query(state, &ctx, request).await?;
        let value = serde_json::to_value(&response).map_err(AppError::internal)?;
        for row in value
            .pointer("/data/records")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                matching.insert(id);
            }
        }
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-marketing/segment_refresh:{list}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this list is being refreshed"));
    }
    let current: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT person_id FROM marketing_list_member WHERE list_id = $1 AND person_id = ANY($2)",
    )
    .bind(list)
    .bind(&people)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let (enter, leave) = crate::segment::diff(&current, &matching);
    if !enter.is_empty() {
        sqlx::query(
            "INSERT INTO marketing_list_member (list_id, person_id, person_entity, source) \
             SELECT $1, p, $2, 'segment' FROM unnest($3::uuid[]) AS p \
             ON CONFLICT (list_id, person_id) DO NOTHING",
        )
        .bind(list)
        .bind(target)
        .bind(&enter)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason) \
             SELECT $1, p, 'entered', 'live' FROM unnest($2::uuid[]) AS p",
        )
        .bind(list)
        .bind(&enter)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if !leave.is_empty() {
        sqlx::query("DELETE FROM marketing_list_member WHERE list_id = $1 AND person_id = ANY($2)")
            .bind(list)
            .bind(&leave)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO marketing_list_membership_event (list_id, person_id, change, reason) \
             SELECT $1, p, 'left', 'live' FROM unnest($2::uuid[]) AS p",
        )
        .bind(list)
        .bind(&leave)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if !enter.is_empty() || !leave.is_empty() {
        sqlx::query(
            "UPDATE marketing_list SET member_count = \
                (SELECT COUNT(*) FROM marketing_list_member WHERE list_id = $1), \
                modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(list)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_named(
            &mut tx,
            "marketing_list",
            list,
            attome_core::change_feed::ChangeOperation::Update,
            "marketing.list.refreshed",
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(enter.len() + leave.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn only_target_consent_and_one_lookup_away_are_live() {
        let away = s(&["account"]);
        assert!(is_live_eligible(&s(&["contact"]), "contact", &away));
        assert!(is_live_eligible(
            &s(&["contact", "account", "consent_current"]),
            "contact",
            &away
        ));
        assert!(!is_live_eligible(
            &s(&["contact", "opportunity"]),
            "contact",
            &away
        ));
        assert!(
            !is_live_eligible(&[], "contact", &away),
            "unknown relations are not eligible"
        );
        assert!(
            !is_live_eligible(&s(&["account"]), "contact", &away),
            "must read its target"
        );
    }

    #[test]
    fn changes_group_by_entity_once() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let grouped = group(&[
            ("contact".into(), a),
            ("contact".into(), a),
            ("account".into(), b),
        ]);
        assert_eq!(grouped["contact"], vec![a]);
        assert_eq!(grouped["account"], vec![b]);
    }
}

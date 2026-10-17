//! Competitor mentions (roadmap D25-T4): [`sweep_mentions`] reads new
//! emails (`communication`) and notes (`note`) off the change feed (its own
//! cursor, `attome-sales/mention-scan`), and when one about a deal, or about
//! an account with open deals, names a tracked competitor as a whole word,
//! proposes the competitor on each such deal as a `competitor_mention`
//! (status `proposed`) with a snippet. Nothing is linked: a person confirms.
//!
//! Names are matched after [`normalize_ar`], so diacritics, letter variants
//! and case do not hide a mention. The competitor names are read from the
//! `competitor` table once per sweep (the table is the only source of truth;
//! there is no cache to invalidate, and a cold start costs one small query).
//!
//! A proposal is written as the deal's owner and only when the owner can
//! read the email or note, so no proposal shows a source its reader cannot
//! open. One proposal per source, competitor and deal, and none for a
//! competitor already on the deal, so a retried sweep adds nothing twice.

use attome_core::EngineState;
use attome_core::match_normalize::normalize_ar;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

/// The change-feed consumer.
pub const MENTION_SCAN_CONSUMER: &str = "attome-sales/mention-scan";

const SWEEP_BATCH: i64 = 200;

/// Characters of context a proposal shows.
pub const SNIPPET_CHARS: usize = 200;

/// Open deals one account's email can propose on.
const DEALS_PER_SOURCE: i64 = 50;

/// A tracked competitor's normalised names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompetitorNames {
    pub id: Uuid,
    pub names: Vec<String>,
}

impl CompetitorNames {
    /// From a competitor's name and Arabic name; names shorter than two
    /// characters are dropped (they would match everywhere).
    pub fn new(id: Uuid, name: Option<&str>, name_ar: Option<&str>) -> Self {
        let mut names: Vec<String> = [name, name_ar]
            .into_iter()
            .flatten()
            .map(normalize_ar)
            .filter(|n| n.chars().count() >= 2)
            .collect();
        names.dedup();
        Self { id, names }
    }
}

/// Where `needle` occurs in `hay` as a whole word: the char offset of the
/// first such occurrence. Both are already normalised.
pub fn whole_word_at(hay: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric());
        if boundary(before) && boundary(after) {
            return Some(hay[..start].chars().count());
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    None
}

/// Up to [`SNIPPET_CHARS`] of `text` centred on the char offset `at`.
pub fn snippet(text: &str, at: usize) -> String {
    let start = at.saturating_sub(SNIPPET_CHARS / 2);
    text.chars().skip(start).take(SNIPPET_CHARS).collect()
}

/// The competitors `text` names, with a snippet around the first mention.
pub fn mentions(text: &str, competitors: &[CompetitorNames]) -> Vec<(Uuid, String)> {
    let hay = normalize_ar(text);
    competitors
        .iter()
        .filter_map(|c| {
            c.names
                .iter()
                .find_map(|n| whole_word_at(&hay, n))
                .map(|at| (c.id, snippet(&hay, at)))
        })
        .collect()
}

type SourceRow = (Option<String>, Option<String>, Option<String>);

/// The text and subject record of an email or note.
async fn source_of(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<Option<(String, String, Uuid)>, AppError> {
    let sql = match entity {
        "communication" => {
            "SELECT entity_name, record_id, concat_ws(' ', subject, body) FROM communication \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
        }
        "note" => {
            "SELECT entity_name, record_id, concat_ws(' ', title, note_text) FROM note \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
        }
        _ => return Ok(None),
    };
    let row: Option<SourceRow> = sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let Some((Some(regarding), Some(record), Some(text))) = row else {
        return Ok(None);
    };
    let Ok(record) = record.trim().parse::<Uuid>() else {
        return Ok(None);
    };
    Ok(Some((regarding, text, record)))
}

/// The open deals a source is about, with their owners.
async fn deals_of(
    state: &EngineState,
    regarding: &str,
    record: Uuid,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    let column = match regarding {
        "opportunity" => "id",
        "account" => "account_ref",
        _ => return Ok(Vec::new()),
    };
    sqlx::query_as(&format!(
        "SELECT id, owner_ref FROM opportunity \
         WHERE {column} = $1 AND owner_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) \
           AND COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost') \
         ORDER BY id LIMIT $2"
    ))
    .bind(record)
    .bind(DEALS_PER_SOURCE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Proposes the competitors one email or note names; proposals written.
pub async fn scan_source(
    state: &EngineState,
    entity: &str,
    id: Uuid,
    competitors: &[CompetitorNames],
) -> Result<u64, AppError> {
    let Some((regarding, text, record)) = source_of(state, entity, id).await? else {
        return Ok(0);
    };
    let hits = mentions(&text, competitors);
    if hits.is_empty() {
        return Ok(0);
    }
    let deals = deals_of(state, &regarding, record).await?;
    let Some(source_entity) = state.entities.load().get(entity).map(|m| m.entity_id) else {
        return Ok(0);
    };
    let db = &state.base.db;
    let mut written = 0;
    for (deal, owner) in deals {
        let ctx = match state.base.security.resolve_strict(owner).await {
            Ok(ctx) => ctx,
            Err(_) => continue,
        };
        // The owner sees the proposal, so the owner must be able to read
        // the source it quotes.
        if attome_records::entity_crud::require_record_access(
            state,
            &ctx,
            source_entity,
            entity,
            id,
            attome_security::RecordAction::Read,
        )
        .await
        .is_err()
        {
            continue;
        }
        for (competitor, snip) in &hits {
            let known: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM opportunity_competitor \
                     WHERE opportunity_ref = $1 AND competitor_ref = $2 \
                       AND (is_active IS NULL OR is_active = true)) \
                 OR EXISTS (SELECT 1 FROM competitor_mention \
                     WHERE opportunity_ref = $1 AND competitor_ref = $2 \
                       AND source_entity = $3 AND source_id = $4)",
            )
            .bind(deal)
            .bind(competitor)
            .bind(entity)
            .bind(id.to_string())
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if known {
                continue;
            }
            let created = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                owner,
                "competitor_mention",
                json!({
                    "opportunity_ref": deal.to_string(),
                    "competitor_ref": competitor.to_string(),
                    "source_entity": entity,
                    "source_id": id.to_string(),
                    "snippet": snip,
                    "status": "proposed",
                }),
            )
            .await;
            match created {
                Ok(_) => written += 1,
                // An owner who may not hold proposals is skipped, never retried
                // forever by a stuck cursor.
                Err(e) => tracing::warn!(%deal, %owner, error = %e, "mention proposal skipped"),
            }
        }
    }
    Ok(written)
}

/// The tracked competitors' names.
pub async fn competitor_names(state: &EngineState) -> Result<Vec<CompetitorNames>, AppError> {
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, name, name_ar FROM competitor \
         WHERE (is_active IS NULL OR is_active = true) AND COALESCE(is_tracked, true) \
         ORDER BY id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, ar)| CompetitorNames::new(id, name.as_deref(), ar.as_deref()))
        .filter(|c| !c.names.is_empty())
        .collect())
}

/// Scans the emails and notes logged since the cursor; proposals written.
pub async fn sweep_mentions(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, MENTION_SCAN_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('competitor_mention') IS NOT NULL \
            AND to_regclass('opportunity_competitor') IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut written = 0;
    if installed {
        let sources: Vec<(String, Uuid)> = events
            .iter()
            .filter(|e| {
                matches!(e.entity_logicalname.as_str(), "communication" | "note")
                    && e.operation() == Some(attome_core::change_feed::ChangeOperation::Create)
            })
            .map(|e| (e.entity_logicalname.clone(), e.record_id))
            .collect();
        if !sources.is_empty() {
            let competitors = competitor_names(state).await?;
            if !competitors.is_empty() {
                for (entity, id) in sources {
                    written += scan_source(state, &entity, id, &competitors).await?;
                }
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, MENTION_SCAN_CONSUMER, &last).await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arabic_name_matches_with_diacritics() {
        let id = Uuid::nil();
        let c = CompetitorNames::new(id, Some("Acme"), Some("أكمي"));
        // Diacritics and the hamza variant in the email still match.
        let hits = mentions(
            "نحن نقارن عرضكم مع إكْمِي هذا الأسبوع",
            std::slice::from_ref(&c),
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, id);
        // Case does not matter; part of a word does not count.
        assert_eq!(
            mentions("They also talked to ACME.", std::slice::from_ref(&c)).len(),
            1
        );
        assert!(mentions("acmerail is unrelated", &[c]).is_empty());
    }

    #[test]
    fn short_names_and_snippets_are_bounded() {
        assert!(
            CompetitorNames::new(Uuid::nil(), Some("X"), None)
                .names
                .is_empty()
        );
        let long = "a ".repeat(400) + "rival " + &"b ".repeat(400);
        let at = whole_word_at(&long, "rival").unwrap_or_default();
        let s = snippet(&long, at);
        assert_eq!(s.chars().count(), SNIPPET_CHARS);
        assert!(s.contains("rival"));
    }
}

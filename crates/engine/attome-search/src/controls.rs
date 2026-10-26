//! A25-T3: what an administrator tunes about ranking, applied to every full
//! search after the permission filter.
//!
//! - **Synonyms** (`search_synonym`): a group of terms that mean the same.
//!   A query holding one term also runs with each other term in its place,
//!   as extra lexical alternatives beside the glossary's (C10-T1). Terms are
//!   normalised on both sides (`normalize_ar`).
//! - **Stop words** (`search_stopword`): dropped from the query before the
//!   legs run, unless every word of the query is one.
//! - **Entity boost** (`search_entity_setting.boost`): multiplies the fused
//!   score of that entity's results. The default 1 changes nothing.
//! - **Pins** (`search_pin`): a record placed at a position for one
//!   normalised query. A pin is placed only when the caller may read the
//!   record: a pinned record already in the results passed the filter with
//!   them, and any other is read again through the same visibility fragment
//!   first, so a pin never shows a record its caller cannot see.
//! - **Personal ranking** (`search.personal_weights`): small additions for a
//!   record the caller owns, one they opened from a search in the last 30
//!   days, and one a team of theirs owns. All three are 0 by default, so a
//!   deployment turns them on. Ownership only ranks what the caller can
//!   already see; it never admits a record (D-357 ruling 2).
//!
//! The synonym, stop word, boost and pin tables are read once per process
//! into one snapshot, kept [`CONTROLS_TTL_SECS`]: its source of truth is
//! PostgreSQL, a writer drops it with [`invalidate`] on its own node and
//! other nodes wait for the TTL, a failed load is logged and leaves the
//! search untuned, and a cold node loads on its first search.
//!
//! The per-attribute weight of the matched segment is not applied: the fused
//! statement does not say which attribute matched (A25-T4's explanation adds
//! that).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use attome_cache::{HotCache, create_hot_cache, get_recorded};
use attome_db::DbPool;
use attome_types::AppError;
use serde::Deserialize;
use uuid::Uuid;

use crate::lang::normalize_ar;

/// How long a node keeps the controls snapshot.
pub const CONTROLS_TTL_SECS: u64 = 60;

/// The most synonym alternatives one query adds.
pub const MAX_ALTERNATIVES: usize = 8;

/// The `hot_cache_lookups_total{cache=...}` label.
const METRIC_NAME: &str = "search_controls";

const KEY: &str = "controls";

static CACHE: LazyLock<HotCache<Arc<Controls>>> =
    LazyLock::new(|| create_hot_cache(1, CONTROLS_TTL_SECS));

/// One fused search row: record, entity, score, matched legs, leg counts.
pub type FusedRow = (Uuid, String, f64, Vec<String>, serde_json::Value);

/// One pinned record for a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub entity: String,
    pub record_id: Uuid,
    /// 1 is the top.
    pub position: usize,
}

/// The tuning tables, normalised.
#[derive(Debug, Clone, Default)]
pub struct Controls {
    synonyms: Vec<Vec<String>>,
    stopwords: HashSet<String>,
    boosts: HashMap<String, f64>,
    pins: HashMap<String, Vec<Pin>>,
}

/// One normalised, space-joined term.
fn norm(text: &str) -> String {
    normalize_ar(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `phrase` occurs in `text` as whole words. Pure.
fn has_phrase(text: &str, phrase: &str) -> bool {
    format!(" {text} ").contains(&format!(" {phrase} "))
}

impl Controls {
    /// The snapshot from the tables' rows. Pure.
    pub fn from_rows(
        synonyms: Vec<Vec<String>>,
        stopwords: Vec<String>,
        boosts: Vec<(String, f64)>,
        pins: Vec<(String, String, Uuid, i32)>,
    ) -> Self {
        let synonyms = synonyms
            .into_iter()
            .map(|group| {
                let mut terms: Vec<String> = group
                    .iter()
                    .map(|t| norm(t))
                    .filter(|t| !t.is_empty())
                    .collect();
                terms.dedup();
                terms
            })
            .filter(|group| group.len() >= 2)
            .collect();
        let stopwords = stopwords
            .iter()
            .map(|w| norm(w))
            .filter(|w| !w.is_empty())
            .collect();
        let boosts = boosts
            .into_iter()
            .filter(|(_, b)| b.is_finite() && *b >= 0.0)
            .collect();
        let mut by_query: HashMap<String, Vec<Pin>> = HashMap::new();
        for (query, entity, record_id, position) in pins {
            by_query.entry(norm(&query)).or_default().push(Pin {
                entity,
                record_id,
                position: usize::try_from(position.max(1)).unwrap_or(1),
            });
        }
        for pins in by_query.values_mut() {
            pins.sort_by_key(|p| p.position);
        }
        Self {
            synonyms,
            stopwords,
            boosts,
            pins: by_query,
        }
    }

    /// `text` without its stop words, or `text` itself when every word is
    /// one (a query of stop words still searches). Pure.
    pub fn without_stopwords(&self, text: &str) -> String {
        if self.stopwords.is_empty() {
            return text.to_owned();
        }
        let kept: Vec<&str> = text
            .split_whitespace()
            .filter(|w| !self.stopwords.contains(&norm(w)))
            .collect();
        if kept.is_empty() {
            text.to_owned()
        } else {
            kept.join(" ")
        }
    }

    /// The query with one synonym in place of each term it holds, at most
    /// [`MAX_ALTERNATIVES`], never the query itself. Pure.
    pub fn alternatives(&self, normalized: &str) -> Vec<String> {
        let query = norm(normalized);
        let mut out: Vec<String> = Vec::new();
        for group in &self.synonyms {
            for term in group.iter().filter(|t| has_phrase(&query, t)) {
                for other in group.iter().filter(|o| *o != term) {
                    let padded = format!(" {query} ").replacen(
                        &format!(" {term} "),
                        &format!(" {other} "),
                        1,
                    );
                    let alt = padded.trim().to_owned();
                    if alt != query && !out.contains(&alt) {
                        out.push(alt);
                    }
                    if out.len() >= MAX_ALTERNATIVES {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// The boost of `entity`'s results (1 unless set). Pure.
    pub fn boost(&self, entity: &str) -> f64 {
        self.boosts.get(entity).copied().unwrap_or(1.0)
    }

    /// The pins of a query. Pure.
    pub fn pins_for(&self, normalized: &str) -> &[Pin] {
        self.pins.get(&norm(normalized)).map_or(&[], Vec::as_slice)
    }

    /// Whether any pin exists, so a search can skip the pin read. Pure.
    pub fn has_pins(&self) -> bool {
        !self.pins.is_empty()
    }
}

/// The controls snapshot, from this node's cache or the tables.
pub async fn load(db: &DbPool) -> Result<Arc<Controls>, AppError> {
    if let Some(cached) = get_recorded(&CACHE, KEY, METRIC_NAME).await {
        return Ok(cached);
    }
    let synonyms: Vec<Vec<String>> = sqlx::query_scalar("SELECT terms FROM search_synonym")
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let stopwords: Vec<String> = sqlx::query_scalar("SELECT word FROM search_stopword")
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let boosts: Vec<(String, f32)> = sqlx::query_as(
        "SELECT entity_logicalname, boost FROM search_entity_setting WHERE boost <> 1",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let pins: Vec<(String, String, Uuid, i32)> = sqlx::query_as(
        "SELECT query_norm, entity_logicalname, record_id, position FROM search_pin",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let controls = Arc::new(Controls::from_rows(
        synonyms,
        stopwords,
        boosts.into_iter().map(|(e, b)| (e, f64::from(b))).collect(),
        pins,
    ));
    CACHE.insert(KEY.to_owned(), Arc::clone(&controls)).await;
    Ok(controls)
}

/// Drops this node's snapshot; a writer of the tables calls it (A25-T9).
pub fn invalidate() {
    CACHE.invalidate_all();
}

/// `search.personal_weights`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
pub struct PersonalWeights {
    /// Added for a record the caller owns.
    #[serde(default)]
    pub owner: f64,
    /// Added for a record the caller opened from a search in the last 30 days.
    #[serde(default)]
    pub opened: f64,
    /// Added for a record a team of the caller's owns.
    #[serde(default)]
    pub team: f64,
}

impl PersonalWeights {
    /// The weights a setting value names; anything malformed is all zero.
    pub fn from_setting(value: &serde_json::Value) -> Self {
        let weights: Self = serde_json::from_value(value.clone()).unwrap_or_default();
        let clean = |w: f64| {
            if w.is_finite() {
                w.clamp(0.0, 1.0)
            } else {
                0.0
            }
        };
        Self {
            owner: clean(weights.owner),
            opened: clean(weights.opened),
            team: clean(weights.team),
        }
    }

    pub fn is_off(&self) -> bool {
        self.owner == 0.0 && self.opened == 0.0 && self.team == 0.0
    }
}

/// What the caller has to do with each candidate, for personal ranking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Personal {
    pub owned: bool,
    pub opened: bool,
    pub team_owned: bool,
}

/// Re-scores and re-sorts `rows`: each score times its entity's boost, plus
/// the personal additions; ties keep their order. Pure.
pub fn rerank(
    rows: &mut [FusedRow],
    controls: &Controls,
    weights: PersonalWeights,
    personal: &HashMap<(String, Uuid), Personal>,
) {
    for row in rows.iter_mut() {
        let mut score = row.2 * controls.boost(&row.1);
        if let Some(p) = personal.get(&(row.1.clone(), row.0)) {
            if p.owned {
                score += weights.owner;
            }
            if p.opened {
                score += weights.opened;
            }
            if p.team_owned {
                score += weights.team;
            }
        }
        row.2 = score;
    }
    rows.sort_by(|a, b| b.2.total_cmp(&a.2));
}

/// Places each pin at its position (1-based, past the end means last),
/// lifting it out of the rows first when it is already there. `visible`
/// names the pins the caller may read; any other is left out. Pure.
pub fn place_pins(rows: &mut Vec<FusedRow>, pins: &[Pin], visible: &HashSet<(String, Uuid)>) {
    for pin in pins {
        let key = (pin.entity.clone(), pin.record_id);
        if !visible.contains(&key) {
            continue;
        }
        let existing = rows
            .iter()
            .position(|r| r.0 == pin.record_id && r.1 == pin.entity);
        let row = match existing {
            Some(i) => rows.remove(i),
            None => (
                pin.record_id,
                pin.entity.clone(),
                rows.first().map_or(1.0, |r| r.2),
                vec!["pin".to_owned()],
                serde_json::Value::Null,
            ),
        };
        let at = pin.position.saturating_sub(1).min(rows.len());
        rows.insert(at, row);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(entity: &str, id: Uuid, score: f64) -> FusedRow {
        (
            id,
            entity.to_owned(),
            score,
            vec![],
            serde_json::Value::Null,
        )
    }

    #[test]
    fn a_synonym_widens_the_query_both_ways() {
        let controls = Controls::from_rows(
            vec![vec!["CR".into(), "Commercial Registration".into()]],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(
            controls.alternatives("cr 1010"),
            ["commercial registration 1010"]
        );
        assert_eq!(controls.alternatives("commercial registration"), ["cr"]);
        assert!(
            controls.alternatives("crane").is_empty(),
            "whole words only"
        );
    }

    #[test]
    fn stop_words_drop_unless_they_are_the_whole_query() {
        let controls = Controls::from_rows(vec![], vec!["the".into(), "في".into()], vec![], vec![]);
        assert_eq!(
            controls.without_stopwords("the acme invoice"),
            "acme invoice"
        );
        assert_eq!(
            controls.without_stopwords("فاتورة في الرياض"),
            "فاتورة الرياض"
        );
        assert_eq!(controls.without_stopwords("the"), "the");
    }

    #[test]
    fn boosts_and_personal_weights_reorder_results() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let controls = Controls::from_rows(vec![], vec![], vec![("account".into(), 2.0)], vec![]);
        let mut rows = vec![
            row("contact", a, 0.5),
            row("account", b, 0.3),
            row("contact", c, 0.4),
        ];
        let personal = HashMap::from([(
            ("contact".to_owned(), c),
            Personal {
                owned: true,
                ..Personal::default()
            },
        )]);
        let weights = PersonalWeights::from_setting(&serde_json::json!({"owner": 0.25}));
        rerank(&mut rows, &controls, weights, &personal);
        let order: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
        assert_eq!(order, [c, b, a], "0.65 owned, 0.6 boosted, 0.5");
        assert!(PersonalWeights::from_setting(&serde_json::json!("bad")).is_off());
    }

    #[test]
    fn pin_hidden_from_unauthorized_is_left_out() {
        let (a, b, hidden, shown) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let controls = Controls::from_rows(
            vec![],
            vec![],
            vec![],
            vec![
                ("Price List".into(), "doc".into(), hidden, 1),
                ("price list".into(), "doc".into(), shown, 2),
            ],
        );
        let mut rows = vec![row("doc", a, 0.9), row("doc", b, 0.8)];
        let visible = HashSet::from([("doc".to_owned(), shown)]);
        place_pins(&mut rows, controls.pins_for("price  list"), &visible);
        let order: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
        assert_eq!(order, [a, shown, b], "the unreadable pin never appears");
    }
}

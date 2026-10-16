//! A15-T4: the duplicate check before a record is saved. Every active match
//! rule of the entity whose `on_save` is not `off` turns the record's values
//! into keys (`phone`, `email`, `id`, `name`, `phonetic` fields;
//! `attome_core::match_normalize`) and looks them up in `match_key`, the
//! keys the sweep and scans keep for the stored records. A live record that
//! scores at or over the rule's threshold (`attome_core::match_rule::
//! weighted_score`, the sweep's formula, over the key fields with evidence
//! on both sides) is a match. The caller sees only the matches it may read;
//! the others are a count. What the save then does is the strictest
//! `on_save` among the rules that matched: `warn` (the response lists them),
//! `allow_with_reason` (refused unless the request gives
//! `Attome-Duplicate-Reason`, which the audit keeps) or `block` (refused,
//! `409 duplicate_detected`).
//!
//! Non-key comparators (exact, normalized, trigram) are left to the sweep:
//! they have no stored key to look up before the record exists.

use attome_core::match_rule::{MatchField, OnSave, weighted_score};
use attome_core::{EngineState, quote_ident};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most candidate records one rule looks at.
const MAX_CANDIDATES: i64 = 20;

/// One existing record a save matches.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DuplicateMatch {
    pub record_id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    /// The rule's score for the pair, 0 to 1.
    pub score: f64,
}

/// What the check found.
#[derive(Debug, Default)]
pub struct DuplicateOutcome {
    /// The strictest `on_save` among the rules that matched.
    pub action: Option<OnSave>,
    /// The matches the caller may read.
    pub visible: Vec<DuplicateMatch>,
    /// How many matches the caller may not read.
    pub hidden: i64,
}

/// A record value as a key reads it.
fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The match keys of `values` for one rule: `(field, key)` per key field.
fn keys_of(fields: &[MatchField], values: &Map<String, Value>) -> Vec<(MatchField, String)> {
    fields
        .iter()
        .filter(|f| f.comparator.is_key())
        .filter_map(|f| {
            let value = values.get(&f.field).and_then(value_text)?;
            f.key_of(&value).map(|key| (f.clone(), key))
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    name: String,
    fields: Value,
    threshold: f64,
    on_save: String,
}

/// Finds the stored records `values` would duplicate (see the module doc).
/// `record_id` is the record being updated, never its own duplicate.
pub async fn check(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
    values: &Map<String, Value>,
) -> Result<DuplicateOutcome, AppError> {
    if skipped() {
        return Ok(DuplicateOutcome::default());
    }
    find(state, ctx, entity_id, entity_name, record_id, values, true).await
}

/// A15-T9: the same search under every active rule of the entity, whatever
/// its `on_save` — what a flow's "if a duplicate exists" step asks.
pub async fn find_any(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
    values: &Map<String, Value>,
) -> Result<DuplicateOutcome, AppError> {
    find(state, ctx, entity_id, entity_name, record_id, values, false).await
}

async fn find(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
    values: &Map<String, Value>,
    on_save_rules_only: bool,
) -> Result<DuplicateOutcome, AppError> {
    let db = &state.base.db;
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, name, fields, threshold::float8 AS threshold, on_save FROM match_rule \
          WHERE entity_logicalname = $1 AND is_active AND NOT is_deleted \
            AND (NOT $2 OR on_save <> 'off')",
    )
    .bind(entity_name)
    .bind(on_save_rules_only)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut outcome = DuplicateOutcome::default();
    for rule in rules {
        let fields: Vec<MatchField> = match serde_json::from_value(rule.fields) {
            Ok(fields) => fields,
            Err(e) => {
                tracing::warn!(error = %e, rule_id = %rule.id, "duplicate check: unreadable rule fields");
                continue;
            }
        };
        let keys = keys_of(&fields, values);
        if keys.is_empty() {
            continue;
        }
        let names: Vec<&str> = keys.iter().map(|(f, _)| f.field.as_str()).collect();
        let wanted: Vec<&str> = keys.iter().map(|(_, k)| k.as_str()).collect();
        let candidates: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT mk.record_id FROM match_key mk \
               JOIN unnest($2::text[], $3::text[]) AS k(field, key) \
                 ON mk.field = k.field AND mk.key = k.key \
              WHERE mk.match_rule_id = $1 AND ($4::uuid IS NULL OR mk.record_id <> $4) \
              LIMIT $5",
        )
        .bind(rule.id)
        .bind(&names)
        .bind(&wanted)
        .bind(record_id)
        .bind(MAX_CANDIDATES)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if candidates.is_empty() {
            continue;
        }
        // Keys stay after a record is deleted; only live records count.
        let live: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {} WHERE id = ANY($1) AND is_active = true",
            quote_ident(entity_name)
        ))
        .bind(&candidates)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let theirs: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT record_id, field, key FROM match_key \
              WHERE match_rule_id = $1 AND record_id = ANY($2)",
        )
        .bind(rule.id)
        .bind(&live)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let action = OnSave::parse(&rule.on_save);
        for id in live {
            let evidence: Vec<(f64, bool)> = keys
                .iter()
                .filter_map(|(field, key)| {
                    theirs
                        .iter()
                        .find(|(r, f, _)| *r == id && *f == field.field)
                        .map(|(_, _, their)| (field.weight, their == key))
                })
                .collect();
            let Some(score) = weighted_score(&evidence) else {
                continue;
            };
            if score < rule.threshold {
                continue;
            }
            match crate::entity_crud::require_record_access(
                state,
                ctx,
                entity_id,
                entity_name,
                id,
                RecordAction::Read,
            )
            .await
            {
                Ok(()) => outcome.visible.push(DuplicateMatch {
                    record_id: id,
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    score,
                }),
                Err(AppError::Forbidden | AppError::NotFound) => outcome.hidden += 1,
                Err(e) => return Err(e),
            }
            outcome.action = Some(outcome.action.map_or(action, |a| a.max(action)));
        }
    }
    Ok(outcome)
}

/// S1-T14: the outcome of a write whose request skipped the check
/// (`Attome-Duplicate-Check: skip`, privilege `duplicate.bypass`): nothing
/// matched. The write path audits the skip in its own transaction.
pub fn skipped() -> bool {
    attome_core::match_rule::duplicate_check_skipped()
}

/// Applies the outcome to the save: `Err(409 duplicate_detected)` when a
/// rule blocks it (or wants a reason and none was given), else the matches
/// to report with the saved record and how many the caller cannot see.
pub fn enforce(
    outcome: DuplicateOutcome,
    reason: Option<&str>,
) -> Result<(Vec<DuplicateMatch>, i64), AppError> {
    let refused = match outcome.action {
        None | Some(OnSave::Off) => return Ok((Vec::new(), 0)),
        Some(OnSave::Block) => true,
        Some(OnSave::AllowWithReason) => reason.is_none(),
        Some(OnSave::Warn) => false,
    };
    if refused {
        return Err(AppError::DuplicateDetected {
            matches: serde_json::to_value(&outcome.visible).map_err(AppError::internal)?,
            hidden: outcome.hidden,
        });
    }
    Ok((outcome.visible, outcome.hidden))
}

/// A15-T11: the check and its verdict for one write path, run before the
/// write's transaction opens: `Err(409 duplicate_detected)` when a rule
/// refuses the save, else the matches to report. The reason is the one the
/// request gave (`Attome-Duplicate-Reason`); a bulk or imported row carries
/// none, so a rule that wants one refuses it.
pub async fn guard(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
    values: &Map<String, Value>,
) -> Result<(Vec<DuplicateMatch>, i64), AppError> {
    let reason = attome_core::match_rule::duplicate_reason();
    enforce(
        check(state, ctx, entity_id, entity_name, record_id, values).await?,
        reason.as_deref(),
    )
}

/// After a save, writes the record's keys for every active rule of its
/// entity (the fields the write carried), so the next save sees it without
/// waiting for the sweep. A failure is logged: the sweep writes them too.
pub async fn write_match_keys(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
    values: &Map<String, Value>,
) {
    if let Err(e) = try_write_match_keys(state, entity_name, record_id, values).await {
        tracing::warn!(error = %e, %record_id, entity = %entity_name, "match keys not written after save");
    }
}

async fn try_write_match_keys(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
    values: &Map<String, Value>,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let rules: Vec<(Uuid, Value)> = sqlx::query_as(
        "SELECT id, fields FROM match_rule \
          WHERE entity_logicalname = $1 AND is_active AND NOT is_deleted",
    )
    .bind(entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (rule_id, fields) in rules {
        let Ok(fields) = serde_json::from_value::<Vec<MatchField>>(fields) else {
            continue;
        };
        for field in fields
            .iter()
            .filter(|f| f.comparator.is_key() && values.contains_key(&f.field))
        {
            let key = values
                .get(&field.field)
                .and_then(value_text)
                .and_then(|v| field.key_of(&v));
            match key {
                Some(key) => {
                    sqlx::query(
                        "INSERT INTO match_key (entity_logicalname, record_id, match_rule_id, field, key) \
                         VALUES ($1, $2, $3, $4, $5) \
                         ON CONFLICT (match_rule_id, field, record_id) DO UPDATE SET key = EXCLUDED.key",
                    )
                    .bind(entity_name)
                    .bind(record_id)
                    .bind(rule_id)
                    .bind(&field.field)
                    .bind(key)
                    .execute(db)
                    .await
                    .map_err(AppError::internal)?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM match_key WHERE match_rule_id = $1 AND field = $2 AND record_id = $3",
                    )
                    .bind(rule_id)
                    .bind(&field.field)
                    .bind(record_id)
                    .execute(db)
                    .await
                    .map_err(AppError::internal)?;
                }
            }
        }
    }
    Ok(())
}

// ── A15-T7/T8: the rule preview and the open pairs ──────────────────────────

/// The rows a rule preview reads at most.
pub const RULE_PREVIEW_SAMPLE: i64 = 5_000;
/// The example pairs a rule preview returns.
const RULE_PREVIEW_EXAMPLES: usize = 20;

/// One pair a draft rule would flag.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RulePreviewPair {
    pub record_a: Uuid,
    pub record_b: Uuid,
    pub score: f64,
}

/// What a draft rule would flag over a sample.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RulePreview {
    /// Rows read.
    pub sampled: i64,
    /// Pairs the rule would flag among them.
    pub pairs: i64,
    /// Up to 20 of them, highest score first.
    pub examples: Vec<RulePreviewPair>,
}

/// The value one field of a draft rule compares, for the preview: the key
/// for a key comparator, the trimmed lowercased text for `normalized`, the
/// text for `exact`; `trigram` is left to the sweep.
fn preview_key(field: &MatchField, value: &str) -> Option<String> {
    use attome_core::match_rule::Comparator;
    match field.comparator {
        Comparator::Exact => Some(value.to_owned()),
        Comparator::Normalized => Some(
            value
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        ),
        c if c.is_key() => field.key_of(value),
        _ => None,
    }
    .filter(|k| !k.is_empty())
}

/// A15-T7: how many pairs a draft rule (already validated) would flag over
/// the entity's first `sample` live records, with up to 20 examples. Pairs
/// are found on the fields' keys (exact, normalized and key comparators;
/// trigram fields count as no evidence) and scored as the sweep scores them.
/// Writes nothing.
pub async fn preview_rule(
    state: &EngineState,
    entity_name: &str,
    fields: &[MatchField],
    threshold: f64,
    sample: i64,
) -> Result<RulePreview, AppError> {
    let cols = fields
        .iter()
        .map(|f| {
            format!(
                "{}::text AS {}",
                quote_ident(&f.field),
                quote_ident(&f.field)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
        "SELECT t.id, (SELECT row_to_json(x) FROM (SELECT {cols}) x)::jsonb FROM {} t \
          WHERE t.is_active = true ORDER BY t.id LIMIT $1",
        quote_ident(entity_name)
    ))
    .bind(sample)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let keyed: Vec<(Uuid, Vec<Option<String>>)> = rows
        .iter()
        .map(|(id, values)| {
            let keys = fields
                .iter()
                .map(|f| {
                    values
                        .get(&f.field)
                        .and_then(Value::as_str)
                        .and_then(|v| preview_key(f, v))
                })
                .collect();
            (*id, keys)
        })
        .collect();
    // Candidate pairs share a key on at least one field.
    let mut groups: std::collections::HashMap<(usize, &str), Vec<usize>> =
        std::collections::HashMap::new();
    for (i, (_, keys)) in keyed.iter().enumerate() {
        for (f, key) in keys.iter().enumerate() {
            if let Some(key) = key {
                groups.entry((f, key.as_str())).or_default().push(i);
            }
        }
    }
    let mut seen: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    let mut found: Vec<RulePreviewPair> = Vec::new();
    for members in groups.values() {
        for (n, &i) in members.iter().enumerate() {
            for &j in &members[n + 1..] {
                let pair = (i.min(j), i.max(j));
                if !seen.insert(pair) {
                    continue;
                }
                let (a, b) = (&keyed[pair.0], &keyed[pair.1]);
                let evidence: Vec<(f64, bool)> = fields
                    .iter()
                    .enumerate()
                    .filter_map(|(f, field)| match (&a.1[f], &b.1[f]) {
                        (Some(x), Some(y)) => Some((field.weight, x == y)),
                        _ => None,
                    })
                    .collect();
                if let Some(score) = weighted_score(&evidence)
                    && score >= threshold
                {
                    found.push(RulePreviewPair {
                        record_a: a.0,
                        record_b: b.0,
                        score,
                    });
                }
            }
        }
    }
    let pairs = found.len() as i64;
    found.sort_by(|x, y| y.score.total_cmp(&x.score));
    found.truncate(RULE_PREVIEW_EXAMPLES);
    Ok(RulePreview {
        sampled: rows.len() as i64,
        pairs,
        examples: found,
    })
}

/// A15-T8: up to `limit` live records' values of `fields` (attribute names
/// the caller has resolved and may read), newest first, keeping only
/// records the caller may read — the sample a rule proposal shows a model.
pub async fn sample_values(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    fields: &[String],
    limit: i64,
) -> Result<Vec<Value>, AppError> {
    if fields.is_empty() {
        return Ok(Vec::new());
    }
    let cols = fields
        .iter()
        .map(|f| format!("{}::text AS {}", quote_ident(f), quote_ident(f)))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
        "SELECT t.id, (SELECT row_to_json(x) FROM (SELECT {cols}) x)::jsonb FROM {} t \
          WHERE t.is_active = true ORDER BY t.id DESC LIMIT $1",
        quote_ident(entity_name)
    ))
    .bind(limit.saturating_mul(2))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for (id, values) in rows {
        if out.len() as i64 >= limit {
            break;
        }
        match crate::entity_crud::require_record_access(
            state,
            ctx,
            entity_id,
            entity_name,
            id,
            RecordAction::Read,
        )
        .await
        {
            Ok(()) => out.push(values),
            Err(AppError::Forbidden | AppError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// One open duplicate pair whose records the caller may both read.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OpenDuplicatePair {
    pub candidate_id: Uuid,
    pub record_a: Uuid,
    pub record_b: Uuid,
    pub rule_id: Uuid,
    pub score: f64,
}

/// A15-T8: an entity's open duplicate pairs (or one record's), highest score
/// first, keeping only pairs whose records the caller may both read.
pub async fn list_open(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<OpenDuplicatePair>, AppError> {
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, f64)> = sqlx::query_as(
        "SELECT id, record_a, record_b, match_rule_id, score::float8 FROM duplicate_candidate \
          WHERE entity_logicalname = $1 AND status = 'open' \
            AND ($2::uuid IS NULL OR record_a = $2 OR record_b = $2) \
          ORDER BY score DESC, id LIMIT $3",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(limit.saturating_mul(4))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for (candidate_id, record_a, record_b, rule_id, score) in rows {
        if out.len() as i64 >= limit {
            break;
        }
        let mut readable = true;
        for id in [record_a, record_b] {
            match crate::entity_crud::require_record_access(
                state,
                ctx,
                entity_id,
                entity_name,
                id,
                RecordAction::Read,
            )
            .await
            {
                Ok(()) => {}
                Err(AppError::Forbidden | AppError::NotFound) => readable = false,
                Err(e) => return Err(e),
            }
        }
        if readable {
            out.push(OpenDuplicatePair {
                candidate_id,
                record_a,
                record_b,
                rule_id,
                score,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(action: OnSave) -> DuplicateOutcome {
        DuplicateOutcome {
            action: Some(action),
            visible: vec![DuplicateMatch {
                record_id: Uuid::nil(),
                rule_id: Uuid::nil(),
                rule_name: "phone".into(),
                score: 1.0,
            }],
            hidden: 1,
        }
    }

    #[test]
    fn block_and_missing_reason_refuse_warn_reports() {
        assert!(matches!(
            enforce(outcome(OnSave::Block), Some("x")),
            Err(AppError::DuplicateDetected { hidden: 1, .. })
        ));
        assert!(enforce(outcome(OnSave::AllowWithReason), None).is_err());
        let (matches, hidden) =
            enforce(outcome(OnSave::AllowWithReason), Some("twins")).unwrap_or_default();
        assert_eq!((matches.len(), hidden), (1, 1));
        let (matches, _) = enforce(outcome(OnSave::Warn), None).unwrap_or_default();
        assert_eq!(matches.len(), 1);
        let (matches, _) = enforce(DuplicateOutcome::default(), None).unwrap_or_default();
        assert!(matches.is_empty());
    }
}

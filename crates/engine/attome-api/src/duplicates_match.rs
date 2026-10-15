//! D-432 / M13 (Master Data Management, scoped to dedup + survivorship
//! only) — the matching job: `EngineJob::DataMatchSweep`'s handler.
//!
//! Reads a bounded batch off the entity-change outbox cursor
//! (`attome_core::change_feed`, consumer key [`CONSUMER`] — same
//! non-destructive per-consumer cursor model `attome_events::dispatch` already
//! uses, chosen over `attome-workflow`'s destructive `processed_at` claim
//! because this is exactly the "a second consumer added from D-358 onward"
//! case that model exists for), and for every `create`/`update`/`restore`
//! event, evaluates each of that entity's active `match_rule` rows
//! against the rest of the table, writing an `duplicate_candidate`
//! row for every peer that clears the rule's `threshold`.
//!
//! ## Comparators — what's real and what isn't (verified 2026-08-27)
//!
//! `exact` and `normalized` need no infrastructure beyond ordinary SQL.
//! `trigram` is genuine, already-shipped infrastructure: migration `0107`
//! runs `CREATE EXTENSION pg_trgm` and attome-search's `FuzzyLeg`
//! (`legs/stage1.rs`) already calls `similarity()` against it — the "M11
//! fuzzy leg" the module plan's `Depends on` line names. This module calls
//! the same `similarity()` function directly (not through attome-search's
//! `search_index`, which is a different, title-only corpus keyed to
//! search *retrieval* — a match rule compares two arbitrary records' own
//! field values instead), which needs no additional index: `similarity()` is
//! a plain SQL function once the extension exists, and a per-field GIN index
//! is a retrieval-time optimization this Phase-1 scope doesn't need. There is
//! **no** equivalent per-field embedding infrastructure — `0122_search_
//! embedding.sql` embeds the search corpus (title/body of an indexed
//! record), not arbitrary attribute values — so `embedding` is accepted at
//! the wire/schema level (`MatchField::comparator`, this module) but rejected
//! with a typed `422 Validation` at rule-save time
//! (`duplicates_admin::validate_match_fields`) rather than silently ignored
//! or ever reaching this module.
//!
//! ## Key comparators (A15-T3)
//!
//! `phone`, `email`, `id`, `name` and `phonetic` compare a normalized key
//! (`attome_core::match_normalize`: an international phone number, a
//! lowercased email, an id without separators, a name with titles dropped and
//! word order ignored, a transliteration skeleton that lets an Arabic name
//! meet its Latin spelling). Each record's key per rule and field is kept in
//! `match_key`, written when the sweep evaluates the record, so a peer is
//! compared by an index lookup instead of normalizing every row. A peer with
//! no key yet (not evaluated since the rule was saved) gives no evidence.
//! A `phone` field names the `default_country` its local numbers belong to.
//!
//! ## Scoring
//!
//! Each field is a boolean per-field indicator, not a continuous one — the
//! plan's own "trigram ≥ t" phrasing is a threshold comparator, the same
//! shape as `exact`/`normalized`, not a raw similarity score. A field where
//! either side is null contributes to neither the numerator nor the
//! denominator ("no evidence" — a rule with one field and one side null never
//! produces a candidate). The rule's score is the weighted average of every
//! field that DID have evidence:
//!
//! ```text
//! score = Σ(weight_i × indicator_i) / Σ(weight_i)   over fields with evidence
//! ```
//!
//! A candidate pair is written when `score >= rule.threshold` and at least
//! one field had evidence (an all-null comparison never matches, regardless
//! of threshold).
//!
//! ## Blocking keys (REVIEW-2026-09-02 finding #5)
//!
//! A field can be marked [`MatchField::is_blocking_key`]. When a rule has at
//! least one, the candidate peer set is first narrowed to rows that clear
//! that field's own comparator on its own terms (an exact/normalized
//! equality, or a trigram `similarity() >= min_similarity`) — the standard
//! record-linkage blocking technique: a peer can only be structurally
//! excluded if it could never have contributed a nonzero indicator on the
//! blocking field(s) in the first place, so blocking a field a true
//! duplicate pair actually agrees on never loses that pair. [`MAX_BLOCKED_
//! CANDIDATES`] is then a pure safety valve against a pathologically
//! non-selective blocking key (e.g. a near-constant column), not the primary
//! narrowing mechanism.
//!
//! **A rule with no blocking key configured scans every active peer, with no
//! cap.** Previously every rule — blocked or not — was capped at 5,000 rows
//! ordered by `id`, an arbitrary cutoff unrelated to similarity: any entity
//! over that size silently never matched a true duplicate outside the
//! sampled prefix, regardless of how similar it was. That was a correctness
//! bug, not a performance tuning knob, so the fix removes the cap entirely
//! for an unblocked rule rather than raising it — the admin's tool for
//! keeping a large entity's sweep fast is to mark a selective field as a
//! blocking key, not a platform-wide row ceiling that quietly drops matches.

use attome_core::{EngineState, change_feed, quote_ident};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// `change_consumer_cursor.consumer` key — see `attome_core::
/// change_feed`'s module doc for why this non-destructive cursor model is
/// required for any consumer added after attome-workflow's original
/// `processed_at` claim.
const CONSUMER: &str = "mdm/match-sweep";

/// Outbox events read per tick — same order of magnitude as `attome_events::
/// dispatch`'s per-subscription batch and `attome_workflow::entity_trigger`'s
/// `DISPATCH_BATCH_SIZE`.
const OUTBOX_BATCH_LIMIT: i64 = 200;

/// See this module's doc comment, "Blocking keys". Applies only when at
/// least one field is `is_blocking_key` — a safety valve on the *blocked*
/// candidate set, not the primary way this module bounds work.
const MAX_BLOCKED_CANDIDATES: i64 = 5000;

/// Candidate pairs kept per (changed record, rule) — the top-scoring peers
/// only, not every peer that cleared the threshold, so one very duplicate-y
/// record can't flood the steward queue from a single sweep tick.
const TOP_CANDIDATES_PER_RULE: i64 = 5;

/// The rule vocabulary, shared with the check before save (A15-T4).
pub(crate) use attome_core::match_rule::{Comparator, MatchField};

struct MatchRule {
    id: Uuid,
    fields: Vec<MatchField>,
    threshold: f64,
    auto_merge: bool,
}

#[derive(Default, Debug)]
pub struct MatchSweepStats {
    pub events_processed: usize,
    pub candidates_written: usize,
    pub auto_merge_submitted: usize,
}

/// A15-T6: the rows one scan page reads.
pub const MATCH_SCAN_PAGE: i64 = 500;

/// A15-T6: `EngineJob::DataMatchScan`'s handler — one page of a full scan of
/// a rule's entity: the next [`MATCH_SCAN_PAGE`] live rows after `after_id`,
/// each with its match keys written and scored against its peers (the same
/// evaluation the sweep runs on a changed record). A full page enqueues the
/// next one; a short page ends the scan and stamps the rule's
/// `last_scan_at`. A rule deleted or switched off meanwhile ends it.
pub async fn run_match_scan(
    state: &EngineState,
    rule_id: Uuid,
    after_id: Option<Uuid>,
) -> Result<MatchSweepStats, AppError> {
    let mut stats = MatchSweepStats::default();
    let row: Option<(String, Value, f64, bool)> = sqlx::query_as(
        "SELECT entity_logicalname, fields, threshold::float8, auto_merge FROM match_rule \
          WHERE id = $1 AND is_active AND NOT is_deleted",
    )
    .bind(rule_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((entity, fields_json, threshold, auto_merge)) = row else {
        return Ok(stats);
    };
    let fields: Vec<MatchField> = serde_json::from_value(fields_json)
        .map_err(|e| AppError::internal(format!("corrupt match_rule({rule_id}).fields: {e}")))?;
    let (_, entity_name, _, is_append_only) =
        attome_records::entity_crud::resolve_entity(state, &entity).await?;
    if is_append_only {
        return Ok(stats);
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {} WHERE is_active = true AND ($1::uuid IS NULL OR id > $1) \
         ORDER BY id LIMIT $2",
        quote_ident(&entity_name)
    ))
    .bind(after_id)
    .bind(MATCH_SCAN_PAGE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rules = [MatchRule {
        id: rule_id,
        fields,
        threshold,
        auto_merge,
    }];
    for id in &ids {
        evaluate_rules(state, &entity_name, *id, &rules, &mut stats).await?;
        stats.events_processed += 1;
    }
    match ids.last() {
        Some(last) if ids.len() as i64 == MATCH_SCAN_PAGE => {
            attome_jobs::enqueue_dedup(
                &state.base.db,
                attome_core::jobs::EngineJob::DataMatchScan {
                    rule_id,
                    after_id: Some(*last),
                },
                &format!("match-scan:{rule_id}:{last}"),
            )
            .await
            .map_err(AppError::internal)?;
        }
        _ => {
            sqlx::query("UPDATE match_rule SET last_scan_at = now() WHERE id = $1")
                .bind(rule_id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        }
    }
    Ok(stats)
}

/// A15-T6: starts a full scan of one rule (deduplicated: a start already
/// queued is not queued twice). `Ok(true)` when a scan was queued.
pub async fn start_match_scan(db: &attome_db::DbPool, rule_id: Uuid) -> Result<bool, AppError> {
    attome_jobs::enqueue_dedup(
        db,
        attome_core::jobs::EngineJob::DataMatchScan {
            rule_id,
            after_id: None,
        },
        &format!("match-scan:{rule_id}:start"),
    )
    .await
    .map_err(AppError::internal)
}

/// A15-T6: starts the scans whose schedule is due: a rule with
/// `scan_schedule` `hourly`, `daily` or `weekly` (with or without a leading
/// `@`) whose last scan finished longer ago than that, or never.
pub async fn start_due_scans(db: &attome_db::DbPool) -> Result<usize, AppError> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM match_rule \
          WHERE is_active AND NOT is_deleted AND scan_schedule IS NOT NULL \
            AND (CASE ltrim(lower(trim(scan_schedule)), '@') \
                   WHEN 'hourly' THEN interval '1 hour' \
                   WHEN 'daily' THEN interval '1 day' \
                   WHEN 'weekly' THEN interval '7 days' END) IS NOT NULL \
            AND (last_scan_at IS NULL OR last_scan_at < now() - \
                 (CASE ltrim(lower(trim(scan_schedule)), '@') \
                   WHEN 'hourly' THEN interval '1 hour' \
                   WHEN 'daily' THEN interval '1 day' \
                   ELSE interval '7 days' END))",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut started = 0;
    for rule_id in due {
        if start_match_scan(db, rule_id).await? {
            started += 1;
        }
    }
    Ok(started)
}

/// `EngineJob::DataMatchSweep`'s handler — see `attome_core::jobs::EngineJob::
/// DataMatchSweep`'s doc comment for the job contract.
pub async fn run_match_sweep(state: &EngineState) -> Result<MatchSweepStats, AppError> {
    // A15-T6: the scheduled full scans that are due start here, on the
    // sweep's own tick; a failure to start one never stops the sweep.
    if let Err(e) = start_due_scans(&state.base.db).await {
        tracing::warn!(error = %e, "mdm match sweep: could not start the due scans");
    }
    let mut stats = MatchSweepStats::default();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = change_feed::read_batch(&mut conn, CONSUMER, OUTBOX_BATCH_LIMIT).await?;
    if events.is_empty() {
        return Ok(stats);
    }

    // Dedup within the batch — a record touched by several events in one
    // tick (e.g. two rapid updates) is evaluated once, not once per event.
    // `delete`/`purge` are skipped: a retired record can neither be a new
    // duplicate nor usefully surface one (its candidate rows, if any, are
    // left for a steward to dismiss — this sweep does not clean those up,
    // same "propose, never silently reconcile" posture the rest of this
    // module takes).
    let mut seen = std::collections::HashSet::new();
    for event in &events {
        stats.events_processed += 1;
        let Some(op) = event.operation() else {
            continue;
        };
        if !matches!(
            op,
            change_feed::ChangeOperation::Create
                | change_feed::ChangeOperation::Update
                | change_feed::ChangeOperation::Restore
        ) {
            continue;
        }
        if !seen.insert((event.entity_logicalname.clone(), event.record_id)) {
            continue;
        }
        if let Err(e) = evaluate_record(
            state,
            &event.entity_logicalname,
            event.record_id,
            &mut stats,
        )
        .await
        {
            // One record's evaluation failing (a rule referencing a field
            // that was since removed, a transient DB error) must not stall
            // the whole sweep — same "one subscription's failure doesn't
            // stop the tick" posture `attome_events::dispatch::dispatch_pending`
            // takes for the same reason.
            tracing::warn!(
                entity = %event.entity_logicalname,
                record_id = %event.record_id,
                error = %e,
                "mdm match sweep: evaluating one record failed, continuing"
            );
        }
    }

    if let Some(last) = events.last() {
        change_feed::advance(&mut conn, CONSUMER, last).await?;
    }
    Ok(stats)
}

async fn load_active_match_rules(
    db: &attome_db::DbPool,
    entity_logicalname: &str,
) -> Result<Vec<MatchRule>, AppError> {
    let rows: Vec<(Uuid, Value, f64, bool)> = sqlx::query_as(
        "SELECT id, fields, threshold::float8, auto_merge \
           FROM match_rule \
          WHERE entity_logicalname = $1 AND is_active AND NOT is_deleted",
    )
    .bind(entity_logicalname)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut rules = Vec::with_capacity(rows.len());
    for (id, fields_json, threshold, auto_merge) in rows {
        let fields: Vec<MatchField> = serde_json::from_value(fields_json)
            .map_err(|e| AppError::internal(format!("corrupt match_rule({id}).fields: {e}")))?;
        rules.push(MatchRule {
            id,
            fields,
            threshold,
            auto_merge,
        });
    }
    Ok(rules)
}

async fn evaluate_record(
    state: &EngineState,
    entity_logicalname: &str,
    record_id: Uuid,
    stats: &mut MatchSweepStats,
) -> Result<(), AppError> {
    let rules = load_active_match_rules(&state.base.db, entity_logicalname).await?;
    evaluate_rules(state, entity_logicalname, record_id, &rules, stats).await
}

/// Evaluates `rules` (all on one entity) for one record.
async fn evaluate_rules(
    state: &EngineState,
    entity_logicalname: &str,
    record_id: Uuid,
    rules: &[MatchRule],
    stats: &mut MatchSweepStats,
) -> Result<(), AppError> {
    if rules.is_empty() {
        return Ok(());
    }
    // Validated against the live metadata registry — never trust the rule's
    // own `fields[].field` strings as identifiers without this (guidelines
    // §4: dynamic identifiers must come from validated metadata).
    let (_, entity_name, attrs, is_append_only) =
        attome_records::entity_crud::resolve_entity(state, entity_logicalname).await?;
    if is_append_only {
        return Ok(());
    }
    let known_fields: std::collections::HashSet<&str> =
        attrs.iter().map(|a| a.logicalname.as_str()).collect();
    let table = quote_ident(&entity_name);

    for rule in rules {
        // A rule naming a field that no longer exists on this entity (a
        // field was deleted after the rule was saved) is skipped for that
        // field's contribution entirely, same "degrade, don't crash the
        // sweep" posture the outer loop already takes — not a reason to
        // refuse the whole rule if other fields still resolve.
        let usable_fields: Vec<&MatchField> = rule
            .fields
            .iter()
            .filter(|f| {
                f.comparator != Comparator::Embedding && known_fields.contains(f.field.as_str())
            })
            .collect();
        if usable_fields.is_empty() {
            continue;
        }

        let target =
            match fetch_target_values(&state.base.db, &table, record_id, &usable_fields).await? {
                Some(v) => v,
                None => return Ok(()), // record no longer active/visible — nothing to match against.
            };
        // A15-T3: this record's keys first, so peers compare against them.
        upsert_match_keys(
            &state.base.db,
            &entity_name,
            rule.id,
            record_id,
            &usable_fields,
            &target,
        )
        .await?;

        let candidates = score_peers(
            &state.base.db,
            &table,
            record_id,
            rule.id,
            &usable_fields,
            &target,
            rule.threshold,
        )
        .await?;

        for (peer_id, score, field_scores) in candidates {
            let (a, b) = if record_id < peer_id {
                (record_id, peer_id)
            } else {
                (peer_id, record_id)
            };
            let low_risk = rule.auto_merge && is_low_risk(state, &entity_name, a, b).await?;
            let inserted = insert_candidate(
                &state.base.db,
                &entity_name,
                a,
                b,
                rule.id,
                score,
                low_risk,
                &field_scores,
            )
            .await?;
            if inserted {
                stats.candidates_written += 1;
                if low_risk && submit_auto_merge_request(state, &entity_name, a, b).await? {
                    stats.auto_merge_submitted += 1;
                }
            }
        }
    }
    Ok(())
}

/// Fetches `record_id`'s own value for every usable field, cast to text —
/// keeping every comparison uniformly text-typed regardless of the
/// underlying column type (same `::text` normalization
/// `data_profile_admin::profile_field` already uses for a generic per-field
/// scan). `None` when the record is missing or inactive.
async fn fetch_target_values(
    db: &attome_db::DbPool,
    table: &str,
    record_id: Uuid,
    fields: &[&MatchField],
) -> Result<Option<Map<String, Value>>, AppError> {
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
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match row {
        Some(Value::Object(obj)) => Ok(Some(obj)),
        _ => Ok(None),
    }
}

/// A15-T3: writes `record_id`'s key per key-comparator field of one rule
/// into `match_key` (removing it when the value gives none).
async fn upsert_match_keys(
    db: &attome_db::DbPool,
    entity_name: &str,
    rule_id: Uuid,
    record_id: Uuid,
    fields: &[&MatchField],
    target: &Map<String, Value>,
) -> Result<(), AppError> {
    for field in fields.iter().filter(|f| f.comparator.is_key()) {
        let key = target
            .get(&field.field)
            .and_then(Value::as_str)
            .and_then(|v| field.key_of(v));
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
    Ok(())
}

/// One SQL parameter this module builds dynamically — never a raw
/// interpolated literal (guidelines §4: bind every runtime value, including
/// admin-configured ones like a rule's `weight`/`min_similarity`, not just
/// end-user request data).
enum Bind {
    Text(Option<String>),
    Num(f64),
    Id(Uuid),
}

/// The per-field boolean-indicator SQL fragment, referencing peer column
/// `p."{field}"` and the target's own value / the field's weight / (trigram
/// only) its similarity floor as bound parameters at the given placeholder
/// positions. `NULL` (no evidence) when either side is null.
fn field_indicator_sql(
    target_placeholder: usize,
    min_sim_placeholder: usize,
    key_placeholders: (usize, usize),
    field: &MatchField,
) -> String {
    let col = quote_ident(&field.field);
    if field.comparator.is_key() {
        // A15-T3: the peer's stored key against the target's; a peer without
        // a key gives no evidence (the scalar subquery is NULL).
        let (rule_ph, field_ph) = key_placeholders;
        return format!(
            "CASE WHEN ${target_placeholder}::text IS NULL THEN NULL ELSE \
                  (SELECT CASE WHEN mk.key = ${target_placeholder}::text THEN 1.0 ELSE 0.0 END \
                     FROM match_key mk WHERE mk.match_rule_id = ${rule_ph}::uuid \
                      AND mk.field = ${field_ph}::text AND mk.record_id = p.id) END"
        );
    }
    match field.comparator {
        Comparator::Exact => format!(
            "CASE WHEN p.{col} IS NOT NULL AND ${target_placeholder}::text IS NOT NULL \
                  THEN (CASE WHEN p.{col}::text = ${target_placeholder}::text THEN 1.0 ELSE 0.0 END) \
                  ELSE NULL END"
        ),
        Comparator::Normalized => format!(
            "CASE WHEN p.{col} IS NOT NULL AND ${target_placeholder}::text IS NOT NULL \
                  THEN (CASE WHEN lower(regexp_replace(trim(both from p.{col}::text), '\\s+', ' ', 'g')) \
                             = lower(regexp_replace(trim(both from ${target_placeholder}::text), '\\s+', ' ', 'g')) \
                        THEN 1.0 ELSE 0.0 END) \
                  ELSE NULL END"
        ),
        Comparator::Trigram => format!(
            "CASE WHEN p.{col} IS NOT NULL AND ${target_placeholder}::text IS NOT NULL \
                  THEN (CASE WHEN similarity(p.{col}::text, ${target_placeholder}::text) >= ${min_sim_placeholder}::float8 \
                             THEN 1.0 ELSE 0.0 END) \
                  ELSE NULL END"
        ),
        _ => "NULL".to_owned(),
    }
}

/// The per-field blocking predicate for a field marked [`MatchField::
/// is_blocking_key`] — true only when this field's evidence could possibly
/// have contributed a nonzero indicator in [`field_indicator_sql`] (same
/// comparator, same threshold), so blocking on a field a true duplicate pair
/// agrees on never excludes that pair. SQL's own NULL propagation handles
/// "no evidence" (either side null) the same way the indicator does — no
/// explicit null guard needed here.
fn field_blocking_sql(
    target_placeholder: usize,
    min_sim_placeholder: usize,
    key_placeholders: (usize, usize),
    field: &MatchField,
) -> String {
    let col = quote_ident(&field.field);
    if field.comparator.is_key() {
        let (rule_ph, field_ph) = key_placeholders;
        return format!(
            "EXISTS (SELECT 1 FROM match_key mk WHERE mk.match_rule_id = ${rule_ph}::uuid \
                AND mk.field = ${field_ph}::text AND mk.record_id = p.id \
                AND mk.key = ${target_placeholder}::text)"
        );
    }
    match field.comparator {
        Comparator::Exact => {
            format!("p.{col}::text = ${target_placeholder}::text")
        }
        Comparator::Normalized => format!(
            "lower(regexp_replace(trim(both from p.{col}::text), '\\s+', ' ', 'g')) \
             = lower(regexp_replace(trim(both from ${target_placeholder}::text), '\\s+', ' ', 'g'))"
        ),
        Comparator::Trigram => format!(
            "similarity(p.{col}::text, ${target_placeholder}::text) >= ${min_sim_placeholder}::float8"
        ),
        _ => "FALSE".to_owned(),
    }
}

/// Scores `record_id` against its entity's other live rows — every one of
/// them if the rule has no blocking key, or only those that clear at least
/// one blocking field (up to [`MAX_BLOCKED_CANDIDATES`]) otherwise — and
/// returns the top [`TOP_CANDIDATES_PER_RULE`] that clear `threshold`,
/// highest score first. See this module's doc comment, "Blocking keys".
async fn score_peers(
    db: &attome_db::DbPool,
    table: &str,
    record_id: Uuid,
    rule_id: Uuid,
    fields: &[&MatchField],
    target: &Map<String, Value>,
    threshold: f64,
) -> Result<Vec<(Uuid, f64, Value)>, AppError> {
    let peer_cols = fields
        .iter()
        .map(|f| quote_ident(&f.field))
        .collect::<Vec<_>>()
        .join(", ");

    let mut numer_terms = Vec::with_capacity(fields.len());
    let mut denom_terms = Vec::with_capacity(fields.len());
    let mut blocking_terms = Vec::new();
    // A15-T3: each field's indicator, kept with the candidate.
    let mut score_terms = Vec::with_capacity(fields.len());
    // $1 is the excluded record id (bound below); every other runtime value
    // — target value, weight, and (trigram) similarity floor — gets its own
    // placeholder, never interpolated as a literal.
    let mut binds: Vec<Bind> = Vec::with_capacity(fields.len() * 3);
    let mut next_placeholder = 2usize;
    for field in fields {
        let target_placeholder = next_placeholder;
        next_placeholder += 1;
        let target_value = target.get(&field.field).and_then(Value::as_str);
        // A key comparator compares the target's key, not its raw value.
        binds.push(Bind::Text(if field.comparator.is_key() {
            target_value.and_then(|v| field.key_of(v))
        } else {
            target_value.map(str::to_owned)
        }));

        let weight_placeholder = next_placeholder;
        next_placeholder += 1;
        binds.push(Bind::Num(field.weight));

        // Trigram is the only comparator that reads a placeholder here;
        // every other arm ignores `min_sim_placeholder` — allocate it
        // unconditionally anyway so the placeholder numbering stays simple
        // and correct regardless of comparator mix.
        let min_sim_placeholder = next_placeholder;
        next_placeholder += 1;
        binds.push(Bind::Num(field.min_similarity.unwrap_or(0.3)));

        // A15-T3: the rule and the field name a key comparator looks up, and
        // the field name its score is kept under.
        let rule_placeholder = next_placeholder;
        next_placeholder += 1;
        binds.push(Bind::Id(rule_id));
        let field_placeholder = next_placeholder;
        next_placeholder += 1;
        binds.push(Bind::Text(Some(field.field.clone())));
        let key_placeholders = (rule_placeholder, field_placeholder);

        let indicator = field_indicator_sql(
            target_placeholder,
            min_sim_placeholder,
            key_placeholders,
            field,
        );
        score_terms.push(format!("${field_placeholder}::text, ({indicator})"));
        numer_terms.push(format!(
            "COALESCE(${weight_placeholder}::float8 * ({indicator}), 0)"
        ));
        denom_terms.push(format!(
            "(CASE WHEN ({indicator}) IS NULL THEN 0 ELSE ${weight_placeholder}::float8 END)"
        ));

        if field.is_blocking_key {
            blocking_terms.push(field_blocking_sql(
                target_placeholder,
                min_sim_placeholder,
                key_placeholders,
                field,
            ));
        }
    }
    let numer = numer_terms.join(" + ");
    let field_scores = score_terms.join(", ");
    let denom = denom_terms.join(" + ");
    let threshold_placeholder = next_placeholder;
    binds.push(Bind::Num(threshold));

    // See this module's doc comment, "Blocking keys": no blocking field
    // configured means no cap at all (correctness over speed — every active
    // peer is scored); a blocking field narrows the candidate set to rows
    // that clear it, with `MAX_BLOCKED_CANDIDATES` as a pure safety valve.
    let (candidate_filter, candidate_limit) = if blocking_terms.is_empty() {
        (String::from("TRUE"), String::new())
    } else {
        (
            format!("({})", blocking_terms.join(" OR ")),
            format!("ORDER BY id LIMIT {MAX_BLOCKED_CANDIDATES}"),
        )
    };

    let sql = format!(
        "WITH capped AS ( \
             SELECT id, {peer_cols} FROM {table} \
              WHERE is_active = true AND id <> $1 AND {candidate_filter} \
              {candidate_limit} \
         ), scored AS ( \
             SELECT p.id, ({numer}) / NULLIF({denom}, 0) AS score, \
                    jsonb_build_object({field_scores}) AS field_scores FROM capped p \
         ) \
         SELECT id, score, field_scores FROM scored \
          WHERE score IS NOT NULL AND score >= ${threshold_placeholder}::float8 \
          ORDER BY score DESC LIMIT {TOP_CANDIDATES_PER_RULE}"
    );

    let mut q = sqlx::query_as::<_, (Uuid, f64, Value)>(&sql).bind(record_id);
    for b in binds {
        q = match b {
            Bind::Text(v) => q.bind(v),
            Bind::Num(v) => q.bind(v),
            Bind::Id(v) => q.bind(v),
        };
    }
    q.fetch_all(db).await.map_err(AppError::internal)
}

/// D-432 / M13 — the auto-merge gate's other half (alongside
/// `match_rule.auto_merge`): both records must be judged safe for
/// unattended consolidation before this sweep will even *offer* it via a
/// `attome_approval` request (execution still requires a human decision either
/// way — see `admin_security_context`'s doc comment in `entity_crud::merge`).
/// "Low risk" here means neither record is depended on by any other entity's
/// lookup field — a merge that would redirect zero dependent rows can only
/// ever touch the two records it names, which bounds the blast radius of a
/// wrong auto-merge to something a steward reviewing the resulting audit
/// trail can trivially undo (re-split is not implemented, but nothing
/// *else* was silently rewritten). A record with any dependents is never
/// auto-merge-eligible, regardless of rule/score — it only ever reaches the
/// ordinary steward queue.
async fn is_low_risk(
    state: &EngineState,
    entity_name: &str,
    record_a: Uuid,
    record_b: Uuid,
) -> Result<bool, AppError> {
    let entity_id = match state.entities.load().get(entity_name) {
        Some(meta) => meta.entity_id,
        None => return Ok(false),
    };
    let dependents = state.entities.load().dependents_of(entity_id);
    if dependents.is_empty() {
        return Ok(true);
    }
    for (dep_entity, dep_field, _) in &dependents {
        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);
        let referenced: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {dep_table} WHERE {dep_field_ident} = ANY($1))"
        ))
        .bind(vec![record_a, record_b])
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if referenced {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Writes one candidate row, canonicalizing pair order (caller already
/// passes `a < b`). `ON CONFLICT DO NOTHING` on the pair's unique index
/// (migration `0218`) — a pair already recorded (in any status, including a
/// steward's prior `dismissed`) is never re-flagged, see that migration's
/// header. Returns whether a new row was actually inserted.
#[allow(clippy::too_many_arguments)]
async fn insert_candidate(
    db: &attome_db::DbPool,
    entity_name: &str,
    a: Uuid,
    b: Uuid,
    match_rule_id: Uuid,
    score: f64,
    auto_merge_eligible: bool,
    field_scores: &Value,
) -> Result<bool, AppError> {
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO duplicate_candidate \
             (entity_logicalname, record_a, record_b, match_rule_id, score, auto_merge_eligible, \
              field_scores) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (entity_logicalname, record_a, record_b) DO NOTHING \
         RETURNING id",
    )
    .bind(entity_name)
    .bind(a)
    .bind(b)
    .bind(match_rule_id)
    .bind(score as f32)
    .bind(auto_merge_eligible)
    .bind(field_scores)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(inserted.is_some())
}

/// D-432 / M13 — submits the `mdm.auto_merge` four-eyes request
/// (`attome_approval::submit`, `requested_by = attome_approval::POLICY_ACTOR_ID`
/// — the system, not a human, proposed this) for a freshly-written
/// auto-merge-eligible candidate, and records the request id back onto the
/// candidate row so the duplicates admin surface can show its status.
/// Deliberately calls `attome_approval::submit` directly rather than
/// `attome_audit::approval::gate` — `gate()` only submits a request when the
/// deployment's `approval.required_actions` config opts `mdm.auto_merge`
/// in; skipping straight to `submit` makes the four-eyes step mandatory for
/// *every* auto-merge regardless of that config, matching guidelines §7/§2:
/// no destructive automation without a human decision in the loop, ever,
/// not merely by default.
async fn submit_auto_merge_request(
    state: &EngineState,
    entity_name: &str,
    canonical_id: Uuid,
    duplicate_id: Uuid,
) -> Result<bool, AppError> {
    // Only one outstanding auto-merge request per candidate pair — a repeat
    // sweep tick that re-scores the same still-open candidate must not pile
    // up duplicate approval requests for it.
    let already_requested: bool = sqlx::query_scalar(
        "SELECT approval_request_id IS NOT NULL \
           FROM duplicate_candidate \
          WHERE entity_logicalname = $1 AND record_a = $2 AND record_b = $3",
    )
    .bind(entity_name)
    .bind(canonical_id)
    .bind(duplicate_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .unwrap_or(true);
    if already_requested {
        return Ok(false);
    }

    let payload = serde_json::json!({
        "entity": entity_name,
        "canonical_id": canonical_id,
        "duplicate_id": duplicate_id,
    });
    let request = attome_approval::submit(
        &state.base.db,
        crate::duplicates_admin::ACTION_MDM_AUTO_MERGE,
        payload,
        attome_approval::POLICY_ACTOR_ID,
        1,
        chrono::Duration::hours(72),
    )
    .await?;

    sqlx::query(
        "UPDATE duplicate_candidate SET approval_request_id = $4, row_version = row_version + 1 \
          WHERE entity_logicalname = $1 AND record_a = $2 AND record_b = $3",
    )
    .bind(entity_name)
    .bind(canonical_id)
    .bind(duplicate_id)
    .bind(request.id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

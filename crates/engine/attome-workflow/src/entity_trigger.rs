//! Entity create/update auto-start (P-workflow-engine.md §5 step 6
//! follow-up, D-267 addendum) — the entity-event trigger dispatch that was
//! originally left as a documented gap: `attome-workflow` depends on
//! `attome-records` for entity-mutation reuse, so the entity write path
//! calling directly into `attome-workflow` would be a real dependency cycle. Closed via
//! an event-outbox instead: `entity_mutation::create_one`/`update_one`
//! (crate-agnostic — every entity write, from any caller, funnels through
//! them) write a durable `entity_change_event` row in the same
//! transaction as the mutation; this module drains that outbox from the
//! one place both the entity engine and `attome-workflow` are already visible for
//! job dispatch (`crates/server/src/jobs.rs`), the same shape every other
//! cross-layer job handler in this platform already uses.
//!
//! **Delivery (M06 W1, plan §4.1, G1).** Dispatch is a D-358 change-feed
//! consumer ([`CONSUMER`]): it reads a batch after its cursor, starts and
//! resumes what each event matches, and only then advances the cursor. It
//! used to claim a batch destructively (`SET processed_at = NOW()`, committed)
//! before starting anything, so an error or crash mid-batch silently lost
//! every claimed-but-unstarted event. Now a crash re-reads from the cursor
//! (at-least-once), and a re-read is harmless: an instance start carries the
//! event id and migration 0501's unique index makes a second start a no-op
//! (`instance_admin::start_instance_for_event`), and a wait resume is a CAS on
//! `node_run.status = 'waiting'` whose wait row is deleted with it.
//!
//! A failing event stops the batch and is retried on the next run; once it
//! has failed often enough for long enough it is dead-lettered and skipped
//! ([`dispatch_pending`]), so one poison event cannot hold the feed.
//!
//! `processed_at` is still stamped, after dispatch, for three reasons:
//! `change_feed::prune` deletes only stamped rows; a pre-upgrade node still
//! running the old destructive claim during a rolling deploy skips stamped
//! rows; and an event already stamped (by that old node, or by this loop
//! before a crash that preceded the cursor advance) is skipped here rather
//! than re-evaluated.
//!
//! **Entry conditions (plan §4.2, G3).** An entry trigger may carry a
//! attome-rules `expression`; `trigger_index` folds it into the entry row's
//! `condition`. It is compiled against the watched entity's live schema
//! (cached in `EngineState::rule_compiled`, keyed by the immutable published
//! version + node) and evaluated against the record's current state before a
//! start. Anything but a clean `true` starts nothing; a compile error or an
//! unknown entity is logged at `warn` and fails closed.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeEvent};
use attome_types::AppError;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::trigger_index::EntryMatch;

const DISPATCH_BATCH_SIZE: i64 = 200;

/// This dispatcher's `change_consumer_cursor.consumer` key.
pub const CONSUMER: &str = "attome-workflow/entry";

/// Fixed, well-known system-user id for workflow instances a machine
/// trigger starts (no human requester exists to attribute them to) — the
/// `principal_ref` an entity-write node's durable idempotency key needs
/// (§4.4 mechanism 1), and the `started_by` shown in the instance monitoring
/// UI. Lazily ensured (`ensure_system_user`) rather than seeded in a
/// migration: this is workflow-owned application state, not infrastructure
/// DDL (guidelines §4's DDL-ownership split).
pub(crate) fn workflow_system_user_id() -> Uuid {
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0057_0f10_0001)
}

pub async fn ensure_system_user(db: &PgPool) -> Result<Uuid, AppError> {
    let id = workflow_system_user_id();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, created_at) \
         VALUES ($1, 'workflow-system', 'workflow-system@internal.attome', true, NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Seeds this consumer's cursor the first time it runs (plan §5
/// "Enterprise": the first cursor starts at the oldest unprocessed row so no
/// in-flight event is skipped). A zero cursor — what `change_feed::cursor`
/// would create — would re-read the whole retained feed; the stamped rows in
/// it are skipped anyway, but reading them is wasted work on a large backlog.
///
/// The seed is one below the lower of (a) the oldest unstamped row's xid and
/// (b) the visibility horizon: a row written by a transaction still open now
/// is invisible to this statement, carries an xid at or above the horizon,
/// and must stay ahead of the cursor. Done here, not in migration 0501, so a
/// fresh database, a cloned test template and a deleted cursor row all get
/// the same seed, and `ON CONFLICT DO NOTHING` makes a racing first run
/// harmless.
async fn seed_cursor(conn: &mut PgConnection) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM change_consumer_cursor WHERE consumer = $1)",
    )
    .bind(CONSUMER)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO change_consumer_cursor (consumer, last_commit_xid) \
         SELECT $1, (GREATEST(LEAST( \
                    (SELECT MIN(commit_xid::text::bigint) FROM entity_change_event \
                      WHERE processed_at IS NULL), \
                    pg_snapshot_xmin(pg_current_snapshot())::text::bigint \
                ) - 1, 0))::text::xid8 \
         ON CONFLICT (consumer) DO NOTHING",
    )
    .bind(CONSUMER)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Reads a batch of change-feed events after [`CONSUMER`]'s cursor and, for
/// each, does two independent things (§4.3's `entry`/`wait` role split):
/// starts a new instance for every published entry trigger whose
/// `(entity_logicalname, trigger_type)` matches and whose condition passes
/// (`trigger_index::match_entry_triggers`), AND resumes every running
/// instance's Wait-for-Event node whose `(entity_logicalname[, condition])`
/// matches (`trigger_index::match_wait_triggers`). Returns the total count of
/// instances started + node_runs resumed.
///
/// An error stops the batch at the failing event: the events before it are
/// stamped and the cursor advanced past them, the failing one and those after
/// it are re-read on the next run. Each failed attempt is counted in
/// `workflow_trigger_failure` (migration 0510); an event that has failed
/// [`MAX_ATTEMPTS`] times over at least [`DEAD_LETTER_AFTER_SECS`] is
/// dead-lettered instead — logged at `error`, counted in
/// `workflow_trigger_dead_letters_total`, stamped, and skipped — so one
/// permanently failing event cannot hold every entity-triggered workflow.
pub async fn dispatch_pending(state: &EngineState) -> Result<u64, AppError> {
    dispatch_pending_with_fault(state, None).await
}

/// The [`dispatch_pending_with_fault`] hook's type.
#[doc(hidden)]
pub type DispatchFault = dyn Fn(&ChangeEvent) -> Result<(), AppError> + Send + Sync;

/// Test seam for [`dispatch_pending`]: `fault`, when given, runs after an
/// event's starts and resumes are durable but before the event is stamped and
/// the cursor advanced — the exact window a crash would hit — and an `Err`
/// from it aborts the run there. Production passes `None`.
#[doc(hidden)]
pub async fn dispatch_pending_with_fault(
    state: &EngineState,
    fault: Option<&DispatchFault>,
) -> Result<u64, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    seed_cursor(&mut conn).await?;
    let events = change_feed::read_batch(&mut conn, CONSUMER, DISPATCH_BATCH_SIZE).await?;
    if events.is_empty() {
        return Ok(0);
    }

    let ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
    let already_stamped: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_change_event \
         WHERE id = ANY($1) AND processed_at IS NOT NULL",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();

    let system_user_id = ensure_system_user(&state.base.db).await?;
    let mut count = 0u64;
    let mut done: Vec<&ChangeEvent> = Vec::with_capacity(events.len());
    for event in &events {
        if !already_stamped.contains(&event.id) {
            let outcome = match dispatch_one(state, event, system_user_id).await {
                Ok(n) => match fault {
                    Some(fault) => fault(event).map(|()| n),
                    None => Ok(n),
                },
                Err(e) => Err(e),
            };
            match outcome {
                Ok(n) => count += n,
                Err(e) => match record_failure(state, &mut conn, event, &e).await {
                    Failure::DeadLettered { newly } => {
                        // A re-read after a failed `finish` finds the event
                        // already dead: skip it again, count it once.
                        if newly {
                            metrics::counter!("workflow_trigger_dead_letters_total").increment(1);
                            tracing::error!(
                                event_id = %event.id,
                                entity = %event.entity_logicalname,
                                record_id = %event.record_id,
                                error = %e,
                                "workflow entity-trigger dispatch: event dead-lettered after \
                                 repeated failures; skipping it (see workflow_trigger_failure)"
                            );
                        }
                    }
                    Failure::Held => {
                        tracing::error!(
                            event_id = %event.id,
                            entity = %event.entity_logicalname,
                            record_id = %event.record_id,
                            error = %e,
                            "workflow entity-trigger dispatch: event failed; it and the rest of \
                             the batch will be re-read on the next run"
                        );
                        finish(&mut conn, &done).await?;
                        return Err(e);
                    }
                },
            }
        }
        done.push(event);
    }
    finish(&mut conn, &done).await?;
    Ok(count)
}

/// Stamps `processed_at` on the dispatched events and advances the cursor
/// past the last of them. The work these events caused is already committed
/// in its own transactions; this is only the record that it happened. A crash
/// before it re-delivers them, which the idempotent start and resume absorb.
async fn finish(conn: &mut PgConnection, done: &[&ChangeEvent]) -> Result<(), AppError> {
    let Some(last) = done.last() else {
        return Ok(());
    };
    let ids: Vec<Uuid> = done.iter().map(|e| e.id).collect();
    sqlx::query(
        "UPDATE entity_change_event SET processed_at = NOW() \
         WHERE id = ANY($1) AND processed_at IS NULL",
    )
    .bind(&ids)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // An event that failed before and has now gone through leaves no
    // failure row behind; a dead letter stays for the operator.
    sqlx::query(
        "DELETE FROM workflow_trigger_failure \
         WHERE event_id = ANY($1) AND dead_lettered_at IS NULL",
    )
    .bind(&ids)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    change_feed::advance(conn, CONSUMER, last).await
}

/// Failed attempts before an event may be dead-lettered.
pub const MAX_ATTEMPTS: i32 = 5;

/// How long an event must have been failing before it may be dead-lettered.
/// With [`MAX_ATTEMPTS`] this keeps an outage that fails every event for a
/// few runs from dead-lettering a healthy backlog: only an event that still
/// fails after both bounds is skipped.
pub const DEAD_LETTER_AFTER_SECS: i64 = 15 * 60;

/// Longest `last_error` kept, in characters.
const LAST_ERROR_MAX_CHARS: usize = 2000;

/// What one failed attempt did to its event.
enum Failure {
    /// The event stays at the head of the feed for the next run.
    Held,
    /// The event is dead-lettered and the caller skips it. `newly` is false
    /// when an earlier run had already dead-lettered it.
    DeadLettered { newly: bool },
}

/// Records one failed attempt for `event` in `workflow_trigger_failure`
/// (migration 0510) and dead-letters it once both [`MAX_ATTEMPTS`] and
/// [`DEAD_LETTER_AFTER_SECS`] are reached.
///
/// Only a failure that belongs to the event counts. A breaker or unavailable
/// dependency (`Overloaded`, `CapabilityUnavailable`) is not counted, and
/// neither is any failure while a fresh pool connection cannot run
/// `SELECT 1`: dispatch wraps database errors as `Internal`, so the variant
/// alone cannot tell a pool timeout from a bad event, and this run's held
/// connection can still work while the pool is exhausted. An uncounted or
/// unrecordable failure holds the event, so nothing is skipped on a failure
/// that was never recorded.
async fn record_failure(
    state: &EngineState,
    conn: &mut PgConnection,
    event: &ChangeEvent,
    error: &AppError,
) -> Failure {
    if matches!(
        error,
        AppError::Overloaded(_) | AppError::CapabilityUnavailable(_)
    ) || sqlx::query("SELECT 1")
        .execute(&state.base.db)
        .await
        .is_err()
    {
        return Failure::Held;
    }
    let last_error: String = error
        .to_string()
        .chars()
        .take(LAST_ERROR_MAX_CHARS)
        .collect();
    let dead = sqlx::query_as::<_, (bool, bool)>(
        "INSERT INTO workflow_trigger_failure \
             (event_id, entity_logicalname, record_id, operation, last_error) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (event_id) DO UPDATE SET \
             attempts = workflow_trigger_failure.attempts + 1, \
             last_error = EXCLUDED.last_error, \
             last_failed_at = now(), \
             dead_lettered_at = COALESCE( \
                 workflow_trigger_failure.dead_lettered_at, \
                 CASE WHEN workflow_trigger_failure.attempts + 1 >= $6 \
                       AND workflow_trigger_failure.first_failed_at \
                           <= now() - make_interval(secs => $7) \
                      THEN now() END) \
         RETURNING dead_lettered_at IS NOT NULL, \
                   COALESCE(dead_lettered_at = now(), false)",
    )
    .bind(event.id)
    .bind(&event.entity_logicalname)
    .bind(event.record_id)
    .bind(&event.operation)
    .bind(last_error)
    .bind(MAX_ATTEMPTS)
    .bind(DEAD_LETTER_AFTER_SECS as f64)
    .fetch_one(&mut *conn)
    .await;
    // `now()` is the statement's transaction time, so it equals
    // `dead_lettered_at` only when this very statement set it.
    match dead {
        Ok((true, newly)) => Failure::DeadLettered { newly },
        Ok((false, _)) => Failure::Held,
        Err(e) => {
            tracing::warn!(
                event_id = %event.id,
                error = %e,
                "workflow entity-trigger dispatch: could not record the failed attempt"
            );
            Failure::Held
        }
    }
}

async fn dispatch_one(
    state: &EngineState,
    event: &ChangeEvent,
    system_user_id: Uuid,
) -> Result<u64, AppError> {
    let mut count = start_entry_instances(state, event, system_user_id).await?;
    count += resume_waits(state, event).await?;
    Ok(count)
}

/// Starts every entry trigger `event` matches (condition included) and
/// returns how many instances this call newly started. Idempotent per event:
/// a trigger this event already started is a no-op (migration 0501).
pub(crate) async fn start_entry_instances(
    state: &EngineState,
    event: &ChangeEvent,
    system_user_id: Uuid,
) -> Result<u64, AppError> {
    // B5-T3: a quiet write (a bulk edit run without automation) starts no
    // flow; a running flow waiting on the record still resumes.
    if event.quiet {
        return Ok(0);
    }
    let mut count = 0u64;
    // M1-T1: a merge survivor's named event starts `merge` triggers only
    // (its ordinary update has its own event); E14-T9: a watched-page view
    // starts `web.page_viewed` triggers only; every other event matches its
    // operation (`create`, `update`, `delete`, `restore`).
    let trigger_type =
        crate::trigger_index::entry_trigger_type(&event.operation, event.event_name.as_deref());
    let entry_matches = crate::trigger_index::match_entry_triggers(
        &state.base.db,
        &event.entity_logicalname,
        trigger_type,
    )
    .await
    .map_err(AppError::internal)?;

    // The record's current state, loaded at most once per event and only if
    // some matching trigger carries an expression.
    let mut record: Option<Option<serde_json::Map<String, Value>>> = None;
    for m in entry_matches {
        if !entry_condition_passes(state, &m, event, &mut record).await? {
            continue;
        }
        let context = json!({
            "entity_logicalname": event.entity_logicalname,
            "record_id": event.record_id,
            "operation": trigger_type,
            "changed_attributes": event.changed_attributes,
        });
        let started = crate::instance_admin::start_instance_for_event(
            state,
            m.definition_version_id,
            &m.node_id,
            Some(system_user_id),
            Some(event.record_id),
            context,
            event.id,
        )
        .await?;
        if started.is_some() {
            count += 1;
        }
    }
    Ok(count)
}

/// Resumes every running Wait-for-Event node `event` matches.
async fn resume_waits(state: &EngineState, event: &ChangeEvent) -> Result<u64, AppError> {
    let mut count = 0u64;
    if !crate::trigger_index::resumes_waits(event.event_name.as_deref()) {
        return Ok(0);
    }
    let wait_matches =
        crate::trigger_index::match_wait_triggers(&state.base.db, &event.entity_logicalname)
            .await
            .map_err(AppError::internal)?;
    for w in wait_matches {
        if !wait_condition_matches(w.condition.as_ref(), event.record_id, &event.operation) {
            continue;
        }
        let output = json!({
            "entity_logicalname": event.entity_logicalname,
            "record_id": event.record_id,
            "operation": event.operation,
        });
        crate::scheduler::resume_node(state, w.instance_id, &w.node_id, w.node_run_id, output)
            .await?;
        count += 1;
    }
    Ok(count)
}

/// Whether entry trigger `m` may start an instance for `event`: its
/// `condition` object's `record_id`/`operation` keys (the same filter a
/// Wait-for-Event node uses), then its attome-rules `expression`, if any.
///
/// Fails closed: an unknown entity or an expression that no longer compiles
/// against the entity's live schema is a `warn` and no start — never a start
/// that ignores the author's condition. Only a transient failure (a database
/// error loading the record, the evaluator's wall-clock breaker) is an `Err`,
/// so the event is retried rather than decided on a hiccup.
async fn entry_condition_passes(
    state: &EngineState,
    m: &EntryMatch,
    event: &ChangeEvent,
    record: &mut Option<Option<serde_json::Map<String, Value>>>,
) -> Result<bool, AppError> {
    let condition = m.condition.as_ref();
    if !wait_condition_matches(
        condition.filter(|c| c.is_object()),
        event.record_id,
        &event.operation,
    ) {
        return Ok(false);
    }
    // M1-T1: an update trigger may name attributes; it starts only when the
    // write changed one of them.
    if !attributes_match(condition, &event.changed_attributes) {
        return Ok(false);
    }
    let Some(expression) = condition
        .and_then(|c| c.get("expression"))
        .and_then(Value::as_str)
    else {
        return Ok(true);
    };

    let attrs = {
        let registry = state.entities.load();
        match registry.get(&event.entity_logicalname) {
            Some(meta) => meta.attrs.clone(),
            None => {
                tracing::warn!(
                    definition_version_id = %m.definition_version_id,
                    node_id = %m.node_id,
                    entity = %event.entity_logicalname,
                    "workflow entry trigger has an expression but its entity is unknown; \
                     not starting (fail closed)"
                );
                return Ok(false);
            }
        }
    };

    let rule = trigger_rule(m, &event.entity_logicalname, expression);
    let schema = attome_records::rule_engine::schema_for_entity(&attrs);
    let compiled = match attome_records::rule_engine::get_or_compile(state, &rule, &schema).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                definition_version_id = %m.definition_version_id,
                node_id = %m.node_id,
                entity = %event.entity_logicalname,
                error = %e,
                "workflow entry trigger expression does not compile; not starting (fail closed)"
            );
            return Ok(false);
        }
    };

    if record.is_none() {
        *record =
            Some(load_record(state, &event.entity_logicalname, event.record_id, &attrs).await?);
    }
    let Some(Some(obj)) = record.as_ref() else {
        // Hard-deleted since the event was written: there is no state to
        // evaluate, so the condition cannot be shown to hold.
        return Ok(false);
    };

    let ctx = attome_records::rule_engine::context_for_record(chrono::Utc::now(), &attrs, obj);
    match compiled.eval(&ctx) {
        Ok(v) => Ok(attome_records::rule_engine::json_from_rules_value(&v) == Value::Bool(true)),
        Err(e) if e.is_transient() => Err(AppError::Overloaded(
            "workflow entry-trigger expression evaluation",
        )),
        Err(e) => {
            tracing::warn!(
                definition_version_id = %m.definition_version_id,
                node_id = %m.node_id,
                record_id = %event.record_id,
                error = %e,
                "workflow entry trigger expression failed to evaluate; not starting"
            );
            Ok(false)
        }
    }
}

/// The synthetic `RuleDef` a trigger expression compiles through, so it
/// shares `rule_engine::get_or_compile` and the bounded `rule_compiled` cache
/// with stored rules. Its id is a v5 UUID of (published version, node id) and
/// its version is 0: a published version's graph is immutable, so that pair
/// fixes the expression exactly as a rule's `(id, version)` does.
pub fn trigger_rule(m: &EntryMatch, entity: &str, expression: &str) -> attome_core::RuleDef {
    attome_core::RuleDef {
        id: Uuid::new_v5(&m.definition_version_id, m.node_id.as_bytes()),
        entity_logicalname: entity.to_owned(),
        name: format!("workflow-trigger:{}:{}", m.definition_version_id, m.node_id),
        kind: "validation".to_owned(),
        target_field: None,
        expression: expression.to_owned(),
        message: None,
        severity: "error".to_owned(),
        is_active: true,
        display_order: 0,
        version: 0,
        row_version: 0,
    }
}

/// The record's current column values under the workflow system context (no
/// record-level security: a trigger watches every record of its entity).
/// `entity` is a registry-resolved logical name, quoted through the shared
/// helper; `None` when the row no longer exists.
async fn load_record(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    attrs: &[attome_core::AttrInfo],
) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
    let table = attome_core::quote_ident(entity);
    let cols = attome_core::select_columns(attrs, true);
    let sql = format!("SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1) t");
    let row: Option<Value> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(match row {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    })
}

/// Publish-time check (plan §4.2): every entry trigger's `expression` must
/// compile against its watched entity's live schema and produce a boolean. A
/// failure names the node and rejects the publish, so a broken condition is
/// caught by its author rather than silently starting nothing at dispatch.
/// Compiles through the same cache key dispatch uses, so the first dispatch
/// after a publish is a cache hit.
pub async fn validate_entry_expressions(
    state: &EngineState,
    definition_version_id: Uuid,
    graph: &crate::graph::Graph,
) -> Result<(), AppError> {
    for node in &graph.nodes {
        if crate::node_types::NodeType::parse(&node.node_type)
            != Some(crate::node_types::NodeType::Trigger)
        {
            continue;
        }
        let Some(expression) = node.config.get("expression") else {
            continue;
        };
        let Some(expression) = expression.as_str().filter(|s| !s.trim().is_empty()) else {
            return Err(AppError::Validation(format!(
                "trigger node {:?}: expression must be a non-empty string",
                node.id
            )));
        };
        let Some(entity) = node
            .config
            .get("entity_logicalname")
            .and_then(Value::as_str)
        else {
            return Err(AppError::Validation(format!(
                "trigger node {:?}: an expression needs entity_logicalname",
                node.id
            )));
        };
        let attrs = {
            let registry = state.entities.load();
            let Some(meta) = registry.get(entity) else {
                return Err(AppError::Validation(format!(
                    "trigger node {:?}: unknown entity {entity:?}",
                    node.id
                )));
            };
            meta.attrs.clone()
        };
        let m = EntryMatch {
            definition_version_id,
            node_id: node.id.clone(),
            condition: None,
        };
        let rule = trigger_rule(&m, entity, expression);
        let schema = attome_records::rule_engine::schema_for_entity(&attrs);
        let compiled = attome_records::rule_engine::get_or_compile(state, &rule, &schema)
            .await
            .map_err(|e| {
                AppError::Validation(format!(
                    "trigger node {:?}: expression does not compile: {e}",
                    node.id
                ))
            })?;
        attome_records::rule_engine::check_boolean_result_type(&compiled).map_err(|_| {
            AppError::Validation(format!(
                "trigger node {:?}: expression must produce a boolean",
                node.id
            ))
        })?;
    }
    Ok(())
}

/// Secondary in-app filter over a Wait-for-Event node's `condition` JSON
/// (§8 risk mitigation — `entity_logicalname` is the real index, this only
/// narrows an already-small, single-entity-scoped result set). Supports the
/// two conventions `execute_wait_for_event`'s config already documents as
/// meaningful: an optional `record_id` (only that exact record's event
/// resumes the wait) and an optional `operation` (only `create` or
/// `update`, matching the outbox row's own `operation` column). Either or
/// both absent matches unconditionally. Entry triggers apply the same filter
/// before their attome-rules `expression` ([`entry_condition_passes`]).
/// M1-T1: the trigger's `attributes` filter against the event's changed
/// attributes. No filter (or an empty one) matches every event.
fn attributes_match(condition: Option<&Value>, changed: &[String]) -> bool {
    let Some(wanted) = condition
        .and_then(|c| c.get("attributes"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    else {
        return true;
    };
    wanted
        .iter()
        .filter_map(Value::as_str)
        .any(|w| changed.iter().any(|c| c == w))
}

fn wait_condition_matches(
    condition: Option<&serde_json::Value>,
    record_id: Uuid,
    operation: &str,
) -> bool {
    let Some(condition) = condition else {
        return true;
    };
    if let Some(want_record_id) = condition
        .get("record_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        && want_record_id != record_id
    {
        return false;
    }
    if let Some(want_operation) = condition
        .get("operation")
        .and_then(serde_json::Value::as_str)
        && want_operation != operation
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(condition: Option<Value>) -> EntryMatch {
        EntryMatch {
            definition_version_id: Uuid::nil(),
            node_id: "t".to_owned(),
            condition,
        }
    }

    #[test]
    fn trigger_rule_id_is_stable_per_version_and_node() {
        let a = trigger_rule(&entry(None), "account", "true");
        let b = trigger_rule(&entry(None), "account", "true");
        assert_eq!(a.id, b.id);
        let mut other = entry(None);
        other.node_id = "t2".to_owned();
        assert_ne!(a.id, trigger_rule(&other, "account", "true").id);
    }

    #[test]
    fn condition_object_filters_by_operation_and_record() {
        let rid = Uuid::now_v7();
        let c = json!({"operation": "update"});
        assert!(!wait_condition_matches(Some(&c), rid, "create"));
        assert!(wait_condition_matches(Some(&c), rid, "update"));
        let c = json!({"record_id": Uuid::nil().to_string()});
        assert!(!wait_condition_matches(Some(&c), rid, "create"));
        assert!(wait_condition_matches(None, rid, "create"));
    }
}

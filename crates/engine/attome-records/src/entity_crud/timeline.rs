//! `GET /api/v1/{entity}/{id}/timeline` — one record's activity feed, for any
//! entity (basic-units plan U3, ruling B-R4, recorded as D-601).
//!
//! **Why here.** This crate owns the record-level read decision
//! (`access::require_record_read`), the per-entity row-security predicate the
//! sources need, and the polymorphic-child list (D-593). Every source is a
//! metadata entity or an audit ledger table read by SQL, so nothing here needs
//! a sibling engine crate: `attome-service`'s ticket route calls down into this
//! module (`attome-service → attome-records` is a new, one-way, same-layer
//! edge with no cycle), and `attome-audit` — which sits *below* this crate and
//! below `attome-security` — could not host it without a reverse edge.
//!
//! **Sources**, each a `TimelineEntryKind`:
//! - `audit_event` — `audit_header` rows for the record;
//! - `state_transition` — `audit_detail` rows for the entity's state field,
//!   taken from its state model (`EngineState::state_models`); an entity with no
//!   model has no transitions;
//! - `communication`, `note`, `activity` — polymorphic children
//!   (`entity_name` + `record_id`) on `communication`, `note`,
//!   `activity`, each read only when the entity is registered;
//! - `decision` — `dashboard_decision` rows linked through
//!   `record_relationship` in either direction.
//!
//! **Authorization.**
//! 1. The record itself: `{entity}.read` plus `require_record_read`, the exact
//!    decision `GET /api/v1/{entity}/{id}` makes; a record the caller cannot
//!    read, or that does not exist, is `NotFound`.
//! 2. Audit rows (both kinds) are gated by that record alone — the D-147 rule
//!    for the audit family: nobody holds a share on an individual audit entry.
//!    Their field names and values follow the record read's field-security
//!    filter (B-R12): a sensitive field the caller has no read grant for is
//!    never named, and a sensitive field's values are never shown.
//! 3. Children and decisions: the caller must hold `{source}.read`, and each
//!    row must pass that source entity's own row-level security, ANDed into the
//!    source query itself (`rls_predicate_with_conditions`, the predicate every
//!    generic list uses). The parent half of D-593 is satisfied by
//!    construction — every child row read here is attached to the record from
//!    step 1. Sensitive child columns the caller cannot read are left out of
//!    the entry's `detail`.
//!
//! **Paging.** A keyset over `(occurred_at DESC, kind ASC, source_id DESC)`,
//! where `kind` compares by its wire name. Each source query applies the
//! keyset condition and fetches `page_size + 1` rows; the merge keeps the first
//! `page_size`. Because every source contributes its own first `page_size + 1`
//! rows past the cursor, the merged page is exactly the global order's next
//! `page_size` rows, and `next_cursor` is present exactly when more exist.
//! Timestamps travel as integer microseconds (PostgreSQL's own precision), so
//! entries sharing one timestamp page without loss or repetition.

use std::collections::HashSet;

use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::record_action::Read;
use attome_security::{RecordAction, SecurityContextExt, rls_predicate_with_conditions};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage, DEFAULT_PAGE_SIZE, ErrorResponse, MAX_PAGE_SIZE};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::access::{require_record_read, resolve_record_access_inputs};
use super::resolve::resolve_entity;

/// One entry in a record's timeline.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelineEntry {
    pub kind: TimelineEntryKind,
    pub occurred_at: DateTime<Utc>,
    /// The entity or ledger table the underlying row belongs to —
    /// `audit_header`, `audit_detail` (state transitions),
    /// `communication`, `note`, `activity` or
    /// `dashboard_decision`.
    pub source_entity: String,
    pub source_id: Uuid,
    /// Short, human-readable description of the event.
    pub summary: String,
    /// Kind-specific detail (audit operation and readable changed fields,
    /// communication subject/channel, note title, activity type, decision
    /// status, …). A JSON object rather than one struct with mostly-empty
    /// fields across six unrelated shapes.
    pub detail: Value,
}

/// The source an entry came from. Entries sort by their wire name within one
/// timestamp, so the order is stable and documented: `activity`,
/// `audit_event`, `communication`, `decision`, `note`, `state_transition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEntryKind {
    AuditEvent,
    StateTransition,
    Communication,
    Decision,
    Note,
    Activity,
}

impl TimelineEntryKind {
    pub const ALL: [TimelineEntryKind; 6] = [
        TimelineEntryKind::AuditEvent,
        TimelineEntryKind::StateTransition,
        TimelineEntryKind::Communication,
        TimelineEntryKind::Decision,
        TimelineEntryKind::Note,
        TimelineEntryKind::Activity,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuditEvent => "audit_event",
            Self::StateTransition => "state_transition",
            Self::Communication => "communication",
            Self::Decision => "decision",
            Self::Note => "note",
            Self::Activity => "activity",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// Query string for `GET /api/v1/{entity}/{id}/timeline`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimelineQuery {
    /// Opaque cursor from a previous page's `next_cursor`. A malformed value is
    /// a 422.
    pub cursor: Option<String>,
    /// Entries per page, 1..=200 (default 50); larger values are clamped.
    pub page_size: Option<i64>,
    /// Comma-separated kinds to include (`audit_event`, `state_transition`,
    /// `communication`, `note`, `activity`, `decision`). Omitted or empty means
    /// every kind. An unknown kind is a 422.
    pub kinds: Option<String>,
}

/// A position in the timeline's global order: the last entry of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelineCursor {
    pub occurred_micros: i64,
    pub kind: TimelineEntryKind,
    pub source_id: Uuid,
}

/// Validated timeline options, for non-HTTP callers (the ticket route).
#[derive(Debug, Clone)]
pub struct TimelineOptions {
    pub cursor: Option<TimelineCursor>,
    pub page_size: i64,
    /// `None` = every kind.
    pub kinds: Option<HashSet<TimelineEntryKind>>,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            kinds: None,
        }
    }
}

impl TimelineOptions {
    /// Validates a raw query: 422 on a malformed cursor or an unknown kind.
    pub fn from_query(q: &TimelineQuery) -> Result<Self, AppError> {
        let cursor = match q.cursor.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(decode_timeline_cursor(raw)?),
        };
        let kinds = match q.kinds.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(raw) => {
                let mut set = HashSet::new();
                for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    let kind = TimelineEntryKind::parse(part).ok_or_else(|| {
                        AppError::Validation(format!("unknown timeline kind: {part}"))
                    })?;
                    set.insert(kind);
                }
                Some(set)
            }
        };
        Ok(Self {
            cursor,
            page_size: clamp_page_size(q.page_size),
            kinds,
        })
    }

    fn wants(&self, kind: TimelineEntryKind) -> bool {
        self.kinds.as_ref().is_none_or(|k| k.contains(&kind))
    }
}

pub(super) fn clamp_page_size(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE)
}

// ── Cursor codec ─────────────────────────────────────────────────────────────

/// `base64url("{micros}:{tag}:{uuid}")`. The tag is a timeline kind here and
/// the literal `change` for record history, so a cursor from one route is
/// refused by the other.
pub(super) fn encode_cursor(micros: i64, tag: &str, id: Uuid) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{micros}:{tag}:{id}"))
}

pub(super) fn decode_cursor(raw: &str) -> Result<(i64, String, Uuid), AppError> {
    let invalid = || AppError::Validation("malformed cursor".into());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    let mut parts = text.splitn(3, ':');
    let micros = parts
        .next()
        .and_then(|p| p.parse::<i64>().ok())
        .ok_or_else(invalid)?;
    let tag = parts.next().ok_or_else(invalid)?.to_owned();
    let id = parts
        .next()
        .and_then(|p| Uuid::parse_str(p).ok())
        .ok_or_else(invalid)?;
    // Reject a timestamp chrono cannot represent, so a forged cursor is a 422
    // rather than a later panic or a nonsensical SQL bind.
    DateTime::<Utc>::from_timestamp_micros(micros).ok_or_else(invalid)?;
    Ok((micros, tag, id))
}

fn decode_timeline_cursor(raw: &str) -> Result<TimelineCursor, AppError> {
    let (occurred_micros, tag, source_id) = decode_cursor(raw)?;
    let kind = TimelineEntryKind::parse(&tag)
        .ok_or_else(|| AppError::Validation("malformed cursor".into()))?;
    Ok(TimelineCursor {
        occurred_micros,
        kind,
        source_id,
    })
}

pub(super) fn micros_to_datetime(micros: i64) -> Result<DateTime<Utc>, AppError> {
    DateTime::<Utc>::from_timestamp_micros(micros)
        .ok_or_else(|| AppError::internal("timeline timestamp out of range"))
}

/// The keyset condition one source applies, given the cursor and the source's
/// own (constant) kind — see the module doc's **Paging**. `occ` is the
/// source's timestamp expression, `id` its id column; `ts`/`idp` are the
/// placeholders the caller binds the cursor's timestamp and id to. Returns
/// `(sql, binds_id)`: whether the id placeholder is used.
fn keyset_sql(
    cursor: Option<&TimelineCursor>,
    kind: TimelineEntryKind,
    occ: &str,
    id: &str,
    ts: usize,
    idp: usize,
) -> Option<(String, bool)> {
    let cursor = cursor?;
    Some(match kind.as_str().cmp(cursor.kind.as_str()) {
        std::cmp::Ordering::Greater => (format!("AND {occ} <= ${ts}"), false),
        std::cmp::Ordering::Less => (format!("AND {occ} < ${ts}"), false),
        std::cmp::Ordering::Equal => (
            format!("AND ({occ} < ${ts} OR ({occ} = ${ts} AND {id} < ${idp}))"),
            true,
        ),
    })
}

/// The sort key of an entry: newest first, then kind name, then id newest
/// first.
fn sort_key(
    e: &(i64, TimelineEntry),
) -> (
    std::cmp::Reverse<i64>,
    &'static str,
    std::cmp::Reverse<Uuid>,
) {
    (
        std::cmp::Reverse(e.0),
        e.1.kind.as_str(),
        std::cmp::Reverse(e.1.source_id),
    )
}

// ── Field security ───────────────────────────────────────────────────────────

/// B-R12's field filter, the one a record read applies
/// (`select_columns_filtered`/`build_response`): an `is_sensitive` attribute
/// is readable only with a field-security read grant; every other attribute
/// is readable. A name that is not a current attribute of the entity (a
/// dropped field, a system column) is not readable here: fail closed.
pub(super) fn readable_attr<'a>(
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &'a [AttrInfo],
    field: &str,
) -> Option<&'a AttrInfo> {
    attrs
        .iter()
        .find(|a| a.logicalname == field)
        .filter(|a| !a.is_sensitive || ctx.has_field_read_grant(entity_name, &a.logicalname))
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Builds one page of a record's timeline as `ctx`. See the module doc for the
/// sources, the authorization of each, and the paging contract.
///
/// Checks `{entity}.read` itself (`Forbidden`), so a non-HTTP caller gets the
/// same answer the route's extractor gives. A record the caller cannot read,
/// or that does not exist, is `NotFound`.
pub async fn record_timeline(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    opts: &TimelineOptions,
) -> Result<CursorPage<TimelineEntry>, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    ctx.require(&entity_name, "read")?;
    require_record_read(state, ctx, entity_id, &entity_name, record_id).await?;
    require_live_record(state, &entity_name, is_append_only, record_id).await?;

    let limit = opts.page_size + 1;
    let cursor = opts.cursor.as_ref();
    let mut rows: Vec<(i64, TimelineEntry)> = Vec::new();

    if opts.wants(TimelineEntryKind::AuditEvent) {
        rows.extend(
            fetch_audit_events(state, ctx, &entity_name, &attrs, record_id, cursor, limit).await?,
        );
    }
    if opts.wants(TimelineEntryKind::StateTransition) {
        rows.extend(
            fetch_state_transitions(state, ctx, &entity_name, &attrs, record_id, cursor, limit)
                .await?,
        );
    }
    for source in CHILD_SOURCES {
        if opts.wants(source.kind) {
            rows.extend(
                fetch_child_source(state, ctx, source, &entity_name, record_id, cursor, limit)
                    .await?,
            );
        }
    }
    if opts.wants(TimelineEntryKind::Decision) {
        rows.extend(
            fetch_linked_decisions(state, ctx, &entity_name, record_id, cursor, limit).await?,
        );
    }

    rows.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    let has_more = rows.len() as i64 > opts.page_size;
    rows.truncate(opts.page_size as usize);
    let next_cursor = if has_more {
        rows.last()
            .map(|(micros, e)| encode_cursor(*micros, e.kind.as_str(), e.source_id))
    } else {
        None
    };
    Ok(CursorPage::new(
        rows.into_iter().map(|(_, e)| e).collect(),
        next_cursor,
    ))
}

/// `require_record_access` short-circuits for a Global-tier caller without
/// looking at the row, so a missing or soft-deleted record must be refused
/// here, the way a record read's own fetch refuses it.
pub(super) async fn require_live_record(
    state: &EngineState,
    entity_name: &str,
    is_append_only: bool,
    record_id: Uuid,
) -> Result<(), AppError> {
    let table = quote_ident(entity_name);
    let live = attome_core::live_row_predicate("t", is_append_only)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();
    let exists: bool = sqlx::query_scalar(&attome_db::tag_dynamic(
        "entity.timeline",
        &format!("SELECT EXISTS(SELECT 1 FROM {table} t WHERE t.id = $1 {live})"),
    ))
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

// ── Audit sources ────────────────────────────────────────────────────────────

/// Mirrors `attome_audit::model::AuditOperation`'s discriminants.
pub(super) fn audit_operation_label(op: i32) -> &'static str {
    match op {
        0 => "created",
        1 => "updated",
        2 => "soft_deleted",
        3 => "hard_deleted",
        4 => "restored",
        5 => "merged",
        6 => "cloned",
        7 => "imported",
        8 => "exported",
        9 => "login",
        10 => "logout",
        11 => "failed_login",
        12 => "permission_changed",
        13 => "role_changed",
        14 => "owner_changed",
        15 => "approved",
        16 => "rejected",
        17 => "submitted",
        18 => "cancelled",
        19 => "closed",
        20 => "activated",
        21 => "erasure",
        22 => "mfa_reset",
        23 => "account_disabled",
        24 => "account_enabled",
        25 => "file_scanned",
        26 => "escalated",
        _ => "unknown",
    }
}

type AuditEventRow = (
    Uuid,
    Option<i32>,
    DateTime<Utc>,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
);

async fn fetch_audit_events(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    cursor: Option<&TimelineCursor>,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::AuditEvent;
    let keyset = keyset_sql(cursor, kind, "h.changed_on", "h.id", 4, 5);
    let sql = format!(
        "SELECT h.id, h.operation::int, h.changed_on, \
                (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint, \
                h.user_display_name, h.event_name, h.event_comment, \
                ARRAY(SELECT d.field_name::text FROM audit_detail d \
                      WHERE d.audit_ref = h.id AND d.field_name IS NOT NULL \
                      ORDER BY d.field_name) \
         FROM audit_header h \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND h.changed_on IS NOT NULL {keyset} \
         ORDER BY h.changed_on DESC, h.id DESC LIMIT $3",
        keyset = keyset.as_ref().map_or("", |k| k.0.as_str()),
    );
    let sql = attome_db::tag_dynamic("entity.timeline", &sql);
    let mut q = sqlx::query_as::<_, AuditEventRow>(&sql)
        .bind(entity_name)
        .bind(record_id)
        .bind(limit);
    if let (Some(c), Some((_, binds_id))) = (cursor, &keyset) {
        q = q.bind(micros_to_datetime(c.occurred_micros)?);
        if *binds_id {
            q = q.bind(c.source_id);
        }
    }
    let rows = q
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                operation,
                changed_on,
                micros,
                user_display_name,
                event_name,
                event_comment,
                fields,
            )| {
                let op = audit_operation_label(operation.unwrap_or(-1));
                let label = event_name.clone().unwrap_or_else(|| op.to_string());
                // A blank stored name reads as no name ("updated by " with
                // nothing after it otherwise).
                let by = user_display_name
                    .clone()
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| "system".to_string());
                let changed_fields: Vec<String> = fields
                    .into_iter()
                    .filter(|f| readable_attr(ctx, entity_name, attrs, f).is_some())
                    .collect();
                (
                    micros,
                    TimelineEntry {
                        kind,
                        occurred_at: changed_on,
                        source_entity: "audit_header".to_string(),
                        source_id: id,
                        summary: format!("{label} by {by}"),
                        detail: serde_json::json!({
                            "operation": op,
                            "event_name": event_name,
                            "event_comment": event_comment,
                            "user_display_name": user_display_name,
                            "changed_fields": changed_fields,
                        }),
                    },
                )
            },
        )
        .collect())
}

type StateTransitionRow = (
    Uuid,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    i64,
    Option<bool>,
);

/// The entity's state-field changes, read from the audit trail. The field is
/// the one the entity's state model names (`EngineState::state_models`), never a
/// hard-coded column; an entity with no state model has no transitions here.
async fn fetch_state_transitions(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    cursor: Option<&TimelineCursor>,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::StateTransition;
    let state_field = {
        let models = state.state_models.load();
        match models.get(entity_name).and_then(|e| e.model.as_ref()) {
            Some(model) => model.state_field.clone(),
            None => return Ok(Vec::new()),
        }
    };
    // B-R12: a state field the caller cannot read is not shown at all.
    let Some(attr) = readable_attr(ctx, entity_name, attrs, &state_field) else {
        return Ok(Vec::new());
    };
    let attr_sensitive = attr.is_sensitive;

    let keyset = keyset_sql(cursor, kind, "h.changed_on", "d.id", 5, 6);
    let sql = format!(
        "SELECT d.id, d.old_value, d.new_value, h.changed_on, \
                (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint, d.is_sensitive \
         FROM audit_detail d \
         JOIN audit_header h ON h.id = d.audit_ref \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND d.field_name = $3 \
           AND h.changed_on IS NOT NULL {keyset} \
         ORDER BY h.changed_on DESC, d.id DESC LIMIT $4",
        keyset = keyset.as_ref().map_or("", |k| k.0.as_str()),
    );
    let sql = attome_db::tag_dynamic("entity.timeline", &sql);
    let mut q = sqlx::query_as::<_, StateTransitionRow>(&sql)
        .bind(entity_name)
        .bind(record_id)
        .bind(&state_field)
        .bind(limit);
    if let (Some(c), Some((_, binds_id))) = (cursor, &keyset) {
        q = q.bind(micros_to_datetime(c.occurred_micros)?);
        if *binds_id {
            q = q.bind(c.source_id);
        }
    }
    let rows = q
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(id, old_value, new_value, changed_on, micros, row_sensitive)| {
                let masked = attr_sensitive || row_sensitive.unwrap_or(false);
                let (old_value, new_value) = if masked {
                    (None, None)
                } else {
                    (old_value, new_value)
                };
                let summary = if masked {
                    format!("{state_field} changed")
                } else {
                    let from = old_value.clone().unwrap_or_else(|| "?".to_string());
                    let to = new_value.clone().unwrap_or_else(|| "?".to_string());
                    format!("{state_field}: {from} -> {to}")
                };
                (
                    micros,
                    TimelineEntry {
                        kind,
                        occurred_at: changed_on,
                        source_entity: "audit_detail".to_string(),
                        source_id: id,
                        summary,
                        detail: serde_json::json!({
                            "field_name": state_field,
                            "old_value": old_value,
                            "new_value": new_value,
                            "masked": masked,
                        }),
                    },
                )
            },
        )
        .collect())
}

// ── Polymorphic child sources ────────────────────────────────────────────────

/// One polymorphic-child source (B-R2's `entity_name` + `record_id` pair).
pub(super) struct ChildSource {
    kind: TimelineEntryKind,
    entity: &'static str,
    /// Columns copied into `detail` when the entity has them and the caller
    /// can read them.
    detail_columns: &'static [&'static str],
    /// A date column preferred over `created_at` as the entry's time, when the
    /// entity has it (a communication's `sent_at`).
    time_column: Option<&'static str>,
}

/// `activity` is listed even where it is not yet provisioned (U2): a
/// source whose entity is not in the metadata registry is skipped.
const CHILD_SOURCES: &[ChildSource] = &[
    ChildSource {
        kind: TimelineEntryKind::Communication,
        entity: "communication",
        detail_columns: &["subject", "channel", "direction", "status"],
        time_column: Some("sent_at"),
    },
    ChildSource {
        kind: TimelineEntryKind::Note,
        entity: "note",
        detail_columns: &["title", "note_text"],
        time_column: None,
    },
    ChildSource {
        kind: TimelineEntryKind::Activity,
        entity: "activity",
        detail_columns: &[
            "activity_type",
            "subject",
            "status",
            "priority",
            "due_at",
            "completed_at",
            "direction",
            "duration_minutes",
        ],
        time_column: None,
    },
];

/// `jsonb_build_object(...)` over the readable subset of `columns` on the
/// source entity, or an empty object.
fn detail_object_sql(
    ctx: &SecurityContext,
    source_entity: &str,
    attrs: &[AttrInfo],
    columns: &[&str],
) -> String {
    let pairs: Vec<String> = columns
        .iter()
        .filter(|c| readable_attr(ctx, source_entity, attrs, c).is_some())
        .map(|c| format!("'{c}', t.{}", quote_ident(c)))
        .collect();
    if pairs.is_empty() {
        "'{}'::jsonb".to_owned()
    } else {
        format!("jsonb_build_object({})", pairs.join(", "))
    }
}

/// Runs one source query shaped as
/// `SELECT jsonb_build_object('id', …, 'micros', …, 'created_by', …, 'detail', …)`
/// with the caller's row-level-security fragment for `source_entity` appended
/// at `{rls}`. `binds` are the query's own leading values; the RLS binds
/// follow them.
async fn run_source_query(
    state: &EngineState,
    ctx: &SecurityContext,
    source_entity: &str,
    source_entity_id: Uuid,
    attrs: &[AttrInfo],
    sql_template: &str,
    binds: Vec<SourceBind>,
) -> Result<Vec<Value>, AppError> {
    let (access_level, owner_visible) = resolve_record_access_inputs(
        state,
        ctx,
        source_entity_id,
        source_entity,
        RecordAction::Read,
    )
    .await?;
    let privilege_key = format!("{source_entity}.read");
    let pred = rls_predicate_with_conditions(
        ctx,
        source_entity_id,
        "t",
        access_level,
        RecordAction::Read.share_capability(),
        &privilege_key,
        attrs,
        owner_visible,
        binds.len() + 1,
    );
    let sql = sql_template.replace("{rls}", pred.as_ref().map_or("", |p| p.sql.as_str()));
    let sql = attome_db::tag_dynamic("entity.timeline", &sql);
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for b in &binds {
        q = match b {
            SourceBind::Text(s) => q.bind(s.clone()),
            SourceBind::Int(i) => q.bind(*i),
            SourceBind::Ts(t) => q.bind(*t),
            SourceBind::Id(u) => q.bind(*u),
        };
    }
    if let Some(pred) = &pred {
        if let Some(tb) = &pred.tier_binds {
            q = attome_security::bind_rls_predicate(q, tb);
        }
        for bind in &pred.condition_binds {
            q = q.bind(bind);
        }
    }
    q.fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

enum SourceBind {
    Text(String),
    Int(i64),
    Ts(DateTime<Utc>),
    Id(Uuid),
}

/// Pushes the cursor binds `keyset_sql` asked for.
fn push_keyset_binds(
    binds: &mut Vec<SourceBind>,
    cursor: Option<&TimelineCursor>,
    keyset: &Option<(String, bool)>,
) -> Result<(), AppError> {
    if let (Some(c), Some((_, binds_id))) = (cursor, keyset) {
        binds.push(SourceBind::Ts(micros_to_datetime(c.occurred_micros)?));
        if *binds_id {
            binds.push(SourceBind::Id(c.source_id));
        }
    }
    Ok(())
}

/// Decodes one `run_source_query` row into its sort micros, id, and the
/// `detail` object.
fn decode_source_row(row: &Value) -> Option<(i64, Uuid, Value)> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let micros = row.get("micros").and_then(Value::as_i64)?;
    let mut detail = row.get("detail").cloned().unwrap_or(Value::Null);
    if let (Value::Object(map), Some(by)) = (&mut detail, row.get("created_by")) {
        map.insert("created_by".into(), by.clone());
    }
    Some((micros, id, detail))
}

fn text_of<'a>(detail: &'a Value, key: &str) -> Option<&'a str> {
    detail
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn child_summary(kind: TimelineEntryKind, detail: &Value) -> String {
    match kind {
        TimelineEntryKind::Communication => format!(
            "Communication: {}",
            text_of(detail, "subject").unwrap_or("(no subject)")
        ),
        TimelineEntryKind::Note => {
            let text = text_of(detail, "title")
                .map(str::to_owned)
                .or_else(|| {
                    text_of(detail, "note_text").map(|t| t.chars().take(80).collect::<String>())
                })
                .unwrap_or_else(|| "(untitled)".to_owned());
            format!("Note: {text}")
        }
        TimelineEntryKind::Activity => {
            let subject = text_of(detail, "subject").unwrap_or("(no subject)");
            match text_of(detail, "activity_type") {
                Some(t) => format!("Activity ({t}): {subject}"),
                None => format!("Activity: {subject}"),
            }
        }
        _ => String::new(),
    }
}

async fn fetch_child_source(
    state: &EngineState,
    ctx: &SecurityContext,
    source: &ChildSource,
    entity_name: &str,
    record_id: Uuid,
    cursor: Option<&TimelineCursor>,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    if ctx.require(source.entity, "read").is_err() {
        return Ok(Vec::new());
    }
    let Some(meta) = state.entities.load().get(source.entity).cloned() else {
        return Ok(Vec::new());
    };
    let has = |c: &str| meta.attrs.iter().any(|a| a.logicalname == c);
    if !has("entity_name") || !has("record_id") {
        return Ok(Vec::new());
    }
    let occ = match source.time_column.filter(|c| has(c)) {
        Some(c) => format!("COALESCE(t.{}, t.created_at)", quote_ident(c)),
        None => "t.created_at".to_owned(),
    };
    let detail = detail_object_sql(ctx, source.entity, &meta.attrs, source.detail_columns);
    let live = attome_core::live_row_predicate("t", meta.is_append_only)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();

    let mut binds = vec![
        SourceBind::Text(entity_name.to_owned()),
        SourceBind::Text(record_id.to_string()),
        SourceBind::Int(limit),
    ];
    let keyset = keyset_sql(cursor, source.kind, &occ, "t.id", 4, 5);
    push_keyset_binds(&mut binds, cursor, &keyset)?;
    let table = quote_ident(source.entity);
    let sql = format!(
        "SELECT jsonb_build_object('id', t.id, \
                'micros', (EXTRACT(EPOCH FROM {occ}) * 1000000)::bigint, \
                'created_by', t.created_by, 'detail', {detail}) \
         FROM {table} t \
         WHERE t.entity_name = $1 AND t.record_id = $2 AND {occ} IS NOT NULL {live} {keyset} {{rls}} \
         ORDER BY {occ} DESC, t.id DESC LIMIT $3",
        keyset = keyset.as_ref().map_or("", |k| k.0.as_str()),
    );
    let rows = run_source_query(
        state,
        ctx,
        source.entity,
        meta.entity_id,
        &meta.attrs,
        &sql,
        binds,
    )
    .await?;

    Ok(rows
        .iter()
        .filter_map(decode_source_row)
        .filter_map(|(micros, id, detail)| {
            Some((
                micros,
                TimelineEntry {
                    kind: source.kind,
                    occurred_at: micros_to_datetime(micros).ok()?,
                    source_entity: source.entity.to_owned(),
                    source_id: id,
                    summary: child_summary(source.kind, &detail),
                    detail,
                },
            ))
        })
        .collect())
}

// ── Linked decisions ─────────────────────────────────────────────────────────

const DECISION_ENTITY: &str = "dashboard_decision";
const RELATIONSHIP_ENTITY: &str = "record_relationship";

/// Decisions linked to the record through `record_relationship`, in either
/// direction. Each decision row must pass the decision entity's own row
/// security; the link row itself is plumbing and carries no content.
async fn fetch_linked_decisions(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    record_id: Uuid,
    cursor: Option<&TimelineCursor>,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::Decision;
    if ctx.require(DECISION_ENTITY, "read").is_err() {
        return Ok(Vec::new());
    }
    let (meta, has_links) = {
        let registry = state.entities.load();
        (
            registry.get(DECISION_ENTITY).cloned(),
            registry.get(RELATIONSHIP_ENTITY).is_some(),
        )
    };
    let Some(meta) = meta else {
        return Ok(Vec::new());
    };
    if !has_links {
        return Ok(Vec::new());
    }
    let detail = detail_object_sql(ctx, DECISION_ENTITY, &meta.attrs, &["title", "status"]);
    let live = attome_core::live_row_predicate("t", meta.is_append_only)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();
    let mut binds = vec![
        SourceBind::Text(entity_name.to_owned()),
        SourceBind::Text(record_id.to_string()),
        SourceBind::Int(limit),
    ];
    let keyset = keyset_sql(cursor, kind, "t.created_at", "t.id", 4, 5);
    push_keyset_binds(&mut binds, cursor, &keyset)?;
    let table = quote_ident(DECISION_ENTITY);
    let sql = format!(
        "SELECT jsonb_build_object('id', t.id, \
                'micros', (EXTRACT(EPOCH FROM t.created_at) * 1000000)::bigint, \
                'created_by', t.created_by, 'detail', {detail}) \
         FROM {table} t \
         WHERE t.id::text IN ( \
                SELECT lower(r.to_record_id) FROM record_relationship r \
                 WHERE r.is_active IS NOT FALSE AND r.from_entity_name = $1 \
                   AND r.from_record_id = $2 AND r.to_entity_name = '{DECISION_ENTITY}' \
                UNION \
                SELECT lower(r.from_record_id) FROM record_relationship r \
                 WHERE r.is_active IS NOT FALSE AND r.to_entity_name = $1 \
                   AND r.to_record_id = $2 AND r.from_entity_name = '{DECISION_ENTITY}') \
           AND t.created_at IS NOT NULL {live} {keyset} {{rls}} \
         ORDER BY t.created_at DESC, t.id DESC LIMIT $3",
        keyset = keyset.as_ref().map_or("", |k| k.0.as_str()),
    );
    let rows = run_source_query(
        state,
        ctx,
        DECISION_ENTITY,
        meta.entity_id,
        &meta.attrs,
        &sql,
        binds,
    )
    .await?;

    Ok(rows
        .iter()
        .filter_map(decode_source_row)
        .filter_map(|(micros, id, detail)| {
            let title = text_of(&detail, "title").unwrap_or("(untitled)").to_owned();
            let summary = match text_of(&detail, "status") {
                Some(status) => format!("Linked decision: {title} ({status})"),
                None => format!("Linked decision: {title}"),
            };
            Some((
                micros,
                TimelineEntry {
                    kind,
                    occurred_at: micros_to_datetime(micros).ok()?,
                    source_entity: DECISION_ENTITY.to_owned(),
                    source_id: id,
                    summary,
                    detail,
                },
            ))
        })
        .collect())
}

// ── Route ────────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/timeline",
    tag = "entity",
    operation_id = "get_record_timeline",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        TimelineQuery,
    ),
    responses(
        (status = 200, description = "One keyset page of the record's permission-filtered timeline", body = CursorPage<TimelineEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "Malformed cursor or unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_record_timeline(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<CursorPage<TimelineEntry>>, AppError> {
    let opts = TimelineOptions::from_query(&query)?;
    Ok(Json(
        record_timeline(&state, &ctx, &entity_input, record_id, &opts).await?,
    ))
}

/// The most entries one timeline export holds.
pub const MAX_TIMELINE_EXPORT: usize = 2000;

/// Query string for `GET /api/v1/{entity}/{id}/timeline/export`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimelineExportQuery {
    /// Comma-separated kinds to include, as for the timeline itself.
    pub kinds: Option<String>,
}

/// One CSV cell: quoted when it holds a comma, quote or line break, and
/// prefixed with an apostrophe when a spreadsheet would read it as a formula.
fn csv_cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// The timeline as CSV: when, what kind, the summary, and where it came from.
pub fn timeline_csv(entries: &[TimelineEntry]) -> String {
    let mut out = String::from("occurred_at,kind,summary,source_entity,source_id\r\n");
    for entry in entries {
        let kind = serde_json::to_value(entry.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let row = [
            entry.occurred_at.to_rfc3339(),
            kind,
            entry.summary.clone(),
            entry.source_entity.clone(),
            entry.source_id.to_string(),
        ];
        out.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// B1-T4: the record's timeline, filtered by kind, as a CSV file: the same
/// entries, under the same permissions, as the timeline itself, newest
/// first, up to 2000.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/timeline/export",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        TimelineExportQuery,
    ),
    responses(
        (status = 200, description = "The timeline as CSV", body = String, content_type = "text/csv"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "Unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn export_record_timeline(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(query): Query<TimelineExportQuery>,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;
    let mut opts = TimelineOptions::from_query(&TimelineQuery {
        cursor: None,
        page_size: Some(MAX_PAGE_SIZE),
        kinds: query.kinds,
    })?;
    let mut entries = Vec::new();
    loop {
        let page = record_timeline(&state, &ctx, &entity_input, record_id, &opts).await?;
        entries.extend(page.items);
        let Some(next) = page.next_cursor else { break };
        if entries.len() >= MAX_TIMELINE_EXPORT {
            break;
        }
        opts.cursor = Some(decode_timeline_cursor(&next)?);
    }
    entries.truncate(MAX_TIMELINE_EXPORT);
    let file = format!("attachment; filename=\"timeline-{record_id}.csv\"");
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_owned(),
            ),
            (axum::http::header::CONTENT_DISPOSITION, file),
        ],
        // A byte-order mark so spreadsheet programs read Arabic as UTF-8.
        format!("\u{feff}{}", timeline_csv(&entries)),
    )
        .into_response())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_record_timeline, export_record_timeline))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_csv_quotes_and_guards_cells() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a, b"), "\"a, b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=SUM(A1)"), "'=SUM(A1)");
        let entry = TimelineEntry {
            kind: TimelineEntryKind::Note,
            occurred_at: "2026-10-14T10:00:00Z".parse().unwrap(),
            source_entity: "note".into(),
            source_id: Uuid::nil(),
            summary: "ملاحظة, مهمة".into(),
            detail: Value::Null,
        };
        let csv = timeline_csv(&[entry]);
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines[0], "occurred_at,kind,summary,source_entity,source_id");
        assert!(lines[1].starts_with("2026-10-14T10:00:00+00:00,note,\"ملاحظة, مهمة\",note,"));
    }

    #[test]
    fn cursor_round_trips() {
        let id = Uuid::now_v7();
        let raw = encode_cursor(1_700_000_000_123_456, "note", id);
        let c = decode_timeline_cursor(&raw).expect("decode");
        assert_eq!(c.occurred_micros, 1_700_000_000_123_456);
        assert_eq!(c.kind, TimelineEntryKind::Note);
        assert_eq!(c.source_id, id);
    }

    #[test]
    fn malformed_cursors_are_validation_errors() {
        for raw in [
            "not base64 !!",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("x:note:y"),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode("12:bogus:0196f3a0-0000-7000-8000-000000000000"),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("12:note"),
        ] {
            let got = decode_timeline_cursor(raw);
            assert!(
                matches!(got, Err(AppError::Validation(_))),
                "{raw}: {got:?}"
            );
        }
    }

    #[test]
    fn unknown_kind_is_a_validation_error() {
        let q = TimelineQuery {
            kinds: Some("note,bogus".into()),
            ..Default::default()
        };
        assert!(matches!(
            TimelineOptions::from_query(&q),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn page_size_is_clamped() {
        assert_eq!(clamp_page_size(None), DEFAULT_PAGE_SIZE);
        assert_eq!(clamp_page_size(Some(0)), 1);
        assert_eq!(clamp_page_size(Some(10_000)), MAX_PAGE_SIZE);
    }

    #[test]
    fn keyset_depends_on_kind_order() {
        let c = TimelineCursor {
            occurred_micros: 1,
            kind: TimelineEntryKind::Communication,
            source_id: Uuid::nil(),
        };
        // "note" > "communication": equal timestamps still come after.
        let (sql, id) = keyset_sql(Some(&c), TimelineEntryKind::Note, "x", "t.id", 4, 5).unwrap();
        assert_eq!(sql, "AND x <= $4");
        assert!(!id);
        // "audit_event" < "communication": only strictly older rows.
        let (sql, _) =
            keyset_sql(Some(&c), TimelineEntryKind::AuditEvent, "x", "t.id", 4, 5).unwrap();
        assert_eq!(sql, "AND x < $4");
        let (sql, id) = keyset_sql(
            Some(&c),
            TimelineEntryKind::Communication,
            "x",
            "t.id",
            4,
            5,
        )
        .unwrap();
        assert_eq!(sql, "AND (x < $4 OR (x = $4 AND t.id < $5))");
        assert!(id);
        assert!(keyset_sql(None, TimelineEntryKind::Note, "x", "t.id", 4, 5).is_none());
    }
}

//! `GET /api/v1/{entity}/{id}/timeline` — one record's activity feed, for any
//! entity (basic-units plan U3, ruling B-R4, recorded as D-601; B1-T1 added
//! approvals, flow and agent runs, provenance, related records and filters).
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
//! - `communication`, `note`, `activity` (tasks are activities) — polymorphic
//!   children (`entity_name` + `record_id`) on `communication`, `note`,
//!   `activity`, each read only when the entity is registered;
//! - `decision` — `dashboard_decision` rows linked through
//!   `record_relationship` in either direction;
//! - `approval` — `approval_request` rows regarding the record (its action,
//!   status and step; never its payload);
//! - `flow_run` — `workflow_instance` runs correlated with the record;
//! - `agent_run` — one entry per agent session that changed the record, from
//!   the audit rows it wrote (`initiator = 1`).
//!
//! **Provenance.** Every entry carries `actor` (the user who acted, or for
//! whom an agent acted), `actor_kind` (`person`, `agent`, `flow`, `system`),
//! `run_id` (the agent session or flow instance, when there is one) and
//! `source_record` (the record the underlying row belongs to).
//!
//! **Related records.** The setting `records.timeline_roll_in` lists, per
//! entity, the child relationships whose records roll in (an account rolls
//! in its contacts' and opportunities' entries): `{"account": [{"entity":
//! "contact", "via": "account_id"}]}`. `via` must be a lookup on the child
//! that targets this entity. The caller must hold `{child}.read` and read the
//! lookup; the child rows pass the child's own row security, and at most
//! [`ROLL_IN_RECORDS`] newest children per relationship roll in. A rolled-in
//! record's entries are read exactly as its own timeline would read them.
//! Decisions are the record's own only. `related=false` turns roll-in off.
//!
//! **Pins** (B1-T2). An entry can be pinned on the record
//! (`timeline_pin`, migration 0284; `PUT`/`DELETE
//! /api/v1/{entity}/{id}/timeline/pins/{kind}/{source_id}`). Each entry says
//! whether it is pinned, and `pinned_only=true` reads only the pinned
//! entries, through the same sources and permissions, so a pin never shows
//! an entry its reader may not see.
//!
//! **Filters.** `kinds`, `actor`, `channel` (communications only: any other
//! kind is left out while it is set), `from`/`to` (half-open, on the entry's
//! time) and `q`: words matched (case-insensitively, as a substring) against
//! the text a source's summary is built from, readable columns only. Each
//! filter is part of every source's SQL, so paging stays exact.
//!
//! **Authorization.**
//! 1. The record itself: `{entity}.read` plus `require_record_read`, the exact
//!    decision `GET /api/v1/{entity}/{id}` makes; a record the caller cannot
//!    read, or that does not exist, is `NotFound`.
//! 2. Audit rows (audit events, transitions and agent runs), approvals and
//!    flow runs are gated by that record alone — the D-147 rule for the audit
//!    family: nobody holds a share on an individual audit entry. Their field
//!    names and values follow the record read's field-security filter (B-R12):
//!    a sensitive field the caller has no read grant for is never named, and a
//!    sensitive field's values are never shown.
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
//! An entry reached through two records (a communication linked to an account
//! and to its rolled-in contact) appears once. Timestamps travel as integer
//! microseconds (PostgreSQL's own precision), so entries sharing one timestamp
//! page without loss or repetition. Migration 0283 indexes the audit and
//! approval sources by record, newest first.

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

/// B1-T1: the setting listing each entity's rolled-in relationships.
pub const ROLL_IN_SETTING: &str = "records.timeline_roll_in";

/// B1-T1: the most child records one relationship rolls in (the newest).
pub const ROLL_IN_RECORDS: i64 = 200;

/// B1-T1: the most relationships one entity rolls in.
const MAX_ROLL_IN_RELATIONS: usize = 10;

/// The longest `q` accepted.
const MAX_QUERY_CHARS: usize = 200;

/// One entry in a record's timeline.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelineEntry {
    pub kind: TimelineEntryKind,
    pub occurred_at: DateTime<Utc>,
    /// The entity or ledger table the underlying row belongs to —
    /// `audit_header`, `audit_detail` (state transitions),
    /// `communication`, `note`, `activity`, `dashboard_decision`,
    /// `approval_request`, `workflow_instance` or `agent_session`.
    pub source_entity: String,
    pub source_id: Uuid,
    /// Short, human-readable description of the event.
    pub summary: String,
    /// Kind-specific detail (audit operation and readable changed fields,
    /// communication subject/channel, note title, activity type, decision
    /// status, approval action and status, flow name, agent actions, …). A
    /// JSON object rather than one struct with mostly-empty fields across
    /// unrelated shapes.
    pub detail: Value,
    /// B1-T1: who acted — the user, or the user an agent or flow acted for.
    pub actor: Option<Uuid>,
    /// B1-T1: what kind of actor made the entry.
    pub actor_kind: ActorKind,
    /// B1-T1: the agent session or flow instance, when the entry came from one.
    pub run_id: Option<Uuid>,
    /// B1-T1: the record the underlying row belongs to: this record, or a
    /// related record rolled in.
    pub source_record: SourceRecord,
    /// B1-T2: pinned on this record, shown above the rest.
    pub pinned: bool,
}

/// B1-T1: who made a timeline entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Person,
    Agent,
    Flow,
    System,
}

/// B1-T1: the record an entry's row belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SourceRecord {
    pub entity: String,
    pub id: Uuid,
}

/// The source an entry came from. Entries sort by their wire name within one
/// timestamp, so the order is stable and documented: `activity`,
/// `agent_run`, `approval`, `audit_event`, `communication`, `decision`,
/// `flow_run`, `note`, `state_transition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEntryKind {
    AuditEvent,
    StateTransition,
    Communication,
    Decision,
    Note,
    Activity,
    Approval,
    FlowRun,
    AgentRun,
}

impl TimelineEntryKind {
    pub const ALL: [TimelineEntryKind; 9] = [
        TimelineEntryKind::AuditEvent,
        TimelineEntryKind::StateTransition,
        TimelineEntryKind::Communication,
        TimelineEntryKind::Decision,
        TimelineEntryKind::Note,
        TimelineEntryKind::Activity,
        TimelineEntryKind::Approval,
        TimelineEntryKind::FlowRun,
        TimelineEntryKind::AgentRun,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuditEvent => "audit_event",
            Self::StateTransition => "state_transition",
            Self::Communication => "communication",
            Self::Decision => "decision",
            Self::Note => "note",
            Self::Activity => "activity",
            Self::Approval => "approval",
            Self::FlowRun => "flow_run",
            Self::AgentRun => "agent_run",
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
    /// `communication`, `note`, `activity`, `decision`, `approval`,
    /// `flow_run`, `agent_run`). Omitted or empty means every kind. An unknown
    /// kind is a 422.
    pub kinds: Option<String>,
    /// Only entries this user made (or an agent or flow made for them).
    pub actor: Option<Uuid>,
    /// Only communications on this channel (`email`, `phone`, …).
    pub channel: Option<String>,
    /// Only entries at or after this time.
    pub from: Option<DateTime<Utc>>,
    /// Only entries before this time.
    pub to: Option<DateTime<Utc>>,
    /// Words to find in the entries' text, up to 200 characters.
    pub q: Option<String>,
    /// Whether related records roll in (`records.timeline_roll_in`); default
    /// true.
    pub related: Option<bool>,
    /// B1-T2: only the entries pinned on this record.
    pub pinned_only: Option<bool>,
}

/// A position in the timeline's global order: the last entry of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelineCursor {
    pub occurred_micros: i64,
    pub kind: TimelineEntryKind,
    pub source_id: Uuid,
}

/// B1-T1: the timeline's filters besides kind.
#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    pub actor: Option<Uuid>,
    pub channel: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub q: Option<String>,
    /// B1-T2: the pinned entries' ids by kind, when only those are wanted
    /// (set by [`record_timeline`], never by a client).
    pub pinned: Option<std::collections::HashMap<TimelineEntryKind, Vec<Uuid>>>,
}

/// Validated timeline options, for non-HTTP callers (the ticket route).
#[derive(Debug, Clone)]
pub struct TimelineOptions {
    pub cursor: Option<TimelineCursor>,
    pub page_size: i64,
    /// `None` = every kind.
    pub kinds: Option<HashSet<TimelineEntryKind>>,
    pub filter: TimelineFilter,
    /// Whether the configured related records roll in.
    pub related: bool,
    /// B1-T2: only the entries pinned on this record.
    pub pinned_only: bool,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            kinds: None,
            filter: TimelineFilter::default(),
            related: true,
            pinned_only: false,
        }
    }
}

impl TimelineOptions {
    /// Validates a raw query: 422 on a malformed cursor, an unknown kind, a
    /// `from` not before `to`, or a `q` over 200 characters.
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
        if let (Some(from), Some(to)) = (q.from, q.to)
            && from >= to
        {
            return Err(AppError::Validation("from must be before to".into()));
        }
        let words =
            q.q.as_deref()
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .map(str::to_owned);
        if words
            .as_ref()
            .is_some_and(|w| w.chars().count() > MAX_QUERY_CHARS)
        {
            return Err(AppError::Validation("q is at most 200 characters".into()));
        }
        Ok(Self {
            cursor,
            page_size: clamp_page_size(q.page_size),
            kinds,
            filter: TimelineFilter {
                actor: q.actor,
                channel: q
                    .channel
                    .as_deref()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned),
                from: q.from,
                to: q.to,
                q: words,
                pinned: None,
            },
            related: q.related.unwrap_or(true),
            pinned_only: q.pinned_only.unwrap_or(false),
        })
    }

    fn wants(&self, kind: TimelineEntryKind) -> bool {
        // A channel is a communication's: every other kind is left out.
        if self.filter.channel.is_some() && kind != TimelineEntryKind::Communication {
            return false;
        }
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

// ── SQL pieces ───────────────────────────────────────────────────────────────

/// Adds a bind and returns its placeholder.
fn ph(binds: &mut Vec<SourceBind>, bind: SourceBind) -> String {
    binds.push(bind);
    format!("${}", binds.len())
}

/// The keyset condition one source applies, given the cursor and the source's
/// own (constant) kind — see the module doc's **Paging**. `occ` is the
/// source's timestamp expression, `id` its id column; the cursor's values are
/// bound as they are needed.
fn keyset_sql(
    cursor: Option<&TimelineCursor>,
    kind: TimelineEntryKind,
    occ: &str,
    id: &str,
    binds: &mut Vec<SourceBind>,
) -> Result<String, AppError> {
    let Some(cursor) = cursor else {
        return Ok(String::new());
    };
    let ts = ph(
        binds,
        SourceBind::Ts(micros_to_datetime(cursor.occurred_micros)?),
    );
    Ok(match kind.as_str().cmp(cursor.kind.as_str()) {
        std::cmp::Ordering::Greater => format!("AND {occ} <= {ts}"),
        std::cmp::Ordering::Less => format!("AND {occ} < {ts}"),
        std::cmp::Ordering::Equal => {
            let idp = ph(binds, SourceBind::Id(cursor.source_id));
            format!("AND ({occ} < {ts} OR ({occ} = {ts} AND {id} < {idp}))")
        }
    })
}

/// A `LIKE` pattern finding `words` anywhere, its wildcards escaped.
fn like_pattern(words: &str) -> String {
    let escaped = words
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// The filter conditions one source applies. `actor` is the source's actor
/// column (`None`: it has none, so an actor filter matches nothing); `text`
/// the expressions its summary is built from, readable ones only (empty: the
/// words match nothing).
fn filter_sql(
    filter: &TimelineFilter,
    occ: &str,
    actor: Option<&str>,
    text: &[String],
    binds: &mut Vec<SourceBind>,
) -> String {
    let mut sql = String::new();
    if let Some(from) = filter.from {
        let p = ph(binds, SourceBind::Ts(from));
        sql.push_str(&format!(" AND {occ} >= {p}"));
    }
    if let Some(to) = filter.to {
        let p = ph(binds, SourceBind::Ts(to));
        sql.push_str(&format!(" AND {occ} < {p}"));
    }
    if let Some(who) = filter.actor {
        match actor {
            Some(col) => {
                let p = ph(binds, SourceBind::Id(who));
                sql.push_str(&format!(" AND {col} = {p}"));
            }
            None => sql.push_str(" AND false"),
        }
    }
    if let Some(words) = &filter.q {
        if text.is_empty() {
            sql.push_str(" AND false");
        } else {
            let p = ph(binds, SourceBind::Text(like_pattern(words)));
            let hay = text
                .iter()
                .map(|t| format!("coalesce(({t})::text, '')"))
                .collect::<Vec<_>>()
                .join(" || ' ' || ");
            sql.push_str(&format!(" AND ({hay}) ILIKE {p}"));
        }
    }
    sql
}

/// `col = $n` for one record, `col = ANY($n)` for several (one keeps the
/// newest-first index order usable).
fn record_match(col: &str, ids: &[Uuid], as_text: bool, binds: &mut Vec<SourceBind>) -> String {
    match (ids, as_text) {
        ([one], false) => format!("{col} = {}", ph(binds, SourceBind::Id(*one))),
        ([one], true) => format!("{col} = {}", ph(binds, SourceBind::Text(one.to_string()))),
        (many, false) => format!(
            "{col} = ANY({})",
            ph(binds, SourceBind::IdList(many.to_vec()))
        ),
        (many, true) => format!(
            "{col} = ANY({})",
            ph(
                binds,
                SourceBind::TextList(many.iter().map(Uuid::to_string).collect())
            )
        ),
    }
}

/// B1-T2: with only pinned entries wanted, a source keeps its pinned ids
/// (none pinned: nothing). Empty otherwise.
fn pin_sql(
    filter: &TimelineFilter,
    kind: TimelineEntryKind,
    id: &str,
    binds: &mut Vec<SourceBind>,
) -> String {
    let Some(pinned) = &filter.pinned else {
        return String::new();
    };
    match pinned.get(&kind) {
        Some(ids) if !ids.is_empty() => {
            format!(
                " AND {id} = ANY({})",
                ph(binds, SourceBind::IdList(ids.clone()))
            )
        }
        _ => " AND false".to_owned(),
    }
}

/// B1-T2: the most entries one record holds pinned.
pub const MAX_PINS: i64 = 50;

/// B1-T2: the entries pinned on a record, as `(kind, source id)`.
pub async fn read_pins(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
) -> Result<HashSet<(TimelineEntryKind, Uuid)>, AppError> {
    let rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT kind, source_id FROM timeline_pin WHERE entity_name = $1 AND record_id = $2 \
          ORDER BY pinned_at DESC LIMIT $3",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(MAX_PINS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, id)| TimelineEntryKind::parse(&kind).map(|k| (k, id)))
        .collect())
}

/// The epoch-microseconds expression the sources sort and page by.
fn micros_sql(occ: &str) -> String {
    format!("(EXTRACT(EPOCH FROM {occ}) * 1000000)::bigint")
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
        .filter(|a| !a.is_read_gated() || ctx.has_field_read_grant(entity_name, &a.logicalname))
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// The records one timeline reads: the record itself, then each rolled-in
/// entity's related records.
struct Target {
    entity: String,
    attrs: Vec<AttrInfo>,
    ids: Vec<Uuid>,
}

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

    let mut targets = vec![Target {
        entity: entity_name.clone(),
        attrs,
        ids: vec![record_id],
    }];
    if opts.related {
        targets.extend(related_targets(state, ctx, entity_id, &entity_name, record_id).await?);
    }

    // B1-T2: what is pinned on the record; with `pinned_only`, every source
    // reads only those entries (under its own permissions, as always).
    let pins = read_pins(state, &entity_name, record_id).await?;
    let pinned_opts;
    let opts = if opts.pinned_only {
        if pins.is_empty() {
            return Ok(CursorPage::new(Vec::new(), None));
        }
        let mut by_kind: std::collections::HashMap<TimelineEntryKind, Vec<Uuid>> =
            std::collections::HashMap::new();
        for (kind, id) in &pins {
            by_kind.entry(*kind).or_default().push(*id);
        }
        let mut narrowed = opts.clone();
        narrowed.filter.pinned = Some(by_kind);
        pinned_opts = narrowed;
        &pinned_opts
    } else {
        opts
    };

    let limit = opts.page_size + 1;
    let mut rows: Vec<(i64, TimelineEntry)> = Vec::new();
    for target in &targets {
        if opts.wants(TimelineEntryKind::AuditEvent) {
            rows.extend(fetch_audit_events(state, ctx, target, opts, limit).await?);
        }
        if opts.wants(TimelineEntryKind::StateTransition) {
            rows.extend(fetch_state_transitions(state, ctx, target, opts, limit).await?);
        }
        for source in CHILD_SOURCES {
            if opts.wants(source.kind) {
                rows.extend(fetch_child_source(state, ctx, source, target, opts, limit).await?);
            }
        }
        if opts.wants(TimelineEntryKind::Approval) {
            rows.extend(fetch_approvals(state, target, opts, limit).await?);
        }
        if opts.wants(TimelineEntryKind::FlowRun) {
            rows.extend(fetch_flow_runs(state, target, opts, limit).await?);
        }
        if opts.wants(TimelineEntryKind::AgentRun) {
            rows.extend(fetch_agent_runs(state, target, opts, limit).await?);
        }
    }
    if opts.wants(TimelineEntryKind::Decision) {
        rows.extend(
            fetch_linked_decisions(state, ctx, &entity_name, record_id, opts, limit).await?,
        );
    }

    // Stable: the record's own copy of an entry reached twice stays first.
    rows.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    rows.dedup_by(|b, a| a.1.kind == b.1.kind && a.1.source_id == b.1.source_id && a.0 == b.0);
    let has_more = rows.len() as i64 > opts.page_size;
    rows.truncate(opts.page_size as usize);
    for (_, entry) in &mut rows {
        entry.pinned = pins.contains(&(entry.kind, entry.source_id));
    }
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

/// One rolled-in relationship of `records.timeline_roll_in`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RollIn {
    /// The child entity.
    pub entity: String,
    /// Its lookup to the record's entity.
    pub via: String,
}

/// The relationships `entity_name` rolls in, from the setting; a malformed
/// entry is skipped.
pub fn roll_in_config(state: &EngineState, entity_name: &str) -> Vec<RollIn> {
    let Some(descriptor) = attome_core::setting_registry().get(ROLL_IN_SETTING) else {
        return Vec::new();
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    parse_roll_in(&value, entity_name)
}

fn parse_roll_in(value: &Value, entity_name: &str) -> Vec<RollIn> {
    value
        .get(entity_name)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value::<RollIn>(item.clone()).ok())
                .take(MAX_ROLL_IN_RELATIONS)
                .collect()
        })
        .unwrap_or_default()
}

/// The related records the caller may read, per configured relationship;
/// relationships to one child entity merge.
async fn related_targets(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
) -> Result<Vec<Target>, AppError> {
    let mut targets: Vec<Target> = Vec::new();
    for roll in roll_in_config(state, entity_name) {
        if ctx.require(&roll.entity, "read").is_err() {
            continue;
        }
        let Some(meta) = state.entities.load().get(roll.entity.as_str()).cloned() else {
            continue;
        };
        let is_lookup_here = meta
            .attrs
            .iter()
            .any(|a| a.logicalname == roll.via && a.lookup_entity_ref == Some(entity_id));
        if !is_lookup_here {
            tracing::warn!(
                entity = entity_name,
                child = %roll.entity,
                via = %roll.via,
                "records.timeline_roll_in: not a lookup to this entity; skipped"
            );
            continue;
        }
        if readable_attr(ctx, &roll.entity, &meta.attrs, &roll.via).is_none() {
            continue;
        }
        let live = attome_core::live_row_predicate("t", meta.is_append_only)
            .map(|p| format!("AND {p}"))
            .unwrap_or_default();
        let sql = format!(
            "SELECT jsonb_build_object('id', t.id) FROM {table} t \
             WHERE t.{via} = $1 {live} {{rls}} ORDER BY t.id DESC LIMIT $2",
            table = quote_ident(&roll.entity),
            via = quote_ident(&roll.via),
        );
        let rows = run_source_query(
            state,
            ctx,
            &roll.entity,
            meta.entity_id,
            &meta.attrs,
            &sql,
            vec![SourceBind::Id(record_id), SourceBind::Int(ROLL_IN_RECORDS)],
        )
        .await?;
        let ids: Vec<Uuid> = rows
            .iter()
            .filter_map(|r| r.get("id").and_then(Value::as_str))
            .filter_map(|s| Uuid::parse_str(s).ok())
            .filter(|id| *id != record_id)
            .collect();
        if ids.is_empty() {
            continue;
        }
        match targets.iter_mut().find(|t| t.entity == roll.entity) {
            Some(target) => {
                for id in ids {
                    if !target.ids.contains(&id) {
                        target.ids.push(id);
                    }
                }
            }
            None => targets.push(Target {
                entity: roll.entity.clone(),
                attrs: meta.attrs.clone(),
                ids,
            }),
        }
    }
    Ok(targets)
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

// ── Rows ─────────────────────────────────────────────────────────────────────

/// One source row as the queries build it:
/// `jsonb_build_object('id', …, 'micros', …, 'record', …, 'actor', …,
/// 'detail', …)`, with `record_entity`, `initiator`, `source`, `run` and
/// `created_by` where the source has them.
struct SourceRow {
    micros: i64,
    id: Uuid,
    record_entity: Option<String>,
    record: Option<Uuid>,
    actor: Option<Uuid>,
    initiator: Option<i64>,
    source: Option<i64>,
    run: Option<Uuid>,
    detail: Value,
}

fn uuid_of(row: &Value, key: &str) -> Option<Uuid> {
    row.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn decode_row(row: &Value) -> Option<SourceRow> {
    let mut detail = row.get("detail").cloned().unwrap_or(Value::Null);
    if let (Value::Object(map), Some(by)) = (&mut detail, row.get("created_by")) {
        map.insert("created_by".into(), by.clone());
    }
    Some(SourceRow {
        micros: row.get("micros").and_then(Value::as_i64)?,
        id: uuid_of(row, "id")?,
        record_entity: row
            .get("record_entity")
            .and_then(Value::as_str)
            .map(str::to_owned),
        record: uuid_of(row, "record"),
        actor: uuid_of(row, "actor"),
        initiator: row.get("initiator").and_then(Value::as_i64),
        source: row.get("source").and_then(Value::as_i64),
        run: uuid_of(row, "run"),
        detail,
    })
}

/// An audit row's actor kind: `initiator` 1 is an agent, 2 the system; a row
/// written by the workflow engine (`source` 4) is a flow's.
fn audit_actor_kind(initiator: Option<i64>, source: Option<i64>) -> ActorKind {
    match (initiator, source) {
        (Some(1), _) => ActorKind::Agent,
        (Some(2), _) => ActorKind::System,
        (_, Some(4)) => ActorKind::Flow,
        _ => ActorKind::Person,
    }
}

/// Turns decoded rows into entries; `summary` builds each one's summary from
/// its detail. `fallback` is the record a row without its own belongs to.
fn entries(
    rows: &[Value],
    kind: TimelineEntryKind,
    source_entity: &str,
    fallback: (&str, Uuid),
    actor_kind: impl Fn(&SourceRow) -> ActorKind,
    summary: impl Fn(&Value) -> String,
) -> Vec<(i64, TimelineEntry)> {
    rows.iter()
        .filter_map(decode_row)
        .filter_map(|row| {
            let occurred_at = micros_to_datetime(row.micros).ok()?;
            let source_record = SourceRecord {
                entity: row
                    .record_entity
                    .clone()
                    .unwrap_or_else(|| fallback.0.to_owned()),
                id: row.record.unwrap_or(fallback.1),
            };
            let entry = TimelineEntry {
                kind,
                occurred_at,
                source_entity: source_entity.to_owned(),
                source_id: row.id,
                summary: summary(&row.detail),
                actor: row.actor,
                actor_kind: actor_kind(&row),
                run_id: row.run,
                source_record,
                detail: row.detail,
                pinned: false,
            };
            Some((row.micros, entry))
        })
        .collect()
}

/// Runs a source query with no row security of its own (the audit family,
/// approvals and flow runs: gated by the record).
async fn run_plain_query(
    state: &EngineState,
    sql: &str,
    binds: Vec<SourceBind>,
) -> Result<Vec<Value>, AppError> {
    let sql = attome_db::tag_dynamic("entity.timeline", sql);
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for b in binds {
        q = bind_source(q, b);
    }
    q.fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

fn bind_source<'q>(
    q: sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>,
    b: SourceBind,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments> {
    match b {
        SourceBind::Text(s) => q.bind(s),
        SourceBind::Int(i) => q.bind(i),
        SourceBind::Ts(t) => q.bind(t),
        SourceBind::Id(u) => q.bind(u),
        SourceBind::TextList(v) => q.bind(v),
        SourceBind::IdList(v) => q.bind(v),
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

async fn fetch_audit_events(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    opts: &TimelineOptions,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::AuditEvent;
    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(target.entity.clone()));
    let record = record_match("h.record_id", &target.ids, false, &mut binds);
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(
        opts.cursor.as_ref(),
        kind,
        "h.changed_on",
        "h.id",
        &mut binds,
    )?;
    let text = [
        "h.event_name".to_owned(),
        "h.event_comment".to_owned(),
        "h.user_display_name".to_owned(),
    ];
    let filter = filter_sql(
        &opts.filter,
        "h.changed_on",
        Some("h.user_id"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "h.id", &mut binds);
    let sql = format!(
        "SELECT jsonb_build_object('id', h.id, 'micros', {micros}, 'record', h.record_id, \
                'actor', h.user_id, 'initiator', h.initiator, 'source', h.source, \
                'run', CASE WHEN h.initiator = 1 THEN h.agent_session_id \
                            WHEN h.source = 4 THEN h.correlation_id END, \
                'detail', jsonb_build_object('operation', h.operation, \
                    'event_name', h.event_name, 'event_comment', h.event_comment, \
                    'user_display_name', h.user_display_name, \
                    'changed_fields', ARRAY(SELECT d.field_name::text FROM audit_detail d \
                        WHERE d.audit_ref = h.id AND d.field_name IS NOT NULL \
                        ORDER BY d.field_name))) \
         FROM audit_header h \
         WHERE h.entity_name = {entity} AND {record} AND h.changed_on IS NOT NULL {keyset} {filter}{pins} \
         ORDER BY h.changed_on DESC, h.id DESC LIMIT {lim}",
        micros = micros_sql("h.changed_on"),
    );
    let rows = run_plain_query(state, &sql, binds).await?;
    let fallback = (target.entity.as_str(), target.ids[0]);
    let mut out = entries(
        &rows,
        kind,
        "audit_header",
        fallback,
        |r| audit_actor_kind(r.initiator, r.source),
        |_| String::new(),
    );
    // The summary and the changed fields follow the field filter.
    for (_, entry) in &mut out {
        let detail = &mut entry.detail;
        let op = audit_operation_label(
            detail
                .get("operation")
                .and_then(Value::as_i64)
                .and_then(|o| i32::try_from(o).ok())
                .unwrap_or(-1),
        );
        let event_name = text_of(detail, "event_name").map(str::to_owned);
        let label = event_name.unwrap_or_else(|| op.to_owned());
        // A blank stored name reads as no name ("updated by " with nothing
        // after it otherwise).
        let by = text_of(detail, "user_display_name")
            .filter(|n| !n.trim().is_empty())
            .unwrap_or("system")
            .to_owned();
        entry.summary = format!("{label} by {by}");
        if let Value::Object(map) = detail {
            map.insert("operation".into(), Value::from(op));
            let fields: Vec<Value> = map
                .get("changed_fields")
                .and_then(Value::as_array)
                .map(|f| {
                    f.iter()
                        .filter_map(Value::as_str)
                        .filter(|f| readable_attr(ctx, &target.entity, &target.attrs, f).is_some())
                        .map(Value::from)
                        .collect()
                })
                .unwrap_or_default();
            map.insert("changed_fields".into(), Value::Array(fields));
        }
    }
    Ok(out)
}

/// The entity's state-field changes, read from the audit trail. The field is
/// the one the entity's state model names (`EngineState::state_models`), never a
/// hard-coded column; an entity with no state model has no transitions here.
async fn fetch_state_transitions(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    opts: &TimelineOptions,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::StateTransition;
    let state_field = {
        let models = state.state_models.load();
        match models.get(&target.entity).and_then(|e| e.model.as_ref()) {
            Some(model) => model.state_field.clone(),
            None => return Ok(Vec::new()),
        }
    };
    // B-R12: a state field the caller cannot read is not shown at all.
    let Some(attr) = readable_attr(ctx, &target.entity, &target.attrs, &state_field) else {
        return Ok(Vec::new());
    };
    let attr_sensitive = attr.is_read_gated();

    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(target.entity.clone()));
    let record = record_match("h.record_id", &target.ids, false, &mut binds);
    let field = ph(&mut binds, SourceBind::Text(state_field.clone()));
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(
        opts.cursor.as_ref(),
        kind,
        "h.changed_on",
        "d.id",
        &mut binds,
    )?;
    // Masked values are never searched.
    let text = if attr_sensitive {
        Vec::new()
    } else {
        vec![
            "CASE WHEN coalesce(d.is_sensitive, false) THEN NULL \
              ELSE coalesce(d.old_value, '') || ' ' || coalesce(d.new_value, '') END"
                .to_owned(),
        ]
    };
    let filter = filter_sql(
        &opts.filter,
        "h.changed_on",
        Some("h.user_id"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "d.id", &mut binds);
    let sql = format!(
        "SELECT jsonb_build_object('id', d.id, 'micros', {micros}, 'record', h.record_id, \
                'actor', h.user_id, 'initiator', h.initiator, 'source', h.source, \
                'run', CASE WHEN h.initiator = 1 THEN h.agent_session_id \
                            WHEN h.source = 4 THEN h.correlation_id END, \
                'detail', jsonb_build_object('old_value', d.old_value, \
                    'new_value', d.new_value, 'masked', coalesce(d.is_sensitive, false))) \
         FROM audit_detail d \
         JOIN audit_header h ON h.id = d.audit_ref \
         WHERE h.entity_name = {entity} AND {record} AND d.field_name = {field} \
           AND h.changed_on IS NOT NULL {keyset} {filter}{pins} \
         ORDER BY h.changed_on DESC, d.id DESC LIMIT {lim}",
        micros = micros_sql("h.changed_on"),
    );
    let rows = run_plain_query(state, &sql, binds).await?;
    let mut out = entries(
        &rows,
        kind,
        "audit_detail",
        (target.entity.as_str(), target.ids[0]),
        |r| audit_actor_kind(r.initiator, r.source),
        |_| String::new(),
    );
    for (_, entry) in &mut out {
        let row_sensitive = entry
            .detail
            .get("masked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let masked = attr_sensitive || row_sensitive;
        let (old_value, new_value) = if masked {
            (None, None)
        } else {
            (
                text_of(&entry.detail, "old_value").map(str::to_owned),
                text_of(&entry.detail, "new_value").map(str::to_owned),
            )
        };
        entry.summary = if masked {
            format!("{state_field} changed")
        } else {
            let from = old_value.clone().unwrap_or_else(|| "?".to_string());
            let to = new_value.clone().unwrap_or_else(|| "?".to_string());
            format!("{state_field}: {from} -> {to}")
        };
        entry.detail = serde_json::json!({
            "field_name": state_field,
            "old_value": old_value,
            "new_value": new_value,
            "masked": masked,
        });
    }
    Ok(out)
}

/// One entry per agent session that changed the record, at its last change:
/// the actions it ran and how many changes it made. Its actor is the person
/// the agent acted for.
async fn fetch_agent_runs(
    state: &EngineState,
    target: &Target,
    opts: &TimelineOptions,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::AgentRun;
    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(target.entity.clone()));
    let record = record_match("h.record_id", &target.ids, false, &mut binds);
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(opts.cursor.as_ref(), kind, "r.occ", "r.session", &mut binds)?;
    let text = [
        "s.surface".to_owned(),
        "array_to_string(r.actions, ' ')".to_owned(),
    ];
    let filter = filter_sql(
        &opts.filter,
        "r.occ",
        Some("s.owner_user_id"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "r.session", &mut binds);
    let sql = format!(
        "SELECT jsonb_build_object('id', r.session, 'micros', {micros}, 'record', r.record_id, \
                'actor', s.owner_user_id, 'run', r.session, \
                'detail', jsonb_build_object('surface', s.surface, 'actions', to_jsonb(r.actions), \
                    'changes', r.changes, 'started_at', s.started_at, 'ended_at', s.ended_at)) \
         FROM (SELECT h.agent_session_id AS session, \
                      (array_agg(h.record_id ORDER BY h.changed_on DESC))[1] AS record_id, \
                      max(h.changed_on) AS occ, count(*) AS changes, \
                      array_remove(array_agg(DISTINCT h.agent_action_id::text), NULL) AS actions \
                 FROM audit_header h \
                WHERE h.entity_name = {entity} AND {record} AND h.initiator = 1 \
                  AND h.agent_session_id IS NOT NULL AND h.changed_on IS NOT NULL \
                GROUP BY h.agent_session_id) r \
         LEFT JOIN agent_session s ON s.id = r.session \
         WHERE true {keyset} {filter}{pins} \
         ORDER BY r.occ DESC, r.session DESC LIMIT {lim}",
        micros = micros_sql("r.occ"),
    );
    let rows = run_plain_query(state, &sql, binds).await?;
    Ok(entries(
        &rows,
        kind,
        "agent_session",
        (target.entity.as_str(), target.ids[0]),
        |_| ActorKind::Agent,
        |detail| {
            let changes = detail.get("changes").and_then(Value::as_i64).unwrap_or(0);
            let actions: Vec<&str> = detail
                .get("actions")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if actions.is_empty() {
                format!("Agent run: {changes} change(s)")
            } else {
                format!("Agent run: {} ({changes} change(s))", actions.join(", "))
            }
        },
    ))
}

// ── Approvals and flow runs ──────────────────────────────────────────────────

/// Approval requests regarding the record: the action, status and step, never
/// the payload.
async fn fetch_approvals(
    state: &EngineState,
    target: &Target,
    opts: &TimelineOptions,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::Approval;
    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(target.entity.clone()));
    let record = record_match("a.regarding_id", &target.ids, false, &mut binds);
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(
        opts.cursor.as_ref(),
        kind,
        "a.requested_at",
        "a.id",
        &mut binds,
    )?;
    let text = ["a.action_type".to_owned(), "a.status".to_owned()];
    let filter = filter_sql(
        &opts.filter,
        "a.requested_at",
        Some("a.requested_by"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "a.id", &mut binds);
    let sql = format!(
        "SELECT jsonb_build_object('id', a.id, 'micros', {micros}, 'record', a.regarding_id, \
                'actor', a.requested_by, \
                'detail', jsonb_build_object('action_type', a.action_type, 'status', a.status, \
                    'step', a.step, 'required_approvals', a.required_approvals)) \
         FROM approval_request a \
         WHERE a.regarding_entity = {entity} AND {record} {keyset} {filter}{pins} \
         ORDER BY a.requested_at DESC, a.id DESC LIMIT {lim}",
        micros = micros_sql("a.requested_at"),
    );
    let rows = run_plain_query(state, &sql, binds).await?;
    Ok(entries(
        &rows,
        kind,
        "approval_request",
        (target.entity.as_str(), target.ids[0]),
        |_| ActorKind::Person,
        |detail| {
            let action = text_of(detail, "action_type").unwrap_or("change");
            match text_of(detail, "status") {
                Some(status) => format!("Approval: {action} ({status})"),
                None => format!("Approval: {action}"),
            }
        },
    ))
}

/// Flow runs correlated with the record: the flow, and how the run stands.
async fn fetch_flow_runs(
    state: &EngineState,
    target: &Target,
    opts: &TimelineOptions,
    limit: i64,
) -> Result<Vec<(i64, TimelineEntry)>, AppError> {
    let kind = TimelineEntryKind::FlowRun;
    let mut binds = Vec::new();
    let record = record_match("w.correlation_entity_id", &target.ids, false, &mut binds);
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(
        opts.cursor.as_ref(),
        kind,
        "w.started_at",
        "w.id",
        &mut binds,
    )?;
    let text = [
        "d.name".to_owned(),
        "d.logicalname".to_owned(),
        "w.status".to_owned(),
    ];
    let filter = filter_sql(
        &opts.filter,
        "w.started_at",
        Some("w.started_by"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "w.id", &mut binds);
    let sql = format!(
        "SELECT jsonb_build_object('id', w.id, 'micros', {micros}, \
                'record', w.correlation_entity_id, 'actor', w.started_by, 'run', w.id, \
                'detail', jsonb_build_object('flow', d.logicalname, 'flow_name', d.name, \
                    'status', w.status, 'completed_at', w.completed_at)) \
         FROM workflow_instance w \
         LEFT JOIN workflow_definition_version v ON v.id = w.definition_version_id \
         LEFT JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE {record} {keyset} {filter}{pins} \
         ORDER BY w.started_at DESC, w.id DESC LIMIT {lim}",
        micros = micros_sql("w.started_at"),
    );
    let rows = run_plain_query(state, &sql, binds).await?;
    Ok(entries(
        &rows,
        kind,
        "workflow_instance",
        (target.entity.as_str(), target.ids[0]),
        |_| ActorKind::Flow,
        |detail| {
            let flow = text_of(detail, "flow_name")
                .or_else(|| text_of(detail, "flow"))
                .unwrap_or("(flow)");
            match text_of(detail, "status") {
                Some(status) => format!("Flow: {flow} ({status})"),
                None => format!("Flow: {flow}"),
            }
        },
    ))
}

// ── Polymorphic child sources ────────────────────────────────────────────────

/// One polymorphic-child source (B-R2's `entity_name` + `record_id` pair).
pub(super) struct ChildSource {
    kind: TimelineEntryKind,
    entity: &'static str,
    /// Columns copied into `detail` when the entity has them and the caller
    /// can read them.
    detail_columns: &'static [&'static str],
    /// The columns its summary is built from, which `q` searches.
    text_columns: &'static [&'static str],
    /// A date column preferred over `created_at` as the entry's time, when the
    /// entity has it (a communication's `sent_at`).
    time_column: Option<&'static str>,
    /// D15-T2: a link table that also places a row on other records
    /// (`communication_link`: one captured email, every matching record).
    link_table: Option<&'static str>,
}

/// `activity` is listed even where it is not yet provisioned (U2): a
/// source whose entity is not in the metadata registry is skipped.
const CHILD_SOURCES: &[ChildSource] = &[
    ChildSource {
        kind: TimelineEntryKind::Communication,
        entity: "communication",
        detail_columns: &["subject", "channel", "direction", "status"],
        text_columns: &["subject"],
        time_column: Some("sent_at"),
        link_table: Some("communication_link"),
    },
    ChildSource {
        kind: TimelineEntryKind::Note,
        entity: "note",
        detail_columns: &["title", "note_text"],
        text_columns: &["title", "note_text"],
        time_column: None,
        link_table: None,
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
        text_columns: &["subject", "activity_type"],
        time_column: None,
        link_table: None,
    },
];

/// `jsonb_build_object(...)` over the readable subset of `columns` on the
/// source entity, or an empty object.
pub(super) fn detail_object_sql(
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
pub(super) async fn run_source_query(
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
    for b in binds {
        q = bind_source(q, b);
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

pub(super) enum SourceBind {
    Text(String),
    Int(i64),
    Ts(DateTime<Utc>),
    Id(Uuid),
    TextList(Vec<String>),
    IdList(Vec<Uuid>),
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
    target: &Target,
    opts: &TimelineOptions,
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
    let readable = |c: &str| readable_attr(ctx, source.entity, &meta.attrs, c).is_some();
    let occ = match source.time_column.filter(|c| has(c)) {
        Some(c) => format!("COALESCE(t.{}, t.created_at)", quote_ident(c)),
        None => "t.created_at".to_owned(),
    };
    let detail = detail_object_sql(ctx, source.entity, &meta.attrs, source.detail_columns);
    let live = attome_core::live_row_predicate("t", meta.is_append_only)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();

    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(target.entity.clone()));
    let own = record_match("t.record_id", &target.ids, true, &mut binds);
    let lim = ph(&mut binds, SourceBind::Int(limit));
    // The row's own record, or (D15-T2) a record it is linked to; record
    // security on the row applies either way.
    let placed = match source.link_table {
        Some(link) => {
            let linked = record_match("l.record_id::text", &target.ids, true, &mut binds);
            format!(
                "((t.entity_name = {entity} AND {own}) OR t.id IN \
                  (SELECT l.communication_id FROM {} l WHERE l.entity_name = {entity} AND {linked}))",
                quote_ident(link)
            )
        }
        None => format!("t.entity_name = {entity} AND {own}"),
    };
    let keyset = keyset_sql(opts.cursor.as_ref(), source.kind, &occ, "t.id", &mut binds)?;
    let text: Vec<String> = source
        .text_columns
        .iter()
        .filter(|c| has(c) && readable(c))
        .map(|c| format!("t.{}", quote_ident(c)))
        .collect();
    let mut filter = filter_sql(&opts.filter, &occ, Some("t.created_by"), &text, &mut binds);
    let pins = pin_sql(&opts.filter, source.kind, "t.id", &mut binds);
    if let Some(channel) = &opts.filter.channel {
        if has("channel") && readable("channel") {
            let p = ph(&mut binds, SourceBind::Text(channel.clone()));
            filter.push_str(&format!(" AND t.channel::text = {p}"));
        } else {
            filter.push_str(" AND false");
        }
    }
    let table = quote_ident(source.entity);
    let sql = format!(
        "SELECT jsonb_build_object('id', t.id, 'micros', {micros}, \
                'record_entity', t.entity_name, 'record', t.record_id, \
                'actor', t.created_by, 'created_by', t.created_by, 'detail', {detail}) \
         FROM {table} t \
         WHERE {placed} AND {occ} IS NOT NULL {live} {keyset} {filter}{pins} {{rls}} \
         ORDER BY {occ} DESC, t.id DESC LIMIT {lim}",
        micros = micros_sql(&occ),
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
    Ok(entries(
        &rows,
        source.kind,
        source.entity,
        (target.entity.as_str(), target.ids[0]),
        |_| ActorKind::Person,
        |detail| child_summary(source.kind, detail),
    ))
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
    opts: &TimelineOptions,
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
    let mut binds = Vec::new();
    let entity = ph(&mut binds, SourceBind::Text(entity_name.to_owned()));
    let record = ph(&mut binds, SourceBind::Text(record_id.to_string()));
    let lim = ph(&mut binds, SourceBind::Int(limit));
    let keyset = keyset_sql(
        opts.cursor.as_ref(),
        kind,
        "t.created_at",
        "t.id",
        &mut binds,
    )?;
    let text: Vec<String> = ["title"]
        .into_iter()
        .filter(|c| readable_attr(ctx, DECISION_ENTITY, &meta.attrs, c).is_some())
        .map(|c| format!("t.{}", quote_ident(c)))
        .collect();
    let filter = filter_sql(
        &opts.filter,
        "t.created_at",
        Some("t.created_by"),
        &text,
        &mut binds,
    );
    let pins = pin_sql(&opts.filter, kind, "t.id", &mut binds);
    let table = quote_ident(DECISION_ENTITY);
    let sql = format!(
        "SELECT jsonb_build_object('id', t.id, 'micros', {micros}, \
                'actor', t.created_by, 'created_by', t.created_by, 'detail', {detail}) \
         FROM {table} t \
         WHERE t.id::text IN ( \
                SELECT lower(r.to_record_id) FROM record_relationship r \
                 WHERE r.is_active IS NOT FALSE AND r.from_entity_name = {entity} \
                   AND r.from_record_id = {record} AND r.to_entity_name = '{DECISION_ENTITY}' \
                UNION \
                SELECT lower(r.from_record_id) FROM record_relationship r \
                 WHERE r.is_active IS NOT FALSE AND r.to_entity_name = {entity} \
                   AND r.to_record_id = {record} AND r.from_entity_name = '{DECISION_ENTITY}') \
           AND t.created_at IS NOT NULL {live} {keyset} {filter}{pins} {{rls}} \
         ORDER BY t.created_at DESC, t.id DESC LIMIT {lim}",
        micros = micros_sql("t.created_at"),
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
    Ok(entries(
        &rows,
        kind,
        DECISION_ENTITY,
        (entity_name, record_id),
        |_| ActorKind::Person,
        |detail| {
            let title = text_of(detail, "title").unwrap_or("(untitled)");
            match text_of(detail, "status") {
                Some(status) => format!("Linked decision: {title} ({status})"),
                None => format!("Linked decision: {title}"),
            }
        },
    ))
}

// ── Route ────────────────────────────────────────────────────────────────────

/// A record's timeline
///
/// One record's activity feed: changes, communications, notes, tasks, approvals, flow and agent runs, with who or what made each entry, and the related records the deployment rolls in; filtered by kind, actor, channel, dates and words. For a caller who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/timeline",
    tag = "entity",
    operation_id = "get_record_timeline",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        TimelineQuery,
    ),
    responses(
        (status = 200, description = "One keyset page of the record's permission-filtered timeline", body = CursorPage<TimelineEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "Malformed cursor, unknown kind, from not before to, or q too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_record_timeline(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(mut query): Query<TimelineQuery>,
) -> Result<Json<CursorPage<TimelineEntry>>, AppError> {
    query.cursor = attome_types::cursor::open_opt(query.cursor.as_deref())?;
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

/// Export a record's timeline
///
/// B1-T4: the record's timeline, filtered by kind, as a CSV file: the same
/// entries, under the same permissions, as the timeline itself, newest
/// first, up to 2000.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/timeline/export",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
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
        ..Default::default()
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
            actor: None,
            actor_kind: ActorKind::Person,
            run_id: None,
            source_record: SourceRecord {
                entity: "contact".into(),
                id: Uuid::nil(),
            },
            pinned: false,
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
        let mut binds = vec![SourceBind::Int(1), SourceBind::Int(2), SourceBind::Int(3)];
        let sql = keyset_sql(Some(&c), TimelineEntryKind::Note, "x", "t.id", &mut binds).unwrap();
        assert_eq!(sql, "AND x <= $4");
        assert_eq!(binds.len(), 4);
        // "audit_event" < "communication": only strictly older rows.
        let mut binds = vec![SourceBind::Int(1), SourceBind::Int(2), SourceBind::Int(3)];
        let sql = keyset_sql(
            Some(&c),
            TimelineEntryKind::AuditEvent,
            "x",
            "t.id",
            &mut binds,
        )
        .unwrap();
        assert_eq!(sql, "AND x < $4");
        let mut binds = vec![SourceBind::Int(1), SourceBind::Int(2), SourceBind::Int(3)];
        let sql = keyset_sql(
            Some(&c),
            TimelineEntryKind::Communication,
            "x",
            "t.id",
            &mut binds,
        )
        .unwrap();
        assert_eq!(sql, "AND (x < $4 OR (x = $4 AND t.id < $5))");
        assert_eq!(binds.len(), 5);
        let mut binds = Vec::new();
        assert_eq!(
            keyset_sql(None, TimelineEntryKind::Note, "x", "t.id", &mut binds).unwrap(),
            ""
        );
        assert!(binds.is_empty());
    }

    // feature: B1
    #[test]
    fn filters_become_bound_conditions() {
        let filter = TimelineFilter {
            actor: Some(Uuid::nil()),
            channel: None,
            from: Some("2026-10-01T00:00:00Z".parse().unwrap()),
            to: Some("2026-11-01T00:00:00Z".parse().unwrap()),
            q: Some("50%_off".into()),
            pinned: None,
        };
        let mut binds = vec![SourceBind::Int(1)];
        let sql = filter_sql(
            &filter,
            "t.created_at",
            Some("t.created_by"),
            &["t.subject".to_owned()],
            &mut binds,
        );
        assert_eq!(
            sql,
            " AND t.created_at >= $2 AND t.created_at < $3 AND t.created_by = $4 \
             AND (coalesce((t.subject)::text, '')) ILIKE $5"
        );
        assert!(matches!(&binds[4], SourceBind::Text(p) if p == "%50\\%\\_off%"));
        // A source with no actor column or no searchable text matches nothing.
        let mut binds = Vec::new();
        let sql = filter_sql(&filter, "x", None, &[], &mut binds);
        assert!(sql.ends_with(" AND false AND false"), "{sql}");
    }

    // feature: B1
    #[test]
    fn one_record_matches_by_equality_and_several_by_any() {
        let one = [Uuid::nil()];
        let two = [Uuid::nil(), Uuid::max()];
        let mut binds = vec![SourceBind::Int(1)];
        assert_eq!(
            record_match("h.record_id", &one, false, &mut binds),
            "h.record_id = $2"
        );
        assert_eq!(
            record_match("t.record_id", &two, true, &mut binds),
            "t.record_id = ANY($3)"
        );
        assert!(matches!(&binds[2], SourceBind::TextList(v) if v.len() == 2));
    }

    // feature: B1
    #[test]
    fn audit_rows_name_their_actor_kind() {
        assert_eq!(audit_actor_kind(Some(0), Some(0)), ActorKind::Person);
        assert_eq!(audit_actor_kind(Some(1), Some(1)), ActorKind::Agent);
        assert_eq!(audit_actor_kind(Some(2), None), ActorKind::System);
        assert_eq!(audit_actor_kind(Some(0), Some(4)), ActorKind::Flow);
        assert_eq!(audit_actor_kind(None, None), ActorKind::Person);
    }

    // feature: B1
    #[test]
    fn roll_in_reads_the_entity_list_and_skips_malformed_items() {
        let value = serde_json::json!({
            "account": [
                {"entity": "contact", "via": "account_id"},
                {"entity": "opportunity"},
                "nonsense",
                {"entity": "opportunity", "via": "account_ref"}
            ]
        });
        assert_eq!(
            parse_roll_in(&value, "account"),
            vec![
                RollIn {
                    entity: "contact".into(),
                    via: "account_id".into()
                },
                RollIn {
                    entity: "opportunity".into(),
                    via: "account_ref".into()
                },
            ]
        );
        assert!(parse_roll_in(&value, "contact").is_empty());
        assert!(parse_roll_in(&serde_json::json!({}), "account").is_empty());
    }

    // feature: B1
    #[test]
    fn channel_keeps_only_communications_and_dates_must_be_ordered() {
        let opts = TimelineOptions::from_query(&TimelineQuery {
            channel: Some(" email ".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(opts.filter.channel.as_deref(), Some("email"));
        assert!(opts.wants(TimelineEntryKind::Communication));
        assert!(!opts.wants(TimelineEntryKind::Note));
        assert!(opts.related, "related records roll in by default");
        let bad = TimelineQuery {
            from: Some("2026-10-02T00:00:00Z".parse().unwrap()),
            to: Some("2026-10-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };
        assert!(matches!(
            TimelineOptions::from_query(&bad),
            Err(AppError::Validation(_))
        ));
        let long = TimelineQuery {
            q: Some("x".repeat(201)),
            ..Default::default()
        };
        assert!(matches!(
            TimelineOptions::from_query(&long),
            Err(AppError::Validation(_))
        ));
    }
}

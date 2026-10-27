//! M84 Phase 1 (Queue Management, D-464) — work queues: distributing human
//! work (`service_ticket` rows) to whoever is free and able, and making backlog
//! and capacity visible. Not `attome-jobs`' job queue/DLQ/replay machinery
//! (out of scope, unrelated concept) — this is the *work* queue the plan
//! titles "work queues; the job queue is fine".
//!
//! **Scope: tickets only, not work requests.** `service_work_request` is
//! pre-triage intake with no `assignee_id`/`status` workflow of its own
//! (`convert.rs` turns it into a ticket/task/project); a person claims and
//! works a *ticket*, not a still-untriaged request. `service_ticket.work_queue_ref`
//! (this file's schema) is therefore the only field claim/assign operate
//! against.
//!
//! **`work_queue_ref`, not `queue_ref`.** `service_work_request.queue_ref` and
//! `service_offering.default_queue_ref` already exist as unwired `text`
//! placeholders (`seed.rs`, pre-M84). `attome-metadata`'s attribute reconciler
//! refuses a field TYPE change on an existing attribute
//! (`reconcile.rs::reconcile_attribute_with_lookup_ref`'s `check_field_type_
//! drift` — "a field TYPE change is refused... surface, never cast") to keep
//! an upgraded deployment's boot safe, so turning that `text` field into a
//! real `lookup` in place is not an option without breaking any deployment
//! that already provisioned it. A new, distinctly-named `lookup` attribute
//! is the only additive path; those two placeholders are left exactly as
//! they were (still unwired, still text) rather than silently repointed.
//!
//! **Claim vs. assign.** Both take the queue's advisory lock
//! (`"attome-service/queue-claim:<queue_id>"`, `attome_service::ADVISORY_LOCK_
//! NAMESPACE`, already registered in `crates/server/tests/
//! advisory_lock_namespaces.rs` for this crate's whole `"attome-service/…"` key
//! space — this file adds a new key under that existing namespace, not a new
//! namespace) before reading which ticket is "next", so two concurrent
//! callers against the same queue can't both observe (and then both claim)
//! the same ticket. `claim` is self-service: the caller claims whatever is
//! next by (priority, age) for themselves, and must already be an active
//! member (or the queue's lead). `assign` targets a specific ticket and
//! either takes an explicit `assignee_id` (`manual`/`skill_match`, see
//! [`Distribution::SkillMatch`]'s doc comment) or computes one
//! (`round_robin`/`least_loaded`).
//!
//! **G4-T1: skill match and V7 queue items.** A `skill_match` queue routes
//! to an available member who holds every skill the ticket needs, at its
//! level: the queue's `required_skills` (`skill` or `skill:level`, comma
//! separated, as `schedule_candidates::parse_skills` reads them) plus the
//! `queue_item_skill` rows of the ticket's queue item (platform changeset
//! 0076), against the member's `resource_skill` rows (whose new `kind`
//! says whether a skill is a skill, language, certification or product);
//! the least loaded such member gets it, and an explicit `assignee_id` must
//! hold them too. Every claim and assign also moves the ticket's
//! `queue_item` (V7-T1, `attome_project::queue`) to `picked` with the
//! assignee, creating it when the ticket was queued after the last boot's
//! migration. The V7 `queue` rows carry the same ids as the service queues,
//! so `work_queue_ref` values name both.
//!
//! **`calendar_ref` is schema-ready, not consumed here** — same "reserved
//! for a later phase" posture `service_offering.intake_form_ref`/
//! `approval_policy_ref` already use. Idle-item escalation
//! ([`run_escalation_sweep`]) measures idle time in plain wall-clock terms;
//! wiring it through `attome_calendar::BusinessCalendar` the way
//! `sla.rs::compute_due` does (through `attome_core::calendar`, D-517) is
//! real follow-up work, not silently dropped.

use std::collections::HashMap;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::TicketUpdate;
use crate::schedule_candidates::{NeededSkill, parse_skills, skills_cover};

// ── Distribution strategy vocabulary (checklist's exact terms) ────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Distribution {
    /// A human names `assignee_id` explicitly on `/assign`.
    Manual,
    /// Rotates through active members in a stable order, advancing a
    /// persisted pointer (`service_work_queue.last_assigned_member_ref`) each
    /// time — a member at/over `capacity` is skipped, not just deprioritized.
    RoundRobin,
    /// Assigns to whichever active member currently has the fewest open
    /// (`assignee_id = member AND status NOT IN (resolved, closed)`) tickets
    /// in this queue, again skipping anyone at/over `capacity`.
    LeastLoaded,
    /// G4-T1: the least loaded available member who holds every skill the
    /// ticket needs (the queue's `required_skills` plus its queue item's
    /// `queue_item_skill` rows) at its level, from their `resource_skill`
    /// rows; an explicit `assignee_id` must hold them too.
    SkillMatch,
}

impl Distribution {
    fn parse(s: &str) -> Self {
        // An unrecognised value defaults to Manual rather than erroring —
        // same "unknown value degrades safely" posture `clock::ClockState::
        // parse` documents for itself.
        match s {
            "round_robin" => Self::RoundRobin,
            "least_loaded" => Self::LeastLoaded,
            "skill_match" => Self::SkillMatch,
            _ => Self::Manual,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::RoundRobin => "round_robin",
            Self::LeastLoaded => "least_loaded",
            Self::SkillMatch => "skill_match",
        }
    }
}

// ── Queue row + advisory lock ──────────────────────────────────────────────

struct QueueRow {
    distribution: Distribution,
    capacity: Option<i64>,
    last_assigned_member_ref: Option<Uuid>,
    lead_ref: Option<Uuid>,
    is_active: bool,
}

/// `(distribution, capacity, last_assigned_member_ref, lead_ref, is_active)`
/// — [`load_queue`]'s raw row shape, named so clippy's `type_complexity`
/// lint doesn't flag the inline tuple.
type QueueRawRow = (String, Option<f64>, Option<Uuid>, Option<Uuid>, bool);

/// Loads and row-locks the queue (`FOR UPDATE`, within the caller's already
/// advisory-locked transaction — belt and suspenders, same posture
/// `clock::get_or_create_clock` documents for its own `FOR UPDATE`).
async fn load_queue(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
) -> Result<QueueRow, AppError> {
    let row: Option<QueueRawRow> = sqlx::query_as(
        "SELECT distribution, capacity::double precision, last_assigned_member_ref, \
                lead_ref, COALESCE(is_active, true) \
         FROM service_work_queue WHERE id = $1 FOR UPDATE",
    )
    .bind(queue_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (distribution, capacity, last_assigned_member_ref, lead_ref, is_active) =
        row.ok_or(AppError::NotFound)?;
    Ok(QueueRow {
        distribution: Distribution::parse(&distribution),
        capacity: capacity.map(|c| c as i64),
        last_assigned_member_ref,
        lead_ref,
        is_active,
    })
}

/// Advisory-locks this queue's claim/assign key before any read — same
/// "lock, then act" order `convert.rs::lock_and_load_work_request` and
/// `clock::lock_ticket` already use, so two concurrent claim/assign attempts
/// against the same queue serialize instead of both observing the same
/// "next" ticket. Key shape per coding-guidelines §2:
/// `"attome-service/queue-claim:<queue_id>"`, namespace 14
/// (`attome_service::ADVISORY_LOCK_NAMESPACE`) — already registered in
/// `crates/server/tests/advisory_lock_namespaces.rs` for this crate's whole
/// key space, so no new namespace entry is needed for this new key prefix
/// under it.
async fn lock_queue(tx: &mut Transaction<'_, Postgres>, queue_id: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-service/queue-claim:{queue_id}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another claim/assign request for this queue is already in progress",
        ));
    }
    Ok(())
}

// ── Membership / load queries ──────────────────────────────────────────────

async fn is_active_member(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM service_work_queue_member \
         WHERE queue_ref = $1 AND user_ref = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(queue_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(found.is_some())
}

/// Currently-open (`status NOT IN (resolved, closed)`) ticket count for one
/// member, scoped to this queue — `capacity` is documented per-queue
/// ("max concurrent items per member"), so load is counted per-queue too,
/// not globally across every queue the member belongs to.
async fn open_item_count(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
    member_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_ticket \
         WHERE work_queue_ref = $1 AND assignee_id = $2 \
           AND status NOT IN ('resolved', 'closed') \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(queue_id)
    .bind(member_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Every active member of the queue, each with their current open-item count
/// in it — one aggregate query backing both `round_robin`'s eligibility
/// filter and `least_loaded`'s pick, ordered by `user_ref` for determinism
/// (round-robin's own ordering, and least-loaded's tie-break).
async fn member_loads(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
) -> Result<Vec<(Uuid, i64)>, AppError> {
    sqlx::query_as(
        "SELECT m.user_ref, COUNT(t.id) FILTER (WHERE t.id IS NOT NULL) \
         FROM service_work_queue_member m \
         LEFT JOIN service_ticket t ON t.assignee_id = m.user_ref AND t.work_queue_ref = $1 \
             AND t.status NOT IN ('resolved', 'closed') \
             AND (t.is_active IS NULL OR t.is_active = true) \
         WHERE m.queue_ref = $1 AND (m.is_active IS NULL OR m.is_active = true) \
         GROUP BY m.user_ref \
         ORDER BY m.user_ref",
    )
    .bind(queue_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// G5-T3: the members automatic distribution may route to — those whose
/// `service.presence` is not `busy` or `away`.
fn available_loads(state: &EngineState, loads: Vec<(Uuid, i64)>) -> Vec<(Uuid, i64)> {
    loads
        .into_iter()
        .filter(|(user, _)| crate::presence::is_available(state, *user))
        .collect()
}

/// The next unassigned, open ticket in the queue, ordered by
/// (priority desc, age asc) per the target design's "priority queues"
/// section — `FOR UPDATE` so a concurrent generic-CRUD update to this exact
/// ticket (e.g. an admin editing it by hand) can't race the claim.
async fn next_open_ticket(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
) -> Result<Option<(Uuid, String)>, AppError> {
    sqlx::query_as(
        "SELECT id, ticket_number FROM service_ticket \
         WHERE work_queue_ref = $1 AND assignee_id IS NULL \
           AND status NOT IN ('resolved', 'closed') \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY \
           CASE priority \
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
             WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 \
           END, \
           created_at ASC \
         LIMIT 1 FOR UPDATE",
    )
    .bind(queue_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

// ── G4-T1: skills and the V7 queue item ────────────────────────────────────

/// Whether `table` is provisioned (the V7 queue tables come from a platform
/// changeset; a bare test database may lack them).
async fn has_table(tx: &mut Transaction<'_, Postgres>, table: &str) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The skills a ticket needs: its queue's `required_skills`, then its queue
/// item's `queue_item_skill` rows (a name in both keeps the higher level).
async fn required_skills(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
    ticket_id: Uuid,
) -> Result<Vec<NeededSkill>, AppError> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT required_skills FROM service_work_queue WHERE id = $1")
            .bind(queue_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let mut need = parse_skills(raw.as_deref());
    if has_table(tx, "queue_item_skill").await? && has_table(tx, "queue_item").await? {
        let rows: Vec<(String, Option<f64>)> = sqlx::query_as(
            "SELECT s.skill, s.min_level::float8 FROM queue_item_skill s \
               JOIN queue_item i ON i.id = s.queue_item_ref \
              WHERE i.record_entity = 'service_ticket' AND i.record_id = $1 \
                AND i.queue_ref = $2 AND i.is_active IS NOT FALSE \
                AND s.is_active IS NOT FALSE",
        )
        .bind(ticket_id.to_string())
        .bind(queue_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        need = merge_needed(need, rows);
    }
    Ok(need)
}

/// `need` plus the (skill, level) rows, one entry per lower-cased name,
/// keeping the higher level. Pure.
fn merge_needed(mut need: Vec<NeededSkill>, rows: Vec<(String, Option<f64>)>) -> Vec<NeededSkill> {
    for (skill, level) in rows {
        let skill = skill.trim().to_lowercase();
        if skill.is_empty() {
            continue;
        }
        match need.iter_mut().find(|n| n.skill == skill) {
            Some(n) => {
                n.min_level = match (n.min_level, level) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                }
            }
            None => need.push(NeededSkill {
                skill,
                min_level: level,
            }),
        }
    }
    need
}

/// Each member's skills (lower-cased name to their highest level).
async fn member_skills(
    tx: &mut Transaction<'_, Postgres>,
    members: &[Uuid],
) -> Result<HashMap<Uuid, HashMap<String, Option<f64>>>, AppError> {
    let mut out: HashMap<Uuid, HashMap<String, Option<f64>>> = HashMap::new();
    if members.is_empty() || !has_table(tx, "resource_skill").await? {
        return Ok(out);
    }
    let rows: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(
        "SELECT user_id, skill, skill_level::float8 FROM resource_skill \
          WHERE user_id = ANY($1) AND is_active IS NOT FALSE",
    )
    .bind(members)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for (user, skill, level) in rows {
        let entry = out
            .entry(user)
            .or_default()
            .entry(skill.trim().to_lowercase())
            .or_insert(level);
        if level > *entry {
            *entry = level;
        }
    }
    Ok(out)
}

/// The members of `loads` who hold every needed skill, order kept. Pure.
fn qualified_loads(
    loads: Vec<(Uuid, i64)>,
    skills: &HashMap<Uuid, HashMap<String, Option<f64>>>,
    need: &[NeededSkill],
) -> Vec<(Uuid, i64)> {
    let none = HashMap::new();
    loads
        .into_iter()
        .filter(|(user, _)| skills_cover(skills.get(user).unwrap_or(&none), need))
        .collect()
}

/// V7-T1: the ticket's queue item is `picked` by `user`; one is created when
/// the ticket was queued after the boot migration made the others.
async fn pick_queue_item(
    tx: &mut Transaction<'_, Postgres>,
    queue_id: Uuid,
    ticket_id: Uuid,
    user: Uuid,
) -> Result<(), AppError> {
    if !(has_table(tx, "queue_item").await? && has_table(tx, "queue").await?) {
        return Ok(());
    }
    let updated = sqlx::query(
        "UPDATE queue_item SET status = 'picked', assigned_ref = $3, modified_at = now(), \
                row_version = row_version + 1 \
          WHERE record_entity = 'service_ticket' AND record_id = $2 AND queue_ref = $1 \
            AND is_active IS NOT FALSE",
    )
    .bind(queue_id)
    .bind(ticket_id.to_string())
    .bind(user)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated == 0 {
        sqlx::query(
            "INSERT INTO queue_item \
               (id, queue_ref, record_entity, record_id, priority, status, assigned_ref, \
                entered_at, created_by, owner_ref, owner_type, organization_ref, \
                created_at, modified_at) \
             SELECT uuidv7(), q.id, 'service_ticket', t.id::text, \
                    COALESCE(t.priority::text, 'medium'), 'picked', $3, t.created_at, \
                    t.created_by, t.owner_ref, t.owner_type, t.organization_ref, now(), now() \
               FROM service_ticket t JOIN queue q ON q.id = $1 \
              WHERE t.id = $2",
        )
        .bind(queue_id)
        .bind(ticket_id)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

// ── Pure distribution pickers (DB-free, directly unit-testable) ───────────

/// The next member after `last_assigned` in `members` (wrapping), or the
/// first member if there is no prior pointer or the prior pointer is no
/// longer eligible (dropped membership, now over capacity). `None` only when
/// `members` is empty.
fn next_round_robin_member(members: &[Uuid], last_assigned: Option<Uuid>) -> Option<Uuid> {
    if members.is_empty() {
        return None;
    }
    match last_assigned.and_then(|last| members.iter().position(|m| *m == last)) {
        Some(idx) => Some(members[(idx + 1) % members.len()]),
        None => Some(members[0]),
    }
}

/// The eligible (under-capacity) member with the fewest open items;
/// `loads` must already be sorted by member id (deterministic tie-break —
/// [`member_loads`]'s own `ORDER BY`). `None` when every member is at/over
/// `capacity`, or there are no members.
fn least_loaded_member(loads: &[(Uuid, i64)], capacity: Option<i64>) -> Option<Uuid> {
    loads
        .iter()
        .filter(|(_, count)| capacity.is_none_or(|cap| *count < cap))
        .min_by_key(|(_, count)| *count)
        .map(|(id, _)| *id)
}

// ── Audit (best-effort, same posture as clock.rs::write_audit) ────────────

/// Thin wrapper over the shared `attome_audit::write_business_event` (M26 R-15
/// dedup).
async fn write_audit(
    state: &EngineState,
    actor: Uuid,
    ticket_id: Uuid,
    event_name: &str,
    comment: String,
) {
    attome_audit::write_business_event(
        state,
        "service_ticket",
        ticket_id,
        AuditOperation::Update,
        event_name,
        actor,
        None,
        None,
        comment,
    )
    .await;
}

// ── Claim / assign — the engine functions (HTTP-shape-free, same reason
// `convert::convert_work_request_to_ticket` is shaped this way: this crate's
// own tests call them directly) ────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct ClaimResponse {
    /// `false` when the queue is currently empty — not an error, just
    /// nothing to claim right now.
    pub claimed: bool,
    pub ticket_id: Option<Uuid>,
    pub ticket_number: Option<String>,
}

/// Self-service claim: the caller takes whatever is next by (priority, age)
/// for themselves. Requires the caller to be an active member of the queue
/// (or its `lead_ref`), and — when `capacity` is set — to currently be under
/// it.
pub async fn claim_next_ticket(
    state: &EngineState,
    queue_id: Uuid,
    actor: Uuid,
) -> Result<ClaimResponse, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_queue(&mut tx, queue_id).await?;
    let queue = load_queue(&mut tx, queue_id).await?;

    if !queue.is_active {
        return Err(AppError::Conflict("this queue is not active"));
    }
    if !is_active_member(&mut tx, queue_id, actor).await? && queue.lead_ref != Some(actor) {
        return Err(AppError::Forbidden);
    }
    if let Some(capacity) = queue.capacity {
        let current = open_item_count(&mut tx, queue_id, actor).await?;
        if current >= capacity {
            return Err(AppError::Conflict(
                "you are already at capacity for this queue",
            ));
        }
    }

    let Some((ticket_id, ticket_number)) = next_open_ticket(&mut tx, queue_id).await? else {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(ClaimResponse {
            claimed: false,
            ticket_id: None,
            ticket_number: None,
        });
    };

    let updated = sqlx::query(
        "UPDATE service_ticket SET assignee_id = $2, claimed_at = NOW() \
         WHERE id = $1 AND assignee_id IS NULL",
    )
    .bind(ticket_id)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::internal(
            "ticket vanished or was claimed between read and update",
        ));
    }
    pick_queue_item(&mut tx, queue_id, ticket_id, actor).await?;
    tx.commit().await.map_err(AppError::internal)?;

    write_audit(
        state,
        actor,
        ticket_id,
        "queue.claimed",
        format!("Ticket {ticket_number} self-claimed from queue {queue_id}"),
    )
    .await;

    Ok(ClaimResponse {
        claimed: true,
        ticket_id: Some(ticket_id),
        ticket_number: Some(ticket_number),
    })
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRequest {
    pub ticket_id: Uuid,
    /// Required when the queue's distribution is `manual`; optional for
    /// `skill_match` (the member must hold the skills); must be omitted for
    /// `round_robin`/`least_loaded`, whose target is computed automatically.
    pub assignee_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AssignResponse {
    pub ticket_id: Uuid,
    pub assignee_id: Uuid,
    pub distribution: String,
}

/// Assigns `ticket` to `user` and stamps the claim: the one assignment
/// write, shared by [`assign_ticket`] (`only_if_unassigned`) and the
/// hand-offs (`crate::handoff`). Rows changed.
pub(crate) async fn set_assignee(
    tx: &mut Transaction<'_, Postgres>,
    ticket: Uuid,
    user: Uuid,
    only_if_unassigned: bool,
) -> Result<u64, AppError> {
    let sql = if only_if_unassigned {
        "UPDATE service_ticket SET assignee_id = $2, claimed_at = NOW() \
         WHERE id = $1 AND assignee_id IS NULL"
    } else {
        "UPDATE service_ticket SET assignee_id = $2, claimed_at = NOW() WHERE id = $1"
    };
    Ok(sqlx::query(sql)
        .bind(ticket)
        .bind(user)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected())
}

/// Auto/manual assignment of one specific, already-queued ticket, per the
/// queue's `distribution` strategy.
pub async fn assign_ticket(
    state: &EngineState,
    queue_id: Uuid,
    ticket_id: Uuid,
    requested_assignee: Option<Uuid>,
    actor: Uuid,
) -> Result<AssignResponse, AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    lock_queue(&mut tx, queue_id).await?;
    let queue = load_queue(&mut tx, queue_id).await?;

    if !queue.is_active {
        return Err(AppError::Conflict("this queue is not active"));
    }

    let row: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT ticket_number, assignee_id FROM service_ticket \
         WHERE id = $1 AND work_queue_ref = $2 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(ticket_id)
    .bind(queue_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (ticket_number, existing_assignee) = row.ok_or(AppError::NotFound)?;
    if existing_assignee.is_some() {
        return Err(AppError::Conflict("this ticket is already assigned"));
    }

    let target = match queue.distribution {
        Distribution::SkillMatch => {
            let need = required_skills(&mut tx, queue_id, ticket_id).await?;
            match requested_assignee {
                Some(target) => {
                    if !is_active_member(&mut tx, queue_id, target).await? {
                        return Err(AppError::Validation(
                            "assignee_id is not an active member of this queue".to_string(),
                        ));
                    }
                    let skills = member_skills(&mut tx, &[target]).await?;
                    if !skills_cover(skills.get(&target).unwrap_or(&HashMap::new()), &need) {
                        return Err(AppError::Validation(
                            "assignee_id does not hold the skills this ticket needs".to_string(),
                        ));
                    }
                    if let Some(capacity) = queue.capacity {
                        let current = open_item_count(&mut tx, queue_id, target).await?;
                        if current >= capacity {
                            return Err(AppError::Conflict(
                                "target member is at capacity for this queue",
                            ));
                        }
                    }
                    target
                }
                None => {
                    let loads = available_loads(state, member_loads(&mut tx, queue_id).await?);
                    let members: Vec<Uuid> = loads.iter().map(|(id, _)| *id).collect();
                    let skills = member_skills(&mut tx, &members).await?;
                    let qualified = qualified_loads(loads, &skills, &need);
                    least_loaded_member(&qualified, queue.capacity).ok_or(AppError::Conflict(
                        "no available member of this queue holds the skills this ticket needs \
                         and has spare capacity",
                    ))?
                }
            }
        }
        Distribution::Manual => {
            let Some(target) = requested_assignee else {
                return Err(AppError::Validation(
                    "assignee_id is required: this queue's distribution is manual".to_string(),
                ));
            };
            if !is_active_member(&mut tx, queue_id, target).await? {
                return Err(AppError::Validation(
                    "assignee_id is not an active member of this queue".to_string(),
                ));
            }
            if let Some(capacity) = queue.capacity {
                let current = open_item_count(&mut tx, queue_id, target).await?;
                if current >= capacity {
                    return Err(AppError::Conflict(
                        "target member is at capacity for this queue",
                    ));
                }
            }
            target
        }
        Distribution::RoundRobin => {
            if requested_assignee.is_some() {
                return Err(AppError::Validation(
                    "assignee_id must not be set: this queue's distribution is round_robin"
                        .to_string(),
                ));
            }
            let loads = available_loads(state, member_loads(&mut tx, queue_id).await?);
            let eligible: Vec<Uuid> = loads
                .iter()
                .filter(|(_, count)| queue.capacity.is_none_or(|cap| *count < cap))
                .map(|(id, _)| *id)
                .collect();
            next_round_robin_member(&eligible, queue.last_assigned_member_ref).ok_or(
                AppError::Conflict("no active member of this queue currently has spare capacity"),
            )?
        }
        Distribution::LeastLoaded => {
            if requested_assignee.is_some() {
                return Err(AppError::Validation(
                    "assignee_id must not be set: this queue's distribution is least_loaded"
                        .to_string(),
                ));
            }
            let loads = available_loads(state, member_loads(&mut tx, queue_id).await?);
            least_loaded_member(&loads, queue.capacity).ok_or(AppError::Conflict(
                "no active member of this queue currently has spare capacity",
            ))?
        }
    };

    let updated = set_assignee(&mut tx, ticket_id, target, true).await?;
    if updated == 0 {
        return Err(AppError::internal(
            "ticket vanished or was assigned between read and update",
        ));
    }
    pick_queue_item(&mut tx, queue_id, ticket_id, target).await?;

    if queue.distribution == Distribution::RoundRobin {
        sqlx::query("UPDATE service_work_queue SET last_assigned_member_ref = $2 WHERE id = $1")
            .bind(queue_id)
            .bind(target)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }

    tx.commit().await.map_err(AppError::internal)?;

    write_audit(
        state,
        actor,
        ticket_id,
        "queue.assigned",
        format!(
            "Ticket {ticket_number} assigned to {target} via queue {queue_id} ({})",
            queue.distribution.as_str()
        ),
    )
    .await;

    Ok(AssignResponse {
        ticket_id,
        assignee_id: target,
        distribution: queue.distribution.as_str().to_string(),
    })
}

// ── HTTP ────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/queues/{id}/claim",
    tag = "service",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success (claimed may be false if the queue has nothing open)", body = ClaimResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an active member or lead of this queue", body = ErrorResponse),
        (status = 404, description = "No such queue", body = ErrorResponse),
        (status = 409, description = "Queue is not active, another claim is in progress, or the caller is at capacity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn claim_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(queue_id): Path<Uuid>,
) -> Result<Json<ClaimResponse>, AppError> {
    let response = claim_next_ticket(&state, queue_id, ctx.user_id).await?;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/queues/{id}/assign",
    tag = "service",
    params(("id" = Uuid, Path)),
    request_body = AssignRequest,
    responses(
        (status = 200, description = "Success", body = AssignResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such queue, or the ticket isn't in this queue", body = ErrorResponse),
        (status = 409, description = "Ticket already assigned, queue inactive, another claim/assign is in progress, or no member has capacity", body = ErrorResponse),
        (status = 422, description = "assignee_id required/forbidden for this queue's distribution, or names a non-member", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn assign_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(queue_id): Path<Uuid>,
    Json(body): Json<AssignRequest>,
) -> Result<Json<AssignResponse>, AppError> {
    let response = assign_ticket(
        &state,
        queue_id,
        body.ticket_id,
        body.assignee_id,
        ctx.user_id,
    )
    .await?;
    Ok(Json(response))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/queues/{id}/claim", post(claim_route))
        .route("/api/v1/queues/{id}/assign", post(assign_route))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(claim_route, assign_route))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Capacity-overflow alert + idle-item escalation (scheduled sweep) ──────

/// One sweep's outcome — for the job handler's `tracing::info!` summary,
/// same shape `sla::sweep_breaches`-style stats structs already take.
#[derive(Debug, Default, Clone, Copy)]
pub struct EscalationSweepStats {
    pub overflow_alerts: u64,
    pub idle_escalations: u64,
}

async fn notify_one(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
    recipient: Uuid,
    subject: String,
    body_text: String,
    route: String,
) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(recipient),
        is_global: false,
        organization_ref: None,
        channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
        subject: Some(subject),
        body_html: None,
        body_text: Some(body_text),
        route: Some(route),
        variables: std::collections::HashMap::new(),
        priority: "high".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(e) = attome_notification::dispatch::create_dispatch(db, notification_cfg, req).await
    {
        tracing::error!(error = %e, recipient = %recipient, "queue: escalation notification dispatch failed");
    }
}

/// One active queue's identity + the two escalation-relevant fields not
/// already covered by [`QueueRow`] (that struct is claim/assign-shaped;
/// this one is sweep-shaped — kept separate rather than growing `QueueRow`
/// with fields only the sweep needs).
struct SweepQueueRow {
    id: Uuid,
    name: String,
    capacity: Option<i64>,
    escalation_recipient: Option<Uuid>,
    lead_ref: Option<Uuid>,
    escalate_after_minutes: Option<i64>,
}

/// `(id, name, capacity, escalation_recipient, lead_ref,
/// escalate_after_minutes)` — [`active_queues`]'s raw row shape, named so
/// clippy's `type_complexity` lint doesn't flag the inline tuple (same
/// reason [`QueueRawRow`] exists above).
type SweepRawRow = (
    Uuid,
    String,
    Option<f64>,
    Option<Uuid>,
    Option<Uuid>,
    Option<f64>,
);

async fn active_queues(db: &DbPool) -> Result<Vec<SweepQueueRow>, AppError> {
    let rows: Vec<SweepRawRow> = sqlx::query_as(
        "SELECT id, name, capacity::double precision, escalation_recipient, lead_ref, \
                escalate_after_minutes::double precision \
         FROM service_work_queue WHERE COALESCE(is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, capacity, escalation_recipient, lead_ref, escalate_after_minutes)| {
                SweepQueueRow {
                    id,
                    name,
                    capacity: capacity.map(|c| c as i64),
                    escalation_recipient,
                    lead_ref,
                    escalate_after_minutes: escalate_after_minutes.map(|m| m as i64),
                }
            },
        )
        .collect())
}

/// Capacity overflow: this queue has an unassigned open item, but every
/// active member is already at/over `capacity` (or the queue has no active
/// members at all) — nobody can claim/be assigned the backlog right now.
/// `None` (never alerts) when `capacity` is unset — an uncapped queue can't
/// overflow by definition.
async fn queue_is_overflowing(db: &DbPool, queue: &SweepQueueRow) -> Result<bool, AppError> {
    let Some(capacity) = queue.capacity else {
        return Ok(false);
    };
    let has_unassigned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM service_ticket WHERE work_queue_ref = $1 AND assignee_id IS NULL \
             AND status NOT IN ('resolved', 'closed') AND (is_active IS NULL OR is_active = true))",
    )
    .bind(queue.id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !has_unassigned {
        return Ok(false);
    }
    let has_capacity: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM service_work_queue_member m \
             WHERE m.queue_ref = $1 AND (m.is_active IS NULL OR m.is_active = true) \
               AND ( \
                   SELECT COUNT(*) FROM service_ticket t \
                   WHERE t.work_queue_ref = $1 AND t.assignee_id = m.user_ref \
                     AND t.status NOT IN ('resolved', 'closed') \
                     AND (t.is_active IS NULL OR t.is_active = true) \
               ) < $2 \
         )",
    )
    .bind(queue.id)
    .bind(capacity as f64)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(!has_capacity)
}

/// Tickets in this queue that are still unassigned and older than
/// `escalate_after_minutes` — plain wall-clock age (`calendar_ref` is not
/// consulted here, see this module's doc comment).
async fn idle_ticket_count(
    db: &DbPool,
    queue: &SweepQueueRow,
    escalate_after_minutes: i64,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_ticket \
         WHERE work_queue_ref = $1 AND assignee_id IS NULL \
           AND status NOT IN ('resolved', 'closed') \
           AND (is_active IS NULL OR is_active = true) \
           AND created_at < NOW() - ($2 * INTERVAL '1 minute')",
    )
    .bind(queue.id)
    .bind(escalate_after_minutes as f64)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// M84 Phase 1 checklist item 5 — periodic sweep: alerts a queue's
/// `escalation_recipient` (falling back to `lead_ref` when unset) when the
/// queue is overflowing capacity, and again when it has items that have sat
/// unassigned past `escalate_after_minutes`. No persistent "already alerted"
/// marker — same re-nag-every-tick convention `EngineJob::
/// ContentReviewReminderSweep`'s own doc comment documents for itself
/// ("an owner who ignores the reminder is nagged again on the next tick
/// rather than only once"): the condition is cheap to re-check and clears
/// itself the moment capacity frees up or the backlog is worked, so there is
/// no stale-flag risk to guard against. A queue with neither
/// `escalation_recipient` nor `lead_ref` set is logged and skipped, never
/// silently dropped nor sent to a fabricated recipient.
pub async fn run_escalation_sweep(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<EscalationSweepStats, AppError> {
    let mut stats = EscalationSweepStats::default();
    for queue in active_queues(db).await? {
        let recipient = queue.escalation_recipient.or(queue.lead_ref);

        if queue_is_overflowing(db, &queue).await? {
            match recipient {
                Some(recipient) => {
                    notify_one(
                        db,
                        notification_cfg,
                        recipient,
                        format!("[Queue Overflow] {}", queue.name),
                        format!(
                            "Queue \"{}\" has unassigned work and every active member is at \
                             capacity.",
                            queue.name
                        ),
                        format!("/xrm/service/queue-board?queue={}", queue.id),
                    )
                    .await;
                    stats.overflow_alerts += 1;
                }
                None => tracing::warn!(
                    queue_id = %queue.id, queue_name = %queue.name,
                    "queue: capacity overflow has no resolvable recipient (no escalation_recipient or lead_ref)"
                ),
            }
        }

        if let Some(escalate_after_minutes) = queue.escalate_after_minutes {
            let idle = idle_ticket_count(db, &queue, escalate_after_minutes).await?;
            if idle > 0 {
                match recipient {
                    Some(recipient) => {
                        notify_one(
                            db,
                            notification_cfg,
                            recipient,
                            format!("[Queue Idle Items] {}", queue.name),
                            format!(
                                "Queue \"{}\" has {idle} unassigned item(s) older than \
                                 {escalate_after_minutes} minutes.",
                                queue.name
                            ),
                            format!("/xrm/service/queue-board?queue={}", queue.id),
                        )
                        .await;
                        stats.idle_escalations += 1;
                    }
                    None => tracing::warn!(
                        queue_id = %queue.id, queue_name = %queue.name,
                        "queue: idle-item escalation has no resolvable recipient (no escalation_recipient or lead_ref)"
                    ),
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── G4-T1: skill match on V7 queues ─────────────────────────────────
    #[test]
    fn queue_on_v7_item_skills_join_the_queue_skills() {
        let need = merge_needed(
            parse_skills(Some("Arabic:3, billing")),
            vec![
                ("arabic".into(), Some(4.0)),
                ("Billing".into(), Some(2.0)),
                (" SAP ".into(), None),
                ("  ".into(), Some(1.0)),
            ],
        );
        assert_eq!(
            need,
            vec![
                NeededSkill {
                    skill: "arabic".into(),
                    min_level: Some(4.0)
                },
                NeededSkill {
                    skill: "billing".into(),
                    min_level: Some(2.0)
                },
                NeededSkill {
                    skill: "sap".into(),
                    min_level: None
                },
            ]
        );
    }

    #[test]
    fn queue_on_v7_skill_match_keeps_only_qualified_members() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut skills: HashMap<Uuid, HashMap<String, Option<f64>>> = HashMap::new();
        skills.insert(
            a,
            HashMap::from([("arabic".into(), Some(5.0)), ("billing".into(), None)]),
        );
        skills.insert(
            b,
            HashMap::from([("arabic".into(), Some(2.0)), ("billing".into(), None)]),
        );
        let need = parse_skills(Some("arabic:3,billing"));
        let qualified = qualified_loads(vec![(a, 4), (b, 0), (c, 0)], &skills, &need);
        // b's Arabic is below the level and c has no skills: a gets it,
        // even though a is the busiest.
        assert_eq!(qualified, vec![(a, 4)]);
        assert_eq!(least_loaded_member(&qualified, Some(4)), None);
        assert_eq!(least_loaded_member(&qualified, Some(5)), Some(a));
        // No skills needed: everyone qualifies.
        assert_eq!(qualified_loads(vec![(c, 1)], &skills, &[]), vec![(c, 1)]);
    }

    // ── next_round_robin_member ────────────────────────────────────────
    #[test]
    fn round_robin_starts_at_first_member_with_no_prior_pointer() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_eq!(next_round_robin_member(&[a, b], None), Some(a));
    }

    #[test]
    fn round_robin_advances_to_the_next_member() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let c = Uuid::now_v7();
        assert_eq!(next_round_robin_member(&[a, b, c], Some(a)), Some(b));
    }

    #[test]
    fn round_robin_wraps_around() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_eq!(next_round_robin_member(&[a, b], Some(b)), Some(a));
    }

    #[test]
    fn round_robin_restarts_when_the_prior_pointer_is_no_longer_eligible() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let stale = Uuid::now_v7();
        assert_eq!(next_round_robin_member(&[a, b], Some(stale)), Some(a));
    }

    #[test]
    fn round_robin_none_with_no_members() {
        assert_eq!(next_round_robin_member(&[], Some(Uuid::now_v7())), None);
    }

    // ── least_loaded_member ────────────────────────────────────────────
    #[test]
    fn least_loaded_picks_the_lowest_count() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let loads = vec![(a, 3), (b, 1)];
        assert_eq!(least_loaded_member(&loads, None), Some(b));
    }

    #[test]
    fn least_loaded_skips_members_at_or_over_capacity() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let loads = vec![(a, 1), (b, 5)];
        // a has fewer items but is at capacity 1 -> only b is eligible? No:
        // a=1 >= capacity(1) is excluded, b=5 >= capacity(1) is also
        // excluded -> nobody eligible.
        assert_eq!(least_loaded_member(&loads, Some(1)), None);
    }

    #[test]
    fn least_loaded_none_when_everyone_is_at_capacity() {
        let a = Uuid::now_v7();
        let loads = vec![(a, 2)];
        assert_eq!(least_loaded_member(&loads, Some(2)), None);
    }

    #[test]
    fn least_loaded_none_with_no_members() {
        assert_eq!(least_loaded_member(&[], None), None);
    }

    // ── Distribution::parse ────────────────────────────────────────────
    #[test]
    fn distribution_parse_recognizes_every_variant() {
        assert_eq!(Distribution::parse("manual"), Distribution::Manual);
        assert_eq!(Distribution::parse("round_robin"), Distribution::RoundRobin);
        assert_eq!(
            Distribution::parse("least_loaded"),
            Distribution::LeastLoaded
        );
        assert_eq!(Distribution::parse("skill_match"), Distribution::SkillMatch);
    }

    #[test]
    fn distribution_parse_defaults_unknown_values_to_manual() {
        assert_eq!(Distribution::parse("bogus"), Distribution::Manual);
    }
}

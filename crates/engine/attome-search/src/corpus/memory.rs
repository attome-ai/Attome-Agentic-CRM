//! Memory storage, visibility, and recall (M35, D-451).
//!
//! **The rule:**
//!
//! ```text
//! memory visible  ⟺  owner_principal = the caller's own user id
//!                     AND (parent_record_id IS NULL OR that record visible)
//! ```
//!
//! ## Why this is `KnowledgeVisibility`'s shape, not a new one
//!
//! I-1 says there is one retrieval enforcement point. [`MemoryVisibility`]
//! adds no second predicate: clause 2 is `PolymorphicVisibility` — the same
//! fragment record search and [`crate::knowledge::KnowledgeVisibility`] both
//! use, unchanged — and clause 1 is a plain indexed equality, cheaper than
//! `KnowledgeVisibility`'s own clause 1 (which has to resolve a caller's
//! readable *collections* first; a memory's owner is already known).
//!
//! ## Per-principal only (D-451) — `scope_kind` categorizes, it does not share
//!
//! A memory's `scope_kind`/`scope_ref` say what the memory is *about* (the
//! caller's own preference, an organization they administer, a conversation,
//! a workflow instance, a decision, an agent session) — they never widen who
//! can read the row. There is no organization-wide or cross-principal memory
//! in this module: every scope kind resolves visibility through the same
//! `owner_principal` equality. This is the plan's explicit refusal of
//! cross-agent shared memory (⛔ M100) taken to its logical conclusion rather
//! than left as a gap — see D-451 for the recorded reasoning.
//!
//! ## Entity-scope memory is never model-authored free text
//!
//! `scope_kind = 'entity'` rows are regenerated summaries of one record's
//! history, computed by `attome-ai`'s `memory.remember` executor from that
//! record's audit trail — never accepted as caller-supplied `summary`/
//! `facts`. This module has no way to tell the difference between a
//! regenerated and a hand-written row (it stores whatever it is given), so
//! that guarantee lives in the executor, the same layering
//! `article.draft`/`DraftedArticle` uses for "only a draft, never published"
//! (`attome-ai/src/actions/draft_article.rs`).
//!
//! ## Embedding: schema only, in this slice
//!
//! `embedding`/`embedding_model` exist on the table (same `halfvec(1024)` +
//! HNSW shape 0122 added to `knowledge_chunk`), but no code in this
//! crate populates or queries them yet — Stage 2 (semantic ANN) is not wired
//! for *any* corpus in `attome-search` today (see `lib.rs`'s own "Stage 1, in
//! progress" status note), and inventing a live embedding-generation call
//! site here, ahead of the corpus it is meant to piggyback on, would be
//! building infrastructure nobody else has proven yet. [`recall`] uses
//! lexical (`tsv`) matching only, the same Stage 1 shape
//! `legs::stage1::LexicalLeg` already uses elsewhere in this crate. Wiring
//! the embedding column is a follow-up once Stage 2 lands platform-wide.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use attome_security::visibility::PolymorphicVisibility;
use attome_types::AppError;

/// The seven scope kinds the plan defines (`document/module-master-plans/
/// M35-ai-memory.md` §3), mirrored as a closed Rust enum the same way
/// `attome_jobs::RewrapDomain` mirrors its own DB-`CHECK`ed text column —
/// `as_str`/`FromStr` keep the two representations from drifting apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScopeKind {
    User,
    Organization,
    Entity,
    Conversation,
    Workflow,
    Decision,
    Agent,
}

impl MemoryScopeKind {
    pub const ALL: [Self; 7] = [
        Self::User,
        Self::Organization,
        Self::Entity,
        Self::Conversation,
        Self::Workflow,
        Self::Decision,
        Self::Agent,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Organization => "organization",
            Self::Entity => "entity",
            Self::Conversation => "conversation",
            Self::Workflow => "workflow",
            Self::Decision => "decision",
            Self::Agent => "agent",
        }
    }
}

impl fmt::Display for MemoryScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MemoryScopeKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "organization" => Ok(Self::Organization),
            "entity" => Ok(Self::Entity),
            "conversation" => Ok(Self::Conversation),
            "workflow" => Ok(Self::Workflow),
            "decision" => Ok(Self::Decision),
            "agent" => Ok(Self::Agent),
            _ => Err(
                "scope_kind must be one of: user, organization, entity, conversation, workflow, decision, agent",
            ),
        }
    }
}

/// Size caps mirroring migration `0256`'s `CHECK` constraints — validated
/// here too, so a caller gets a clean `AppError::Validation` instead of a raw
/// constraint-violation error surfacing from the database (guidelines §4:
/// never expose raw database errors to clients).
pub const MAX_KIND_CHARS: usize = 64;
pub const MAX_SUMMARY_CHARS: usize = 2000;
pub const MAX_FACTS_BYTES: usize = 8192;
pub const MAX_SOURCE_REFS_BYTES: usize = 8192;

/// Upper bound on a single recall — this is context for a prompt, not a list
/// view; an unbounded result would both blow the token budget and make every
/// recalled row Untrusted content the model has to read.
pub const MAX_RECALL_LIMIT: i64 = 20;

fn validate_content(
    kind: &str,
    summary: &str,
    facts: &[String],
    source_refs: &[String],
) -> Result<(), AppError> {
    if kind.trim().is_empty() {
        return Err(AppError::Validation("kind must not be empty".into()));
    }
    if kind.chars().count() > MAX_KIND_CHARS {
        return Err(AppError::Validation(format!(
            "kind must be at most {MAX_KIND_CHARS} characters"
        )));
    }
    if summary.trim().is_empty() {
        return Err(AppError::Validation("summary must not be empty".into()));
    }
    if summary.chars().count() > MAX_SUMMARY_CHARS {
        return Err(AppError::Validation(format!(
            "summary must be at most {MAX_SUMMARY_CHARS} characters"
        )));
    }
    let facts_size = serde_json::to_vec(facts)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if facts_size > MAX_FACTS_BYTES {
        return Err(AppError::Validation(format!(
            "facts must serialize to at most {MAX_FACTS_BYTES} bytes"
        )));
    }
    let refs_size = serde_json::to_vec(source_refs)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if refs_size > MAX_SOURCE_REFS_BYTES {
        return Err(AppError::Validation(format!(
            "source_refs must serialize to at most {MAX_SOURCE_REFS_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Everything needed to filter `memory` rows for one caller.
pub struct MemoryVisibility<'a> {
    owner_principal: Uuid,
    /// The record predicate, applied only to `scope_kind = 'entity'` rows —
    /// same NULL-guarded shape as `KnowledgeVisibility::records`.
    records: &'a PolymorphicVisibility<'a>,
}

impl std::fmt::Debug for MemoryVisibility<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryVisibility").finish_non_exhaustive()
    }
}

impl<'a> MemoryVisibility<'a> {
    pub fn new(owner_principal: Uuid, records: &'a PolymorphicVisibility<'a>) -> Self {
        Self {
            owner_principal,
            records,
        }
    }

    /// Pushes the memory filter, binding every value as it goes.
    ///
    /// `alias` is a SQL identifier chosen by the calling code and is
    /// **spliced, not bound** — it must never come from request data.
    pub fn push(&self, qb: &mut QueryBuilder<'_, Postgres>, alias: &str) {
        // Clause 1: the per-principal equality — the entirety of D-451's
        // access control. An indexed equality (`memory_owner_scope_idx`),
        // paid by every row.
        qb.push(" AND ");
        qb.push(alias);
        qb.push(".owner_principal = ");
        qb.push_bind(self.owner_principal);

        // Clause 2: the expensive one, guarded by the NULL check so it only
        // ever runs for `scope_kind = 'entity'` rows — same reasoning as
        // `KnowledgeVisibility::push`.
        qb.push(" AND (");
        qb.push(alias);
        qb.push(".parent_record_id IS NULL OR TRUE");
        self.records.push(
            qb,
            &format!("{alias}.parent_entity"),
            &format!("{alias}.parent_record_id"),
        );
        qb.push(")");
    }
}

/// A memory row about to be written.
pub struct NewMemory<'a> {
    pub scope_kind: MemoryScopeKind,
    /// Ignored (stored as `""`) for `scope_kind = Entity`, which carries its
    /// reference in `parent_entity`/`parent_record_id` instead.
    pub scope_ref: &'a str,
    /// Never caller-supplied at the `attome-ai` layer — see that crate's
    /// `actions/memory.rs` for the structural guarantee. This module trusts
    /// its caller the same way `attome_api::entity_crud::create_record_for`
    /// trusts its own callers to have already checked privilege.
    pub owner_principal: Uuid,
    pub parent_entity: Option<&'a str>,
    pub parent_record_id: Option<Uuid>,
    pub kind: &'a str,
    pub summary: &'a str,
    pub facts: &'a [String],
    pub source_refs: &'a [String],
}

impl std::fmt::Debug for NewMemory<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewMemory").finish_non_exhaustive()
    }
}

/// Writes one memory row. Validates size caps before hitting the database so
/// a caller gets `AppError::Validation`, not a raw constraint-violation
/// error (guidelines §4/§6).
///
/// Takes any executor so `memory.remember` can write the row and its audit
/// event in one transaction (M35 v1 Track A); a pool works exactly as before.
pub async fn store<'e, E>(db: E, memory: NewMemory<'_>) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    validate_content(
        memory.kind,
        memory.summary,
        memory.facts,
        memory.source_refs,
    )?;
    if (memory.parent_entity.is_some() || memory.parent_record_id.is_some())
        != matches!(memory.scope_kind, MemoryScopeKind::Entity)
    {
        return Err(AppError::Validation(
            "parent_entity/parent_record_id are set if and only if scope_kind is entity".into(),
        ));
    }

    let scope_ref = if matches!(memory.scope_kind, MemoryScopeKind::Entity) {
        ""
    } else {
        memory.scope_ref
    };

    let facts_json = serde_json::to_value(memory.facts).map_err(AppError::internal)?;
    let source_refs_json = serde_json::to_value(memory.source_refs).map_err(AppError::internal)?;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO memory \
            (scope_kind, scope_ref, owner_principal, parent_entity, parent_record_id, \
             kind, summary, facts, source_refs) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING id",
    )
    .bind(memory.scope_kind.as_str())
    .bind(scope_ref)
    .bind(memory.owner_principal)
    .bind(memory.parent_entity)
    .bind(memory.parent_record_id)
    .bind(memory.kind)
    .bind(memory.summary)
    .bind(facts_json)
    .bind(source_refs_json)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(id)
}

/// Deletes one memory row — `memory.forget`'s primitive. Scoped to
/// `owner_principal` in the query itself, not checked-then-deleted, so there
/// is no window between check and delete. Returns the deleted row's scope
/// kind, or `None` when no row was removed (guidelines §2: zero rows is
/// meaningful) — the caller maps `None` to `NotFound` rather than assuming
/// success, and records the scope kind on the delete's audit event.
///
/// Takes any executor for the same reason [`store`] does.
pub async fn forget<'e, E>(
    db: E,
    owner_principal: Uuid,
    memory_id: Uuid,
) -> Result<Option<MemoryScopeKind>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let deleted: Option<String> = sqlx::query_scalar(
        "DELETE FROM memory WHERE id = $1 AND owner_principal = $2 RETURNING scope_kind",
    )
    .bind(memory_id)
    .bind(owner_principal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    deleted
        .map(|kind| kind.parse::<MemoryScopeKind>().map_err(AppError::internal))
        .transpose()
}

/// One principal's memory rows for a DSR access/portability export (M24,
/// M35 v1 Track A) — one JSON text per row, `$1 = owner_principal`, streamed
/// by `attome-compliance::dsr_admin`. Kept here so this module stays the single
/// owner of which memory columns leave the platform: what the subject can be
/// shown about themselves (scope, kind, summary, facts, source refs,
/// timestamps), not the derived index artefacts (`tsv`, `embedding`,
/// `embedding_model`) or `row_version`. Ordered by `id` so re-running the
/// same export reproduces the same checksum.
pub const MEMORY_EXPORT_SQL: &str = "SELECT row_to_json(t)::text FROM (\
     SELECT id, scope_kind, scope_ref, parent_entity, parent_record_id, kind, summary, \
            facts, source_refs, created_at, updated_at \
       FROM memory WHERE owner_principal = $1 ORDER BY id) t";

/// One recalled memory — shaped for direct use as `Segment::Untrusted`
/// content by `attome-ai` (memory is retrieved content, same taint
/// treatment as any other tool result, TODO-052/I-10).
#[derive(Debug, Clone, Serialize)]
pub struct MemoryHit {
    pub id: Uuid,
    pub scope_kind: String,
    pub kind: String,
    pub summary: String,
    pub facts: Vec<String>,
    pub source_refs: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct MemoryHitRow {
    id: Uuid,
    scope_kind: String,
    kind: String,
    summary: String,
    facts: serde_json::Value,
    source_refs: serde_json::Value,
}

impl From<MemoryHitRow> for MemoryHit {
    fn from(row: MemoryHitRow) -> Self {
        Self {
            id: row.id,
            scope_kind: row.scope_kind,
            kind: row.kind,
            summary: row.summary,
            facts: serde_json::from_value(row.facts).unwrap_or_default(),
            source_refs: serde_json::from_value(row.source_refs).unwrap_or_default(),
        }
    }
}

/// One recall request. `scope_kind`/`scope_ref` narrow to one category/
/// instance (e.g. "this conversation's memories") when set; `None` recalls
/// across every scope kind the caller owns.
pub struct RecallQuery<'a> {
    pub owner_principal: Uuid,
    pub scope_kind: Option<MemoryScopeKind>,
    pub scope_ref: Option<&'a str>,
    /// Plain-text lexical query. `None` returns the caller's most recent
    /// memories in that scope, unranked by relevance — useful for "recall
    /// everything about this conversation" rather than a search.
    pub query_text: Option<&'a str>,
    pub records: &'a PolymorphicVisibility<'a>,
    pub limit: i64,
}

impl std::fmt::Debug for RecallQuery<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecallQuery").finish_non_exhaustive()
    }
}

/// Recalls memories for one caller — the retrieval leg `attome-ai` wraps as
/// `Segment::Untrusted` before prompt assembly. Lexical (`tsv`) only in this
/// slice; see the module doc for why the embedding column is schema-only for
/// now.
pub async fn recall(db: &PgPool, query: RecallQuery<'_>) -> Result<Vec<MemoryHit>, AppError> {
    let limit = query.limit.clamp(1, MAX_RECALL_LIMIT);
    let visibility = MemoryVisibility::new(query.owner_principal, query.records);

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT m.id, m.scope_kind, m.kind, m.summary, m.facts, m.source_refs \
         FROM memory m WHERE true",
    );
    visibility.push(&mut qb, "m");

    if let Some(scope_kind) = query.scope_kind {
        qb.push(" AND m.scope_kind = ");
        qb.push_bind(scope_kind.as_str());
    }
    if let Some(scope_ref) = query.scope_ref {
        qb.push(" AND m.scope_ref = ");
        qb.push_bind(scope_ref);
    }

    match query.query_text.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => {
            qb.push(" AND m.tsv @@ plainto_tsquery('english', ");
            qb.push_bind(text.to_owned());
            qb.push(") ORDER BY ts_rank(m.tsv, plainto_tsquery('english', ");
            qb.push_bind(text.to_owned());
            qb.push(")) DESC, m.created_at DESC");
        }
        None => {
            qb.push(" ORDER BY m.created_at DESC");
        }
    }

    qb.push(" LIMIT ");
    qb.push_bind(limit);

    let rows: Vec<MemoryHitRow> = qb
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;

    Ok(rows.into_iter().map(MemoryHit::from).collect())
}

/// M24/D-428 — deletes every memory row owned by `owner_principal`, the
/// unconditional step `attome-compliance::dsr_admin::do_fulfill_erasure` runs
/// for every erasure request (same shape as that function's own
/// `withdraw_consents_for_subject`, which reaches into `audit_consent` the
/// same unconditional way). Hard delete, not crypto-shred: unlike a business
/// entity record (D-107), a memory row carries no separate audit-trail
/// evidentiary value that erasure must preserve — it IS the data.
pub async fn erase_for_subject(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    owner_principal: Uuid,
) -> Result<i64, AppError> {
    let result = sqlx::query("DELETE FROM memory WHERE owner_principal = $1")
        .bind(owner_principal)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(result.rows_affected() as i64)
}

/// The retention sweep's primitive (`ai.memory_retention_days`,
/// `attome-compliance::retention`). Deletes rows older than `retention_days`
/// regardless of scope kind — v1 applies one deployment-wide window
/// uniformly (see `attome-core::setting_catalog::ai_settings`'s doc
/// comment); differentiating by scope class is a follow-up, not a v1
/// requirement.
pub async fn purge_expired(db: &PgPool, retention_days: i64) -> Result<u64, AppError> {
    let result =
        sqlx::query("DELETE FROM memory WHERE created_at < NOW() - make_interval(days => $1)")
            .bind(retention_days as i32)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_server::security::{AccessLevel, SecurityContext};
    use std::collections::{HashMap, HashSet};

    fn ctx(is_admin: bool) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: vec![Uuid::now_v7()],
            team_ids: vec![Uuid::now_v7()],
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    fn fragment(owner: Uuid, is_admin: bool) -> String {
        let c = ctx(is_admin);
        let access: HashMap<String, (Uuid, AccessLevel)> =
            [("account".to_string(), (Uuid::now_v7(), AccessLevel::Team))].into();
        let empty = HashSet::new();
        let records = PolymorphicVisibility::new(&c, &access, &empty, None);
        let vis = MemoryVisibility::new(owner, &records);
        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("SELECT 1 FROM memory m WHERE true");
        vis.push(&mut qb, "m");
        qb.into_sql()
    }

    /// The cheap clause — the whole of D-451's access control — is an indexed
    /// equality on `owner_principal`, present for every caller.
    #[test]
    fn every_memory_is_filtered_by_owner_principal() {
        let sql = fragment(Uuid::now_v7(), false);
        assert!(
            sql.contains("m.owner_principal = "),
            "the owner clause must be an indexed equality: {sql}"
        );
    }

    /// **D-451's deliberate difference from `KnowledgeVisibility`.** An admin
    /// is NOT exempt from the owner clause — unlike record visibility, where
    /// `is_unfiltered()` lets an admin see every record, memory is
    /// per-principal for everyone, admins included. There is no
    /// "read anyone's memory" privilege in this design.
    #[test]
    fn an_admin_is_still_scoped_to_their_own_memories() {
        let admin_owner = Uuid::now_v7();
        let sql = fragment(admin_owner, true);
        assert!(
            sql.contains("m.owner_principal = "),
            "an admin caller must still be filtered by owner_principal, or \
             D-451's per-principal ruling has a silent admin exception: {sql}"
        );
    }

    /// The record predicate sits behind the `parent_record_id IS NULL` guard
    /// — same performance/correctness shape `KnowledgeVisibility` uses, so a
    /// `user`/`organization`/`conversation`/`workflow`/`decision`/`agent`-scope
    /// row (no parent) never pays for the polymorphic check.
    #[test]
    fn the_record_predicate_is_guarded_by_the_null_check() {
        let sql = fragment(Uuid::now_v7(), false);
        let guard = sql
            .find("m.parent_record_id IS NULL")
            .expect("the guard must be present");
        let predicate = sql
            .find("record_share")
            .expect("the record predicate must be present");
        assert!(
            guard < predicate,
            "the record predicate must sit INSIDE the null guard, or every \
             non-entity-scope memory pays for a check that cannot apply to \
             it: {sql}"
        );
    }

    /// Parentheses balance — the same mechanical check `knowledge.rs` and
    /// `visibility.rs` both carry, after a fragment that was one `)` short
    /// read perfectly and produced "syntax error at end of input".
    #[test]
    fn the_pushed_fragment_is_parenthesis_balanced() {
        for admin in [false, true] {
            let sql = fragment(Uuid::now_v7(), admin);
            let mut depth = 0i32;
            for ch in sql.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "closed one too many: {sql}");
            }
            assert_eq!(depth, 0, "unbalanced: {sql}");
        }
    }

    #[test]
    fn scope_kind_round_trips_through_its_string_form() {
        for kind in MemoryScopeKind::ALL {
            let parsed: MemoryScopeKind = kind.as_str().parse().expect("parses");
            assert_eq!(parsed.as_str(), kind.as_str());
        }
        assert!("not_a_scope".parse::<MemoryScopeKind>().is_err());
    }

    #[test]
    fn content_validation_rejects_an_oversized_summary() {
        let too_long = "x".repeat(MAX_SUMMARY_CHARS + 1);
        let err = validate_content("fact", &too_long, &[], &[]);
        assert!(err.is_err(), "a summary over the cap must be rejected");
    }

    #[test]
    fn content_validation_rejects_an_empty_summary() {
        assert!(validate_content("fact", "", &[], &[]).is_err());
        assert!(validate_content("", "something", &[], &[]).is_err());
    }

    #[test]
    fn content_validation_accepts_ordinary_content() {
        assert!(
            validate_content(
                "preference",
                "prefers dark mode",
                &["likes concise replies".to_string()],
                &["conversation:abc123".to_string()],
            )
            .is_ok()
        );
    }
}

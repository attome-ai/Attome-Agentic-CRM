use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_auth::SessionClaims;
use attome_core::{EngineState, quote_ident};
use attome_security::record_action::UpdateAndDelete;
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::entity_mutation::{
    MutationMode, delete_one, guard_hierarchy_redirect_cycle, lock_hierarchy_entity_unconditional,
    update_one,
};
use crate::mutation_ring::MutationRing;

use super::access::{fetch_audit_ctx, require_child_parent_access, require_record_access};
use super::resolve::resolve_entity;
use super::response::{EntityRecordResponse, build_response, resolve_lookup_meta};
use super::row_version::optional_expected_row_version;
use super::survivorship::{apply_picks, compute_fill, load_survivorship_rules, picks_of};
use attome_core::change_feed::MERGED_EVENT;
use attome_types::ErrorResponse;

/// D-432 / M13 — a synthetic, fully-privileged context for a merge performed
/// by the platform rather than a live HTTP caller: the duplicates admin
/// surface's manual "merge this candidate" action, and the `mdm.auto_merge`
/// four-eyes approval's execution callback. Same shape as
/// `attome_workflow::scheduler::system_security_context` — `is_admin: true`
/// short-circuits every `require`/`rls_predicate`/`resolve_entity_access_level`
/// check `do_merge_core` makes, so this is sound *only* because both call
/// sites are already gated by `Authorized<Admin>` (the duplicates route) or a
/// decided `attome_approval` request (the auto-merge callback) before they ever
/// construct one — never build this for a value that traces back to an
/// unauthenticated or ordinary-privilege caller.
pub fn admin_security_context(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: true,
        privileges: Default::default(),
        field_grants: Default::default(),
        field_write_grants: Default::default(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: Default::default(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// `do_merge_core`'s result: the merged record exactly as the pre-D-432
/// response always shaped it, plus the field names a `manual`-strategy
/// survivorship rule could not auto-decide (empty when no survivorship rules
/// are configured for this entity, or none applied to a field both rows
/// disagreed on) — see `entity_crud::survivorship`'s doc comment.
pub struct MergeOutcome {
    pub response: EntityRecordResponse,
    pub survivorship_conflicts: Vec<String>,
    /// A15-T5: the merge log row that can undo this merge.
    pub merge_log_id: Uuid,
}

impl std::fmt::Debug for MergeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergeOutcome").finish_non_exhaustive()
    }
}

/// D-432 / M13 — the merge endpoint's response. `#[serde(flatten)]` keeps
/// every field an existing caller already reads (`id`, `data`, `row_version`,
/// …) at the top level, unchanged — `survivorship_conflicts` is purely
/// additive alongside them (guidelines §12: prefer additive public API
/// changes).
#[derive(Serialize, utoipa::ToSchema)]
pub struct MergeResponse {
    #[serde(flatten)]
    record: EntityRecordResponse,
    /// Field names a `manual`-strategy survivorship rule could not
    /// auto-decide (both records carried a non-null, differing value) — the
    /// canonical record's pre-merge value was kept; a steward should review.
    /// Always empty for an entity with no survivorship rules configured.
    survivorship_conflicts: Vec<String>,
    /// A15-T5: the merge log row; undoing the merge names it.
    merge_log_id: Uuid,
}

impl std::fmt::Debug for MergeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergeResponse").finish_non_exhaustive()
    }
}

impl MergeResponse {
    /// `duplicates_admin`'s manual-merge route builds its response through
    /// this rather than constructing the struct directly — its fields are
    /// module-private so every caller goes through `do_merge_core`'s
    /// `MergeOutcome` first, the same "extend the merge contract, don't grow
    /// a second one" posture the rest of D-432 takes.
    pub fn from_outcome(outcome: MergeOutcome) -> Self {
        Self {
            record: outcome.response,
            survivorship_conflicts: outcome.survivorship_conflicts,
            merge_log_id: outcome.merge_log_id,
        }
    }
}

// â”€â”€ POST /api/v1/{entity}/{id}/merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Merge a duplicate into a record
///
/// F028 â€” merges `duplicate_id`'s record into the canonical record at `id`:
/// unions data (the canonical record's own value always wins on conflict; a
/// null/absent canonical field is filled from the duplicate's value),
/// redirects every other entity's lookup field that pointed at the
/// duplicate to the canonical id instead (reusing `dependents_of` â€” the
/// same "who points at this entity" registry lookup `on_target_delete`,
/// P-data-lifecycle, already built), then soft-deletes the duplicate.
/// Redirect touches dependent rows regardless of their own `is_active`
/// (F026 restore can bring a dependent back later; it must not wake up
/// still pointing at a retired id). All three steps commit atomically â€”
/// a partially-redirected merge would be worse than the duplicate data it's
/// meant to fix.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/merge",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("If-Match" = Option<String>, Header,
         description = "Optional row_version for optimistic concurrency on the canonical \
                        record (C-07/DATA-7). Omitted, the merge checks the canonical's own \
                        just-read version as before; supplied and stale, the response is 409."),
    ),
    responses(
        (status = 200, description = "Success", body = MergeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "If-Match row_version did not match the canonical record", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update), (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::SoftDelete)])))),
)]
pub(super) async fn merge_records(
    State(state): State<EngineState>,
    // Merge both updates the canonical record and retires the duplicate, so
    // the extractor requires `{entity}.update` AND `{entity}.delete`. The
    // *dependent* entities it redirects are not in the path and stay below.
    ctx: Authorized<RecordScoped<UpdateAndDelete>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, canonical_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<MergeResponse>, AppError> {
    let duplicate_id = body
        .get("duplicate_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("body must have a 'duplicate_id' UUID".into()))?;
    // D-432 / M13 — optional linkage to the duplicates admin queue: when a
    // steward merges directly from a flagged `duplicate_candidate`
    // row, passing its id here closes that row out (`status = 'merged'`) in
    // the same transaction as the merge itself instead of a second,
    // unguarded write after the fact.
    let candidate_id = body
        .get("candidate_id")
        .and_then(Value::as_str)
        .map(|s| {
            Uuid::parse_str(s)
                .map_err(|_| AppError::Validation("candidate_id must be a UUID".into()))
        })
        .transpose()?;
    // C-07 — DATA-7/CONC-1 style optional `If-Match`, same as delete/restore:
    // absent means "no externally supplied expectation", not "skip the
    // guard" — `do_merge_core_with_version` still checks the canonical's own
    // just-read version unconditionally.
    let expected_row_version = optional_expected_row_version(&headers)?;
    // A15-T10: the fields a person chose the source of.
    let picks = picks_of(&body)?;

    let outcome = do_merge_core_with_version(
        &state,
        &ctx,
        &entity_input,
        canonical_id,
        duplicate_id,
        claims.sub,
        candidate_id,
        expected_row_version,
        &picks,
    )
    .await?;

    Ok(Json(MergeResponse::from_outcome(outcome)))
}

/// The actual merge — shared by the HTTP endpoint above, the duplicates
/// admin surface's manual "merge this candidate" action
/// (`duplicates_admin::merge_candidate`), and the `mdm.auto_merge` four-eyes
/// approval's execution callback (`approval_admin::execute_approved`). See
/// `admin_security_context`'s doc comment for the authorization posture the
/// latter two rely on. `actor_user_id` is who the audit trail and
/// `modified_by` columns attribute the merge to; `ctx` is what authorizes it —
/// the same person on every call site today, but kept as two parameters
/// because they answer different questions.
pub async fn do_merge_core(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    canonical_id: Uuid,
    duplicate_id: Uuid,
    actor_user_id: Uuid,
    candidate_id: Option<Uuid>,
) -> Result<MergeOutcome, AppError> {
    do_merge_core_with_version(
        state,
        ctx,
        entity_input,
        canonical_id,
        duplicate_id,
        actor_user_id,
        candidate_id,
        None,
        &serde_json::Map::new(),
    )
    .await
}

/// C-07 — same as [`do_merge_core`], but additionally threads an optional
/// `If-Match`-sourced row_version expectation for the canonical record down
/// to the fill (DATA-7/CONC-1 pattern: `None` means "no externally supplied
/// expectation", not "skip the guard" — the merge always re-checks its own
/// just-read version, it just has nothing external to compare it against).
/// Only the HTTP route above threads a real value through; the duplicates-
/// admin manual-merge action and the `mdm.auto_merge` approval callback have
/// no `If-Match` of their own to offer, so they keep calling
/// [`do_merge_core`], which passes `None` unchanged from before this
/// parameter existed — additive, guidelines §12.
#[allow(clippy::too_many_arguments)]
pub async fn do_merge_core_with_version(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    canonical_id: Uuid,
    duplicate_id: Uuid,
    actor_user_id: Uuid,
    candidate_id: Option<Uuid>,
    expected_row_version: Option<i64>,
    picks: &serde_json::Map<String, Value>,
) -> Result<MergeOutcome, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;

    if is_append_only {
        return Err(AppError::Forbidden);
    }

    if duplicate_id == canonical_id {
        return Err(AppError::Validation(
            "duplicate_id must differ from the canonical record id".into(),
        ));
    }
    // Canonical record is updated in place; the duplicate is soft-deleted —
    // each needs its own action's depth, not one shared capability (a caller
    // whose role grants Team-Update but only User-Delete on this entity must
    // fail the merge if the duplicate falls outside their delete scope, even
    // when the canonical record is within their update scope).
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        canonical_id,
        RecordAction::Update,
    )
    .await?;
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        duplicate_id,
        RecordAction::Delete,
    )
    .await?;
    // D-593 (U1): merging two notes/communications/… also needs read access
    // to the records each one hangs off.
    require_child_parent_access(state, ctx, &entity_name, canonical_id).await?;
    require_child_parent_access(state, ctx, &entity_name, duplicate_id).await?;

    let table = quote_ident(&entity_name);
    let dependents = state.entities.load().dependents_of(entity_id);
    // D-133 follow-up: merge redirects dependent records across other
    // entities the caller may hold no privilege on at all â€” Action access
    // on the two merged records themselves says nothing about that. Fail
    // closed on the whole merge before any redirect runs, rather than
    // partially applying it.
    //
    // P-field-write-security (D-141): the redirect below is itself a write
    // to `dep_field` on every dependent row â€” if that field is `is_sensitive`,
    // entity-level `update` privilege is necessary but not sufficient, same
    // reasoning `validate_field_write_grants` applies to an ordinary
    // create/update payload. Checked here, alongside the entity-level check
    // above and before the transaction opens, so an unauthorized field fails
    // the whole merge exactly like an unauthorized dependent record does.
    for (dep_entity, dep_field, _) in &dependents {
        ctx.require(dep_entity, "update")?;
        // D-507: the same write rule `validate_field_write_grants` uses —
        // sensitive OR write-restricted.
        let dep_field_write_gated = state
            .entities
            .load()
            .get(dep_entity)
            .and_then(|meta| meta.attrs.iter().find(|a| &a.logicalname == dep_field))
            .is_some_and(|a| a.requires_field_write_grant());
        if dep_field_write_gated && !ctx.has_field_write_grant(dep_entity, dep_field) {
            return Err(AppError::Forbidden);
        }
    }
    let (user_ctx, org_ref) = fetch_audit_ctx(state, actor_user_id).await;

    // M01 Core C-12: both resolved here, on the pool, before the transaction
    // below opens. `load_survivorship_rules` only needs `entity_name`, known
    // well before any lock is taken. The per-dependent access ladder below
    // only needs `(user, dep_entity, Update)` — never a specific dependent
    // row, which the transaction's own locking loop further down resolves —
    // so there is no reason either has to wait until the transaction is
    // open, and no excuse to acquire a second pool connection from inside it
    // once it is (M01-core C-12; this loop used to call
    // `resolve_entity_access_level`/`resolve_owner_visible` against
    // `state.base.db` from inside the open transaction below).
    let survivorship_rules = load_survivorship_rules(&state.base.db, &entity_name).await?;
    let mut dep_access: Vec<(Option<AccessLevel>, bool)> = Vec::with_capacity(dependents.len());
    for (dep_entity, _dep_field, _mode) in &dependents {
        let dep_entity_id = state
            .entities
            .load()
            .get(dep_entity)
            .map(|meta| meta.entity_id);
        let access_level = match dep_entity_id {
            Some(id) => Some(
                resolve_entity_access_level(
                    &state.base.db,
                    ctx.user_id,
                    id,
                    dep_entity,
                    RecordAction::Update,
                )
                .await?,
            ),
            None => None,
        };
        let owner_visible = match dep_entity_id {
            Some(id) => {
                resolve_owner_visible(
                    &state.base.db,
                    ctx.user_id,
                    id,
                    dep_entity,
                    RecordAction::Update,
                )
                .await?
            }
            None => false,
        };
        dep_access.push((access_level, owner_visible));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // P-hierarchy-mutation-locking / F028: when this entity has a
    // self-referencing hierarchy field, the dependent-redirect step below can
    // rewrite many rows' parent pointer in one batch UPDATE. Serialize the
    // whole merge against every other hierarchy-touching write on this
    // entity up front — the same entity-level lock every PATCH/upsert/bulk
    // write already takes (`lock_hierarchy_entity`) — before any hierarchy
    // validation below runs.
    let has_hierarchy_field = attrs
        .iter()
        .any(|a| a.field_type_int == 11 && a.lookup_entity_ref == Some(entity_id));
    if has_hierarchy_field {
        lock_hierarchy_entity_unconditional(&mut tx, &entity_name).await?;
    }

    // Lock both rows in a fixed order (by id) so a concurrent merge of the
    // same two records in the opposite direction can't deadlock.
    let lock_order = if canonical_id < duplicate_id {
        [canonical_id, duplicate_id]
    } else {
        [duplicate_id, canonical_id]
    };
    for id in lock_order {
        sqlx::query(&attome_db::tag_dynamic(
            "entity.merge",
            &format!("SELECT id FROM {table} WHERE id = $1 FOR UPDATE"),
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // Explicit projection, not `SELECT *`/`RETURNING *` (external review,
    // 2026-07-21) â€” always the full column set (`include_sensitive = true`):
    // the union-fill logic below reads every attribute off both rows
    // regardless of the caller's own field visibility, same reason
    // create/update always fetch everything for their audit diff.
    let merge_cols = attome_core::select_columns(&attrs, true);
    let canonical_row: Option<Value> = sqlx::query_scalar(&attome_db::tag_dynamic("entity.merge", &format!(
        "SELECT row_to_json(t) FROM (SELECT {merge_cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    )))
    .bind(canonical_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let canonical_row = canonical_row.ok_or(AppError::NotFound)?;

    let duplicate_row: Option<Value> = sqlx::query_scalar(&attome_db::tag_dynamic("entity.merge", &format!(
        "SELECT row_to_json(t) FROM (SELECT {merge_cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    )))
    .bind(duplicate_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let duplicate_row = duplicate_row.ok_or_else(|| {
        AppError::Validation("duplicate_id does not exist or is already inactive".into())
    })?;

    let Value::Object(canonical_obj) = &canonical_row else {
        return Err(AppError::internal("canonical row was not a JSON object"));
    };
    let Value::Object(duplicate_obj) = &duplicate_row else {
        return Err(AppError::internal("duplicate row was not a JSON object"));
    };

    // C-07 — row_version guard on the canonical record. "current" is the
    // caller's `If-Match`, or (absent) the version just read above — see
    // `optional_expected_row_version`'s DATA-7/CONC-1 doc comment for why
    // absence means "no expectation" rather than "skip the guard". Checked
    // unconditionally, even when the fill below ends up empty, so a stale
    // `If-Match` still surfaces as 409 rather than silently succeeding.
    let canonical_row_version = canonical_obj
        .get("row_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::internal("canonical row missing row_version"))?;
    if let Some(expected) = expected_row_version
        && expected != canonical_row_version
    {
        return Err(AppError::VersionConflict);
    }

    // D-432 / M13 — survivorship-aware union: an entity with no configured
    // `survivorship_rule` rows merges exactly as before (every
    // attribute defaults to `most_complete` — canonical wins outright, a
    // null/absent canonical value is filled from the duplicate's). A field
    // with a `manual` rule that finds a genuine (non-null, differing)
    // disagreement is never auto-filled — it's reported in
    // `survivorship_conflicts` instead, and the canonical's pre-merge value
    // is left untouched. See `entity_crud::survivorship`'s doc comment for
    // the full decision table. M01 Core C-12: `survivorship_rules` is now
    // resolved before this transaction opened — see that call site's own
    // comment.
    let (mut fill, mut survivorship_conflicts) =
        compute_fill(&attrs, canonical_obj, duplicate_obj, &survivorship_rules);
    // A15-T10: a person's per-field choices win over the rules.
    apply_picks(
        &attrs,
        canonical_obj,
        duplicate_obj,
        picks,
        &mut fill,
        &mut survivorship_conflicts,
    )?;

    let mut merged_row = canonical_row.clone();
    if !fill.is_empty() {
        // C-07 — the union-fill is an ordinary write to the canonical
        // record: route it through `update_one` so it gets the same rule
        // engine, state-transition guard, lookup-liveness check
        // (`lock_lookup_targets` — a dangling lookup copied from the
        // duplicate is now refused instead of written unchecked), and
        // row_version guard every other write already has, instead of a
        // bespoke `UPDATE` with none of them. `update_one` itself runs
        // `validate_body`/`validate_field_write_grants`/
        // `guard_hierarchy_cycles` internally, so the fill no longer needs
        // its own copies of those calls.
        //
        // `MutationMode::BundleRecordSet` skips only `lock_file_field_sessions`
        // (lookup-liveness stays enforced): the fill can copy an existing
        // file-typed field's value from the duplicate's own row, which never
        // had — and does not need — a fresh interactive upload session
        // scoped to the canonical record, the same "no interactive session
        // to check a file-typed field's key against" reasoning that mode's
        // own doc comment gives for a record-set apply. Reusing an existing
        // mode rather than adding a merge-specific one, since this file is
        // deliberately scoped away from editing `entity_mutation.rs` (C-07);
        // that doc comment naming this as a second caller is a known,
        // reported drift for a follow-up there.
        let mutation = update_one(
            &mut tx,
            state,
            ctx,
            &entity_name,
            entity_id,
            canonical_id,
            &attrs,
            &fill,
            actor_user_id,
            canonical_row_version,
            MutationMode::BundleRecordSet(None),
        )
        .await?;
        merged_row = mutation
            .new_row
            .ok_or_else(|| AppError::internal("update_one returned no new_row for the fill"))?;
    }

    // Redirect every dependent lookup field from the duplicate to the
    // canonical id â€” no `is_active` filter, deliberately (see doc comment).
    //
    // D-133 follow-up / merge-dependent-authz: the entity-level `ctx.require`
    // check above is necessary but not sufficient under a narrowed
    // access_level â€” a caller can hold coarse "update" privilege on
    // `dep_entity` in general while specific rows fall outside their
    // record-level (RLS) scope. RLS-filtering the redirect `UPDATE` (the
    // previous approach) would silently leave those rows still pointing at
    // the (about-to-be-retired) duplicate â€” an inconsistent merge, not a
    // smaller one. Instead: for every dependent entity, enumerate every row
    // currently pointing at the duplicate, lock it, and count how many fall
    // inside the caller's authorized scope. If the authorized count is less
    // than the total, the caller cannot legally redirect all of them â€”
    // reject the whole merge before mutating anything. Only once every
    // dependent row across every dependent entity is confirmed authorized
    // and locked do the redirects below run, all inside the same
    // transaction.
    let mut redirect_summary: Vec<String> = Vec::new();
    // A15-T5: every row moved off the duplicate, for the merge log (undo).
    let mut moved: Vec<Value> = Vec::new();
    for ((dep_entity, dep_field, _mode), (access_level, dep_owner_visible)) in
        dependents.iter().zip(dep_access.iter())
    {
        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);
        // D-369: attrs come along with the same registry read entity_id
        // already needed — an arc-swap read, not an extra DB round trip.
        let dep_meta = state.entities.load().get(dep_entity).cloned();
        let dep_entity_id = dep_meta.as_ref().map(|meta| meta.entity_id);
        let dep_attrs = dep_meta.as_ref().map(|m| m.attrs.as_slice()).unwrap_or(&[]);
        // M01 Core C-12: resolved before this transaction opened — see that
        // call site's own comment.
        let access_level = *access_level;
        let dep_owner_visible = *dep_owner_visible;
        let dep_privilege_key = format!("{dep_entity}.update");
        let rls = match (dep_entity_id, access_level) {
            (Some(id), Some(access_level)) => rls_predicate_with_conditions(
                ctx,
                id,
                "d",
                access_level,
                RecordAction::Update.share_capability(),
                &dep_privilege_key,
                dep_attrs,
                dep_owner_visible,
                2,
            ),
            _ => None,
        };
        let predicate = rls.as_ref().map_or("", |p| p.sql.as_str());

        // Lock every dependent row referencing the duplicate FIRST, with no
        // RLS filter â€” this is the total set, and once locked it cannot
        // change out from under this transaction. Then, against that exact
        // frozen id list (not a second independent query against live
        // table state, which could see a different snapshot than the count
        // above and race), determine the authorized subset. Comparing
        // lengths this way has no TOCTOU window between "how many total" and
        // "how many authorized" â€” both answers come from the same locked set.
        let lock_sql =
            format!("SELECT id FROM {dep_table} WHERE {dep_field_ident} = $1 FOR UPDATE");
        let lock_sql = attome_db::tag_dynamic("entity.merge", &lock_sql);
        let all_ids: Vec<Uuid> = sqlx::query_scalar(&lock_sql)
            .bind(duplicate_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;

        if all_ids.is_empty() {
            continue;
        }

        let authorized_sql =
            format!("SELECT d.id FROM {dep_table} d WHERE d.id = ANY($1) {predicate}");
        let authorized_sql = attome_db::tag_dynamic("entity.merge", &authorized_sql);
        let mut aq = sqlx::query_scalar::<_, Uuid>(&authorized_sql).bind(&all_ids);
        if let Some(pred) = &rls {
            if let Some(tb) = &pred.tier_binds {
                aq = bind_rls_predicate(aq, tb);
            }
            for bind in &pred.condition_binds {
                aq = aq.bind(bind);
            }
        }
        let authorized_ids: Vec<Uuid> = aq.fetch_all(&mut *tx).await.map_err(AppError::internal)?;

        if authorized_ids.len() != all_ids.len() {
            // At least one dependent row referencing the duplicate falls
            // outside the caller's record-level access on `dep_entity`.
            // Reject the entire merge â€” do not redirect only the rows the
            // caller happens to be authorized on.
            return Err(AppError::Forbidden);
        }

        // P-hierarchy-mutation-locking / F028: when the field being
        // redirected is this entity's own self-referencing hierarchy field
        // (dep_entity == entity_name), the redirect below is a batch UPDATE
        // that can rewrite many rows' parent pointer at once â€” no
        // single-record guard covers that. Reuse the authorized/locked id
        // set above (it's exactly the rows the redirect is about to touch)
        // and reject the whole merge if repointing any of them at
        // canonical_id would create a cycle or a self-parent, before the
        // redirect runs.
        if dep_entity == &entity_name {
            guard_hierarchy_redirect_cycle(
                &mut tx,
                dep_entity,
                dep_field,
                canonical_id,
                &authorized_ids,
            )
            .await?;
        }

        // `RETURNING id` (not a bare row count) — C-07: each redirected row
        // needs its own change-feed row, same reasoning
        // `apply_dependents_on_delete`'s own cascade step already applies to
        // the rows IT touches (`entity_mutation.rs`'s "each one needs its
        // own feed row, so the ids have to come back" comment).
        let redirect_sql = format!(
            "UPDATE {dep_table} SET {dep_field_ident} = $1, row_version = row_version + 1, \
                    modified_at = NOW(), modified_by = $3 WHERE id = ANY($2) RETURNING id"
        );
        let redirect_sql = attome_db::tag_dynamic("entity.merge", &redirect_sql);
        let redirected_ids: Vec<Uuid> = sqlx::query_scalar(&redirect_sql)
            .bind(canonical_id)
            .bind(&authorized_ids)
            .bind(actor_user_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let affected = redirected_ids.len();
        if affected > 0 {
            // C-07 — a consumer holding a derived copy of `dep_entity`
            // (search index, cache, another node's read replica) must see
            // this FK move off the retired duplicate.
            attome_core::change_feed::emit_many(
                &mut tx,
                dep_entity,
                &redirected_ids,
                attome_core::ChangeOperation::Update,
            )
            .await?;
            redirect_summary.push(format!("{dep_entity}.{dep_field}: {affected}"));
            moved.push(serde_json::json!({
                "entity": dep_entity,
                "field": dep_field,
                "ids": redirected_ids,
            }));
        }
    }

    // C-07 — retire the duplicate through the same primitive an ordinary
    // DELETE uses: it re-locks/re-verifies `is_active`, applies the entity's
    // restrict/orphan/cascade-deactivate policy (a no-op in the normal case
    // — every dependent field was already redirected off the duplicate
    // above, under this same transaction's locks, so nothing should still
    // reference it), and emits the duplicate's own change-feed row — the
    // disclosure defect `apply_dependents_on_delete`'s own doc comment
    // describes for an ordinary delete applied equally to a duplicate that
    // never got one at all. No `expected_row_version`: the merge route's
    // `If-Match` names the canonical record at the URL id, not the
    // duplicate, and the duplicate is already locked/re-verified active
    // earlier in this same transaction (the `lock_order` loop above) — no
    // concurrent writer can have touched it since.
    // A15-T5: the entity's merge mode: retire the duplicate (the default), or
    // keep it live with a redirect to the survivor.
    let merge_mode: String = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT merge_mode FROM merge_setting WHERE entity_logicalname = $1"
    ))
    .bind(&entity_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .unwrap_or_else(|| "soft_delete".to_owned());
    let keep_merged = merge_mode == "keep_merged";
    let cascade_summary: Vec<String> = if keep_merged {
        Vec::new()
    } else {
        delete_one(
            &mut tx,
            &entity_name,
            &dependents,
            duplicate_id,
            actor_user_id,
            None,
            &crate::entity_mutation::DeleteOrigin::with_id(
                crate::entity_mutation::DeleteKind::Merge,
                format!("merge:{duplicate_id}"),
            ),
        )
        .await?
        .cascade_summary
    };
    // A15-T5: the merge log holds what undo needs: both rows as they were,
    // every moved row, the mode, and the survivor's version after the merge.
    let survivor_row_version = merged_row
        .get("row_version")
        .and_then(Value::as_i64)
        .unwrap_or(canonical_row_version);
    let merge_log_id: Uuid = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "INSERT INTO merge_log (entity_logicalname, survivor_id, merged_ids, survivor_before, \
             merged_before, moved_rows, merge_mode, merged_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id"
    ))
    .bind(&entity_name)
    .bind(canonical_id)
    .bind(vec![duplicate_id])
    .bind(&canonical_row)
    .bind(&duplicate_row)
    .bind(serde_json::json!({
        "survivor_row_version": survivor_row_version,
        "moved": moved,
    }))
    .bind(&merge_mode)
    .bind(actor_user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // M1-T1: the survivor's own event, named, so a flow can start on a merge.
    attome_core::change_feed::emit_with(
        &mut tx,
        &entity_name,
        canonical_id,
        attome_core::ChangeOperation::Update,
        Some(MERGED_EVENT),
        &attome_core::change_feed::ChangePayload::default(),
    )
    .await?;
    if keep_merged {
        sqlx::query(attome_db::tagged_sql!(
            "entity.merge",
            "INSERT INTO record_redirect (entity_logicalname, from_id, to_id, merge_log_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (entity_logicalname, from_id) DO UPDATE \
             SET to_id = EXCLUDED.to_id, merge_log_id = EXCLUDED.merge_log_id"
        ))
        .bind(&entity_name)
        .bind(duplicate_id)
        .bind(canonical_id)
        .bind(merge_log_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // D-432 / M13 — closes out the steward queue row this merge resolved, in
    // the same transaction as the merge itself. `AND status = 'open'` makes a
    // double-submit (two stewards racing the same candidate) a no-op on the
    // second call rather than silently overwriting who resolved it first;
    // `rows_affected` is deliberately not checked here — a candidate_id that
    // no longer matches 'open' (already merged/dismissed, or simply wrong)
    // must not fail an otherwise-successful merge of the two underlying
    // records.
    // A29-T3: the survivor keeps every system's id: the merged record's links
    // move to it, and the merged record's own external ids become links.
    sqlx::query(attome_db::tagged_sql!(
        "entity.merge",
        "UPDATE external_id_link SET record_id = $1 WHERE entity = $2 AND record_id = $3"
    ))
    .bind(canonical_id)
    .bind(&entity_name)
    .bind(duplicate_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for attr in &attrs {
        let Some(system) = super::upsert::external_id_system_of(attr) else {
            continue;
        };
        let value: Option<String> = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.merge",
            &format!(
                "SELECT {}::text FROM {table} WHERE id = $1",
                quote_ident(&attr.logicalname)
            ),
        ))
        .bind(duplicate_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .flatten();
        if let Some(value) = value {
            sqlx::query(
                attome_db::tagged_sql!("entity.merge", "INSERT INTO external_id_link (entity, record_id, system, external_id) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (entity, system, external_id) DO UPDATE SET record_id = EXCLUDED.record_id"),
            )
            .bind(&entity_name)
            .bind(canonical_id)
            .bind(system)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }

    if let Some(candidate_id) = candidate_id {
        sqlx::query(attome_db::tagged_sql!(
            "entity.merge",
            "UPDATE duplicate_candidate \
                SET status = 'merged', resolved_at = NOW(), resolved_by = $2, \
                    row_version = row_version + 1 \
              WHERE id = $1 AND status = 'open'"
        ))
        .bind(candidate_id)
        .bind(actor_user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    let canonical_event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: Some(canonical_id),
        operation: AuditOperation::Update,
        version_before: None,
        version_after: None,
        user_context: user_ctx.clone(),
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: Some(format!(
            "merged {duplicate_id} into this record; filled fields: {}; redirected dependents: \
             {}; survivorship conflicts: {}",
            fill.keys().cloned().collect::<Vec<_>>().join(", "),
            if redirect_summary.is_empty() {
                "none".to_owned()
            } else {
                redirect_summary.join(", ")
            },
            if survivorship_conflicts.is_empty() {
                "none".to_owned()
            } else {
                survivorship_conflicts.join(", ")
            }
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };

    let duplicate_event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: Some(duplicate_id),
        operation: if keep_merged {
            AuditOperation::Merge
        } else {
            AuditOperation::SoftDelete
        },
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: None,
        event_comment: Some(if keep_merged {
            format!("merged into {canonical_id}; kept, redirecting to it")
        } else if cascade_summary.is_empty() {
            format!("merged into {canonical_id}")
        } else {
            format!(
                "merged into {canonical_id}; cascade-deactivated dependents: {}",
                cascade_summary.join(", ")
            )
        }),
        changed_fields: vec![],
        snapshot_json: None,
    };

    // C-10: both events commit together through the ring's batch entry
    // point — `commit_mutation`'s single-`MutationResult` shape does not fit
    // a merge (two records mutated, one canonical `Update` and one
    // duplicate `SoftDelete`), so `commit_events` is the shape that does:
    // write N audit events in the caller's open transaction, commit once,
    // rw-pin once. No share grant, no file mirror, no privilege-grant/
    // audit-user invalidation — merge has never needed any of the three
    // (neither participant is a fresh row or a file-typed-column write, and
    // this path has never invalidated the privilege-grant/audit-user caches
    // either — not a gap this item closes).
    MutationRing::new(state)
        .commit_events(
            tx,
            vec![canonical_event, duplicate_event],
            actor_user_id,
            "merge entity_input",
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "commit failed on merge {entity_input}");
            e
        })?;

    let lookups = resolve_lookup_meta(state, ctx, &merged_row, &attrs).await;
    let response = build_response(&state.base.config.storage.attribute_encryption_key, entity_id, merged_row, &attrs, lookups, ctx, &entity_name);

    Ok(MergeOutcome {
        response,
        survivorship_conflicts,
        merge_log_id,
    })
}

// ── A15-T5: preview and undo ─────────────────────────────────────────────────

/// One relationship a merge would move rows along.
#[derive(Debug, Serialize, ToSchema)]
pub struct MergeMove {
    /// `entity.field`.
    pub relationship: String,
    pub count: i64,
}

/// A15-T5: what merging would do, without doing it.
#[derive(Debug, Serialize, ToSchema)]
pub struct MergePreview {
    /// Rows that would move from the merged record to the survivor.
    pub moved: Vec<MergeMove>,
    /// The flows an update of the survivor or a delete of the merged record
    /// would start.
    pub flows: Vec<String>,
    /// The survivor's values after the merge.
    #[schema(value_type = Object)]
    pub result: Value,
    /// Fields a `manual` survivorship rule leaves to a person.
    pub conflicts: Vec<String>,
    /// `soft_delete` or `keep_merged`.
    pub merge_mode: String,
}

/// A15-T5: the merge preview: per relationship how many rows would move to
/// the survivor, the flows the merge would start, the merged values, and
/// the fields left to a person. Writes nothing.
pub async fn merge_preview(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    canonical_id: Uuid,
    duplicate_id: Uuid,
    picks: &serde_json::Map<String, Value>,
) -> Result<MergePreview, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, entity_input).await?;
    for id in [canonical_id, duplicate_id] {
        require_record_access(state, ctx, entity_id, &entity_name, id, RecordAction::Read).await?;
    }
    let db = &state.base.db;
    let table = quote_ident(&entity_name);
    let cols = attome_core::select_columns(&attrs, true);
    let read = |id: Uuid| {
        let sql = format!(
            "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
        );
        async move {
            sqlx::query_scalar::<_, Value>(&attome_db::tag_dynamic("entity.merge", &sql))
                .bind(id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
                .ok_or(AppError::NotFound)
        }
    };
    let canonical = read(canonical_id).await?;
    let duplicate = read(duplicate_id).await?;
    let (Value::Object(canonical_obj), Value::Object(duplicate_obj)) = (&canonical, &duplicate)
    else {
        return Err(AppError::internal("merge preview rows were not objects"));
    };
    let rules = load_survivorship_rules(db, &entity_name).await?;
    let (mut fill, mut conflicts) = compute_fill(&attrs, canonical_obj, duplicate_obj, &rules);
    apply_picks(
        &attrs,
        canonical_obj,
        duplicate_obj,
        picks,
        &mut fill,
        &mut conflicts,
    )?;
    let mut result = canonical_obj.clone();
    for (field, value) in fill {
        result.insert(field, value);
    }
    let mut moved = Vec::new();
    let dependents = state.entities.load().dependents_of(entity_id);
    for (dep_entity, dep_field, _) in dependents {
        let count: i64 = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.merge",
            &format!(
                "SELECT count(*) FROM {} WHERE {} = $1",
                quote_ident(&dep_entity),
                quote_ident(&dep_field)
            ),
        ))
        .bind(duplicate_id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if count > 0 {
            moved.push(MergeMove {
                relationship: format!("{dep_entity}.{dep_field}"),
                count,
            });
        }
    }
    let flows: Vec<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT DISTINCT d.name FROM workflow_trigger_index ti \
           JOIN workflow_definition_version v ON v.id = ti.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
          WHERE ti.role = 'entry' AND ti.entity_logicalname = $1 \
            AND ti.match_type IN ('update', 'delete') ORDER BY 1"
    ))
    .bind(&entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let merge_mode: String = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT merge_mode FROM merge_setting WHERE entity_logicalname = $1"
    ))
    .bind(&entity_name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .unwrap_or_else(|| "soft_delete".to_owned());
    Ok(MergePreview {
        moved,
        flows,
        result: Value::Object(result),
        conflicts,
        merge_mode,
    })
}

/// A15-T5: what an undo restored.
#[derive(Debug, Serialize, ToSchema)]
pub struct MergeUndone {
    pub survivor_id: Uuid,
    pub merged_ids: Vec<Uuid>,
    /// Rows moved back to the merged records.
    pub rows_moved_back: i64,
}

/// A15-T5: undoes a merge as one unit: the survivor's values as they were
/// before it, the merged record live again (or its redirect removed), and
/// every row the merge moved pointing back at the merged record. Refused
/// with 409 when the survivor changed since the merge (its version differs
/// from the one the merge left), when `expected_survivor_row_version` is
/// stale, or when the merge was undone already; one undo of a merge runs at
/// a time (`attome-records/merge_undo:{id}`).
pub async fn undo_merge(
    state: &EngineState,
    ctx: &SecurityContext,
    actor_user_id: Uuid,
    merge_log_id: Uuid,
    expected_survivor_row_version: Option<i64>,
) -> Result<MergeUndone, AppError> {
    #[allow(clippy::type_complexity)]
    let log: Option<(
        String,
        Uuid,
        Vec<Uuid>,
        Value,
        Value,
        String,
        Option<chrono::DateTime<Utc>>,
    )> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT entity_logicalname, survivor_id, merged_ids, survivor_before, moved_rows, \
                    merge_mode, undone_at FROM merge_log WHERE id = $1"
    ))
    .bind(merge_log_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (entity, survivor_id, merged_ids, survivor_before, moved_rows, merge_mode, undone_at) =
        log.ok_or(AppError::NotFound)?;
    if undone_at.is_some() {
        return Err(AppError::Conflict("this merge was undone already"));
    }
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, &entity).await?;
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        survivor_id,
        RecordAction::Update,
    )
    .await?;
    let table = quote_ident(&entity_name);
    let (user_ctx, org_ref) = fetch_audit_ctx(state, actor_user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT pg_try_advisory_xact_lock($1, hashtext($2))"
    ))
    .bind(crate::ADVISORY_LOCK_NAMESPACE)
    .bind(format!("attome-records/merge_undo:{merge_log_id}"))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("this merge is being undone already"));
    }
    let still_open: bool = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT undone_at IS NULL FROM merge_log WHERE id = $1 FOR UPDATE"
    ))
    .bind(merge_log_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !still_open {
        return Err(AppError::Conflict("this merge was undone already"));
    }

    // The survivor must be exactly as the merge left it.
    let current: Option<i64> = sqlx::query_scalar(&attome_db::tag_dynamic(
        "entity.merge",
        &format!("SELECT row_version FROM {table} WHERE id = $1 FOR UPDATE"),
    ))
    .bind(survivor_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let current = current.ok_or(AppError::NotFound)?;
    let logged = moved_rows
        .get("survivor_row_version")
        .and_then(Value::as_i64);
    if logged != Some(current) || expected_survivor_row_version.is_some_and(|e| e != current) {
        return Err(AppError::VersionConflict);
    }

    // The survivor's own fields as they were before the merge.
    let restore_cols: Vec<String> = attrs
        .iter()
        .filter(|a| !a.is_computed())
        .map(|a| a.logicalname.clone())
        .filter(|name| survivor_before.get(name).is_some())
        .collect();
    if !restore_cols.is_empty() {
        let list = restore_cols
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(&attome_db::tag_dynamic("entity.merge", &format!(
            "UPDATE {table} SET ({list}) = (SELECT {list} FROM jsonb_populate_record(NULL::{table}, $1)), \
                    row_version = row_version + 1, modified_at = now(), modified_by = $3 \
              WHERE id = $2"
        )))
        .bind(&survivor_before)
        .bind(survivor_id)
        .bind(actor_user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // The merged records come back (or stop redirecting).
    if merge_mode == "keep_merged" {
        sqlx::query(attome_db::tagged_sql!(
            "entity.merge",
            "DELETE FROM record_redirect WHERE merge_log_id = $1"
        ))
        .bind(merge_log_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    } else {
        sqlx::query(&attome_db::tag_dynamic(
            "entity.merge",
            &format!(
                "UPDATE {table} SET is_active = true, row_version = row_version + 1, \
                    modified_at = now(), modified_by = $2 WHERE id = ANY($1)"
            ),
        ))
        .bind(&merged_ids)
        .bind(actor_user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // Every moved row points back at the record it was moved off.
    let back_to = merged_ids.first().copied().ok_or(AppError::NotFound)?;
    let mut rows_moved_back = 0i64;
    // Only fields the registry still knows are written to.
    let moves: Vec<(String, String, Vec<Uuid>)> = {
        let registry = state.entities.load();
        moved_rows
            .get("moved")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|moved| {
                let dep_entity = moved.get("entity").and_then(Value::as_str)?;
                let dep_field = moved.get("field").and_then(Value::as_str)?;
                let known = registry
                    .get(dep_entity)
                    .is_some_and(|meta| meta.attrs.iter().any(|a| a.logicalname == dep_field));
                let ids: Vec<Uuid> = moved
                    .get("ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                    .collect();
                known.then(|| (dep_entity.to_owned(), dep_field.to_owned(), ids))
            })
            .collect()
    };
    for (dep_entity, dep_field, ids) in &moves {
        let (dep_entity, dep_field) = (dep_entity.as_str(), dep_field.as_str());
        let back: Vec<Uuid> = sqlx::query_scalar(&attome_db::tag_dynamic(
            "entity.merge",
            &format!(
                "UPDATE {} SET {} = $1, row_version = row_version + 1, modified_at = now(), \
                    modified_by = $4 WHERE id = ANY($2) AND {} = $3 RETURNING id",
                quote_ident(dep_entity),
                quote_ident(dep_field),
                quote_ident(dep_field)
            ),
        ))
        .bind(back_to)
        .bind(ids)
        .bind(survivor_id)
        .bind(actor_user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !back.is_empty() {
            attome_core::change_feed::emit_many(
                &mut tx,
                dep_entity,
                &back,
                attome_core::ChangeOperation::Update,
            )
            .await?;
            rows_moved_back += back.len() as i64;
        }
    }
    let mut touched = vec![survivor_id];
    touched.extend(merged_ids.iter().copied());
    attome_core::change_feed::emit_many(
        &mut tx,
        &entity_name,
        &touched,
        attome_core::ChangeOperation::Update,
    )
    .await?;
    sqlx::query(attome_db::tagged_sql!(
        "entity.merge",
        "UPDATE merge_log SET undone_at = now(), undone_by = $2 WHERE id = $1"
    ))
    .bind(merge_log_id)
    .bind(actor_user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let event = |record_id: Uuid, operation: AuditOperation, comment: String| AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: Some(record_id),
        operation,
        version_before: None,
        version_after: None,
        user_context: user_ctx.clone(),
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("merge_undone".to_owned()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let mut events = vec![event(
        survivor_id,
        AuditOperation::Update,
        format!("merge {merge_log_id} undone; {rows_moved_back} row(s) moved back"),
    )];
    for id in &merged_ids {
        events.push(event(
            *id,
            AuditOperation::Restore,
            format!("merge {merge_log_id} undone"),
        ));
    }
    MutationRing::new(state)
        .commit_events(tx, events, actor_user_id, "undo merge")
        .await?;
    Ok(MergeUndone {
        survivor_id,
        merged_ids,
        rows_moved_back,
    })
}

// ── A15-T7: the preview and undo routes ─────────────────────────────────────

/// Preview a merge
///
/// `POST /api/v1/{entity}/{id}/merge/preview` — what merging `duplicate_id`
/// into the record at `id` would do (see [`merge_preview`]); writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/merge/preview",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record")),
    responses(
        (status = 200, description = "What the merge would move, start and produce", body = MergePreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "A record is missing or not visible to the caller", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "runs survivorship and counts related rows without writing"
    )))),
)]
pub(super) async fn merge_preview_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<attome_security::record_action::Read>>,
    Path((entity_input, canonical_id)): Path<(String, Uuid)>,
    Json(body): Json<Value>,
) -> Result<Json<MergePreview>, AppError> {
    let duplicate_id = body
        .get("duplicate_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("body must have a 'duplicate_id' UUID".into()))?;
    let picks = picks_of(&body)?;
    Ok(Json(
        merge_preview(
            &state,
            &ctx,
            &entity_input,
            canonical_id,
            duplicate_id,
            &picks,
        )
        .await?,
    ))
}

/// Undo a merge
///
/// `POST /api/v1/{entity}/merges/{merge_id}/undo` — undoes a merge as one
/// unit (see [`undo_merge`]). Needs `{entity}.update` and `{entity}.delete`
/// (it rewrites the survivor and brings the merged records back) and access
/// to the survivor; `If-Match` may carry the survivor's row version.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/merges/{merge_id}/undo",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("merge_id" = Uuid, Path, description = "The merge"),
        ("If-Match" = Option<String>, Header, description = "The survivor's row_version"),
    ),
    responses(
        (status = 200, description = "The merge is undone", body = MergeUndone),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such merge of this entity", body = ErrorResponse),
        (status = 409, description = "The survivor changed since the merge, or it was undone already", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update), (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Restore)])))),
)]
pub(super) async fn undo_merge_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<UpdateAndDelete>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, merge_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MergeUndone>, AppError> {
    let (_, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    let logged: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "entity.merge",
        "SELECT entity_logicalname FROM merge_log WHERE id = $1"
    ))
    .bind(merge_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if logged.as_deref() != Some(entity_name.as_str()) {
        return Err(AppError::NotFound);
    }
    let expected = optional_expected_row_version(&headers)?;
    Ok(Json(
        undo_merge(&state, &ctx, claims.sub, merge_id, expected).await?,
    ))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(merge_records, merge_preview_route, undo_merge_route))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

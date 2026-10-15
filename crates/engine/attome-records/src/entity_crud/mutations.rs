use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use attome_audit::{AuditFieldChange, AuditOperation};
use attome_auth::SessionClaims;
use attome_core::changeset::{RecordingCtx, reference};
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_profiler::measure;
use attome_security::record_action::{Create, Delete, Read, Update};
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::Value;
use uuid::Uuid;

use crate::entity_mutation::{
    MutationMode, is_multi_valued, json_to_str, validate_body, validate_lookup_targets,
};
use crate::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};

use super::access::{
    FILE_MIRROR_ENTITY, PRIVILEGE_GRANT_ENTITY, guard_cascade_dependent_access,
    require_child_parent_access, require_child_parent_access_for_write, require_record_access,
    require_record_access_any_active_state, require_record_read,
};
use super::resolve::resolve_entity;
use super::response::{EntityRecordResponse, build_response, resolve_lookup_meta};
use super::row_version::{
    expected_row_version, if_none_match_row_version, optional_expected_row_version,
    row_version_etag,
};
use attome_types::ErrorResponse;

/// Builds the changed-fields list by comparing submitted body against an optional
/// old record snapshot. When old is None every field is treated as a new value.
///
/// For lookup-typed fields, also resolves `old_lookup_entity`/`old_lookup_name`/
/// `new_lookup_entity`/`new_lookup_name` for `audit_detail` (previously
/// hardcoded to `None` unconditionally â€” DECISIONS.md D-057's own note flagged
/// this as a separate, pre-existing gap). Resolution batches by distinct target
/// entity across every lookup field touched by this change (old and new value
/// together), same shape as `resolve_lookup_meta` â€” at most one query per
/// distinct target entity, never one per field.
/// M01 Core C-12: `conn` is the caller's own already-open mutation
/// transaction connection (`&mut *tx`), never the pool. Every call site
/// invokes this after the mutation itself already ran inside that same
/// transaction (its old/new values often come straight from the
/// mutation's own result), so the transaction is always still open here --
/// running these lookup-display-name queries against `state.base.db`
/// instead would check out a second pool connection while the first is
/// still held, self-deadlocking every such request once the pool
/// saturates.
pub async fn field_changes_from_obj(
    conn: &mut sqlx::PgConnection,
    state: &EngineState,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    old: Option<&Value>,
) -> Vec<AuditFieldChange> {
    let registry = state.entities.load();
    let mut ids_by_target: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    for attr in attrs {
        if attr.field_type_int != 11 {
            continue;
        }
        let Some(target_id) = attr.lookup_entity_ref else {
            continue;
        };
        let Some(new_v) = obj.get(&attr.logicalname) else {
            continue;
        };
        let old_v = old.and_then(|r| r.get(&attr.logicalname));
        for v in [Some(new_v), old_v] {
            if let Some(id) = v
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                ids_by_target.entry(target_id).or_default().insert(id);
            }
        }
    }

    // (target logicalname, resolved display names) per distinct target,
    // copied out of the registry before any `.await` below.
    let mut queries = Vec::new();
    for (target_id, ids) in ids_by_target {
        let Some(target_meta) = registry.get_by_id(target_id) else {
            continue;
        };
        queries.push((
            target_id,
            target_meta.logicalname.clone(),
            target_meta.primary_name_attribute.clone(),
            ids.into_iter().collect::<Vec<_>>(),
        ));
    }
    drop(registry);

    let mut targets: HashMap<Uuid, (String, HashMap<Uuid, String>)> = HashMap::new();
    for (target_id, target_logicalname, name_attr, ids) in queries {
        let names: HashMap<Uuid, String> = match &name_attr {
            Some(col) => {
                let target_table = quote_ident(&target_logicalname);
                let name_col = quote_ident(col);
                let rows: Result<Vec<(Uuid, Option<String>)>, _> = sqlx::query_as(&format!(
                    "SELECT id, {name_col}::text FROM {target_table} WHERE id = ANY($1)"
                ))
                .bind(&ids)
                .fetch_all(&mut *conn)
                .await;
                match rows {
                    Ok(rows) => rows
                        .into_iter()
                        .filter_map(|(id, n)| n.map(|n| (id, n)))
                        .collect(),
                    Err(e) => {
                        tracing::warn!(error = %e, target_entity = %target_logicalname, "lookup display-name resolution failed for audit detail, leaving lookup_name blank");
                        HashMap::new()
                    }
                }
            }
            None => HashMap::new(),
        };
        targets.insert(target_id, (target_logicalname, names));
    }

    attrs
        .iter()
        .filter_map(|attr| {
            obj.get(&attr.logicalname).map(|new_v| {
                let old_v = old.and_then(|r| r.get(&attr.logicalname));
                let lookup = attr.lookup_entity_ref.and_then(|id| targets.get(&id));

                let resolve = |v: Option<&Value>| -> (Option<String>, Option<String>) {
                    let Some((target_logicalname, names)) = lookup else {
                        return (None, None);
                    };
                    let Some(id) = v
                        .and_then(Value::as_str)
                        .and_then(|s| Uuid::parse_str(s).ok())
                    else {
                        return (None, None);
                    };
                    (Some(target_logicalname.clone()), names.get(&id).cloned())
                };

                let (old_lookup_entity, old_lookup_name) = resolve(old_v);
                let (new_lookup_entity, new_lookup_name) = resolve(Some(new_v));

                AuditFieldChange {
                    field_name: attr.logicalname.clone(),
                    display_name: None,
                    data_type: None,
                    old_value: old_v.and_then(|v| json_to_str(v, attr)),
                    new_value: json_to_str(new_v, attr),
                    old_display_value: None,
                    new_display_value: None,
                    old_lookup_entity,
                    old_lookup_name,
                    new_lookup_entity,
                    new_lookup_name,
                    is_sensitive: attr.is_sensitive,
                }
            })
        })
        .collect()
}

// â”€â”€ GET /api/v1/{entity}/{id} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_record(
    State(state): State<EngineState>,
    // `{entity}.read` is enforced by the extractor (D-353). What remains here
    // is the record-level half, which needs the database and so cannot move.
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    // A polymorphic-audit row (`audit_header`/`audit_detail`/
    // `audit_snapshot`) that resolves to a business record is gated
    // solely by the caller's access to *that* record
    // (`require_referenced_record_access`, D-147) — the audit row's own
    // `require_record_access` predicate is skipped in that case rather than
    // additionally required, since nobody grants access to an individual
    // audit-log entry via `record_share` keyed to its own id; requiring
    // both would make a narrowed-tier caller's audit visibility
    // unsatisfiable regardless of what they're otherwise entitled to see.
    // A row with no resolvable target (e.g. a login/logout event, or any
    // non-audit entity — `polymorphic_audit_target` returns `None` for
    // both) falls back to the ordinary check. U1 (basic-units plan B-R1): a
    // note/communication/tag/follow is also gated by the record it is
    // attached to, on top of its own check. All three live in
    // `require_record_read`, shared with `read_record` and the timeline and
    // history routes (D-601).
    require_record_read(&state, &ctx, entity_id, &entity_name, record_id).await?;

    // entity_name is DB-sourced, safe for dynamic SQL; quoted so a
    // logicalname matching a reserved word (order, user, group, ...) still
    // parses.
    let table = quote_ident(&entity_name);

    // P1.12: routes to the readonly pool when configured, unless ctx.user_id
    // wrote recently (sticky-primary) â€” see AppState::read_pool.
    let pool = state.base.read_pool(ctx.user_id).await;

    // Caching-efficiency fix (2026-07-30): a matching `If-None-Match` short-
    // circuits before the wide, per-field-grant-filtered SELECT below â€” the
    // whole point being to save that query, not just the wire payload â€” via
    // one cheap PK-indexed probe of just `row_version`. Runs only when the
    // header is present and parses; absent/malformed always falls through
    // to the full read unchanged, matching today's behavior byte-for-byte
    // for every caller that doesn't send the header.
    //
    // TODO(needs live Postgres to verify, not available in this sandbox):
    // confirm the planner uses the `id` primary-key index for this probe
    // (expected, `id` is the PK) and that the two-query path is actually a
    // net win over the single wide SELECT under real traffic before calling
    // this optimization validated â€” see coding-guidelines.md Â§14
    // (performance work is evidence-driven).
    if let Some(if_none_match) = if_none_match_row_version(&headers) {
        let current_version: Option<i64> = sqlx::query_scalar(&format!(
            "SELECT row_version FROM {table} WHERE id = $1 AND is_active = true"
        ))
        .bind(record_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::internal)?;

        // `None` (record missing/inactive) deliberately falls through to the
        // full read below, which resolves to the correct `AppError::NotFound`
        // â€” a 304 must never be the way a caller learns a record disappeared.
        if let Some(current_version) = current_version
            && current_version == if_none_match
        {
            return Ok((
                StatusCode::NOT_MODIFIED,
                [(axum::http::header::ETAG, row_version_etag(current_version))],
            )
                .into_response());
        }
    }

    let response = read_record_projection(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        &attrs,
        record_id,
        attome_security::field_gate::Surface::Interactive,
    )
    .await?;
    let etag = row_version_etag(response.row_version);
    Ok((
        StatusCode::OK,
        [(axum::http::header::ETAG, etag)],
        Json(response),
    )
        .into_response())
}

/// The record read itself, with every transport concern removed: no
/// extractor, no `If-None-Match`, no ETag, no `Response`.
///
/// Extracted so `attome-ai`'s `record.get` reuses THIS, rather than growing a
/// second SELECT with its own opinion about field grants (guidelines Â§9: reuse
/// the shared engine path, never bypass it with route-local SQL). The
/// record-level authorization above it is likewise shared â€” see
/// [`read_record`], which is the entry point an action calls.
///
/// Explicit column projection (external review, 2026-07-21): no `SELECT *` â€”
/// the registry-sourced `attrs` already says which columns exist and which are
/// readable, so a wide entity's unrequested/sensitive columns are never pulled
/// across the wire, not fetched-then-pruned in Rust. Per-field grant
/// (F013/F135, D-111): each `is_sensitive` attribute is gated independently
/// via `ctx.has_field_read_grant`, the same predicate `build_response` uses.
pub(crate) async fn read_record_projection(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    surface: attome_security::field_gate::Surface,
) -> Result<EntityRecordResponse, AppError> {
    // entity_name is DB-sourced, safe for dynamic SQL; quoted so a
    // logicalname matching a reserved word (order, user, group, ...) still
    // parses.
    let table = quote_ident(entity_name);
    // P1.12: routes to the readonly pool when configured, unless this caller
    // wrote recently (sticky-primary) â€” see AppState::read_pool.
    let pool = state.base.read_pool(ctx.user_id).await;

    // D-589: AI context and document generation read one record at a time,
    // but they are bulk surfaces.
    let cols = if surface == attome_security::field_gate::Surface::Bulk {
        let primary_name = state
            .entities
            .load()
            .get(entity_name)
            .and_then(|m| m.primary_name_attribute.clone());
        attome_security::field_gate::bulk_columns(ctx, entity_name, attrs, primary_name.as_deref())
    } else {
        attome_core::select_columns_filtered(attrs, |attr| {
            ctx.has_field_read_grant(entity_name, &attr.logicalname)
        })
    };
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    );

    let row: Option<Value> = sqlx::query_scalar::<_, Value>(&sql)
        .bind(record_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::internal)?;

    let row = row.ok_or(AppError::NotFound)?;
    let lookups = resolve_lookup_meta(state, ctx, &row, attrs).await;
    Ok(build_response(
        entity_id,
        row,
        attrs,
        lookups,
        ctx,
        entity_name,
    ))
}

/// Read one record as `ctx`, with the full record-level authorization the HTTP
/// GET applies â€” resolution, the polymorphic-audit carve-out, `require_record_access`,
/// per-field grants, and lookup metadata.
///
/// This is the entry point `attome-ai`'s `record.get` calls. It exists so
/// that "an action inherits exactly what the human can already see" is a
/// property of shared code rather than a claim two implementations have to
/// keep agreeing on. The action layer adds risk gating and provenance ON TOP
/// of this; it does not get its own way into the data.
pub async fn read_record(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
) -> Result<EntityRecordResponse, AppError> {
    read_record_for(
        state,
        ctx,
        entity_input,
        record_id,
        attome_security::field_gate::Surface::Interactive,
    )
    .await
}

/// [`read_record`] for a caller that feeds a D-589 bulk surface (AI context
/// and tools, document generation): same record-level authorization, but the
/// projection follows the caller's bulk field exposure.
pub async fn read_record_bulk(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
) -> Result<EntityRecordResponse, AppError> {
    read_record_for(
        state,
        ctx,
        entity_input,
        record_id,
        attome_security::field_gate::Surface::Bulk,
    )
    .await
}

async fn read_record_for(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    surface: attome_security::field_gate::Surface,
) -> Result<EntityRecordResponse, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, entity_input).await?;
    // Same decision as the handler above — see its comment.
    require_record_read(state, ctx, entity_id, &entity_name, record_id).await?;
    read_record_projection(
        state,
        ctx,
        entity_id,
        &entity_name,
        &attrs,
        record_id,
        surface,
    )
    .await
}

// â”€â”€ POST /api/v1/{entity} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[utoipa::path(
    post,
    path = "/api/v1/{entity}",
    tag = "entity",
    params(("entity" = String, Path)),
    responses(
        (status = 201, description = "Success", body = EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
pub(super) async fn create_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Create>>,
    Extension(claims): Extension<SessionClaims>,
    recording: RecordingCtx,
    Path(entity_input): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<EntityRecordResponse>), AppError> {
    // The extractor above IS the create-privilege check. See
    // `create_record_for`'s doc for what a non-HTTP caller must do instead.
    // D-787 rule 7: a write to a reference-data entity is recorded as
    // `upsert_record` when a changeset is in play (`Op::UpsertRecord`, in
    // `entity_mutation::record_reference_write`); every other write is
    // unchanged (the ambient recording is read only for reference data).
    let (_, response) = reference::scope(
        Arc::new(recording.0),
        create_record_for(&state, &ctx, claims.sub, &entity_input, body),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// What a dry-run create found (A3-T3).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CreateCheck {
    /// The create would succeed.
    pub valid: bool,
    /// Why it would not, as the create would say it.
    pub error: Option<String>,
    /// Business-rule warnings the create would raise.
    pub warnings: Vec<CreateCheckWarning>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CreateCheckWarning {
    pub rule: String,
    pub field: Option<String>,
    pub message: String,
}

/// Runs the whole create path for `values` and rolls it back: every check a
/// create makes (normalisation, types, required fields, field grants, record
/// validators, business rules, lookups), and nothing written. The caller must
/// already hold the create privilege on `entity`, as for
/// [`create_record_for`].
pub async fn validate_create(
    state: &EngineState,
    security: &attome_server::security::SecurityContext,
    entity: &str,
    values: &serde_json::Map<String, Value>,
) -> Result<CreateCheck, AppError> {
    let (_, entity_name, attrs, _) = resolve_entity(state, entity).await?;
    let actor = crate::mutation_ring::MutationActor::fetch(state, security.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let outcome = crate::entity_mutation::create_one(
        &mut tx,
        state,
        security,
        &entity_name,
        &attrs,
        values,
        security.user_id,
        actor.org_ref,
        crate::entity_mutation::MutationMode::Strict,
    )
    .await;
    // Always rolled back: a check never writes.
    tx.rollback().await.map_err(AppError::internal)?;
    match outcome {
        Ok(result) => Ok(CreateCheck {
            valid: true,
            error: None,
            warnings: result
                .warnings
                .iter()
                .map(|w| CreateCheckWarning {
                    rule: w.rule_name.clone(),
                    field: w.field.clone(),
                    message: w.message.clone(),
                })
                .collect(),
        }),
        Err(
            error @ (AppError::Validation(_)
            | AppError::Conflict(_)
            | AppError::Forbidden
            | AppError::NotFound),
        ) => Ok(CreateCheck {
            valid: false,
            error: Some(error.to_string()),
            warnings: Vec::new(),
        }),
        Err(other) => Err(other),
    }
}

/// `POST /api/v1/{entity}/validate` (A3-T3): checks a record without saving it.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/validate",
    tag = "entity",
    params(("entity" = String, Path)),
    responses(
        (status = 200, description = "Whether the create would succeed, why not, and its warnings; nothing is written", body = CreateCheck),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the create privilege", body = ErrorResponse),
        (status = 422, description = "The body is not a JSON object", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "runs the create path and rolls it back; writes nothing")))),
)]
pub(super) async fn validate_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Create>>,
    Path(entity_input): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<CreateCheck>, AppError> {
    let values = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    Ok(Json(
        validate_create(&state, &ctx, &entity_input, values).await?,
    ))
}

/// Creates a record, given an **already-authorized** caller.
///
/// Extracted from the handler (TODO-060) so a non-HTTP caller — an action —
/// can reach the create path without a second implementation of it.
///
/// # The authorization contract, which is the whole reason this doc exists
///
/// **This function does NOT check the create privilege.** The HTTP handler's
/// `Authorized<RecordScoped<Create>>` extractor is what performs that check,
/// and it runs off an `AuthorizedContext` the `authz` middleware placed on the
/// request — machinery a non-HTTP caller does not go through and cannot
/// construct.
///
/// So **every non-HTTP caller must call `SecurityContextExt::require(entity,
/// "create")` first.** That is not a second enforcement path: `require` is the
/// shared implementation of the same rule the extractor mirrors, and
/// `record_scoped_policy_matches_require` (attome-security's context tests) locks
/// the two together.
///
/// Getting this wrong reaches `entity_mutation::create_one` with no privilege
/// check at all, which is why the requirement is stated here rather than left
/// to a caller to infer from the parameter list.
pub async fn create_record_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    body: Value,
) -> Result<(uuid::Uuid, EntityRecordResponse), AppError> {
    let state = state.clone();
    let entity_input = entity_input.to_owned();
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    // D-516 ruling 5 (audit 10/10 plan item 1.1). `entity_mutation::create_one`
    // refuses the ledger too — that is the choke point covering the bundle
    // record-set and workflow Create Record paths — but this one is checked
    // here, before `validate_body` below, so the answer is "forbidden" rather
    // than a 422 that tells an unauthorized caller which columns a
    // well-formed forgery would need.
    if super::LEDGER_ENTITIES.contains(&entity_name.as_str()) {
        return Err(AppError::Forbidden);
    }
    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    measure!("entity.create.validate", {
        // D-524: an omitted engine-managed field counts as its declared
        // initial value for the required check; `create_one` writes it.
        let with_initial =
            crate::entity_mutation::apply_engine_managed_initial_values(&state, &entity_name, obj)?;
        validate_body(&attrs, with_initial.as_ref().unwrap_or(obj), true)?;
        validate_lookup_targets(&state, &attrs, obj).await?;
    });
    require_child_parent_access_for_write(&state, ctx, &entity_name, None, obj).await?;

    let actor = MutationActor::fetch(&state, acting_user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut mutation = measure!("entity.create.db_write", {
        crate::entity_mutation::create_one(
            &mut tx,
            &state,
            ctx,
            &entity_name,
            &attrs,
            obj,
            acting_user_id,
            actor.org_ref,
            MutationMode::Strict,
        )
        .await?
    });
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("create mutation returned no row"))?;
    let warnings = std::mem::take(&mut mutation.warnings);

    let mut audit = MutationAudit::new();
    audit.changed_fields = field_changes_from_obj(&mut tx, &state, &attrs, obj, None).await;

    // C-10: the D-133 (2) creator-share grant, the `attome_document` file
    // mirror, the audit write, the commit, and the post-commit invalidation +
    // rw-pin are now the ring's job — see `MutationRing::commit_mutation`'s
    // doc comment for why this used to be copy-pasted at every mutation call
    // site instead.
    let committed = measure!("entity.create.commit", {
        MutationRing::new(&state)
            .commit_mutation(
                tx,
                ctx,
                entity_id,
                &entity_name,
                &attrs,
                &actor,
                AuditOperation::Create,
                MutationSideEffects {
                    grant_creator_share: true,
                    mirror_file_fields: true,
                },
                GrantInvalidation::ByRow(Some(&row)),
                audit,
                "create entity_input",
                mutation,
            )
            .await?
    });

    let lookups = resolve_lookup_meta(&state, ctx, &row, &attrs).await;
    let response =
        build_response(entity_id, row, &attrs, lookups, ctx, &entity_name).with_warnings(warnings);
    Ok((committed.result.record_id, response))
}

/// Updates a record, given an **already-authorized** caller — the
/// non-HTTP-caller counterpart to [`create_record_for`], added for M59
/// (`attome-integration`'s admin credential-provisioning flow, D-425): a
/// system row is created via `create_record_for` first, and once its real
/// id is known, `credential_ref` is backfilled onto it through this
/// function rather than a route-local `UPDATE` against a provisioned
/// entity table (guidelines §9 — reuse the engine's mutation primitives).
///
/// # The authorization contract
///
/// Unlike `create_record_for`, this function DOES perform the record-level
/// access check itself (`require_record_access`) — for update, unlike
/// create, that check is an ordinary async function or the caller could not
/// reasonably invoke it (there is no `Authorized<RecordScoped<Update>>>`
/// analog outside axum extraction). It still does **not** substitute for
/// the table-level privilege check `Authorized<RecordScoped<Update>>`
/// performs for an HTTP caller — same rule `create_record_for` states: a
/// non-HTTP caller must call `SecurityContextExt::require(entity, "update")`
/// itself first.
pub async fn update_record_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    record_id: uuid::Uuid,
    // Mandatory, not `Option` — D-079: a version-less update is a 422 for an
    // HTTP caller (`expected_row_version`'s header-required doc comment), and
    // this non-HTTP counterpart preserves the same contract rather than
    // quietly defaulting to an unguarded last-write-wins update.
    expected_row_version: i64,
    body: Value,
) -> Result<EntityRecordResponse, AppError> {
    update_record_for_with_comment(
        state,
        ctx,
        acting_user_id,
        entity_input,
        record_id,
        expected_row_version,
        body,
        None,
    )
    .await
}

/// [`update_record_for`] with a caller-supplied audit `event_comment` — M07
/// Phase A (§4.1): `POST /{entity}/{id}/transition` is a thin caller of this,
/// so a state change through that route runs exactly the generic PATCH path
/// (guards, rules, record validators, change feed, audit, rw-pin) and only
/// adds its `comment` to the audit event. Same authorization contract as
/// [`update_record_for`].
#[allow(clippy::too_many_arguments)]
pub async fn update_record_for_with_comment(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    record_id: uuid::Uuid,
    expected_row_version: i64,
    body: Value,
    event_comment: Option<String>,
) -> Result<EntityRecordResponse, AppError> {
    update_record_for_outcome(
        state,
        ctx,
        acting_user_id,
        entity_input,
        record_id,
        expected_row_version,
        body,
        event_comment,
        MutationMode::Strict,
    )
    .await
    .map(|outcome| outcome.response)
}

/// What [`update_record_for_outcome`] did: the record as the caller may see
/// it, plus the approval request the write submitted instead of performing
/// its transition (M07 Phase F), if any. `response.approval_request_id()`
/// carries the same id for an HTTP caller.
pub struct UpdateOutcome {
    pub response: EntityRecordResponse,
    pub approval: Option<crate::entity_mutation::ApprovalSubmitted>,
}

impl std::fmt::Debug for UpdateOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateOutcome").finish_non_exhaustive()
    }
}

/// [`update_record_for_with_comment`] with the full outcome and an explicit
/// [`MutationMode`]. Every caller except the state engine's approval flow
/// passes `MutationMode::Strict`; `attome_state::approval` passes
/// `MutationMode::ApprovalFlow(request_id)` to move a record out of a
/// pending state, which the mutation path checks against that request (see
/// the variant's doc comment) — so this is still the one write path, with
/// the one audit event, change feed row and rw-pin. Same authorization
/// contract as [`update_record_for`].
#[allow(clippy::too_many_arguments)]
pub async fn update_record_for_outcome(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    record_id: uuid::Uuid,
    expected_row_version: i64,
    body: Value,
    event_comment: Option<String>,
    mode: MutationMode,
) -> Result<UpdateOutcome, AppError> {
    let state = state.clone();
    let entity_input = entity_input.to_owned();
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(&state, &entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    require_record_access(
        &state,
        ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;
    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    validate_body(&attrs, obj, false)?;
    validate_lookup_targets(&state, &attrs, obj).await?;
    require_child_parent_access(&state, ctx, &entity_name, record_id).await?;
    require_child_parent_access_for_write(&state, ctx, &entity_name, Some(record_id), obj).await?;

    let actor = MutationActor::fetch(&state, acting_user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut mutation = crate::entity_mutation::update_one(
        &mut tx,
        &state,
        ctx,
        &entity_name,
        entity_id,
        record_id,
        &attrs,
        obj,
        acting_user_id,
        expected_row_version,
        mode,
    )
    .await?;
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("update mutation returned no row"))?;
    let approval = mutation.approval.clone();
    let warnings = std::mem::take(&mut mutation.warnings);

    let mut audit = MutationAudit::new();
    // M07 Phase F: the entity event of a write parked pending approval names
    // the request, so the timeline shows why the record is not in the state
    // that was asked for.
    audit.event_comment = match &approval {
        Some(a) => Some(match event_comment {
            Some(c) => format!(
                "{c} (approval request {} submitted for '{}' -> '{}')",
                a.request_id, a.from, a.requested
            ),
            None => format!(
                "approval request {} submitted for '{}' -> '{}'",
                a.request_id, a.from, a.requested
            ),
        }),
        None => event_comment,
    };
    // The diff is computed from the row actually written (the pending state
    // for a parked transition), not from the caller's body.
    let written_obj;
    let diff_obj = match (&approval, row.as_object()) {
        (Some(_), Some(written)) => {
            written_obj = obj
                .keys()
                .filter_map(|k| written.get(k).map(|v| (k.clone(), v.clone())))
                .collect::<serde_json::Map<String, Value>>();
            &written_obj
        }
        _ => obj,
    };
    audit.changed_fields =
        field_changes_from_obj(&mut tx, &state, &attrs, diff_obj, mutation.old_row.as_ref()).await;

    // C-10: see `create_record_for`'s comment at its own ring call.
    MutationRing::new(&state)
        .commit_mutation(
            tx,
            ctx,
            entity_id,
            &entity_name,
            &attrs,
            &actor,
            AuditOperation::Update,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: true,
            },
            GrantInvalidation::ByRow(Some(&row)),
            audit,
            "update entity_input",
            mutation,
        )
        .await?;

    let lookups = resolve_lookup_meta(&state, ctx, &row, &attrs).await;
    let response = build_response(entity_id, row, &attrs, lookups, ctx, &entity_name)
        .with_approval_request_id(approval.as_ref().map(|a| a.request_id))
        .with_warnings(warnings);
    Ok(UpdateOutcome { response, approval })
}

/// Reconciles `attome_document` rows mirroring `entity_name`/`record_id`'s own
/// file-typed fields, in the same transaction as the write that touched them
/// (D-36x). Called from both `create_record_for` and `update_record` — every
/// generic-CRUD write is a potential source/target change for a file field,
/// not just an explicit edit of that one field, so this always re-diffs the
/// mutated entity's file columns against the mirror rather than trying to
/// detect "did this specific field change."
///
/// No-op, cheaply, in three cases: `entity_name` is `attome_document` itself
/// (don't mirror Document's own `file` field into itself — infinite
/// regress), the mutated entity has no `file`-typed attributes at all, or
/// `attome_document` is not provisioned in this deployment (checked via
/// `resolve_entity` rather than assuming it exists — the Documents feature
/// is optional metadata, not a hard dependency generic mutation code should
/// take on one specific entity).
///
/// Mirrored rows never get their own `record_share` grant — a
/// `attome_document` row's visibility is purely inherited from the record it
/// mirrors (`access.rs::POLYMORPHIC_AUDIT_ENTITIES`), so there is nothing to
/// grant. They also don't get a dedicated audit event of their own: the
/// mutation that changed the source field is already audited (with that
/// field's before/after value), and a Document row is a derived, read-only
/// projection of that same change, not an independently authored record —
/// `write_entity_change_event` inside `create_one` still fires, so reactive
/// subsystems (workflow triggers, etc.) still see it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_file_field_documents(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user_id: Uuid,
    org_ref: Uuid,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    row: &Value,
) -> Result<(), AppError> {
    if entity_name == FILE_MIRROR_ENTITY {
        return Ok(());
    }
    if !attrs.iter().any(AttrInfo::is_file_backed) {
        return Ok(());
    }
    let Ok((_, _, doc_attrs, _)) = resolve_entity(state, FILE_MIRROR_ENTITY).await else {
        return Ok(());
    };
    let Some(obj) = row.as_object() else {
        return Ok(());
    };

    for attr in attrs.iter().filter(|a| a.is_file_backed()) {
        let current_keys: Vec<String> = match obj.get(&attr.logicalname) {
            Some(value) if is_multi_valued(attr) => value
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            Some(value) => value
                .as_str()
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default(),
            None => Vec::new(),
        };

        // `record_id`/`source_field` are plain `text` columns (see
        // `access.rs::polymorphic_audit_target`'s comment on why
        // `attome_document.record_id` can't be a `lookup`-typed column) — bind
        // as strings, not `Uuid`, to match.
        let existing: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, file FROM attome_document \
             WHERE entity_name = $1 AND record_id = $2 AND source_field = $3 AND is_active = true",
        )
        .bind(entity_name)
        .bind(record_id.to_string())
        .bind(&attr.logicalname)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        for (doc_id, key) in &existing {
            if current_keys.contains(key) {
                continue;
            }
            sqlx::query(
                "UPDATE attome_document SET is_active = false, modified_by = $1, \
                 modified_at = now(), row_version = row_version + 1 WHERE id = $2",
            )
            .bind(acting_user_id)
            .bind(doc_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            attome_core::change_feed::emit_tx(
                tx,
                FILE_MIRROR_ENTITY,
                *doc_id,
                attome_core::ChangeOperation::Delete,
            )
            .await?;
        }

        for key in &current_keys {
            if existing.iter().any(|(_, k)| k == key) {
                continue;
            }
            // Same `{uuid-36chars}-{filename}` key shape every file field
            // uses (`files.rs::final_key`) — same stripping
            // `AttachmentComponent.displayName` does client-side.
            let last_segment = key.rsplit('/').next().unwrap_or(key);
            let display_name = last_segment.get(37..).unwrap_or(last_segment).to_owned();

            let mut doc_obj = serde_json::Map::new();
            doc_obj.insert("name".into(), Value::String(display_name));
            doc_obj.insert("entity_name".into(), Value::String(entity_name.to_owned()));
            doc_obj.insert("record_id".into(), Value::String(record_id.to_string()));
            doc_obj.insert("folder".into(), Value::String("uploads".to_owned()));
            doc_obj.insert("file".into(), Value::String(key.clone()));
            doc_obj.insert(
                "source_field".into(),
                Value::String(attr.logicalname.clone()),
            );

            crate::entity_mutation::create_one(
                tx,
                state,
                ctx,
                FILE_MIRROR_ENTITY,
                &doc_attrs,
                &doc_obj,
                acting_user_id,
                org_ref,
                MutationMode::MirroredFileWrite,
            )
            .await?;
        }
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/api/v1/{entity}/{id}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
    ),
    responses(
        (status = 200, description = "Success", body = EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
pub(super) async fn update_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<SessionClaims>,
    recording: RecordingCtx,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<EntityRecordResponse>, AppError> {
    // C-10: this used to be a byte-for-byte copy of `update_record_for`
    // (the same resolve/access-check/validate/update_one/mirror/audit/
    // commit/invalidate/rw-pin sequence, with `ctx`/`claims.sub` spelled
    // differently). Header parsing is the one thing that non-HTTP-caller
    // version cannot do for itself, so that is all this handler still does.
    let expected_version = expected_row_version(&headers)?;
    // D-787 rule 7: see `create_record` (reference data only).
    let response = reference::scope(
        Arc::new(recording.0),
        update_record_for(
            &state,
            &ctx,
            claims.sub,
            &entity_input,
            record_id,
            expected_version,
            body,
        ),
    )
    .await?;
    Ok(Json(response))
}

/// `DELETE /api/v1/{entity}/{id}?reason=`.
#[derive(Debug, serde::Deserialize)]
pub(super) struct DeleteQuery {
    reason: Option<String>,
}

/// A18-T2: a request's delete belongs to the operation its
/// `Attome-Operation-Id` header names, else to the request itself.
pub fn request_delete_origin(
    headers: &axum::http::HeaderMap,
) -> crate::entity_mutation::DeleteOrigin {
    let named = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    match named("attome-operation-id").or_else(|| named("x-request-id")) {
        Some(id) => crate::entity_mutation::DeleteOrigin::with_id(
            crate::entity_mutation::DeleteKind::Request,
            id,
        ),
        None => {
            crate::entity_mutation::DeleteOrigin::new(crate::entity_mutation::DeleteKind::Request)
        }
    }
}

/// Soft-deletes a record, given an **already-authorized** caller — the
/// non-HTTP-caller counterpart to the `DELETE /api/v1/{entity}/{id}` handler,
/// added for C5's `record.delete` action (guidelines §9 — reuse the engine's
/// mutation primitives rather than a route-local path).
///
/// # The authorization contract
///
/// Same as [`update_record_for`]: this function performs the record-level
/// access check (`require_record_access`) and the cascade-dependent access
/// guard itself, but **not** the table-level privilege check
/// `Authorized<RecordScoped<Delete>>` performs for an HTTP caller — a
/// non-HTTP caller must call `SecurityContextExt::require(entity, "delete")`
/// itself first. `expected_row_version` is the optional `If-Match` (DATA-7).
pub async fn delete_record_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    record_id: uuid::Uuid,
    expected_row_version: Option<i64>,
    origin: &crate::entity_mutation::DeleteOrigin,
) -> Result<(), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    crate::entity_mutation::require_metadata_table_unlocked(state, ctx, &entity_name).await?;
    require_record_access(
        state,
        ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Delete,
    )
    .await?;
    require_child_parent_access(state, ctx, &entity_name, record_id).await?;
    let actor = MutationActor::fetch(state, acting_user_id).await;
    let dependents = state.entities.load().dependents_of(entity_id);
    // M01 Core C-12: resolved here, on the pool, before the transaction below
    // opens — see `resolve_cascade_dependent_access`'s doc comment.
    let cascade_access =
        super::access::resolve_cascade_dependent_access(state, ctx, &dependents).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    guard_cascade_dependent_access(&mut tx, state, ctx, &dependents, record_id, &cascade_access)
        .await?;
    // DATA-7/CONC-1 — optional `If-Match`. `delete_one` already threads an
    // `Option<i64>` down to `apply_dependents_on_delete`, which returns
    // `VersionConflict` (409) on mismatch; this path just never supplied one.
    let mutation = crate::entity_mutation::delete_one(
        &mut tx,
        &entity_name,
        &dependents,
        record_id,
        acting_user_id,
        expected_row_version,
        origin,
    )
    .await?;

    let mut audit = MutationAudit::new();
    audit.event_comment = if mutation.cascade_summary.is_empty() {
        None
    } else {
        Some(format!(
            "cascade-deactivated dependents: {}",
            mutation.cascade_summary.join(", ")
        ))
    };

    // C-10: see `create_record_for`'s comment at its own ring call.
    // `GrantInvalidation::ByRow(None)` matches this route's own pre-ring
    // behavior — the row still exists (only `is_active` flipped), so the
    // fallback live-table SELECT `invalidate_privilege_grant_target` runs
    // when given no row still finds it.
    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            entity_id,
            &entity_name,
            &attrs,
            &actor,
            AuditOperation::SoftDelete,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(None),
            audit,
            "delete entity_input",
            mutation,
        )
        .await?;
    Ok(())
}

#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("If-Match" = Option<String>, Header,
         description = "Optional row_version for optimistic concurrency (DATA-7). \
                        Omitted, the delete is unguarded as before; supplied and stale, \
                        the response is 409."),
        ("reason" = Option<String>, Query,
         description = "Why the record is deleted (A18); required when the entity's bin \
                        setting says so, else 422 delete_reason_required."),
        ("Attome-Operation-Id" = Option<String>, Header,
         description = "Groups deletes into one action the bin can restore at once; \
                        defaults to the request id."),
    ),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "If-Match row_version did not match the stored record", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::SoftDelete)])))),
)]
pub(super) async fn delete_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Delete>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<DeleteQuery>,
) -> Result<StatusCode, AppError> {
    // C5: the whole sequence lives in `delete_record_for`; header parsing is
    // the one thing it cannot do for itself — same split `update_record`
    // makes with `update_record_for`.
    let origin = request_delete_origin(&headers).reason(query.reason.as_deref());
    delete_record_for(
        &state,
        &ctx,
        claims.sub,
        &entity_input,
        record_id,
        optional_expected_row_version(&headers)?,
        &origin,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A18-T6: the approval action a permanent delete waits on when its
/// entity's bin setting asks for one.
pub const ACTION_RECORD_HARD_DELETE: &str = "record.hard_delete";

/// Permanently removes a record. This is intentionally separate from the
/// conventional DELETE route, whose public contract is a reversible
/// deactivation. A physical delete is refused while *any* record still points
/// at the target (including an inactive record), so it can never manufacture
/// dangling metadata-level lookups.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/hard-delete",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("If-Match" = Option<String>, Header,
         description = "Optional row_version for optimistic concurrency (DATA-7). \
                        Omitted, the delete is unguarded as before; supplied and stale, \
                        the response is 409."),
    ),
    responses(
        (status = 204, description = "Record permanently deleted"),
        (status = 202, description = "The entity's bin setting asks for approval: the request was submitted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's hard_delete privilege", body = ErrorResponse),
        (status = 409, description = "Record is referenced, under legal hold, or the If-Match row_version did not match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::HardDelete)])))),
)]
pub(super) async fn hard_delete_record(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Delete>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    use axum::response::IntoResponse;
    let expected_version = optional_expected_row_version(&headers)?;
    let (_, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    let needs_approval: bool =
        sqlx::query_scalar("SELECT hard_delete_needs_approval FROM bin_setting WHERE entity = $1")
            .bind(&entity_name)
            .fetch_optional(&state.base.db)
            .await
            .map_err(attome_db::classify)?
            .unwrap_or(false);
    if let Some(request) = attome_audit::approval::gate_required(
        &state,
        ACTION_RECORD_HARD_DELETE,
        serde_json::json!({
            "entity": entity_name,
            "record_id": record_id,
            "expected_version": expected_version,
        }),
        claims.sub,
        needs_approval,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "approval_pending": true,
                "approval_request_id": request.id,
            })),
        )
            .into_response());
    }
    hard_delete_record_for(
        &state,
        &ctx,
        claims.sub,
        &entity_name,
        record_id,
        expected_version,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The permanent delete itself, for a caller already through the route's
/// checks or an approved request (A18-T6): access, the entity's
/// `hard_delete` privilege, legal holds, the physical DELETE, audit and file
/// cleanup.
pub async fn hard_delete_record_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user: Uuid,
    entity_input: &str,
    record_id: Uuid,
    expected_version: Option<i64>,
) -> Result<(), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    crate::entity_mutation::require_metadata_table_unlocked(state, ctx, &entity_name).await?;
    require_record_access_any_active_state(
        state,
        ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Delete,
        false,
    )
    .await?;
    require_child_parent_access(state, ctx, &entity_name, record_id).await?;
    // A18-T6: past the recycle bin is its own privilege, not `delete`.
    ctx.require(
        &entity_name,
        attome_security::entity_privileges::HARD_DELETE_ACTION,
    )?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if attome_core::legal_hold::record_is_held(&mut *tx, &entity_name, record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("record is under an active legal hold"));
    }

    let dependents = state.entities.load().dependents_of(entity_id);
    // DATA-7/CONC-1 — optional `If-Match`. The predicate is a no-op when the
    // caller sent no header ($2 IS NULL), so a header-less hard delete keeps
    // exactly today's behaviour, including not treating "no such row" as an
    // error. C-08: the referenced-by-dependents check, the version-guarded
    // physical DELETE, and the change-feed emit now live in
    // `entity_mutation::hard_delete_one`, same signature family as
    // `delete_one`.
    let mutation = crate::entity_mutation::hard_delete_one(
        &mut tx,
        &entity_name,
        &dependents,
        record_id,
        acting_user,
        expected_version,
    )
    .await?;
    let snapshot = mutation
        .old_row
        .clone()
        .ok_or_else(|| AppError::internal("hard_delete_one returned no pre-delete snapshot"))?;
    // Captured before `snapshot` is moved into the audit event below — a
    // hard delete is the only mutation that removes a row (not just a field
    // value) out from under a file-typed column, so this is the one place
    // that must clean up storage rather than leave the object orphaned
    // (D-362's documented gap, generalized here for every entity with a file
    // field, not just Document).
    let file_keys = file_keys_to_delete(&attrs, &snapshot);
    // Same "captured before the move" reasoning as `file_keys` above, for
    // `GrantInvalidation::ByUser`'s doc-noted hard-delete case: once this row
    // is physically DELETEd its `user_ref` is unrecoverable, so this pulls it
    // out of the snapshot now rather than trying to reconstruct it from
    // `record_id` after commit the way the soft-delete path can.
    let grant_user_ref = (entity_name == PRIVILEGE_GRANT_ENTITY)
        .then(|| snapshot.get("user_ref").and_then(Value::as_str))
        .flatten()
        .and_then(|s| Uuid::parse_str(s).ok());

    let actor = MutationActor::fetch(state, acting_user).await;
    let mut audit = MutationAudit::new();
    audit.event_comment = Some("record permanently deleted from list action".to_owned());
    // Audit 10/10 plan item 5.3 (D-540 ruling 3): the snapshot is a whole-row
    // `row_to_json` capture, so a credential column (password_hash,
    // secret_hash) must never reach it in any form, not even ciphertext —
    // stripped here, before `attome_audit::AuditService::write`'s encryption.
    // `is_sensitive` columns keep their real value only when the audit
    // erasure key encrypts the snapshot at rest (D-107); with no key they are
    // masked, the same D-540 fallback the detail rows get from
    // `attome_audit::value_mode::ValueMode::Restricted`.
    //
    // Runs after `file_keys_to_delete` above, which needs the real storage
    // keys of file-typed columns; stripping first would orphan those objects.
    let snapshot = strip_credential_columns(&entity_name, snapshot);
    audit.snapshot_json = Some(if state.audit_erasure_key.is_some() {
        snapshot
    } else {
        mask_sensitive_columns(&attrs, snapshot)
    });

    // C-10: see `create_record_for`'s comment at its own ring call.
    // `GrantInvalidation::ByUser` (not `ByRow`) because the row is already
    // physically gone — there is nothing left for `ByRow`'s live-table
    // fallback SELECT to find.
    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            entity_id,
            &entity_name,
            &attrs,
            &actor,
            AuditOperation::HardDelete,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByUser(grant_user_ref),
            audit,
            "hard delete record",
            mutation,
        )
        .await?;

    // Best-effort, same posture as the rejected-upload cleanup in files.rs
    // and the orphan sweep in files_scan.rs: the row is already gone and
    // committed, so a storage failure here has nothing left to roll back —
    // log it for the sweep to notice eventually rather than fail the request.
    for key in file_keys {
        let Ok(path) = ObjectPath::parse(&key) else {
            tracing::warn!(record_id = %record_id, key = %key, "hard delete: unparseable storage key, skipping cleanup");
            continue;
        };
        if let Err(e) = state.base.storage.store().delete(&path).await {
            tracing::warn!(record_id = %record_id, key = %key, error = %e, "hard delete: failed to delete storage object");
        }
    }

    Ok(())
}

/// D-540 ruling 3 (plan 5.3): strips `NotCaptured` (credential) columns from
/// a whole-row snapshot before it ever reaches `attome-audit`'s encryption —
/// D-540 is explicit that these are removed from `snapshot_json` *before*
/// encryption, never merely encrypted. `is_sensitive` (`Restricted`) columns
/// are handled separately: encrypted at rest by the audit service when an
/// erasure key is set, otherwise masked by [`mask_sensitive_columns`].
fn strip_credential_columns(entity_name: &str, snapshot: Value) -> Value {
    let Value::Object(mut obj) = snapshot else {
        return snapshot;
    };
    for key in obj.keys().cloned().collect::<Vec<_>>() {
        if attome_core::credential_columns::is_credential_column(Some(entity_name), &key) {
            obj.insert(key, Value::Null);
        }
    }
    Value::Object(obj)
}

/// D-540's no-key fallback for a whole-row snapshot: every non-null
/// `is_sensitive` column becomes `"********"`, matching what
/// `attome_audit`'s `mask_event_in_place` writes into the detail rows when no
/// erasure key is configured. A null stays null, an absent column stays
/// absent.
fn mask_sensitive_columns(attrs: &[AttrInfo], snapshot: Value) -> Value {
    let Value::Object(mut obj) = snapshot else {
        return snapshot;
    };
    for attr in attrs.iter().filter(|a| a.is_sensitive) {
        if let Some(value) = obj.get_mut(&attr.logicalname)
            && !value.is_null()
        {
            *value = Value::String("********".to_owned());
        }
    }
    Value::Object(obj)
}

/// Walks `attrs` for `field_type == file` (D-362's `field_type_int == 12`,
/// single and multi alike — the multi/single split lives entirely in
/// `options.multi`, not a second integer) and reads the object key(s) out of
/// `snapshot` (a `row_to_json` capture taken before the row's `DELETE`).
/// Single-valued: the column is a plain string key. Multi-valued: a JSONB
/// array of keys (D-362). A missing/null value yields nothing for that
/// field, not an error — a file field is optional unless the metadata says
/// otherwise, and validation already ran at write time.
fn file_keys_to_delete(attrs: &[AttrInfo], snapshot: &Value) -> Vec<String> {
    let Some(obj) = snapshot.as_object() else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for attr in attrs.iter().filter(|a| a.is_file_backed()) {
        let Some(value) = obj.get(&attr.logicalname) else {
            continue;
        };
        if is_multi_valued(attr) {
            if let Some(arr) = value.as_array() {
                keys.extend(arr.iter().filter_map(|v| v.as_str().map(str::to_owned)));
            }
        } else if let Some(s) = value.as_str() {
            keys.push(s.to_owned());
        }
    }
    keys
}

/// Restores a soft-deleted record, given an **already-authorized** caller —
/// the non-HTTP-caller counterpart to the `POST /api/v1/{entity}/{id}/restore`
/// handler, added for C5's `record.restore` action.
///
/// # The authorization contract
///
/// Same as [`update_record_for`]: this function performs the record-level
/// access check for a record in any active state itself, but **not** the
/// table-level check `Authorized<RecordScoped<Update>>` performs for an HTTP
/// caller — restore reuses the "update" grant, so a non-HTTP caller must call
/// `SecurityContextExt::require(entity, "update")` itself first.
/// `expected_row_version` is the optional `If-Match` (DATA-7).
pub async fn restore_record_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    acting_user_id: uuid::Uuid,
    entity_input: &str,
    record_id: uuid::Uuid,
    expected_row_version: Option<i64>,
) -> Result<EntityRecordResponse, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    crate::entity_mutation::require_metadata_table_unlocked(state, ctx, &entity_name).await?;
    require_record_access_any_active_state(
        state,
        ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
        false,
    )
    .await?;
    require_child_parent_access(state, ctx, &entity_name, record_id).await?;

    if is_append_only {
        return Err(AppError::Forbidden);
    }
    let actor = MutationActor::fetch(state, acting_user_id).await;
    let dependents = state.entities.load().dependents_of(entity_id);

    // DATA-7/CONC-1 — optional `If-Match`. The predicate is a no-op when the
    // caller sent no header, so a header-less restore is unchanged. C-08:
    // the version/liveness checks, the lookup-liveness re-validation, and
    // the cascade reactivation now live in `entity_mutation::restore_one`,
    // same signature family as `delete_one` — see that function's doc
    // comment for why restore never used to re-check lookup liveness and
    // what closes the gap.
    let expected_version = expected_row_version;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let mutation = crate::entity_mutation::restore_one(
        &mut tx,
        state,
        &entity_name,
        &attrs,
        &dependents,
        record_id,
        acting_user_id,
        expected_version,
    )
    .await?;
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("restore_one returned no restored row"))?;

    let mut audit = MutationAudit::new();
    audit.event_comment = if mutation.cascade_summary.is_empty() {
        None
    } else {
        Some(format!(
            "cascade-reactivated dependents: {}",
            mutation.cascade_summary.join(", ")
        ))
    };

    // C-10: see `create_record_for`'s comment at its own ring call. C-08's
    // own note still applies — restore never called the invalidation hooks
    // before that item, and the ring is what now makes calling them
    // unconditional rather than something each mutation kind has to
    // remember for itself.
    MutationRing::new(state)
        .commit_mutation(
            tx,
            ctx,
            entity_id,
            &entity_name,
            &attrs,
            &actor,
            AuditOperation::Restore,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(Some(&row)),
            audit,
            "restore entity_input",
            mutation,
        )
        .await?;

    let lookups = resolve_lookup_meta(state, ctx, &row, &attrs).await;
    let response = build_response(entity_id, row, &attrs, lookups, ctx, &entity_name);

    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/restore",
    tag = "entity",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("If-Match" = Option<String>, Header,
         description = "Optional row_version for optimistic concurrency (DATA-7). \
                        Omitted, the restore is unguarded as before; supplied and stale, \
                        the response is 409."),
    ),
    responses(
        (status = 200, description = "Success", body = EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Record is not deleted, or the If-Match row_version did not match", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Restore)])))),
)]
pub(super) async fn restore_record(
    State(state): State<EngineState>,
    // Restore is a mutation on an existing record — reuses the "update" grant
    // rather than inventing a new permission verb for a rare admin action.
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
) -> Result<Json<EntityRecordResponse>, AppError> {
    // C5: the whole sequence lives in `restore_record_for`; header parsing is
    // the one thing it cannot do for itself.
    let response = restore_record_for(
        &state,
        &ctx,
        claims.sub,
        &entity_input,
        record_id,
        optional_expected_row_version(&headers)?,
    )
    .await?;
    Ok(Json(response))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    get_record,
    create_record,
    validate_record,
    update_record,
    delete_record,
    hard_delete_record,
    restore_record
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

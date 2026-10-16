use attome_audit::AuditOperation;
use attome_auth::SessionClaims;
use attome_core::changeset::{RecordingCtx, reference};
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_metadata::provision::table_row_count_exceeds;
use attome_security::record_action::CreateAndUpdate;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::AppError;
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::entity_mutation::{
    MutationMode, create_one, json_to_str, sql_cast, update_one, validate_body,
    validate_field_write_grants, validate_lookup_targets,
};
use crate::mutation_ring::{
    GrantInvalidation, MutationActor, MutationAudit, MutationRing, MutationSideEffects,
};

use super::access::{
    POLYMORPHIC_CHILD_ENTITIES, require_child_parent_access, require_child_parent_access_for_write,
    require_record_access_in_tx, resolve_record_access_inputs,
};
use super::mutations::field_changes_from_obj;
use super::resolve::resolve_entity;
use super::response::{EntityRecordResponse, build_response, resolve_lookup_meta};
use super::row_version::expected_upsert_row_version;
use attome_types::ErrorResponse;

// â”€â”€ POST /api/v1/{entity}/upsert â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// M01 Core C-06: same "full-table-scan-shaped DDL never runs unbounded on
/// the request thread" size gate `ATTRIBUTE_INDEX_INLINE_ROW_LIMIT`
/// (`attome-server/admin/attribute.rs`) and `SCHEMA_CHANGE_INLINE_ROW_LIMIT`
/// apply to their own index/constraint DDL — same value (10,000), for the
/// same reason: cheap enough that raising it needs actual evidence, not a
/// guess. See `upsert_record`'s own comment at the gate for what happens
/// once the table is over this and no index exists yet.
const UPSERT_INDEX_INLINE_ROW_LIMIT: i64 = 10_000;

/// A29-T2: the upsert's query string.
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct UpsertQuery {
    /// Match on this attribute's value in `data` (an external id or a
    /// business-key attribute). Without it and without `match`, the
    /// entity's business key.
    key: Option<String>,
}

/// F023 â€” match-or-create by unique key. Body: `{ "match": {...}, "data": {...} }`.
/// `match` selects the candidate row (AND-ed equality, at least one field);
/// `data` overrides/extends it â€” the merged field set is what's actually
/// written on either branch, so a match field's value is preserved on insert
/// without needing to repeat it in `data`.
///
/// M01 Core C-06: once the natural-key resolution below has settled on
/// insert vs. update, the write itself goes through the same
/// `entity_mutation::create_one`/`update_one` primitives interactive CRUD
/// uses â€” never a hand-rolled `INSERT ... ON CONFLICT`. That is what buys
/// upsert autovalue, state-model initial-state defaulting, rule evaluation,
/// the file-upload trust anchor (`lock_file_field_sessions`),
/// `file_version`, and the change-feed row for free, and is why the
/// insert/update decision below happens BEFORE any column list is built
/// rather than inside one shared SQL statement.
///
/// A29-T2: `?key=<attribute>` names the key to match on instead of a
/// `match` object: an external-id attribute or one of the entity's business
/// key, with its value taken from `data`.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/upsert",
    tag = "entity",
    params(("entity" = String, Path), UpsertQuery, super::response::SelectParam),
    responses(
        (status = 201, description = "Success. With `Prefer: return=minimal`, only `{id, row_version}` (a MinimalRecord), with `Preference-Applied` and `ETag`", body = EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create), (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
pub(super) async fn upsert_record(
    State(state): State<EngineState>,
    // RecordScoped, not Admin: the per-entity checks are resolved from the
    // path, and the `require_admin` gate further down is deliberately
    // CONDITIONAL — only provisioning a genuinely new upsert index (production
    // DDL) needs elevation. Typing this handler `Admin` would make every
    // ordinary upsert admin-only.
    //
    // Upsert can create or update, so both grants are required upfront rather
    // than checking post-hoc which branch ran (deliberate simplification) —
    // that pair is what `CreateAndUpdate` names.
    ctx: Authorized<RecordScoped<CreateAndUpdate>>,
    Extension(claims): Extension<SessionClaims>,
    recording: RecordingCtx,
    Path(entity_input): Path<String>,
    Query(query): Query<UpsertQuery>,
    Query(select): Query<super::response::SelectParam>,
    cookie: Option<Extension<attome_server::middleware::auth::CookieSession>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Result<axum::response::Response, AppError> {
    // S1-T3: a bad `select` refuses the request before anything is written.
    let select =
        super::response::resolve_select(&state, &ctx, &entity_input, select.select.as_deref())
            .await?;
    // A29-T4: people may not write a field locked to integrations.
    let parts: Vec<&serde_json::Map<String, Value>> = ["match", "data"]
        .iter()
        .filter_map(|k| body.get(*k).and_then(Value::as_object))
        .collect();
    refuse_integration_only_fields(&state, &entity_input, cookie.is_some(), &parts).await?;
    // D-787 rule 7: a write to a reference-data entity is recorded as
    // `upsert_record` when a changeset is in play (read only for reference
    // data, in `entity_mutation::record_reference_write`; every other upsert
    // is unchanged).
    let (status, Json(record)) = reference::scope(
        Arc::new(recording.0),
        upsert_record_inner(state, ctx, claims, entity_input, query.key, body),
    )
    .await?;
    // S1-T5: `Prefer: return=minimal` answers with the id and row version.
    Ok(super::response::write_response(
        status,
        super::response::return_pref(&headers),
        record.selected(select.as_deref()),
    ))
}

/// The upsert itself (the handler wraps it in the ambient recording).
async fn upsert_record_inner(
    state: EngineState,
    ctx: Authorized<RecordScoped<CreateAndUpdate>>,
    claims: SessionClaims,
    entity_input: String,
    key: Option<String>,
    body: Value,
) -> Result<(StatusCode, Json<EntityRecordResponse>), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(&state, &entity_input).await?;

    if is_append_only {
        return Err(AppError::Forbidden);
    }

    let body_obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    let unknown_envelope = body_obj
        .keys()
        .filter(|key| !matches!(key.as_str(), "match" | "data" | "row_version"))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_envelope.is_empty() {
        return Err(AppError::Validation(format!(
            "unknown upsert field(s): {}",
            unknown_envelope.join(", ")
        )));
    }
    let expected_version = expected_upsert_row_version(body_obj)?;

    let mut data_obj = body
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // A29-T2: a lookup may name its target by an external id.
    resolve_lookups_by_external_id(&state, &attrs, &mut data_obj).await?;
    // A29-T2: the key is a `match` object, or `?key=` / the business key
    // read from `data`; a declared key already has its unique index.
    let (match_owned, key_indexed) = match (body.get("match"), key) {
        (Some(_), Some(_)) => {
            return Err(AppError::Validation(
                "give either a 'match' object or ?key=, not both".into(),
            ));
        }
        (Some(given), None) => {
            let mut given = given
                .as_object()
                .cloned()
                .ok_or_else(|| AppError::Validation("'match' must be an object".into()))?;
            resolve_lookups_by_external_id(&state, &attrs, &mut given).await?;
            (given, false)
        }
        (None, key) => {
            declared_key_match(&state, &entity_name, &attrs, key.as_deref(), &data_obj).await?
        }
    };
    let match_obj = &match_owned;

    if match_obj.is_empty() {
        return Err(AppError::Validation(
            "'match' must have at least one field".into(),
        ));
    }

    validate_body(&attrs, match_obj, false)?;
    validate_body(&attrs, &data_obj, false)?;

    // Merged field set: `data` overrides `match` for any overlapping key â€”
    // this is what's written on both branches.
    let mut merged = match_obj.clone();
    for (k, v) in &data_obj {
        merged.insert(k.clone(), v.clone());
    }
    // D-524: an omitted engine-managed field counts as its declared initial
    // value for the required check (the create branch's `create_one` writes
    // it); a non-initial value is refused here, before either branch.
    let with_initial =
        crate::entity_mutation::apply_engine_managed_initial_values(&state, &entity_name, &merged)?;
    validate_body(&attrs, with_initial.as_ref().unwrap_or(&merged), true)?;
    validate_field_write_grants(&ctx, &entity_name, &attrs, &merged)?;
    validate_lookup_targets(&state, &attrs, &merged).await?;

    let table = quote_ident(&entity_name);
    let match_attrs: Vec<&AttrInfo> = attrs
        .iter()
        .filter(|a| match_obj.contains_key(&a.logicalname))
        .collect();
    if match_attrs
        .iter()
        .any(|a| match_obj[&a.logicalname].is_null())
    {
        return Err(AppError::Validation(
            "upsert match fields cannot be null".into(),
        ));
    }
    let match_columns = match_attrs
        .iter()
        .map(|a| quote_ident(&a.logicalname))
        .collect::<Vec<_>>();
    let conflict_predicates = match_attrs
        .iter()
        .enumerate()
        .map(|(index, attr)| {
            format!(
                "{} = ${}{}",
                quote_ident(&attr.logicalname),
                index + 1,
                sql_cast(attr)
            )
        })
        .collect::<Vec<_>>();
    let conflict_values = match_attrs
        .iter()
        .map(|attr| {
            merged
                .get(&attr.logicalname)
                .and_then(|v| json_to_str(v, attr))
        })
        .collect::<Vec<_>>();
    let key_material = match_attrs
        .iter()
        .map(|a| a.logicalname.as_str())
        .collect::<Vec<_>>()
        .join("_");
    let digest = format!("{:x}", Sha256::digest(key_material.as_bytes()));
    let index_name = quote_ident(&format!("ux_{entity_name}_upsert_{}", &digest[..16]));
    // CREATE INDEX CONCURRENTLY is production DDL, not ordinary record I/O —
    // gate provisioning a genuinely new upsert key behind system.admin so a
    // caller with plain entity create+update privilege can't trigger
    // unreviewed schema changes just by picking a novel `match` field set.
    // An already-provisioned key (the common, repeat-call case) needs no
    // elevated privilege — this must stay cheap for normal upsert traffic.
    // A29-T2: a declared key (external id, business key) brings its own
    // unique index; no ad hoc one is built for it.
    let index_already_exists: bool = key_indexed
        || sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(&index_name)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !index_already_exists {
        ctx.require_admin()?;
        // guidelines §9 / M01 Core C-06: never run a full-table-scan-shaped
        // DDL unbounded on the request thread once a table has grown past a
        // small size — the same size-gate rule
        // `ATTRIBUTE_INDEX_INLINE_ROW_LIMIT`/`SCHEMA_CHANGE_INLINE_ROW_LIMIT`
        // already apply to their own DDL. Unlike those two, there is no
        // durable job wired for this composite, hash-named key shape today
        // — `BuildAttributeIndex` only knows how to rebuild a single
        // already-registered attribute's own index, and adding an
        // equivalent for an ad hoc multi-column upsert key means a new
        // `EngineJob` variant plus a worker dispatch arm in
        // `crates/server/src/jobs.rs`, both outside this change's file
        // scope. Fail closed with a typed error instead of either blocking
        // the request for however long the table takes, or fabricating a
        // job dispatch nothing will ever run; see the C-06 plan note this
        // change's commit message links for the follow-up this leaves.
        if table_row_count_exceeds(&state.base.db, &entity_name, UPSERT_INDEX_INLINE_ROW_LIMIT)
            .await?
        {
            return Err(AppError::Validation(format!(
                "{entity_name} has grown too large to provision a new upsert key inline; \
                 provision this key while the table is smaller"
            )));
        }
    }
    if !key_indexed {
        sqlx::query(&format!(
            "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {index_name} ON {table} ({}) WHERE is_active = TRUE",
            match_columns.join(", ")
        ))
        .execute(&state.base.db)
        .await
        .map_err(|_| AppError::Validation("natural key columns are not indexable".into()))?;
    }

    let actor = MutationActor::fetch(&state, claims.sub).await;

    // M01 Core C-12: resolved here, on the pool, before the transaction below
    // opens. Whether this upsert ends up updating an existing row is not
    // known until the `FOR UPDATE` precheck below runs inside that
    // transaction, but the access-level ladder and owner-visible flag for
    // `(entity, Update)` depend only on the caller and the entity — never on
    // which row matches — so there is no reason to wait, and no excuse to
    // acquire a second pool connection from inside the open transaction the
    // way `require_record_access` would (see
    // `access::require_record_access_in_tx`'s doc comment). Resolved
    // unconditionally: cheap, and unused when this upsert turns out to be an
    // insert.
    let (update_access_level, update_owner_visible) =
        resolve_record_access_inputs(&state, &ctx, entity_id, &entity_name, RecordAction::Update)
            .await?;

    // A15-T11: the duplicate rules judge an upsert like any save, before the
    // transaction opens; the record the upsert would update is not its own
    // duplicate.
    let would_update: Option<Uuid> = {
        let sql = format!(
            "SELECT id FROM {table} WHERE {} AND is_active = TRUE",
            conflict_predicates.join(" AND ")
        );
        let mut probe = sqlx::query_scalar::<_, Uuid>(&sql);
        for value in &conflict_values {
            probe = probe.bind(value.clone());
        }
        probe
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
    };
    let (duplicates, hidden_duplicates) =
        crate::duplicate_check::guard(&state, &ctx, entity_id, &entity_name, would_update, &merged)
            .await?;

    // D-593 (U1): a polymorphic child (note, communication, tag, follow, …)
    // is written only by someone who can read the record it hangs off. The
    // parent checks need their own pool connection, so — like the access
    // inputs above (C-12) — they run before the transaction: resolve the row
    // this upsert would update without a lock, check its current parent and
    // any parent the body names, and refuse below if the row locked inside
    // the transaction turns out to be a different one.
    let child_precheck: Option<Option<Uuid>> = if !ctx.is_admin
        && POLYMORPHIC_CHILD_ENTITIES.contains(&entity_name.as_str())
    {
        let sql = format!(
            "SELECT id FROM {table} WHERE {} AND is_active = TRUE",
            conflict_predicates.join(" AND ")
        );
        let mut probe = sqlx::query_scalar::<_, Uuid>(&sql);
        for value in &conflict_values {
            probe = probe.bind(value.clone());
        }
        let found = probe
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        if let Some(id) = found {
            require_child_parent_access(&state, &ctx, &entity_name, id).await?;
        }
        require_child_parent_access_for_write(&state, &ctx, &entity_name, found, &merged).await?;
        Some(found)
    } else {
        None
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Resolve the conflict row under the same transaction that will perform
    // the actual create/update dispatched below. FOR UPDATE makes the row we
    // may update stable across this decision and the mutation primitive's own
    // guards (hierarchy cycle check, optimistic-concurrency predicate).
    let precheck_sql = format!(
        "SELECT id FROM {table} WHERE {} AND is_active = TRUE FOR UPDATE",
        conflict_predicates.join(" AND ")
    );
    let mut precheck = sqlx::query_scalar::<_, Uuid>(&precheck_sql);
    for value in &conflict_values {
        precheck = precheck.bind(value.clone());
    }
    let existing_id: Option<Uuid> = precheck
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    if child_precheck.is_some_and(|checked| checked != existing_id) {
        // The matching row changed between the parent check and the lock.
        return Err(AppError::Conflict(
            "the matching record changed while the upsert was being authorized; retry",
        ));
    }

    let mut mutation = if let Some(record_id) = existing_id {
        let Some(expected_row_version) = expected_version else {
            return Err(AppError::Validation(
                "row_version is required to update an existing record via upsert".into(),
            ));
        };
        // M01 Core C-12: the tx-safe counterpart of `require_record_access`
        // — this transaction is already open and `record_id` is already
        // locked (the `FOR UPDATE` precheck above), so this runs its EXISTS
        // probe on `tx`'s own connection using the access data resolved
        // before `begin()`, rather than acquiring a second pool connection
        // from inside the open transaction.
        require_record_access_in_tx(
            &mut tx,
            &state,
            &ctx,
            entity_id,
            &entity_name,
            record_id,
            RecordAction::Update,
            update_access_level,
            update_owner_visible,
        )
        .await?;
        update_one(
            &mut tx,
            &state,
            &ctx,
            &entity_name,
            entity_id,
            record_id,
            &attrs,
            &merged,
            claims.sub,
            expected_row_version,
            MutationMode::Strict,
        )
        .await?
    } else {
        create_one(
            &mut tx,
            &state,
            &ctx,
            &entity_name,
            &attrs,
            &merged,
            claims.sub,
            actor.org_ref,
            MutationMode::Strict,
        )
        .await?
    };
    // `existing_id` is `Copy` — still readable after the `if let` above.
    let inserted = existing_id.is_none();
    let (status, operation) = if inserted {
        (StatusCode::CREATED, AuditOperation::Create)
    } else {
        (StatusCode::OK, AuditOperation::Update)
    };

    let mut audit = MutationAudit::new();
    audit.changed_fields =
        field_changes_from_obj(&mut tx, &state, &attrs, &merged, mutation.old_row.as_ref()).await;
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("upsert mutation returned no row"))?;
    let warnings = std::mem::take(&mut mutation.warnings);

    // C-10: see `mutations.rs::create_record_for`'s comment at its own ring
    // call. D-133 (2): the insert branch of an upsert is exactly as much a
    // "create" as `create_record_for`'s own INSERT — `grant_creator_share:
    // inserted` grants the same implicit creator share, or a
    // Team/BusinessUnit-scoped caller could upsert-insert a record it then
    // can't see again.
    MutationRing::new(&state)
        .commit_mutation(
            tx,
            &ctx,
            entity_id,
            &entity_name,
            &attrs,
            &actor,
            operation,
            MutationSideEffects {
                grant_creator_share: inserted,
                mirror_file_fields: false,
            },
            GrantInvalidation::ByRow(Some(&row)),
            audit,
            "upsert entity_input",
            mutation,
        )
        .await?;

    let lookups = resolve_lookup_meta(&state, &ctx, &row, &attrs).await;
    let response = build_response(entity_id, row, &attrs, lookups, &ctx, &entity_name)
        .with_warnings(warnings)
        .with_duplicates(duplicates, hidden_duplicates);

    Ok((status, Json(response)))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(upsert_record))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// A29-T2: the system an attribute holds external ids for
/// (`options.external_id.system`), if it does.
pub(super) fn external_id_system_of(attr: &AttrInfo) -> Option<&str> {
    attr.options
        .as_ref()
        .and_then(|o| o.get("external_id"))
        .and_then(|e| e.get("system"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// A29-T4: a person signed in to the app (a cookie session; API keys and
/// service-to-service callers are integrations) may not write a field locked
/// to integrations. `fields` is a write body: a record's values, or an
/// upsert's `match` and `data`.
pub(super) async fn refuse_integration_only_fields(
    state: &EngineState,
    entity_input: &str,
    interactive: bool,
    fields: &[&serde_json::Map<String, Value>],
) -> Result<(), AppError> {
    if !interactive {
        return Ok(());
    }
    let (_, _, attrs, _) = resolve_entity(state, entity_input).await?;
    let locked = attrs
        .iter()
        .filter(|a| attome_field::integrations_only(a.options.as_ref()))
        .find(|a| fields.iter().any(|f| f.contains_key(&a.logicalname)));
    match locked {
        // Q15-T4: refused by name.
        Some(attr) => Err(AppError::AttributeNotWritable(attr.logicalname.clone())),
        None => Ok(()),
    }
}

/// A29-T2: whether an attribute holds an external id.
fn is_external_id(attr: &AttrInfo) -> bool {
    external_id_system_of(attr).is_some()
}

/// A29-T2: the `match` an upsert without one uses: `key` (an external-id
/// attribute or a business-key attribute) or else the entity's business key,
/// each with its value from `data`; and whether that key already has its
/// own unique index (an external id, or the whole business key).
async fn declared_key_match(
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    key: Option<&str>,
    data: &serde_json::Map<String, Value>,
) -> Result<(serde_json::Map<String, Value>, bool), AppError> {
    let business_key = attome_metadata::provision::read_business_key(&state.base.db, entity_name)
        .await?
        .and_then(|k| k.fields)
        .unwrap_or_default();
    let (fields, indexed): (Vec<String>, bool) = match key {
        Some(key) => {
            let key = key.trim();
            let attr = attrs
                .iter()
                .find(|a| a.logicalname == key)
                .ok_or_else(|| AppError::Validation(format!("key: {key} is not a field")))?;
            if !is_external_id(attr) && !business_key.iter().any(|f| f == key) {
                return Err(AppError::Validation(format!(
                    "key: {key} is neither an external id nor part of the business key"
                )));
            }
            let whole_key = business_key.len() == 1 && business_key[0] == key;
            (
                vec![attr.logicalname.clone()],
                is_external_id(attr) || whole_key,
            )
        }
        None if !business_key.is_empty() => (business_key, true),
        None => {
            return Err(AppError::Validation(
                "give a 'match' object or ?key=, or declare a business key".into(),
            ));
        }
    };
    let mut matched = serde_json::Map::new();
    for field in fields {
        match data.get(&field) {
            Some(value) if !value.is_null() => {
                matched.insert(field, value.clone());
            }
            _ => {
                return Err(AppError::Validation(format!(
                    "data.{field}: the key needs a value"
                )));
            }
        }
    }
    Ok((matched, indexed))
}

/// The most lookups one write may give by external id.
const MAX_LOOKUPS_BY_EXTERNAL_ID: usize = 50;

/// A29-T2: a lookup value given as `{"by": "<external-id attribute of the
/// target>", "value": ...}` becomes the id of the live target record holding
/// that id. Values no record holds are refused together, each named.
pub(super) async fn resolve_lookups_by_external_id(
    state: &EngineState,
    attrs: &[AttrInfo],
    fields: &mut serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let by_id: Vec<(String, Uuid, String, Value)> = attrs
        .iter()
        .filter(|a| a.field_type() == attome_core::FieldType::Lookup)
        .filter_map(|a| {
            let object = fields.get(&a.logicalname)?.as_object()?;
            let by = object.get("by")?.as_str()?.to_owned();
            let value = object.get("value")?.clone();
            Some((a.logicalname.clone(), a.lookup_entity_ref?, by, value))
        })
        .collect();
    if by_id.len() > MAX_LOOKUPS_BY_EXTERNAL_ID {
        return Err(AppError::Validation(format!(
            "at most {MAX_LOOKUPS_BY_EXTERNAL_ID} lookups by external id in one write"
        )));
    }
    let mut unmatched = Vec::new();
    for (field, target_ref, by, value) in by_id {
        let target: Option<String> =
            sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
                .bind(target_ref)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        let target =
            target.ok_or_else(|| AppError::Validation(format!("{field}: no target entity")))?;
        let (_, target_name, target_attrs, _) = resolve_entity(state, &target).await?;
        let by_attr = target_attrs
            .iter()
            .find(|a| a.logicalname == by && is_external_id(a))
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "{field}.by: {by} is not an external id of {target_name}"
                ))
            })?;
        let Some(text) = json_to_str(&value, by_attr) else {
            return Err(AppError::Validation(format!(
                "{field}.value: give the external id"
            )));
        };
        let mut found: Option<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {} WHERE {} = $1{} AND is_active = TRUE",
            quote_ident(&target_name),
            quote_ident(&by_attr.logicalname),
            sql_cast(by_attr)
        ))
        .bind(&text)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        // A29-T3: an id a merged record held now links to the survivor.
        if found.is_none()
            && let Some(system) = external_id_system_of(by_attr)
        {
            found = sqlx::query_scalar(&format!(
                "SELECT l.record_id FROM external_id_link l JOIN {} t ON t.id = l.record_id \
                 WHERE l.entity = $1 AND l.system = $2 AND l.external_id = $3 AND t.is_active = TRUE",
                quote_ident(&target_name)
            ))
            .bind(&target_name)
            .bind(system)
            .bind(&text)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        }
        match found {
            Some(id) => {
                fields.insert(field, Value::String(id.to_string()));
            }
            None => unmatched.push(format!("{field} ({by} = {text})")),
        }
    }
    if unmatched.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "no record holds these external ids: {}",
            unmatched.join(", ")
        )))
    }
}

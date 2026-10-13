//! Record sets: Phase 3 reference data (P-environment-promotion §5 step 24).
//!
//! A record set carries plain business-entity rows, keyed by a declared
//! business key (`RecordSet::key_fields`) rather than by id — the first two
//! intended consumers, notification templates and autovalue sequences, are
//! metadata-defined entities today with no typed bundle component of their
//! own, so a record set carries them with no adapter (§4 "What was cut and
//! why").
//!
//! **Plan** ([`plan_record_sets`]) validates the entity/key shape against the
//! already-exported live bundle (no extra round trip) and resolves each row
//! by its key with a direct, bound SQL read — record data itself is never
//! part of an exported bundle ([`super::model::RecordSet`]'s doc comment), so
//! there is no "live" record set to diff against, only the live table.
//!
//! **Apply** ([`apply_record`]) writes through the SAME entity-mutation
//! primitives every other record write in this platform goes through
//! ([`attome_records::entity_mutation::create_one`]/[`update_one`] — guidelines §9:
//! reuse established mutation primitives, never route-local SQL) under a
//! dedicated [`MutationMode::BundleRecordSet`](attome_records::entity_mutation::MutationMode::BundleRecordSet).
//! Compare-first, same posture as every `attome_metadata::provision::reconcile_*`
//! primitive: the persisted plan only decided whether this step runs at all;
//! the row is resolved fresh here too, so a re-apply of an already-landed
//! record set is `Unchanged` with no write, and a genuine concurrent edit
//! surfaces as `AppError::VersionConflict` — which `apply.rs`'s step runner
//! already turns into a per-object failure message, no special-casing needed
//! here.
//!
//! **Key references (D-534).** A lookup field's value may name its target by
//! business key instead of by id — `{"key": {"name": "API Key"}}` — and is
//! resolved to the one active target row that key matches before the row is
//! compared or written, at plan time (an unresolvable or ambiguous reference
//! is a `blocked` entry) and again at apply time. A literal id only exists on
//! the deployment that created the row, so a reference to reference data some
//! other bundle seeds must use a key: a `derived_id` literal matches only a row
//! that bundle itself created, never one that predates it under another id.
//!
//! **Declared business keys (Solution 7 Phase 2, D-787 rule 7).** A changeset
//! `upsert_record` on an entity that declares a key goes through
//! [`apply_upsert_record`] instead: matched by the declared key only, over all
//! rows (live first, then newest; a retired match is restored), and an update
//! writes only the op's `changed` fields (design §3.9).
//!
//! **The customer wins (Solution 7 Phase 2, Topic 14; design §9).** Each of
//! those fields goes through the three-way rule
//! ([`attome_core::release_report::decide`]) against the record baseline
//! (`record_baseline`: the hash of our last intended value and of
//! the value as stored after our write): a field the customer changed since
//! our last write keeps the customer's value; when we changed it too and the
//! two differ, a release-report `conflict` item (customer value kept, ours,
//! the business key — sealed) offers Accept / Use mine. Baselines, writes
//! and conflict items share the step's transaction.

use std::collections::{HashMap, HashSet};

use attome_core::changeset::errors;
use attome_core::release_report::{self as rr, Baseline, ConflictValues, Decision, NewItem};
use attome_core::{AttrInfo, EngineState, FieldType, quote_ident};
use attome_db::DbPool;
use attome_metadata::provision::ReconcileOutcome;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use super::derived_id::derived_id;
use super::model::{Bundle, COMPONENT_RECORD};
use super::plan::{Diff, PlanAction, PlanEntry};
use attome_records::entity_mutation::{self, MutationMode, json_to_str, sql_cast};

/// `entity[k1=v1,k2=v2]` — the human key every [`PlanEntry`] and apply step
/// for a record-set row is addressed by (matches the shape every other
/// component's key uses, e.g. `account.email`, `Group/Item`).
pub fn record_key(
    entity: &str,
    key_fields: &[String],
    row: &serde_json::Map<String, Value>,
) -> String {
    let parts: Vec<String> = key_fields
        .iter()
        .map(|k| {
            format!(
                "{k}={}",
                row.get(k)
                    .map(display_value)
                    .unwrap_or_else(|| "?".to_owned())
            )
        })
        .collect();
    format!("{entity}[{}]", parts.join(","))
}

fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

/// Field types that can serve as a business key. A multi-valued choice/file
/// has no single scalar to bind into an equality predicate, so it is refused
/// rather than silently comparing against the first element.
fn valid_key_field_type(field_type: &str) -> bool {
    matches!(field_type, "text" | "number" | "date" | "bool" | "lookup")
}

fn push(diff: &mut Diff, entry: PlanEntry) {
    match entry.action {
        PlanAction::Blocked => diff.blocked.push(entry),
        _ => diff.entries.push(entry),
    }
}

/// The single member a lookup value's key-reference object carries.
const KEY_REFERENCE_MEMBER: &str = "key";

/// `None` when `value` is not a key reference (a literal id, or null); a
/// lookup value is otherwise always a UUID string, so any object on a lookup
/// field is read as one. `Err` names what is wrong with a malformed one.
fn parse_key_reference(value: &Value) -> Option<Result<Vec<(&str, &Value)>, String>> {
    let Value::Object(object) = value else {
        return None;
    };
    let malformed = || {
        Err(format!(
            "a key reference must be {{\"{KEY_REFERENCE_MEMBER}\": {{\"<field>\": <value>, ...}}}}"
        ))
    };
    let (1, Some(Value::Object(fields))) = (object.len(), object.get(KEY_REFERENCE_MEMBER)) else {
        return Some(malformed());
    };
    if fields.is_empty() {
        return Some(malformed());
    }
    let mut key = Vec::with_capacity(fields.len());
    for (field, v) in fields {
        if !matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
            return Some(Err(format!(
                "key reference field {field} must be a string, number or boolean"
            )));
        }
        key.push((field.as_str(), v));
    }
    Some(Ok(key))
}

/// `row` with every lookup field's key reference replaced by the id of the
/// one active target row it names. The inner `Err` is a reason the row cannot
/// be resolved (plan: `blocked`; apply: a validation error); the outer one is
/// an infrastructure failure.
async fn resolve_key_references(
    db: &DbPool,
    attrs_by_name: &HashMap<&str, &AttrInfo>,
    row: &serde_json::Map<String, Value>,
) -> Result<Result<serde_json::Map<String, Value>, String>, AppError> {
    let mut resolved = row.clone();
    for (field, value) in row {
        let Some(attr) = attrs_by_name.get(field.as_str()) else {
            continue;
        };
        if !matches!(
            FieldType::from_int(attr.field_type_int),
            Some(FieldType::Lookup)
        ) {
            continue;
        }
        let key = match parse_key_reference(value) {
            None => continue,
            Some(Ok(key)) => key,
            Some(Err(reason)) => return Ok(Err(format!("{field}: {reason}"))),
        };
        match resolve_key_reference(db, attr, &key).await? {
            Ok(id) => {
                resolved.insert(field.clone(), Value::String(id.to_string()));
            }
            Err(reason) => return Ok(Err(format!("{field}: {reason}"))),
        }
    }
    Ok(Ok(resolved))
}

/// Resolves one key reference against `attr`'s lookup target: exactly one
/// active row must match, the same rule staged import's `by_natural_key`
/// lookup resolution applies (`attome_records::data_mapping`).
async fn resolve_key_reference(
    db: &DbPool,
    attr: &AttrInfo,
    key: &[(&str, &Value)],
) -> Result<Result<Uuid, String>, AppError> {
    let Some(target_id) = attr.lookup_entity_ref else {
        return Ok(Err(
            "the lookup field records no target entity, so a key reference cannot be resolved"
                .to_owned(),
        ));
    };
    let target: Option<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(target_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(target) = target else {
        return Ok(Err(
            "the lookup field's target entity is not live".to_owned()
        ));
    };
    let (target_name, target_attrs) =
        match attome_records::entity_crud::resolve_entity_from_db(db, &target).await {
            Ok((_, name, attrs, _)) => (name, attrs),
            Err(error) => {
                return Ok(Err(format!(
                    "target entity {target} could not be resolved: {error}"
                )));
            }
        };
    let target_attrs: HashMap<&str, &AttrInfo> = target_attrs
        .iter()
        .map(|a| (a.logicalname.as_str(), a))
        .collect();

    let mut conditions = Vec::with_capacity(key.len());
    let mut binds: Vec<Option<String>> = Vec::with_capacity(key.len());
    let mut shown = Vec::with_capacity(key.len());
    for (i, &(field, value)) in key.iter().enumerate() {
        let Some(field_attr) = target_attrs.get(field) else {
            return Ok(Err(format!("{target_name} has no field {field}")));
        };
        let field_type = FieldType::from_int(field_attr.field_type_int)
            .map(|t| t.as_str())
            .unwrap_or("unknown");
        if !valid_key_field_type(field_type) {
            return Ok(Err(format!(
                "{target_name}.{field} (type {field_type}) cannot be a business key"
            )));
        }
        conditions.push(format!(
            "{} = ${}{}",
            quote_ident(field),
            i + 1,
            sql_cast(field_attr)
        ));
        binds.push(json_to_str(value, field_attr));
        shown.push(format!("{field}={}", display_value(value)));
    }

    let sql = format!(
        "SELECT id FROM {table} WHERE {cond} AND is_active = true LIMIT 2",
        table = quote_ident(&target_name),
        cond = conditions.join(" AND "),
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
    for bind in &binds {
        q = q.bind(bind);
    }
    let ids = q.fetch_all(db).await.map_err(AppError::internal)?;
    let shown = shown.join(",");
    Ok(match ids.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!("no active {target_name} row matches {shown}")),
        _ => Err(format!(
            "more than one active {target_name} row matches {shown}"
        )),
    })
}

/// One resolved live row: enough to decide create/update/noop and, at apply
/// time, the `expected_row_version` an update is bound against.
struct CurrentRecord {
    id: Uuid,
    row_version: i64,
    /// Every column read back, minus `id`/`row_version` — compared field by
    /// field against the bundle's desired row.
    values: serde_json::Map<String, Value>,
}

/// Resolves one row by `key_fields`, reading back exactly the columns the
/// bundle's row names (validated against `attrs_by_name` by the caller) plus
/// `id`/`row_version` — never `SELECT *`. `None` when no live row matches.
async fn fetch_current(
    db: &DbPool,
    entity: &str,
    attrs_by_name: &HashMap<&str, &AttrInfo>,
    key_fields: &[String],
    row: &serde_json::Map<String, Value>,
) -> Result<Option<CurrentRecord>, AppError> {
    let table = quote_ident(entity);

    // `row`'s keys are already unique (it's a map), so no dedup is needed.
    let mut select_cols = vec![quote_ident("id"), quote_ident("row_version")];
    select_cols.extend(row.keys().map(|f| quote_ident(f)));

    let mut conditions = Vec::with_capacity(key_fields.len());
    let mut binds: Vec<Option<String>> = Vec::with_capacity(key_fields.len());
    for (i, k) in key_fields.iter().enumerate() {
        let attr = *attrs_by_name.get(k.as_str()).ok_or_else(|| {
            AppError::internal(format!(
                "record set key field {k} missing from resolved attrs (should have been \
                 validated at plan time)"
            ))
        })?;
        conditions.push(format!("{} = ${}{}", quote_ident(k), i + 1, sql_cast(attr)));
        let value = row.get(k).ok_or_else(|| {
            AppError::internal(format!("record set key field {k} missing from row"))
        })?;
        binds.push(json_to_str(value, attr));
    }

    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE {cond} AND is_active = true LIMIT 1) t",
        cols = select_cols.join(", "),
        cond = conditions.join(" AND "),
    );
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for bind in &binds {
        q = q.bind(bind);
    }
    let Some(found) = q.fetch_optional(db).await.map_err(AppError::internal)? else {
        return Ok(None);
    };
    let Some(obj) = found.as_object() else {
        return Err(AppError::internal(
            "record row_to_json did not return a JSON object",
        ));
    };
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("record row is missing a valid id"))?;
    let row_version = obj
        .get("row_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::internal("record row is missing row_version"))?;
    let mut values = obj.clone();
    values.remove("id");
    values.remove("row_version");
    Ok(Some(CurrentRecord {
        id,
        row_version,
        values,
    }))
}

/// `"field: live -> desired"` for every field the bundle's row names that
/// differs from the live value — same convention `plan.rs::scalar_changes`
/// uses for every other component.
fn record_changes(
    desired: &serde_json::Map<String, Value>,
    current: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (field, want) in desired {
        let have = current.get(field).cloned().unwrap_or(Value::Null);
        if &have != want {
            out.push(format!("{field}: {have} -> {want}"));
        }
    }
    out
}

// ── Plan ─────────────────────────────────────────────────────────────────────

/// Plans every row of every record set in `desired` against live data.
/// `live` is the already-exported bundle (validates entity/attribute shape
/// with no extra round trip); the row resolution itself reads the entity
/// table directly, since record data is never part of an export. Never
/// produces a `Retire` line — a record set expresses no removal in this
/// phase (§3 "record set (Phase 3)").
pub async fn plan_record_sets(
    db: &DbPool,
    live: &Bundle,
    desired: &Bundle,
) -> Result<Diff, AppError> {
    let mut diff = Diff::default();

    for rs in &desired.record_sets {
        if rs.key_fields.is_empty() {
            push(
                &mut diff,
                PlanEntry::blocked(
                    COMPONENT_RECORD,
                    rs.entity.clone(),
                    "record set has no key_fields",
                ),
            );
            continue;
        }
        let mut seen = HashSet::new();
        if !rs.key_fields.iter().all(|k| seen.insert(k.as_str())) {
            push(
                &mut diff,
                PlanEntry::blocked(
                    COMPONENT_RECORD,
                    rs.entity.clone(),
                    "key_fields lists the same field twice",
                ),
            );
            continue;
        }

        let Some(entity_def) = live.entities.iter().find(|e| e.logicalname == rs.entity) else {
            push(
                &mut diff,
                PlanEntry::blocked(
                    COMPONENT_RECORD,
                    rs.entity.clone(),
                    format!("entity '{}' is not live", rs.entity),
                ),
            );
            continue;
        };
        let field_types: HashMap<&str, &str> = entity_def
            .attributes
            .iter()
            .map(|a| (a.logicalname.as_str(), a.field_type.as_str()))
            .collect();

        let mut bad_keys = Vec::new();
        for k in &rs.key_fields {
            match field_types.get(k.as_str()) {
                None => bad_keys.push(format!("{k} (no such field)")),
                Some(t) if !valid_key_field_type(t) => {
                    bad_keys.push(format!("{k} (type {t} cannot be a business key)"))
                }
                _ => {}
            }
        }
        if !bad_keys.is_empty() {
            push(
                &mut diff,
                PlanEntry::blocked(
                    COMPONENT_RECORD,
                    rs.entity.clone(),
                    format!(
                        "invalid key_fields on {}: {}",
                        rs.entity,
                        bad_keys.join(", ")
                    ),
                ),
            );
            continue;
        }

        let attrs = match attome_records::entity_crud::resolve_entity_from_db(db, &rs.entity).await
        {
            Ok((_, _, attrs, _)) => attrs,
            Err(error) => {
                push(
                    &mut diff,
                    PlanEntry::blocked(
                        COMPONENT_RECORD,
                        rs.entity.clone(),
                        format!("entity '{}' could not be resolved: {error}", rs.entity),
                    ),
                );
                continue;
            }
        };
        let attrs_by_name: HashMap<&str, &AttrInfo> =
            attrs.iter().map(|a| (a.logicalname.as_str(), a)).collect();

        for row in &rs.rows {
            let key = record_key(&rs.entity, &rs.key_fields, row);

            let missing: Vec<&str> = rs
                .key_fields
                .iter()
                .filter(|k| !row.contains_key(k.as_str()))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                push(
                    &mut diff,
                    PlanEntry::blocked(
                        COMPONENT_RECORD,
                        key,
                        format!("row is missing key field(s): {}", missing.join(", ")),
                    ),
                );
                continue;
            }

            let unknown: Vec<&str> = row
                .keys()
                .filter(|f| !attrs_by_name.contains_key(f.as_str()))
                .map(String::as_str)
                .collect();
            if !unknown.is_empty() {
                push(
                    &mut diff,
                    PlanEntry::blocked(
                        COMPONENT_RECORD,
                        key,
                        format!("unknown field(s) on {}: {}", rs.entity, unknown.join(", ")),
                    ),
                );
                continue;
            }

            let row = match resolve_key_references(db, &attrs_by_name, row).await {
                Ok(Ok(resolved)) => resolved,
                Ok(Err(reason)) => {
                    push(&mut diff, PlanEntry::blocked(COMPONENT_RECORD, key, reason));
                    continue;
                }
                Err(error) => {
                    push(
                        &mut diff,
                        PlanEntry::blocked(
                            COMPONENT_RECORD,
                            key,
                            format!("could not resolve row: {error}"),
                        ),
                    );
                    continue;
                }
            };

            match fetch_current(db, &rs.entity, &attrs_by_name, &rs.key_fields, &row).await {
                Ok(None) => push(
                    &mut diff,
                    PlanEntry::new(COMPONENT_RECORD, key, PlanAction::Create),
                ),
                Ok(Some(current)) => {
                    let changes = record_changes(&row, &current.values);
                    if changes.is_empty() {
                        push(
                            &mut diff,
                            PlanEntry::new(COMPONENT_RECORD, key, PlanAction::Noop),
                        );
                    } else {
                        let mut e = PlanEntry::new(COMPONENT_RECORD, key, PlanAction::Update);
                        e.changes = changes;
                        push(&mut diff, e);
                    }
                }
                Err(error) => push(
                    &mut diff,
                    PlanEntry::blocked(
                        COMPONENT_RECORD,
                        key,
                        format!("could not resolve row: {error}"),
                    ),
                ),
            }
        }
    }

    Ok(diff)
}

// ── Apply ────────────────────────────────────────────────────────────────────

/// `is_admin: true`, every grant set empty — the platform's established
/// "no human actor, full trust" context for a background writer (mirrors
/// `attome-workflow::scheduler::system_security_context`, which this file
/// cannot import directly: `attome-workflow` depends on `attome-api`, not the
/// reverse).
fn system_security_context(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

/// Creates or updates one record-set row through the ordinary entity-
/// mutation primitives, resolving fresh against live data first (compare-
/// first — see the module doc). `actor` is the identity recorded as
/// `created_by`/`modified_by`/`owner_ref` — the apply job's `requested_by`, or
/// `Uuid::nil()` when there is none.
pub async fn apply_record(
    state: &EngineState,
    actor: Uuid,
    entity: &str,
    key_fields: &[String],
    row: &serde_json::Map<String, Value>,
) -> Result<ReconcileOutcome, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        attome_records::entity_crud::resolve_entity_from_db(&state.base.db, entity).await?;
    let attrs_by_name: HashMap<&str, &AttrInfo> =
        attrs.iter().map(|a| (a.logicalname.as_str(), a)).collect();

    // Key references resolve again here, not from the plan: the plan only
    // decided whether this step runs, and the target row is read fresh.
    let resolved = match resolve_key_references(&state.base.db, &attrs_by_name, row).await? {
        Ok(resolved) => resolved,
        Err(reason) => return Err(AppError::Validation(reason)),
    };

    let current = fetch_current(
        &state.base.db,
        &entity_name,
        &attrs_by_name,
        key_fields,
        &resolved,
    )
    .await?;
    let ctx = system_security_context(actor);

    match current {
        None => {
            let (_, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, actor).await;
            // D-374 amendment: the same record set produces the same row id
            // on every fresh deployment it's applied to — derived from the
            // exact key `plan_record_sets`/`PlanEntry` already address this
            // row by, never compared against a live id (a row that already
            // exists under a different id is matched by key above and takes
            // the `Some(current)` branch below, untouched by this). Derived
            // from the row as authored, not `resolved`, so it never depends
            // on a key reference's deployment-specific target id.
            let desired_id = derived_id(COMPONENT_RECORD, &record_key(entity, key_fields, row));
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            entity_mutation::create_one(
                &mut tx,
                state,
                &ctx,
                &entity_name,
                &attrs,
                &resolved,
                actor,
                org_ref,
                MutationMode::BundleRecordSet(Some(desired_id)),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(ReconcileOutcome::Created)
        }
        Some(current) => {
            let changes = record_changes(&resolved, &current.values);
            if changes.is_empty() {
                return Ok(ReconcileOutcome::Unchanged);
            }
            if is_append_only {
                return Err(AppError::Validation(format!(
                    "{entity_name} is append-only; the record set names a change to an \
                     existing row, which cannot be applied"
                )));
            }
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            entity_mutation::update_one(
                &mut tx,
                state,
                &ctx,
                &entity_name,
                entity_id,
                current.id,
                &attrs,
                &resolved,
                actor,
                current.row_version,
                MutationMode::BundleRecordSet(None),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(ReconcileOutcome::Updated)
        }
    }
}

// ── upsert_record by declared business key (Solution 7 Phase 2) ─────────────

/// The live-preference alias the business-key match reads back (never a
/// metadata field name: those are `[a-z][a-z0-9_]*` without this prefix
/// shape in practice, and it is removed from the values before comparing).
const LIVE_ALIAS: &str = "bk_row_live";

/// One row matched by a declared business key, live or retired.
struct KeyedRecord {
    id: Uuid,
    row_version: i64,
    live: bool,
    values: serde_json::Map<String, Value>,
}

/// D-787 rule 7 matching: the declared key only, over **all** rows (a
/// retired record is reactivated, not duplicated), preferring a live row,
/// then the newest. A null key value matches null (`IS NOT DISTINCT FROM`,
/// the unique index is `NULLS NOT DISTINCT`). Reads back `id`,
/// `row_version`, liveness and the columns `row` names — never `SELECT *`.
async fn fetch_by_declared_key(
    db: &DbPool,
    entity: &str,
    attrs_by_name: &HashMap<&str, &AttrInfo>,
    key_fields: &[String],
    key: &serde_json::Map<String, Value>,
    row: &serde_json::Map<String, Value>,
    is_append_only: bool,
) -> Result<Option<KeyedRecord>, AppError> {
    let live = if is_append_only {
        "true".to_owned()
    } else {
        "(is_active IS NULL OR is_active = true)".to_owned()
    };
    let mut select_cols = vec![
        quote_ident("id"),
        quote_ident("row_version"),
        format!("{live} AS {}", quote_ident(LIVE_ALIAS)),
    ];
    select_cols.extend(row.keys().map(|f| quote_ident(f)));

    let mut conditions = Vec::with_capacity(key_fields.len());
    let mut binds: Vec<Option<String>> = Vec::with_capacity(key_fields.len());
    for (i, k) in key_fields.iter().enumerate() {
        let attr = *attrs_by_name
            .get(k.as_str())
            .ok_or_else(|| AppError::Validation(format!("{entity} has no key field {k}")))?;
        let value = key
            .get(k)
            .ok_or_else(|| AppError::Validation(errors::BUSINESS_KEY_MISMATCH.to_owned()))?;
        conditions.push(format!(
            "{} IS NOT DISTINCT FROM ${}{}",
            quote_ident(k),
            i + 1,
            sql_cast(attr)
        ));
        binds.push(json_to_str(value, attr));
    }
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE {cond} \
         ORDER BY {live_alias} DESC, created_at DESC NULLS LAST, id DESC LIMIT 1) t",
        cols = select_cols.join(", "),
        table = quote_ident(entity),
        cond = conditions.join(" AND "),
        live_alias = quote_ident(LIVE_ALIAS),
    );
    let mut q = sqlx::query_scalar::<_, Value>(&sql);
    for bind in &binds {
        q = q.bind(bind);
    }
    let Some(found) = q.fetch_optional(db).await.map_err(AppError::internal)? else {
        return Ok(None);
    };
    let Value::Object(mut values) = found else {
        return Err(AppError::internal(
            "record row_to_json did not return a JSON object",
        ));
    };
    let id = values
        .remove("id")
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("record row is missing a valid id"))?;
    let row_version = values
        .remove("row_version")
        .as_ref()
        .and_then(Value::as_i64)
        .ok_or_else(|| AppError::internal("record row is missing row_version"))?;
    let live = values
        .remove(LIVE_ALIAS)
        .as_ref()
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Ok(Some(KeyedRecord {
        id,
        row_version,
        live,
        values,
    }))
}

/// The fields of `desired` an update considers (design §3.9): with `changed`
/// (the fields the recorded write set), only those; without it (an older
/// file), every field. The three-way rule then decides each one.
fn effective_fields<'a>(
    desired: &'a serde_json::Map<String, Value>,
    changed: Option<&[String]>,
) -> Vec<(&'a String, &'a Value)> {
    desired
        .iter()
        .filter(|(field, _)| changed.is_none_or(|list| list.iter().any(|c| c == *field)))
        .collect()
}

/// `sha256:` of a value's RFC 8785 canonical JSON (the baseline's hash).
pub(crate) fn value_hash(value: &Value) -> Result<String, AppError> {
    crate::changeset::jcs::canonicalize(value)
        .map(|text| rr::hash_text(&text))
        .map_err(|e| AppError::internal(format!("canonical JSON of a record value: {e}")))
}

/// What the three-way rule made of one record's fields.
#[derive(Debug, Default)]
struct ThreeWay {
    /// Fields to write (ours), each only when it differs from live.
    writes: serde_json::Map<String, Value>,
    /// Our intended hash of each written field (its stored hash is read back
    /// after the write).
    written_hashes: Vec<(String, String)>,
    /// Baselines set without a write (agreeing values, kept conflicts).
    rebase: Vec<(String, Baseline)>,
    /// `(field, ours, theirs)` both sides changed: the customer's stays.
    conflicts: Vec<(String, Value, Value)>,
}

/// Applies [`rr::decide`] to every field of the effective change set.
fn three_way(
    effective: &[(&String, &Value)],
    live: &serde_json::Map<String, Value>,
    baselines: &HashMap<String, Baseline>,
) -> Result<ThreeWay, AppError> {
    let mut out = ThreeWay::default();
    for (field, ours) in effective {
        let theirs = live.get(field.as_str()).unwrap_or(&Value::Null);
        let ours_hash = value_hash(ours)?;
        let live_hash = value_hash(theirs)?;
        match rr::decide(
            &live_hash,
            &ours_hash,
            theirs == *ours,
            baselines.get(field.as_str()),
        ) {
            Decision::Write => {
                out.writes.insert((*field).clone(), (*ours).clone());
                out.written_hashes.push(((*field).clone(), ours_hash));
            }
            Decision::Rebase => out.rebase.push((
                (*field).clone(),
                Baseline {
                    value_hash: ours_hash,
                    live_hash: Some(live_hash),
                },
            )),
            Decision::Noop | Decision::KeepTheirs => {}
            Decision::Conflict => {
                out.conflicts
                    .push(((*field).clone(), (*ours).clone(), theirs.clone()));
                out.rebase.push((
                    (*field).clone(),
                    Baseline {
                        value_hash: ours_hash,
                        live_hash: None,
                    },
                ));
            }
        }
    }
    Ok(out)
}

/// The baseline of every field we just wrote: our intended hash, and the
/// stored value's hash read back from the write's returned row.
fn written_baselines(
    written: &[(String, String)],
    new_row: Option<&Value>,
) -> Result<Vec<(String, Baseline)>, AppError> {
    written
        .iter()
        .map(|(field, ours_hash)| {
            let stored = new_row.and_then(|row| row.get(field.as_str()));
            Ok((
                field.clone(),
                Baseline {
                    value_hash: ours_hash.clone(),
                    live_hash: stored.map(value_hash).transpose()?,
                },
            ))
        })
        .collect()
}

/// Applies one `upsert_record` of an entity that declares a business key
/// (D-787 rule 7, design §3.8, §3.9, §9): `target.key` names exactly the
/// declared key (checked by the caller); the record is matched by it over
/// all rows (live first, then newest), a retired match is reactivated, and
///
/// - **created** (no match): every `values` field, plus the key, under the
///   deployment-independent `derived_id` of `record_key(entity, key)`; every
///   field's baseline is ours;
/// - **updated**: only the fields in `changed` (all of `values` when the op
///   carries none), each through the three-way rule (module doc): written
///   when only we changed it, kept when the customer changed it, a
///   release-report conflict when both did.
///
/// `values` may change a key field: `key` is the key *before* the recorded
/// write, so a key change replays as "find by the old key, set the new one".
/// Writes through the entity-mutation primitives like [`apply_record`].
/// `op` is the applied operation's `(changeset id, seq)` (the baseline's
/// stamp).
#[allow(clippy::too_many_arguments)] // one operation's parts, named at its one call site
pub async fn apply_upsert_record(
    state: &EngineState,
    actor: Uuid,
    entity: &str,
    key_fields: &[String],
    key: &serde_json::Map<String, Value>,
    values: &serde_json::Map<String, Value>,
    changed: Option<&[String]>,
    op: (Uuid, i32),
) -> Result<ReconcileOutcome, AppError> {
    let db = &state.base.db;
    let (entity_id, entity_name, attrs, is_append_only) =
        attome_records::entity_crud::resolve_entity_from_db(db, entity).await?;
    let attrs_by_name: HashMap<&str, &AttrInfo> =
        attrs.iter().map(|a| (a.logicalname.as_str(), a)).collect();

    // The row as authored: the values, with the key filling any key field
    // the values do not set (a changed key value stays the new one).
    let mut authored = values.clone();
    for (field, value) in key {
        authored
            .entry(field.clone())
            .or_insert_with(|| value.clone());
    }
    let unknown: Vec<&str> = authored
        .keys()
        .filter(|f| !attrs_by_name.contains_key(f.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Err(AppError::Validation(format!(
            "unknown field(s) on {entity_name}: {}",
            unknown.join(", ")
        )));
    }
    let resolved = resolve_key_references(db, &attrs_by_name, &authored)
        .await?
        .map_err(AppError::Validation)?;
    let resolved_key = resolve_key_references(db, &attrs_by_name, key)
        .await?
        .map_err(AppError::Validation)?;

    let current = fetch_by_declared_key(
        db,
        &entity_name,
        &attrs_by_name,
        key_fields,
        &resolved_key,
        &resolved,
        is_append_only,
    )
    .await?;
    let ctx = system_security_context(actor);

    let Some(current) = current else {
        let (_, org_ref) = attome_records::entity_crud::fetch_audit_ctx(state, actor).await;
        // Same id on every deployment for the same key (D-374 amendment),
        // derived from the key as authored (a key reference renders as its
        // JSON text), never from a deployment-local resolved id.
        let desired_id = derived_id(COMPONENT_RECORD, &record_key(entity, key_fields, key));
        let mut tx = attome_db::tx::begin(db).await?;
        let created = entity_mutation::create_one(
            &mut tx,
            state,
            &ctx,
            &entity_name,
            &attrs,
            &resolved,
            actor,
            org_ref,
            MutationMode::BundleRecordSet(Some(desired_id)),
        )
        .await?;
        // Every field we created is ours (design §9.1).
        let ours: Vec<(String, String)> = resolved
            .iter()
            .map(|(field, value)| Ok((field.clone(), value_hash(value)?)))
            .collect::<Result<_, AppError>>()?;
        for (field, baseline) in written_baselines(&ours, created.new_row.as_ref())? {
            rr::write_baseline(
                &mut tx,
                &entity_name,
                created.record_id,
                &field,
                &baseline,
                op,
            )
            .await?;
        }
        attome_db::tx::commit(tx).await?;
        return Ok(ReconcileOutcome::Created);
    };

    let mut tx = attome_db::tx::begin(db).await?;
    let baselines = rr::read_baselines(&mut tx, &entity_name, current.id).await?;
    let effective = effective_fields(&resolved, changed);
    let decided = three_way(&effective, &current.values, &baselines)?;
    if is_append_only && !decided.writes.is_empty() {
        return Err(AppError::Validation(format!(
            "{entity_name} is append-only; the operation names a change to an existing row, \
             which cannot be applied"
        )));
    }

    let mut row_version = current.row_version;
    if !current.live {
        // Matched a retired record: bring it back rather than create a
        // duplicate under the same key (D-787 rule 7).
        let dependents = state.entities.load().dependents_of(entity_id);
        entity_mutation::restore_one(
            &mut tx,
            state,
            &entity_name,
            &attrs,
            &dependents,
            current.id,
            actor,
            Some(row_version),
        )
        .await?;
        row_version = sqlx::query_scalar::<_, i64>(&format!(
            "SELECT row_version FROM {} WHERE id = $1",
            quote_ident(&entity_name)
        ))
        .bind(current.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    let mut baselines_out = decided.rebase;
    if !decided.writes.is_empty() {
        let updated = entity_mutation::update_one(
            &mut tx,
            state,
            &ctx,
            &entity_name,
            entity_id,
            current.id,
            &attrs,
            &decided.writes,
            actor,
            row_version,
            MutationMode::BundleRecordSet(None),
        )
        .await?;
        baselines_out.extend(written_baselines(
            &decided.written_hashes,
            updated.new_row.as_ref(),
        )?);
    }
    for (field, baseline) in &baselines_out {
        rr::write_baseline(&mut tx, &entity_name, current.id, field, baseline, op).await?;
    }
    let conflicts = decided.conflicts.len();
    if conflicts > 0 {
        let ring = attome_core::recovery_archive::ring(state.base.config.as_ref());
        let key_value = Value::Object(key.clone());
        let items: Vec<NewItem> = decided
            .conflicts
            .into_iter()
            .map(|(field, ours, theirs)| NewItem {
                kind: rr::ItemKind::Conflict,
                entity: entity_name.clone(),
                field: Some(field),
                record_id: Some(current.id),
                object_kind: None,
                object_ref: None,
                detail: serde_json::json!({
                    "key_fields": key_fields,
                    "values_stored": ring.is_some(),
                }),
                values: Some(ConflictValues {
                    theirs,
                    ours,
                    key: Some(key_value.clone()),
                }),
                op: Some(op),
            })
            .collect();
        rr::insert_items(
            &mut tx,
            ring,
            items,
            &format!("upsert_record {entity_name}"),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    if conflicts > 0 {
        tracing::info!(
            entity = %entity_name, record_id = %current.id, conflicts,
            "upsert_record: the customer changed field(s) we also changed; their values stay \
             and the release report offers Use mine"
        );
    }
    if current.live && decided.writes.is_empty() {
        return Ok(ReconcileOutcome::Unchanged);
    }
    Ok(ReconcileOutcome::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ours_was(pairs: &[(&str, Value)]) -> HashMap<String, Baseline> {
        pairs
            .iter()
            .map(|(field, value)| {
                let hash = value_hash(value).expect("hash");
                (
                    (*field).to_owned(),
                    Baseline {
                        value_hash: hash.clone(),
                        live_hash: Some(hash),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn an_update_writes_ours_keeps_theirs_and_reports_both_changed() {
        // We last wrote code BH, name "Bahrain", rank 1. The customer renamed
        // it since; our new release changes name and rank.
        let baselines = ours_was(&[
            ("code", json!("BH")),
            ("name", json!("Bahrain")),
            ("rank", json!(1)),
        ]);
        let desired = json!({ "code": "BH", "name": "State of Bahrain", "rank": 2 });
        let desired = desired.as_object().expect("object");
        let current = json!({ "code": "BH", "name": "Kingdom of Bahrain", "rank": 1 });
        let current = current.as_object().expect("object");

        // Without `changed` (an older file): every field is considered.
        let all = three_way(&effective_fields(desired, None), current, &baselines).expect("decide");
        assert_eq!(
            all.writes,
            *json!({ "rank": 2 }).as_object().expect("object")
        );
        assert_eq!(all.conflicts.len(), 1);
        let (field, ours, theirs) = &all.conflicts[0];
        assert_eq!(
            (field.as_str(), ours, theirs),
            (
                "name",
                &json!("State of Bahrain"),
                &json!("Kingdom of Bahrain")
            )
        );
        // The kept conflict's baseline is ours, with no stored form.
        assert!(
            all.rebase
                .iter()
                .any(|(f, b)| f == "name" && b.live_hash.is_none())
        );

        // With `changed`: only those fields.
        let changed = vec!["rank".to_owned()];
        let ours = three_way(
            &effective_fields(desired, Some(changed.as_slice())),
            current,
            &baselines,
        )
        .expect("decide");
        assert_eq!(ours.writes.len(), 1);
        assert!(ours.conflicts.is_empty());

        // The customer changed `name`, we did not: theirs stays, no report.
        let keep = json!({ "name": "Bahrain" });
        let keep = keep.as_object().expect("object");
        let kept = three_way(&effective_fields(keep, None), current, &baselines).expect("decide");
        assert!(kept.writes.is_empty() && kept.conflicts.is_empty() && kept.rebase.is_empty());

        // No baseline (data older than baselines): a difference is the
        // customer's, an agreement only records the baseline.
        let fresh =
            three_way(&effective_fields(desired, None), current, &HashMap::new()).expect("decide");
        assert!(fresh.writes.is_empty());
        assert_eq!(fresh.conflicts.len(), 2);
        assert!(
            fresh
                .rebase
                .iter()
                .any(|(f, b)| f == "code" && b.live_hash.is_some())
        );
    }

    #[test]
    fn a_written_field_records_the_stored_form() {
        let written = vec![("rank".to_owned(), value_hash(&json!(2)).expect("hash"))];
        let row = json!({ "rank": 2.0 });
        let out = written_baselines(&written, Some(&row)).expect("baselines");
        assert_eq!(out[0].1.value_hash, value_hash(&json!(2)).expect("hash"));
        assert_eq!(
            out[0].1.live_hash.as_deref(),
            Some(value_hash(&json!(2.0)).expect("hash").as_str())
        );
        assert!(
            written_baselines(&written, None).expect("baselines")[0]
                .1
                .live_hash
                .is_none()
        );
    }

    fn row(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn record_key_formats_entity_and_key_fields() {
        let r = row(&[
            ("name", Value::String("Welcome".into())),
            ("channel", Value::String("email".into())),
            ("subject", Value::String("Hi".into())),
        ]);
        let key_fields = vec!["name".to_owned(), "channel".to_owned()];
        assert_eq!(
            record_key("notification_template", &key_fields, &r),
            "notification_template[name=Welcome,channel=email]"
        );
    }

    #[test]
    fn record_key_marks_a_missing_key_field() {
        let r = row(&[("name", Value::String("Welcome".into()))]);
        let key_fields = vec!["name".to_owned(), "channel".to_owned()];
        assert_eq!(
            record_key("notification_template", &key_fields, &r),
            "notification_template[name=Welcome,channel=?]"
        );
    }

    #[test]
    fn record_changes_reports_only_differing_fields() {
        let desired = row(&[
            ("name", Value::String("Welcome".into())),
            ("subject", Value::String("Hi there".into())),
        ]);
        let current = row(&[
            ("name", Value::String("Welcome".into())),
            ("subject", Value::String("Hi".into())),
        ]);
        let changes = record_changes(&desired, &current);
        assert_eq!(changes, vec!["subject: \"Hi\" -> \"Hi there\"".to_owned()]);
    }

    #[test]
    fn record_changes_is_empty_for_identical_rows() {
        let desired = row(&[("name", Value::String("Welcome".into()))]);
        let current = desired.clone();
        assert!(record_changes(&desired, &current).is_empty());
    }

    #[test]
    fn valid_key_field_type_excludes_multi_valued_shapes() {
        assert!(valid_key_field_type("text"));
        assert!(valid_key_field_type("lookup"));
        assert!(!valid_key_field_type("choice"));
        assert!(!valid_key_field_type("file"));
    }

    #[test]
    fn a_literal_id_or_null_is_not_a_key_reference() {
        assert!(parse_key_reference(&json!("43d8599f-d4fe-5acd-bdef-4b527bb354e3")).is_none());
        assert!(parse_key_reference(&Value::Null).is_none());
    }

    #[test]
    fn a_key_reference_yields_its_fields() {
        let value = json!({"key": {"name": "API Key", "rank": 1}});
        let key = parse_key_reference(&value)
            .expect("an object is a key reference")
            .expect("well-formed");
        assert_eq!(key, vec![("name", &json!("API Key")), ("rank", &json!(1))]);
    }

    #[test]
    fn a_malformed_key_reference_is_rejected_not_ignored() {
        for value in [
            json!({"name": "API Key"}),
            json!({"key": {"name": "API Key"}, "extra": true}),
            json!({"key": {}}),
            json!({"key": "API Key"}),
            json!({"key": {"name": null}}),
            json!({"key": {"name": {"nested": 1}}}),
        ] {
            assert!(
                matches!(parse_key_reference(&value), Some(Err(_))),
                "{value} must be rejected"
            );
        }
    }
}

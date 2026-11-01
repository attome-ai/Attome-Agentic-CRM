//! A1-T8: splitting one text attribute into several (a full name into its
//! parts, an address into its lines). Each target is an existing text
//! attribute of the entity and gets the value of a rule expression over the
//! source (`word(full_name, 1)`,
//! `if(word_count(full_name) >= 4, word(full_name, 3), "")`, see the rule
//! language's `word`, `word_count` and `split_part`).
//!
//! - `POST /api/v1/admin/entities/{entity_id}/refactor/preview` reads up to
//!   [`PREVIEW_ROWS`] live rows and answers how many would change, how many
//!   cannot be split (an expression fails on them) and up to
//!   [`MAX_EXAMPLES`] examples. It writes nothing.
//! - `POST /api/v1/admin/entities/{entity_id}/refactor` queues the split as
//!   a durable data step run of kind `split` (`RunDataStep`), which
//!   backfills the targets in keyset batches of [`SPLIT_BATCH`] rows, each
//!   batch in its own short transaction with its cursor, and pauses,
//!   resumes and is cancelled through `/api/v1/admin/data-step-runs/{id}`.
//!   A row whose source is empty is left alone; a row an expression fails on
//!   is left alone and counted in the run's `rows_nulled` (here: rows that
//!   could not be split). The source is never changed.
//!
//! An empty piece is stored as no value. Rows are written directly, as the
//! other data step runs write theirs, with `row_version` raised so an open
//! form sees the change.
//!
//! **Text to option set.** `POST /api/v1/admin/entities/{entity_id}/refactor/option-set-preview`
//! groups a text attribute's distinct values (up to [`MAX_DISTINCT`]) by
//! their normal form (trimmed, case-folded, Arabic letters normalised), so
//! `Riyadh`, ` riyadh ` and `RIYADH` are one option; a `merge_map` joins
//! further forms (`{"ruh": "Riyadh"}`). Each group's option is the merge
//! map's value or the group's most common spelling. The answer carries the
//! groups with their row counts and the `map` (every stored spelling to its
//! option) ready for the field's existing type change to `choice`
//! (`POST .../fields/{field_id}/change-type` with `conversion.map`), which
//! converts the column and is recorded like any other structure change.

use std::collections::BTreeMap;

use attome_core::{EngineState, FieldType, quote_ident};
use attome_metadata::provision::field_change as fc;
use attome_rules::{Compiled, Context, Schema, Type, Value as RuleValue};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Rows a preview reads.
pub const PREVIEW_ROWS: i64 = 10_000;
/// Rows one batch of a split writes.
pub const SPLIT_BATCH: i64 = 1_000;
/// The most attributes one split fills.
pub const MAX_TARGETS: usize = 8;
/// Examples a preview shows.
pub const MAX_EXAMPLES: usize = 20;
/// Distinct values an option set preview reads.
pub const MAX_DISTINCT: i64 = 5_000;
/// The longest option value (the type change's own limit).
pub const MAX_OPTION_LEN: usize = 100;
/// Spellings listed per option.
const MAX_SPELLINGS: usize = 20;

/// One attribute a split fills, and how.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SplitTarget {
    /// An existing text attribute of the entity.
    pub field: String,
    /// A rule expression over the source attribute, for example
    /// `word(full_name, 1)`.
    pub expression: String,
}

/// A split of one text attribute into several.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SplitBody {
    /// The text attribute to split; it is not changed.
    pub source: String,
    pub targets: Vec<SplitTarget>,
}

/// One row as a split would write it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SplitExample {
    pub id: Uuid,
    pub source: String,
    /// Each target and its value; `null` for no value.
    #[schema(value_type = Object)]
    pub values: BTreeMap<String, Option<String>>,
}

/// What a split would do.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SplitPreview {
    /// Rows read (at most 10,000).
    pub rows_read: i64,
    /// Rows the split would write.
    pub rows_changed: i64,
    /// Rows an expression fails on; they are left as they are.
    pub rows_unconvertible: i64,
    /// Whether the entity has more rows than were read.
    pub more_rows: bool,
    pub examples: Vec<SplitExample>,
}

/// A queued split.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SplitQueued {
    pub run_id: Uuid,
}

/// A text attribute to turn into an option set.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct OptionSetBody {
    /// The text attribute.
    pub source: String,
    /// Further spellings to join: a spelling (compared in its normal form)
    /// to the option it belongs to.
    #[serde(default)]
    pub merge_map: BTreeMap<String, String>,
}

/// One option and the stored spellings that become it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OptionGroup {
    pub value: String,
    pub rows: i64,
    /// Up to 20 of its stored spellings.
    pub spellings: Vec<String>,
}

/// What turning a text attribute into an option set would give.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OptionSetPreview {
    /// Distinct stored values read (at most 5,000).
    pub values_read: i64,
    /// Whether the attribute has more distinct values than were read.
    pub more_values: bool,
    /// The options, most rows first.
    pub groups: Vec<OptionGroup>,
    /// Rows whose value would become no value: longer than 100 characters
    /// once normalised, or only spaces.
    pub rows_unconvertible: i64,
    /// Every stored spelling to its option: the `conversion.map` for the
    /// field's type change to `choice`.
    #[schema(value_type = Object)]
    pub map: BTreeMap<String, String>,
}

/// A value's normal form: trimmed, case-folded, Arabic letters normalised.
/// Pure.
pub fn normal_form(value: &str) -> String {
    attome_rules::arabic::normalize_ar(&value.trim().to_lowercase())
}

/// Groups `(stored value, rows)` by normal form and `merge_map`, into the
/// options (most rows first), the spelling-to-option map, and the rows that
/// cannot become an option. Pure.
pub fn option_groups(
    values: &[(String, i64)],
    merge_map: &BTreeMap<String, String>,
) -> (Vec<OptionGroup>, BTreeMap<String, String>, i64) {
    let merges: BTreeMap<String, String> = merge_map
        .iter()
        .map(|(from, to)| (normal_form(from), to.trim().to_owned()))
        .collect();
    // normal form -> (rows, spellings with their rows)
    let mut by_form: BTreeMap<String, (i64, Vec<(String, i64)>)> = BTreeMap::new();
    let mut unconvertible = 0;
    for (value, rows) in values {
        let form = normal_form(value);
        if form.is_empty() {
            unconvertible += rows;
            continue;
        }
        let key = merges.get(&form).map(|to| normal_form(to)).unwrap_or(form);
        let entry = by_form.entry(key).or_default();
        entry.0 += rows;
        entry.1.push((value.clone(), *rows));
    }
    let mut groups = Vec::new();
    let mut map = BTreeMap::new();
    for (form, (rows, mut spellings)) in by_form {
        spellings.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let value = merges
            .iter()
            .find(|(_, to)| normal_form(to) == form)
            .map(|(_, to)| to.clone())
            .unwrap_or_else(|| spellings[0].0.trim().to_owned());
        if value.chars().count() > MAX_OPTION_LEN {
            unconvertible += rows;
            continue;
        }
        for (spelling, _) in &spellings {
            map.insert(spelling.clone(), value.clone());
        }
        groups.push(OptionGroup {
            value,
            rows,
            spellings: spellings
                .into_iter()
                .take(MAX_SPELLINGS)
                .map(|(s, _)| s)
                .collect(),
        });
    }
    groups.sort_by(|a, b| b.rows.cmp(&a.rows).then_with(|| a.value.cmp(&b.value)));
    (groups, map, unconvertible)
}

/// A checked split: the entity's table, the source and the compiled targets.
struct Plan {
    entity: String,
    source: String,
    targets: Vec<(String, Compiled)>,
}

/// Checks a split against the entity's metadata and compiles its
/// expressions over the source.
fn plan(state: &EngineState, entity_id: Uuid, body: &SplitBody) -> Result<Plan, AppError> {
    let registry = state.entities.load();
    let meta = registry.get_by_id(entity_id).ok_or(AppError::NotFound)?;
    let text_field = |name: &str| {
        meta.attrs
            .iter()
            .any(|a| a.logicalname == name && a.field_type() == FieldType::Text)
    };
    let source = body.source.trim();
    if !text_field(source) || fc::is_system_column(source) {
        return Err(AppError::Validation(format!(
            "source {source:?} is not a text attribute of {}",
            meta.logicalname
        )));
    }
    if body.targets.is_empty() || body.targets.len() > MAX_TARGETS {
        return Err(AppError::Validation(format!(
            "a split fills 1 to {MAX_TARGETS} attributes"
        )));
    }
    let schema = Schema::new().with_field(source, Type::Text);
    let mut targets: Vec<(String, Compiled)> = Vec::with_capacity(body.targets.len());
    for target in &body.targets {
        let field = target.field.trim();
        if field == source
            || fc::is_system_column(field)
            || !text_field(field)
            || targets.iter().any(|(f, _)| f == field)
        {
            return Err(AppError::Validation(format!(
                "target {field:?} must be another text attribute of {}, named once",
                meta.logicalname
            )));
        }
        let compiled = attome_rules::compile(target.expression.trim(), &schema)
            .map_err(|e| AppError::Validation(format!("{field}: {e}")))?;
        targets.push((field.to_owned(), compiled));
    }
    Ok(Plan {
        entity: meta.logicalname.clone(),
        source: source.to_owned(),
        targets,
    })
}

/// One source value split: each target's value (`None` for none), or
/// `None` when an expression fails on it. Pure.
fn split_value(
    source_field: &str,
    targets: &[(String, Compiled)],
    value: &str,
) -> Option<Vec<Option<String>>> {
    let ctx = Context::new(chrono::Utc::now())
        .with_field(source_field, RuleValue::Text(value.to_owned()));
    targets
        .iter()
        .map(|(_, compiled)| match compiled.eval(&ctx) {
            Ok(RuleValue::Text(t)) if t.trim().is_empty() => Some(None),
            Ok(RuleValue::Text(t)) => Some(Some(t)),
            Ok(RuleValue::Null) => Some(None),
            Ok(RuleValue::Number(n)) => Some(Some(n.to_string())),
            _ => None,
        })
        .collect()
}

/// A batch of live rows after `after`: `(id, source)` with a source.
async fn read_batch(
    conn: &mut sqlx::PgConnection,
    plan: &Plan,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<(Uuid, String)>, AppError> {
    // Identifiers from validated metadata, quoted; values bound.
    let sql = format!(
        "SELECT id, {src}::text FROM {table} \
          WHERE ($1::uuid IS NULL OR id > $1) AND is_active IS DISTINCT FROM false \
            AND {src} IS NOT NULL AND btrim({src}::text) <> '' \
          ORDER BY id LIMIT $2",
        src = quote_ident(&plan.source),
        table = quote_ident(&plan.entity),
    );
    sqlx::query_as(&sql)
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// Preview a split
///
/// What splitting a text attribute into others would write, over up to
/// 10,000 rows, with examples. Writes nothing. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/refactor/preview",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "evaluates the split over the entity's rows and answers counts and examples; writes nothing"
    )))),
    params(("entity_id" = Uuid, Path, description = "The entity")),
    request_body = SplitBody,
    responses(
        (status = 200, description = "What the split would write", body = SplitPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "Not a text source, a bad target or an expression that does not compile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn preview_split(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<SplitBody>,
) -> Result<Json<SplitPreview>, AppError> {
    let plan = plan(&state, entity_id, &body)?;
    let mut conn = state
        .base
        .db_migrator
        .acquire()
        .await
        .map_err(AppError::internal)?;
    let rows = read_batch(&mut conn, &plan, None, PREVIEW_ROWS + 1).await?;
    let more_rows = rows.len() as i64 > PREVIEW_ROWS;
    let mut preview = SplitPreview {
        rows_read: 0,
        rows_changed: 0,
        rows_unconvertible: 0,
        more_rows,
        examples: Vec::new(),
    };
    for (id, source) in rows.into_iter().take(PREVIEW_ROWS as usize) {
        preview.rows_read += 1;
        match split_value(&plan.source, &plan.targets, &source) {
            None => preview.rows_unconvertible += 1,
            Some(values) => {
                preview.rows_changed += 1;
                if preview.examples.len() < MAX_EXAMPLES {
                    preview.examples.push(SplitExample {
                        id,
                        source,
                        values: plan
                            .targets
                            .iter()
                            .map(|(f, _)| f.clone())
                            .zip(values)
                            .collect(),
                    });
                }
            }
        }
    }
    Ok(Json(preview))
}

/// Split a text attribute
///
/// Queues the split of a text attribute into other text attributes as a
/// durable run (`/api/v1/admin/data-step-runs/{id}` shows, pauses and
/// cancels it). Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/refactor",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create),
    ])))),
    params(("entity_id" = Uuid, Path, description = "The entity")),
    request_body = SplitBody,
    responses(
        (status = 202, description = "The split is queued", body = SplitQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "Not a text source, a bad target or an expression that does not compile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn queue_split(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<SplitBody>,
) -> Result<impl IntoResponse, AppError> {
    let run_id = queue(&state, entity_id, &body, ctx.user_id, None).await?;
    Ok((StatusCode::ACCEPTED, Json(SplitQueued { run_id })))
}

/// A22-T4: a changeset's `data_step` of kind `split` on `entity` (args
/// `source` and `targets`, as the admin route takes them), queued as the
/// same durable run, tied to its changeset operation; applying the
/// operation again finds that run and queues nothing.
pub(crate) async fn queue_split_from_changeset(
    state: &EngineState,
    actor: Uuid,
    changeset_op: (Uuid, i32),
    entity: &str,
    args: Option<&Value>,
) -> Result<Uuid, AppError> {
    let body: SplitBody = serde_json::from_value(args.cloned().unwrap_or(Value::Null))
        .map_err(|e| AppError::Validation(format!("data_step split: {e}")))?;
    let entity_id = state
        .entities
        .load()
        .get(entity)
        .map(|meta| meta.entity_id)
        .ok_or(AppError::NotFound)?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM data_step_run WHERE changeset_id = $1 AND op_seq = $2 AND kind = 'split'",
    )
    .bind(changeset_op.0)
    .bind(changeset_op.1)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    if let Some(run_id) = existing {
        return Ok(run_id);
    }
    queue(state, entity_id, &body, actor, Some(changeset_op)).await
}

/// Plans the split, writes the run (`admin`, or `apply` with its changeset
/// operation), queues it and audits it, in one transaction; the run's id.
async fn queue(
    state: &EngineState,
    entity_id: Uuid,
    body: &SplitBody,
    actor: Uuid,
    changeset_op: Option<(Uuid, i32)>,
) -> Result<Uuid, AppError> {
    let plan = plan(state, entity_id, body)?;
    let spec = json!({
        "entity_id": entity_id,
        "source": plan.source,
        "targets": plan.targets.iter().zip(&body.targets).map(|((field, _), t)| json!({
            "field": field,
            "expression": t.expression.trim(),
        })).collect::<Vec<_>>(),
    });
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    let run_id: Uuid = sqlx::query_scalar(
        "INSERT INTO data_step_run \
           (source, entity_logicalname, kind, spec, created_by, changeset_id, op_seq) \
         VALUES ($1, $2, 'split', $3, $4, $5, $6) RETURNING id",
    )
    .bind(if changeset_op.is_some() {
        "apply"
    } else {
        "admin"
    })
    .bind(&plan.entity)
    .bind(&spec)
    .bind(actor)
    .bind(changeset_op.map(|(id, _)| id))
    .bind(changeset_op.map(|(_, seq)| seq))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::RunDataStep { run_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "data_step_run",
            run_id,
            attome_audit::AuditOperation::Create,
            "entity.split",
            actor,
        )
        .comment(format!(
            "split {}.{} into {}",
            plan.entity,
            plan.source,
            plan.targets
                .iter()
                .map(|(f, _)| f.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(run_id)
}

/// `RunDataStep` for a `split` run: batches from the run's cursor, each
/// batch's writes, counts and cursor committed together, then finished.
pub(crate) async fn continue_split(state: &EngineState, run: &fc::RunRow) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let entity_id = run
        .spec
        .get("entity_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::internal(format!("split run {}: spec.entity_id missing", run.id))
        })?;
    let body: SplitBody = serde_json::from_value(run.spec.clone())
        .map_err(|e| AppError::internal(format!("split run {}: spec: {e}", run.id)))?;
    // Checked again: the metadata may have changed since it was queued.
    let plan = plan(state, entity_id, &body)?;
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "split: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let rows = read_batch(&mut tx, &plan, cursor, SPLIT_BATCH).await?;
        let read = rows.len();
        let mut ids: Vec<Uuid> = Vec::with_capacity(read);
        let mut columns: Vec<Vec<Option<String>>> =
            vec![Vec::with_capacity(read); plan.targets.len()];
        let mut failed: u64 = 0;
        for (id, source) in &rows {
            match split_value(&plan.source, &plan.targets, source) {
                Some(values) => {
                    ids.push(*id);
                    for (column, value) in columns.iter_mut().zip(values) {
                        column.push(value);
                    }
                }
                None => failed += 1,
            }
        }
        if !ids.is_empty() {
            // Identifiers from validated metadata, quoted; values bound.
            let sets: Vec<String> = plan
                .targets
                .iter()
                .enumerate()
                .map(|(i, (field, _))| format!("{} = v.c{i}", quote_ident(field)))
                .collect();
            let unnest: Vec<String> = (0..plan.targets.len())
                .map(|i| format!("${}::text[]", i + 2))
                .collect();
            let names: Vec<String> = (0..plan.targets.len()).map(|i| format!("c{i}")).collect();
            let sql = format!(
                "UPDATE {table} AS t SET {sets}, modified_at = now(), row_version = t.row_version + 1 \
                   FROM unnest($1::uuid[], {unnest}) AS v(id, {names}) \
                  WHERE t.id = v.id",
                table = quote_ident(&plan.entity),
                sets = sets.join(", "),
                unnest = unnest.join(", "),
                names = names.join(", "),
            );
            let mut query = sqlx::query(&sql).bind(&ids);
            for column in &columns {
                query = query.bind(column);
            }
            query.execute(&mut *tx).await.map_err(AppError::internal)?;
        }
        if let Some((last, _)) = rows.last() {
            cursor = Some(*last);
        }
        fc::advance_run(
            &mut tx,
            run.id,
            cursor,
            read as u64,
            ids.len() as u64,
            failed,
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        if (read as i64) < SPLIT_BATCH {
            break;
        }
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    fc::finish_run(&mut conn, run.id, None).await?;
    tracing::info!(run_id = %run.id, entity = %run.entity_logicalname, "split: finished");
    Ok(())
}

/// Preview a text attribute as an option set
///
/// Groups a text attribute's stored values into options (trimmed,
/// case-folded, Arabic letters normalised, plus a merge map) and answers the
/// options with their row counts and the map for the field's type change to
/// `choice`. Writes nothing. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/refactor/option-set-preview",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "groups a text attribute's stored values into options; writes nothing"
    )))),
    params(("entity_id" = Uuid, Path, description = "The entity")),
    request_body = OptionSetBody,
    responses(
        (status = 200, description = "The options and the conversion map", body = OptionSetPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "Not a text attribute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn preview_option_set(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<OptionSetBody>,
) -> Result<Json<OptionSetPreview>, AppError> {
    let (entity, source) = {
        let registry = state.entities.load();
        let meta = registry.get_by_id(entity_id).ok_or(AppError::NotFound)?;
        let source = body.source.trim().to_owned();
        let is_text = meta
            .attrs
            .iter()
            .any(|a| a.logicalname == source && a.field_type() == FieldType::Text);
        if !is_text || fc::is_system_column(&source) {
            return Err(AppError::Validation(format!(
                "{source:?} is not a text attribute of {}",
                meta.logicalname
            )));
        }
        (meta.logicalname.clone(), source)
    };
    // Identifiers from validated metadata, quoted; values bound.
    let sql = format!(
        "SELECT {src}::text, COUNT(*)::bigint FROM {table} \
          WHERE is_active IS DISTINCT FROM false AND {src} IS NOT NULL \
          GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $1",
        src = quote_ident(&source),
        table = quote_ident(&entity),
    );
    let mut values: Vec<(String, i64)> = sqlx::query_as(&sql)
        .bind(MAX_DISTINCT + 1)
        .fetch_all(&state.base.db_migrator)
        .await
        .map_err(AppError::internal)?;
    let more_values = values.len() as i64 > MAX_DISTINCT;
    values.truncate(MAX_DISTINCT as usize);
    let (groups, map, rows_unconvertible) = option_groups(&values, &body.merge_map);
    Ok(Json(OptionSetPreview {
        values_read: values.len() as i64,
        more_values,
        groups,
        rows_unconvertible,
        map,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/entities/{entity_id}/refactor/option-set-preview",
            post(preview_option_set),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/refactor/preview",
            post(preview_split),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/refactor",
            post(queue_split),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(preview_split, queue_split, preview_option_set))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(source: &str, exprs: &[&str]) -> Vec<(String, Compiled)> {
        let schema = Schema::new().with_field(source, Type::Text);
        exprs
            .iter()
            .enumerate()
            .map(|(i, e)| (format!("t{i}"), attome_rules::compile(e, &schema).unwrap()))
            .collect()
    }

    #[test]
    fn split_full_name_into_four_parts() {
        let t = targets(
            "full_name",
            &[
                "word(full_name, 1)",
                "if(word_count(full_name) >= 3, word(full_name, 2), \"\")",
                "if(word_count(full_name) >= 4, word(full_name, 3), \"\")",
                "if(word_count(full_name) >= 2, word(full_name, -1), \"\")",
            ],
        );
        assert_eq!(
            split_value("full_name", &t, "محمد عبدالله سالم الأحمد").unwrap(),
            vec![
                Some("محمد".to_owned()),
                Some("عبدالله".to_owned()),
                Some("سالم".to_owned()),
                Some("الأحمد".to_owned())
            ]
        );
        assert_eq!(
            split_value("full_name", &t, "Sara Ali").unwrap(),
            vec![Some("Sara".to_owned()), None, None, Some("Ali".to_owned())]
        );
    }

    #[test]
    fn text_to_option_set_merges_variants() {
        let values = vec![
            ("Riyadh".to_owned(), 10),
            (" riyadh ".to_owned(), 3),
            ("RUH".to_owned(), 2),
            ("جدة".to_owned(), 4),
            ("جده".to_owned(), 1),
            ("   ".to_owned(), 5),
        ];
        let merge: BTreeMap<String, String> = [("ruh".to_owned(), "Riyadh".to_owned())]
            .into_iter()
            .collect();
        let (groups, map, unconvertible) = option_groups(&values, &merge);
        assert_eq!(unconvertible, 5);
        assert_eq!(groups.len(), 2, "{groups:?}");
        assert_eq!(groups[0].value, "Riyadh");
        assert_eq!(groups[0].rows, 15);
        assert_eq!(groups[1].value, "جدة");
        assert_eq!(groups[1].rows, 5);
        assert_eq!(map.get(" riyadh ").map(String::as_str), Some("Riyadh"));
        assert_eq!(map.get("RUH").map(String::as_str), Some("Riyadh"));
        assert_eq!(map.get("جده").map(String::as_str), Some("جدة"));
        assert!(!map.contains_key("   "));
    }

    #[test]
    fn a_failing_expression_leaves_the_row_unconvertible() {
        let t = targets("code", &["len(code) > 1"]);
        assert_eq!(split_value("code", &t, "a-b"), None);
    }
}

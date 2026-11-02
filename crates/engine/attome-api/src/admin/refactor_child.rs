//! A1-T9: extracting repeating attributes into a child entity: `phone_1`,
//! `phone_2` and `phone_3` of a contact become rows of a `contact_phone`
//! child, one per non-empty value, each with a lookup to its contact.
//!
//! `POST /api/v1/admin/entities/{entity_id}/refactor/extract-child`:
//!
//! 1. checks the sources: two to twelve attributes of the entity, all of
//!    one field type and options, none a lookup, file or image;
//! 2. creates the child entity through the ordinary entity and field
//!    creation (recorded in the open changeset like any admin change): the
//!    value field (the sources' type and options), a text field naming the
//!    source each row came from, and the lookup to the parent;
//! 3. queues a durable data step run of kind `extract_child` that copies
//!    the values in keyset batches of [`EXTRACT_BATCH`] parent rows, each
//!    batch's rows, counts and cursor in one short transaction, so a stopped
//!    run resumes where it was and copies each parent once. A child row
//!    takes its parent's owner and unit, so whoever reads the parent reads
//!    its rows. Paused, resumed and cancelled through
//!    `/api/v1/admin/data-step-runs/{id}`.
//!
//! The source attributes are kept. The answer lists every object that reads
//! them (`metadata_reference`: queries, views, rules, workflows,
//! dashboards) to move to the child: there is no Develop-mode draft to
//! write the rewritten objects into, so they are listed for the builder
//! rather than changed. Delete the sources once nothing reads them.

use attome_core::changeset::RecordingCtx;
use attome_core::{EngineState, FieldType, quote_ident};
use attome_metadata::provision::field_change as fc;
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

/// Parent rows one batch reads.
pub const EXTRACT_BATCH: i64 = 1_000;
/// The fewest and most attributes one extraction takes.
pub const MIN_SOURCES: usize = 2;
pub const MAX_SOURCES: usize = 12;
/// References listed in the answer.
const MAX_REFERENCES: i64 = 500;

/// Repeating attributes to move into a child entity.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractChildBody {
    /// The repeating attributes, in order (`phone_1`, `phone_2`, ...).
    pub sources: Vec<String>,
    /// The child entity's logical name (`contact_phone`).
    pub child_logicalname: String,
    /// Its display name (`Contact phone`).
    pub child_name: String,
    /// The child's value field (default `value`).
    #[serde(default)]
    pub value_field: Option<String>,
    /// The child's field naming the source attribute (default `source_field`).
    #[serde(default)]
    pub source_field: Option<String>,
    /// The child's lookup to the parent (default `<parent>_ref`).
    #[serde(default)]
    pub lookup_field: Option<String>,
}

/// An object that reads a moved attribute.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ToReview {
    /// `query`, `view`, `rule`, `workflow`, `dashboard`, ...
    pub kind: String,
    pub id: Uuid,
    pub label: String,
    pub attribute: String,
}

/// The queued extraction.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExtractChildQueued {
    pub run_id: Uuid,
    pub child_entity_id: Uuid,
    /// Objects that read the sources and should move to the child.
    pub to_review: Vec<ToReview>,
}

/// The checked plan of an extraction.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractPlan {
    pub parent: String,
    pub parent_id: Uuid,
    pub sources: Vec<String>,
    pub field_type: FieldType,
    pub options: Option<Value>,
    pub child: String,
    pub value_field: String,
    pub source_field: String,
    pub lookup_field: String,
}

fn identifier(name: &str) -> bool {
    attome_metadata::provision::valid_identifier(name)
        && name.starts_with(|c: char| c.is_ascii_lowercase())
}

/// Checks `body` against the parent's metadata. Pure.
pub fn plan(
    parent: &attome_core::EntityMeta,
    body: &ExtractChildBody,
) -> Result<ExtractPlan, AppError> {
    let bad = |m: String| Err(AppError::Validation(m));
    if !(MIN_SOURCES..=MAX_SOURCES).contains(&body.sources.len()) {
        return bad(format!(
            "sources names {MIN_SOURCES} to {MAX_SOURCES} attributes"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut attrs = Vec::new();
    for name in &body.sources {
        if !seen.insert(name.as_str()) {
            return bad(format!("{name} is named twice"));
        }
        let Some(attr) = parent.attrs.iter().find(|a| a.logicalname == *name) else {
            return bad(format!("{} has no attribute {name}", parent.logicalname));
        };
        attrs.push(attr);
    }
    let first = attrs[0];
    let field_type = first.field_type();
    if matches!(
        field_type,
        FieldType::Lookup | FieldType::File | FieldType::Image
    ) {
        return bad("a lookup, file or image attribute cannot be extracted".into());
    }
    if attrs
        .iter()
        .any(|a| a.field_type() != field_type || a.options != first.options)
    {
        return bad("the sources must share one field type and its options".into());
    }
    let child = body.child_logicalname.trim().to_lowercase();
    let value_field = body.value_field.clone().unwrap_or_else(|| "value".into());
    let source_field = body
        .source_field
        .clone()
        .unwrap_or_else(|| "source_field".into());
    let lookup_field = body
        .lookup_field
        .clone()
        .unwrap_or_else(|| format!("{}_ref", parent.logicalname));
    for name in [&child, &value_field, &source_field, &lookup_field] {
        if !identifier(name) {
            return bad(format!("{name} is not a lower-case identifier"));
        }
    }
    if value_field == source_field || value_field == lookup_field || source_field == lookup_field {
        return bad("the child's three fields need three names".into());
    }
    if body.child_name.trim().is_empty() {
        return bad("child_name is required".into());
    }
    Ok(ExtractPlan {
        parent: parent.logicalname.clone(),
        parent_id: parent.entity_id,
        sources: body.sources.clone(),
        field_type,
        options: first.options.clone(),
        child,
        value_field,
        source_field,
        lookup_field,
    })
}

/// One batch's copy: the parents `$1` (ids) that are live, one child row
/// per non-empty source, with the parent's owner and unit, created by `$2`.
/// Identifiers come from the checked plan, quoted; a source's name is a
/// checked identifier, written as a literal. Pure.
pub fn batch_sql(plan: &ExtractPlan) -> String {
    let pairs: Vec<String> = plan
        .sources
        .iter()
        .map(|s| format!("('{s}', p.{})", quote_ident(s)))
        .collect();
    format!(
        "INSERT INTO {child} ({lookup}, {value}, {source}, created_by, modified_by, modified_at, \
                              owner_ref, owner_type, organization_ref) \
         SELECT p.\"id\", s.v, s.f, $2, $2, now(), p.owner_ref, p.owner_type, p.organization_ref \
           FROM {parent} p \
          CROSS JOIN LATERAL (VALUES {pairs}) AS s(f, v) \
          WHERE p.\"id\" = ANY($1) \
            AND (p.is_active IS NULL OR p.is_active = true) \
            AND s.v IS NOT NULL AND btrim(s.v::text) <> ''",
        child = quote_ident(&plan.child),
        lookup = quote_ident(&plan.lookup_field),
        value = quote_ident(&plan.value_field),
        source = quote_ident(&plan.source_field),
        parent = quote_ident(&plan.parent),
        pairs = pairs.join(", "),
    )
}

/// Extract repeating attributes into a child entity
///
/// Creates the child entity (value, source and lookup fields) and queues
/// the copy of every non-empty value as a durable run
/// (`/api/v1/admin/data-step-runs/{id}`). The sources are kept; the answer
/// lists the objects that read them. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/refactor/extract-child",
    operation_id = "extract_child_entity",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
    ])))),
    params(("entity_id" = Uuid, Path, description = "The parent entity")),
    request_body = ExtractChildBody,
    responses(
        (status = 202, description = "The child exists and the copy is queued", body = ExtractChildQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "The child's name is taken", body = ErrorResponse),
        (status = 422, description = "Bad sources or names", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn extract_child(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<ExtractChildBody>,
) -> Result<impl IntoResponse, AppError> {
    let parent = state
        .entities
        .load()
        .get_by_id(entity_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let plan = plan(&parent, &body)?;
    recording.preflight(&state.base.db_migrator).await?;

    // The child, through the ordinary entity and field creation.
    let create: super::entity::CreateEntityBody = serde_json::from_value(json!({
        "logicalname": plan.child,
        "name": body.child_name.trim(),
        "primary_name_attribute": (plan.field_type == FieldType::Text).then_some(&plan.value_field),
    }))
    .map_err(AppError::internal)?;
    super::entity::create_entity_core(&state, ctx.user_id, &recording, create).await?;
    let child_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM entity_info WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&plan.child)
    .fetch_one(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)?;
    let fields = [
        json!({
            "logicalname": plan.value_field,
            "name": "Value",
            "field_type": plan.field_type.as_str(),
            "options": plan.options,
        }),
        json!({
            "logicalname": plan.source_field,
            "name": "Source field",
            "field_type": "text",
            "is_filterable": true,
        }),
        json!({
            "logicalname": plan.lookup_field,
            "name": parent.logicalname,
            "field_type": "lookup",
            "lookup_entity_ref": plan.parent_id,
            "is_filterable": true,
        }),
    ];
    for field in fields {
        let body: super::attribute::CreateAttributeBody =
            serde_json::from_value(field).map_err(AppError::internal)?;
        let response = super::attribute::do_create_attribute_recorded(
            &state,
            child_id,
            ctx.user_id,
            body,
            Some(&*recording),
        )
        .await?;
        if response.status() != StatusCode::CREATED {
            return Err(AppError::internal(format!(
                "creating a field of {} answered {}",
                plan.child,
                response.status()
            )));
        }
    }

    let spec = json!({
        "entity_id": entity_id,
        "sources": plan.sources,
        "child": plan.child,
        "value_field": plan.value_field,
        "source_field": plan.source_field,
        "lookup_field": plan.lookup_field,
    });
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    let run_id: Uuid = sqlx::query_scalar(
        "INSERT INTO data_step_run (source, entity_logicalname, kind, spec, created_by) \
         VALUES ('admin', $1, 'extract_child', $2, $3) RETURNING id",
    )
    .bind(&plan.parent)
    .bind(&spec)
    .bind(ctx.user_id)
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
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "data_step_run",
            run_id,
            attome_audit::AuditOperation::Create,
            "entity.extract_child",
            ctx.user_id,
        )
        .comment(format!(
            "extract {}.{} into {}",
            plan.parent,
            plan.sources.join(", "),
            plan.child
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    let to_review = attome_core::metadata_reference::references_to_entity(
        &state.base.db_migrator,
        &plan.parent,
        MAX_REFERENCES,
    )
    .await?
    .into_iter()
    .filter(|r| plan.sources.contains(&r.to_attribute))
    .map(|r| ToReview {
        kind: r.from_kind,
        id: r.from_ref,
        label: r.from_label,
        attribute: r.to_attribute,
    })
    .collect();
    Ok((
        StatusCode::ACCEPTED,
        Json(ExtractChildQueued {
            run_id,
            child_entity_id: child_id,
            to_review,
        }),
    ))
}

/// `RunDataStep` for an `extract_child` run: batches of parents from the
/// run's cursor, each batch's child rows, counts and cursor committed
/// together, then finished.
pub(crate) async fn continue_extract(
    state: &EngineState,
    run: &fc::RunRow,
) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let parent_id = run
        .spec
        .get("entity_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            AppError::internal(format!("extract run {}: spec.entity_id missing", run.id))
        })?;
    let text = |key: &str| {
        run.spec
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                AppError::internal(format!("extract run {}: spec.{key} missing", run.id))
            })
    };
    let body = ExtractChildBody {
        sources: run
            .spec
            .get("sources")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        child_logicalname: text("child")?,
        child_name: text("child")?,
        value_field: Some(text("value_field")?),
        source_field: Some(text("source_field")?),
        lookup_field: Some(text("lookup_field")?),
    };
    // Checked again: the metadata may have changed since it was queued.
    let parent = state
        .entities
        .load()
        .get_by_id(parent_id)
        .cloned()
        .ok_or_else(|| AppError::internal(format!("extract run {}: the parent is gone", run.id)))?;
    let plan = plan(&parent, &body)?;
    let child_live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_info WHERE logicalname = $1 \
                          AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&plan.child)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !child_live {
        return Err(AppError::internal(format!(
            "extract run {}: the child {} is gone",
            run.id, plan.child
        )));
    }
    let insert = batch_sql(&plan);
    let actor = run.created_by;
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "extract_child: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT \"id\" FROM {} WHERE \"id\" > $1 ORDER BY \"id\" LIMIT $2",
            quote_ident(&plan.parent)
        ))
        .bind(cursor.unwrap_or(Uuid::nil()))
        .bind(EXTRACT_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let read = ids.len();
        let written = if ids.is_empty() {
            0
        } else {
            sqlx::query(&insert)
                .bind(&ids)
                .bind(actor)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .rows_affected()
        };
        if let Some(last) = ids.last() {
            cursor = Some(*last);
        }
        fc::advance_run(&mut tx, run.id, cursor, read as u64, written, 0).await?;
        attome_db::tx::commit(tx).await?;
        if (read as i64) < EXTRACT_BATCH {
            break;
        }
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    fc::finish_run(&mut conn, run.id, None).await?;
    tracing::info!(run_id = %run.id, parent = %plan.parent, child = %plan.child, "extract_child: finished");
    Ok(())
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/refactor/extract-child",
        post(extract_child),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(extract_child),
    components(schemas(ExtractChildBody, ExtractChildQueued, ToReview))
)]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{AttrInfo, DataClassification, EntityMeta, OnTargetDelete};

    fn attr(name: &str, ty: FieldType) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: FieldType::to_int(&ty),
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    fn contact() -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::nil(),
            logicalname: "contact".into(),
            attrs: vec![
                attr("phone_1", FieldType::Text),
                attr("phone_2", FieldType::Text),
                attr("phone_3", FieldType::Text),
                attr("age", FieldType::Number),
                attr("account_ref", FieldType::Lookup),
            ],
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    fn body(sources: &[&str]) -> ExtractChildBody {
        ExtractChildBody {
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            child_logicalname: "contact_phone".into(),
            child_name: "Contact phone".into(),
            value_field: None,
            source_field: None,
            lookup_field: None,
        }
    }

    #[test]
    fn extract_phones_into_child_plan() {
        let plan = plan(&contact(), &body(&["phone_1", "phone_2", "phone_3"])).unwrap();
        assert_eq!(plan.lookup_field, "contact_ref");
        assert_eq!(plan.value_field, "value");
        let sql = batch_sql(&plan);
        assert!(
            sql.starts_with(
                "INSERT INTO \"contact_phone\" (\"contact_ref\", \"value\", \"source_field\""
            ),
            "{sql}"
        );
        assert!(
            sql.contains(
                "('phone_1', p.\"phone_1\"), ('phone_2', p.\"phone_2\"), ('phone_3', p.\"phone_3\")"
            ),
            "{sql}"
        );
        assert!(
            sql.contains("p.owner_ref, p.owner_type, p.organization_ref"),
            "{sql}"
        );
        assert!(sql.contains("btrim(s.v::text) <> ''"), "{sql}");
    }

    #[test]
    fn extract_refuses_mixed_or_unsuitable_sources() {
        for sources in [
            vec!["phone_1"],
            vec!["phone_1", "age"],
            vec!["phone_1", "phone_1"],
            vec!["phone_1", "missing"],
            vec!["account_ref", "account_ref"],
        ] {
            assert!(plan(&contact(), &body(&sources)).is_err(), "{sources:?}");
        }
        let mut bad = body(&["phone_1", "phone_2"]);
        bad.child_logicalname = "Contact Phone".into();
        assert!(plan(&contact(), &bad).is_err());
        let mut same = body(&["phone_1", "phone_2"]);
        same.source_field = Some("value".into());
        assert!(plan(&contact(), &same).is_err());
    }
}

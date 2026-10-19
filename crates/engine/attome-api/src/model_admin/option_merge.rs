//! A5-T2: merging one value of an option set into another.
//!
//! `POST /api/v1/admin/model/option_set/{id}/merge` with `{from, into}`
//! retires `from` (when it is not retired already) and publishes the set,
//! through the same edit and publish path as the option set editor, so from
//! then on no new write may use it. It then queues the registered
//! `option_set_merge` job, which rewrites every record holding `from` in a
//! choice field that uses the set to `into`, in chunks of [`CHUNK`] records
//! by id, through the generic update path as the person who asked: each
//! change is checked, audited and in the record's history like any other
//! update. A record changed between the read and its update is left for a
//! second run, which finds only what is still left.
//!
//! A retired value is refused on new writes (the field's choices are the
//! set's published, not retired codes, A5-T1) and stays on old records until
//! a merge moves them.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::{EngineState, quote_ident};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{kinds, refresh_cooked};

/// The registered job's name.
pub const MERGE_JOB: &str = "option_set_merge";

/// Records read and updated per chunk.
pub const CHUNK: i64 = 1_000;

/// `{from, into}`: the codes to merge.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct MergeValuesRequest {
    /// The value to retire.
    from: String,
    /// The value its records take; must be an active value of the set.
    into: String,
}

/// The merge was published and its record update queued.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MergeValuesQueued {
    /// The option set version that retired `from` (the current one when it
    /// was retired already).
    version_no: i64,
    queued: bool,
}

/// The job's payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct MergePayload {
    pub user_id: Uuid,
    pub set: String,
    pub from: String,
    pub into: String,
}

/// Merges one value of an option set into another (A5-T2).
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/option_set/{id}/merge",
    description = "Retires `from` (publishing the set) and queues a background job that moves every record holding `from` to `into`, as the caller (A5-T2). The retirement, its audit event and the job commit together.",
    operation_id = "merge_option_set_values",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The option set")),
    request_body = MergeValuesRequest,
    responses(
        (status = 202, description = "`from` retired and published; the record update is queued", body = MergeValuesQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such option set", body = ErrorResponse),
        (status = 409, description = "The set has an open draft, or another save is in progress", body = ErrorResponse),
        (status = 422, description = "An unknown code, the same code twice, or a retired `into`", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(crate) async fn merge_values(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(request): Json<MergeValuesRequest>,
) -> Result<(axum::http::StatusCode, Json<MergeValuesQueued>), AppError> {
    let kind = kinds()
        .get(attome_model::kinds::OPTION_SET.as_str())
        .ok_or(AppError::NotFound)?;
    let db = &state.base.db;
    let head = attome_model::store::read(db, id, None).await?;
    if head.kind != attome_model::kinds::OPTION_SET.as_str() {
        return Err(AppError::NotFound);
    }
    if head.state != "published" {
        return Err(AppError::Conflict(
            "the option set has an open draft; publish or discard it first",
        ));
    }
    let (from, into) = (request.from.trim(), request.into.trim());
    let values = head.doc["values"].as_array().cloned().unwrap_or_default();
    let position = |code: &str| values.iter().position(|v| v["code"] == json!(code));
    let from_at = position(from)
        .ok_or_else(|| AppError::Validation(format!("from: no value `{from}` in this set")))?;
    let into_at = position(into)
        .ok_or_else(|| AppError::Validation(format!("into: no value `{into}` in this set")))?;
    if from_at == into_at {
        return Err(AppError::Validation(
            "from and into are the same value".into(),
        ));
    }
    if values[into_at]["retired"] == json!(true) {
        return Err(AppError::Validation(format!("into: `{into}` is retired")));
    }

    let payload = MergePayload {
        user_id: ctx.user_id,
        set: head.name.clone(),
        from: from.to_owned(),
        into: into.to_owned(),
    };
    let job = attome_core::jobs::JOB_TYPES
        .job(MERGE_JOB, &payload)
        .map_err(AppError::internal)?;
    let retire = values[from_at]["retired"] != json!(true);
    if retire {
        // The same guard as the publish route: blocking customer tests first.
        attome_records::customer_tests::publish_guard(&state, &ctx).await?;
    }

    // One transaction: the retirement and its publish (when needed), the
    // audit event and the job, so none of them stands without the others.
    let mut version_no = head.version_no;
    let mut tx = attome_db::tx::begin(db).await?;
    if retire {
        attome_metadata::model_edit::edit(
            db,
            &mut tx,
            kind.as_ref(),
            attome_metadata::model_edit::EditRequest {
                id,
                base_hash: head.content_hash.clone(),
                name: Some(head.name.clone()),
                commands: vec![json!({
                    "op": "set",
                    "path": format!("/values/{from_at}/retired"),
                    "value": true
                })],
            },
            Some(ctx.user_id),
        )
        .await?;
        let published = attome_model::publish::publish(
            &mut tx,
            kinds(),
            &attome_model::validate::CrossChecks::default(),
            kind.as_ref(),
            id,
        )
        .await?;
        version_no = published.version_no;
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            Some(id),
        )
        .named("model.option_set_merge")
        .comment(format!(
            "option set `{}`: `{from}` merged into `{into}` (v{version_no})",
            head.name
        )),
    )
    .await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    if retire {
        refresh_cooked(&state).await?;
    }
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(MergeValuesQueued {
            version_no,
            queued: true,
        }),
    ))
}

/// One choice field that takes its values from the set.
#[derive(sqlx::FromRow)]
struct SetField {
    entity: String,
    field: String,
    multi: bool,
}

/// The job: rewrites `from` to `into` in every record of every choice field
/// using the set, as `payload.user_id`. Answers how many records changed.
pub async fn apply(state: &EngineState, payload: &MergePayload) -> Result<u64, AppError> {
    // Authorized again now, not trusted from when it was queued: the person
    // must still be an administrator, and each table is checked below.
    let ctx = state.base.security.resolve_strict(payload.user_id).await?;
    ctx.require_admin()?;
    let db = &state.base.db;
    let fields: Vec<SetField> = sqlx::query_as(
        "SELECT e.logicalname AS entity, a.logicalname AS field, \
                COALESCE((a.options->>'multi')::boolean, false) AS multi \
         FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE a.options->>'option_set' = $1 \
           AND (a.is_active IS NULL OR a.is_active) AND (e.is_active IS NULL OR e.is_active) \
         ORDER BY e.logicalname, a.logicalname",
    )
    .bind(&payload.set)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut changed = 0u64;
    for field in fields {
        ctx.require(&field.entity, "update")?;
        let column = quote_ident(&field.field);
        let holds = if field.multi {
            format!("$1 = ANY({column})")
        } else {
            format!("{column} = $1")
        };
        let mut after: Option<Uuid> = None;
        loop {
            let rows: Vec<(Uuid, i64, Value)> = sqlx::query_as(&format!(
                "SELECT id, row_version, to_jsonb({column}) FROM {table} \
                 WHERE {holds} AND is_active = true AND ($2::uuid IS NULL OR id > $2) \
                 ORDER BY id LIMIT $3",
                table = quote_ident(&field.entity),
            ))
            .bind(&payload.from)
            .bind(after)
            .bind(CHUNK)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            let Some(last) = rows.last().map(|r| r.0) else {
                break;
            };
            for (id, row_version, value) in rows {
                let merged = merged_value(&value, &payload.from, &payload.into);
                let update = attome_records::entity_crud::update_record_for(
                    state,
                    &ctx,
                    payload.user_id,
                    &field.entity,
                    id,
                    row_version,
                    json!({ field.field.clone(): merged }),
                )
                .await;
                match update {
                    Ok(_) => changed += 1,
                    // Changed since the read: the next run takes it.
                    Err(AppError::VersionConflict | AppError::VersionConflictAt { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
            after = Some(last);
        }
    }
    tracing::info!(changed, set = %payload.set, from = %payload.from, into = %payload.into, "option set merge applied");
    Ok(changed)
}

/// A field's value with `from` replaced by `into`: the code itself, or for a
/// multi-select the list with `from` replaced and no code twice.
fn merged_value(value: &Value, from: &str, into: &str) -> Value {
    match value {
        Value::Array(codes) => {
            let mut out: Vec<Value> = Vec::with_capacity(codes.len());
            for code in codes {
                let code = if code == from {
                    json!(into)
                } else {
                    code.clone()
                };
                if !out.contains(&code) {
                    out.push(code);
                }
            }
            Value::Array(out)
        }
        _ => json!(into),
    }
}

#[cfg(test)]
mod tests {
    use super::merged_value;
    use serde_json::json;

    #[test]
    fn option_set_merge_replaces_the_code_once() {
        assert_eq!(
            merged_value(&json!("jedda"), "jedda", "jeddah"),
            json!("jeddah")
        );
        assert_eq!(
            merged_value(&json!(["riyadh", "jedda", "jeddah"]), "jedda", "jeddah"),
            json!(["riyadh", "jeddah"])
        );
    }
}

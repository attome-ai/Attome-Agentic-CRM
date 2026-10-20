//! W1-T6: drafting a contract from its type's template.
//!
//! `POST /api/v1/contract/contracts/{id}/draft` adds the contract's next
//! `contract_version` (source `draft`) and, in the same transaction,
//! enqueues a K3 render of the contract type's `draft_template_ref` against
//! the contract, whose document the worker attaches to that version's `file`
//! (`attome_docgen::render::AttachTarget`). Nothing renders on the request
//! thread. The template sees the contract and its `contract_clause` rows
//! (the clauses chosen for it, with their text) in the contract's
//! `language`, and only what the caller may read: the worker re-derives the
//! caller's field and record access at render time, so a field hidden from
//! them renders empty.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The answer to a draft request.
#[derive(Debug, Serialize, ToSchema)]
pub struct DraftQueued {
    /// The new `contract_version`; its file arrives when the render finishes.
    pub version_id: Uuid,
    pub version_no: i64,
    /// The render, at `GET /api/v1/docgen/renders/{render_id}`.
    pub render_id: Uuid,
}

/// A lookup's id from a record read. Pure.
pub fn lookup_id(data: &Value, field: &str) -> Option<Uuid> {
    match data.get(field)? {
        Value::String(s) => s.parse().ok(),
        Value::Object(o) => o.get("id")?.as_str()?.parse().ok(),
        _ => None,
    }
}

/// Drafts a contract from its type's template.
///
/// Adds the contract's next version (source `draft`) and queues a render of
/// the contract type's template against the contract; the document is
/// attached to the new version when the render finishes. The template is
/// rendered as the caller, in the contract's language, with the clauses
/// chosen for the contract. The caller needs update rights on the contract
/// and create rights on contract versions.
#[utoipa::path(
    post,
    path = "/api/v1/contract/contracts/{id}/draft",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The version is added and its render queued", body = DraftQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not change the contract or add versions", body = ErrorResponse),
        (status = 404, description = "No such contract the caller may read", body = ErrorResponse),
        (status = 409, description = "Another draft of this contract is being added", body = ErrorResponse),
        (status = 422, description = "The contract has no type, or its type no template", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_draft(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<DraftQueued>), AppError> {
    ctx.refuse_if_capped()?;
    ctx.require("contract", "update")?;
    ctx.require("contract_version", "create")?;
    let contract = attome_records::entity_crud::read_record(&state, &ctx, "contract", id).await?;
    let contract_type = lookup_id(contract.data(), "contract_type_ref").ok_or_else(|| {
        AppError::Validation("the contract has no contract type to draft from".into())
    })?;
    let kind =
        attome_records::entity_crud::read_record(&state, &ctx, "contract_type", contract_type)
            .await?;
    let template = lookup_id(kind.data(), "draft_template_ref")
        .ok_or_else(|| AppError::Validation("the contract type has no draft template".into()))?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-contract/draft:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another draft of this contract is being added",
        ));
    }
    let version_no: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version_no), 0)::bigint + 1 FROM contract_version \
          WHERE contract_id = $1 AND is_active IS NOT FALSE",
    )
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let version_id: Uuid = sqlx::query_scalar(
        "INSERT INTO contract_version \
           (contract_id, source, version_no, created_by_ref, created_by, owner_ref) \
         VALUES ($1, 'draft', $2, $3, $3, $3) RETURNING id",
    )
    .bind(id.to_string())
    .bind(version_no)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(
        &mut tx,
        "contract_version",
        version_id,
        ChangeOperation::Create,
    )
    .await?;
    let render_id = attome_docgen::render::enqueue_in_tx(
        &state,
        &ctx,
        &mut tx,
        template,
        id,
        Some(attome_docgen::render::AttachTarget {
            entity: "contract_version",
            record_id: version_id,
            field: "file",
        }),
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "contract_version",
            version_id,
            attome_audit::AuditOperation::Create,
            "contract.draft_requested",
            ctx.user_id,
        )
        .comment(format!(
            "draft {version_no} of contract {id}, render {render_id}"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(DraftQueued {
            version_id,
            version_no,
            render_id,
        }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_draft), components(schemas(DraftQueued)))]
pub struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lookups_read_as_ids_or_objects() {
        let id = Uuid::now_v7();
        let data = json!({
            "a": id.to_string(),
            "b": { "id": id.to_string(), "name": "Lease" },
            "c": null,
            "d": "not an id",
        });
        assert_eq!(lookup_id(&data, "a"), Some(id));
        assert_eq!(lookup_id(&data, "b"), Some(id));
        assert_eq!(lookup_id(&data, "c"), None);
        assert_eq!(lookup_id(&data, "d"), None);
        assert_eq!(lookup_id(&data, "missing"), None);
    }
}

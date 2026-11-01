//! W1-T10: an approved contract signed through K4, then active.
//!
//! `POST /api/v1/contract/contracts/{id}/send-for-signature` (only from
//! `approved`) takes the contract's latest version with a file, files a copy
//! of it as an `attome_document` on the contract (the document an envelope
//! signs), and creates and sends a K4 envelope to the signers in their
//! order (`attome_document::esign`). The link is kept in
//! `contract_signature` (migration 0352), one open signing per contract.
//! National identity signing (Nafath, UAE Pass) is refused: AJ1/AJ2 are not
//! built.
//!
//! The `contract_signature` job ([`tick`], every five minutes) takes each
//! signing whose envelope completed: it adds a contract version of source
//! `signed` holding the signed file, and moves the contract `approved ->
//! active` through the generic update, as the person who sent it (so the
//! transition's privilege and audit apply). The envelope keeps the
//! certificate: what was signed (by hash), by whom, when and how checked.
//! A declined or voided envelope ends the signing with the contract still
//! approved.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "contract_signature";
/// Signings one tick finishes.
const BATCH: i64 = 50;

/// Who signs, and how.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendForSignatureBody {
    pub signers: Vec<attome_document::esign::NewSigner>,
    /// `k4` (the default): email codes through K4. `nafath` and `uae_pass`
    /// are refused until their connectors exist.
    #[serde(default)]
    pub method: Option<String>,
}

/// A signing started.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SignatureSent {
    pub envelope_id: Uuid,
    pub document_id: Uuid,
}

/// Why a send is refused, if it is. Pure.
pub fn send_refusal(status: Option<&str>, method: Option<&str>) -> Option<AppError> {
    match method.map(str::trim).unwrap_or("k4") {
        "k4" => {}
        "nafath" | "uae_pass" => {
            return Some(AppError::Validation(
                "method: national identity signing is not available yet; use k4".into(),
            ));
        }
        _ => {
            return Some(AppError::Validation(
                "method is k4, nafath or uae_pass".into(),
            ));
        }
    }
    if status != Some("approved") {
        return Some(AppError::Conflict(
            "only an approved contract can be sent for signature",
        ));
    }
    None
}

fn file_key_of(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Object(o) => ["final_key", "key", "file_key"]
            .iter()
            .find_map(|k| o.get(*k).and_then(Value::as_str))
            .map(str::to_owned),
        _ => None,
    }
}

/// Copies the stored file `src` into `field` of `entity`'s record as a
/// server-made clean file (the generated-file path, as docgen attaches a
/// render), and sets the field through the generic update.
#[allow(clippy::too_many_arguments)]
async fn attach_copy(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
    field: &str,
    src: &str,
    filename: &str,
    checksum: &str,
) -> Result<String, AppError> {
    let session_id = Uuid::now_v7();
    let key = attome_document::files::final_key(entity, record_id, field, session_id, filename);
    let from = ObjectPath::parse(src).map_err(AppError::internal)?;
    let to = ObjectPath::parse(&key).map_err(AppError::internal)?;
    let store = state.base.storage.store();
    store.copy(&from, &to).await.map_err(AppError::internal)?;
    let size = store.head(&to).await.map_err(AppError::internal)?.size;
    attome_document::files::record_generated_clean_file(
        state,
        attome_document::files::GeneratedCleanFile {
            session_id,
            entity,
            record_id,
            field,
            owner: attome_document::files::FileOwner::Staff(ctx.user_id),
            object_key: &key,
            filename,
            content_type: "application/pdf",
            size_bytes: i64::try_from(size).unwrap_or(i64::MAX),
            checksum_sha256: checksum,
        },
    )
    .await?;
    let record = attome_records::entity_crud::read_record(state, ctx, entity, record_id).await?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        entity,
        record_id,
        record.row_version(),
        json!({ field: key }),
    )
    .await?;
    Ok(key)
}

/// The lowercase hex SHA-256 of a stored file.
async fn sha256_of(state: &EngineState, key: &str) -> Result<String, AppError> {
    use sha2::Digest;
    let path = ObjectPath::parse(key).map_err(AppError::internal)?;
    let bytes = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .map_err(AppError::internal)?
        .bytes()
        .await
        .map_err(AppError::internal)?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

/// Sends `contract` for signature as `ctx`; see the module doc.
pub async fn send_for_signature(
    state: &EngineState,
    ctx: &SecurityContext,
    contract: Uuid,
    body: &SendForSignatureBody,
) -> Result<SignatureSent, AppError> {
    ctx.require("contract", "update")?;
    let record = attome_records::entity_crud::read_record(state, ctx, "contract", contract).await?;
    let data = record.data();
    if let Some(refused) = send_refusal(
        data.get("status").and_then(Value::as_str),
        body.method.as_deref(),
    ) {
        return Err(refused);
    }
    let open: Option<Uuid> = sqlx::query_scalar(
        "SELECT envelope_id FROM contract_signature \
          WHERE contract_id = $1 AND finished_at IS NULL",
    )
    .bind(contract)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if open.is_some() {
        return Err(AppError::Conflict(
            "this contract is already out for signature",
        ));
    }
    let version: Option<(Uuid, Option<i64>, Value)> = sqlx::query_as(
        "SELECT id, version_no::bigint, to_jsonb(file) FROM contract_version \
          WHERE contract_id = $1 AND file IS NOT NULL AND is_active IS DISTINCT FROM false \
          ORDER BY version_no DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(contract.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((_, version_no, file)) = version else {
        return Err(AppError::Validation(
            "the contract has no version with a file to sign; draft it first".into(),
        ));
    };
    let src = file_key_of(Some(&file))
        .ok_or_else(|| AppError::Validation("the latest version has no file".into()))?;
    let title = data
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Contract")
        .to_owned();
    let filename = format!(
        "{}-v{}.pdf",
        title
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
            .take(80)
            .collect::<String>()
            .trim(),
        version_no.unwrap_or(1)
    );

    ctx.require("attome_document", "create")?;
    let (document, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "attome_document",
        json!({
            "name": filename,
            "entity_name": "contract",
            "record_id": contract.to_string(),
            "folder": "Signatures",
        }),
    )
    .await?;
    let checksum = sha256_of(state, &src).await?;
    attach_copy(
        state,
        ctx,
        "attome_document",
        document,
        "file",
        &src,
        &filename,
        &checksum,
    )
    .await?;
    let envelope = attome_document::esign::create_envelope(
        state,
        ctx,
        &attome_document::esign::NewEnvelope {
            title: format!("Signature: {title}"),
            document_ids: vec![document],
            signers: body
                .signers
                .iter()
                .map(|s| attome_document::esign::NewSigner {
                    name: s.name.clone(),
                    email: s.email.clone(),
                    role: s.role.clone(),
                    order: s.order,
                })
                .collect(),
        },
    )
    .await?;
    attome_document::esign::send_envelope(state, ctx, envelope).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO contract_signature (contract_id, envelope_id, document_id, requested_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(contract)
    .bind(envelope)
    .bind(document)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e.as_database_error() {
        Some(d) if d.is_unique_violation() => {
            AppError::Conflict("this contract is already out for signature")
        }
        _ => AppError::internal(e),
    })?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contract",
            contract,
            attome_audit::AuditOperation::Create,
            "contract.sent_for_signature",
            ctx.user_id,
        )
        .comment(format!("envelope {envelope}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(SignatureSent {
        envelope_id: envelope,
        document_id: document,
    })
}

type Finished = (Uuid, Uuid, Uuid, Uuid, String);

/// One run of the `contract_signature` job: completed envelopes make their
/// contracts active; declined or voided ones end their signing. Answers
/// how many contracts it activated.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let rows: Vec<Finished> = sqlx::query_as(
        "SELECT s.contract_id, s.envelope_id, s.document_id, s.requested_by, e.status \
           FROM contract_signature s JOIN esign_envelope e ON e.id = s.envelope_id \
          WHERE s.finished_at IS NULL AND e.status IN ('completed', 'declined', 'voided') \
          ORDER BY s.created_at LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut activated = 0;
    for (contract, envelope, document, requester, status) in rows {
        let outcome = if status == "completed" {
            complete(state, contract, document, requester).await
        } else {
            Ok(())
        };
        match outcome {
            Ok(()) => {
                sqlx::query(
                    "UPDATE contract_signature SET finished_at = now(), outcome = $2 \
                      WHERE contract_id = $1 AND envelope_id = $3 AND finished_at IS NULL",
                )
                .bind(contract)
                .bind(&status)
                .bind(envelope)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                if status == "completed" {
                    activated += 1;
                }
            }
            Err(e) => {
                tracing::warn!(%contract, %envelope, error = %e,
                    "contract signature: the signed contract was not activated; tried again next tick");
            }
        }
    }
    Ok(activated)
}

/// The signed file as a `signed` version, then `approved -> active`, as the
/// person who sent it.
async fn complete(
    state: &EngineState,
    contract: Uuid,
    document: Uuid,
    requester: Uuid,
) -> Result<(), AppError> {
    let ctx = attome_security::resolve_uncached(&state.base.db, requester).await?;
    let record =
        attome_records::entity_crud::read_record(state, &ctx, "contract", contract).await?;
    if record.data().get("status").and_then(Value::as_str) == Some("active") {
        return Ok(());
    }
    let doc =
        attome_records::entity_crud::read_record(state, &ctx, "attome_document", document).await?;
    let src = file_key_of(doc.data().get("file"))
        .ok_or_else(|| AppError::internal("the signed document has no file"))?;
    let filename = doc
        .data()
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("signed.pdf")
        .to_owned();
    let next: Option<i64> = sqlx::query_scalar(
        "SELECT max(version_no)::bigint FROM contract_version WHERE contract_id = $1",
    )
    .bind(contract.to_string())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (version, _) = attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        ctx.user_id,
        "contract_version",
        json!({
            "contract_id": contract.to_string(),
            "source": "signed",
            "version_no": next.map_or(1, |v| v + 1),
        }),
    )
    .await?;
    let checksum = sha256_of(state, &src).await?;
    attach_copy(
        state,
        &ctx,
        "contract_version",
        version,
        "file",
        &src,
        &filename,
        &checksum,
    )
    .await?;
    let record =
        attome_records::entity_crud::read_record(state, &ctx, "contract", contract).await?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        ctx.user_id,
        "contract",
        contract,
        record.row_version(),
        json!({ "status": "active" }),
    )
    .await?;
    Ok(())
}

/// Send a contract for signature
///
/// Sends an approved contract's latest version to its signers through an
/// electronic signature envelope, in their order. When everyone has signed
/// the signed file becomes a `signed` version and the contract becomes
/// active. The caller needs to update the contract.
#[utoipa::path(
    post,
    path = "/api/v1/contract/contracts/{id}/send-for-signature",
    operation_id = "post_contract_send_for_signature",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract's id")),
    request_body = SendForSignatureBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The envelope is sent", body = SignatureSent),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "The caller may not update the contract or file documents", body = attome_types::ErrorResponse),
        (status = 404, description = "No such contract the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "The contract is not approved, or is already out for signature", body = attome_types::ErrorResponse),
        (status = 422, description = "No version with a file, bad signers, or a signing method not available", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_send(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SendForSignatureBody>,
) -> Result<(StatusCode, Json<SignatureSent>), AppError> {
    ctx.refuse_if_capped()?;
    let sent = send_for_signature(&state, &ctx, id, &body).await?;
    Ok((StatusCode::ACCEPTED, Json(sent)))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_send),
    components(schemas(SendForSignatureBody, SignatureSent))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_from_draft_is_409() {
        assert!(matches!(
            send_refusal(Some("draft"), None),
            Some(AppError::Conflict(_))
        ));
        assert!(send_refusal(Some("approved"), None).is_none());
        assert!(send_refusal(Some("approved"), Some("k4")).is_none());
        assert!(matches!(
            send_refusal(Some("approved"), Some("nafath")),
            Some(AppError::Validation(_))
        ));
    }
}

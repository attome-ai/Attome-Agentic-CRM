//! W1-T8: negotiation rounds with the counterparty through a review link.
//!
//! `POST /api/v1/contract/contracts/{id}/share-for-review` opens the next
//! round: a `contract_review_link` row (migration 0353) and an emailed link
//! whose signed token (`attome_auth::signed_link`, domain [`LINK_DOMAIN`])
//! names that row and expires after `contract.review_link_days` (14 by
//! default). Opening a round closes the one before, so a link is good for
//! one round only.
//!
//! The link is the only authority on the public routes,
//! `GET`/`POST /api/v1/contract/review/{token}` (one token segment, listed in
//! `attome_server::middleware::bypass`). They show the contract's title and
//! its current version (a short-lived download link) and the link's own
//! comments and uploads: nothing of another contract, no internal note. The
//! counterparty may comment, and may upload one PDF or Word version, which
//! ends the round. The upload goes through the upload pipeline's virus scan
//! (`attome_document::files::ingest`) into a new `contract_version` of
//! source `counterparty_upload`, created as the person who shared the link.
//!
//! The `contract_review` job ([`tick`], every five minutes) takes each
//! upload whose scan finished: a clean file is set on its version and a
//! comparison with the version before it is queued (`compare`); a rejected
//! one is noted. Every round (shared, commented, uploaded, compared) is a
//! note on the contract's timeline.

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
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "contract_review";
/// What the link's signature is bound to.
pub const LINK_DOMAIN: &str = "attome-contract/review";
/// The link's lifetime when the setting is unset.
pub const DEFAULT_LINK_DAYS: i64 = 14;
/// The largest upload, so its base64 fits the 10 MB request body.
pub const MAX_UPLOAD_BYTES: usize = 7 * 1024 * 1024;
const MAX_COMMENT_CHARS: usize = 4000;
/// Uploads one tick finishes.
const BATCH: i64 = 50;
/// How long the current version's download link lasts.
const DOWNLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// Who reviews this round.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ShareForReviewBody {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    /// A line for the email.
    #[serde(default)]
    pub message: Option<String>,
}

/// The round opened.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReviewShared {
    pub link_id: Uuid,
    pub round: i32,
    pub expires_at: DateTime<Utc>,
}

/// The version the counterparty reviews.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReviewVersion {
    pub version_no: Option<i64>,
    /// Valid for 15 minutes.
    pub download_url: Option<String>,
}

/// Something the counterparty sent through this link.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReviewEntry {
    /// `comment` or `upload`.
    pub kind: String,
    pub body: Option<String>,
    pub file_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What the link shows.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReviewView {
    pub contract_title: String,
    pub round: i32,
    pub expires_at: DateTime<Utc>,
    pub version: Option<ReviewVersion>,
    pub entries: Vec<ReviewEntry>,
}

/// A comment, a version, or both.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewAction {
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    /// `application/pdf` or the Word (DOCX) type.
    #[serde(default)]
    pub content_type: Option<String>,
    /// The file, base64; at most 7 MB decoded.
    #[serde(default)]
    pub content_base64: Option<String>,
}

/// What the action did.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReviewActionDone {
    pub round: i32,
    /// The new version, when a file was sent; it is compared once scanned.
    pub version_id: Option<Uuid>,
}

/// An uploaded file: its name, content type and bytes.
pub type Upload = (String, &'static str, Vec<u8>);

/// A review entry as stored: kind, body, file name, time.
type EntryRow = (String, Option<String>, Option<String>, DateTime<Utc>);

/// The file an action carries, checked. Pure.
pub fn upload_of(action: &ReviewAction) -> Result<Option<Upload>, AppError> {
    let Some(encoded) = action.content_base64.as_deref() else {
        return Ok(None);
    };
    let content_type = match action.content_type.as_deref().map(str::trim) {
        Some("application/pdf") => "application/pdf",
        Some(t) if t == DOCX => DOCX,
        _ => {
            return Err(AppError::Validation(
                "content_type: a PDF or Word (DOCX) file".into(),
            ));
        }
    };
    let name = action
        .file_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= 200)
        .ok_or_else(|| AppError::Validation("file_name: 1 to 200 characters".into()))?;
    if encoded.len() > MAX_UPLOAD_BYTES / 3 * 4 + 8 {
        return Err(AppError::Validation("the file is larger than 7 MB".into()));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| AppError::Validation("content_base64 is not base64".into()))?;
    if bytes.is_empty() || bytes.len() > MAX_UPLOAD_BYTES {
        return Err(AppError::Validation(
            "the file is empty or larger than 7 MB".into(),
        ));
    }
    Ok(Some((name.to_owned(), content_type, bytes)))
}

fn link_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// `contract.review_link_days`, or 14.
fn link_days(state: &EngineState) -> i64 {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("contract.review_link_days")
        .map(|d| settings.resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .filter(|d| (1..=90).contains(d))
        .unwrap_or(DEFAULT_LINK_DAYS)
}

/// The signed token for `link`, valid until `expires`.
pub fn token_for(
    state: &EngineState,
    link: Uuid,
    expires: DateTime<Utc>,
) -> Result<String, AppError> {
    attome_auth::signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &link.to_string(),
        expires.timestamp(),
    )
    .ok_or_else(|| AppError::internal("could not sign the review link"))
}

fn email_job(to: &str, subject: String, text: String) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
        to: to.to_owned(),
        subject,
        text_body: text,
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
        stream: Default::default(),
        list_unsubscribe: None,
    }))
}

/// A note on the contract's timeline, in `tx`. Internal: never shown
/// through the link.
async fn note(tx: &mut attome_db::Tx<'_>, contract: Uuid, text: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
         VALUES ($1, 'contract', $2, $3, false)",
    )
    .bind(Uuid::now_v7())
    .bind(contract.to_string())
    .bind(text)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

fn file_key_of(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Opens the next review round of `contract` as `ctx`; see the module doc.
pub async fn share_for_review(
    state: &EngineState,
    ctx: &SecurityContext,
    contract: Uuid,
    body: &ShareForReviewBody,
) -> Result<ReviewShared, AppError> {
    ctx.require("contract", "update")?;
    if !attome_document::esign::email_ok(&body.email) {
        return Err(AppError::Validation("email: a valid address".into()));
    }
    let record = attome_records::entity_crud::read_record(state, ctx, "contract", contract).await?;
    let data = record.data();
    if matches!(
        data.get("status").and_then(Value::as_str),
        Some("active" | "terminated" | "expired")
    ) {
        return Err(AppError::Conflict(
            "a contract in force is not negotiated; amend it instead",
        ));
    }
    let title = data
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Contract")
        .to_owned();
    let has_version: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM contract_version \
          WHERE contract_id = $1 AND file IS NOT NULL AND is_active IS NOT FALSE)",
    )
    .bind(contract.to_string())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !has_version {
        return Err(AppError::Validation(
            "the contract has no version with a file to review; draft it first".into(),
        ));
    }
    let expires = Utc::now() + Duration::days(link_days(state));
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-contract/review:{contract}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another review round of this contract is being opened",
        ));
    }
    sqlx::query(
        "UPDATE contract_review_link SET closed_at = now() \
          WHERE contract_id = $1 AND closed_at IS NULL",
    )
    .bind(contract)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (link, round): (Uuid, i32) = sqlx::query_as(
        "INSERT INTO contract_review_link (contract_id, round, email, name, created_by, expires_at) \
         SELECT $1, COALESCE(MAX(round), 0) + 1, $2, $3, $4, $5 \
           FROM contract_review_link WHERE contract_id = $1 \
         RETURNING id, round",
    )
    .bind(contract)
    .bind(body.email.trim())
    .bind(body.name.as_deref().map(str::trim))
    .bind(ctx.user_id)
    .bind(expires)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let url = format!(
        "{}/contract-review/{}",
        state.base.config.frontend_url().trim_end_matches('/'),
        token_for(state, link, expires)?
    );
    let greeting = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or_else(|| "Hello,".to_owned(), |n| format!("Hello {n},"));
    let message = body
        .message
        .as_deref()
        .map(|m| format!("{}\n\n", m.trim().chars().take(2000).collect::<String>()))
        .unwrap_or_default();
    attome_jobs::enqueue_in_tx(
        &mut tx,
        email_job(
            body.email.trim(),
            format!("For your review: {title}"),
            format!(
                "{greeting}\n\n{message}Please review \"{title}\". You can comment on it and send \
                 back your version here, until {}:\n\n{url}\n",
                expires.format("%Y-%m-%d")
            ),
        ),
    )
    .await
    .map_err(AppError::internal)?;
    note(
        &mut tx,
        contract,
        &format!("Review round {round} shared with the counterparty."),
    )
    .await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Access,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "contract",
            Some(contract),
        )
        .comment(format!("review link for round {round}, until {expires}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ReviewShared {
        link_id: link,
        round,
        expires_at: expires,
    })
}

type LinkRow = (Uuid, i32, DateTime<Utc>, Uuid);

/// The open, unexpired link a token names: (contract, round, expires,
/// shared by). `NotFound` for anything else.
async fn open_link(state: &EngineState, token: &str) -> Result<(Uuid, LinkRow), AppError> {
    let link = attome_auth::signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token,
        Utc::now().timestamp(),
    )
    .and_then(|s| Uuid::parse_str(&s).ok())
    .ok_or(AppError::NotFound)?;
    let row: Option<LinkRow> = sqlx::query_as(
        "SELECT contract_id, round, expires_at, created_by FROM contract_review_link \
          WHERE id = $1 AND closed_at IS NULL AND expires_at > now()",
    )
    .bind(link)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    row.map(|r| (link, r)).ok_or(AppError::NotFound)
}

/// What the counterparty behind `token` sees.
pub async fn review_view(state: &EngineState, token: &str) -> Result<ReviewView, AppError> {
    let (link, (contract, round, expires_at, _)) = open_link(state, token).await?;
    let title: Option<String> =
        sqlx::query_scalar("SELECT title FROM contract WHERE id = $1 AND is_active IS NOT FALSE")
            .bind(contract)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let version: Option<(Option<i64>, Value)> = sqlx::query_as(
        "SELECT version_no::bigint, to_jsonb(file) FROM contract_version \
          WHERE contract_id = $1 AND file IS NOT NULL AND is_active IS NOT FALSE \
          ORDER BY version_no DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(contract.to_string())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let version = match version {
        Some((version_no, file)) => {
            let download_url = match file_key_of(Some(&file)) {
                Some(key) => Some(
                    attome_storage::presign_download(&state.base.storage, &key, DOWNLOAD_TTL)
                        .await
                        .map_err(AppError::internal)?,
                ),
                None => None,
            };
            Some(ReviewVersion {
                version_no,
                download_url,
            })
        }
        None => None,
    };
    let entries: Vec<EntryRow> = sqlx::query_as(
        "SELECT kind, body, file_name, created_at FROM contract_review_entry \
          WHERE link_id = $1 ORDER BY created_at, id",
    )
    .bind(link)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(ReviewView {
        contract_title: title.unwrap_or_default(),
        round,
        expires_at,
        version,
        entries: entries
            .into_iter()
            .map(|(kind, body, file_name, created_at)| ReviewEntry {
                kind,
                body,
                file_name,
                created_at,
            })
            .collect(),
    })
}

/// Acts for the counterparty behind `token`; see the module doc.
pub async fn review_act(
    state: &EngineState,
    token: &str,
    action: &ReviewAction,
) -> Result<ReviewActionDone, AppError> {
    let comment = action
        .comment
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    if comment.is_some_and(|c| c.chars().count() > MAX_COMMENT_CHARS) {
        return Err(AppError::Validation(
            "comment: at most 4,000 characters".into(),
        ));
    }
    let upload = upload_of(action)?;
    if comment.is_none() && upload.is_none() {
        return Err(AppError::Validation(
            "send a comment, a file, or both".into(),
        ));
    }
    let (link, (contract, round, _, shared_by)) = open_link(state, token).await?;

    let mut version_id = None;
    let mut session_id = None;
    let mut file_name = None;
    if let Some((name, content_type, bytes)) = upload {
        // The version is the sharer's: the counterparty has no account.
        let ctx = attome_security::resolve_uncached(&state.base.db, shared_by).await?;
        ctx.require("contract_version", "create")?;
        let next: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(version_no)::bigint FROM contract_version WHERE contract_id = $1",
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
                "source": "counterparty_upload",
                "version_no": next.map_or(1, |v| v + 1),
            }),
        )
        .await?;
        let session = attome_document::files::ingest(
            state,
            attome_document::files::FileOwner::Staff(shared_by),
            "contract_version",
            version,
            "file",
            &name,
            content_type,
            bytes,
        )
        .await?;
        version_id = Some(version);
        session_id = Some(session);
        file_name = Some(name);
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if let Some(comment) = comment {
        sqlx::query(
            "INSERT INTO contract_review_entry (link_id, kind, body) VALUES ($1, 'comment', $2)",
        )
        .bind(link)
        .bind(comment)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        note(
            &mut tx,
            contract,
            &format!("Counterparty comment, round {round}: {comment}"),
        )
        .await?;
    }
    if let (Some(version), Some(session), Some(name)) = (version_id, session_id, &file_name) {
        sqlx::query(
            "INSERT INTO contract_review_entry (link_id, kind, file_name, session_id, version_id) \
             VALUES ($1, 'upload', $2, $3, $4)",
        )
        .bind(link)
        .bind(name)
        .bind(session)
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        // A version ends the round: the link is single-use per round. A
        // second upload racing this one finds it closed.
        let closed = sqlx::query(
            "UPDATE contract_review_link SET closed_at = now() \
              WHERE id = $1 AND closed_at IS NULL",
        )
        .bind(link)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if closed.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        note(
            &mut tx,
            contract,
            &format!(
                "Round {round}: the counterparty sent {name}; it is compared with the version \
                 before once scanned."
            ),
        )
        .await?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contract",
            contract,
            attome_audit::AuditOperation::Create,
            "contract.counterparty_review",
            shared_by,
        )
        .comment(format!(
            "round {round} by the counterparty: {}{}",
            if comment.is_some() { "comment " } else { "" },
            version_id.map_or_else(String::new, |v| format!("version {v}"))
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(ReviewActionDone { round, version_id })
}

type ScannedUpload = (Uuid, Uuid, Uuid, i32, Uuid, String, Option<String>);

/// One run of the `contract_review` job: counterparty uploads whose scan
/// finished are set on their versions and compared, or noted as refused.
/// Answers how many comparisons it queued.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let rows: Vec<ScannedUpload> = sqlx::query_as(
        "SELECT e.id, l.contract_id, e.version_id, l.round, l.created_by, s.status, s.final_key \
           FROM contract_review_entry e \
           JOIN contract_review_link l ON l.id = e.link_id \
           JOIN upload_session s ON s.id = e.session_id \
          WHERE e.kind = 'upload' AND e.processed_at IS NULL \
            AND s.status IN ('clean', 'rejected', 'expired') \
          ORDER BY e.created_at LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut queued = 0;
    for (entry, contract, version, round, shared_by, status, final_key) in rows {
        match finish_upload(
            state, contract, version, round, shared_by, &status, final_key,
        )
        .await
        {
            Ok(comparison) => {
                sqlx::query(
                    "UPDATE contract_review_entry SET processed_at = now(), comparison_id = $2 \
                      WHERE id = $1",
                )
                .bind(entry)
                .bind(comparison)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                if comparison.is_some() {
                    queued += 1;
                }
            }
            Err(e) => {
                tracing::warn!(%contract, %version, error = %e,
                    "contract review: a counterparty version was not compared; tried again next tick");
            }
        }
    }
    Ok(queued)
}

async fn finish_upload(
    state: &EngineState,
    contract: Uuid,
    version: Uuid,
    round: i32,
    shared_by: Uuid,
    status: &str,
    final_key: Option<String>,
) -> Result<Option<Uuid>, AppError> {
    let key = final_key.filter(|_| status == "clean");
    let Some(key) = key else {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        note(
            &mut tx,
            contract,
            &format!("Round {round}: the counterparty's file was refused by the virus scan."),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        return Ok(None);
    };
    let ctx = attome_security::resolve_uncached(&state.base.db, shared_by).await?;
    let record =
        attome_records::entity_crud::read_record(state, &ctx, "contract_version", version).await?;
    if file_key_of(record.data().get("file")).as_deref() != Some(key.as_str()) {
        attome_records::entity_crud::update_record_for(
            state,
            &ctx,
            ctx.user_id,
            "contract_version",
            version,
            record.row_version(),
            json!({ "file": key }),
        )
        .await?;
    }
    let previous: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM contract_version \
          WHERE contract_id = $1 AND id <> $2 AND file IS NOT NULL AND is_active IS NOT FALSE \
          ORDER BY version_no DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(contract.to_string())
    .bind(version)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(previous) = previous else {
        return Ok(None);
    };
    let comparison = crate::compare::request_compare(
        state,
        &ctx,
        contract,
        &crate::compare::ContractCompareBody {
            from_version: previous,
            to_version: version,
        },
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    note(
        &mut tx,
        contract,
        &format!(
            "Round {round}: the counterparty's version is being compared with the one before."
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(comparison))
}

/// Share a contract for counterparty review
///
/// Opens the contract's next negotiation round: emails the counterparty a
/// link, valid for `contract.review_link_days` (14 by default), to read the
/// current version, comment and send back their own version. Opening a
/// round closes the link of the round before. The caller needs to update
/// the contract.
#[utoipa::path(
    post,
    path = "/api/v1/contract/contracts/{id}/share-for-review",
    operation_id = "post_contract_share_for_review",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract's id")),
    request_body = ShareForReviewBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The round is open and the link emailed", body = ReviewShared),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "The caller may not update the contract", body = attome_types::ErrorResponse),
        (status = 404, description = "No such contract the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "The contract is in force, or a round is being opened", body = attome_types::ErrorResponse),
        (status = 422, description = "A bad email, or no version with a file", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_share(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ShareForReviewBody>,
) -> Result<(StatusCode, Json<ReviewShared>), AppError> {
    ctx.refuse_if_capped()?;
    let shared = share_for_review(&state, &ctx, id, &body).await?;
    Ok((StatusCode::CREATED, Json(shared)))
}

/// Open a contract review link
///
/// What the counterparty reviews: the contract's title, its current version
/// and what they sent through this link. No session; the link's signed
/// token is the credential.
#[utoipa::path(
    get,
    path = "/api/v1/contract/review/{token}",
    operation_id = "get_contract_review",
    tag = "contract",
    params(("token" = String, Path, description = "The review link's token")),
    responses(
        (status = 200, description = "What the counterparty reviews", body = ReviewView),
        (status = 404, description = "An unknown, expired or closed link", body = attome_types::ErrorResponse),
    ),
)]
// The contract a counterparty's link opens. No sign-in: the link is the
// authority.
pub async fn get_review(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Json<ReviewView>, AppError> {
    Ok(Json(review_view(&state, &token).await?))
}

/// Comment or send a version through a review link
///
/// The counterparty comments, sends back their version (PDF or Word, at most
/// 7 MB, virus-scanned before anyone sees it), or both. A version ends the
/// round. No session; the link's signed token is the credential.
#[utoipa::path(
    post,
    path = "/api/v1/contract/review/{token}",
    operation_id = "post_contract_review",
    tag = "contract",
    params(("token" = String, Path, description = "The review link's token")),
    request_body = ReviewAction,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Received", body = ReviewActionDone),
        (status = 404, description = "An unknown, expired or closed link", body = attome_types::ErrorResponse),
        (status = 422, description = "Nothing sent, a comment too long, or a file of the wrong type or size", body = attome_types::ErrorResponse),
    ),
)]
// A counterparty comments or sends a version. No sign-in: the link is the
// authority.
pub async fn post_review(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    Json(body): Json<ReviewAction>,
) -> Result<Json<ReviewActionDone>, AppError> {
    Ok(Json(review_act(&state, &token, &body).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_share, get_review, post_review),
    components(schemas(
        ShareForReviewBody,
        ReviewShared,
        ReviewVersion,
        ReviewEntry,
        ReviewView,
        ReviewAction,
        ReviewActionDone
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn action(content_type: &str, name: &str, bytes: &[u8]) -> ReviewAction {
        ReviewAction {
            comment: None,
            file_name: Some(name.into()),
            content_type: Some(content_type.into()),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        }
    }

    #[test]
    fn only_pdf_and_word_files_are_taken() {
        let pdf = upload_of(&action("application/pdf", "v2.pdf", b"%PDF-1.4"))
            .unwrap_or_default()
            .map(|(n, t, b)| (n, t, b.len()));
        assert_eq!(pdf, Some(("v2.pdf".to_owned(), "application/pdf", 8)));
        assert!(upload_of(&action(DOCX, "v2.docx", b"PK")).is_ok_and(|u| u.is_some()));
        assert!(upload_of(&action("text/html", "x.html", b"<p>")).is_err());
        assert!(upload_of(&action("application/pdf", " ", b"%PDF")).is_err());
        assert!(upload_of(&action("application/pdf", "e.pdf", b"")).is_err());
        let none = ReviewAction {
            comment: Some("ok".into()),
            file_name: None,
            content_type: None,
            content_base64: None,
        };
        assert!(upload_of(&none).is_ok_and(|u| u.is_none()));
    }
}

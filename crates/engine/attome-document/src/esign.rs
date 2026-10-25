//! K4-T1: electronic signatures.
//!
//! **The envelope.** A signed-in person who may read some documents puts
//! them in an envelope with its signers (name, email, role, signing order)
//! (`POST /api/v1/esign/envelopes`). Each document's file is hashed
//! (SHA-256) then, so the certificate names exactly what was signed. Sending
//! (`…/{id}/send`) emails the first signers in order a personal link; when
//! everyone at one position has signed, the next position is emailed.
//!
//! **The ceremony.** A link is a signed token over the signer (30 days), and
//! is the only authority on the public routes (`/api/v1/esign/sign/{token}`):
//! the signer reads the envelope, asks for a six-digit code by email (the
//! platform's one-time codes: hashed, five minutes, one use, five tries; at
//! most one a minute), and signs with the code and their typed name, or
//! declines. Email codes are the only identity check built: national
//! identity (Nafath, UAE Pass) needs their credentials.
//!
//! **The record.** Every step is an event in `esign_event`, each hashed with
//! the one before ([`event_hash`]), so a changed or removed event breaks the
//! chain. When the last signer signs, the envelope is `completed` and keeps
//! its certificate ([`certificate`]): the documents and their hashes, each
//! signer with when, from which address and how they were checked, the
//! events, and the chain's last hash; the certificate's own hash is kept
//! beside it. A decline ends the envelope (`declined`). Nothing is deleted.

use std::net::SocketAddr;

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The signed-link domain of a signer's link.
const LINK_DOMAIN: &str = "attome-document/esign";
/// How long a signer's link works.
pub const LINK_DAYS: i64 = 30;
/// Documents and signers an envelope may hold.
pub const MAX_DOCUMENTS: usize = 10;
pub const MAX_SIGNERS: usize = 20;
/// The largest file hashed into an envelope.
const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
/// The first hash of every chain.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Pure rules ──────────────────────────────────────────────────────────────

/// A signer as the rules see them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerState {
    pub id: Uuid,
    pub order: i32,
    /// `waiting`, `notified`, `signed` or `declined`.
    pub status: String,
}

/// The signing position whose turn it is: the lowest order with a signer
/// who has not signed; `None` when everyone has signed. Pure.
pub fn current_order(signers: &[SignerState]) -> Option<i32> {
    signers
        .iter()
        .filter(|s| s.status != "signed")
        .map(|s| s.order)
        .min()
}

/// Whether `signer` may sign now: not signed or declined, nobody declined,
/// and it is their position's turn. Pure.
pub fn may_sign(signer: Uuid, signers: &[SignerState]) -> bool {
    if signers.iter().any(|s| s.status == "declined") {
        return false;
    }
    let Some(me) = signers.iter().find(|s| s.id == signer) else {
        return false;
    };
    matches!(me.status.as_str(), "waiting" | "notified") && current_order(signers) == Some(me.order)
}

/// The envelope's status once its signers are as given (a sent envelope).
/// Pure.
pub fn status_after(signers: &[SignerState]) -> &'static str {
    if signers.iter().any(|s| s.status == "declined") {
        "declined"
    } else if !signers.is_empty() && signers.iter().all(|s| s.status == "signed") {
        "completed"
    } else {
        "sent"
    }
}

/// The signers to email next: those at the current position still waiting.
/// Pure.
pub fn to_notify(signers: &[SignerState]) -> Vec<Uuid> {
    let Some(order) = current_order(signers) else {
        return Vec::new();
    };
    signers
        .iter()
        .filter(|s| s.order == order && s.status == "waiting")
        .map(|s| s.id)
        .collect()
}

/// One event's hash, chained to the one before. Pure.
#[allow(clippy::too_many_arguments)]
pub fn event_hash(
    prev: &str,
    seq: i32,
    kind: &str,
    signer: Option<Uuid>,
    at: DateTime<Utc>,
    ip: Option<&str>,
    detail: &Value,
) -> String {
    let material = format!(
        "{prev}|{seq}|{kind}|{}|{}|{}|{}",
        signer.map(|s| s.to_string()).unwrap_or_default(),
        at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        ip.unwrap_or_default(),
        detail
    );
    hex::encode(Sha256::digest(material.as_bytes()))
}

/// One stored event.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, sqlx::FromRow)]
pub struct EnvelopeEvent {
    pub seq: i32,
    pub signer_id: Option<Uuid>,
    pub kind: String,
    pub at: DateTime<Utc>,
    pub ip: Option<String>,
    #[schema(value_type = Object)]
    pub detail: Value,
    pub prev_hash: String,
    pub hash: String,
}

/// Whether the events form an unbroken chain from [`GENESIS`]. Pure.
pub fn chain_intact(events: &[EnvelopeEvent]) -> bool {
    let mut prev = GENESIS.to_owned();
    for (i, e) in events.iter().enumerate() {
        let expected_seq = i32::try_from(i + 1).unwrap_or(i32::MAX);
        if e.seq != expected_seq || e.prev_hash != prev {
            return false;
        }
        let hash = event_hash(
            &e.prev_hash,
            e.seq,
            &e.kind,
            e.signer_id,
            e.at,
            e.ip.as_deref(),
            &e.detail,
        );
        if hash != e.hash {
            return false;
        }
        prev = hash;
    }
    true
}

/// A document in an envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct EnvelopeDocument {
    pub document_id: Uuid,
    pub name: String,
    pub sha256: String,
}

/// A signer, as the envelope's owner sees them.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, sqlx::FromRow)]
pub struct EnvelopeSigner {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub sign_order: i32,
    pub status: String,
    pub typed_name: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub decline_reason: Option<String>,
}

/// The completion certificate. Pure.
pub fn certificate(
    envelope: Uuid,
    title: &str,
    completed_at: DateTime<Utc>,
    documents: &[EnvelopeDocument],
    signers: &[EnvelopeSigner],
    events: &[EnvelopeEvent],
) -> Value {
    json!({
        "envelope_id": envelope,
        "title": title,
        "completed_at": completed_at,
        "documents": documents.iter().map(|d| json!({
            "document_id": d.document_id, "name": d.name, "sha256": d.sha256,
        })).collect::<Vec<_>>(),
        "signers": signers.iter().map(|s| json!({
            "name": s.name,
            "email": s.email,
            "role": s.role,
            "order": s.sign_order,
            "typed_name": s.typed_name,
            "signed_at": s.signed_at,
            "ip": s.ip,
            "user_agent": s.user_agent,
            "identity_check": "email_code",
        })).collect::<Vec<_>>(),
        "events": events.iter().map(|e| json!({
            "seq": e.seq, "kind": e.kind, "at": e.at, "ip": e.ip, "signer_id": e.signer_id,
            "hash": e.hash,
        })).collect::<Vec<_>>(),
        "chain_hash": events.last().map(|e| e.hash.clone()).unwrap_or_else(|| GENESIS.to_owned()),
    })
}

/// A plausible email address: one `@`, something either side, a dot in
/// the domain, no spaces. Pure.
pub fn email_ok(email: &str) -> bool {
    let e = email.trim();
    let mut parts = e.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !e.chars().any(char::is_whitespace)
        && e.len() <= 254
}

// ── Storage ─────────────────────────────────────────────────────────────────

async fn signer_states(
    conn: &mut sqlx::PgConnection,
    envelope: Uuid,
) -> Result<Vec<SignerState>, AppError> {
    let rows: Vec<(Uuid, i32, String)> = sqlx::query_as(
        "SELECT id, sign_order, status FROM esign_signer WHERE envelope_id = $1 ORDER BY sign_order, id",
    )
    .bind(envelope)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, order, status)| SignerState { id, order, status })
        .collect())
}

/// Appends one event to the envelope's chain, in the caller's transaction
/// (which holds the envelope's row lock).
async fn append_event(
    tx: &mut attome_db::Tx<'_>,
    envelope: Uuid,
    kind: &str,
    signer: Option<Uuid>,
    ip: Option<&str>,
    detail: Value,
) -> Result<(), AppError> {
    let last: Option<(i32, String)> = sqlx::query_as(
        "SELECT seq, hash FROM esign_event WHERE envelope_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(envelope)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (seq, prev) = match last {
        Some((seq, hash)) => (seq + 1, hash),
        None => (1, GENESIS.to_owned()),
    };
    // Microsecond precision: what Postgres keeps, so the hash re-computes.
    let at = DateTime::<Utc>::from_timestamp_micros(Utc::now().timestamp_micros())
        .unwrap_or_else(Utc::now);
    let hash = event_hash(&prev, seq, kind, signer, at, ip, &detail);
    sqlx::query(
        "INSERT INTO esign_event (envelope_id, seq, signer_id, kind, at, ip, detail, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(envelope)
    .bind(seq)
    .bind(signer)
    .bind(kind)
    .bind(at)
    .bind(ip)
    .bind(&detail)
    .bind(&prev)
    .bind(&hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
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

fn signer_link(state: &EngineState, signer: Uuid) -> Result<String, AppError> {
    let expires = (Utc::now() + Duration::days(LINK_DAYS)).timestamp();
    let token = attome_auth::signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &signer.to_string(),
        expires,
    )
    .ok_or_else(|| AppError::internal("could not sign the signer's link"))?;
    Ok(format!(
        "{}/esign/{token}",
        state.base.config.frontend_url().trim_end_matches('/')
    ))
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
    }))
}

/// Emails the signers whose turn it is and marks them notified, in `tx`.
async fn notify_next(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    envelope: Uuid,
    title: &str,
) -> Result<(), AppError> {
    let states = signer_states(&mut *tx, envelope).await?;
    for signer in to_notify(&states) {
        let (name, email): (String, String) =
            sqlx::query_as("SELECT name, email FROM esign_signer WHERE id = $1")
                .bind(signer)
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?;
        let link = signer_link(state, signer)?;
        attome_jobs::enqueue_in_tx(
            tx,
            email_job(
                &email,
                format!("Please sign: {title}"),
                format!(
                    "{name},\n\nYou are asked to sign \"{title}\". Open this link to read and sign it:\n\n{link}\n\n\
                     يُطلب منك توقيع \"{title}\". افتح هذا الرابط لقراءته وتوقيعه:\n\n{link}\n"
                ),
            ),
        )
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE esign_signer SET status = 'notified' WHERE id = $1 AND status = 'waiting'",
        )
        .bind(signer)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        append_event(tx, envelope, "notified", Some(signer), None, json!({})).await?;
    }
    Ok(())
}

/// Locks the envelope's row and answers its title, status and creator.
async fn lock_envelope(
    tx: &mut attome_db::Tx<'_>,
    envelope: Uuid,
) -> Result<(String, String, Uuid), AppError> {
    sqlx::query_as("SELECT title, status, created_by FROM esign_envelope WHERE id = $1 FOR UPDATE")
        .bind(envelope)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

// ── The owner's routes ──────────────────────────────────────────────────────

/// A signer to add.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewSigner {
    pub name: String,
    pub email: String,
    /// `signer` (the default), `approver` or `witness`.
    #[serde(default)]
    pub role: Option<String>,
    /// Signing position, 1 first; equal positions sign in any order.
    #[serde(default)]
    pub order: Option<i32>,
}

/// A new envelope.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewEnvelope {
    pub title: String,
    /// `attome_document` records the caller may read.
    pub document_ids: Vec<Uuid>,
    pub signers: Vec<NewSigner>,
}

/// An envelope, as its owner sees it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnvelopeView {
    pub id: Uuid,
    pub title: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub documents: Vec<EnvelopeDocument>,
    pub signers: Vec<EnvelopeSigner>,
    pub events: Vec<EnvelopeEvent>,
    /// The events form an unbroken hash chain.
    pub chain_intact: bool,
    #[schema(value_type = Option<Object>)]
    pub certificate: Option<Value>,
    pub certificate_hash: Option<String>,
}

/// A stored file key from a record's file field (a key, or an object
/// naming one).
fn file_key(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Object(o) => ["final_key", "key", "file_key"]
            .iter()
            .find_map(|k| o.get(*k).and_then(Value::as_str))
            .map(str::to_owned),
        _ => None,
    }
}

async fn file_sha256(state: &EngineState, key: &str) -> Result<String, AppError> {
    let path = ObjectPath::parse(key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let object = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .map_err(|_| AppError::Validation("a document's file could not be read".into()))?;
    if object.meta.size > MAX_FILE_BYTES {
        return Err(AppError::Validation(
            "a document's file is larger than 50 MB".into(),
        ));
    }
    let bytes = object.bytes().await.map_err(AppError::internal)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Creates a draft envelope as `ctx`; see the module doc.
pub async fn create_envelope(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &NewEnvelope,
) -> Result<Uuid, AppError> {
    let title = body.title.trim();
    if title.is_empty() || title.chars().count() > 300 {
        return Err(AppError::Validation("title: 1 to 300 characters".into()));
    }
    if body.document_ids.is_empty() || body.document_ids.len() > MAX_DOCUMENTS {
        return Err(AppError::Validation(format!(
            "document_ids: 1 to {MAX_DOCUMENTS} documents"
        )));
    }
    if body.signers.is_empty() || body.signers.len() > MAX_SIGNERS {
        return Err(AppError::Validation(format!("signers: 1 to {MAX_SIGNERS}")));
    }
    for s in &body.signers {
        if s.name.trim().is_empty() || !email_ok(&s.email) {
            return Err(AppError::Validation(
                "every signer needs a name and a valid email".into(),
            ));
        }
        if let Some(role) = s.role.as_deref()
            && !matches!(role, "signer" | "approver" | "witness")
        {
            return Err(AppError::Validation(
                "role: signer, approver or witness".into(),
            ));
        }
        if s.order
            .is_some_and(|o| !(1..=MAX_SIGNERS as i32).contains(&o))
        {
            return Err(AppError::Validation(format!("order: 1 to {MAX_SIGNERS}")));
        }
    }
    // The caller must be able to read every document; each file is hashed
    // now, outside any transaction.
    let mut documents = Vec::new();
    for id in &body.document_ids {
        let record =
            attome_records::entity_crud::read_record(state, ctx, "attome_document", *id).await?;
        let data = record.data();
        let key = file_key(data.get("file"))
            .ok_or_else(|| AppError::Validation(format!("document {id} has no file")))?;
        let name = data
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("document")
            .to_owned();
        let sha = file_sha256(state, &key).await?;
        documents.push((*id, name, key, sha));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let envelope: Uuid = sqlx::query_scalar(
        "INSERT INTO esign_envelope (title, created_by) VALUES ($1, $2) RETURNING id",
    )
    .bind(title)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for (position, (id, name, key, sha)) in documents.iter().enumerate() {
        sqlx::query(
            "INSERT INTO esign_document (envelope_id, document_id, name, file_key, sha256, position) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(envelope)
        .bind(id)
        .bind(name)
        .bind(key)
        .bind(sha)
        .bind(i32::try_from(position).unwrap_or(0))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    for s in &body.signers {
        sqlx::query(
            "INSERT INTO esign_signer (envelope_id, name, email, role, sign_order) \
             VALUES ($1, $2, lower($3), $4, $5)",
        )
        .bind(envelope)
        .bind(s.name.trim())
        .bind(s.email.trim())
        .bind(s.role.as_deref().unwrap_or("signer"))
        .bind(s.order.unwrap_or(1))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    append_event(
        &mut tx,
        envelope,
        "created",
        None,
        None,
        json!({ "by": ctx.user_id, "documents": documents.len(), "signers": body.signers.len() }),
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "esign_envelope",
            envelope,
            attome_audit::AuditOperation::Create,
            "esign.envelope_created",
            ctx.user_id,
        )
        .comment(title.to_owned()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(envelope)
}

/// The owner (or an administrator) only; others get `NotFound`.
async fn require_owner(
    state: &EngineState,
    ctx: &SecurityContext,
    envelope: Uuid,
) -> Result<(), AppError> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM esign_envelope WHERE id = $1")
            .bind(envelope)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match owner {
        Some(o) if o == ctx.user_id || ctx.is_admin => Ok(()),
        _ => Err(AppError::NotFound),
    }
}

/// Sends a draft envelope: the first signers are emailed.
pub async fn send_envelope(
    state: &EngineState,
    ctx: &SecurityContext,
    envelope: Uuid,
) -> Result<(), AppError> {
    require_owner(state, ctx, envelope).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (title, status, _) = lock_envelope(&mut tx, envelope).await?;
    if status != "draft" {
        return Err(AppError::Conflict("only a draft envelope can be sent"));
    }
    sqlx::query("UPDATE esign_envelope SET status = 'sent', sent_at = now(), row_version = row_version + 1 WHERE id = $1")
        .bind(envelope)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    append_event(
        &mut tx,
        envelope,
        "sent",
        None,
        None,
        json!({ "by": ctx.user_id }),
    )
    .await?;
    notify_next(state, &mut tx, envelope, &title).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "esign_envelope",
            envelope,
            attome_audit::AuditOperation::Update,
            "esign.envelope_sent",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// An envelope's status (`draft`, `sent`, `completed`, `declined`,
/// `voided`), `None` when there is no such envelope. For engines that wait
/// on a signature (F10-T10 plan acceptance) without reading K4's tables.
pub async fn envelope_status(
    state: &EngineState,
    envelope: Uuid,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar("SELECT status FROM esign_envelope WHERE id = $1")
        .bind(envelope)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Voids a draft or sent envelope; its links stop working.
pub async fn void_envelope(
    state: &EngineState,
    ctx: &SecurityContext,
    envelope: Uuid,
) -> Result<(), AppError> {
    require_owner(state, ctx, envelope).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (_, status, _) = lock_envelope(&mut tx, envelope).await?;
    if !matches!(status.as_str(), "draft" | "sent") {
        return Err(AppError::Conflict("a finished envelope cannot be voided"));
    }
    sqlx::query(
        "UPDATE esign_envelope SET status = 'voided', row_version = row_version + 1 WHERE id = $1",
    )
    .bind(envelope)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    append_event(
        &mut tx,
        envelope,
        "voided",
        None,
        None,
        json!({ "by": ctx.user_id }),
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "esign_envelope",
            envelope,
            attome_audit::AuditOperation::Update,
            "esign.envelope_voided",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

async fn load_view(state: &EngineState, envelope: Uuid) -> Result<EnvelopeView, AppError> {
    let db = &state.base.db;
    type Head = (
        String,
        String,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<Value>,
        Option<String>,
    );
    let head: Head = sqlx::query_as(
        "SELECT title, status, created_at, sent_at, completed_at, certificate, certificate_hash \
           FROM esign_envelope WHERE id = $1",
    )
    .bind(envelope)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let documents: Vec<EnvelopeDocument> = sqlx::query_as(
        "SELECT document_id, name, sha256 FROM esign_document WHERE envelope_id = $1 ORDER BY position",
    )
    .bind(envelope)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let signers: Vec<EnvelopeSigner> = sqlx::query_as(
        "SELECT id, name, email, role, sign_order, status, typed_name, signed_at, ip, user_agent, \
                decline_reason FROM esign_signer WHERE envelope_id = $1 ORDER BY sign_order, id",
    )
    .bind(envelope)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let events: Vec<EnvelopeEvent> = sqlx::query_as(
        "SELECT seq, signer_id, kind, at, ip, detail, prev_hash, hash FROM esign_event \
          WHERE envelope_id = $1 ORDER BY seq",
    )
    .bind(envelope)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(EnvelopeView {
        id: envelope,
        title: head.0,
        status: head.1,
        created_at: head.2,
        sent_at: head.3,
        completed_at: head.4,
        chain_intact: chain_intact(&events),
        documents,
        signers,
        events,
        certificate: head.5,
        certificate_hash: head.6,
    })
}

// ── The signer's routes ─────────────────────────────────────────────────────

/// What a signer sees.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SignerView {
    pub envelope_title: String,
    pub envelope_status: String,
    pub signer_name: String,
    pub signer_status: String,
    /// It is this signer's turn.
    pub may_sign: bool,
    pub documents: Vec<EnvelopeDocument>,
}

/// A signer's action.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SignerAction {
    /// `code` (email me a code), `sign` or `decline`.
    pub action: String,
    /// The emailed code, to sign or decline.
    #[serde(default)]
    pub code: Option<String>,
    /// The signer's name as they type it, to sign.
    #[serde(default)]
    pub typed_name: Option<String>,
    /// Why, to decline.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What a signer's action did.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SignerActionDone {
    /// `code_sent`, `signed` or `declined`.
    pub result: String,
    pub envelope_status: String,
}

/// The signer a link names, while it is valid; `NotFound` otherwise.
fn signer_of(state: &EngineState, token: &str) -> Result<Uuid, AppError> {
    attome_auth::signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token,
        Utc::now().timestamp(),
    )
    .and_then(|s| Uuid::parse_str(&s).ok())
    .ok_or(AppError::NotFound)
}

async fn signer_envelope(
    state: &EngineState,
    signer: Uuid,
) -> Result<(Uuid, String, String, String), AppError> {
    sqlx::query_as("SELECT envelope_id, name, email, status FROM esign_signer WHERE id = $1")
        .bind(signer)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// What the signer behind `token` sees.
pub async fn signer_view(state: &EngineState, token: &str) -> Result<SignerView, AppError> {
    let signer = signer_of(state, token)?;
    let (envelope, name, _, status) = signer_envelope(state, signer).await?;
    let view = load_view(state, envelope).await?;
    if matches!(view.status.as_str(), "draft" | "voided") {
        return Err(AppError::NotFound);
    }
    let states: Vec<SignerState> = view
        .signers
        .iter()
        .map(|s| SignerState {
            id: s.id,
            order: s.sign_order,
            status: s.status.clone(),
        })
        .collect();
    Ok(SignerView {
        envelope_title: view.title,
        envelope_status: view.status.clone(),
        signer_name: name,
        signer_status: status,
        may_sign: view.status == "sent" && may_sign(signer, &states),
        documents: view.documents,
    })
}

/// The purpose a signer's codes are issued under.
fn code_purpose(envelope: Uuid) -> String {
    format!("esign:{envelope}")
}

/// Acts for the signer behind `token`; see the module doc.
pub async fn signer_act(
    state: &EngineState,
    token: &str,
    action: &SignerAction,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<SignerActionDone, AppError> {
    let signer = signer_of(state, token)?;
    let (envelope, name, email, _) = signer_envelope(state, signer).await?;
    let db = &state.base.db;
    match action.action.as_str() {
        "code" => {
            let view = signer_view(state, token).await?;
            if !view.may_sign {
                return Err(AppError::Conflict("it is not this signer's turn"));
            }
            // At most one code a minute.
            let recent: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM one_time_code WHERE user_ref = $1 AND purpose = $2 \
                   AND created_at > now() - interval '60 seconds')",
            )
            .bind(signer)
            .bind(code_purpose(envelope))
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if recent {
                return Err(AppError::Conflict("a code was sent less than a minute ago"));
            }
            let sender = QueueCode {
                email: &email,
                title: &view.envelope_title,
                db,
            };
            attome_auth::otp::issue(
                db,
                &state.base.pepper_ring(),
                &sender,
                signer,
                &code_purpose(envelope),
                attome_auth::otp::OtpChannel::Email,
            )
            .await?;
            Ok(SignerActionDone {
                result: "code_sent".into(),
                envelope_status: view.envelope_status,
            })
        }
        "sign" | "decline" => {
            let decline = action.action == "decline";
            let typed = action
                .typed_name
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty());
            if !decline && typed.is_none() {
                return Err(AppError::Validation(
                    "typed_name: type your name to sign".into(),
                ));
            }
            let code = action.code.as_deref().unwrap_or_default();
            let outcome = attome_auth::otp::verify(
                db,
                &state.base.pepper_ring(),
                signer,
                &code_purpose(envelope),
                code,
            )
            .await?;
            if outcome != attome_auth::otp::OtpOutcome::Verified {
                return Err(AppError::Validation(
                    "code: the code is wrong, used or expired; ask for a new one".into(),
                ));
            }
            let mut tx = attome_db::tx::begin(db).await?;
            let (title, status, _) = lock_envelope(&mut tx, envelope).await?;
            let states = signer_states(&mut tx, envelope).await?;
            if status != "sent" || !may_sign(signer, &states) {
                return Err(AppError::Conflict(
                    "this envelope is not waiting for this signer",
                ));
            }
            if decline {
                sqlx::query(
                    "UPDATE esign_signer SET status = 'declined', decline_reason = $2, ip = $3, \
                         user_agent = $4, signed_at = now() WHERE id = $1",
                )
                .bind(signer)
                .bind(action.reason.as_deref().map(str::trim))
                .bind(&ip)
                .bind(&user_agent)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                append_event(
                    &mut tx,
                    envelope,
                    "declined",
                    Some(signer),
                    ip.as_deref(),
                    json!({ "reason": action.reason, "identity_check": "email_code" }),
                )
                .await?;
            } else {
                sqlx::query(
                    "UPDATE esign_signer SET status = 'signed', typed_name = $2, ip = $3, \
                         user_agent = $4, signed_at = now() WHERE id = $1",
                )
                .bind(signer)
                .bind(typed)
                .bind(&ip)
                .bind(&user_agent)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                append_event(
                    &mut tx,
                    envelope,
                    "signed",
                    Some(signer),
                    ip.as_deref(),
                    json!({ "typed_name": typed, "identity_check": "email_code" }),
                )
                .await?;
            }
            let after = signer_states(&mut tx, envelope).await?;
            let next_status = status_after(&after);
            match next_status {
                "declined" => {
                    sqlx::query("UPDATE esign_envelope SET status = 'declined', row_version = row_version + 1 WHERE id = $1")
                        .bind(envelope)
                        .execute(&mut *tx)
                        .await
                        .map_err(AppError::internal)?;
                }
                "completed" => {
                    append_event(&mut tx, envelope, "completed", None, None, json!({})).await?;
                    complete_in_tx(&mut tx, envelope, &title).await?;
                }
                _ => notify_next(state, &mut tx, envelope, &title).await?,
            }
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                attome_audit::BusinessEvent::new(
                    "esign_envelope",
                    envelope,
                    attome_audit::AuditOperation::Update,
                    if decline {
                        "esign.declined"
                    } else {
                        "esign.signed"
                    },
                    Uuid::nil(),
                )
                .comment(format!("{name} <{email}>")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(SignerActionDone {
                result: if decline { "declined" } else { "signed" }.into(),
                envelope_status: next_status.into(),
            })
        }
        _ => Err(AppError::Validation("action: code, sign or decline".into())),
    }
}

/// Builds and keeps the certificate, and marks the envelope completed.
async fn complete_in_tx(
    tx: &mut attome_db::Tx<'_>,
    envelope: Uuid,
    title: &str,
) -> Result<(), AppError> {
    let documents: Vec<EnvelopeDocument> = sqlx::query_as(
        "SELECT document_id, name, sha256 FROM esign_document WHERE envelope_id = $1 ORDER BY position",
    )
    .bind(envelope)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let signers: Vec<EnvelopeSigner> = sqlx::query_as(
        "SELECT id, name, email, role, sign_order, status, typed_name, signed_at, ip, user_agent, \
                decline_reason FROM esign_signer WHERE envelope_id = $1 ORDER BY sign_order, id",
    )
    .bind(envelope)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let events: Vec<EnvelopeEvent> = sqlx::query_as(
        "SELECT seq, signer_id, kind, at, ip, detail, prev_hash, hash FROM esign_event \
          WHERE envelope_id = $1 ORDER BY seq",
    )
    .bind(envelope)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let cert = certificate(envelope, title, now, &documents, &signers, &events);
    let cert_hash = hex::encode(Sha256::digest(cert.to_string().as_bytes()));
    sqlx::query(
        "UPDATE esign_envelope SET status = 'completed', completed_at = $2, certificate = $3, \
             certificate_hash = $4, row_version = row_version + 1 WHERE id = $1",
    )
    .bind(envelope)
    .bind(now)
    .bind(&cert)
    .bind(&cert_hash)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for s in &signers {
        attome_jobs::enqueue_in_tx(
            tx,
            email_job(
                &s.email,
                format!("Signed by everyone: {title}"),
                format!(
                    "\"{title}\" has been signed by everyone. Certificate hash: {cert_hash}\n\n\
                     تم توقيع \"{title}\" من الجميع. بصمة الشهادة: {cert_hash}\n"
                ),
            ),
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Sends a signer's code by email, queued.
struct QueueCode<'a> {
    email: &'a str,
    title: &'a str,
    db: &'a attome_db::DbPool,
}

impl attome_auth::otp::OtpSender for QueueCode<'_> {
    async fn send(
        &self,
        _user_id: Uuid,
        _channel: attome_auth::otp::OtpChannel,
        code: &str,
    ) -> Result<(), AppError> {
        let mut tx = attome_db::tx::begin(self.db).await?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            email_job(
                self.email,
                format!("Your signing code: {code}"),
                format!(
                    "Your code to sign \"{}\" is {code}. It works once, for five minutes.\n\n\
                     رمزك لتوقيع \"{}\" هو {code}. يعمل مرة واحدة لمدة خمس دقائق.\n",
                    self.title, self.title
                ),
            ),
        )
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        Ok(())
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct EnvelopeCreated {
    pub id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/esign/envelopes",
    operation_id = "post_esign_envelope",
    tag = "document",
    request_body = NewEnvelope,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The draft envelope", body = EnvelopeCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "A document the caller may not read", body = ErrorResponse),
        (status = 422, description = "A bad title, document, signer or file", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Creates a draft envelope from documents the caller may read.
async fn post_envelope(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<NewEnvelope>,
) -> Result<(StatusCode, Json<EnvelopeCreated>), AppError> {
    let id = create_envelope(&state, &ctx, &body).await?;
    Ok((StatusCode::CREATED, Json(EnvelopeCreated { id })))
}

#[utoipa::path(
    get,
    path = "/api/v1/esign/envelopes/{id}",
    operation_id = "get_esign_envelope",
    tag = "document",
    params(("id" = Uuid, Path, description = "The envelope")),
    responses(
        (status = 200, description = "The envelope, its signers, events and certificate", body = EnvelopeView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No envelope of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// An envelope of the caller's (or any, for an administrator).
async fn get_envelope(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<EnvelopeView>, AppError> {
    require_owner(&state, &ctx, id).await?;
    Ok(Json(load_view(&state, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/esign/envelopes/{id}/send",
    operation_id = "post_esign_envelope_send",
    tag = "document",
    params(("id" = Uuid, Path, description = "The envelope")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Sent; the first signers are emailed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No envelope of the caller's", body = ErrorResponse),
        (status = 409, description = "Not a draft", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Sends a draft envelope to its first signers.
async fn post_send(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    send_envelope(&state, &ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/esign/envelopes/{id}/void",
    operation_id = "post_esign_envelope_void",
    tag = "document",
    params(("id" = Uuid, Path, description = "The envelope")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Voided; its links stop working"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No envelope of the caller's", body = ErrorResponse),
        (status = 409, description = "Already finished", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Voids a draft or sent envelope.
async fn post_void(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    void_envelope(&state, &ctx, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/esign/sign/{token}",
    operation_id = "get_esign_signer_view",
    tag = "document",
    params(("token" = String, Path, description = "The signer's link token")),
    responses(
        (status = 200, description = "What the signer signs", body = SignerView),
        (status = 404, description = "An unknown, expired or voided link", body = ErrorResponse),
    ),
)]
/// The envelope a signer's link opens. No sign-in: the link is the authority.
async fn get_sign(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Json<SignerView>, AppError> {
    Ok(Json(signer_view(&state, &token).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/esign/sign/{token}",
    operation_id = "post_esign_signer_action",
    tag = "document",
    params(("token" = String, Path, description = "The signer's link token")),
    request_body = SignerAction,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Done", body = SignerActionDone),
        (status = 404, description = "An unknown, expired or voided link", body = ErrorResponse),
        (status = 409, description = "Not this signer's turn, or a code was sent less than a minute ago", body = ErrorResponse),
        (status = 422, description = "A wrong code, or no typed name", body = ErrorResponse),
    ),
)]
/// A signer asks for a code, signs or declines. No sign-in: the link and
/// the emailed code are the authority.
async fn post_sign(
    State(state): State<EngineState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SignerAction>,
) -> Result<Json<SignerActionDone>, AppError> {
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer.ip(),
        &headers,
        &state.base.config,
    )
    .to_string();
    let agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(300).collect::<String>());
    Ok(Json(
        signer_act(&state, &token, &body, Some(ip), agent).await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/esign/envelopes", post(post_envelope))
        .route("/api/v1/esign/envelopes/{id}", get(get_envelope))
        .route("/api/v1/esign/envelopes/{id}/send", post(post_send))
        .route("/api/v1/esign/envelopes/{id}/void", post(post_void))
        .route("/api/v1/esign/sign/{token}", get(get_sign).post(post_sign))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_envelope, get_envelope, post_send, post_void, get_sign, post_sign),
    components(schemas(
        NewEnvelope,
        NewSigner,
        EnvelopeCreated,
        EnvelopeView,
        EnvelopeDocument,
        EnvelopeSigner,
        EnvelopeEvent,
        SignerView,
        SignerAction,
        SignerActionDone
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(n: u128, order: i32, status: &str) -> SignerState {
        SignerState {
            id: Uuid::from_u128(n),
            order,
            status: status.into(),
        }
    }

    #[test]
    fn envelope_flow_two_signers_in_order() {
        let mut signers = vec![signer(1, 1, "waiting"), signer(2, 2, "waiting")];
        assert_eq!(to_notify(&signers), vec![Uuid::from_u128(1)]);
        assert!(may_sign(Uuid::from_u128(1), &signers));
        assert!(
            !may_sign(Uuid::from_u128(2), &signers),
            "the second waits for the first"
        );
        signers[0].status = "signed".into();
        assert_eq!(status_after(&signers), "sent");
        assert_eq!(to_notify(&signers), vec![Uuid::from_u128(2)]);
        assert!(may_sign(Uuid::from_u128(2), &signers));
        assert!(!may_sign(Uuid::from_u128(1), &signers), "no signing twice");
        signers[1].status = "signed".into();
        assert_eq!(status_after(&signers), "completed");
        assert!(to_notify(&signers).is_empty());
    }

    #[test]
    fn envelope_flow_decline_ends_it() {
        let signers = vec![signer(1, 1, "declined"), signer(2, 1, "notified")];
        assert_eq!(status_after(&signers), "declined");
        assert!(!may_sign(Uuid::from_u128(2), &signers));
    }

    #[test]
    fn envelope_flow_event_chain_detects_tampering() {
        let at = |s: i64| DateTime::<Utc>::from_timestamp(1_760_000_000 + s, 0).unwrap();
        let mut events = Vec::new();
        let mut prev = GENESIS.to_owned();
        for (i, kind) in ["created", "sent", "signed"].iter().enumerate() {
            let seq = i as i32 + 1;
            let detail = json!({ "n": i });
            let hash = event_hash(
                &prev,
                seq,
                kind,
                None,
                at(i as i64),
                Some("192.0.2.1"),
                &detail,
            );
            events.push(EnvelopeEvent {
                seq,
                signer_id: None,
                kind: (*kind).into(),
                at: at(i as i64),
                ip: Some("192.0.2.1".into()),
                detail,
                prev_hash: prev.clone(),
                hash: hash.clone(),
            });
            prev = hash;
        }
        assert!(chain_intact(&events));
        let mut changed = events.clone();
        changed[1].ip = Some("198.51.100.7".into());
        assert!(!chain_intact(&changed), "a changed event breaks the chain");
        let mut removed = events.clone();
        removed.remove(1);
        assert!(!chain_intact(&removed), "a removed event breaks the chain");
    }

    #[test]
    fn envelope_flow_certificate_lists_hashes_and_ips() {
        let doc = EnvelopeDocument {
            document_id: Uuid::from_u128(9),
            name: "Contract.pdf".into(),
            sha256: "ab".repeat(32),
        };
        let s = EnvelopeSigner {
            id: Uuid::from_u128(1),
            name: "Huda".into(),
            email: "huda@example.com".into(),
            role: "signer".into(),
            sign_order: 1,
            status: "signed".into(),
            typed_name: Some("Huda Saleh".into()),
            signed_at: Some(Utc::now()),
            ip: Some("192.0.2.1".into()),
            user_agent: Some("Firefox".into()),
            decline_reason: None,
        };
        let cert = certificate(Uuid::from_u128(5), "NDA", Utc::now(), &[doc], &[s], &[]);
        assert_eq!(cert["documents"][0]["sha256"], "ab".repeat(32));
        assert_eq!(cert["signers"][0]["ip"], "192.0.2.1");
        assert_eq!(cert["signers"][0]["identity_check"], "email_code");
        assert_eq!(cert["chain_hash"], GENESIS);
    }

    #[test]
    fn envelope_flow_checks_emails() {
        assert!(email_ok("a.b@example.com"));
        assert!(!email_ok("a@b"));
        assert!(!email_ok("a b@example.com"));
        assert!(!email_ok("a@@example.com"));
    }
}

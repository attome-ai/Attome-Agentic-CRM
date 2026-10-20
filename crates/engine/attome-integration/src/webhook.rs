//! `POST /api/v1/integrations/{system}/webhook` — the inbound connector
//! webhook. Bypass-listed via `attome_server::middleware::bypass::
//! is_integrations_webhook_path` — a segment-shape match (one dynamic
//! `{system}` segment, then the literal `webhook`, nothing after) rather
//! than a blanket subtree prefix, precisely so a future sibling route (an
//! admin/config surface) mounted under the same `{system}` segment is never
//! swept into the public bypass just by sharing a prefix — see that
//! function's own doc comment. Because the caller is an external system
//! with no session/API key/S2S credential —
//! this handler performs its own per-system authentication instead
//! (`auth_type = "hmac"` only in Phase 1) — see [`admit`] for the signed,
//! replay-proof wire contract (M59 plan §4.1, MASTER-PLAN P0 row 0.6).
//!
//! Still reaches this handler through the full body-limit + pre-auth
//! rate-limit layers (`attome_server::app::{apply_outer_layers,
//! apply_pre_auth_rate_limit}` wrap the whole router regardless of bypass —
//! see `ServerBuilder::build`'s doc), and through `ModelRegistry`'s license
//! gate (this route is mounted via `IntegrationModel::routes()`, so an
//! unlicensed deployment 404s here exactly like every other module route).
//!
//! **D-425, the property this route exists to prove**: the write that lands
//! an inbound event goes through `attome_records::entity_crud::create_record_for`
//! — the SAME generic entity-mutation path an interactive user's `POST
//! /api/v1/integration_event` would take — running as the target
//! system's own `service_principal_ref`, not a superuser/bypass identity.
//! Rules, state-model enforcement, record-level security, audit, and cache
//! invalidation all therefore apply to an inbound webhook write exactly as
//! they would to any other write. If the service principal lacks
//! `integration_event.create`, the webhook is correctly rejected — an
//! integration is never a privilege-escalation path.

use std::time::Duration;

use attome_cache::Store;
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::connector::{ConnectorKind, connector_for};
use crate::{credential, system};

/// Hex HMAC-SHA256 of the signed message (see [`admit`]).
pub const SIGNATURE_HEADER: &str = "x-integration-signature";
/// Unix seconds, ASCII digits only, covered by the signature.
pub const TIMESTAMP_HEADER: &str = "x-integration-timestamp";
const EVENT_ENTITY: &str = "integration_event";

/// Clock-skew tolerance: `x-integration-timestamp` must fall within ± this
/// many seconds of server time. Same protocol constant as the S2S window
/// (`attome_s2s::rate_limit::TIMESTAMP_WINDOW_SECS`) — not a config knob.
pub const TIMESTAMP_WINDOW_SECS: i64 = 300;

/// Redis TTL of a used signature. Twice the window for the reason
/// `attome_s2s::rate_limit::NONCE_TTL_SECS` gives (B10): a request stamped up to
/// one window in the *future* stays timestamp-valid until `receive + 2·window`,
/// so a nonce that expired sooner would let a byte-for-byte replay through.
pub const NONCE_TTL_SECS: i64 = 2 * TIMESTAMP_WINDOW_SECS;

const _: () = assert!(
    NONCE_TTL_SECS >= 2 * TIMESTAMP_WINDOW_SECS,
    "the webhook nonce TTL must cover the whole timestamp-acceptance window in both directions"
);

/// Bound on the nonce store round-trip. A security control: a timeout
/// rejects (503), never admits — same posture and value as the S2S guard:
/// the shared request-path class, `attome_cache::timeouts::REQUEST_PATH` (300 ms).
const NONCE_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// The longest timestamp string accepted (Unix seconds fit in 11 digits
/// until the year 5138). Bounds the parse and rejects padding games.
const MAX_TIMESTAMP_DIGITS: usize = 12;

#[derive(Serialize, ToSchema)]
struct WebhookAcceptedResponse {
    accepted: usize,
}

/// An admitted inbound call: its timestamped signature verified and its
/// nonce recorded under `nonce_key`.
#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    pub nonce_key: String,
}

fn nonce_key(system_id: Uuid, sig: &[u8]) -> String {
    // Keyed on the *decoded* signature re-encoded lowercase: `hex::decode`
    // accepts either case, so keying on the raw header would let an attacker
    // replay a captured call with its signature upper-cased.
    format!(
        "attome-integration:webhook-nonce:{system_id}:{}",
        hex::encode(sig)
    )
}

fn record(outcome: &'static str) {
    // No-op when no recorder is installed (observability.metrics_port == 0).
    // Labelled by outcome only: a per-system label would be an unbounded
    // series per integration system; the system id is on the log line.
    metrics::counter!("integration_webhook_total", "outcome" => outcome).increment(1);
}

fn reject(system_id: Uuid, outcome: &'static str, err: AppError) -> AppError {
    record(outcome);
    metrics::counter!("security_rejection_total", "reason" => format!("integration_webhook_{outcome}"))
        .increment(1);
    tracing::info!(%system_id, outcome, "inbound integration webhook rejected");
    err
}

/// Constant-time HMAC-SHA256 verification of `message` against the system's
/// credential — same primitive shape as `attome-s2s::crypto::verify_hmac` (this
/// crate does not invent its own crypto, guidelines §7).
fn verify_hmac(credential: &str, message_parts: &[&[u8]], expected: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(credential.as_bytes()) else {
        return false;
    };
    for part in message_parts {
        mac.update(part);
    }
    mac.verify_slice(expected).is_ok()
}

/// Parses the timestamp header: 1..=12 ASCII digits, nothing else (no sign,
/// no whitespace). The caller signs the header string itself, not this value.
fn parse_timestamp(raw: &str) -> Option<i64> {
    if raw.is_empty()
        || raw.len() > MAX_TIMESTAMP_DIGITS
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    raw.parse().ok()
}

/// Authenticates one inbound webhook call and, for the signed form, records
/// its nonce. **The wire contract (M59 plan §4.1):**
///
/// - `x-integration-timestamp`: Unix seconds, ASCII digits.
/// - `x-integration-signature`: hex HMAC-SHA256, keyed by the system's
///   credential, over `"{timestamp}.{raw body}"` — the timestamp exactly as
///   sent in the header, a literal `.`, then the body bytes.
///
/// Checks, in order: signature header present and hex (401); timestamp
/// well-formed (401) and within ±[`TIMESTAMP_WINDOW_SECS`] of `now_unix`
/// (401); HMAC valid (401); then `SET NX EX` of the signature under
/// `attome-integration:webhook-nonce:{system_id}:{sig_hex}` for
/// [`NONCE_TTL_SECS`] — already present is a replay (409), and a Redis
/// error or timeout is a 503 (`CapabilityUnavailable("redis")`): fail
/// closed, same as the S2S nonce store (D-027). The HMAC is verified before
/// the store is touched, so unauthenticated traffic cannot fill it.
///
/// The signature doubles as the nonce: it binds timestamp and body, so two
/// distinct legitimate deliveries always differ in it, and a provider retry
/// re-signs with a fresh timestamp.
pub async fn admit(
    redis: &Store,
    system_id: Uuid,
    credential: &credential::Credential,
    headers: &HeaderMap,
    body: &[u8],
    now_unix: i64,
) -> Result<Admission, AppError> {
    let sig = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| hex::decode(v).ok())
        .ok_or_else(|| reject(system_id, "bad_signature", AppError::Unauthorized))?;

    let Some(raw_ts) = headers.get(TIMESTAMP_HEADER) else {
        return Err(reject(
            system_id,
            "missing_timestamp",
            AppError::Unauthorized,
        ));
    };

    let raw_ts = raw_ts.to_str().unwrap_or_default();
    let ts = parse_timestamp(raw_ts)
        .ok_or_else(|| reject(system_id, "bad_timestamp", AppError::Unauthorized))?;
    if (now_unix - ts).abs() > TIMESTAMP_WINDOW_SECS {
        return Err(reject(system_id, "stale_timestamp", AppError::Unauthorized));
    }
    if !credential.with_value(|c| verify_hmac(c, &[raw_ts.as_bytes(), b".", body], &sig)) {
        return Err(reject(system_id, "bad_signature", AppError::Unauthorized));
    }

    let key = nonce_key(system_id, &sig);
    let stored = tokio::time::timeout(
        NONCE_TIMEOUT,
        redis.set_nx(
            key.as_str(),
            "1",
            Some(std::time::Duration::from_secs(NONCE_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| {
        tracing::error!(%system_id, "webhook nonce store timed out — rejecting (fail closed)");
        reject(
            system_id,
            "store_unavailable",
            AppError::CapabilityUnavailable("redis"),
        )
    })?
    .map_err(|e| {
        tracing::error!(%system_id, error = %e, "webhook nonce store failed — rejecting (fail closed)");
        reject(
            system_id,
            "store_unavailable",
            AppError::CapabilityUnavailable("redis"),
        )
    })?;
    // `SET … NX` stores the key, or finds it already there (a replay).
    if !stored {
        return Err(reject(
            system_id,
            "replay",
            AppError::Conflict("replay: webhook signature already used"),
        ));
    }
    Ok(Admission { nonce_key: key })
}

/// Releases a signed admission's nonce after a call that wrote **nothing**
/// failed, so the provider's retry of the same signed request is not refused
/// as a replay of a call that never landed. Best-effort and bounded: a
/// failure only means that retry gets a 409 until the TTL lapses.
pub async fn release(redis: &Store, admission: &Admission) {
    let nonce_key = &admission.nonce_key;
    match tokio::time::timeout(NONCE_TIMEOUT, redis.del(nonce_key.as_str())).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "could not release webhook nonce"),
        Err(_) => tracing::warn!("releasing webhook nonce timed out"),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/{system}/webhook",
    tag = "integrations",
    params(
        ("system" = Uuid, Path, description = "integration_system id"),
        ("x-integration-timestamp" = Option<String>, Header, description = "Unix seconds; must be within ±300 s of server time"),
        ("x-integration-signature" = String, Header, description = "Hex HMAC-SHA256 with the system's credential over \"{x-integration-timestamp}.{raw body}\""),
    ),
    responses(
        (status = 202, description = "Accepted", body = WebhookAcceptedResponse),
        (status = 401, description = "Missing or invalid signature, or a missing, malformed or stale timestamp", body = ErrorResponse),
        (status = 404, description = "No such system, or this module is not licensed", body = ErrorResponse),
        (status = 409, description = "Replay: this signed request was already accepted", body = ErrorResponse),
        (status = 422, description = "Body could not be decoded", body = ErrorResponse),
        (status = 503, description = "The replay-protection store is unavailable; retry later", body = ErrorResponse),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
async fn handle_webhook(
    State(state): State<EngineState>,
    Path(system_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<WebhookAcceptedResponse>), AppError> {
    // Same posture as `content_public.rs`'s manual license check: this route
    // is bypass-listed for authn/authz, but every request still passes
    // through `IntegrationModel`'s `ModelRegistry` license-gate middleware
    // before reaching this handler at all — this comment exists only so a
    // reader doesn't go looking for a redundant check here.
    let row = system::load(&state.base.db, system_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != "active" {
        return Err(AppError::NotFound);
    }

    let ring = state.base.secrets.load().integration_credential_key.clone();
    let credential = credential::resolve(&state.base.db, &ring, row.credential_ref.as_deref())
        .await?
        .ok_or_else(|| {
            AppError::Validation(
                "system has no credential configured — cannot verify webhook signatures".into(),
            )
        })?;

    // Phase 1: signature verification is HMAC-only, matching
    // `integration_system.auth_type = "hmac"` — the same shape
    // `attome-s2s`'s inbound machine auth uses. A system configured with
    // another `auth_type` cannot receive inbound webhooks yet (its adapter's
    // `webhook()` never runs); this is a deliberate Phase 1 scope line, not
    // an oversight — REST-style API-key/basic/oauth2 credentials authenticate
    // *outbound* calls this deployment makes, not inbound ones from a third
    // party, and verifying an inbound call against them would mean trusting
    // whatever header shape that third party chose to send.
    //
    // Provider-defined signature formats: no adapter in the catalogue has one
    // yet — `rest` receives this platform's own `x-integration-*` contract,
    // `channel` (web chat) arrives through `omnichannel_public` rather than
    // this route, and mailbox/esign/calendar/file_drop are stubs. The first
    // adapter whose provider signs its own format must map the provider's
    // timestamp/delivery-id fields onto [`admit`]'s window and nonce store —
    // never accept an unbounded replay window (M59 plan §4.1).
    if row.auth_type != "hmac" {
        return Err(AppError::Validation(format!(
            "system auth_type {:?} does not support inbound webhooks in M59 Phase 1 (only \"hmac\")",
            row.auth_type
        )));
    }
    let admission = admit(
        &state.base.redis_coordination,
        system_id,
        &credential,
        &headers,
        &body,
        chrono::Utc::now().timestamp(),
    )
    .await?;

    let mut accepted = 0usize;
    let result = land_events(&state, &row, &credential, &body, &mut accepted).await;
    if result.is_err() && accepted == 0 {
        // Nothing reached the inbox, so the signed request has not been
        // "accepted" in S1's sense — let the provider's retry through.
        release(&state.base.redis_coordination, &admission).await;
    }
    result?;
    record("accepted");

    Ok((
        StatusCode::ACCEPTED,
        Json(WebhookAcceptedResponse { accepted }),
    ))
}

/// Decodes the body through the system's adapter and writes each event into
/// the inbox, counting writes in `accepted` as they commit.
async fn land_events(
    state: &EngineState,
    row: &system::IntegrationSystem,
    credential: &credential::Credential,
    body: &[u8],
    accepted: &mut usize,
) -> Result<(), AppError> {
    let system_id = row.id;
    let Some(kind) = ConnectorKind::parse(&row.kind) else {
        return Err(AppError::internal(format!(
            "integration_system {system_id} has an unrecognized kind {:?}",
            row.kind
        )));
    };
    let events = connector_for(kind)
        .webhook(row, Some(credential), body)
        .await?;

    // D-425 — the per-system service principal, resolved fresh (cached L1/L2,
    // attome-security) rather than trusted from a request-supplied value. This
    // is the identity every write below runs as; it is never the caller (an
    // unauthenticated-by-session external system) and never a bypass/
    // superuser context.
    let principal_id = system::service_principal_id(row)?;
    let principal_ctx = state.base.security.resolve(principal_id).await?;

    // The privilege check `Authorized<RecordScoped<Create>>` would perform
    // for an interactive caller of the generic route — required explicitly
    // here per `entity_crud::create_record_for`'s doc, since this handler is
    // not HTTP-extractor-shaped for the service principal's identity. If the
    // service principal was never granted `integration_event.create`,
    // this is where the webhook is correctly rejected.
    principal_ctx.require(EVENT_ENTITY, "create")?;

    for event in &events {
        let record = serde_json::json!({
            "system_ref": row.id.to_string(),
            "event_type": event.event_type,
            "payload": serde_json::to_string(&event.payload).map_err(AppError::internal)?,
            "processed": false,
        });
        attome_records::entity_crud::create_record_for(
            state,
            &principal_ctx,
            principal_id,
            EVENT_ENTITY,
            record,
        )
        .await?;
        *accepted += 1;
    }
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/integrations/{system}/webhook",
        post(handle_webhook),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(handle_webhook))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const CRED: &str = "top-secret";
    const NOW: i64 = 1_800_000_000;

    fn sign(credential: &str, parts: &[&[u8]]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(credential.as_bytes()).unwrap();
        for p in parts {
            mac.update(p);
        }
        hex::encode(mac.finalize().into_bytes())
    }

    fn headers(ts: Option<&str>, sig: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(ts) = ts {
            h.insert(TIMESTAMP_HEADER, HeaderValue::from_str(ts).unwrap());
        }
        if let Some(sig) = sig {
            h.insert(SIGNATURE_HEADER, HeaderValue::from_str(sig).unwrap());
        }
        h
    }

    fn signed(ts: i64, body: &[u8]) -> HeaderMap {
        let ts = ts.to_string();
        let sig = sign(CRED, &[ts.as_bytes(), b".", body]);
        headers(Some(&ts), Some(&sig))
    }

    /// A pool aimed at a port nothing listens on: every command errors or
    /// times out. A test that expects 401 against it proves the rejection
    /// happened before the store was touched; one that expects 503 proves
    /// the store outage fails closed.
    fn dead_redis() -> Store {
        use fred::interfaces::ClientLike;
        use fred::prelude::{RedisConfig, RedisPool};
        let config = RedisConfig::from_url("redis://127.0.0.1:1").unwrap();
        let pool = RedisPool::new(config, None, None, None, 1).unwrap();
        pool.connect();
        Store::Redis(pool)
    }

    async fn run(h: &HeaderMap, body: &[u8]) -> Result<Admission, AppError> {
        admit(
            &dead_redis(),
            Uuid::nil(),
            &credential::Credential::new(CRED.into()),
            h,
            body,
            NOW,
        )
        .await
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn nonce_ttl_covers_the_timestamp_window_in_both_directions() {
        assert!(NONCE_TTL_SECS >= 2 * TIMESTAMP_WINDOW_SECS);
    }

    #[tokio::test]
    async fn a_tampered_body_is_refused_before_the_nonce_store() {
        let h = signed(NOW, b"original body");
        let err = run(&h, b"tampered body").await.unwrap_err();
        assert!(matches!(err, AppError::Unauthorized), "{err:?}");
    }

    #[tokio::test]
    async fn a_tampered_timestamp_is_refused() {
        let body = b"{}";
        let sig = sign(CRED, &[NOW.to_string().as_bytes(), b".", body]);
        let h = headers(Some(&(NOW + 1).to_string()), Some(&sig));
        let err = run(&h, body).await.unwrap_err();
        assert!(matches!(err, AppError::Unauthorized), "{err:?}");
    }

    #[tokio::test]
    async fn a_wrong_credential_is_refused() {
        let ts = NOW.to_string();
        let sig = sign("other-credential", &[ts.as_bytes(), b".", b"{}"]);
        let err = run(&headers(Some(&ts), Some(&sig)), b"{}")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized), "{err:?}");
    }

    #[tokio::test]
    async fn a_stale_or_future_timestamp_is_refused_even_when_correctly_signed() {
        for ts in [
            NOW - TIMESTAMP_WINDOW_SECS - 1,
            NOW + TIMESTAMP_WINDOW_SECS + 1,
            0,
        ] {
            let err = run(&signed(ts, b"{}"), b"{}").await.unwrap_err();
            assert!(matches!(err, AppError::Unauthorized), "ts={ts}: {err:?}");
        }
    }

    #[tokio::test]
    async fn a_malformed_timestamp_is_refused() {
        for ts in [
            "",
            " 1800000000",
            "+1800000000",
            "18e8",
            "-5",
            "1234567890123",
        ] {
            let sig = sign(CRED, &[ts.as_bytes(), b".", b"{}"]);
            let err = run(&headers(Some(ts), Some(&sig)), b"{}")
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Unauthorized), "ts={ts:?}: {err:?}");
        }
    }

    #[tokio::test]
    async fn a_missing_or_malformed_signature_is_refused() {
        let ts = NOW.to_string();
        for h in [
            headers(Some(&ts), None),
            headers(Some(&ts), Some("not-hex")),
        ] {
            let err = run(&h, b"{}").await.unwrap_err();
            assert!(matches!(err, AppError::Unauthorized), "{err:?}");
        }
    }

    /// A body-only signature (no timestamp, so no replay window) is refused.
    #[tokio::test]
    async fn a_body_only_signature_is_refused() {
        let sig = sign(CRED, &[b"{}"]);
        let err = run(&headers(None, Some(&sig)), b"{}").await.unwrap_err();
        assert!(matches!(err, AppError::Unauthorized), "{err:?}");
    }

    /// Fail closed: a correctly signed, in-window request is refused with a
    /// 503 when the nonce store cannot be reached — never admitted unguarded.
    #[tokio::test]
    async fn a_valid_request_is_refused_when_redis_is_down() {
        let err = run(&signed(NOW, b"{}"), b"{}").await.unwrap_err();
        assert!(
            matches!(err, AppError::CapabilityUnavailable("redis")),
            "{err:?}"
        );
    }

    #[test]
    fn the_nonce_key_is_case_normalised_and_scoped_per_system() {
        let sig = hex::decode("ABCDEF").unwrap();
        assert_eq!(
            nonce_key(Uuid::nil(), &sig),
            format!("attome-integration:webhook-nonce:{}:abcdef", Uuid::nil())
        );
        assert_ne!(
            nonce_key(Uuid::from_u128(1), &sig),
            nonce_key(Uuid::from_u128(2), &sig)
        );
    }
}

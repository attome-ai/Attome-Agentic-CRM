use attome_auth::session::{SessionClaims, TokenType};
use attome_server::{
    middleware::{bypass::is_bypass, client_ip::client_ip},
    state::AppState,
};
use attome_types::AppError;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use uuid::Uuid;

use crate::{claims::S2SClaims, concurrency, crypto, db, rate_limit, telemetry};

const H_CLIENT_ID: &str = "x-s2s-client-id";
const H_KEY_ID: &str = "x-s2s-key-id";
const H_TIMESTAMP: &str = "x-s2s-timestamp";
const H_NONCE: &str = "x-s2s-nonce";
const H_SIGNATURE: &str = "x-s2s-signature";
const H_CORR_ID: &str = "x-correlation-id";
/// S1-T10: the user a granted client acts as; its value is signed.
const H_ACT_AS: &str = "x-attome-act-as";

fn required_header(req: &Request, name: &'static str) -> Result<String, Box<Response>> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            tracing::debug!("s2s: missing required header '{name}'");
            Box::new(AppError::Unauthorized.into_response())
        })
}

fn optional_header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Whether a request from `ip` is allowed for a client whose `allowed_cidrs`
/// column holds `cidrs`. No entries configured means the client isn't
/// IP-restricted. Fail-closed: a restricted client with no resolvable caller
/// IP (e.g. missing `ConnectInfo`) is rejected rather than let through.
fn ip_allowed(cidrs: Option<&[String]>, ip: Option<std::net::IpAddr>) -> bool {
    match cidrs.filter(|c| !c.is_empty()) {
        None => true,
        Some(cidrs) => ip.is_some_and(|ip| {
            cidrs
                .iter()
                .any(|cidr| attome_config::cidr_contains(cidr, ip))
        }),
    }
}

/// S2S HMAC authentication layer.
///
/// Fast-path: no `X-S2S-Client-Id` header → zero-cost pass-through.
/// On success: injects both `S2SClaims` (XRM layer) and `SessionClaims`
/// (so `attome-server/auth.rs` skips re-auth without needing S2S knowledge).
pub async fn s2s_authn(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !req.headers().contains_key(H_CLIENT_ID) {
        return next.run(req).await;
    }

    if is_bypass(req.uri().path()) {
        return next.run(req).await;
    }

    // ── 1. Parse required S2S headers ────────────────────────────────────────
    let client_id = match required_header(&req, H_CLIENT_ID) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let key_public_id = match required_header(&req, H_KEY_ID) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let timestamp_str = match required_header(&req, H_TIMESTAMP) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let nonce = match required_header(&req, H_NONCE) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let signature = match required_header(&req, H_SIGNATURE) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let correlation_id = optional_header(&req, H_CORR_ID);
    let act_as = optional_header(&req, H_ACT_AS);
    let ip_addr = client_ip(&req, &state.config);
    let ip_address = ip_addr.map(|ip| ip.to_string());

    // ── 2. Timestamp window ───────────────────────────────────────────────────
    let timestamp_ms: i64 = match timestamp_str.parse() {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!("s2s: invalid timestamp '{timestamp_str}'");
            return AppError::Unauthorized.into_response();
        }
    };
    // The window and the nonce TTL are one pair of constants in `rate_limit`
    // (B10): the TTL is derived from this window so a nonce can never expire
    // while its timestamp is still acceptable.
    let now_ms = Utc::now().timestamp_millis();
    let window_ms = (rate_limit::TIMESTAMP_WINDOW_SECS as i64) * 1000;

    if (now_ms - timestamp_ms).abs() > window_ms {
        tracing::debug!("s2s: timestamp out of window for client '{client_id}'");
        return AppError::Unauthorized.into_response();
    }

    // ── 3. Load client + key ──────────────────────────────────────────────────
    let record = match db::load_client_and_key(&state.db, &client_id, &key_public_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::debug!("s2s: unknown client '{client_id}' or key '{key_public_id}'");
            return AppError::Unauthorized.into_response();
        }
        Err(e) => return e.into_response(),
    };

    // ── 4. Status, expiry, and IP allowlist ─────────────────────────────────────
    if record.client_status != "active" {
        tracing::debug!(
            "s2s: client '{}' status is '{}'",
            record.client_id,
            record.client_status
        );
        return AppError::Unauthorized.into_response();
    }
    if record.key_status != "active" {
        tracing::debug!(
            "s2s: key slot '{}' status is '{}'",
            record.key_slot,
            record.key_status
        );
        return AppError::Unauthorized.into_response();
    }
    if let Some(exp) = record.key_expires_at
        && exp < Utc::now()
    {
        tracing::debug!("s2s: key for client '{}' has expired", record.client_id);
        return AppError::Unauthorized.into_response();
    }
    if let Some(last_used) = record.client_last_used {
        let days_idle = (Utc::now() - last_used).num_days();
        if days_idle >= record.auto_disable_days as i64 {
            tracing::warn!(
                "s2s: client '{}' idle for {days_idle} days (limit {}), rejecting",
                record.client_id,
                record.auto_disable_days,
            );
            return AppError::Unauthorized.into_response();
        }
    }

    if !ip_allowed(record.allowed_cidrs.as_deref(), ip_addr) {
        tracing::warn!(
            "s2s: client '{}' request from disallowed IP '{}'",
            record.client_id,
            ip_address.as_deref().unwrap_or("unknown"),
        );
        return AppError::Unauthorized.into_response();
    }

    // B9: the service user is the principal every downstream authz check and
    // audit row is attributed to. A client row with no `service_user_ref`
    // (pre-T1-8 rows, before the admin API required it) has no principal to
    // act as, so it is rejected here like any other unusable client state
    // (suspended, expired, idle) — never authenticated as `Uuid::nil`, which
    // is not a user and made the request's identity a fabrication. The
    // repair path is `PATCH /api/v1/admin/s2s/clients/{id}` with a
    // `service_user_ref`.
    let service_user_id = match record.service_user_ref {
        Some(id) => id,
        None => {
            tracing::warn!(
                "s2s: client '{}' has no service_user_ref, rejecting — set one via \
                 PATCH /api/v1/admin/s2s/clients/{}",
                record.client_id,
                record.client_db_id,
            );
            return AppError::Unauthorized.into_response();
        }
    };

    // ── 5. Nonce uniqueness (replay protection) + rate limit ──────────────────
    // Combined into one pipelined Redis round-trip (P1.11d) — checked here,
    // before body-buffering/HMAC verification, so a rate-limited or replayed
    // request never pays for that work. This also closes a prior gap where
    // only successfully-signed requests were rate-limited: an attacker
    // spamming forged signatures on a valid client_id/key_id now hits the
    // same per-client quota instead of bypassing it entirely.
    match rate_limit::check_with_nonce(
        &state.redis_coordination,
        &record.client_id,
        &nonce,
        record.rate_limit_rpm,
    )
    .await
    {
        Ok(()) => {}
        Err(e @ AppError::Conflict(_)) => {
            tracing::warn!(
                "s2s: replay nonce detected for client '{}'",
                record.client_id
            );
            return e.into_response();
        }
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    axum::http::header::RETRY_AFTER,
                    HeaderValue::from_static("60"),
                )],
                "rate limit exceeded",
            )
                .into_response();
        }
        Err(e) => return e.into_response(),
    }

    // ── 5b. Concurrency cap ───────────────────────────────────────────────────
    // `s2s_client.max_concurrent` bounds how many of this client's
    // requests may be in flight at once, enforced across every app node via
    // Redis. Acquired after the rate-limit/replay check (so a throttled
    // request never consumes a concurrency slot) and released once the
    // downstream handler returns.
    let concurrency_guard = match concurrency::acquire(
        &state.redis_coordination,
        &record.client_id,
        record.max_concurrent,
    )
    .await
    {
        Ok(guard) => guard,
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }) => {
            tracing::warn!(
                "s2s: client '{}' exceeded max_concurrent={}",
                record.client_id,
                record.max_concurrent
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(
                    axum::http::header::RETRY_AFTER,
                    HeaderValue::from_static("1"),
                )],
                "too many concurrent requests",
            )
                .into_response();
        }
        Err(e) => return e.into_response(),
    };

    // ── 6. Buffer body + SHA-256 ────────────────────────────────────────────────
    let method = req.method().as_str().to_owned();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path())
        .to_owned();
    let max_bytes = record.max_payload_bytes as usize;

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, max_bytes).await {
        Ok(b) => b,
        Err(_) => {
            concurrency_guard.release().await;
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds client limit",
            )
                .into_response();
        }
    };
    let body_sha256 = crypto::sha256_hex(&body_bytes);

    // ── 7. HMAC verification ──────────────────────────────────────────────────
    let secrets = state.secrets.load();
    let raw_secret = match crypto::decrypt_key_secret(
        &secrets.s2s_key_encryption_key,
        record.key_db_id,
        &record.secret_encrypted,
    ) {
        Ok(s) => s,
        Err(e) => {
            concurrency_guard.release().await;
            return e.into_response();
        }
    };

    let canonical = crypto::canonical_message_with_act_as(
        &method,
        &path_and_query,
        &body_sha256,
        &timestamp_str,
        &nonce,
        act_as.as_deref(),
    );

    if !crypto::verify_hmac(&raw_secret, &canonical, &signature) {
        tracing::warn!("s2s: HMAC mismatch for client '{}'", record.client_id);
        concurrency_guard.release().await;
        return AppError::Unauthorized.into_response();
    }

    // ── 7b. Entity ceiling (D-766) ────────────────────────────────────────────
    // A client with `s2s_permission` rows may touch only those entities,
    // with only the verbs they grant — on top of, never instead of, its
    // service user's roles. A client with no rows keeps the service user's
    // roles as its only bound (the pre-D-766 behaviour); boot warns about it.
    let ceiling = match db::load_permissions(&state.db, record.client_db_id).await {
        Ok(rows) => entity_ceiling(&rows),
        Err(e) => {
            tracing::error!(
                "s2s: loading permissions for client '{}' failed: {e}",
                record.client_id
            );
            concurrency_guard.release().await;
            return AppError::Internal("s2s permission lookup failed".into()).into_response();
        }
    };
    // An admin service user cannot be capped: admin implies every entity
    // privilege, and deferred work (jobs, report runs) re-resolves the user
    // by id and would be admin again. Refused as a misconfiguration.
    if ceiling.is_some() {
        match state.security.resolve(service_user_id).await {
            Ok(ctx) if ctx.is_admin => {
                tracing::warn!(
                    "s2s: client '{}' has permission rows but its service user is an admin — \
                     refused (D-766); point it at a non-admin service user",
                    record.client_id
                );
                concurrency_guard.release().await;
                return AppError::Forbidden.into_response();
            }
            Ok(_) => {}
            Err(e) => {
                concurrency_guard.release().await;
                return e.into_response();
            }
        }
    }

    // ── 7c. Act as a user (S1-T10) ────────────────────────────────────────────
    // Only for a client granted can_act_as_user; the header's value was part
    // of the signed message above. The user must be an active, ordinary
    // account; under an entity ceiling it may not be an admin either (the
    // same rule as the service user, D-766).
    let acted_as_user_id = match act_as.as_deref() {
        None => None,
        Some(raw) => {
            match db::client_can_act_as_user(&state.db, record.client_db_id).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        "s2s: client '{}' sent x-attome-act-as without can_act_as_user",
                        record.client_id
                    );
                    concurrency_guard.release().await;
                    return AppError::Forbidden.into_response();
                }
                Err(e) => {
                    concurrency_guard.release().await;
                    return e.into_response();
                }
            }
            let Ok(user_id) = Uuid::parse_str(raw.trim()) else {
                concurrency_guard.release().await;
                return AppError::Unauthorized.into_response();
            };
            match db::act_as_user_is_usable(&state.db, user_id).await {
                Ok(true) => {}
                Ok(false) => {
                    concurrency_guard.release().await;
                    return AppError::Forbidden.into_response();
                }
                Err(e) => {
                    concurrency_guard.release().await;
                    return e.into_response();
                }
            }
            if ceiling.is_some() {
                match state.security.resolve(user_id).await {
                    Ok(ctx) if ctx.is_admin => {
                        concurrency_guard.release().await;
                        return AppError::Forbidden.into_response();
                    }
                    Ok(_) => {}
                    Err(e) => {
                        concurrency_guard.release().await;
                        return e.into_response();
                    }
                }
            }
            Some(user_id)
        }
    };
    let principal = acted_as_user_id.unwrap_or(service_user_id);

    // ── 8. Inject claims ──────────────────────────────────────────────────────
    let s2s_claims = S2SClaims {
        client_db_id: record.client_db_id,
        client_id: record.client_id.clone(),
        client_name: record.client_name.clone(),
        key_db_id: record.key_db_id,
        key_slot: record.key_slot.clone(),
        service_user_id,
        correlation_id: correlation_id.clone(),
        acted_as_user_id,
    };

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(s2s_claims);
    // S8-T1: the client whose pinned API version applies.
    req.extensions_mut()
        .insert(attome_server::middleware::api_version::S2sClientRef(
            record.client_db_id,
        ));
    if let Some(ceiling) = ceiling {
        req.extensions_mut().insert(ceiling);
    }

    // Inject SessionClaims so authn in attome-server skips re-auth. `sub` is
    // the client's service user, checked non-NULL in step 4 above.
    let now = Utc::now().timestamp();
    req.extensions_mut().insert(SessionClaims {
        sub: principal,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        // authn's epoch::check never runs for this request (it short-circuits
        // whenever SessionClaims is already present — this insert IS that
        // case) — auth_epoch (D-113/D-129) is a session_token-cookie concept,
        // irrelevant to S2S machine auth's own HMAC-based revocation.
        epoch: 0,
        // Not a real JWT (never encoded/decoded, just fabricated in-process
        // to satisfy downstream extractors) — iss/aud are irrelevant since
        // `jwt::validate_token`'s checks never run against this value.
        iss: state.config.auth.jwt_issuer.clone(),
        aud: state.config.jwt_audience().to_string(),
        typ: TokenType::Session,
    });

    // ── 9. Key last-used touch (P-job-system-hardening (b), was P1.4's
    // durable TouchS2sKey queue job) ─────────────────────────────────────────
    // Coalesced into a Redis hash and periodically bulk-flushed
    // (`attome_s2s::telemetry`) rather than a Postgres queue row per request —
    // this value doesn't need replay-safe delivery, only "eventually
    // accurate to within one flush interval" (see that module's doc comment
    // for the accepted tradeoff). Best-effort, same as before.
    {
        if let Err(e) = telemetry::record_touch(
            &state.redis_coordination,
            record.client_db_id,
            record.key_db_id,
            Utc::now(),
        )
        .await
        {
            tracing::warn!("s2s: failed to record key last_used touch: {e}");
        }
    }

    let start = std::time::Instant::now();
    let response = next.run(req).await;
    concurrency_guard.release().await;
    let elapsed_ms = start.elapsed().as_millis() as i32;
    let status_code = response.status().as_u16() as i16;

    let mut response = response;
    if let Some(ref corr) = correlation_id
        && let Ok(val) = HeaderValue::from_str(corr)
    {
        response.headers_mut().insert(H_CORR_ID, val);
    }

    // MAJOR (P-job-system-hardening (b), was P1.4's durable S2sAccessLog
    // queue job): security/audit data, so this keeps at-least-once delivery
    // via a Redis Stream + consumer group (`attome_s2s::telemetry`) instead of
    // the apalis queue -- an entry stays pending (and later reclaimable)
    // until its row actually commits to s2s_access_log, so a crash
    // mid-batch re-delivers rather than silently drops. Awaited, not
    // spawned, same reasoning as before: a tokio::spawn here could drop the
    // XADD itself if the process dies first.
    if state.config.s2s.access_log_enabled {
        let entry = crate::access_log::LogEntry {
            client_ref: Some(record.client_db_id),
            client_name: Some(record.client_name.clone()),
            method: method.clone(),
            path: path_and_query.clone(),
            status_code: Some(status_code),
            response_time_ms: Some(elapsed_ms),
            bytes_received: None,
            bytes_sent: None,
            correlation_id: correlation_id.clone(),
            ip_address: ip_address.clone(),
            nonce: Some(nonce.clone()),
            error_code: None,
            acted_as_user_id,
            created_at: Utc::now(),
        };
        // Internal memory-bound safety cap on the access-log stream, never
        // varied per-deployment — not a config knob.
        const STREAM_MAXLEN: u64 = 100_000;
        if let Err(e) =
            telemetry::record_access_log(&state.redis_coordination, &entry, STREAM_MAXLEN).await
        {
            tracing::warn!("s2s: failed to record access log entry: {e}");
        }
    }

    response
}

/// D-766: the client's `s2s_permission` rows as an [`EntityCeiling`], or
/// `None` when it has none. `can_export` is not a privilege verb; the export
/// route checks it itself (`db::client_can_export`, D-408).
///
/// [`EntityCeiling`]: attome_server::security::EntityCeiling
fn entity_ceiling(rows: &[db::PermissionRow]) -> Option<attome_server::security::EntityCeiling> {
    if rows.is_empty() {
        return None;
    }
    let keys = rows.iter().flat_map(|r| {
        [
            ("read", r.can_read),
            ("create", r.can_create),
            ("update", r.can_update),
            ("delete", r.can_delete),
            ("bulk", r.can_bulk),
        ]
        .into_iter()
        .filter(|(_, granted)| *granted)
        .map(move |(verb, _)| format!("{}.{verb}", r.entity_name))
    });
    Some(attome_server::security::EntityCeiling::new(keys))
}

#[cfg(test)]
mod ceiling_tests {
    use super::entity_ceiling;
    use crate::db::PermissionRow;

    fn row(entity: &str, read: bool, delete: bool, bulk: bool) -> PermissionRow {
        PermissionRow {
            entity_name: entity.into(),
            can_read: read,
            can_create: false,
            can_update: false,
            can_delete: delete,
            can_export: true,
            can_bulk: bulk,
        }
    }

    #[test]
    fn a_client_without_rows_has_no_ceiling() {
        assert!(entity_ceiling(&[]).is_none());
    }

    #[test]
    fn rows_become_exactly_their_granted_verbs() {
        let c = entity_ceiling(&[
            row("account", true, false, true),
            row("contact", false, false, false),
        ])
        .expect("rows present");
        assert!(c.allows("account.read"));
        assert!(c.allows("account.bulk"));
        assert!(!c.allows("account.delete"));
        assert!(!c.allows("account.update"));
        assert!(
            !c.allows("contact.read"),
            "a row with every flag off grants nothing"
        );
        assert!(
            !c.allows("lead.read"),
            "an entity with no row is outside the ceiling"
        );
        assert!(
            c.allows("sidebar.manage"),
            "non-entity keys are not the ceiling's concern"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::ip_allowed;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_cidrs_configured_allows_any_ip() {
        assert!(ip_allowed(None, Some(ip("203.0.113.9"))));
        assert!(ip_allowed(Some(&[]), Some(ip("203.0.113.9"))));
    }

    #[test]
    fn ip_inside_an_allowed_cidr_is_allowed() {
        let cidrs = vec!["10.20.0.0/16".to_string(), "192.168.1.0/24".to_string()];
        assert!(ip_allowed(Some(&cidrs), Some(ip("10.20.30.40"))));
        assert!(ip_allowed(Some(&cidrs), Some(ip("192.168.1.5"))));
    }

    #[test]
    fn ip_outside_every_allowed_cidr_is_rejected() {
        let cidrs = vec!["10.20.0.0/16".to_string()];
        assert!(!ip_allowed(Some(&cidrs), Some(ip("203.0.113.9"))));
    }

    #[test]
    fn restricted_client_with_unresolvable_ip_fails_closed() {
        let cidrs = vec!["10.20.0.0/16".to_string()];
        assert!(!ip_allowed(Some(&cidrs), None));
    }

    #[test]
    fn malformed_cidr_entry_never_matches() {
        let cidrs = vec!["not-a-cidr".to_string()];
        assert!(!ip_allowed(Some(&cidrs), Some(ip("10.20.30.40"))));
    }
}

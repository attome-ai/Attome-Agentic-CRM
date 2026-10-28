//! TOTP MFA (P2.8 step 7, D-069). Backs the self-service enroll/confirm/
//! disable/regenerate-recovery-codes endpoints and the login-time verify/
//! recovery endpoints. Mirrors `reset.rs`/`verification.rs`'s split: this
//! module only ever proves possession of a second factor — it never decides
//! session policy (that's `accounts::login`) or touches `SecurityContext`.
//!
//! Secret-at-rest: versioned AES-256-GCM envelope (`crate::envelope`), keyed
//! by `config.auth.mfa_encryption_key` — a dedicated `KeyRing`, never S2S's
//! `key_encryption_key` (separate trust domains, D-069). P-key-rotation-and-jwt
//! (a): this used to be a hand-rolled `nonce || ciphertext` blob with no key
//! identity; see `crate::envelope`'s doc for why that made rotation destructive.
//!
//! Pending-MFA token: a short-lived (~5min) HS256 JWT, structurally distinct
//! from `SessionClaims` via its `typ` claim (`MfaPendingLogin`/
//! `MfaPendingEnroll`) so it can never be confused with or substituted for a
//! real session token by the authn middleware, which only ever parses
//! `SessionClaims` and rejects the wrong `typ` (P-key-rotation-and-jwt (c),
//! audit finding #21 — previously only claims *shape* distinguished the two).
//! `verify_pending_token` itself stays a pure, stateless signature/claims
//! check (D-069) — same trust level as a session token.
//!
//! P-mfa-challenge-hardening: `PendingClaims` carries a `jti` backing a
//! single-use Redis challenge marker (`mfa:pending:{jti}`, coordination pool,
//! `SET NX EX` at issuance) — distinct from `SessionClaims`'s denylist-keyed
//! `jti`, this one is consumed exactly once and enforces a per-challenge
//! attempt ceiling (`auth.mfa_challenge_max_attempts`). This supersedes only
//! D-069's "no Redis/DB row backs it" line (D-149 in
//! `document/base/auth/plans/attome-auth-plan.md` §5.1) — the pending
//! token itself is still a self-contained JWT; the marker is a separate gate
//! its *consumers* (`complete_pending_login` etc.) apply after
//! `verify_pending_token` succeeds, not part of token verification.

use attome_cache::Store;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::Utc;
use fred::interfaces::LuaInterface;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;

use crate::apikey_hash::{
    PepperRing, VerifyOutcome, dummy_peppered_hash, hash_peppered_secret, verify_peppered_secret,
};
use crate::jwt::{decode_claims, encode_claims};
use crate::session::TokenType;

const TOTP_DIGITS: u8 = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP_SECS: u64 = 30;
const RECOVERY_CODE_COUNT: usize = 10;
const PENDING_TOKEN_TTL_SECS: i64 = 300;

/// Guidelines §10/P1.15 §4(d): the challenge marker is a security control —
/// fail closed and fast, never hang on a slow/unreachable Redis. Same budget
/// as `rate_limit.rs`'s `OP_TIMEOUT`/`xrm-s2s`'s nonce guard.
const MFA_MARKER_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// P-mfa-challenge-hardening: atomic one-time-use + attempt-ceiling primitive
/// for the `mfa:pending:{jti}` marker, the same class of primitive as
/// `rate_limit.rs`'s `RATE_LIMIT_SCRIPT` — a plain GET-then-DEL is not enough
/// here because two concurrent wrong-code submissions against the same
/// marker must not each independently read "N attempts left" and both
/// proceed (the exact undercounting race that rate limiter had before its own
/// atomicity fix).
///
/// `KEYS[1]` = marker key, `ARGV[1]` = `"consume"` | `"fail"`, `ARGV[2]` = max
/// attempts. Returns `1` if the challenge is still alive (successfully
/// consumed, or a failed attempt was recorded without hitting the ceiling),
/// `0` if the marker was already gone — previously consumed, expired, or the
/// ceiling was just hit by this very call. Callers never need to distinguish
/// "already gone" from "ceiling hit just now": both must produce the same
/// generic `Unauthorized`, per the anti-enumeration discipline `accounts::
/// login`/`reset::request` already apply elsewhere in this codebase.
const MFA_CHALLENGE_STEP_SCRIPT: &str = r#"
local v = redis.call('GET', KEYS[1])
if v == false then
  return 0
end
if ARGV[1] == 'consume' then
  redis.call('DEL', KEYS[1])
  return 1
end
local n = redis.call('INCR', KEYS[1])
if n >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return 0
end
return 1
"#;

fn challenge_marker_key(jti: Uuid) -> String {
    format!("mfa:pending:{jti}")
}

/// Runs one atomic step of [`MFA_CHALLENGE_STEP_SCRIPT`] against the marker
/// for `jti`. Fails closed (`AppError::Unauthorized`, not `internal`) on a
/// Redis timeout/error — this runs on the verify path, so an outage must
/// reject the attempt exactly like a bad code, never fall through as if no
/// marker existed (D-027).
async fn challenge_step(
    redis: &Store,
    jti: Uuid,
    consume: bool,
    max_attempts: u32,
) -> Result<bool, AppError> {
    let key = challenge_marker_key(jti);
    // The in-process form of MFA_CHALLENGE_STEP_SCRIPT, one locked step.
    let redis = match redis {
        Store::Redis(pool) => pool,
        Store::Memory(memory) => {
            let alive = memory
                .transaction(|ks| -> Result<bool, attome_cache::memory::WrongType> {
                    if ks.get_str(&key)?.is_none() {
                        return Ok(false);
                    }
                    if consume {
                        ks.del(&key);
                        return Ok(true);
                    }
                    let attempts = ks.incr_by(&key, 1)?;
                    if attempts >= i64::from(max_attempts) {
                        ks.del(&key);
                        return Ok(false);
                    }
                    Ok(true)
                })
                .map_err(|_| AppError::Unauthorized)?;
            return Ok(alive);
        }
    };
    let arg = if consume { "consume" } else { "fail" };
    let alive: i64 = tokio::time::timeout(
        MFA_MARKER_TIMEOUT,
        redis.eval(
            MFA_CHALLENGE_STEP_SCRIPT,
            vec![key],
            vec![arg.to_string(), max_attempts.to_string()],
        ),
    )
    .await
    .map_err(|_| AppError::Unauthorized)?
    .map_err(|_| AppError::Unauthorized)?;
    Ok(alive == 1)
}

/// BAU-28 (F18): refuses a pending token whose challenge marker is gone
/// (consumed, exhausted or expired) **before** any verifier runs, so a dead
/// challenge costs no KDF permit and a correct TOTP code sent against it does
/// not advance `last_accepted_totp_step`. Fails closed like
/// [`challenge_step`]; the atomic consume-or-fail step still runs after the
/// verifier and remains the single-use authority.
async fn require_live_challenge(redis: &Store, jti: Uuid) -> Result<(), AppError> {
    let alive = tokio::time::timeout(MFA_MARKER_TIMEOUT, redis.exists(&challenge_marker_key(jti)))
        .await
        .map_err(|_| AppError::Unauthorized)?
        .map_err(|_| AppError::Unauthorized)?;
    if alive == 0 {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

/// Wraps a login/enrollment-confirm attempt with the marker's consume-or-fail
/// bookkeeping: a successful `outcome` consumes the challenge (rejecting it
/// if the marker was already gone — single-use, even for a byte-identical
/// valid code); a failed `outcome` records one attempt against the ceiling
/// and returns the original error unchanged (unless the marker check itself
/// fails closed, which surfaces as the same `Unauthorized`).
async fn consume_or_record_failure<T>(
    redis: &Store,
    jti: Uuid,
    max_attempts: u32,
    outcome: Result<T, AppError>,
) -> Result<T, AppError> {
    match outcome {
        Ok(value) => {
            if challenge_step(redis, jti, true, max_attempts).await? {
                Ok(value)
            } else {
                Err(AppError::Unauthorized)
            }
        }
        Err(err) => {
            challenge_step(redis, jti, false, max_attempts).await?;
            Err(err)
        }
    }
}

const FIELD_NAME: &str = "auth.mfa_encryption_key";

// ── Secret-at-rest crypto ──────────────────────────────────────────────────────

fn encrypt_secret(mfa_ring: &KeyRing, plaintext: &str) -> Result<String, AppError> {
    crate::envelope::encrypt(FIELD_NAME, mfa_ring, plaintext)
}

fn decrypt_secret(mfa_ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    crate::envelope::decrypt(FIELD_NAME, mfa_ring, encoded)
        .map(attome_types::secret::SecretString::into_exposed)
}

fn totp_for(secret_base32: &str, account_name: &str) -> Result<Totp, AppError> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|_| AppError::internal("stored mfa secret is not valid base32"))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(TOTP_DIGITS)
        .with_skew(u16::from(TOTP_SKEW))
        .with_step_duration(TOTP_STEP_SECS)
        .with_secret(secret)
        .with_issuer(Some("Attome"))
        .with_account_name(account_name.to_string())
        .build()
        .map_err(AppError::internal)
}

/// Constant-time equality for TOTP codes — plain fixed-width ASCII-digit
/// strings, so a manual XOR-accumulate avoids leaking a timing side channel
/// on how many leading digits match without pulling in a `subtle` dependency
/// (same reasoning as apikey_hash.rs's `Mac::verify_slice` comment).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Returns the newest RFC 6238 time-step whose code matches within the
/// configured clock-skew window. Choosing the newest match prevents a client
/// clock that is one step ahead from later being accepted on the server's
/// current step.
fn matching_totp_step(totp: &Totp, code: &str, now_secs: u64) -> Option<i64> {
    let current_step = now_secs / TOTP_STEP_SECS;
    let first_step = current_step.saturating_sub(u64::from(TOTP_SKEW));
    let last_step = current_step.saturating_add(u64::from(TOTP_SKEW));

    (first_step..=last_step).rev().find_map(|step| {
        ct_eq(&totp.generate(step * TOTP_STEP_SECS).to_string(), code)
            .then(|| i64::try_from(step).ok())
            .flatten()
    })
}

// ── Pending-MFA token (issued by accounts::login, consumed by mfa::verify*) ───

/// `pub(crate)` — `jwt.rs`'s own tests construct this directly to prove
/// `validate_token` rejects a pending token presented as a session token
/// (see `jwt::tests::validate_rejects_a_pending_typ_presented_as_a_session_token`).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PendingClaims {
    pub(crate) sub: Uuid,
    pub(crate) typ: TokenType,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    /// Required since BAU-12c (no transition window any more).
    pub(crate) iss: String,
    pub(crate) aud: String,
    /// P-mfa-challenge-hardening: identifies this challenge's single-use
    /// Redis marker (`mfa:pending:{jti}`). Hard-required: this token's
    /// 5-minute TTL means no in-flight pending token can outlive a rolling
    /// deploy window in a way that matters.
    pub(crate) jti: Uuid,
}

/// Mints a pending-MFA JWT. Pure/sync and Redis-free by design — the
/// companion single-use challenge marker is a separate concern the caller
/// (`start_challenge`) writes once it has the `jti` this returns, keeping
/// this function testable without a live Redis (mirrors `PendingClaims`
/// roundtrip unit tests below).
fn issue_pending_token(
    user_id: Uuid,
    typ: TokenType,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<(String, Uuid), AppError> {
    debug_assert!(matches!(
        typ,
        TokenType::MfaPendingLogin | TokenType::MfaPendingEnroll
    ));
    let now = Utc::now().timestamp();
    let jti = Uuid::now_v7();
    let claims = PendingClaims {
        sub: user_id,
        typ,
        iat: now,
        exp: now + PENDING_TOKEN_TTL_SECS,
        iss: issuer.to_string(),
        aud: audience.to_string(),
        jti,
    };
    let token = encode_claims(&claims, jwt_ring)?;
    Ok((token, jti))
}

/// Mints a pending-MFA JWT (`issue_pending_token`) and seeds its single-use
/// Redis challenge marker in the same call — both must succeed or the whole
/// issuance fails (never hand back a JWT with no matching marker). The
/// marker starts at attempt-count `"0"` (string-encoded so the Lua script's
/// `INCR` works directly on it), TTL'd to the same `PENDING_TOKEN_TTL_SECS`
/// as the JWT's own `exp`, `SET NX` so an id collision (astronomically
/// unlikely, `Uuid::now_v7`) is a hard error rather than silently reusing a
/// live marker. A marker-write failure aborts the login attempt as
/// `AppError::internal` (retried by the client) rather than a silently
/// degraded pending token that can never satisfy the marker check below.
pub async fn start_challenge(
    redis: &Store,
    user_id: Uuid,
    typ: TokenType,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<String, AppError> {
    let (token, jti) = issue_pending_token(user_id, typ, jwt_ring, issuer, audience)?;
    tokio::time::timeout(
        MFA_MARKER_TIMEOUT,
        redis.set_nx(
            &challenge_marker_key(jti),
            "0",
            Some(Duration::from_secs(PENDING_TOKEN_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("mfa challenge marker write timed out"))??;
    Ok(token)
}

/// Validates a pending token and checks it carries the expected `typ` — an
/// enroll-purpose token must never be usable to satisfy a login-verify
/// challenge or vice versa, even though both are signed under the same ring.
/// `iss`/`aud` must match exactly, as for session tokens.
/// The account a pending MFA token names, **only when the token verifies**
/// (signature, type, issuer, audience), else `None`. For recording a failed
/// second-factor attempt against the account without trusting an unverified
/// `sub`.
pub fn verified_pending_subject(
    token: &str,
    expected: TokenType,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Option<Uuid> {
    verify_pending_token(token, expected, jwt_ring, issuer, audience)
        .ok()
        .map(|(sub, _jti)| sub)
}

fn verify_pending_token(
    token: &str,
    expected: TokenType,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<(Uuid, Uuid), AppError> {
    let claims: PendingClaims =
        decode_claims(token, jwt_ring).map_err(|_| AppError::Unauthorized)?;
    if claims.typ != expected {
        return Err(AppError::Unauthorized);
    }
    if claims.iss != issuer || claims.aud != audience {
        return Err(AppError::Unauthorized);
    }
    Ok((claims.sub, claims.jti))
}

/// Q5-T3: redeems an `MfaEnrollmentRequired` pending token without a code,
/// for a person putting enrolment off within their grace period: the token
/// must verify as an enrolment token, its challenge must be live, and the
/// challenge is consumed, so the token works once. Answers the person.
pub async fn redeem_pending_enroll(
    redis: &Store,
    pending_token: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<Uuid, AppError> {
    let (user_id, jti) = verify_pending_token(
        pending_token,
        TokenType::MfaPendingEnroll,
        jwt_ring,
        issuer,
        audience,
    )?;
    require_live_challenge(redis, jti).await?;
    if !challenge_step(redis, jti, true, 1).await? {
        return Err(AppError::Unauthorized);
    }
    Ok(user_id)
}

// ── Enrollment status ───────────────────────────────────────────────────────

/// Whether `user_id` has a confirmed (active) TOTP enrollment. Deliberately
/// ignores pending/unconfirmed rows — an in-progress enrollment is not yet a
/// usable second factor, so `accounts::login` must treat that account as
/// unenrolled.
pub async fn is_enrolled(db: &DbPool, user_id: Uuid) -> Result<bool, AppError> {
    let confirmed: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM user_mfa
         WHERE user_ref = $1 AND is_deleted = false AND confirmed_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(confirmed.unwrap_or(false))
}

// ── Rewrap (P-key-rotation-and-jwt (b)) ────────────────────────────────────────

/// One batch's outcome from [`rewrap_secrets`] — `scanned < batch_size` (or
/// `last_id` unchanged/`None`) tells the caller it has reached the end of
/// the table, since a plain `id > cursor ORDER BY id LIMIT n` scan advances
/// past every row it looks at regardless of whether that row needed
/// rewrapping or was already on the active key.
#[derive(Debug)]
pub struct RewrapProgress {
    pub scanned: u64,
    pub rewrapped: u64,
    pub last_id: Option<Uuid>,
}

/// Re-encrypts every `user_mfa.secret_encrypted` row (with `id >
/// after_id`) not already under `ring`'s active key, in one bounded batch —
/// the background convergence half of key rotation: write-under-active/
/// read-under-whatever-key-it-names (`decrypt_secret`) is already safe the
/// instant a new active key is configured; this job just shortens the
/// window during which an old key must stay in the ring by rewriting rows
/// onto the new one. `row_version` guards a row changed mid-batch (by a live
/// enroll/disable/regenerate happening concurrently) — such a row is simply
/// skipped for a later pass, never clobbered. Idempotent: an
/// already-active-key row costs one cheap `stored_key_id` check and nothing
/// else. Callers loop (`after_id = result.last_id`) until `scanned == 0`.
pub async fn rewrap_secrets(
    db: &DbPool,
    ring: &KeyRing,
    after_id: Option<Uuid>,
    batch_size: i64,
) -> Result<RewrapProgress, AppError> {
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT id, secret_encrypted, row_version FROM user_mfa
         WHERE is_deleted = false AND id > $1
         ORDER BY id
         LIMIT $2",
    )
    .bind(after_id.unwrap_or(Uuid::nil()))
    .bind(batch_size)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let scanned = rows.len() as u64;
    let mut rewrapped = 0u64;
    let mut last_id = after_id;
    for (id, secret_encrypted, row_version) in rows {
        last_id = Some(id);
        if crate::envelope::stored_key_id(&secret_encrypted).as_deref()
            == Some(ring.active_key_id.as_str())
        {
            continue; // already under the active key
        }
        let plaintext = decrypt_secret(ring, &secret_encrypted)?;
        let fresh = encrypt_secret(ring, &plaintext)?;

        let updated = sqlx::query(
            "UPDATE user_mfa
             SET secret_encrypted = $1, updated_at = NOW(), row_version = row_version + 1
             WHERE id = $2 AND row_version = $3",
        )
        .bind(&fresh)
        .bind(id)
        .bind(row_version)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if updated > 0 {
            rewrapped += 1;
        }
    }
    Ok(RewrapProgress {
        scanned,
        rewrapped,
        last_id,
    })
}

// ── Enrollment (self-service; also driven by a pending Enroll token) ──────────

pub struct EnrollResponse {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

impl std::fmt::Debug for EnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollResponse").finish_non_exhaustive()
    }
}

/// Starts (or restarts) enrollment: generates a fresh secret, upserts the
/// pending `user_mfa` row (replacing any prior *unconfirmed* attempt —
/// a confirmed enrollment must go through `disable` first, guarded by the
/// partial unique index on `user_ref WHERE is_deleted = false`), and returns
/// the secret + otpauth:// URI for the caller to render as a QR code. Looks
/// up the account's email itself (for the otpauth `account_name` label) so
/// callers never need raw `user_account` access of their own.
pub async fn enroll(
    db: &DbPool,
    mfa_ring: &KeyRing,
    user_id: Uuid,
) -> Result<EnrollResponse, AppError> {
    enroll_with(db, mfa_ring, user_id, &attome_db::NoHook).await
}

/// [`enroll`], plus a [`attome_db::BeforeCommit`] hook that runs in the pending
/// row's transaction with the account id (D-062).
pub async fn enroll_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    user_id: Uuid,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<EnrollResponse, AppError> {
    let already_confirmed = is_enrolled(db, user_id).await?;
    if already_confirmed {
        return Err(AppError::Conflict(
            "mfa already enrolled — disable it before re-enrolling",
        ));
    }

    let account_email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;

    let secret_base32 = Secret::generate().to_base32();
    let secret_encrypted = encrypt_secret(mfa_ring, &secret_base32)?;
    let totp = totp_for(&secret_base32, &account_email)?;

    let mut tx = attome_db::tx::begin(db).await?;
    // Clears out any stale unconfirmed row before inserting — the partial
    // unique index only allows one non-deleted row per user, and a prior
    // abandoned enrollment attempt must not block a new one.
    sqlx::query("DELETE FROM user_mfa WHERE user_ref = $1 AND confirmed_at IS NULL")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("INSERT INTO user_mfa (user_ref, secret_encrypted) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&secret_encrypted)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(EnrollResponse {
        secret_base32,
        otpauth_uri: totp.to_url().map_err(AppError::internal)?,
    })
}

/// Confirms a pending enrollment with a TOTP code, marks it active, and
/// issues the one-time-viewable recovery-code batch. `rows_affected` guards
/// against confirming twice or confirming nothing (no pending row).
pub async fn confirm_enrollment(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
) -> Result<Vec<String>, AppError> {
    confirm_enrollment_with(db, mfa_ring, pepper, user_id, code, &attome_db::NoHook).await
}

/// [`confirm_enrollment`], plus a [`attome_db::BeforeCommit`] hook that runs in
/// the confirmation's transaction with the account id (D-062). Never handed
/// the recovery codes.
///
/// The recovery batch is generated and hashed before the transaction opens
/// (BAU-27), so no hashing runs under the enrollment row's lock.
pub async fn confirm_enrollment_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Vec<String>, AppError> {
    let batch = RecoveryBatch::generate(pepper);
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, secret_encrypted FROM user_mfa
         WHERE user_ref = $1 AND is_deleted = false AND confirmed_at IS NULL
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (mfa_id, secret_encrypted) = row.ok_or(AppError::NotFound)?;

    let secret_base32 = decrypt_secret(mfa_ring, &secret_encrypted)?;
    let totp = totp_for(&secret_base32, "")?;
    let now_secs = u64::try_from(Utc::now().timestamp())
        .map_err(|_| AppError::internal("system clock is before the Unix epoch"))?;
    let accepted_step = matching_totp_step(&totp, code, now_secs).ok_or(AppError::Unauthorized)?;

    let confirmed = sqlx::query(
        "UPDATE user_mfa
         SET confirmed_at = NOW(), updated_at = NOW(), row_version = row_version + 1,
             last_accepted_totp_step = $2
         WHERE id = $1 AND confirmed_at IS NULL",
    )
    .bind(mfa_id)
    .bind(accepted_step)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if confirmed == 0 {
        return Err(AppError::Conflict("mfa enrollment already confirmed"));
    }

    batch.store(&mut tx, user_id).await?;
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(batch.plaintext)
}

/// Disables (soft-deletes) the active enrollment and wipes its recovery
/// codes. Requires a valid current TOTP code or an unused recovery code as
/// proof of possession — a hijacked session alone must not be enough to turn
/// off a user's second factor.
///
/// Exactly one verifier runs, chosen by the code's shape (security contract
/// I11): six ASCII digits go to TOTP only, `XXXX-XXXX` from the recovery
/// alphabet goes to recovery codes only, and anything else is rejected before
/// any verifier runs. A wrong TOTP code never falls through to the recovery
/// verifier.
pub async fn disable(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
) -> Result<(), AppError> {
    disable_with(db, mfa_ring, pepper, user_id, code, &attome_db::NoHook).await
}

/// [`disable`], plus a [`attome_db::BeforeCommit`] hook that runs in the
/// disable's transaction with the account id (D-062).
pub async fn disable_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<(), AppError> {
    match classify_code(code) {
        Some(CodeShape::Totp) => verify_code(db, mfa_ring, user_id, code).await?,
        Some(CodeShape::Recovery) => verify_recovery_code(db, pepper, user_id, code).await?,
        None => return Err(AppError::Unauthorized),
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let disabled = sqlx::query(
        "UPDATE user_mfa SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1
         WHERE user_ref = $1 AND is_deleted = false",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if disabled == 0 {
        return Err(AppError::NotFound);
    }
    sqlx::query("DELETE FROM user_mfa_recovery_code WHERE user_ref = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(())
}

// ── Login-time verification ─────────────────────────────────────────────────

/// Verifies and consumes a TOTP code for a confirmed enrollment. The pending
/// MFA JWT remains stateless; the accepted RFC 6238 counter is the durable
/// replay boundary. Holding the enrollment row lock makes concurrent attempts
/// with the same code deterministic: exactly one can advance the counter.
pub async fn verify_code(
    db: &DbPool,
    mfa_ring: &KeyRing,
    user_id: Uuid,
    code: &str,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(Uuid, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, secret_encrypted, last_accepted_totp_step FROM user_mfa
         WHERE user_ref = $1 AND is_deleted = false AND confirmed_at IS NOT NULL
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (mfa_id, secret_encrypted, last_accepted_step) = row.ok_or(AppError::Unauthorized)?;

    let secret_base32 = decrypt_secret(mfa_ring, &secret_encrypted)?;
    let totp = totp_for(&secret_base32, "")?;
    let now_secs = u64::try_from(Utc::now().timestamp())
        .map_err(|_| AppError::internal("system clock is before the Unix epoch"))?;
    let accepted_step = matching_totp_step(&totp, code, now_secs).ok_or(AppError::Unauthorized)?;
    if last_accepted_step.is_some_and(|last_step| accepted_step <= last_step) {
        return Err(AppError::Unauthorized);
    }

    let updated = sqlx::query(
        "UPDATE user_mfa
         SET last_accepted_totp_step = $2, updated_at = NOW(), row_version = row_version + 1
         WHERE id = $1",
    )
    .bind(mfa_id)
    .bind(accepted_step)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::Unauthorized);
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Verifies + consumes (single-use) a recovery code. Does not disable MFA —
/// the account keeps its TOTP enrollment; only this one code is spent.
///
/// D-627 (BAU-17): peppered-HMAC rows are checked first with plain HMAC
/// compares and take no KDF permit. Argon2 rows written before D-627 still
/// verify through the bounded KDF executor during the compatibility window
/// (retired under BAU-12f's zero-count rule). A miss on an account holding no
/// Argon2 rows verifies against the HMAC dummy (security contract I17).
pub async fn verify_recovery_code(
    db: &DbPool,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
) -> Result<(), AppError> {
    let candidates: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, code_hash FROM user_mfa_recovery_code
         WHERE user_ref = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let (peppered, argon2): (Vec<_>, Vec<_>) = candidates
        .into_iter()
        .partition(|(_, hash)| hash.starts_with(PEPPERED_PREFIX));
    let mut matched_id = None;
    for (id, hash) in &peppered {
        if verify_peppered_secret(pepper, code, hash).await? != VerifyOutcome::Fail {
            matched_id = Some(*id);
            break;
        }
    }
    if matched_id.is_none() {
        for (id, hash) in &argon2 {
            if crate::password::verify_password_async(code, hash).await? {
                matched_id = Some(*id);
                break;
            }
        }
    }
    let Some(recovery_id) = matched_id else {
        if argon2.is_empty() {
            let _ = verify_peppered_secret(pepper, code, &dummy_peppered_hash(pepper)).await?;
        }
        return Err(AppError::Unauthorized);
    };

    let consumed = sqlx::query(
        "UPDATE user_mfa_recovery_code SET used_at = NOW() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(recovery_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if consumed == 0 {
        // Raced with a concurrent redemption of the same code.
        return Err(AppError::Conflict("recovery code already used"));
    }

    Ok(())
}

/// Which verifier a self-service code is for, decided from its shape alone
/// (security contract I11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeShape {
    Totp,
    Recovery,
}

/// `Some(Totp)` for exactly six ASCII digits; `Some(Recovery)` for
/// `XXXX-XXXX` drawn from [`RECOVERY_ALPHABET`]; `None` for anything else.
/// The two shapes cannot overlap: a recovery code always has a hyphen.
fn classify_code(code: &str) -> Option<CodeShape> {
    let bytes = code.as_bytes();
    if bytes.len() == 6 && bytes.iter().all(u8::is_ascii_digit) {
        return Some(CodeShape::Totp);
    }
    let is_recovery = bytes.len() == 9
        && bytes[4] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || RECOVERY_ALPHABET.contains(b));
    is_recovery.then_some(CodeShape::Recovery)
}

// ── Recovery codes ───────────────────────────────────────────────────────────

/// Recovery-code characters: uppercase alphanumerics without 0/O/1/I.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn generate_recovery_code() -> String {
    // 8 random bytes -> 8 uppercase alphanumeric chars, grouped for
    // readability (XXXX-XXXX). Not derived from the TOTP secret.
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let chars: String = bytes
        .iter()
        .map(|b| RECOVERY_ALPHABET[(*b as usize) % RECOVERY_ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// The stored-format prefix every peppered-HMAC hash starts with.
const PEPPERED_PREFIX: &str = "hmac256";

/// A fresh batch of `RECOVERY_CODE_COUNT` recovery codes and their
/// peppered-HMAC hashes (D-627). Built before any transaction opens (BAU-27);
/// HMAC is cheap and takes no KDF permit.
struct RecoveryBatch {
    plaintext: Vec<String>,
    hashes: Vec<String>,
}

impl RecoveryBatch {
    fn generate(pepper: &PepperRing) -> Self {
        let plaintext: Vec<String> = (0..RECOVERY_CODE_COUNT)
            .map(|_| generate_recovery_code())
            .collect();
        let hashes = plaintext
            .iter()
            .map(|code| hash_peppered_secret(pepper, code))
            .collect();
        Self { plaintext, hashes }
    }

    /// Wipes any existing (unused or used) recovery codes for `user_id` and
    /// inserts this batch inside the caller's transaction, so confirmation and
    /// code issuance commit atomically. Only `code_hash` is stored; the
    /// plaintext is visible to the user once.
    async fn store(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_mfa_recovery_code WHERE user_ref = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO user_mfa_recovery_code (user_ref, code_hash)
             SELECT $1, UNNEST($2::text[])",
        )
        .bind(user_id)
        .bind(&self.hashes)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        Ok(())
    }
}

/// Regenerates the recovery-code batch for an already-confirmed enrollment
/// (self-service, proof-of-possession required — same as `disable`).
/// Invalidates every prior code, used or not (guidelines/D-069: no silent
/// accumulation of valid-forever codes across regenerations).
pub async fn regenerate_recovery_codes(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
) -> Result<Vec<String>, AppError> {
    regenerate_recovery_codes_with(db, mfa_ring, pepper, user_id, code, &attome_db::NoHook).await
}

/// [`regenerate_recovery_codes`], plus a [`attome_db::BeforeCommit`] hook that
/// runs in the new batch's transaction with the account id (D-062).
pub async fn regenerate_recovery_codes_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    user_id: Uuid,
    code: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Vec<String>, AppError> {
    verify_code(db, mfa_ring, user_id, code).await?;

    let batch = RecoveryBatch::generate(pepper);
    let mut tx = attome_db::tx::begin(db).await?;
    batch.store(&mut tx, user_id).await?;
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(batch.plaintext)
}

// ── Pending-token verify entry points (called by website auth.rs) ─────────────

/// Consumes a `MfaPendingLogin` pending token + TOTP code, returning the
/// authenticated user id for the caller to issue real session cookies for.
/// P-mfa-challenge-hardening: the challenge marker gates this the same way
/// for a correct code as for a wrong one — a replayed token, even with a
/// byte-identical valid code, is rejected once its marker is gone.
#[allow(clippy::too_many_arguments)]
pub async fn complete_pending_login(
    db: &DbPool,
    mfa_ring: &KeyRing,
    redis: &Store,
    pending_token: &str,
    code: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    max_attempts: u32,
) -> Result<Uuid, AppError> {
    let (user_id, jti) = verify_pending_token(
        pending_token,
        TokenType::MfaPendingLogin,
        jwt_ring,
        issuer,
        audience,
    )?;
    require_live_challenge(redis, jti).await?;
    consume_or_record_failure(
        redis,
        jti,
        max_attempts,
        verify_code(db, mfa_ring, user_id, code).await,
    )
    .await?;
    Ok(user_id)
}

/// Same as `complete_pending_login` but via a recovery code.
#[allow(clippy::too_many_arguments)]
pub async fn complete_pending_login_recovery(
    db: &DbPool,
    pepper: &PepperRing,
    redis: &Store,
    pending_token: &str,
    code: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    max_attempts: u32,
) -> Result<Uuid, AppError> {
    let (user_id, jti) = verify_pending_token(
        pending_token,
        TokenType::MfaPendingLogin,
        jwt_ring,
        issuer,
        audience,
    )?;
    require_live_challenge(redis, jti).await?;
    consume_or_record_failure(
        redis,
        jti,
        max_attempts,
        verify_recovery_code(db, pepper, user_id, code).await,
    )
    .await?;
    Ok(user_id)
}

/// Starts enrollment using an `MfaPendingEnroll` pending token (the
/// `mfa_policy = "required"`, not-yet-enrolled first-login path) instead of
/// an established session. Does not touch the challenge marker at all — it
/// never checks a `code`, so it has nothing to attempt-count; the marker
/// created when this pending token was issued stays alive, untouched, until
/// `confirm_pending_enrollment` actually verifies a code against it.
#[allow(clippy::too_many_arguments)]
pub async fn enroll_pending(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pending_token: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<EnrollResponse, AppError> {
    enroll_pending_with(
        db,
        mfa_ring,
        pending_token,
        jwt_ring,
        issuer,
        audience,
        &attome_db::NoHook,
    )
    .await
}

/// [`enroll_pending`] with [`enroll_with`]'s hook.
#[allow(clippy::too_many_arguments)]
pub async fn enroll_pending_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pending_token: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<EnrollResponse, AppError> {
    let (user_id, _jti) = verify_pending_token(
        pending_token,
        TokenType::MfaPendingEnroll,
        jwt_ring,
        issuer,
        audience,
    )?;
    enroll_with(db, mfa_ring, user_id, hook).await
}

/// Confirms enrollment using an `MfaPendingEnroll` pending token, returning
/// the user id (for session issuance) and the recovery-code batch.
#[allow(clippy::too_many_arguments)]
pub async fn confirm_pending_enrollment(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    redis: &Store,
    pending_token: &str,
    code: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    max_attempts: u32,
) -> Result<(Uuid, Vec<String>), AppError> {
    confirm_pending_enrollment_with(
        db,
        mfa_ring,
        pepper,
        redis,
        pending_token,
        code,
        jwt_ring,
        issuer,
        audience,
        max_attempts,
        &attome_db::NoHook,
    )
    .await
}

/// [`confirm_pending_enrollment`] with [`confirm_enrollment_with`]'s hook.
#[allow(clippy::too_many_arguments)]
pub async fn confirm_pending_enrollment_with(
    db: &DbPool,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    redis: &Store,
    pending_token: &str,
    code: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    max_attempts: u32,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<(Uuid, Vec<String>), AppError> {
    let (user_id, jti) = verify_pending_token(
        pending_token,
        TokenType::MfaPendingEnroll,
        jwt_ring,
        issuer,
        audience,
    )?;
    require_live_challenge(redis, jti).await?;
    let codes = consume_or_record_failure(
        redis,
        jti,
        max_attempts,
        confirm_enrollment_with(db, mfa_ring, pepper, user_id, code, hook).await,
    )
    .await?;
    Ok((user_id, codes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> KeyRing {
        KeyRing::single("ab".repeat(32))
    }

    fn other_ring() -> KeyRing {
        KeyRing::single("cd".repeat(32))
    }

    fn jwt_ring() -> KeyRing {
        KeyRing::single("test-jwt-secret-value".to_string())
    }

    #[test]
    fn encrypt_decrypt_secret_roundtrips_and_detects_wrong_key() {
        let ring_a = test_ring();
        let ring_b = other_ring();
        let secret = Secret::generate().to_base32();

        let encrypted = encrypt_secret(&ring_a, &secret).unwrap();
        assert_eq!(decrypt_secret(&ring_a, &encrypted).unwrap(), secret);
        assert!(decrypt_secret(&ring_b, &encrypted).is_err());
    }

    #[test]
    fn totp_generated_code_is_immediately_valid() {
        let secret = Secret::generate().to_base32();
        let totp = totp_for(&secret, "user@example.com").unwrap();
        let code = totp.generate_current().to_string();
        assert!(totp.check_current(&code).is_some());
    }

    #[test]
    fn totp_rejects_an_obviously_wrong_code() {
        let secret = Secret::generate().to_base32();
        let totp = totp_for(&secret, "user@example.com").unwrap();
        assert!(totp.check_current("000000").is_none());
    }

    #[test]
    fn two_totp_secrets_produce_different_codes() {
        let secret_a = Secret::generate().to_base32();
        let secret_b = Secret::generate().to_base32();
        let totp_a = totp_for(&secret_a, "a").unwrap();
        let totp_b = totp_for(&secret_b, "a").unwrap();
        // Astronomically unlikely to collide; a false failure here would
        // indicate the RNG isn't actually varying the secret.
        assert_ne!(
            totp_a.generate_current().to_string(),
            totp_b.generate_current().to_string()
        );
    }

    #[test]
    fn otpauth_uri_carries_the_issuer_and_account_name() {
        let secret = Secret::generate().to_base32();
        let totp = totp_for(&secret, "user@example.com").unwrap();
        let url = totp.to_url().unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("Attome"));
        assert!(url.contains("user%40example.com") || url.contains("user@example.com"));
    }

    #[test]
    fn generate_recovery_code_excludes_ambiguous_characters() {
        for _ in 0..50 {
            let code = generate_recovery_code();
            assert_eq!(code.len(), 9); // 4 + '-' + 4
            assert!(!code.contains(['0', 'O', '1', 'I']));
        }
    }

    #[test]
    fn generate_recovery_code_is_random_across_calls() {
        let a = generate_recovery_code();
        let b = generate_recovery_code();
        assert_ne!(a, b);
    }

    #[test]
    fn pending_token_roundtrips_and_carries_typ() {
        let user_id = Uuid::now_v7();
        let r = jwt_ring();
        let (token, minted_jti) = issue_pending_token(
            user_id,
            TokenType::MfaPendingLogin,
            &r,
            "attome-test",
            "attome-test",
        )
        .unwrap();
        let (verified_user, verified_jti) = verify_pending_token(
            &token,
            TokenType::MfaPendingLogin,
            &r,
            "attome-test",
            "attome-test",
        )
        .unwrap();
        assert_eq!(verified_user, user_id);
        assert_eq!(verified_jti, minted_jti);
    }

    #[test]
    fn pending_token_rejects_empty_iss_aud() {
        // D-130 addendum (audit finding #6): issue_pending_token always
        // stamps iss/aud, so simulate a pre-this-feature pending token the
        // same way jwt.rs's equivalent test does, by constructing
        // PendingClaims directly.
        let user_id = Uuid::now_v7();
        let r = jwt_ring();
        let now = Utc::now().timestamp();
        let old_style = PendingClaims {
            sub: user_id,
            typ: TokenType::MfaPendingLogin,
            iat: now,
            exp: now + 300,
            iss: String::new(),
            aud: String::new(),
            jti: Uuid::now_v7(),
        };
        let token = encode_claims(&old_style, &r).unwrap();
        assert!(
            verify_pending_token(
                &token,
                TokenType::MfaPendingLogin,
                &r,
                "attome-test",
                "attome-test",
            )
            .is_err(),
            "an empty iss/aud is a mismatch"
        );
        let result = verify_pending_token(
            &token,
            TokenType::MfaPendingLogin,
            &r,
            "attome-test",
            "attome-test",
        );
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn ct_eq_matches_identical_strings() {
        assert!(ct_eq("123456", "123456"));
    }

    #[test]
    fn ct_eq_rejects_a_single_differing_digit() {
        assert!(!ct_eq("123456", "123457"));
    }

    #[test]
    fn ct_eq_rejects_differing_lengths_without_panicking() {
        assert!(!ct_eq("123456", "12345"));
        assert!(!ct_eq("123456", "1234567"));
        assert!(!ct_eq("123456", ""));
    }

    #[test]
    fn matching_totp_step_returns_the_newest_matching_step() {
        let secret = Secret::generate().to_base32();
        let totp = totp_for(&secret, "user@example.com").unwrap();
        let now_secs = 1_800_u64;

        assert_eq!(
            matching_totp_step(&totp, &totp.generate(1_800).to_string(), now_secs),
            Some(60)
        );
        assert_eq!(
            matching_totp_step(&totp, &totp.generate(1_830).to_string(), now_secs),
            Some(61)
        );
        assert_eq!(matching_totp_step(&totp, "000000", now_secs), None);
    }

    #[test]
    fn pending_token_rejects_a_typ_mismatch() {
        let user_id = Uuid::now_v7();
        let r = jwt_ring();
        let (token, _jti) = issue_pending_token(
            user_id,
            TokenType::MfaPendingEnroll,
            &r,
            "attome-test",
            "attome-test",
        )
        .unwrap();
        let result = verify_pending_token(
            &token,
            TokenType::MfaPendingLogin,
            &r,
            "attome-test",
            "attome-test",
        );
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn pending_token_rejects_wrong_secret() {
        let user_id = Uuid::now_v7();
        let signing_ring = KeyRing::single("real-secret".to_string());
        let verify_ring = KeyRing::single("wrong-secret".to_string());
        let (token, _jti) = issue_pending_token(
            user_id,
            TokenType::MfaPendingLogin,
            &signing_ring,
            "attome-test",
            "attome-test",
        )
        .unwrap();
        let result = verify_pending_token(
            &token,
            TokenType::MfaPendingLogin,
            &verify_ring,
            "attome-test",
            "attome-test",
        );
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn pending_token_rejects_a_session_typ_presented_as_pending() {
        let user_id = Uuid::now_v7();
        let r = jwt_ring();
        // A session-typed token, minted the same way accounts::issue_access_token
        // would, must never satisfy a pending-token challenge.
        let claims = crate::session::SessionClaims {
            sub: user_id,
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 900,
            jti: Uuid::now_v7(),
            epoch: 0,
            iss: "attome-test".to_string(),
            aud: "attome-test".to_string(),
            typ: TokenType::Session,
        };
        let token = encode_claims(&claims, &r).unwrap();
        let result = verify_pending_token(
            &token,
            TokenType::MfaPendingLogin,
            &r,
            "attome-test",
            "attome-test",
        );
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    /// Security contract I11: six digits select TOTP and nothing else.
    #[test]
    fn six_ascii_digits_classify_as_totp_only() {
        assert_eq!(classify_code("123456"), Some(CodeShape::Totp));
        assert_eq!(classify_code("000000"), Some(CodeShape::Totp));
        for not_totp in ["12345", "1234567", "12345a", "１２３４５６", " 123456"] {
            assert_ne!(
                classify_code(not_totp),
                Some(CodeShape::Totp),
                "{not_totp:?} must not select the TOTP verifier"
            );
        }
    }

    /// Security contract I11: `XXXX-XXXX` from the recovery alphabet selects
    /// recovery codes; lowercase, excluded characters and wrong grouping do not.
    #[test]
    fn recovery_shaped_codes_classify_as_recovery_only() {
        assert_eq!(classify_code("ABCD-2345"), Some(CodeShape::Recovery));
        for code in (0..50).map(|_| generate_recovery_code()) {
            assert_eq!(
                classify_code(&code),
                Some(CodeShape::Recovery),
                "a generated code {code:?} must classify as recovery"
            );
        }
        for not_recovery in [
            "abcd-2345",
            "ABCD-0345",
            "ABCD-1345",
            "ABCO-2345",
            "ABCI-2345",
            "ABCD2345",
            "ABCD-23456",
            "ABC-D2345",
            "",
        ] {
            assert_eq!(
                classify_code(not_recovery),
                None,
                "{not_recovery:?} matches neither shape"
            );
        }
    }
}

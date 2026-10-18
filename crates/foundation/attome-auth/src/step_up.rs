//! Step-up authentication for sensitive account operations (D-510 rules 3, 4,
//! 6, 7 and 8; attome-auth hardening 2.1b).
//!
//! A sensitive operation needs proof that the caller verified a credential
//! recently, recorded on the caller's own refresh family. This module holds
//! every part of that decision:
//!
//! - [`Operation`]: the closed set of protected operations, each with its max
//!   age and where its freshness comes from;
//! - [`AccountFactors::accepted`]: the factors an account may step up with,
//!   from its current state (rule 4);
//! - [`require_recent_auth`]: the guard (rules 3, 7 and 8);
//! - [`start_challenge`] and [`verify_challenge`]: the single-use challenge
//!   (rule 6), whose success writes the elevation (rule 3).
//!
//! The family is only ever the [`SessionId`] authn took from the validated
//! token, the user only `SessionClaims.sub`, and the operation only the route.
//! Nothing here takes any of them from a request body, query or header.
//!
//! Wiring the guard onto the protected routes is 2.1d; federated step-up is
//! 2.1c.

use std::time::Duration;

use attome_cache::Store;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use fred::interfaces::LuaInterface;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::session::SessionId;

/// How long a step-up challenge lives (rule 6).
pub const CHALLENGE_TTL_SECS: i64 = 300;

/// Wrong credentials one challenge absorbs; the fifth deletes it (rule 6).
pub const CHALLENGE_MAX_ATTEMPTS: u32 = 5;

/// How long a successful step-up elevates the family, before the family's own
/// absolute end caps it (rule 3).
pub const ELEVATION_SECS: i64 = 15 * 60;

/// The single factor a refusal names when the account has nothing it can step
/// up with, such as a Google-only account without TOTP (rule 4).
pub const TOTP_ENROLLMENT_REQUIRED: &str = "totp_enrollment_required";

/// Same fail-closed budget as the MFA challenge marker and the rate limiter.
const CHALLENGE_STORE_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

// ── Operations ──────────────────────────────────────────────────────────────

/// A sensitive operation (rule 1). The operation is always resolved from the
/// route, never from request input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    MfaDisable,
    RecoveryCodesRegenerate,
    IdentityLink,
    ApiKeyCreate,
    /// Q5-T8: an administrator resetting someone's second factor.
    AdminMfaReset,
}

/// Where an operation's freshness comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The request itself carries a verified second-factor code, which counts
    /// as that request's step-up and writes no elevation (rule 8).
    InRequestFactor,
    /// The family must hold a still-valid, fresh elevation (rule 3).
    Elevation,
}

impl Operation {
    pub const ALL: [Operation; 5] = [
        Operation::MfaDisable,
        Operation::RecoveryCodesRegenerate,
        Operation::IdentityLink,
        Operation::ApiKeyCreate,
        Operation::AdminMfaReset,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Operation::MfaDisable => "mfa_disable",
            Operation::RecoveryCodesRegenerate => "recovery_codes_regenerate",
            Operation::IdentityLink => "identity_link",
            Operation::ApiKeyCreate => "api_key_create",
            Operation::AdminMfaReset => "admin_mfa_reset",
        }
    }

    /// The maximum age of the authentication that satisfies this operation
    /// (rule 1).
    pub fn max_age_secs(self) -> i64 {
        match self {
            Operation::ApiKeyCreate => 15 * 60,
            Operation::MfaDisable
            | Operation::RecoveryCodesRegenerate
            | Operation::IdentityLink
            | Operation::AdminMfaReset => 5 * 60,
        }
    }

    pub fn freshness(self) -> Freshness {
        match self {
            Operation::MfaDisable | Operation::RecoveryCodesRegenerate => {
                Freshness::InRequestFactor
            }
            Operation::IdentityLink | Operation::ApiKeyCreate | Operation::AdminMfaReset => {
                Freshness::Elevation
            }
        }
    }

    /// Parses a step-up route segment. Only operations that need elevation
    /// are step-up operations; the in-request-factor ones never take a
    /// challenge, so they do not parse (rule 8).
    pub fn from_step_up_route(segment: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|op| op.freshness() == Freshness::Elevation && op.as_str() == segment)
    }
}

// ── Factors ─────────────────────────────────────────────────────────────────

/// A step-up factor, named on the wire by [`Factor::as_str`] and recorded in
/// `amr` by [`Factor::amr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    Totp,
    RecoveryCode,
    Password,
    /// An OIDC re-authentication (2.1c). No local verifier accepts it.
    Federated,
}

impl Factor {
    pub fn as_str(self) -> &'static str {
        match self {
            Factor::Totp => "totp",
            Factor::RecoveryCode => "recovery_code",
            Factor::Password => "password",
            Factor::Federated => "federated",
        }
    }

    /// The `amr` value this factor records (D-510 rule 2).
    pub fn amr(self) -> &'static str {
        match self {
            Factor::Totp => "otp",
            Factor::RecoveryCode => "rcode",
            Factor::Password => "pwd",
            Factor::Federated => "fed",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        [
            Factor::Totp,
            Factor::RecoveryCode,
            Factor::Password,
            Factor::Federated,
        ]
        .into_iter()
        .find(|factor| factor.as_str() == name)
    }

    fn is_local(self) -> bool {
        !matches!(self, Factor::Federated)
    }
}

/// The account state rule 4 decides from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountFactors {
    pub totp_enrolled: bool,
    pub has_password: bool,
    /// An OIDC identity or a Google account is linked. A Google link counts
    /// since BAU-8b validates Google's `auth_time` locally (D-628 amending
    /// rule 4); it is answered by [`complete_google_step_up_with`].
    pub federated_linked: bool,
}

impl AccountFactors {
    /// The factors this account may step up with (rule 4). Empty means the
    /// account is refused with [`TOTP_ENROLLMENT_REQUIRED`].
    pub fn accepted(self) -> Vec<Factor> {
        if self.totp_enrolled {
            return vec![Factor::Totp, Factor::RecoveryCode];
        }
        let mut accepted = Vec::new();
        if self.has_password {
            accepted.push(Factor::Password);
        }
        if self.federated_linked {
            accepted.push(Factor::Federated);
        }
        accepted
    }
}

/// Reads the current state of an active account. An inactive or missing
/// account is `Unauthorized`.
pub async fn account_factors(db: &DbPool, user_id: Uuid) -> Result<AccountFactors, AppError> {
    let row: Option<(bool, bool, bool)> = sqlx::query_as(
        "SELECT u.password_hash IS NOT NULL,
                EXISTS (SELECT 1 FROM user_mfa m
                        WHERE m.user_ref = u.id AND m.is_deleted = false
                          AND m.confirmed_at IS NOT NULL),
                u.google_sub IS NOT NULL
                    OR EXISTS (SELECT 1 FROM user_identity i WHERE i.user_ref = u.id)
         FROM user_account u
         WHERE u.id = $1 AND u.is_active",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (has_password, totp_enrolled, federated_linked) = row.ok_or(AppError::Unauthorized)?;
    Ok(AccountFactors {
        totp_enrolled,
        has_password,
        federated_linked,
    })
}

/// The structured refusal for `operation` (rule 6): 401 `reauth_required`
/// naming the factors the account can use.
pub fn reauth_required(operation: Operation, accepted: &[Factor]) -> AppError {
    let acceptable_factors = if accepted.is_empty() {
        vec![TOTP_ENROLLMENT_REQUIRED]
    } else {
        accepted.iter().map(|factor| factor.as_str()).collect()
    };
    AppError::ReauthRequired {
        operation: operation.as_str(),
        acceptable_factors,
    }
}

// ── Caller ──────────────────────────────────────────────────────────────────

/// Who is asking, as authn established it. Built only from request extensions
/// (attome-server's `StepUpCaller` extractor), never from request input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// A cookie session whose validated token names its refresh family.
    Session(SessionId),
    /// An API key, an S2S client, or anything else without a refresh family.
    NonSession,
}

/// The family a caller may step up on. API-key and S2S callers can never step
/// up, so they are refused (rule 7).
fn session_of(caller: Caller) -> Result<SessionId, AppError> {
    match caller {
        Caller::Session(session) => Ok(session),
        Caller::NonSession => Err(AppError::Forbidden),
    }
}

// ── Guard ───────────────────────────────────────────────────────────────────

/// A live family's step-up state, evaluated on the database clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyState {
    /// `elevated_until > NOW()`.
    pub elevated: bool,
    /// `NOW() - auth_time` is within the operation's max age.
    pub fresh: bool,
    /// The last `amr` entry: the factor the most recent step-up appended.
    pub last_method: Option<String>,
}

/// Reads the live row of `session`'s family for `user_id`: unused, unrevoked,
/// unexpired and inside its absolute lifetime (D-504). `None` when there is no
/// such row, so a session id never reaches another user's family or a dead
/// one.
async fn live_family_state(
    db: &DbPool,
    user_id: Uuid,
    session: SessionId,
    max_age_secs: i64,
    absolute_secs: i64,
) -> Result<Option<FamilyState>, AppError> {
    let row: Option<(bool, bool, Option<String>)> = sqlx::query_as(
        "SELECT COALESCE(elevated_until > NOW(), FALSE),
                COALESCE(auth_time >= NOW() - make_interval(secs => $3::float8), FALSE),
                amr[array_upper(amr, 1)]
         FROM refresh_token
         WHERE family_id = $1 AND user_ref = $2
           AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
           AND family_started_at + make_interval(secs => $4::float8) > NOW()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(session.0)
    .bind(user_id)
    .bind(max_age_secs)
    .bind(absolute_secs)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(elevated, fresh, last_method)| FamilyState {
        elevated,
        fresh,
        last_method,
    }))
}

/// Rule 3's decision for an elevation operation: elevated, fresh, and the
/// step-up's own factor is one the account accepts now. Checking the last
/// `amr` entry rather than any entry means a sign-in factor, or a factor from
/// before a TOTP enrollment, never satisfies a TOTP-enrolled account.
pub fn decide(
    operation: Operation,
    state: &FamilyState,
    accepted: &[Factor],
) -> Result<(), AppError> {
    let factor_accepted = state
        .last_method
        .as_deref()
        .is_some_and(|method| accepted.iter().any(|factor| factor.amr() == method));
    if state.elevated && state.fresh && factor_accepted {
        Ok(())
    } else {
        Err(reauth_required(operation, accepted))
    }
}

/// The guard for a sensitive operation (rules 3, 7 and 8).
///
/// - An API-key or S2S caller is `Forbidden`; a session without `sid` is
///   `Unauthorized` so the client refreshes; a family that is not live for
///   `user_id` is `Unauthorized`.
/// - An in-request-factor operation needs only the live session: the handler's
///   own code verification is the step-up, and no elevation is read or written.
/// - An elevation operation passes only per [`decide`], and otherwise answers
///   `reauth_required`.
pub async fn require_recent_auth(
    db: &DbPool,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    absolute_secs: i64,
) -> Result<(), AppError> {
    let session = session_of(caller)?;
    let state = live_family_state(
        db,
        user_id,
        session,
        operation.max_age_secs(),
        absolute_secs,
    )
    .await?
    .ok_or(AppError::Unauthorized)?;
    match operation.freshness() {
        Freshness::InRequestFactor => Ok(()),
        Freshness::Elevation => {
            let accepted = account_factors(db, user_id).await?.accepted();
            decide(operation, &state, &accepted)
        }
    }
}

/// What [`require_recent_auth`] decides for an elevation operation right now
/// (D-510 rule 9; attome-auth hardening 2.1d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationStatus {
    pub operation: Operation,
    /// Exactly whether the guard passes now.
    pub elevated: bool,
    /// The family's `elevated_until` while `elevated`, otherwise `None`.
    pub elevated_until: Option<DateTime<Utc>>,
    /// The factors a step-up for this operation accepts, named as the refusal
    /// names them.
    pub acceptable_factors: Vec<&'static str>,
}

/// Reads the guard's decision without acting on it, so a browser navigation
/// (identity linking) can check before it leaves the page (rule 9). It runs
/// [`require_recent_auth`] itself, so the two can never disagree. It writes
/// nothing, creates no challenge, and reads only the caller's own family.
///
/// Its refusals are the guard's: an API-key or S2S caller is `Forbidden`, a
/// session without a live family is `Unauthorized`. An operation that takes its
/// step-up from the request (rule 8) has nothing to read and is `NotFound`.
pub async fn elevation_status(
    db: &DbPool,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    absolute_secs: i64,
) -> Result<ElevationStatus, AppError> {
    if operation.freshness() != Freshness::Elevation {
        return Err(AppError::NotFound);
    }
    match require_recent_auth(db, caller, user_id, operation, absolute_secs).await {
        Ok(()) => {
            let session = session_of(caller)?;
            let elevated_until = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
                "SELECT elevated_until FROM refresh_token
                 WHERE family_id = $1 AND user_ref = $2
                   AND used_at IS NULL AND revoked_at IS NULL
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .bind(session.0)
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
            let accepted = account_factors(db, user_id).await?.accepted();
            Ok(ElevationStatus {
                operation,
                elevated: true,
                elevated_until,
                acceptable_factors: accepted.iter().map(|factor| factor.as_str()).collect(),
            })
        }
        Err(AppError::ReauthRequired {
            acceptable_factors, ..
        }) => Ok(ElevationStatus {
            operation,
            elevated: false,
            elevated_until: None,
            acceptable_factors,
        }),
        Err(other) => Err(other),
    }
}

// ── Challenges ──────────────────────────────────────────────────────────────

/// What a challenge is bound to (rule 6). Stored server-side; the client only
/// ever holds the challenge id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChallengeBinding {
    user_id: Uuid,
    family_id: Uuid,
    operation: Operation,
    factors: Vec<Factor>,
}

fn challenge_key(challenge_id: Uuid) -> String {
    format!("auth:step_up:{challenge_id}")
}

fn attempts_key(challenge_id: Uuid) -> String {
    format!("auth:step_up:{challenge_id}:attempts")
}

/// `KEYS[1]` = challenge, `KEYS[2]` = its attempt counter, `ARGV[1]` =
/// `"consume"` | `"fail"`, `ARGV[2]` = max attempts, `ARGV[3]` = TTL seconds.
/// Returns `1` when the challenge was consumed, or a failure was recorded below
/// the ceiling; `0` when it was already gone or this failure hit the ceiling.
/// Atomic, so two concurrent consumes yield exactly one `1`, and concurrent
/// failures cannot both read "attempts left".
const CHALLENGE_STEP_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
if ARGV[1] == 'consume' then
  redis.call('DEL', KEYS[1], KEYS[2])
  return 1
end
local n = redis.call('INCR', KEYS[2])
if n == 1 then
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
end
if n >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1], KEYS[2])
  return 0
end
return 1
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Consume,
    Fail,
}

/// Runs one atomic step against a challenge. A Redis error or timeout is an
/// `Err`, which every caller treats as a rejection.
async fn challenge_step(redis: &Store, challenge_id: Uuid, step: Step) -> Result<bool, AppError> {
    let redis = match redis {
        Store::Redis(pool) => pool,
        // The in-process form of CHALLENGE_STEP_SCRIPT, one locked step.
        Store::Memory(memory) => {
            let alive = memory
                .transaction(|ks| -> Result<bool, attome_cache::memory::WrongType> {
                    if !ks.exists(&challenge_key(challenge_id)) {
                        return Ok(false);
                    }
                    if step == Step::Consume {
                        ks.del(&challenge_key(challenge_id));
                        ks.del(&attempts_key(challenge_id));
                        return Ok(true);
                    }
                    let attempts = ks.incr_by(&attempts_key(challenge_id), 1)?;
                    if attempts == 1 {
                        ks.expire(
                            &attempts_key(challenge_id),
                            std::time::Duration::from_secs(CHALLENGE_TTL_SECS as u64),
                        );
                    }
                    if attempts >= i64::from(CHALLENGE_MAX_ATTEMPTS) {
                        ks.del(&challenge_key(challenge_id));
                        ks.del(&attempts_key(challenge_id));
                        return Ok(false);
                    }
                    Ok(true)
                })
                .map_err(|_| AppError::Unauthorized)?;
            return Ok(alive);
        }
    };
    let arg = match step {
        Step::Consume => "consume",
        Step::Fail => "fail",
    };
    let alive: i64 = tokio::time::timeout(
        CHALLENGE_STORE_TIMEOUT,
        redis.eval(
            CHALLENGE_STEP_SCRIPT,
            vec![challenge_key(challenge_id), attempts_key(challenge_id)],
            vec![
                arg.to_string(),
                CHALLENGE_MAX_ATTEMPTS.to_string(),
                CHALLENGE_TTL_SECS.to_string(),
            ],
        ),
    )
    .await
    .map_err(|_| AppError::Unauthorized)?
    .map_err(|_| AppError::Unauthorized)?;
    Ok(alive == 1)
}

/// Reads a challenge's binding. `Ok(None)` when it is gone; `Err` on a Redis
/// error, a timeout or an unreadable value.
async fn load_binding(
    redis: &Store,
    challenge_id: Uuid,
) -> Result<Option<ChallengeBinding>, AppError> {
    let value: Option<String> = tokio::time::timeout(
        CHALLENGE_STORE_TIMEOUT,
        redis.get(&challenge_key(challenge_id)),
    )
    .await
    .map_err(|_| AppError::Unauthorized)?
    .map_err(|_| AppError::Unauthorized)?;
    value
        .map(|raw| serde_json::from_str(&raw).map_err(|_| AppError::Unauthorized))
        .transpose()
}

/// The stores a challenge needs.
#[derive(Clone, Copy)]
pub struct StepUpStores<'a> {
    pub db: &'a DbPool,
    /// The coordination pool (rule 6).
    pub redis: &'a Store,
    /// The refresh family's absolute lifetime (`auth.refresh_absolute_lifetime_days`).
    pub absolute_lifetime_secs: i64,
}

impl std::fmt::Debug for StepUpStores<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpStores")
            .field("absolute_lifetime_secs", &self.absolute_lifetime_secs)
            .finish_non_exhaustive()
    }
}

/// A started challenge, as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedChallenge {
    pub challenge_id: Uuid,
    pub operation: Operation,
    pub acceptable_factors: Vec<Factor>,
    pub expires_in_secs: i64,
}

/// Starts a single-use challenge for `operation` on the caller's own family
/// (rule 6), bound to the user, that family, the operation and the factors the
/// account accepts now.
///
/// Refusals: API-key/S2S `Forbidden`; a dead family `Unauthorized`; an in-request-factor operation `NotFound`; an account with no
/// accepted factor at all (rule 4, such as Google-only without TOTP)
/// `reauth_required` with `totp_enrollment_required`. An account whose only
/// factor is `federated` gets a challenge, which it completes at its provider
/// (rule 5). A Redis failure is an internal error, so no challenge exists.
pub async fn start_challenge(
    stores: StepUpStores<'_>,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
) -> Result<StartedChallenge, AppError> {
    let session = session_of(caller)?;
    if operation.freshness() != Freshness::Elevation {
        return Err(AppError::NotFound);
    }
    live_family_state(
        stores.db,
        user_id,
        session,
        operation.max_age_secs(),
        stores.absolute_lifetime_secs,
    )
    .await?
    .ok_or(AppError::Unauthorized)?;

    let accepted = account_factors(stores.db, user_id).await?.accepted();
    if accepted.is_empty() {
        return Err(reauth_required(operation, &accepted));
    }

    let challenge_id = Uuid::now_v7();
    let binding = ChallengeBinding {
        user_id,
        family_id: session.0,
        operation,
        factors: accepted.clone(),
    };
    let value = serde_json::to_string(&binding).map_err(AppError::internal)?;
    let written = tokio::time::timeout(
        CHALLENGE_STORE_TIMEOUT,
        stores.redis.set_nx(
            &challenge_key(challenge_id),
            &value,
            Some(std::time::Duration::from_secs(CHALLENGE_TTL_SECS as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("step-up challenge write timed out"))??;
    if !written {
        return Err(AppError::internal("step-up challenge id collided"));
    }

    Ok(StartedChallenge {
        challenge_id,
        operation,
        acceptable_factors: accepted,
        expires_in_secs: CHALLENGE_TTL_SECS,
    })
}

/// What the client submits to answer a challenge. The operation and family are
/// deliberately absent: they come from the route and the validated token.
#[derive(Debug, Clone, Copy)]
pub struct Submission<'a> {
    pub challenge_id: &'a str,
    pub factor: &'a str,
    pub credential: &'a str,
}

/// Verifies a challenge and, on success, elevates the caller's family (rules
/// 3, 4 and 6). Returns the new `elevated_until`.
///
/// The caller must already have charged the shared per-account MFA budget.
/// Then:
/// 1. the challenge id, factor name and binding are checked — a malformed id,
///    an unknown or expired challenge, or a binding for another user, family
///    or operation rejects without counting an attempt or consuming it;
/// 2. the factor must be in the challenge's factors and in the account's
///    accepted factors now;
/// 3. exactly one verifier runs (contract I11); a wrong credential counts an
///    attempt, and the fifth deletes the challenge;
/// 4. the challenge is consumed atomically, so concurrent correct submissions
///    yield exactly one success;
/// 5. the elevation is written.
///
/// Every rejection, including a Redis failure, is `reauth_required` and writes
/// no elevation.
pub async fn verify_challenge(
    stores: StepUpStores<'_>,
    mfa_ring: &KeyRing,
    pepper: &crate::PepperRing,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    submission: Submission<'_>,
) -> Result<DateTime<Utc>, AppError> {
    verify_challenge_with(
        stores,
        mfa_ring,
        pepper,
        caller,
        user_id,
        operation,
        submission,
        &attome_db::NoHook,
    )
    .await
}

/// [`verify_challenge`], plus a [`attome_db::BeforeCommit`] hook that runs in
/// the elevation's transaction with the account id, so the caller's step-up
/// event commits with the elevation or neither does (D-062). A refusal does
/// not run it.
#[allow(clippy::too_many_arguments)]
pub async fn verify_challenge_with(
    stores: StepUpStores<'_>,
    mfa_ring: &KeyRing,
    pepper: &crate::PepperRing,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    submission: Submission<'_>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<DateTime<Utc>, AppError> {
    let session = session_of(caller)?;
    let accepted = account_factors(stores.db, user_id).await?.accepted();
    let reject = || reauth_required(operation, &accepted);

    let Ok(challenge_id) = Uuid::parse_str(submission.challenge_id) else {
        return Err(reject());
    };
    let Some(factor) = Factor::from_wire(submission.factor) else {
        return Err(reject());
    };
    let Ok(Some(binding)) = load_binding(stores.redis, challenge_id).await else {
        return Err(reject());
    };
    if binding.user_id != user_id
        || binding.family_id != session.0
        || binding.operation != operation
    {
        return Err(reject());
    }
    if !factor.is_local() || !binding.factors.contains(&factor) || !accepted.contains(&factor) {
        return Err(reject());
    }

    let verified = match factor {
        Factor::Totp => {
            crate::mfa::verify_code(stores.db, mfa_ring, user_id, submission.credential).await
        }
        Factor::RecoveryCode => {
            crate::mfa::verify_recovery_code(stores.db, pepper, user_id, submission.credential)
                .await
        }
        Factor::Password => {
            verify_account_password(stores.db, user_id, submission.credential).await
        }
        Factor::Federated => Err(AppError::Unauthorized),
    };
    match verified {
        Ok(()) => {
            if !matches!(
                challenge_step(stores.redis, challenge_id, Step::Consume).await,
                Ok(true)
            ) {
                return Err(reject());
            }
        }
        Err(AppError::Unauthorized | AppError::Conflict(_)) => {
            // The rejection stands whether or not the attempt could be
            // recorded.
            let _ = challenge_step(stores.redis, challenge_id, Step::Fail).await;
            return Err(reject());
        }
        Err(other) => return Err(other),
    }

    write_elevation(
        stores.db,
        user_id,
        session,
        factor,
        None,
        stores.absolute_lifetime_secs,
        hook,
    )
    .await
}

/// Verifies the account's own password. An account without one runs the dummy
/// verify, so the miss costs the same.
async fn verify_account_password(
    db: &DbPool,
    user_id: Uuid,
    password: &str,
) -> Result<(), AppError> {
    let hash: Option<String> = sqlx::query_scalar(
        "SELECT password_hash FROM user_account
         WHERE id = $1 AND is_active",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    match hash {
        Some(hash) if crate::password::verify_password_async(password, &hash).await? => Ok(()),
        Some(_) => Err(AppError::Unauthorized),
        None => {
            crate::password::verify_against_dummy_async(password).await?;
            Err(AppError::Unauthorized)
        }
    }
}

// ── Federated step-up (rule 5, 2.1c) ────────────────────────────────────────

/// Clock-skew allowance for a provider's authentication time, the same leeway
/// the OIDC ID token's own `auth_time` gets.
pub const FEDERATED_AUTH_TIME_LEEWAY_SECS: i64 = 60;

/// The federation protocol a step-up runs over (rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedProtocol {
    Oidc,
}

/// What a federated step-up is bound to. It rides inside the provider flow's
/// single-use, server-side state (`oidc::OidcState`)
/// across the IdP redirect, because the session cookie does not survive that
/// redirect. Only [`begin_federated_step_up`] builds one, from a live challenge
/// and the validated session; the callback trusts nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedStepUp {
    pub challenge_id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub operation: Operation,
    pub protocol: FederatedProtocol,
    pub provider_key: String,
}

impl FederatedStepUp {
    /// The maximum authentication age the provider is asked for (OIDC
    /// `max_age`) and held to.
    pub fn max_age_secs(&self) -> i64 {
        self.operation.max_age_secs()
    }
}

/// Why a federated authentication time cannot satisfy step-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTimeRefusal {
    /// The provider validated no authentication time. Callback time is never a
    /// substitute, and neither is having asked for `prompt=login`, `max_age`
    /// or `ForceAuthn`.
    Missing,
    /// Later than `now` plus the clock-skew leeway.
    InTheFuture,
    /// Older than the operation's max age.
    Stale,
}

/// Rule 5's time check, pure so it is testable without a provider. `asserted`
/// must be the time the provider path validated (the ID token's `auth_time`,
/// the assertion's `AuthnInstant`) and `now` the database clock. Returns the
/// verification time, capped at `now`.
pub fn federated_auth_time(
    asserted: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    max_age_secs: i64,
) -> Result<DateTime<Utc>, AuthTimeRefusal> {
    let asserted = asserted.ok_or(AuthTimeRefusal::Missing)?;
    if asserted > now + chrono::Duration::seconds(FEDERATED_AUTH_TIME_LEEWAY_SECS) {
        return Err(AuthTimeRefusal::InTheFuture);
    }
    let verified_at = asserted.min(now);
    if now - verified_at > chrono::Duration::seconds(max_age_secs) {
        return Err(AuthTimeRefusal::Stale);
    }
    Ok(verified_at)
}

async fn has_federated_link(
    db: &DbPool,
    user_id: Uuid,
    provider_key: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_identity
                        WHERE user_ref = $1 AND provider_key = $2)",
    )
    .bind(user_id)
    .bind(provider_key)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

async fn linked_user(
    db: &DbPool,
    provider_key: &str,
    subject: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT user_ref FROM user_identity
         WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind(provider_key)
    .bind(subject)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Starts the federated half of a challenge (rule 5): checks that the caller
/// may re-authenticate at `provider_key` for this challenge, and returns the
/// binding the provider flow must carry. Does not consume the challenge.
///
/// Requires a cookie session whose live family is the challenge's, the
/// challenge's user and operation, `federated` in both the challenge's factors
/// and the account's accepted factors now (so never for a TOTP-enrolled
/// account), and an OIDC identity linked for `provider_key`. Anything
/// else is `reauth_required`; API-key/S2S callers are `Forbidden`,
/// dead sessions `Unauthorized`, a non-elevation operation `NotFound`.
pub async fn begin_federated_step_up(
    stores: StepUpStores<'_>,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    protocol: FederatedProtocol,
    provider_key: &str,
    challenge_id: &str,
) -> Result<FederatedStepUp, AppError> {
    let session = session_of(caller)?;
    if operation.freshness() != Freshness::Elevation {
        return Err(AppError::NotFound);
    }
    live_family_state(
        stores.db,
        user_id,
        session,
        operation.max_age_secs(),
        stores.absolute_lifetime_secs,
    )
    .await?
    .ok_or(AppError::Unauthorized)?;

    let accepted = account_factors(stores.db, user_id).await?.accepted();
    let reject = || reauth_required(operation, &accepted);
    let Ok(challenge_id) = Uuid::parse_str(challenge_id) else {
        return Err(reject());
    };
    let Ok(Some(binding)) = load_binding(stores.redis, challenge_id).await else {
        return Err(reject());
    };
    if binding.user_id != user_id
        || binding.family_id != session.0
        || binding.operation != operation
        || !binding.factors.contains(&Factor::Federated)
        || !accepted.contains(&Factor::Federated)
    {
        return Err(reject());
    }
    if !has_federated_link(stores.db, user_id, provider_key).await? {
        return Err(reject());
    }

    Ok(FederatedStepUp {
        challenge_id,
        user_id,
        family_id: session.0,
        operation,
        protocol,
        provider_key: provider_key.to_owned(),
    })
}

/// Completes a federated step-up from a validated provider response (rule 5).
/// `step_up` must be the binding the provider flow's single-use state carried;
/// `subject` and `asserted_auth_time` must come from the token or assertion the
/// provider path just validated. Returns the new `elevated_until`.
///
/// Refuses, as `reauth_required` with no elevation written, when:
/// - the callback's protocol or provider is not the one the step-up started;
/// - the challenge is gone or no longer matches the binding, or `federated`
///   is no longer accepted;
/// - `subject` is not linked to the binding's user for this provider;
/// - [`federated_auth_time`] refuses the time (missing, future, stale).
///
/// A refusal after a matching challenge counts an attempt. Success consumes
/// the challenge atomically, then elevates the binding's family only, with the
/// provider's authentication time as the verification time.
pub async fn complete_federated_step_up(
    stores: StepUpStores<'_>,
    step_up: &FederatedStepUp,
    protocol: FederatedProtocol,
    provider_key: &str,
    subject: &str,
    asserted_auth_time: Option<DateTime<Utc>>,
) -> Result<DateTime<Utc>, AppError> {
    complete_federated_step_up_with(
        stores,
        step_up,
        protocol,
        provider_key,
        subject,
        asserted_auth_time,
        &attome_db::NoHook,
    )
    .await
}

/// [`complete_federated_step_up`], plus a [`attome_db::BeforeCommit`] hook that
/// runs in the elevation's transaction with the account id, so a caller's
/// security event commits with the elevation or neither does (D-062, BAU-26).
/// The plain function is this one with [`attome_db::NoHook`]; a refusal never
/// runs the hook.
pub async fn complete_federated_step_up_with(
    stores: StepUpStores<'_>,
    step_up: &FederatedStepUp,
    protocol: FederatedProtocol,
    provider_key: &str,
    subject: &str,
    asserted_auth_time: Option<DateTime<Utc>>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<DateTime<Utc>, AppError> {
    let accepted = account_factors(stores.db, step_up.user_id)
        .await?
        .accepted();
    let reject = || reauth_required(step_up.operation, &accepted);

    if step_up.protocol != protocol || step_up.provider_key != provider_key {
        return Err(reject());
    }
    let Ok(Some(binding)) = load_binding(stores.redis, step_up.challenge_id).await else {
        return Err(reject());
    };
    if binding.user_id != step_up.user_id
        || binding.family_id != step_up.family_id
        || binding.operation != step_up.operation
        || !binding.factors.contains(&Factor::Federated)
        || !accepted.contains(&Factor::Federated)
    {
        return Err(reject());
    }

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(stores.db)
        .await
        .map_err(AppError::internal)?;
    let verified_at = match linked_user(stores.db, provider_key, subject).await? {
        Some(owner) if owner == step_up.user_id => {
            federated_auth_time(asserted_auth_time, now, step_up.max_age_secs()).map_err(
                |refusal| {
                    tracing::warn!(
                        ?refusal,
                        operation = step_up.operation.as_str(),
                        "federated step-up authentication time refused"
                    );
                },
            )
        }
        _ => {
            tracing::warn!(
                operation = step_up.operation.as_str(),
                "federated step-up subject is not linked to the challenge's user"
            );
            Err(())
        }
    };
    let Ok(verified_at) = verified_at else {
        // The refusal stands whether or not the attempt could be recorded.
        let _ = challenge_step(stores.redis, step_up.challenge_id, Step::Fail).await;
        return Err(reject());
    };
    if !matches!(
        challenge_step(stores.redis, step_up.challenge_id, Step::Consume).await,
        Ok(true)
    ) {
        return Err(reject());
    }

    write_elevation(
        stores.db,
        step_up.user_id,
        SessionId(step_up.family_id),
        Factor::Federated,
        Some(verified_at),
        stores.absolute_lifetime_secs,
        hook,
    )
    .await
}

// ── Google step-up (BAU-8c, D-628; owner ruling 2026-09-25) ─────────────────

/// The challenge a Google step-up answers, after every check that needs no
/// Google token: a cookie session whose live family is the challenge's, the
/// challenge's user and operation, `federated` accepted by both the challenge
/// and the account now, and a Google account linked (`google_sub` set).
async fn google_challenge(
    stores: StepUpStores<'_>,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    challenge_id: &str,
) -> Result<(SessionId, Uuid, Vec<Factor>), AppError> {
    let session = session_of(caller)?;
    if operation.freshness() != Freshness::Elevation {
        return Err(AppError::NotFound);
    }
    live_family_state(
        stores.db,
        user_id,
        session,
        operation.max_age_secs(),
        stores.absolute_lifetime_secs,
    )
    .await?
    .ok_or(AppError::Unauthorized)?;

    let accepted = account_factors(stores.db, user_id).await?.accepted();
    let Ok(challenge_id) = Uuid::parse_str(challenge_id) else {
        return Err(reauth_required(operation, &accepted));
    };
    let Ok(Some(binding)) = load_binding(stores.redis, challenge_id).await else {
        return Err(reauth_required(operation, &accepted));
    };
    if binding.user_id != user_id
        || binding.family_id != session.0
        || binding.operation != operation
        || !binding.factors.contains(&Factor::Federated)
        || !accepted.contains(&Factor::Federated)
        || linked_google_sub(stores.db, user_id).await?.is_none()
    {
        return Err(reauth_required(operation, &accepted));
    }
    Ok((session, challenge_id, accepted))
}

async fn linked_google_sub(db: &DbPool, user_id: Uuid) -> Result<Option<String>, AppError> {
    let sub: Option<Option<String>> =
        sqlx::query_scalar("SELECT google_sub FROM user_account WHERE id = $1 AND is_active")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(sub.flatten())
}

/// Checks that the caller's own session may answer `challenge_id` with a Google
/// re-authentication, consuming nothing. The Google step-up route runs it
/// before verifying (and so consuming) the Google credential, so an ineligible
/// session contacts nothing. Refusals are those of
/// [`complete_google_step_up_with`] before its subject and time checks.
pub async fn check_google_step_up(
    stores: StepUpStores<'_>,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    challenge_id: &str,
) -> Result<(), AppError> {
    google_challenge(stores, caller, user_id, operation, challenge_id)
        .await
        .map(|_| ())
}

/// Completes a step-up challenge with a Google re-authentication (D-628, the
/// owner's 2026-09-25 ruling on BAU-8c): Google Identity Services is a POST
/// flow, not a configured OIDC provider, so the session-gated Google step-up
/// route verifies the credential locally (`accounts::verify_google_id_token`,
/// single-use) and hands its `sub` and `auth_time` here. Returns the new
/// `elevated_until`.
///
/// Refuses, as `reauth_required` with no elevation written, when the
/// challenge or session does not qualify (see [`check_google_step_up`]), when
/// `subject` is not the account's own `google_sub`, or when
/// [`federated_auth_time`] refuses the time (missing, future, stale for the
/// operation). A refusal after a matching challenge counts an attempt. Success
/// consumes the challenge atomically, then elevates the caller's family only,
/// with Google's authentication time as the verification time, and runs `hook`
/// in the elevation's transaction (D-062).
#[allow(clippy::too_many_arguments)]
pub async fn complete_google_step_up_with(
    stores: StepUpStores<'_>,
    caller: Caller,
    user_id: Uuid,
    operation: Operation,
    challenge_id: &str,
    subject: &str,
    asserted_auth_time: Option<DateTime<Utc>>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<DateTime<Utc>, AppError> {
    let (session, challenge_id, accepted) =
        google_challenge(stores, caller, user_id, operation, challenge_id).await?;
    let reject = || reauth_required(operation, &accepted);

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(stores.db)
        .await
        .map_err(AppError::internal)?;
    let verified_at = match linked_google_sub(stores.db, user_id).await? {
        Some(linked) if linked == subject => {
            federated_auth_time(asserted_auth_time, now, operation.max_age_secs()).map_err(
                |refusal| {
                    tracing::warn!(
                        ?refusal,
                        operation = operation.as_str(),
                        "google step-up authentication time refused"
                    );
                },
            )
        }
        _ => {
            tracing::warn!(
                operation = operation.as_str(),
                "google step-up subject is not the account's linked google account"
            );
            Err(())
        }
    };
    let Ok(verified_at) = verified_at else {
        // The refusal stands whether or not the attempt could be recorded.
        let _ = challenge_step(stores.redis, challenge_id, Step::Fail).await;
        return Err(reject());
    };
    if !matches!(
        challenge_step(stores.redis, challenge_id, Step::Consume).await,
        Ok(true)
    ) {
        return Err(reject());
    }

    write_elevation(
        stores.db,
        user_id,
        session,
        Factor::Federated,
        Some(verified_at),
        stores.absolute_lifetime_secs,
        hook,
    )
    .await
}

/// Writes a successful step-up onto the family's live rows (rule 3). Only
/// [`verify_challenge`], [`complete_federated_step_up`] and
/// [`complete_google_step_up_with`] call this, after a verified, consumed
/// challenge.
///
/// D-509's lock order: the account row `FOR UPDATE` first, then the token
/// rows, which the UPDATE locks. The verification time is `verified_at` capped
/// at `NOW()`, or `NOW()` for a local factor (`LEAST` ignores a NULL). It
/// becomes `auth_time`, the factor moves to the end of `amr`, and
/// `elevated_until` is the earlier of the verification time + 15 min and the
/// family's absolute end, which must still be in the future. A rotation racing
/// this can only copy the pre-step-up values, so it can lose the elevation but
/// never gain or extend it.
async fn write_elevation(
    db: &DbPool,
    user_id: Uuid,
    session: SessionId,
    factor: Factor,
    verified_at: Option<DateTime<Utc>>,
    absolute_secs: i64,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<DateTime<Utc>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let active: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_account
         WHERE id = $1 AND is_active
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if active.is_none() {
        return Err(AppError::Unauthorized);
    }

    let elevated: Vec<DateTime<Utc>> = sqlx::query_scalar(
        "UPDATE refresh_token
         SET auth_time = LEAST($6::timestamptz, NOW()),
             amr = array_append(array_remove(COALESCE(amr, ARRAY[]::text[]), $3::text), $3::text),
             elevated_until = LEAST(LEAST($6::timestamptz, NOW()) + make_interval(secs => $5::float8),
                                    family_started_at + make_interval(secs => $4::float8))
         WHERE family_id = $2 AND user_ref = $1
           AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
           AND family_started_at IS NOT NULL
           AND family_started_at + make_interval(secs => $4::float8) > NOW()
           AND LEAST(LEAST($6::timestamptz, NOW()) + make_interval(secs => $5::float8),
                     family_started_at + make_interval(secs => $4::float8)) > NOW()
         RETURNING elevated_until",
    )
    .bind(user_id)
    .bind(session.0)
    .bind(factor.amr())
    .bind(absolute_secs)
    .bind(ELEVATION_SECS)
    .bind(verified_at)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(elevated_until) = elevated.into_iter().max() else {
        return Err(AppError::Unauthorized);
    };
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(elevated_until)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_carry_d510_max_ages_and_freshness_sources() {
        assert_eq!(Operation::MfaDisable.max_age_secs(), 300);
        assert_eq!(Operation::RecoveryCodesRegenerate.max_age_secs(), 300);
        assert_eq!(Operation::IdentityLink.max_age_secs(), 300);
        assert_eq!(Operation::ApiKeyCreate.max_age_secs(), 900);
        assert_eq!(
            Operation::MfaDisable.freshness(),
            Freshness::InRequestFactor
        );
        assert_eq!(
            Operation::RecoveryCodesRegenerate.freshness(),
            Freshness::InRequestFactor
        );
        assert_eq!(Operation::IdentityLink.freshness(), Freshness::Elevation);
        assert_eq!(Operation::ApiKeyCreate.freshness(), Freshness::Elevation);
    }

    #[test]
    fn only_elevation_operations_parse_as_step_up_routes() {
        assert_eq!(
            Operation::from_step_up_route("identity_link"),
            Some(Operation::IdentityLink)
        );
        assert_eq!(
            Operation::from_step_up_route("api_key_create"),
            Some(Operation::ApiKeyCreate)
        );
        for not_step_up in [
            "mfa_disable",
            "recovery_codes_regenerate",
            "IdentityLink",
            "identity-link",
            "",
            "admin",
        ] {
            assert_eq!(Operation::from_step_up_route(not_step_up), None);
        }
    }

    #[test]
    fn factor_wire_names_and_amr_values_round_trip() {
        for (factor, wire, amr) in [
            (Factor::Totp, "totp", "otp"),
            (Factor::RecoveryCode, "recovery_code", "rcode"),
            (Factor::Password, "password", "pwd"),
            (Factor::Federated, "federated", "fed"),
        ] {
            assert_eq!(factor.as_str(), wire);
            assert_eq!(factor.amr(), amr);
            assert_eq!(Factor::from_wire(wire), Some(factor));
        }
        assert_eq!(Factor::from_wire("otp"), None);
        assert_eq!(Factor::from_wire("TOTP"), None);
    }

    #[test]
    fn accepted_factors_follow_rule_4() {
        let totp = AccountFactors {
            totp_enrolled: true,
            has_password: true,
            federated_linked: true,
        };
        assert_eq!(totp.accepted(), vec![Factor::Totp, Factor::RecoveryCode]);

        let federated_with_totp = AccountFactors {
            totp_enrolled: true,
            has_password: false,
            federated_linked: true,
        };
        assert_eq!(
            federated_with_totp.accepted(),
            vec![Factor::Totp, Factor::RecoveryCode],
            "a federated account with TOTP needs TOTP"
        );

        let password = AccountFactors {
            has_password: true,
            ..AccountFactors::default()
        };
        assert_eq!(password.accepted(), vec![Factor::Password]);

        let password_and_link = AccountFactors {
            has_password: true,
            federated_linked: true,
            ..AccountFactors::default()
        };
        assert_eq!(
            password_and_link.accepted(),
            vec![Factor::Password, Factor::Federated]
        );

        let federated_only = AccountFactors {
            federated_linked: true,
            ..AccountFactors::default()
        };
        assert_eq!(federated_only.accepted(), vec![Factor::Federated]);

        let google_only = AccountFactors::default();
        assert!(google_only.accepted().is_empty());
    }

    #[test]
    fn a_refusal_names_the_factors_or_totp_enrollment() {
        let AppError::ReauthRequired {
            operation,
            acceptable_factors,
        } = reauth_required(Operation::IdentityLink, &[Factor::Password])
        else {
            panic!("expected reauth_required");
        };
        assert_eq!(operation, "identity_link");
        assert_eq!(acceptable_factors, vec!["password"]);

        let AppError::ReauthRequired {
            acceptable_factors, ..
        } = reauth_required(Operation::ApiKeyCreate, &[])
        else {
            panic!("expected reauth_required");
        };
        assert_eq!(acceptable_factors, vec![TOTP_ENROLLMENT_REQUIRED]);
    }

    fn state(elevated: bool, fresh: bool, last: Option<&str>) -> FamilyState {
        FamilyState {
            elevated,
            fresh,
            last_method: last.map(str::to_owned),
        }
    }

    #[test]
    fn decide_needs_elevation_freshness_and_an_accepted_last_factor() {
        let totp = [Factor::Totp, Factor::RecoveryCode];
        let op = Operation::IdentityLink;
        assert!(decide(op, &state(true, true, Some("otp")), &totp).is_ok());
        assert!(decide(op, &state(true, true, Some("rcode")), &totp).is_ok());

        for rejected in [
            state(false, true, Some("otp")),
            state(true, false, Some("otp")),
            state(true, true, Some("pwd")),
            state(true, true, Some("fed")),
            state(true, true, None),
        ] {
            assert!(
                matches!(
                    decide(op, &rejected, &totp),
                    Err(AppError::ReauthRequired { .. })
                ),
                "{rejected:?} must not satisfy a TOTP-enrolled account"
            );
        }

        assert!(decide(op, &state(true, true, Some("pwd")), &[Factor::Password]).is_ok());
        assert!(
            decide(op, &state(true, true, Some("pwd")), &[]).is_err(),
            "an account with no factor is never satisfied"
        );
    }

    #[test]
    fn callers_without_a_family_never_reach_one() {
        let session = SessionId(Uuid::now_v7());
        assert_eq!(session_of(Caller::Session(session)).ok(), Some(session));
        assert!(matches!(
            session_of(Caller::NonSession),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn challenge_keys_are_namespaced_per_challenge() {
        let id = Uuid::parse_str("0190c3a4-0000-7000-8000-000000000001").unwrap();
        assert_eq!(
            challenge_key(id),
            "auth:step_up:0190c3a4-0000-7000-8000-000000000001"
        );
        assert_eq!(
            attempts_key(id),
            "auth:step_up:0190c3a4-0000-7000-8000-000000000001:attempts"
        );
    }

    fn unreachable_redis() -> Store {
        use fred::prelude::{Builder, RedisConfig};
        let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        Store::Redis(Builder::from_config(config).build_pool(1).unwrap())
    }

    /// Security contract §6: an unreachable challenge store rejects.
    #[tokio::test]
    async fn an_unreachable_challenge_store_fails_closed() {
        let redis = unreachable_redis();
        let id = Uuid::now_v7();
        assert!(load_binding(&redis, id).await.is_err());
        assert!(challenge_step(&redis, id, Step::Consume).await.is_err());
        assert!(challenge_step(&redis, id, Step::Fail).await.is_err());
    }

    fn at(offset_secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + offset_secs, 0).unwrap()
    }

    /// Rule 5: only a validated authentication time inside the operation's
    /// max age counts. A missing one is never replaced by callback time, and
    /// one beyond the clock-skew leeway is refused rather than capped.
    #[test]
    fn a_federated_authentication_time_must_be_present_fresh_and_not_in_the_future() {
        let now = at(0);
        assert_eq!(
            federated_auth_time(None, now, 300),
            Err(AuthTimeRefusal::Missing)
        );
        assert_eq!(federated_auth_time(Some(at(-300)), now, 300), Ok(at(-300)));
        assert_eq!(
            federated_auth_time(Some(at(-301)), now, 300),
            Err(AuthTimeRefusal::Stale)
        );
        assert_eq!(federated_auth_time(Some(at(-900)), now, 900), Ok(at(-900)));
        assert_eq!(
            federated_auth_time(Some(at(-901)), now, 900),
            Err(AuthTimeRefusal::Stale)
        );
        assert_eq!(
            federated_auth_time(Some(at(60)), now, 300),
            Ok(now),
            "a time inside the leeway is capped at now"
        );
        assert_eq!(
            federated_auth_time(Some(at(61)), now, 300),
            Err(AuthTimeRefusal::InTheFuture)
        );
    }

    #[test]
    fn a_federated_binding_round_trips_and_carries_its_operations_max_age() {
        for (operation, max_age) in [
            (Operation::IdentityLink, 300),
            (Operation::ApiKeyCreate, 900),
        ] {
            let binding = FederatedStepUp {
                challenge_id: Uuid::now_v7(),
                user_id: Uuid::now_v7(),
                family_id: Uuid::now_v7(),
                operation,
                protocol: FederatedProtocol::Oidc,
                provider_key: "entra".into(),
            };
            assert_eq!(binding.max_age_secs(), max_age);
            let json = serde_json::to_string(&binding).unwrap();
            assert_eq!(
                serde_json::from_str::<FederatedStepUp>(&json).unwrap(),
                binding
            );
        }
    }
}

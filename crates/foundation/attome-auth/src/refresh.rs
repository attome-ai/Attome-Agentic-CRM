//! Refresh-token flow backing `POST /api/v1/auth/refresh` (Plan 1.6a;
//! rotating families + reuse detection added by P-session-refresh-hardening,
//! D-129). Bearer token shape mirrors `api_key`'s public/secret split:
//! `"{public_id}.{secret}"` — `public_id` is an indexed O(1) lookup handle,
//! `secret` is verified against `refresh_token.secret_hash` (never
//! stored/compared in plaintext).
//!
//! **Secret hashing (D-317, D-500).** That hash is a peppered HMAC-SHA256, the
//! scheme D-112/D-118 built for `api_key.secret_hash` — reused here,
//! not reimplemented, because a refresh secret has the identical shape: 48
//! random alphanumeric characters from `generate_secret`, platform-generated
//! and never human-chosen, so a memory-hard KDF defends against nothing. User
//! passwords remain Argon2 (`crate::password`), untouched.
//!
//! Table: `refresh_token` (infrastructure, mutable — D-005), migration
//! `crates/server/migrations/0020_core_refresh_token.sql`, family/rotation
//! columns added by `0049_refresh_token_families.sql`, the family anchor and
//! the I13 columns by `0462_refresh_family_started_at.sql`. `revoked_at IS NOT
//! NULL` does this table's soft-delete duty; a separate `is_deleted` column
//! would be redundant with it.
//!
//! **Rotation model (D-129):** every redemption (`redeem`) is single-use —
//! it marks the presented token `used_at = NOW()` and issues a replacement
//! in the same `family_id` (one-row CAS, guidelines §2, no advisory lock
//! needed). A token presented a second time after it was already marked used
//! in a prior *committed* transaction is reuse: the entire family is revoked
//! and the request rejected, so a stolen-then-replayed token gets detected
//! instead of silently accepted. A losing race on the *same* in-flight token
//! (the CAS `rows_affected == 0` path) is treated as a clean 401, not a
//! family kill — see `redeem`'s doc comment for why that distinction matters.
//!
//! **Absolute lifetime (D-504, amending D-129).** A family also ends at a fixed
//! instant, however often it rotates. `family_started_at` is the family's
//! anchor: `issue` writes it from the database clock and every rotation copies
//! it verbatim. A redemption at or after `family_started_at + absolute_secs` is
//! rejected and writes nothing, and each replacement's `expires_at` is the
//! earlier of its idle deadline and that instant. Reuse detection also bumps
//! `auth_epoch`, so the account's
//! access tokens stop working too.

use attome_cache::Store;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use rand::distributions::{Alphanumeric, DistString};
use uuid::Uuid;

use crate::apikey_hash::{PepperRing, VerifyOutcome, dummy_hmac_hash, verify_api_key_secret};
use crate::auth_context::{AuthContext, AuthTime};
use crate::session::SessionId;

/// The two lifetimes a refresh family obeys (D-504), both in seconds.
///
/// Bound into SQL as exact seconds, never calendar days: a day-based interval
/// stretches across a daylight-saving change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshLifetimes {
    /// `auth.refresh_token_expiry_days`: how long one row stays valid without
    /// being rotated.
    pub idle_secs: i64,
    /// `auth.refresh_absolute_lifetime_days`: how long the whole family lives
    /// from its anchor, however often it rotates.
    pub absolute_secs: i64,
}

/// D-626: how long after a rotation a retry of the rotated token may still be
/// a lost response rather than reuse.
pub const REUSE_GRACE_SECS: i64 = 10;

/// D-626 rule 1. True when the presented (already used) token was rotated less
/// than `$2` seconds ago on the database clock and its replacement is still
/// unused and unrevoked.
const LOST_RESPONSE_RETRY_SQL: &str = "
    SELECT EXISTS (
        SELECT 1
        FROM refresh_token t
        JOIN refresh_token r ON r.id = t.replaced_by_ref
        WHERE t.id = $1
          AND t.used_at > NOW() - make_interval(secs => $2::float8)
          AND r.used_at IS NULL AND r.revoked_at IS NULL
    )";

fn generate_secret() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 48)
}

/// A newly issued refresh token and the family it starts.
#[derive(Debug)]
pub struct IssuedRefresh {
    /// The bearer string to set as the refresh cookie value.
    pub bearer: String,
    /// The new family's id, stamped as the session token's `sid`.
    pub family_id: Uuid,
}

/// Issues a brand-new refresh token for `user_id`, starting a fresh rotation
/// family. Used anywhere a session begins from scratch — login, register,
/// MFA completion, OIDC/Google callback — never for a rotation of an
/// existing token (that's `redeem`).
///
/// This is the only place a new family anchor is created (D-504 rule 1). The
/// anchor and `expires_at` both come from the database clock, and `expires_at`
/// is capped by the absolute lifetime from the start.
///
/// It is also the only place a family's authentication context is written
/// (D-510 rule 2): `context` records the credential verification that created
/// the session. A local verification's `auth_time` is the database clock at this
/// insert; an asserted one is stored but never later than it; an unknown one is
/// NULL. `elevated_until` stays NULL, so a new sign-in starts unelevated.
pub async fn issue(
    db: &DbPool,
    user_id: Uuid,
    context: &AuthContext,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
) -> Result<IssuedRefresh, AppError> {
    issue_with(db, user_id, context, lifetimes, ring, &attome_db::NoHook).await
}

/// [`issue`], plus a [`attome_db::BeforeCommit`] hook that runs in the insert's
/// transaction with the account id, so a caller's sign-in audit event commits
/// with the session or neither does (audit plan, D-062).
pub async fn issue_with(
    db: &DbPool,
    user_id: Uuid,
    context: &AuthContext,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<IssuedRefresh, AppError> {
    issue_inner(db, user_id, context, lifetimes, ring, None, None, hook)
        .await
        .map(|(issued, _)| issued)
}

/// What the access token minted together with a new family is signed and
/// stamped with (BAU-13c).
#[derive(Debug, Clone, Copy)]
pub struct AccessTokenSpec<'a> {
    /// `auth.jwt_secret`.
    pub jwt_ring: &'a KeyRing,
    /// `auth.jwt_issuer`.
    pub issuer: &'a str,
    /// The session audience.
    pub audience: &'a str,
    /// The access token's lifetime in seconds.
    pub expiry_secs: i64,
}

/// A new refresh family and the access token whose `sid` names it.
#[derive(Debug)]
pub struct IssuedSession {
    /// The refresh bearer to set as the refresh cookie value.
    pub bearer: String,
    /// The new family's id.
    pub family_id: Uuid,
    /// The access token to set as the session cookie value.
    pub access_token: String,
}

/// [`issue_with`], also minting the access token inside the family's
/// transaction (BAU-13c): if minting fails the family rolls back, so no
/// orphan refresh row is left for idle expiry to clean up. The token's epoch
/// is read in the same transaction.
#[allow(clippy::too_many_arguments)]
pub async fn issue_session_with(
    db: &DbPool,
    user_id: Uuid,
    context: &AuthContext,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
    access: &AccessTokenSpec<'_>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<IssuedSession, AppError> {
    issue_session_with_limit(db, user_id, context, lifetimes, ring, access, None, hook).await
}

/// The `Conflict` a sign-in meets when the person is at their session limit
/// and their roles refuse a new one (Q8-T6).
pub const SESSION_LIMIT_REACHED: &str = "session_limit_reached";

/// A person's concurrent-session limit (Q8-T6), from their roles'
/// `role_auth_policy` rows. Agent families (`client_kind = 'agent'`) never
/// count against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimit {
    /// The most live sessions the person may hold, the new one included.
    pub max_sessions: i32,
    /// At the limit, refuse the new sign-in (`true`) or end the sessions
    /// least recently used (`false`).
    pub refuse_new: bool,
}

/// [`issue_session_with`] under a concurrent-session limit (Q8-T6). The limit
/// is applied in the family's own transaction, after the account row's
/// update has locked it, so two sign-ins at once cannot both pass it: at the
/// limit it either ends the person's least recently active staff sessions
/// (activity, else start time) or refuses with
/// `Conflict(SESSION_LIMIT_REACHED)`, writing nothing.
#[allow(clippy::too_many_arguments)]
pub async fn issue_session_with_limit(
    db: &DbPool,
    user_id: Uuid,
    context: &AuthContext,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
    access: &AccessTokenSpec<'_>,
    limit: Option<SessionLimit>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<IssuedSession, AppError> {
    let (issued, access_token) = issue_inner(
        db,
        user_id,
        context,
        lifetimes,
        ring,
        Some(access),
        limit,
        hook,
    )
    .await?;
    let access_token =
        access_token.ok_or_else(|| AppError::internal("session issued without an access token"))?;
    Ok(IssuedSession {
        bearer: issued.bearer,
        family_id: issued.family_id,
        access_token,
    })
}

/// Live staff families of `user_id`: an unused, unrevoked, unexpired row.
const LIVE_STAFF_FAMILIES: &str = "SELECT family_id FROM refresh_token \
     WHERE user_ref = $1 AND revoked_at IS NULL AND used_at IS NULL AND expires_at > NOW() \
       AND client_kind <> 'agent'";

/// Applies `limit` inside the issuing transaction (the account row is
/// already locked by the caller's update).
async fn enforce_limit(
    tx: &mut attome_db::Tx<'_>,
    user_id: Uuid,
    limit: SessionLimit,
) -> Result<(), AppError> {
    if limit.max_sessions <= 0 {
        return Ok(());
    }
    let live: i64 = sqlx::query_scalar(&format!(
        "SELECT count(DISTINCT family_id) FROM ({LIVE_STAFF_FAMILIES}) live"
    ))
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let over = live - i64::from(limit.max_sessions) + 1;
    if over <= 0 {
        return Ok(());
    }
    if limit.refuse_new {
        return Err(AppError::Conflict(SESSION_LIMIT_REACHED));
    }
    sqlx::query(
        "UPDATE refresh_token SET revoked_at = NOW() \
          WHERE revoked_at IS NULL AND family_id IN ( \
                SELECT family_id FROM refresh_token \
                 WHERE user_ref = $1 AND revoked_at IS NULL AND used_at IS NULL \
                   AND expires_at > NOW() AND client_kind <> 'agent' \
                 ORDER BY COALESCE(last_activity_at, family_started_at) ASC, family_id ASC \
                 LIMIT $2)",
    )
    .bind(user_id)
    .bind(over)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn issue_inner(
    db: &DbPool,
    user_id: Uuid,
    context: &AuthContext,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
    access: Option<&AccessTokenSpec<'_>>,
    limit: Option<SessionLimit>,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<(IssuedRefresh, Option<String>), AppError> {
    let family_id = Uuid::now_v7(); // D-018: no exceptions, even for opaque tokens
    let public_id = Uuid::now_v7();
    let secret = generate_secret();
    let secret_hash = ring.hash(&secret);
    let (auth_time_at_issue, asserted_auth_time) = match context.auth_time() {
        AuthTime::AtIssue => (true, None),
        AuthTime::Asserted(at) => (false, Some(at)),
        AuthTime::Unknown => (false, None),
    };

    let mut tx = attome_db::tx::begin(db).await?;
    // BAU-12e (F11): `last_login` is stamped only when a session is issued,
    // after any second factor. The account row is written before the token
    // row (D-509 rule 6's order), and the epoch comes from the same row.
    let epoch: Option<i32> = sqlx::query_scalar(
        "UPDATE user_account SET last_login = now() WHERE id = $1 RETURNING auth_epoch",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let epoch = epoch.ok_or(AppError::Unauthorized)?;
    if let Some(limit) = limit {
        enforce_limit(&mut tx, user_id, limit).await?;
    }
    sqlx::query(
        "INSERT INTO refresh_token
             (user_ref, public_id, secret_hash, family_id, family_started_at, expires_at,
              auth_time, amr, oidc_provider, oidc_sid)
         VALUES ($1, $2, $3, $4, NOW(), NOW() + make_interval(secs => LEAST($5, $6)::float8),
                 CASE WHEN $7 THEN NOW() WHEN $8 > NOW() THEN NOW() ELSE $8 END, $9, $10, $11)",
    )
    .bind(user_id)
    .bind(public_id)
    .bind(&secret_hash)
    .bind(family_id)
    .bind(lifetimes.idle_secs)
    .bind(lifetimes.absolute_secs)
    .bind(auth_time_at_issue)
    .bind(asserted_auth_time)
    .bind(context.amr())
    .bind(context.oidc_provider())
    .bind(context.oidc_sid())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let access_token = match access {
        Some(spec) => Some(crate::accounts::mint_access_token(
            user_id,
            family_id,
            epoch,
            spec.jwt_ring,
            spec.issuer,
            spec.audience,
            spec.expiry_secs,
        )?),
        None => None,
    };
    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        IssuedRefresh {
            bearer: format!("{public_id}.{secret}"),
            family_id,
        },
        access_token,
    ))
}

/// Redeems a presented refresh token: validates it (live, not expired/
/// revoked, secret matches, owning user still active — same checks the old
/// `validate` ran), then rotates it — marks it used and inserts a
/// replacement in the same family — in one transaction. Returns the owning
/// user's id and the new bearer token to set as the replacement cookie.
///
/// **Reuse detection.** If the presented token was already marked used by a
/// *prior, already-committed* redemption, this is not a race — it's either
/// the original owner replaying a stale cookie after a thief already rotated
/// it, or the reverse. Since the two cases are indistinguishable from here,
/// the entire family is revoked (every token descended from the same
/// original issuance) and the request rejected — both parties are forced to
/// re-login, which is the correct fail-safe. The same transaction bumps the
/// account's `auth_epoch`, and the epoch cache on `redis` is invalidated after
/// commit, so an access token already minted from the family stops working on
/// its next request (D-504 rule 9). If that transaction fails, so does the
/// request.
///
/// **Lost-response grace (D-626, amending D-504 rule 9).** A used token
/// presented again less than [`REUSE_GRACE_SECS`] after its rotation, while
/// its replacement is still unused, gets a plain 401 and writes nothing: one
/// lost refresh response must not log the account out everywhere. After the
/// window, or once the replacement has been redeemed, it is reuse as above.
///
/// **Legitimate concurrent double-redeem** (the same still-unused token
/// presented twice at once — a flaky network retry, or two browser tabs
/// racing) is a different case, handled by the one-row CAS UPDATE below: the
/// loser sees `rows_affected == 0` and gets a plain 401 (re-login), not a
/// family kill — the token was never used in a transaction that committed
/// before this one started, so there is nothing to treat as theft.
///
/// **Absolute lifetime (D-504).** The lookup admits a row only while its family
/// is younger than `lifetimes.absolute_secs`, and the replacement is inserted
/// only if that still holds at insert time, both on the database clock. A
/// family therefore expires at `NOW() >= family_started_at + absolute_secs`
/// however often it rotated, and an expired family gets a plain 401 that
/// writes nothing. The replacement copies the presented row's anchor, and its
/// `auth_time`, `amr` and `elevated_until` unchanged.
pub async fn redeem_session(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
) -> Result<RedeemedRefresh, AppError> {
    match redeem_session_outcome(db, redis, presented, lifetimes, ring).await? {
        RedeemOutcome::Rotated(redeemed) => Ok(redeemed),
        RedeemOutcome::ReuseRevoked { .. } => Err(AppError::Unauthorized),
    }
}

/// What [`redeem_session_outcome`] did with a presented token.
#[derive(Debug)]
pub enum RedeemOutcome {
    /// The token rotated normally.
    Rotated(RedeemedRefresh),
    /// The token had already been redeemed: its whole family was revoked and
    /// the account's epoch bumped (committed). The caller must reject the
    /// request exactly as [`redeem_session`] does; the variant exists so the
    /// caller can record the revocation (audit plan 3.4, `SessionRevoked`).
    ReuseRevoked { user_id: Uuid },
}

/// [`redeem_session`], but reporting a reuse revocation as
/// [`RedeemOutcome::ReuseRevoked`] instead of folding it into `Unauthorized`.
/// Every other rejection is still an error.
pub async fn redeem_session_outcome(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
) -> Result<RedeemOutcome, AppError> {
    redeem_session_outcome_with(db, redis, presented, lifetimes, ring, &attome_db::NoHook).await
}

/// [`redeem_session_outcome`], plus a [`attome_db::BeforeCommit`] hook that
/// runs inside the reuse-revocation transaction with the account id, so the
/// caller's revocation event commits with the revoked family (D-062). A
/// normal rotation does not run it.
pub async fn redeem_session_outcome_with(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
    reuse_hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<RedeemOutcome, AppError> {
    let (public_id_str, secret) = presented.split_once('.').ok_or(AppError::Unauthorized)?;
    let public_id: Uuid = public_id_str.parse().map_err(|_| AppError::Unauthorized)?;

    // (id, user_ref, secret_hash, used_at, family_id, family_started_at,
    //  auth_time, amr, elevated_until)
    type RefreshTokenRow = (
        Uuid,
        Uuid,
        String,
        Option<DateTime<Utc>>,
        Uuid,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<Vec<String>>,
        Option<DateTime<Utc>>,
    );
    let row: Option<RefreshTokenRow> = sqlx::query_as(
        "SELECT t.id, t.user_ref, t.secret_hash, t.used_at, t.family_id,
                t.family_started_at, t.auth_time, t.amr, t.elevated_until
         FROM refresh_token t
         JOIN user_account u ON u.id = t.user_ref
             AND u.is_active = TRUE
         WHERE t.public_id = $1 AND t.revoked_at IS NULL AND t.expires_at > NOW()
           AND t.family_started_at + make_interval(secs => $2::float8) > NOW()
           -- Q8-T2: the role's own limits, when the family carries them.
           AND (t.absolute_secs IS NULL
                OR t.family_started_at + make_interval(secs => t.absolute_secs) > NOW())
           AND (t.idle_secs IS NULL
                OR COALESCE(t.last_activity_at, t.created_at)
                   + make_interval(secs => t.idle_secs) > NOW())",
    )
    .bind(public_id)
    .bind(lifetimes.absolute_secs)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    // Same timing-safety shape as accounts::login — verify on both the hit and
    // miss paths so the cost doesn't leak whether `public_id` exists.
    //
    // `OkNeedsRehash` (a row under a retired pepper id) is deliberately
    // treated as plain success rather than triggering a rewrite:
    // this token is being consumed and replaced by the rotation below (D-129),
    // so the replacement row is written in the current format anyway. Refresh
    // tokens converge through rotation; only long-lived api-key rows need
    // `resolve_api_key`'s explicit rehash-on-use.
    let row = match row {
        Some(row) => {
            let outcome = verify_api_key_secret(ring, secret, &row.2).await?;
            if outcome == VerifyOutcome::Fail {
                return Err(AppError::Unauthorized);
            }
            row
        }
        None => {
            let _ = verify_api_key_secret(ring, secret, dummy_hmac_hash()).await?;
            return Err(AppError::Unauthorized);
        }
    };
    let (
        token_id,
        user_id,
        _,
        used_at,
        family_id,
        family_started_at,
        auth_time,
        amr,
        elevated_until,
    ) = row;

    if used_at.is_some() {
        // D-626: a retry within the grace window whose replacement was never
        // redeemed is a lost response, not theft — plain 401, nothing written.
        let lost_response: bool = sqlx::query_scalar(LOST_RESPONSE_RETRY_SQL)
            .bind(token_id)
            .bind(REUSE_GRACE_SECS)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
        if lost_response {
            return Err(AppError::Unauthorized);
        }
        let mut tx = attome_db::tx::begin(db).await?;
        // D-509 rule 6: lock the account row before any token row, the order a
        // password reset also takes, so a reset confirm and a reuse detection
        // for the same account cannot deadlock.
        sqlx::query("SELECT 1 FROM user_account WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = NOW()
             WHERE revoked_at IS NULL AND (id = $2 OR family_id = $1)",
        )
        .bind(family_id)
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        crate::epoch::bump_in_tx(&mut tx, user_id).await?;
        reuse_hook.before_commit(&mut tx, &user_id).await?;
        tx.commit().await.map_err(AppError::internal)?;
        crate::epoch::invalidate_cache(redis, user_id).await;
        tracing::warn!(
            user_id = %user_id,
            token_id = %token_id,
            "refresh token reuse detected — family revoked and auth_epoch bumped"
        );
        return Ok(RedeemOutcome::ReuseRevoked { user_id });
    }

    let new_family_id = family_id;
    let new_public_id = Uuid::now_v7();
    let new_secret = generate_secret();
    let new_secret_hash = ring.hash(&new_secret);

    let mut tx = attome_db::tx::begin(db).await?;

    let anchor = family_started_at;

    // D-504 rules 3-5: the replacement exists only while the family is still
    // inside its absolute lifetime, checked again here on the database clock.
    // No row back means the family expired; rolling back makes the rejection
    // write nothing.
    let new_token_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO refresh_token
             (user_ref, public_id, secret_hash, family_id, family_started_at,
              auth_time, amr, elevated_until, expires_at,
              idle_secs, absolute_secs, last_activity_at, oidc_provider, oidc_sid)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8,
                LEAST(NOW() + make_interval(secs => $9::float8),
                      $5 + make_interval(secs => $10::float8)),
                -- A rotation is not activity: the family keeps its last real use.
                o.idle_secs, o.absolute_secs, COALESCE(o.last_activity_at, o.created_at),
                -- Q1-T10: the family stays tied to its provider session.
                o.oidc_provider, o.oidc_sid
           FROM refresh_token o
          WHERE o.id = $11 AND $5 + make_interval(secs => $10::float8) > NOW()
         RETURNING id",
    )
    .bind(user_id)
    .bind(new_public_id)
    .bind(&new_secret_hash)
    .bind(new_family_id)
    .bind(anchor)
    .bind(auth_time)
    .bind(amr)
    .bind(elevated_until)
    .bind(lifetimes.idle_secs)
    .bind(lifetimes.absolute_secs)
    // Q8-T2: the rotated token keeps the family's role limits.
    .bind(token_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(new_token_id) = new_token_id else {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Unauthorized);
    };

    // One-row CAS (guidelines §2) — only marks the presented token used if it
    // is STILL unused right now. A concurrent redeemer of the same token that
    // committed first wins; this one loses the race and rolls back (dropping
    // the replacement row it just inserted too), rather than leaving an
    // orphaned extra family member.
    let rows_affected = sqlx::query(
        "UPDATE refresh_token SET used_at = NOW(), replaced_by_ref = $1
         WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(new_token_id)
    .bind(token_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows_affected == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Unauthorized);
    }

    tx.commit().await.map_err(AppError::internal)?;

    Ok(RedeemOutcome::Rotated(RedeemedRefresh {
        user_id,
        family_id: new_family_id,
        bearer: format!("{new_public_id}.{new_secret}"),
    }))
}

/// The result of a successful rotation.
#[derive(Debug)]
pub struct RedeemedRefresh {
    /// The account the family belongs to.
    pub user_id: Uuid,
    /// The family the replacement belongs to, stamped as the new session
    /// token's `sid`.
    pub family_id: Uuid,
    /// The replacement bearer string to set as the refresh cookie value.
    pub bearer: String,
}

/// [`redeem_session`], returning only the account id and the replacement
/// bearer. Kept for callers that do not mint a session token.
pub async fn redeem(
    db: &DbPool,
    redis: &Store,
    presented: &str,
    lifetimes: RefreshLifetimes,
    ring: &PepperRing,
) -> Result<(Uuid, String), AppError> {
    redeem_session(db, redis, presented, lifetimes, ring)
        .await
        .map(|redeemed| (redeemed.user_id, redeemed.bearer))
}

/// The authentication context a live refresh family holds (D-510 rule 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// When the credential that created or last elevated the family was
    /// verified. `None` means no usable time: lowest assurance.
    pub auth_time: Option<DateTime<Utc>>,
    /// The verification methods recorded on the family (`pwd`, `otp`, `rcode`,
    /// `fed`). Empty for a family created before 2.1a.
    pub amr: Vec<String>,
    /// Until when the family is elevated by a step-up. `None` for a family that
    /// never stepped up, including every new sign-in.
    pub elevated_until: Option<DateTime<Utc>>,
}

/// Reads the authentication context of the session `session` belongs to, from
/// the family's live row: unused, unrevoked, unexpired, inside its absolute
/// lifetime (D-504) and owned by `user_id`. `None` when no such row exists, so
/// a session id can never surface another account's family or a dead one.
///
/// This row, not any token claim, is the authoritative source for freshness and
/// elevation.
pub async fn session_context(
    db: &DbPool,
    user_id: Uuid,
    session: SessionId,
    absolute_secs: i64,
) -> Result<Option<SessionContext>, AppError> {
    type ContextRow = (
        Option<DateTime<Utc>>,
        Option<Vec<String>>,
        Option<DateTime<Utc>>,
    );
    let row: Option<ContextRow> = sqlx::query_as(
        "SELECT auth_time, amr, elevated_until
         FROM refresh_token
         WHERE family_id = $1 AND user_ref = $2
           AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
           AND family_started_at + make_interval(secs => $3::float8) > NOW()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(session.0)
    .bind(user_id)
    .bind(absolute_secs)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|(auth_time, amr, elevated_until)| SessionContext {
        auth_time,
        amr: amr.unwrap_or_default(),
        elevated_until,
    }))
}

/// Revokes a presented refresh token (logout). A malformed, unknown,
/// already-revoked or wrong-secret token is a no-op — logout must never fail
/// just because there was nothing live to revoke, and a bearer must prove
/// possession of the secret, not just know the `public_id` (BAU-11).
pub async fn revoke(db: &DbPool, presented: &str, ring: &PepperRing) -> Result<(), AppError> {
    revoke_returning_user(db, presented, ring).await.map(|_| ())
}

/// [`revoke`], returning the owning account when a live token was actually
/// revoked (`None` for a malformed, unknown, already-revoked or wrong-secret
/// token), so the logout route can record whose session ended.
pub async fn revoke_returning_user(
    db: &DbPool,
    presented: &str,
    ring: &PepperRing,
) -> Result<Option<Uuid>, AppError> {
    revoke_returning_user_with(db, presented, ring, &attome_db::NoHook).await
}

/// [`revoke_returning_user`], plus a [`attome_db::BeforeCommit`] hook that runs
/// in the revocation's transaction with the owning account, only when a live
/// token was actually revoked (D-062).
///
/// The secret is verified before the transaction opens.
pub async fn revoke_returning_user_with(
    db: &DbPool,
    presented: &str,
    ring: &PepperRing,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    Ok(revoke_session_with(db, presented, ring, hook)
        .await?
        .map(|session| session.user_id))
}

/// A refresh token sign-out revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedSession {
    pub user_id: Uuid,
    /// Q1-T10: the OIDC provider the family signed in through, so sign-out
    /// can end that provider's session too.
    pub oidc_provider: Option<String>,
}

/// [`revoke_returning_user_with`], also answering which OIDC provider (if
/// any) the family signed in through.
pub async fn revoke_session_with(
    db: &DbPool,
    presented: &str,
    ring: &PepperRing,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<Option<RevokedSession>, AppError> {
    let Some((public_id_str, secret)) = presented.split_once('.') else {
        return Ok(None);
    };
    let Ok(public_id) = public_id_str.parse::<Uuid>() else {
        return Ok(None);
    };

    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, secret_hash FROM refresh_token
         WHERE public_id = $1 AND revoked_at IS NULL",
    )
    .bind(public_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((token_id, secret_hash)) = row else {
        return Ok(None);
    };
    if verify_api_key_secret(ring, secret, &secret_hash).await? == VerifyOutcome::Fail {
        return Ok(None);
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let revoked: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "UPDATE refresh_token SET revoked_at = NOW()
         WHERE id = $1 AND revoked_at IS NULL
         RETURNING user_ref, oidc_provider",
    )
    .bind(token_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some((user_id, _)) = &revoked {
        hook.before_commit(&mut tx, user_id).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(revoked.map(|(user_id, oidc_provider)| RevokedSession {
        user_id,
        oidc_provider,
    }))
}

/// Q1-T10: whose sessions a provider's back-channel logout ends.
#[derive(Debug, Clone, Copy)]
pub enum OidcLogoutTarget<'a> {
    /// The families signed in under this provider session, of `user` only
    /// when the token also named a subject.
    Sid { sid: &'a str, user: Option<Uuid> },
    /// Every family `user` signed in through the provider.
    User(Uuid),
}

/// What a back-channel logout did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcLogoutOutcome {
    /// The token's id was seen before; nothing was changed.
    Replayed,
    /// These people's matching families were revoked and their epochs
    /// bumped. Possibly none: the provider may know a session Attome never
    /// had, or one already ended.
    Ended(Vec<Uuid>),
}

/// Q1-T10: ends the refresh families a provider's verified back-channel
/// logout names, in one transaction: claims the token id `replay_key` in
/// `auth_jti_denylist` for `replay_ttl_secs` (a second delivery finds it and
/// changes nothing), revokes the families signed in through `provider` that
/// `target` names, bumps each affected person's `auth_epoch` so their live
/// access tokens stop at once, and runs `hook` per person before the commit.
/// Only families from that provider end: a provider speaks for its own
/// sessions, not for a password sign-in. The caller drops each person's
/// cached epoch after the commit ([`crate::epoch::invalidate_cache`]).
pub async fn revoke_oidc_sessions(
    db: &DbPool,
    provider: &str,
    target: OidcLogoutTarget<'_>,
    replay_key: Uuid,
    replay_ttl_secs: i64,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<OidcLogoutOutcome, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let claimed = sqlx::query(
        "INSERT INTO auth_jti_denylist (jti, expires_at)
         VALUES ($1, NOW() + make_interval(secs => $2::float8))
         ON CONFLICT (jti) DO NOTHING",
    )
    .bind(replay_key)
    .bind(replay_ttl_secs)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(OidcLogoutOutcome::Replayed);
    }
    let (sid, user) = match target {
        OidcLogoutTarget::Sid { sid, user } => (Some(sid), user),
        OidcLogoutTarget::User(user) => (None, Some(user)),
    };
    // The accounts are locked before their token rows, the order a sign-in
    // takes them in (D-509 rule 6), so the two cannot deadlock.
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM refresh_token
          WHERE oidc_provider = $1 AND revoked_at IS NULL
            AND ($2::text IS NULL OR oidc_sid = $2)
            AND ($3::uuid IS NULL OR user_ref = $3)",
    )
    .bind(provider)
    .bind(sid)
    .bind(user)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("SELECT id FROM user_account WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(&candidates)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut users: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE refresh_token SET revoked_at = NOW()
          WHERE oidc_provider = $1 AND revoked_at IS NULL
            AND ($2::text IS NULL OR oidc_sid = $2)
            AND user_ref = ANY($3)
         RETURNING user_ref",
    )
    .bind(provider)
    .bind(sid)
    .bind(&candidates)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    users.sort_unstable();
    users.dedup();
    for user_id in &users {
        crate::epoch::bump_in_tx(&mut tx, *user_id).await?;
        hook.before_commit(&mut tx, user_id).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(OidcLogoutOutcome::Ended(users))
}

/// BAU-13a (F15): one bounded batch of dead refresh families. A family is
/// dead when **every** row is revoked or expired more than `$1` seconds ago,
/// so a live family (any unrevoked, unexpired row) keeps every row, used ones
/// included. Family rows reference each other only (a rotation keeps the
/// family), and a statement-level FK check sees them all gone together.
const PRUNE_DEAD_FAMILIES_SQL: &str = "
    WITH dead AS (
        SELECT family_id
        FROM refresh_token
        GROUP BY family_id
        HAVING bool_and(
            (revoked_at IS NOT NULL
             AND revoked_at < NOW() - make_interval(secs => $1::float8))
            OR expires_at < NOW() - make_interval(secs => $1::float8))
        LIMIT $2
    )
    DELETE FROM refresh_token t
    USING dead d
    WHERE t.family_id = d.family_id";

/// Deletes up to `max_families` dead refresh families (see
/// [`PRUNE_DEAD_FAMILIES_SQL`]) whose last row died more than
/// `retention_secs` ago, returning the number of rows deleted. Safe to run
/// concurrently with redemption: a family a redeem could still rotate has a
/// live row, so it is never dead. The persistent-queue job calls it in a loop
/// until it deletes nothing.
pub async fn prune_dead_families(
    db: &DbPool,
    retention_secs: i64,
    max_families: i64,
) -> Result<u64, AppError> {
    sqlx::query(PRUNE_DEAD_FAMILIES_SQL)
        .bind(retention_secs)
        .bind(max_families)
        .execute(db)
        .await
        .map(|done| done.rows_affected())
        .map_err(AppError::internal)
}

const REVOKE_ALL_FOR_USER_SQL: &str = "UPDATE refresh_token SET revoked_at = NOW()
     WHERE user_ref = $1 AND revoked_at IS NULL";

/// Revokes every live refresh token for `user_id` (admin disable,
/// P-account-state-enforcement; a password reset uses
/// [`revoke_all_for_user_in_tx`] instead). Deliberately bulk, not a per-user
/// Redis stamp checked on every request: a currently-live access token
/// (default 15 min, guidelines §7) still works until it naturally expires
/// (unless `auth_epoch` closes that window — see `attome_auth::epoch`), but no
/// new one can be minted without re-authenticating. Rotation families don't
/// change this — every row (any family) for `user_id` is revoked regardless
/// of lineage.
pub async fn revoke_all_for_user(db: &DbPool, user_id: Uuid) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    revoke_all_for_user_in_tx(&mut tx, user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Transactional form of [`revoke_all_for_user`]. `reset::confirm` calls it so
/// the revocation commits or rolls back together with the new password, the
/// consumed token and the epoch bump (D-509). The caller's transaction must
/// already hold the account row lock (D-509 rule 6).
pub async fn revoke_all_for_user_in_tx(
    tx: &mut attome_db::Tx<'_>,
    user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(REVOKE_ALL_FOR_USER_SQL)
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    // Q5-T4: a remembered browser goes with the sessions.
    sqlx::query(crate::remembered_device::REVOKE_ALL_SQL)
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool that never actually connects — valid for exercising the
    /// early-return parsing paths below, which return before touching the
    /// database at all. Any code path that would actually run a query
    /// against this pool must not be reached by these tests.
    fn unconnected_pool() -> DbPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@127.0.0.1:1/db")
            .expect("connect_lazy must not touch the network")
    }

    /// Same idea for Redis: built, never connected, never reached.
    fn unconnected_redis() -> Store {
        let config = fred::prelude::RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        attome_cache::Store::Redis(
            fred::prelude::Builder::from_config(config)
                .build_pool(1)
                .unwrap(),
        )
    }

    /// Both parsing tests below return before the ring is ever consulted, so
    /// any well-formed ring will do.
    fn test_ring() -> PepperRing {
        PepperRing::new(0, "refresh-unit-test-pepper-0123456789abcdef", &[])
    }

    fn test_lifetimes() -> RefreshLifetimes {
        RefreshLifetimes {
            idle_secs: 3600,
            absolute_secs: 30 * 86_400,
        }
    }

    #[tokio::test]
    async fn redeem_rejects_a_token_with_no_dot_separator_without_querying_the_db() {
        let db = unconnected_pool();
        let result = redeem(
            &db,
            &unconnected_redis(),
            "not-a-valid-token-shape",
            test_lifetimes(),
            &test_ring(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn redeem_rejects_a_non_uuid_public_id_without_querying_the_db() {
        let db = unconnected_pool();
        let result = redeem(
            &db,
            &unconnected_redis(),
            "not-a-uuid.somesecret",
            test_lifetimes(),
            &test_ring(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn revoke_is_a_no_op_for_a_token_with_no_dot_separator() {
        let db = unconnected_pool();
        assert!(
            revoke(&db, "not-a-valid-token-shape", &test_ring())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn revoke_is_a_no_op_for_a_non_uuid_public_id() {
        let db = unconnected_pool();
        assert!(
            revoke(&db, "not-a-uuid.somesecret", &test_ring())
                .await
                .is_ok()
        );
    }
}

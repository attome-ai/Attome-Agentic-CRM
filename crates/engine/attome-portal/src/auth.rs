//! Portal authentication, business logic only (D-573, D-576 item 3, R10).
//! Every function runs on the caller's transaction; the HTTP layer
//! ([`crate::router`]) writes the security event and any email into the same
//! transaction and commits.
//!
//! Nothing here reads or writes `user_account`: a portal user's
//! identity is `webportal_user`, its secrets `webportal_credential`.

use attome_auth::apikey_hash::PepperRing;
use attome_config::KeyRing;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::onetime::{self, Kind};
use crate::provision::{MfaPolicy, PortalDetail, PortalType, PortalUserStatus};
use crate::{mfa, recovery, refresh};

/// R10 lockout: this many consecutive failures lock the account for
/// [`LOCKOUT_MINUTES`].
pub const LOCKOUT_THRESHOLD: i32 = 5;
pub const LOCKOUT_MINUTES: i64 = 15;
/// A second reset link is not issued within this window (anti mail-bombing,
/// per account, without Redis).
pub const RESET_REQUEST_COOLDOWN_SECS: i64 = 60;

/// A live, enabled portal that has users, by keyword. `None` for every other
/// case (unknown, soft-deleted, disabled, anonymous), so callers answer them
/// all with the same 404.
pub async fn resolve_portal_with_users(
    conn: &mut PgConnection,
    keyword: &str,
) -> Result<Option<PortalDetail>, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM webportal \
         WHERE keyword = $1 AND is_active IS NOT FALSE AND is_enabled IS TRUE",
    )
    .bind(keyword.to_ascii_lowercase())
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = id else { return Ok(None) };
    let portal = crate::provision::load_portal(conn, id).await?;
    Ok((portal.is_enabled && portal.portal_type != PortalType::Anonymous).then_some(portal))
}

struct Account {
    user_id: Uuid,
    status: PortalUserStatus,
    password_hash: Option<String>,
    email_verified: bool,
    epoch: i32,
    failed: i32,
    locked_until: Option<DateTime<Utc>>,
    mfa_enabled: bool,
    mfa_secret_enc: Option<String>,
    mfa_last_step: Option<i64>,
}

type AccountRow = (
    Uuid,
    String,
    Option<String>,
    bool,
    i32,
    i32,
    Option<DateTime<Utc>>,
    bool,
    Option<String>,
    Option<i64>,
);

const ACCOUNT_SELECT: &str = "SELECT u.id, u.status, c.password_hash, c.email_verified, c.auth_epoch, \
            c.failed_login_count, c.locked_until, c.mfa_enabled, c.mfa_secret_enc, c.mfa_last_step \
     FROM webportal_user u \
     JOIN webportal_credential c ON c.webportal_user_id = u.id";

fn account_from(r: AccountRow) -> Result<Account, AppError> {
    let status = match r.1.as_str() {
        "invited" => PortalUserStatus::Invited,
        "active" => PortalUserStatus::Active,
        "disabled" => PortalUserStatus::Disabled,
        other => {
            return Err(AppError::internal(format!(
                "webportal_user.status holds an unknown value '{other}'"
            )));
        }
    };
    Ok(Account {
        user_id: r.0,
        status,
        password_hash: r.2,
        email_verified: r.3,
        epoch: r.4,
        failed: r.5,
        locked_until: r.6,
        mfa_enabled: r.7,
        mfa_secret_enc: r.8,
        mfa_last_step: r.9,
    })
}

/// The live account for a login identifier on `portal` (D-777: an email
/// when it contains `@`, otherwise a username), row-locked for the rest of
/// the transaction so concurrent attempts on one account serialize.
async fn account_by_login(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    login: &str,
) -> Result<Option<Account>, AppError> {
    let (filter, key) = match crate::provision::login_key(login) {
        crate::provision::LoginKey::Email(email) => {
            ("u.webportal_ref = $1 AND lower(u.email) = $2", email)
        }
        crate::provision::LoginKey::Username(name) => {
            ("c.webportal_id = $1 AND c.login_username_lower = $2", name)
        }
    };
    let row: Option<AccountRow> = sqlx::query_as(&format!(
        "{ACCOUNT_SELECT} WHERE {filter} AND u.is_active IS NOT FALSE FOR UPDATE OF c"
    ))
    .bind(webportal_id)
    .bind(key)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    row.map(account_from).transpose()
}

async fn account_by_id(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    user_id: Uuid,
) -> Result<Option<Account>, AppError> {
    let row: Option<AccountRow> = sqlx::query_as(&format!(
        "{ACCOUNT_SELECT} WHERE u.id = $1 AND u.webportal_ref = $2 \
           AND u.is_active IS NOT FALSE FOR UPDATE OF c"
    ))
    .bind(user_id)
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    row.map(account_from).transpose()
}

pub enum LoginOutcome {
    Success {
        user_id: Uuid,
        epoch: i32,
        family: refresh::Issued,
        /// The portal requires MFA and the user has not enrolled, or has just
        /// signed in with a recovery code: the session reaches only the MFA
        /// enrollment and logout routes (D-588 item 1).
        mfa_enrollment_required: bool,
        /// The second factor was a recovery code, now spent.
        recovery_code_used: bool,
    },
    /// Password correct, the user is enrolled, and no (or no valid) code was
    /// given. A missing code does not count as a failed attempt.
    MfaRequired {
        user_id: Uuid,
    },
    /// Wrong or unknown email or password, unverified, not active, or a bad
    /// code. `user_id` is set when an account was matched (for the audit
    /// event); the HTTP response is identical either way.
    Failed {
        user_id: Option<Uuid>,
    },
    LockedOut {
        user_id: Uuid,
    },
}

impl std::fmt::Debug for LoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginOutcome").finish_non_exhaustive()
    }
}

async fn record_failure(conn: &mut PgConnection, account: &Account) -> Result<(), AppError> {
    let failed = account.failed + 1;
    let (count, locked_until) = if failed >= LOCKOUT_THRESHOLD {
        (0, Some(Utc::now() + Duration::minutes(LOCKOUT_MINUTES)))
    } else {
        (failed, None)
    };
    sqlx::query(
        "UPDATE webportal_credential SET failed_login_count = $2, \
           locked_until = COALESCE($3, locked_until), updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(account.user_id)
    .bind(count)
    .bind(locked_until)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

pub async fn login(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    mfa_ring: &KeyRing,
    portal: &PortalDetail,
    login: &str,
    password: &str,
    code: Option<&str>,
) -> Result<LoginOutcome, AppError> {
    let Some(account) = account_by_login(conn, portal.id, login).await? else {
        attome_auth::password::verify_against_dummy_async(password).await?;
        return Ok(LoginOutcome::Failed { user_id: None });
    };
    if account.locked_until.is_some_and(|until| until > Utc::now()) {
        return Ok(LoginOutcome::LockedOut {
            user_id: account.user_id,
        });
    }
    let password_ok = match account.password_hash.as_deref() {
        Some(hash) => attome_auth::verify_password_async(password, hash).await?,
        None => {
            attome_auth::password::verify_against_dummy_async(password).await?;
            false
        }
    };
    if !password_ok {
        record_failure(conn, &account).await?;
        return Ok(LoginOutcome::Failed {
            user_id: Some(account.user_id),
        });
    }
    if account.status != PortalUserStatus::Active || !account.email_verified {
        return Ok(LoginOutcome::Failed {
            user_id: Some(account.user_id),
        });
    }
    finish_login(conn, pepper, mfa_ring, portal, &account, code).await
}

/// Completes an OIDC sign-in whose account has TOTP enabled (D-588 item 3):
/// the identity provider stood in for the password, and `code` (TOTP or a
/// recovery code) is still required. Same lockout, replay and session rules
/// as a password login.
pub async fn second_factor(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    mfa_ring: &KeyRing,
    portal: &PortalDetail,
    user_id: Uuid,
    code: &str,
) -> Result<LoginOutcome, AppError> {
    let Some(account) = account_by_id(conn, portal.id, user_id).await? else {
        return Ok(LoginOutcome::Failed { user_id: None });
    };
    if account.locked_until.is_some_and(|until| until > Utc::now()) {
        return Ok(LoginOutcome::LockedOut {
            user_id: account.user_id,
        });
    }
    if account.status != PortalUserStatus::Active || !account.mfa_enabled {
        return Ok(LoginOutcome::Failed {
            user_id: Some(account.user_id),
        });
    }
    finish_login(conn, pepper, mfa_ring, portal, &account, Some(code)).await
}

/// Starts a session for an account whose identity provider has just
/// authenticated it and which has no TOTP to check (D-588 item 3). `None`
/// when the account isn't active on this portal, or has TOTP enabled (the
/// caller must go through [`second_factor`] instead).
pub async fn federated_session(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    mfa_ring: &KeyRing,
    portal: &PortalDetail,
    user_id: Uuid,
) -> Result<Option<LoginOutcome>, AppError> {
    let Some(account) = account_by_id(conn, portal.id, user_id).await? else {
        return Ok(None);
    };
    if account.status != PortalUserStatus::Active
        || account.mfa_enabled
        || account.locked_until.is_some_and(|until| until > Utc::now())
    {
        return Ok(None);
    }
    finish_login(conn, pepper, mfa_ring, portal, &account, None)
        .await
        .map(Some)
}

/// The second factor (when enrolled) and the session: shared by password
/// login, OIDC sign-in and OIDC's second factor, so the rules are one
/// implementation.
async fn finish_login(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    mfa_ring: &KeyRing,
    portal: &PortalDetail,
    account: &Account,
    code: Option<&str>,
) -> Result<LoginOutcome, AppError> {
    let mut accepted_step = None;
    let mut recovery_code_used = false;
    if account.mfa_enabled {
        let Some(code) = code else {
            return Ok(LoginOutcome::MfaRequired {
                user_id: account.user_id,
            });
        };
        // D-588 item 1: a recovery code in place of the TOTP code. The two
        // shapes can't be confused (see `recovery`), and a wrong recovery
        // code counts toward the lockout exactly like a wrong TOTP code.
        if recovery::normalise(code).is_some() {
            if !recovery::consume(conn, pepper, account.user_id, code).await? {
                record_failure(conn, account).await?;
                return Ok(LoginOutcome::Failed {
                    user_id: Some(account.user_id),
                });
            }
            recovery_code_used = true;
        } else {
            accepted_step = verify_totp(conn, mfa_ring, account, code).await?;
            if accepted_step.is_none() {
                return Ok(LoginOutcome::Failed {
                    user_id: Some(account.user_id),
                });
            }
        }
    }

    // On an MFA-required portal, a recovery code buys one thing: the chance
    // to enrol a new authenticator (D-588 item 1). The flag lives on the
    // credential so every later request and refresh keeps enforcing it.
    let reenroll = portal.mfa_policy == MfaPolicy::Required && recovery_code_used;
    let reenroll_required: bool = sqlx::query_scalar(
        "UPDATE webportal_credential SET failed_login_count = 0, locked_until = NULL, \
           last_login_at = NOW(), mfa_last_step = COALESCE($2, mfa_last_step), \
           mfa_reenroll_required = mfa_reenroll_required OR $3, updated_at = NOW() \
         WHERE webportal_user_id = $1 \
         RETURNING mfa_reenroll_required",
    )
    .bind(account.user_id)
    .bind(accepted_step)
    .bind(reenroll)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let family = refresh::issue_family(conn, pepper, portal.id, account.user_id).await?;
    Ok(LoginOutcome::Success {
        user_id: account.user_id,
        epoch: account.epoch,
        family,
        mfa_enrollment_required: enrollment_required(
            portal,
            account.mfa_enabled,
            reenroll_required,
        ),
        recovery_code_used,
    })
}

/// A session may use only the MFA enrollment and logout routes while the
/// portal requires MFA and the user has no usable authenticator: never
/// enrolled, or signed in with a recovery code since (D-588 item 1).
pub fn enrollment_required(portal: &PortalDetail, mfa_enabled: bool, reenroll: bool) -> bool {
    portal.mfa_policy == MfaPolicy::Required && (!mfa_enabled || reenroll)
}

/// The accepted TOTP step for `code`, or `None` after recording the failure.
async fn verify_totp(
    conn: &mut PgConnection,
    mfa_ring: &KeyRing,
    account: &Account,
    code: &str,
) -> Result<Option<i64>, AppError> {
    let secret = mfa::decrypt(
        mfa_ring,
        account
            .mfa_secret_enc
            .as_deref()
            .ok_or_else(|| AppError::internal("mfa enabled without a secret"))?,
    )?;
    let step = mfa::verify(&secret, code, account.mfa_last_step, now_secs())?;
    if step.is_none() {
        record_failure(conn, account).await?;
    }
    Ok(step)
}

fn now_secs() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

/// What an authenticated portal request resolves to.
#[derive(Debug, Clone)]
pub struct PortalPrincipal {
    pub webportal_id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub mfa_enabled: bool,
    pub mfa_enrollment_required: bool,
    /// The user's one role in this portal (D-579), read live on every
    /// request (never cached, G-9): `None` reaches no records.
    pub role_id: Option<Uuid>,
}

/// `(portal live, credential epoch, mfa enabled, re-enroll required, family
/// live, role)`; the epoch is `None` when no live account matches.
type PrincipalRow = (bool, Option<i32>, bool, bool, bool, Option<Uuid>);

/// The server-side half of every authenticated portal request: the account
/// must still be live and `active` on this portal, the portal itself must
/// still be live and enabled, the token's epoch must equal the credential's,
/// and the token's refresh family must be live. One statement (G-9: these
/// checks stay uncached, so the portal cache can never outlive a revocation
/// or a portal deleted through generic CRUD). `Err(NotFound)` when the portal
/// is no longer live and enabled; `Ok(None)` when the account doesn't admit
/// the token.
pub async fn resolve_principal(
    conn: &mut PgConnection,
    portal: &PortalDetail,
    user_id: Uuid,
    epoch: i32,
    family_id: Uuid,
) -> Result<Option<PortalPrincipal>, AppError> {
    let row: Option<PrincipalRow> = sqlx::query_as(
        "SELECT (w.is_active IS NOT FALSE AND w.is_enabled IS TRUE), \
                c.auth_epoch, COALESCE(c.mfa_enabled, FALSE), \
                COALESCE(c.mfa_reenroll_required, FALSE), \
                EXISTS (SELECT 1 FROM webportal_refresh_token t \
                        WHERE t.family_id = $3 AND t.webportal_user_id = u.id \
                          AND t.revoked_at IS NULL AND t.family_expires_at > NOW()), \
                ur.role_id \
         FROM webportal w \
         LEFT JOIN webportal_user u ON u.webportal_ref = w.id AND u.id = $1 \
           AND u.is_active IS NOT FALSE AND u.status = 'active' \
         LEFT JOIN webportal_credential c ON c.webportal_user_id = u.id \
         LEFT JOIN webportal_user_role ur ON ur.webportal_user_id = u.id \
         WHERE w.id = $2",
    )
    .bind(user_id)
    .bind(portal.id)
    .bind(family_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // The portal itself gone or disabled (possibly after the G-9 cache
    // resolved it): the uniform 404, as for an unknown portal.
    let Some((true, current_epoch, mfa_enabled, reenroll, family_live, role_id)) = row else {
        return Err(AppError::NotFound);
    };
    let Some(current_epoch) = current_epoch else {
        // No live, active account (or no credential) on this portal.
        return Ok(None);
    };
    if current_epoch != epoch || !family_live {
        return Ok(None);
    }
    Ok(Some(PortalPrincipal {
        webportal_id: portal.id,
        user_id,
        family_id,
        mfa_enabled,
        mfa_enrollment_required: enrollment_required(portal, mfa_enabled, reenroll),
        role_id,
    }))
}

/// Accepts an invitation: sets the password (already hashed by the caller,
/// after the policy check), marks the email verified (the link was delivered
/// to it), and activates an `invited` user. A disabled user stays disabled.
pub async fn accept_invitation(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    portal: &PortalDetail,
    bearer: &str,
    password_hash: &str,
) -> Result<Option<Uuid>, AppError> {
    let Some(user_id) = onetime::consume(conn, pepper, Kind::Invitation, portal.id, bearer).await?
    else {
        return Ok(None);
    };
    set_password(conn, user_id, password_hash).await?;
    sqlx::query(
        "UPDATE webportal_user SET status = 'active', modified_at = NOW(), \
           row_version = row_version + 1 \
         WHERE id = $1 AND status = 'invited'",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(user_id))
}

async fn set_password(conn: &mut PgConnection, user_id: Uuid, hash: &str) -> Result<(), AppError> {
    let updated = sqlx::query(
        "UPDATE webportal_credential SET password_hash = $2, password_changed_at = NOW(), \
           email_verified = TRUE, failed_login_count = 0, locked_until = NULL, \
           auth_epoch = auth_epoch + 1, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(user_id)
    .bind(hash)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::internal("portal user has no credential row"));
    }
    Ok(())
}

pub struct ResetRequest {
    pub user_id: Uuid,
    pub email: String,
    pub token: onetime::IssuedToken,
}

impl std::fmt::Debug for ResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetRequest").finish_non_exhaustive()
    }
}

/// Issues a reset link for a known, non-disabled account on this portal.
/// `None` for everything else, and within the cooldown, so the response never
/// says whether the address has an account.
pub async fn request_reset(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    portal: &PortalDetail,
    email: &str,
) -> Result<Option<ResetRequest>, AppError> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.email FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.webportal_ref = $1 AND lower(u.email) = $2 AND u.is_active IS NOT FALSE \
           AND u.status <> 'disabled' \
         FOR UPDATE OF c",
    )
    .bind(portal.id)
    .bind(email.trim().to_lowercase())
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((user_id, email)) = row else {
        return Ok(None);
    };
    let recent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal_token \
         WHERE webportal_user_id = $1 AND kind = 'reset' \
           AND created_at > NOW() - make_interval(secs => $2))",
    )
    .bind(user_id)
    .bind(RESET_REQUEST_COOLDOWN_SECS as f64)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if recent {
        return Ok(None);
    }
    let token = onetime::issue(conn, pepper, Kind::Reset, portal.id, user_id).await?;
    Ok(Some(ResetRequest {
        user_id,
        email,
        token,
    }))
}

/// Completes a reset: new password, email verified, lockout cleared, epoch
/// bumped and every refresh family revoked, so every existing session ends.
pub async fn confirm_reset(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    portal: &PortalDetail,
    bearer: &str,
    password_hash: &str,
) -> Result<Option<Uuid>, AppError> {
    let Some(user_id) = onetime::consume(conn, pepper, Kind::Reset, portal.id, bearer).await?
    else {
        return Ok(None);
    };
    set_password(conn, user_id, password_hash).await?;
    refresh::revoke_user(conn, user_id).await?;
    Ok(Some(user_id))
}

pub struct Enrollment {
    pub secret: String,
    pub otpauth_uri: String,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment").finish_non_exhaustive()
    }
}

/// Starts (or restarts) enrollment: a new pending secret. The current secret,
/// if any, stays in force until `confirm_mfa`.
pub async fn enroll_mfa(
    conn: &mut PgConnection,
    mfa_ring: &KeyRing,
    principal: &PortalPrincipal,
    account_label: &str,
    issuer: &str,
) -> Result<Enrollment, AppError> {
    let secret = mfa::generate_secret();
    sqlx::query(
        "UPDATE webportal_credential SET mfa_pending_secret_enc = $2, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(principal.user_id)
    .bind(mfa::encrypt(mfa_ring, &secret)?)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Enrollment {
        otpauth_uri: mfa::provisioning_uri(&secret, issuer, account_label)?,
        secret,
    })
}

/// Promotes the pending secret once `code` proves the authenticator holds it,
/// and replaces the recovery codes (D-588 item 1). `None` for a wrong code or
/// no pending enrollment; otherwise the new codes, shown once.
pub async fn confirm_mfa(
    conn: &mut PgConnection,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    principal: &PortalPrincipal,
    code: &str,
) -> Result<Option<Vec<String>>, AppError> {
    let pending: Option<Option<String>> = sqlx::query_scalar(
        "SELECT mfa_pending_secret_enc FROM webportal_credential \
         WHERE webportal_user_id = $1 FOR UPDATE",
    )
    .bind(principal.user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(Some(pending)) = pending else {
        return Ok(None);
    };
    let secret = mfa::decrypt(mfa_ring, &pending)?;
    let Some(step) = mfa::verify(&secret, code, None, now_secs())? else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE webportal_credential SET mfa_enabled = TRUE, mfa_secret_enc = $2, \
           mfa_pending_secret_enc = NULL, mfa_last_step = $3, mfa_reenroll_required = FALSE, \
           updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(principal.user_id)
    .bind(&pending)
    .bind(step)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(
        recovery::replace_all(conn, pepper, principal.user_id).await?,
    ))
}

pub enum RegenerateRecoveryCodes {
    Codes(Vec<String>),
    /// Wrong or replayed TOTP code, or MFA is not enabled.
    WrongCode,
}

impl std::fmt::Debug for RegenerateRecoveryCodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegenerateRecoveryCodes")
            .finish_non_exhaustive()
    }
}

/// Replaces the recovery codes after a fresh TOTP code (never a recovery
/// code: losing the set must not be enough to mint a new one).
pub async fn regenerate_recovery_codes(
    conn: &mut PgConnection,
    mfa_ring: &KeyRing,
    pepper: &PepperRing,
    portal: &PortalDetail,
    principal: &PortalPrincipal,
    code: &str,
) -> Result<RegenerateRecoveryCodes, AppError> {
    let Some(account) = account_by_id(conn, portal.id, principal.user_id).await? else {
        return Ok(RegenerateRecoveryCodes::WrongCode);
    };
    let Some(enc) = account
        .mfa_secret_enc
        .as_deref()
        .filter(|_| account.mfa_enabled)
    else {
        return Ok(RegenerateRecoveryCodes::WrongCode);
    };
    let secret = mfa::decrypt(mfa_ring, enc)?;
    let Some(step) = mfa::verify(&secret, code, account.mfa_last_step, now_secs())? else {
        return Ok(RegenerateRecoveryCodes::WrongCode);
    };
    sqlx::query(
        "UPDATE webportal_credential SET mfa_last_step = $2, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(principal.user_id)
    .bind(step)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(RegenerateRecoveryCodes::Codes(
        recovery::replace_all(conn, pepper, principal.user_id).await?,
    ))
}

#[derive(Debug)]
pub enum DisableMfa {
    Disabled,
    WrongCode,
    /// The portal requires MFA.
    Required,
}

/// Disables MFA after a valid current code. Refused while the portal
/// requires MFA.
pub async fn disable_mfa(
    conn: &mut PgConnection,
    mfa_ring: &KeyRing,
    portal: &PortalDetail,
    principal: &PortalPrincipal,
    code: &str,
) -> Result<DisableMfa, AppError> {
    if portal.mfa_policy == MfaPolicy::Required {
        return Ok(DisableMfa::Required);
    }
    let Some(account) = account_by_id(conn, portal.id, principal.user_id).await? else {
        return Ok(DisableMfa::WrongCode);
    };
    let Some(enc) = account
        .mfa_secret_enc
        .as_deref()
        .filter(|_| account.mfa_enabled)
    else {
        return Ok(DisableMfa::WrongCode);
    };
    let secret = mfa::decrypt(mfa_ring, enc)?;
    if mfa::verify(&secret, code, account.mfa_last_step, now_secs())?.is_none() {
        return Ok(DisableMfa::WrongCode);
    }
    sqlx::query(
        "UPDATE webportal_credential SET mfa_enabled = FALSE, mfa_secret_enc = NULL, \
           mfa_pending_secret_enc = NULL, mfa_last_step = NULL, updated_at = NOW() \
         WHERE webportal_user_id = $1",
    )
    .bind(principal.user_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    recovery::delete_all(conn, principal.user_id).await?;
    Ok(DisableMfa::Disabled)
}

/// Issues an invitation for a provisioned user who has not set a password
/// yet (admin API). `None` if the user is not in this portal or has already
/// accepted.
pub async fn issue_invitation(
    conn: &mut PgConnection,
    pepper: &PepperRing,
    webportal_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, onetime::IssuedToken)>, AppError> {
    let row: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT u.email, u.status FROM webportal_user u \
         WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((email, status)) = row else {
        return Ok(None);
    };
    // D-777: an invitation is an emailed link.
    let Some(email) = email else {
        return Err(AppError::Validation(
            "this portal user has no email to send an invitation to".into(),
        ));
    };
    if status != "invited" {
        return Err(AppError::Conflict(
            "this portal user has already accepted an invitation",
        ));
    }
    let token = onetime::issue(conn, pepper, Kind::Invitation, webportal_id, user_id).await?;
    Ok(Some((email, token)))
}

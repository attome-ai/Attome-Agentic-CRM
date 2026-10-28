//! Credential flows — register/login/Google ID-token verification and access-token
//! issuance. Moved down from `attome-website/crates/server/src/auth.rs` (Plan 1.6a):
//! the website is meant to parse → call engine → respond, not hold business logic.
//!
//! Account *management* (api-key CRUD, linking a verified Google identity to a
//! `user_account` row) stays out of this module — that lives in `xrm-security`,
//! next to `SecurityContext`. This module only ever proves *who someone is*; it
//! never decides what they're allowed to do.

use attome_cache::Store;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::Utc;
use rand::distributions::{Alphanumeric, DistString};
use uuid::Uuid;

use crate::apikey_hash::PepperRing;
use crate::session::{SessionClaims, TokenType};

/// A verified Google identity — the signature, `aud`, `iss`, `exp` and
/// `email_verified` have all been checked by the time a caller receives this
/// (BAU-8b, OD-7a); only account-linking remains.
pub struct GoogleIdentity {
    pub sub: String,
    pub email: String,
    /// The ID token's own `auth_time`, when Google sent a usable one. D-628
    /// lets a locally validated Google `auth_time` satisfy a step-up
    /// (D-510 rule 4 as amended), so a Google-only account can elevate only
    /// with this — it is a credential property, not decoration.
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    /// The ID token's own `exp`.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for GoogleIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleIdentity")
            .field("auth_time", &self.auth_time)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Creates a new password account. Returns the new user's id.
///
/// `invitation_token` is `Some` only when the caller (`crates/server/src/
/// auth.rs::register`) resolved `auth.registration_mode == "invite"` — this
/// function validates and consumes it (`attome_auth::invitation::
/// validate_and_consume`, P-registration-gating Phase 2, D-128) inside the
/// same transaction as the `user_account` INSERT below, so a token can
/// never be consumed without the account it gated actually being created.
/// `None` in `"public"` mode; the `"disabled"` mode never reaches this
/// function at all (rejected in the handler before any DB work).
///
/// P-account-state-enforcement (audit finding #2, post-audit review item 6):
/// `core_systemuser_email_unique` is a *partial* index (`WHERE is_active IS
/// NULL OR is_active = TRUE`, migration 0024), so a disabled row sits outside
/// it and would otherwise never conflict — registering with a disabled
/// account's email would silently mint a brand-new active account with a
/// clean privilege slate instead of erroring. The pre-check below runs inside
/// the same transaction as the insert and returns the identical `Conflict`
/// message a live duplicate gets — no enumeration delta between "disabled"
/// and "taken".
pub async fn register(
    db: &DbPool,
    email: &str,
    password: &str,
    invitation_token: Option<&str>,
    ring: &PepperRing,
) -> Result<Uuid, AppError> {
    let password = RegistrationPassword::prepare(password).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let user_id = register_in_tx(&mut tx, email, password, invitation_token, ring).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(user_id)
}

/// A registration password that passed the policy and has been hashed
/// (BAU-27, finding BAU-F17). Built **before** the registration transaction
/// opens, so no pool connection or advisory lock is held across the KDF wait;
/// [`register_in_tx`] takes only this, so it cannot hash inside the
/// transaction.
pub struct RegistrationPassword {
    password_hash: String,
}

impl std::fmt::Debug for RegistrationPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationPassword")
            .finish_non_exhaustive()
    }
}

impl RegistrationPassword {
    /// Security contract I2: the policy is enforced here, before any hashing,
    /// so no caller can skip it.
    pub async fn prepare(password: &str) -> Result<Self, AppError> {
        let checked = crate::password::NewPassword::validate(password)?;
        // Z4-T9: the optional online check, after the local policy.
        crate::password_policy::check_online(password).await?;
        let password_hash = crate::password::hash_password_async(checked).await?;
        Ok(Self { password_hash })
    }
}

/// Transactional form of [`register`].  The HTTP layer uses this when account
/// creation must commit with a durable follow-up job (for example, the email
/// verification message); ordinary callers should use [`register`]. The
/// caller prepares `password` with [`RegistrationPassword::prepare`] before
/// it begins `tx`.
pub async fn register_in_tx(
    tx: &mut attome_db::Tx<'_>,
    email: &str,
    password: RegistrationPassword,
    invitation_token: Option<&str>,
    ring: &PepperRing,
) -> Result<Uuid, AppError> {
    let email = crate::email_identity::normalize_email(email);
    let password_hash = password.password_hash;
    let new_id = Uuid::now_v7();

    // Non-blocking advisory lock, namespaced per guidelines §2 — serializes
    // every writer that can create/disable/re-enable an account sharing this
    // email (register, federation linking, admin disable/enable) so a
    // concurrent pair can't interleave a "no disabled row" read from one
    // transaction with a disable committed by another (D-121, extends
    // D-113's own check-then-insert, which a plain SELECT inside a
    // READ COMMITTED transaction does not serialize on its own).
    if !crate::email_identity::try_lock_email(tx, &email).await? {
        return Err(AppError::Conflict("email already registered"));
    }

    let disabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account WHERE email = $1 AND is_active = FALSE)",
    )
    .bind(&email)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if disabled {
        return Err(AppError::Conflict("email already registered"));
    }

    if let Some(token) = invitation_token {
        crate::invitation::validate_and_consume(tx, token, &email, ring).await?;
    }

    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO user_account (id, email, password_hash, created_at, is_active)
         VALUES ($1, $2, $3, now(), true)
         RETURNING id",
    )
    .bind(new_id)
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db)
            if db.constraint() == Some("user_account_email_active_unique") =>
        {
            AppError::Conflict("email already registered")
        }
        other => AppError::internal(other),
    })?;

    Ok(user_id)
}

/// Outcome of [`bootstrap_admin`] — distinguishes the three states
/// `crates/server`'s `--bootstrap-admin` CLI flow needs to react to
/// differently (fresh account with a one-time password to print, an existing
/// active account to just grant a privilege to, or a disabled account the
/// caller must refuse to touch).
#[derive(Debug)]
pub enum BootstrapOutcome {
    /// No existing row for this email — a new account was created.
    Created { user_id: Uuid, password: String },
    /// An active row already existed; nothing was written.
    AlreadyActive { user_id: Uuid },
    /// A row exists but is disabled — the caller must refuse to proceed.
    Disabled,
}

/// Creates the first admin account, or resolves an existing active one, for
/// `crates/server`'s `--bootstrap-admin` CLI flow (P-registration-gating,
/// D-128). This is the one account-creation path in the codebase allowed to
/// treat a pre-existing *active* row as success rather than a conflict —
/// the CLI command is meant to be safely re-run (to add a second admin, or
/// after a typo'd first attempt), so it resolves to that row instead of
/// erroring like [`register`] would. A pre-existing *disabled* row is
/// reported back via [`BootstrapOutcome::Disabled`] rather than silently
/// resurrected — same posture as `register`'s own disabled-email guard
/// (P-account-state-enforcement) — the caller (which owns the CLI-facing
/// wording and knows the admin-enable route) decides how to word the
/// refusal.
///
/// Normalizes `email` the same way every other writer of
/// `user_account.email` does ([`crate::email_identity::normalize_email`])
/// before comparing or storing it. The previous `crates/server`-local
/// implementation this replaces stored the raw, un-normalized argv value —
/// a mixed-case bootstrap email would have stored a row [`login`]'s
/// normalized-email lookup could never match.
pub async fn bootstrap_admin(db: &DbPool, email: &str) -> Result<BootstrapOutcome, AppError> {
    // Hash before the transaction opens, so the per-email lock
    // `bootstrap_admin_in_tx` takes is never held across the KDF wait.
    let credentials = BootstrapCredentials::generate().await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let outcome = bootstrap_admin_in_tx(&mut tx, email, credentials).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(outcome)
}

/// The generated password for a bootstrap admin, and its Argon2 hash.
///
/// Its own type so that the hash — a bounded-executor KDF wait
/// (`password::hash_password_async`) — is computed by the caller *before* it
/// opens the transaction [`bootstrap_admin_in_tx`] runs in (attome-auth
/// hardening 2.4). Hashing inside that transaction held the per-email and
/// seat-admission advisory locks for the whole KDF wait, so every concurrent
/// registration or JIT admission got a `Conflict` meanwhile.
///
/// A bootstrap that finds an existing account discards this; it is a one-off
/// operator command, so the wasted KDF work does not matter.
pub struct BootstrapCredentials {
    password: String,
    password_hash: String,
}

impl std::fmt::Debug for BootstrapCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapCredentials")
            .finish_non_exhaustive()
    }
}

impl BootstrapCredentials {
    /// A fresh random 24-character password and its hash.
    pub async fn generate() -> Result<Self, AppError> {
        let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 24);
        let password_hash = crate::password::hash_password_async(
            crate::password::NewPassword::platform_generated(password.clone()),
        )
        .await?;
        Ok(Self {
            password,
            password_hash,
        })
    }
}

/// [`bootstrap_admin`] without owning the transaction, so a caller that must
/// gate the creation on something this crate cannot see — the seat check, which
/// lives in `xrm-license`, above `base-*` (M04 Phase 2, LIC-F2) — can hold the
/// account row's transaction, take the checks it needs, and then call this.
///
/// Same reason [`register_in_tx`] exists beside `register`: the base layer owns
/// how a row is written, the XRM layer owns the policy around writing it, and
/// the two must commit together or not at all.
///
/// It takes the per-email advisory lock itself
/// ([`crate::email_identity::try_lock_email`], §2's stable, scoped key). A
/// caller that already holds that lock in the same transaction — as
/// `xrm_server::bootstrap_admin::bootstrap_admin_gated` does, to order it
/// before the seat lock — re-acquires it harmlessly: transaction-scoped
/// advisory locks are reentrant within one session.
///
/// The caller is responsible for `tx.commit()`, for deciding whether a seat is
/// about to be consumed before calling it, and for producing `credentials`
/// with [`BootstrapCredentials::generate`] *before* it begins `tx`, so no lock
/// is held across the KDF wait.
pub async fn bootstrap_admin_in_tx(
    tx: &mut attome_db::Tx<'_>,
    email: &str,
    credentials: BootstrapCredentials,
) -> Result<BootstrapOutcome, AppError> {
    let email = crate::email_identity::normalize_email(email);
    let BootstrapCredentials {
        password,
        password_hash,
    } = credentials;

    // Same per-email advisory lock every other account writer takes
    // (guidelines §2) — a concurrent register/disable/enable for this exact
    // email can't interleave with this check-then-insert.
    if !crate::email_identity::try_lock_email(tx, &email).await? {
        return Err(AppError::Conflict(
            "email is concurrently held by another account operation, retry",
        ));
    }

    // `is_active` is NOT NULL since migration 0460 (attome-auth hardening 2.4).
    let existing: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, is_active FROM user_account WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;

    let outcome = match existing {
        Some((_, false)) => BootstrapOutcome::Disabled,
        Some((user_id, true)) => BootstrapOutcome::AlreadyActive { user_id },
        None => {
            let user_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO user_account (id, email, password_hash, created_at, is_active, email_verified)
                 VALUES ($1, $2, $3, now(), true, true)",
            )
            .bind(user_id)
            .bind(&email)
            .bind(&password_hash)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            BootstrapOutcome::Created { user_id, password }
        }
    };

    Ok(outcome)
}

/// The result of a password login: either a session is ready to be issued,
/// or a second factor still needs to be satisfied (P2.8 step 7, D-069). The
/// two MFA variants carry a short-lived pending token (`attome_auth::mfa`) —
/// never a `Uuid` directly — so the website layer cannot accidentally issue
/// session cookies for an account that hasn't cleared its second factor yet.
#[derive(Debug)]
pub enum LoginOutcome {
    Session(Uuid),
    /// Account has a confirmed TOTP enrollment — caller must call
    /// `attome_auth::mfa::complete_pending_login[_recovery]`.
    MfaRequired {
        pending_token: String,
    },
    /// `mfa_policy = "required"` and the account has no confirmed
    /// enrollment — caller must call `attome_auth::mfa::enroll_pending` then
    /// `confirm_pending_enrollment` before any session exists.
    MfaEnrollmentRequired {
        pending_token: String,
    },
}

/// Q5-T3: what a person's second-factor policy asks of a sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UserMfaRequirement {
    /// A second factor is required.
    pub required: bool,
    /// A second factor is used when the person has one (and offered).
    pub optional: bool,
    /// While required and not enrolled: until when the person may postpone
    /// enrolling. `None` or past: no more postponing.
    pub grace_until: Option<chrono::DateTime<chrono::Utc>>,
    /// While required and not enrolled: the person postponed enrolling
    /// until this time (never past `grace_until`).
    pub postponed_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Q5-T4: how many days a browser may be remembered after a second
    /// factor; 0 never (an administrator's policy, and the deployment-wide
    /// switch alone).
    pub remember_device_days: i32,
    /// Q5-T5: an emailed one-time code may serve as the (weaker) second
    /// factor: every role allows it, and the person is not an administrator.
    pub email_code: bool,
}

impl UserMfaRequirement {
    /// The requirement a deployment-wide `auth.mfa_policy` value stands for
    /// (`off`, `optional`, `required`; anything else reads as `optional`).
    pub fn from_mode(mode: &str) -> Self {
        Self {
            required: mode == "required",
            optional: mode != "off" && mode != "required",
            grace_until: None,
            postponed_until: None,
            remember_device_days: 0,
            email_code: false,
        }
    }

    /// Q5-T4: whether this policy lets a browser be remembered.
    pub fn may_remember(&self) -> bool {
        self.remember_device_days > 0
    }

    /// Whether enrolment may still be put off at `now`.
    pub fn in_grace(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.grace_until.is_some_and(|until| now < until)
    }

    /// Whether the person has put enrolment off past `now`.
    pub fn postponed(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.postponed_until.is_some_and(|until| now < until)
    }
}

/// Q5-T3: where a sign-in gets the person's second-factor requirement. The
/// deployment-wide switch is [`ConfigMfaPolicy`]; the per-role policy lives
/// above this crate (`attome_security::mfa_policy::RoleMfaPolicySource`).
pub trait MfaPolicySource: Send + Sync {
    fn policy_for(
        &self,
        user_id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UserMfaRequirement, AppError>> + Send + '_>,
    >;
}

/// The deployment-wide `auth.mfa_policy` as a policy source: the same
/// requirement for everyone, with no grace period.
#[derive(Debug, Clone, Copy)]
pub struct ConfigMfaPolicy<'a>(pub &'a str);

impl MfaPolicySource for ConfigMfaPolicy<'_> {
    fn policy_for(
        &self,
        _user_id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UserMfaRequirement, AppError>> + Send + '_>,
    > {
        let requirement = UserMfaRequirement::from_mode(self.0);
        Box::pin(async move { Ok(requirement) })
    }
}

/// Q5-T4: the remembered-device bearer a sign-in presents, and the ring its
/// hash is checked with.
#[derive(Clone, Copy)]
pub struct RememberedDevice<'a> {
    pub bearer: &'a str,
    pub ring: &'a crate::apikey_hash::PepperRing,
}

impl std::fmt::Debug for RememberedDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RememberedDevice").finish_non_exhaustive()
    }
}

/// Q5-T3: what a password sign-in does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaStep {
    /// A session now.
    Session,
    /// Ask for the person's second factor.
    Challenge,
    /// Make the person enrol one first.
    Enrol,
}

/// Q5-T3: the step for `requirement`, whether the person has a second
/// factor, at `now`. Off: a session, even with a factor. Otherwise a person
/// with a factor is asked for it. Required without one: enrol, unless the
/// person postponed it within the grace period. Optional without one: a
/// session. Pure.
pub fn mfa_step(
    requirement: &UserMfaRequirement,
    enrolled: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> MfaStep {
    if !requirement.required && !requirement.optional {
        return MfaStep::Session;
    }
    if enrolled {
        return MfaStep::Challenge;
    }
    if requirement.required && !requirement.postponed(now) {
        return MfaStep::Enrol;
    }
    MfaStep::Session
}

/// Q5-T3: whether a sign-in through an identity provider meets
/// `requirement`: when a factor is required, the provider must have
/// reported one (`idp_mfa`, Q1-T11), or the person must be within the grace
/// period (enrolment is postponed until it ends). Pure.
pub fn federated_mfa_met(
    requirement: &UserMfaRequirement,
    idp_mfa: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    !requirement.required || idp_mfa || requirement.in_grace(now) || requirement.postponed(now)
}

/// Verifies an email + password login. Returns a [`LoginOutcome`] — a bare
/// session only when `mfa_policy` and the account's enrollment state allow
/// it outright. The deployment-wide form of [`login_with_policy`].
#[allow(clippy::too_many_arguments)]
pub async fn login(
    db: &DbPool,
    redis: &Store,
    email: &str,
    password: &str,
    require_verified_email: bool,
    mfa_policy: &str,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<LoginOutcome, AppError> {
    login_with_policy(
        db,
        redis,
        email,
        password,
        require_verified_email,
        &ConfigMfaPolicy(mfa_policy),
        jwt_ring,
        issuer,
        audience,
        None,
    )
    .await
}

/// Verifies an email + password login. Returns a [`LoginOutcome`] — a bare
/// session only when the person's requirement (`policy`, Q5-T3) and the
/// account's enrollment state allow it outright.
///
/// `require_verified_email` (`config.auth.require_verified_email`) rejects an
/// otherwise-correct login with `Forbidden` when the account's
/// `email_verified` is still false — checked only *after* the password has
/// already verified, so this is not a new enumeration oracle (an attacker
/// without the password never reaches this branch; one who has it already
/// knows the account exists).
#[allow(clippy::too_many_arguments)]
pub async fn login_with_policy(
    db: &DbPool,
    redis: &Store,
    email: &str,
    password: &str,
    require_verified_email: bool,
    policy: &dyn MfaPolicySource,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    remembered: Option<RememberedDevice<'_>>,
) -> Result<LoginOutcome, AppError> {
    let email = crate::email_identity::normalize_email(email);
    let row: Option<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT id, password_hash, email_verified
         FROM user_account
         WHERE email = $1
           AND is_active = true
           AND password_hash IS NOT NULL",
    )
    .bind(&email)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    // Run verify_password on both the hit and miss paths so the argon2 cost
    // doesn't leak whether the email exists (timing/enumeration oracle).
    let password = password.to_owned();
    let (user_id, email_verified) = match row {
        Some((user_id, stored_hash, email_verified)) => {
            let ok = crate::password::verify_password_async(&password, &stored_hash).await?;
            if !ok {
                return Err(AppError::Unauthorized);
            }
            if crate::password::needs_rehash(&stored_hash) {
                rehash_after_login(db, user_id, &password, &stored_hash).await;
            }
            (user_id, email_verified)
        }
        None => {
            crate::password::verify_against_dummy_async(&password).await?;
            return Err(AppError::Unauthorized);
        }
    };

    if require_verified_email && !email_verified {
        return Err(AppError::Forbidden);
    }

    // BAU-12e: `last_login` is stamped by `refresh::issue_with` when a
    // session is actually issued, never here before a second factor.
    let requirement = policy.policy_for(user_id).await?;
    if !requirement.required && !requirement.optional {
        return Ok(LoginOutcome::Session(user_id));
    }
    // Q5-T5: a person whose roles allow email codes has a second factor in
    // their verified email address, TOTP or not.
    let enrolled =
        crate::mfa::is_enrolled(db, user_id).await? || (requirement.email_code && email_verified);
    let mut step = mfa_step(&requirement, enrolled, chrono::Utc::now());
    // Q5-T4: a browser remembered after a second factor skips the challenge
    // while the policy remembers devices and the device is still good.
    if step == MfaStep::Challenge
        && requirement.may_remember()
        && let Some(device) = remembered
    {
        let epoch = crate::epoch::current_epoch(db, user_id).await?;
        if crate::remembered_device::is_remembered(db, device.ring, user_id, device.bearer, epoch)
            .await?
        {
            step = MfaStep::Session;
        }
    }
    match step {
        MfaStep::Challenge => {
            let pending_token = crate::mfa::start_challenge(
                redis,
                user_id,
                TokenType::MfaPendingLogin,
                jwt_ring,
                issuer,
                audience,
            )
            .await?;
            Ok(LoginOutcome::MfaRequired { pending_token })
        }
        MfaStep::Enrol => {
            let pending_token = crate::mfa::start_challenge(
                redis,
                user_id,
                TokenType::MfaPendingEnroll,
                jwt_ring,
                issuer,
                audience,
            )
            .await?;
            Ok(LoginOutcome::MfaEnrollmentRequired { pending_token })
        }
        // Optional and never enrolled, or enrolment postponed within the
        // grace period: the password alone is a full session.
        MfaStep::Session => Ok(LoginOutcome::Session(user_id)),
    }
}

#[cfg(test)]
mod mfa_step_tests {
    use super::*;

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn the_deployment_modes_keep_their_meaning() {
        let now = at(1_000);
        let off = UserMfaRequirement::from_mode("off");
        let optional = UserMfaRequirement::from_mode("optional");
        let required = UserMfaRequirement::from_mode("required");
        assert_eq!(mfa_step(&off, true, now), MfaStep::Session);
        assert_eq!(mfa_step(&optional, true, now), MfaStep::Challenge);
        assert_eq!(mfa_step(&optional, false, now), MfaStep::Session);
        assert_eq!(mfa_step(&required, true, now), MfaStep::Challenge);
        assert_eq!(mfa_step(&required, false, now), MfaStep::Enrol);
        assert_eq!(UserMfaRequirement::from_mode("unknown"), optional);
    }

    #[test]
    fn a_postponement_holds_only_until_it_ends() {
        let required = UserMfaRequirement {
            required: true,
            optional: false,
            grace_until: Some(at(2_000)),
            postponed_until: Some(at(1_500)),
        };
        assert_eq!(mfa_step(&required, false, at(1_000)), MfaStep::Session);
        assert_eq!(mfa_step(&required, false, at(1_600)), MfaStep::Enrol);
        assert!(required.in_grace(at(1_999)) && !required.in_grace(at(2_000)));
    }

    #[test]
    fn a_provider_factor_meets_a_required_policy() {
        let required = UserMfaRequirement::from_mode("required");
        assert!(federated_mfa_met(&required, true, at(1)));
        assert!(!federated_mfa_met(&required, false, at(1)));
        let in_grace = UserMfaRequirement {
            grace_until: Some(at(10)),
            ..required
        };
        assert!(federated_mfa_met(&in_grace, false, at(5)));
        assert!(!federated_mfa_met(&in_grace, false, at(10)));
        assert!(federated_mfa_met(
            &UserMfaRequirement::from_mode("optional"),
            false,
            at(1)
        ));
    }
}

/// BAU-15b (hardening 2.7): upgrades a verified password's hash to the current
/// `auth.kdf` parameters. Runs after the login's own KDF permit is released,
/// takes a permit only if one is free, and holds no transaction across the
/// KDF; the write is a compare-and-swap on the hash it verified, so a reset
/// that landed meanwhile is never overwritten. Every failure leaves the login
/// successful and the stored hash unchanged.
async fn rehash_after_login(db: &DbPool, user_id: Uuid, password: &str, verified_hash: &str) {
    let new_hash = match crate::password::rehash_if_capacity(password).await {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            metrics::counter!("auth_password_rehash_total", "outcome" => "skipped_busy")
                .increment(1);
            return;
        }
        Err(e) => {
            metrics::counter!("auth_password_rehash_total", "outcome" => "failed").increment(1);
            tracing::warn!(%user_id, error = %e, "password rehash on login failed; hash unchanged");
            return;
        }
    };
    let outcome = sqlx::query(
        "UPDATE user_account SET password_hash = $1 WHERE id = $2 AND password_hash = $3",
    )
    .bind(&new_hash)
    .bind(user_id)
    .bind(verified_hash)
    .execute(db)
    .await;
    match outcome {
        Ok(_) => {
            metrics::counter!("auth_password_rehash_total", "outcome" => "stored").increment(1);
        }
        Err(e) => {
            metrics::counter!("auth_password_rehash_total", "outcome" => "failed").increment(1);
            tracing::warn!(%user_id, error = %e, "storing the rehashed password failed; hash unchanged");
        }
    }
}

/// Google's OIDC issuer (OD-7a). Everything about a Google ID token is checked
/// against this issuer's own published discovery document and JWKS, locally.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The provider key Google's discovery/JWKS cache entries use:
/// `oidc:discovery:~google`, `oidc:jwks:~google` and
/// `oidc:jwks-refetch:~google` (BAU-8b). Going through the generic OIDC cache
/// means Google inherits the same 1 h TTL, the same degrade-to-live-fetch
/// posture (D-027) and the same single-flight bounded refetch on an unknown
/// `kid` (D-130/hardening 1.7) as every configured provider.
///
/// The `~` is what keeps it reserved. A configured `oidc.providers` key must be
/// ASCII alphanumeric, `-` or `_` (`AppConfig::validate`), and a portal
/// provider key `[a-z0-9-]`, so no configured provider can share these cache
/// entries. With the plain key `"google"`, an operator who configured an OIDC
/// provider named `google` (say, Google Workspace with its own client) shared
/// Google's cached discovery and JWKS, and a document cached for one issuer
/// then failed validation for the other flow for up to an hour.
const GOOGLE_PROVIDER_KEY: &str = "~google";

/// Upper bound on a Google credential's single-use marker. Google ID tokens
/// live about an hour; a token claiming a much later `exp` is still refused
/// on replay for this long, and after that it is past any lifetime Google
/// issues.
const GOOGLE_CREDENTIAL_MARKER_MAX_TTL_SECS: i64 = 2 * 60 * 60;

/// The leeway `jsonwebtoken` grants past `exp` (its `Validation` default), so
/// the marker outlives the whole window in which the token still verifies.
const GOOGLE_CREDENTIAL_EXP_LEEWAY_SECS: i64 = 60;

/// Bound on the single-use marker's Redis round trip, the same budget every
/// other fail-closed control in this crate uses (`oidc`'s state consume,
/// `step_up`'s challenge store).
const GOOGLE_CREDENTIAL_REDIS_TIMEOUT: std::time::Duration = attome_cache::timeouts::REQUEST_PATH;

fn google_credential_key(credential: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "attome-auth:google-credential:{}",
        hex::encode(Sha256::digest(credential.as_bytes()))
    )
}

/// Records `credential` as used, once. `Ok(())` only for the first
/// presentation; a credential already recorded is `Unauthorized`.
///
/// A security control, so it fails closed (D-027): a Redis error or a timeout
/// is an `Err`, never "assume unused". The key is the credential's SHA-256, so
/// the token itself never reaches Redis; the marker lives until the token
/// could no longer verify anyway (`expires_at` plus `jsonwebtoken`'s leeway),
/// clamped to `[1 s, 2 h]`.
///
/// `coordination_redis` MUST be the coordination-role pool
/// (`AppState.redis_coordination`), the same pool the OIDC `state`, the S2S
/// nonce and the step-up challenges use.
pub async fn consume_google_credential(
    coordination_redis: &Store,
    credential: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let ttl = (expires_at.timestamp() + GOOGLE_CREDENTIAL_EXP_LEEWAY_SECS - Utc::now().timestamp())
        .clamp(1, GOOGLE_CREDENTIAL_MARKER_MAX_TTL_SECS);
    let first = tokio::time::timeout(
        GOOGLE_CREDENTIAL_REDIS_TIMEOUT,
        coordination_redis.set_nx(
            &google_credential_key(credential),
            "1",
            Some(std::time::Duration::from_secs(ttl as u64)),
        ),
    )
    .await
    .map_err(|_| AppError::internal("google credential single-use marker write timed out"))??;

    match first {
        true => Ok(()),
        false => {
            // No credential material in the log line: only the fact of a replay.
            tracing::warn!("a Google ID token was presented a second time; refusing");
            Err(AppError::Unauthorized)
        }
    }
}

/// Verifies a Google ID token **locally** against Google's published JWKS
/// (BAU-8b, OD-7a): fetches `https://accounts.google.com/.well-known/openid-configuration`
/// and its `jwks_uri` through the same cache the OIDC providers use, selects
/// the key the token's `kid` names, and then applies the same
/// `oidc::verify_claims` an OIDC provider's token gets — signature (asymmetric
/// only), `iss`, `aud`, `exp`, `azp` when present, and `email_verified`.
///
/// This replaces the former call to Google's `tokeninfo` endpoint. That call
/// made Google's server the only thing standing between a forged token and a
/// session, gave the sign-in no `auth_time` (so a Google-only account could
/// never satisfy a step-up, D-628), and was the last place a credential left
/// this process on the Google path. Route and SDK button are unchanged
/// (D-072).
///
/// **Each credential is accepted once.** Google Identity Services hands the
/// browser the ID token directly, so the flow has no nonce and nothing binds
/// the token to the browser that received it: a captured credential stays
/// valid for about an hour. Because the verified `auth_time` can satisfy a
/// step-up (D-628), a replay would otherwise mint a fresh, elevated session.
/// After the token verifies, [`consume_google_credential`] records it on the
/// coordination pool and refuses any second presentation — fail closed on a
/// Redis error or timeout. A token that fails verification consumes nothing.
///
/// `cache_redis` MUST be the general cache pool (`AppState.redis`): discovery
/// and JWKS are ordinary caches that degrade to a live fetch, never a
/// correctness-critical gate. `coordination_redis` MUST be
/// `AppState.redis_coordination`. Does **not** touch `user_account` —
/// call `xrm_security::accounts::link_google_account` with the result to
/// resolve/create the local account.
pub async fn verify_google_id_token(
    cache_redis: &Store,
    coordination_redis: &Store,
    google_client_id: &str,
    credential: &str,
) -> Result<GoogleIdentity, AppError> {
    verify_google_id_token_once_at(
        cache_redis,
        coordination_redis,
        GOOGLE_ISSUER,
        google_client_id,
        credential,
    )
    .await
}

/// [`verify_google_id_token`] against `issuer`: verification, then the
/// single-use marker.
async fn verify_google_id_token_once_at(
    cache_redis: &Store,
    coordination_redis: &Store,
    issuer: &str,
    google_client_id: &str,
    credential: &str,
) -> Result<GoogleIdentity, AppError> {
    let identity =
        verify_google_id_token_at(cache_redis, issuer, google_client_id, credential).await?;
    consume_google_credential(coordination_redis, credential, identity.expires_at).await?;
    Ok(identity)
}

/// The verification half of [`verify_google_id_token`], against `issuer`, so
/// tests can point it at a local mock JWKS instead of Google. It does **not**
/// consume the credential; only [`verify_google_id_token_once_at`] may call it
/// on a request path.
///
/// Security contract I5: the ID token is only ever *decoded locally*. It never
/// appears in a URL, a request line, a log line or a returned error — the only
/// outbound requests are the discovery and JWKS GETs, whose URLs are built
/// from the issuer alone, and every transport error is stripped of its URL
/// before `AppError::internal` logs it (BAU-6).
async fn verify_google_id_token_at(
    redis: &Store,
    issuer: &str,
    google_client_id: &str,
    credential: &str,
) -> Result<GoogleIdentity, AppError> {
    // `require_email_verified_claim` is on for Google without exception: an
    // omitted claim is indistinguishable from an IdP that never verifies
    // email, and an unverified address could belong to anyone.
    let provider = attome_config::OidcProviderConfig {
        display_name: "Google".into(),
        issuer: issuer.to_string(),
        client_id: google_client_id.to_string(),
        // Google's ID-token flow sends no client secret: there is no
        // authorization-code exchange to authenticate.
        client_secret: String::new().into(),
        scopes: vec!["openid".into(), "email".into()],
        email_claim: "email".into(),
        require_email_verified_claim: true,
        mfa_acr_values: Vec::new(),
        trust_idp_mfa: true,
    };
    let identity = crate::oidc::verify_id_token_without_nonce(
        redis,
        &provider,
        GOOGLE_PROVIDER_KEY,
        credential,
    )
    .await?;

    Ok(GoogleIdentity {
        sub: identity.sub,
        email: identity.email,
        auth_time: identity.auth_time,
        expires_at: identity.expires_at,
    })
}

/// Mints a short-lived access token (the `session_token` cookie payload) for
/// `user_id`. Takes `jwt_secret` directly (rather than `&AppConfig`) so a
/// caller can pass the hot-rotatable value from `AppState.secrets` instead of
/// the boot-time `config.auth.jwt_secret` — see `AppState::secrets`, which
/// replaced the deleted `base-secrets` crate in D-549 (every secret is now
/// config-sourced and hot-swapable through that handle).
///
/// The sole chokepoint every login/register/MFA-completion/refresh path
/// mints a session through (D-113 Phase 2, wired D-121; P-session-refresh-
/// hardening, D-129) — stamping `epoch::current_epoch` here, rather than at
/// each call site, is what makes wiring the epoch a one-function change
/// instead of a change at every issuer. Reads the epoch fresh from Postgres
/// (never a cached value) so a just-bumped epoch is reflected in the very
/// next token this function mints, even before any cache invalidation
/// reaches this node.
///
/// `family_id` is the refresh family this session belongs to, stamped as the
/// token's `sid` claim (D-510 rule 2). The token carries no authentication time,
/// methods or elevation; those stay on the family row.
pub async fn issue_access_token(
    db: &DbPool,
    user_id: Uuid,
    family_id: Uuid,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    access_token_expiry_secs: i64,
) -> Result<String, AppError> {
    let epoch = crate::epoch::current_epoch(db, user_id).await?;
    mint_access_token(
        user_id,
        family_id,
        epoch,
        jwt_ring,
        issuer,
        audience,
        access_token_expiry_secs,
    )
}

/// Signs a session access token for a known `epoch`. [`issue_access_token`]
/// reads the epoch from the pool; `refresh::issue_session_with` reads it in
/// the family's own transaction (BAU-13c).
pub(crate) fn mint_access_token(
    user_id: Uuid,
    family_id: Uuid,
    epoch: i32,
    jwt_ring: &KeyRing,
    issuer: &str,
    audience: &str,
    access_token_expiry_secs: i64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let claims = SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + access_token_expiry_secs,
        jti: Uuid::now_v7(),
        epoch,
        iss: issuer.to_string(),
        aud: audience.to_string(),
        typ: TokenType::Session,
    };
    crate::jwt::create_session_token(&claims, family_id, jwt_ring)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── BAU-8b (OD-7a): local Google verification ───────────────────────────

    /// A pool that can never be reached. Discovery and JWKS are caches that
    /// degrade to a live fetch (D-027), so an unreachable cache *is* the
    /// cold-start path these tests want — and they need no live Redis.
    fn unconnected_pool() -> Store {
        let config = fred::prelude::RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
        attome_cache::Store::Redis(
            fred::prelude::Builder::from_config(config)
                .build_pool(1)
                .unwrap(),
        )
    }

    /// The one throwaway 2048-bit RSA key these tests sign with. Generated once
    /// per test process — a keygen per test was the largest single cost in this
    /// crate's fast tier (see `oidc.rs`'s `test_keys`).
    fn test_rsa() -> &'static rsa::RsaPrivateKey {
        static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
                .expect("generate a test RSA keypair")
        })
    }

    const TEST_KID: &str = "google-test-key";

    /// The JWKS Google would publish for `test_rsa`.
    fn published_jwks() -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
        use rsa::traits::PublicKeyParts;

        let key = test_rsa();
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": TEST_KID,
                "n": B64URL.encode(key.n().to_bytes_be()),
                "e": B64URL.encode(key.e().to_bytes_be()),
            }]
        })
        .to_string()
    }

    /// An ID token for `claims`, signed by the published key under `kid`.
    fn sign_google_token(claims: &serde_json::Value) -> String {
        use jsonwebtoken::EncodingKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let pem = test_rsa().to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn google_claims(
        issuer: &str,
        audience: serde_json::Value,
        email_verified: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "sub": "google-sub-42",
            "email": "person@example.com",
            "email_verified": email_verified,
            "exp": (Utc::now().timestamp() + 300),
            "iat": Utc::now().timestamp(),
        })
    }

    /// A Google stand-in on one listener: its own
    /// `/.well-known/openid-configuration` (naming itself as `issuer` and
    /// pointing `jwks_uri` at its own `/jwks`) plus that JWKS. Returns the
    /// issuer, which is also the value the token's `iss` must carry.
    async fn mock_google() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let served = issuer.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let base = served.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 2048];
                    loop {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                request.extend_from_slice(&chunk[..n]);
                                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let line = String::from_utf8_lossy(&request).into_owned();
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = if path.starts_with("/.well-known/openid-configuration") {
                        serde_json::json!({
                            "issuer": base,
                            "authorization_endpoint": format!("{base}/authorize"),
                            "token_endpoint": format!("{base}/token"),
                            "jwks_uri": format!("{base}/jwks"),
                        })
                        .to_string()
                    } else if path.starts_with("/jwks") {
                        published_jwks()
                    } else {
                        "{}".to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        issuer
    }

    /// The core of OD-7a: a token signed by the key Google publishes verifies
    /// locally, with no call to Google's tokeninfo endpoint.
    #[tokio::test]
    async fn a_google_token_signed_by_the_published_key_verifies() {
        let issuer = mock_google().await;
        let token = sign_google_token(&google_claims(
            &issuer,
            serde_json::json!("client-id"),
            serde_json::json!(true),
        ));

        let identity = verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &token)
            .await
            .expect("a token signed by the published key must verify");

        assert_eq!(identity.sub, "google-sub-42");
        assert_eq!(identity.email, "person@example.com");
        assert_eq!(
            identity.auth_time, None,
            "a token without auth_time asserts no authentication time"
        );
    }

    /// BAU-8b's whole point for D-628: the validated token's own auth_time is
    /// what a Google-only account elevates with.
    #[tokio::test]
    async fn a_google_token_records_its_own_auth_time() {
        let issuer = mock_google().await;
        let authenticated_at = Utc::now().timestamp() - 120;
        let mut claims = google_claims(
            &issuer,
            serde_json::json!("client-id"),
            serde_json::json!(true),
        );
        claims["auth_time"] = serde_json::json!(authenticated_at);
        let token = sign_google_token(&claims);

        let identity = verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &token)
            .await
            .expect("a token from the published key must verify");

        assert_eq!(
            identity.auth_time.map(|at| at.timestamp()),
            Some(authenticated_at)
        );
    }

    /// The single-use marker is a security control (D-027): when the
    /// coordination store cannot be reached, a genuine, correctly signed token
    /// is refused rather than accepted unmarked.
    #[tokio::test]
    async fn a_valid_google_token_is_refused_when_the_single_use_store_fails() {
        let issuer = mock_google().await;
        let token = sign_google_token(&google_claims(
            &issuer,
            serde_json::json!("client-id"),
            serde_json::json!(true),
        ));

        let result = verify_google_id_token_once_at(
            &unconnected_pool(),
            &unconnected_pool(),
            &issuer,
            "client-id",
            &token,
        )
        .await;

        assert!(
            result.is_err(),
            "an unreachable single-use store must fail closed"
        );
    }

    /// The marker key carries a digest of the credential, never the credential.
    #[test]
    fn the_single_use_key_never_contains_the_credential() {
        let credential = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
        let key = google_credential_key(credential);
        assert!(key.starts_with("attome-auth:google-credential:"));
        assert!(!key.contains(credential));
        assert_eq!(
            key,
            google_credential_key(credential),
            "stable per credential"
        );
        assert_ne!(key, google_credential_key("another-credential"));
    }

    /// Google's cache entries can never be a configured provider's: `~` is
    /// outside every configured-key alphabet.
    #[test]
    fn the_google_cache_key_cannot_be_a_configured_provider_key() {
        assert!(
            !GOOGLE_PROVIDER_KEY
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[tokio::test]
    async fn a_google_token_for_another_audience_is_refused() {
        let issuer = mock_google().await;
        let token = sign_google_token(&google_claims(
            &issuer,
            serde_json::json!("another-client"),
            serde_json::json!(true),
        ));

        let result =
            verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &token).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn an_unverified_google_email_is_refused() {
        let issuer = mock_google().await;
        for email_verified in [serde_json::json!(false), serde_json::json!(null)] {
            let token = sign_google_token(&google_claims(
                &issuer,
                serde_json::json!("client-id"),
                email_verified.clone(),
            ));
            let result =
                verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &token).await;
            assert!(
                matches!(result, Err(AppError::Unauthorized)),
                "email_verified = {email_verified} must be refused"
            );
        }
    }

    /// A token that names the published `kid` but is signed by another key is
    /// refused — the check is the signature, not the key id.
    #[tokio::test]
    async fn a_google_token_signed_by_an_unpublished_key_is_refused() {
        use jsonwebtoken::EncodingKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let issuer = mock_google().await;
        let other = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let pem = other.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let token = jsonwebtoken::encode(
            &header,
            &google_claims(
                &issuer,
                serde_json::json!("client-id"),
                serde_json::json!(true),
            ),
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap();

        let result =
            verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &token).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    // issue_access_token now reads epoch::current_epoch, which always queries
    // Postgres (no early-return path for an unconnected pool, unlike
    // refresh::redeem's parsing-only early returns) — moved to
    // tests/session_epoch.rs, which has live-DB access, per this crate's
    // existing convention for anything that can't be exercised against an
    // unconnected pool (see epoch.rs's own test-module comment). That file
    // also covers KeyRing-signed/iss/aud/typ claim shape (P-key-rotation-
    // and-jwt, D-130) now that this function takes a `&KeyRing` and stamps
    // `iss`/`aud`/`typ`.

    // ── Security contract I5 (attome-auth hardening 1.6) ──────────────────────

    use tracing_subscriber::layer::SubscriberExt;

    /// Records every tracing event's fields, so a test can assert what reached
    /// the logs.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl CapturedLogs {
        fn joined(&self) -> String {
            self.0.lock().unwrap().join("\n")
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedLogs {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Fields<'a>(&'a mut String);
            impl tracing::field::Visit for Fields<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, "{}={value:?} ", field.name());
                }
            }
            let mut line = String::new();
            event.record(&mut Fields(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }

    /// A one-connection HTTP endpoint on localhost. It reads one full request,
    /// writes `reply` (or closes without replying when `None`), and yields
    /// the raw request so the test can assert what did — and did not — travel.
    async fn one_shot_server(
        reply: Option<&'static str>,
    ) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !request_is_complete(&request) {
                let n = socket.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            if let Some(reply) = reply {
                let _ = socket.write_all(reply.as_bytes()).await;
            }
            String::from_utf8_lossy(&request).into_owned()
        });
        (url, handle)
    }

    fn request_is_complete(buf: &[u8]) -> bool {
        let text = String::from_utf8_lossy(buf);
        let Some(header_end) = text.find("\r\n\r\n") else {
            return false;
        };
        let content_length = text[..header_end]
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse::<usize>().unwrap_or(0))
            })
            .unwrap_or(0);
        buf.len() >= header_end + 4 + content_length
    }

    /// A structurally valid ID token whose header names a `kid`, so the
    /// verifier reaches the discovery/JWKS fetch instead of stopping at
    /// header parsing — which is the path the two tests below are about. Its
    /// payload and signature are junk.
    fn credential_reaching_discovery() -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
        format!(
            "{}.{}.{}",
            B64URL.encode(br#"{"alg":"RS256","kid":"test-key-1"}"#),
            B64URL.encode(b"payload"),
            B64URL.encode(b"signature"),
        )
    }

    fn assert_no_credential_in(err: &AppError, logs: &CapturedLogs, credential: &str) {
        assert!(
            matches!(err, AppError::Internal(_)),
            "expected an internal error, got {err:?}"
        );
        assert!(
            !format!("{err:?}").contains(credential),
            "the returned error carries the ID token"
        );
        let logged = logs.joined();
        assert!(
            logged.contains("internal error"),
            "the failure must still be logged, got {logged:?}"
        );
        assert!(
            !logged.contains(credential),
            "the ID token reached the logs: {logged}"
        );
    }

    /// The request a test server saw must never carry the ID token: it is
    /// decoded locally, and the only outbound requests are the discovery and
    /// JWKS GETs, whose URLs are built from the issuer alone.
    fn assert_credential_absent_from(request: &str, credential: &str) {
        assert!(!request.is_empty(), "the endpoint must have been contacted");
        assert!(
            !request.contains(credential),
            "the ID token travelled to the issuer: {request}"
        );
    }

    /// The issuer answers nothing and hangs up, so the discovery fetch fails
    /// and `AppError::internal` logs a transport error — with no credential
    /// in the error, the logs, or the request.
    #[tokio::test]
    async fn a_google_discovery_failure_never_logs_or_returns_the_id_token() {
        let logs = CapturedLogs::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(logs.clone()));
        let (issuer, server) = one_shot_server(None).await;
        let credential = credential_reaching_discovery();

        let result =
            verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &credential).await;

        let err = result.expect_err("a connection closed mid-exchange must fail");
        assert_no_credential_in(&err, &logs, &credential);
        assert_credential_absent_from(&server.await.unwrap(), &credential);
    }

    /// The issuer answers 200 with a body that is not the discovery JSON, so
    /// the decode step fails; reqwest's decode error names the request URL,
    /// which `without_url` strips before `AppError::internal` logs it.
    #[tokio::test]
    async fn a_google_decode_failure_never_logs_or_returns_the_id_token() {
        let logs = CapturedLogs::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(logs.clone()));
        let (issuer, server) = one_shot_server(Some(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json",
        ))
        .await;
        let credential = credential_reaching_discovery();

        let result =
            verify_google_id_token_at(&unconnected_pool(), &issuer, "client-id", &credential).await;

        let err = result.expect_err("an undecodable body must fail");
        assert_no_credential_in(&err, &logs, &credential);
        assert_credential_absent_from(&server.await.unwrap(), &credential);
    }
}

//! Account-management operations that need more than credential verification —
//! moved here (Plan 1.6a) rather than `attome-auth`, since `attome-auth` only ever
//! proves identity and must not touch `user_account` beyond that.
//!
//! P-account-state-enforcement (audit finding #2): federation must *prove
//! identity*, never mutate administrative state. Every write site below stops
//! setting `is_active = true` on an existing row (only a brand-new INSERT gets
//! `is_active = true`, since creating an account is not "reactivating" one),
//! pre-checks for a disabled row with the same email inside the same
//! transaction (closing the `0024_partial_unique_soft_delete.sql` partial-index
//! resurrection hole — a disabled row sits outside that index, so an ordinary
//! `ON CONFLICT` upsert would silently INSERT a second, brand-new active
//! account with the same email instead of being blocked), and re-checks
//! `is_active` after the write as defense in depth against a concurrent
//! disable racing the same login. `is_active IS NULL` is treated as active
//! throughout, matching 0024's index predicate (legacy rows, D-005).

use attome_db::DbPool;
use attome_modules::ModuleSet;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// D-786: the email domain reserved for platform service principals
/// (`metric-service@`, `workflow-system@`, the trd `*-system@` users). Those
/// rows have no credential of their own; nothing may sign in as one, so every
/// federated link/create path below and password register/login/reset refuse
/// an address in this domain.
pub const SERVICE_PRINCIPAL_EMAIL_DOMAIN: &str = "@internal.attome";

/// `true` when `email` (normalized) is in [`SERVICE_PRINCIPAL_EMAIL_DOMAIN`].
pub fn is_reserved_service_email(email: &str) -> bool {
    attome_auth::email_identity::normalize_email(email).ends_with(SERVICE_PRINCIPAL_EMAIL_DOMAIN)
}

/// The client-facing refusal for an address in the reserved domain, shared by
/// the generic-CRUD guard, invitations and S2S client binding.
pub fn reserved_service_email_message() -> String {
    format!(
        "addresses in the {SERVICE_PRINCIPAL_EMAIL_DOMAIN} domain are reserved for platform service principals"
    )
}

/// D-786 follow-up: refuses a caller-supplied address in the reserved domain
/// with a `422`, for write paths (invitations, S2S service users) that must
/// never target a service principal.
pub fn refuse_reserved_service_email(email: &str) -> Result<(), AppError> {
    if is_reserved_service_email(email) {
        return Err(AppError::Validation(reserved_service_email_message()));
    }
    Ok(())
}

/// D-786 follow-up M2: the `EngineModel::record_validators` entry for
/// `user_account` (declared in [`crate::model::SecurityModel`]). No
/// generic create or update may give a user row a reserved-domain address:
/// only engine code (metric, workflow, trd principals) writes one, with its
/// own SQL, so a generic write that names one is squatting or converting a
/// row into a service principal.
pub fn validate_systemuser_record(
    obj: &serde_json::Map<String, serde_json::Value>,
    _registry: &attome_core::meta_registry::EntityMetaRegistry,
) -> Result<(), String> {
    match obj.get("email") {
        Some(serde_json::Value::String(email)) if is_reserved_service_email(email) => {
            Err(reserved_service_email_message())
        }
        _ => Ok(()),
    }
}

/// `true` when a write naming `new` as the email of a row whose current email
/// is `current` must be refused: the row is a service principal and the
/// address would change (anything but the same address, normalized).
fn service_email_change_refused(current: &str, new: &serde_json::Value) -> bool {
    if !is_reserved_service_email(current) {
        return false;
    }
    match new {
        serde_json::Value::String(s) => {
            attome_auth::email_identity::normalize_email(s)
                != attome_auth::email_identity::normalize_email(current)
        }
        _ => true,
    }
}

/// D-786 follow-up M2: the service marker is the address, so a service
/// principal's email is immutable through generic CRUD. Called by
/// `attome_records::entity_mutation::update_one_as` for
/// `user_account` when the body names `email`; resending the current
/// address unchanged (a full-form save) is allowed.
pub async fn guard_service_principal_email_change(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record_id: Uuid,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AppError> {
    let Some(new) = obj.get("email") else {
        return Ok(());
    };
    let current: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    match current.flatten() {
        Some(current) if service_email_change_refused(&current, new) => {
            tracing::warn!(
                user_id = %record_id,
                "generic update refused: a service principal's email cannot be changed"
            );
            Err(AppError::Validation(
                "a platform service principal's email cannot be changed".to_owned(),
            ))
        }
        _ => Ok(()),
    }
}

fn reject_reserved_service_email(email: &str) -> Result<(), AppError> {
    if is_reserved_service_email(email) {
        tracing::warn!(
            "sign-in or identity link refused: the address is reserved for a service principal"
        );
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Refuses when the target account itself is a service principal, whatever
/// email the IdP asserted (the id-anchored and admin pre-provisioning paths).
async fn reject_if_service_account(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), AppError> {
    let email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    match email.flatten() {
        Some(email) => reject_reserved_service_email(&email),
        None => Ok(()),
    }
}

/// Links a verified Google identity (`attome_auth::accounts::verify_google_id_token`'s
/// output) to a `user_account` row, creating one if none exists yet. A
/// *first* login upserts on `email`, so Google links to an existing password
/// account automatically.
///
/// BAU-F22 / BAU-8c (G-7): every later login is anchored on the provider's
/// `sub`, never on the address. Once an email carries a `google_sub`, only
/// that same subject may sign in for it; another subject is
/// `AppError::Conflict` and writes nothing, because a hosted address
/// reassigned to a new person keeps its verified email and would otherwise
/// take over the previous holder's account.
///
/// `_license` is unused: it fed the seat gate, removed with seat enforcement
/// (D-778, CLEANUP-REVIEW 1.2). Kept in the signature until its callers drop
/// it.
pub async fn link_google_account(
    db: &DbPool,
    email: &str,
    google_sub: &str,
    _license: &ModuleSet,
) -> Result<Uuid, AppError> {
    let email = attome_auth::email_identity::normalize_email(email);
    reject_reserved_service_email(&email)?;
    let mut tx = attome_db::tx::begin(db).await?;

    // Same namespaced lock as attome_auth::accounts::register (D-121, extends
    // D-113) — federation and password registration must serialize on the
    // same email so a concurrent register-vs-disable or link-vs-disable
    // pair can't interleave a stale "not disabled" read past a commit on the
    // other side.
    if !attome_auth::email_identity::try_lock_email(&mut tx, &email).await? {
        return Err(AppError::Forbidden);
    }

    reject_if_email_disabled(&mut tx, &email).await?;

    // BAU-F22 / BAU-8c (G-7) — the binding is the provider's `sub`, never the
    // address. `reject_if_linking_would_bypass_existing_credential` below
    // covers a *first* link that collides with a differently-authenticated
    // account; this is the repeat-login half. An address Google has already
    // been linked to must present the SAME `sub` forever: a Workspace (or any
    // hosted) address reassigned to a new person keeps its verified email but
    // gets a new `sub`, and the `ON CONFLICT (email) DO UPDATE` below would
    // otherwise overwrite `google_sub` and hand the previous holder's account
    // — including everything it can reach — to whoever now controls the
    // mailbox. "google" is never a real `user_identity.provider_key`
    // (Google links via `google_sub` on `user_account` directly, a
    // legacy shape that predates the generic OIDC table), so passing it to the
    // takeover gate only excludes a same-provider `user_identity`
    // row, never the password/other-provider checks.
    let existing_google_sub: Option<String> = sqlx::query_scalar(
        "SELECT google_sub FROM user_account WHERE email = $1 AND google_sub IS NOT NULL",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    match existing_google_sub.as_deref() {
        Some(linked) if linked != google_sub => {
            tracing::warn!(
                "google login refused: this address is already linked to another \
                 Google subject; a reassigned address never takes over the account"
            );
            // `Conflict` carries a `&'static str` (attome-types), and the wording
            // is the actionable one the plan asks for: sign in the existing way
            // and link the new identity from settings (D-510's `identity_link`).
            return Err(AppError::Conflict(
                "this email is already linked to a different Google account; sign in your \
                 existing way and link this one from settings",
            ));
        }
        // A repeat login for the same subject skips the takeover gate, which
        // exists for a *first* link onto a differently-authenticated account.
        Some(_) => {}
        None => {
            reject_if_linking_would_bypass_existing_credential(&mut tx, &email, "google").await?;
        }
    }

    let user_id: Uuid = sqlx::query_scalar(
        // email_verified = true unconditionally: Google's tokeninfo already
        // asserted email_verified before this function is ever called
        // (accounts::verify_google_id_token) — every login re-checks it, so
        // there's no local staleness to worry about (P-account-lifecycle).
        // is_active = true only applies to the fresh-INSERT branch — the
        // UPDATE branch never touches it (P-account-state-enforcement).
        "INSERT INTO user_account (id, email, google_sub, created_at, last_login, is_active, email_verified)
         VALUES (uuidv7(), $1, $2, now(), now(), true, true)
         ON CONFLICT (email) WHERE is_active DO UPDATE
             SET google_sub     = EXCLUDED.google_sub,
                 last_login     = now(),
                 email_verified = true
         RETURNING id",
    )
    .bind(email)
    .bind(google_sub)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    reject_if_user_inactive(&mut tx, user_id).await?;
    reject_if_service_account(&mut tx, user_id).await?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(user_id)
}

/// Rejects a login/link attempt whose email belongs to a disabled account —
/// closes the partial-unique-index resurrection hole (see module doc). Must
/// run inside the same transaction as the subsequent insert/upsert so the
/// check and the write observe a consistent snapshot.
async fn reject_if_email_disabled(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &str,
) -> Result<(), AppError> {
    let disabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account WHERE email = $1 AND is_active = FALSE)",
    )
    .bind(email)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if disabled {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Enterprise-audit remediation: federation must never *silently* attach a
/// new identity to an account that can already authenticate another way —
/// an OIDC/Google login asserting a matching email is proof of mailbox
/// control at that IdP, not proof the caller controls the *existing*
/// password or other linked identity on this account. Without this check, an
/// attacker who compromises (or spins up) any operator-configured IdP tenant
/// and can get it to assert a victim's email takes over the victim's
/// password-protected account with zero additional confirmation.
///
/// Blocks the JIT-link only when the target account already has a password
/// (`password_hash IS NOT NULL`), a linked Google identity (`google_sub IS
/// NOT NULL` — Google links on `user_account` directly, never through
/// `user_identity`, so the sub-select below cannot see it; B4), or
/// a linked identity from a *different* provider than the one attempting
/// to link now — a brand-new account (no prior credential at all) still
/// JIT-creates exactly as before, and a repeat login from the *same*
/// provider never reaches this check (it resolves via the existing
/// `(provider_key, sub)` link instead). There is
/// no in-band way to complete a step-up confirmation inside an IdP redirect
/// flow, so this fails closed rather than attempting one: the caller must
/// sign in with their existing credential first and link the new provider
/// from an authenticated settings flow (not yet built) instead.
async fn reject_if_linking_would_bypass_existing_credential(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &str,
    provider_key: &str,
) -> Result<(), AppError> {
    let has_conflicting_credential: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM user_account u
             WHERE u.email = $1 AND (u.is_active IS NULL OR u.is_active = TRUE)
               AND (
                   u.password_hash IS NOT NULL
                   OR u.google_sub IS NOT NULL
                   OR EXISTS(
                       SELECT 1 FROM user_identity i
                       WHERE i.user_ref = u.id AND i.provider_key <> $2
                   )
               )
         )",
    )
    .bind(email)
    .bind(provider_key)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if has_conflicting_credential {
        return Err(AppError::Conflict(
            "an account with this email already has a different sign-in method; \
             sign in that way first, then link this provider from account settings",
        ));
    }
    Ok(())
}

/// Post-write check: defense in depth against a concurrent admin disable
/// racing this same login/link. `is_active IS NULL` is legacy-active (D-005).
async fn reject_if_user_inactive(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), AppError> {
    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if is_active == Some(false) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Links a verified OIDC identity (`attome_auth::oidc::complete_login`'s output)
/// to a `user_account` row — the generic form of `link_google_account`
/// above (P2.8/D-065). Thin wrapper over `link_external_identity`; see that
/// function for the actual logic and its doc comment for the design
/// reasoning. The link lands in the provider-agnostic `user_identity`
/// table.
///
/// The email is always stamped verified for OIDC: `attome_auth::oidc::verify_claims`
/// only ever returns `Ok` when the login is allowed to proceed at all — either
/// the `email_verified` claim explicitly said `true`, or the provider has
/// explicitly opted out of `require_email_verified_claim` (an operator
/// declaration that this provider's emails are trustworthy regardless of
/// claim presence). There is no "authenticated but unverified" OIDC state to
/// plumb through (P-federation-linking-policy §4.1).
///
/// `_license` is unused since seat enforcement was removed (D-778); see
/// [`link_google_account`].
pub async fn link_oidc_identity(
    db: &DbPool,
    provider_key: &str,
    sub: &str,
    email: &str,
    mode: &LinkMode,
    _license: &ModuleSet,
) -> Result<Uuid, AppError> {
    link_external_identity(db, provider_key, sub, email, mode).await
}

/// Q1-T8: what a provider does the first time it sees a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkMode {
    /// Link to an existing active account with the same verified email (or
    /// an administrator's pre-made link); never create one. A person with
    /// neither is refused with `Conflict("no_linked_account")`.
    LinkOnly,
    /// Link as above, or create the account; a created account gets
    /// `default_role` in the same transaction.
    Create { default_role: Option<Uuid> },
}

impl LinkMode {
    /// The mode a provider entry names (`link_only` or `create`).
    pub fn of(link_mode: &str, default_role: Option<Uuid>) -> Self {
        match link_mode {
            "create" => Self::Create { default_role },
            _ => Self::LinkOnly,
        }
    }
}

/// P-federation-linking-policy §4.3 — binds `(provider_key, sub)` directly to
/// an already-known, already-authenticated `user_id`. Two callers, both
/// deliberately bypassing `link_external_identity`'s email-matching entirely
/// (no `reject_if_email_disabled`/`reject_if_linking_would_bypass_existing_
/// credential` — those exist to police an *email-driven* JIT guess; here the
/// target account is not a guess, it's given):
/// - §4.3(a) session-gated self-service linking (`crates/server/src/auth.rs`'s
///   `identity_link_*` handlers) — `user_id` comes from the caller's own live
///   session, proven by completing the IdP round trip while already logged in.
/// - §4.3(b) admin pre-provisioning (`attome-security/src/admin.rs`'s
///   `create_identity_link`) — `user_id` comes from an admin's explicit choice
///   under `system.admin`, ahead of the user's first SSO login.
///
/// Idempotent when `(provider_key, sub)` is already linked to *this same*
/// `user_id` (repeat linking attempt, or a race with itself — just refreshes
/// the stored `email` display value, same as `link_external_identity`'s
/// existing-link branch). Rejects with `Conflict` when already linked to a
/// *different* user — the `core_user_identity_provider_sub_unique` constraint
/// (migration 0025) backstops this against a concurrent race between two
/// linking attempts for the same identity, mapped to the same typed error.
pub async fn link_identity_to_user(
    db: &DbPool,
    user_id: Uuid,
    provider_key: &str,
    sub: &str,
    email: &str,
) -> Result<(), AppError> {
    link_identity_to_user_with(db, user_id, provider_key, sub, email, &attome_db::NoHook).await
}

/// [`link_identity_to_user`], plus a [`attome_db::BeforeCommit`] hook that runs
/// in the link's transaction with the linked account id, so the caller's
/// `Credential` event commits with the link (audit plan 3.6, D-062).
pub async fn link_identity_to_user_with(
    db: &DbPool,
    user_id: Uuid,
    provider_key: &str,
    sub: &str,
    email: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<(), AppError> {
    let email = attome_auth::email_identity::normalize_email(email);
    reject_reserved_service_email(&email)?;
    let mut tx = attome_db::tx::begin(db).await?;
    // D-786: admin pre-provisioning names `user_id` directly; never onto a
    // service principal.
    reject_if_service_account(&mut tx, user_id).await?;

    // Defense in depth: the caller's session was valid when the linking flow
    // started, but the IdP round trip can take minutes — re-check here, same
    // posture as reject_if_user_inactive elsewhere in this module (P-account-
    // state-enforcement).
    reject_if_user_inactive(&mut tx, user_id).await?;

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind(provider_key)
    .bind(sub)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    match existing {
        Some(existing_user) if existing_user == user_id => {
            sqlx::query(
                "UPDATE user_identity SET email = $1
                 WHERE provider_key = $2 AND provider_sub = $3",
            )
            .bind(&email)
            .bind(provider_key)
            .bind(sub)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        Some(_) => {
            return Err(AppError::Conflict(
                "this identity is already linked to a different account",
            ));
        }
        None => {
            sqlx::query(
                "INSERT INTO user_identity (id, user_ref, provider_key, provider_sub, email)
                 VALUES (uuidv7(), $1, $2, $3, $4)",
            )
            .bind(user_id)
            .bind(provider_key)
            .bind(sub)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }

    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Google's analog of `link_identity_to_user` above, for an already-known,
/// already-authenticated `user_id` — extends P-federation-linking-policy
/// §4.3(a) to Google's legacy `google_sub`-on-`user_account` shape (D-072's
/// de-emphasis-not-removal decision kept that shape rather than migrating
/// Google onto the generic `user_identity` table `link_identity_to_user`
/// uses). Deliberately requires the Google identity's verified email to match
/// the caller's own account email (normalized): unlike `user_identity`'s
/// `(provider_key, sub)` join key, `google_login`'s existing-account lookup
/// (`link_google_account`'s `already_google_linked` check) is entirely
/// email-driven, so a linked Google identity with a *different* email would
/// silently stop being reachable through that path on the very next Google
/// sign-in — this rejects that mismatch up front as a validation error (the
/// caller's input is wrong, not a race) rather than producing a link that
/// quietly can't be used to sign in later.
///
/// Idempotent when `google_sub` already resolves to *this same* `user_id`.
/// Rejects with `Conflict` when it already resolves to a *different* user —
/// the partial unique index `core_systemuser_google_sub_unique` (migration
/// 0024) backstops this against a concurrent race between two linking
/// attempts for the same Google identity, mapped to the same typed error,
/// same posture as `link_identity_to_user`'s `core_user_identity_provider_sub_unique`
/// backstop.
pub async fn link_google_to_user(
    db: &DbPool,
    user_id: Uuid,
    google_sub: &str,
    google_email: &str,
) -> Result<(), AppError> {
    link_google_to_user_with(db, user_id, google_sub, google_email, &attome_db::NoHook).await
}

/// [`link_google_to_user`], plus a [`attome_db::BeforeCommit`] hook that runs
/// in the link's transaction with the account id (D-062).
pub async fn link_google_to_user_with(
    db: &DbPool,
    user_id: Uuid,
    google_sub: &str,
    google_email: &str,
    hook: &dyn attome_db::BeforeCommit<Uuid>,
) -> Result<(), AppError> {
    let google_email = attome_auth::email_identity::normalize_email(google_email);
    reject_reserved_service_email(&google_email)?;
    let mut tx = attome_db::tx::begin(db).await?;
    reject_if_service_account(&mut tx, user_id).await?;

    // Defense in depth: the caller's session was valid a moment ago, but
    // nothing prevents a concurrent admin disable racing this same request
    // (P-account-state-enforcement, same posture as link_identity_to_user).
    reject_if_user_inactive(&mut tx, user_id).await?;

    let account_email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if attome_auth::email_identity::normalize_email(&account_email) != google_email {
        return Err(AppError::Validation(
            "this Google account's email must match your account's email to link it".to_string(),
        ));
    }

    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE google_sub = $1")
            .bind(google_sub)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    match existing {
        Some(existing_user) if existing_user == user_id => {
            // Already linked to this same account — idempotent no-op, same
            // shape as link_identity_to_user's matching branch.
        }
        Some(_) => {
            return Err(AppError::Conflict(
                "this Google account is already linked to a different account",
            ));
        }
        None => {
            sqlx::query("UPDATE user_account SET google_sub = $1 WHERE id = $2")
                .bind(google_sub)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        }
    }

    hook.before_commit(&mut tx, &user_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// A row of `list_identities_for_user`'s result: `(provider_key, email,
/// linked_at)`. Tuple type, not a `FromRow` derive — matches the row-alias
/// convention `attome-security/src/admin.rs` already uses (`GrantRow` etc.)
/// rather than introducing a new pattern for one query.
type IdentityLinkRow = (String, String, DateTime<Utc>);

/// P-federation-linking-policy §4.3(a) UI support — lists the federated
/// identities currently linked to `user_id`, so the self-service linking page
/// (`/settings/security`) can show what's already connected instead of
/// blindly offering every configured provider as "not yet linked". Read-only
/// and self-scoped (`user_id` always comes from the caller's own
/// `SessionClaims`, never a path/query parameter) — no `system.admin` gate
/// needed, same posture as `crates/server/src/auth.rs::session_info`.
///
/// Google is intentionally excluded here: it links via
/// `user_account.google_sub`, not `user_identity` (D-072's
/// de-emphasis-not-removal decision), so it has no `created_at` link
/// timestamp to report through this query — `crates/server/src/auth.rs`'s
/// `identity_links` handler reports Google's linked state as a separate
/// synthetic entry instead of extending this function.
pub async fn list_identities_for_user(
    db: &DbPool,
    user_id: Uuid,
) -> Result<Vec<IdentityLinkRow>, AppError> {
    let rows: Vec<IdentityLinkRow> = sqlx::query_as(
        "SELECT provider_key, email, created_at
         FROM user_identity
         WHERE user_ref = $1
         ORDER BY created_at ASC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows)
}

/// The `(provider_key, provider_sub)` pair is treated as the stable
/// identity — an IdP's `sub`/NameID never changes, but its `email` claim can
/// (a user renames their corporate email address). So: if a link for this
/// `(provider_key, sub)` already exists, its `user_ref` is authoritative
/// regardless of what `email` says today; only on the *first* login for that
/// pair does JIT-linking-by-email run (same email-upsert shape as
/// `link_google_account`, so an OIDC login still auto-links to an
/// existing password/Google account). Both branches commit in one
/// transaction — an interrupted link must never leave a `user_account`
/// row with no matching identity link, or vice versa.
async fn link_external_identity(
    db: &DbPool,
    provider_key: &str,
    sub: &str,
    email: &str,
    mode: &LinkMode,
) -> Result<Uuid, AppError> {
    let email = attome_auth::email_identity::normalize_email(email);
    reject_reserved_service_email(&email)?;
    let mut tx = attome_db::tx::begin(db).await?;

    // Only the first-login (JIT-create) branch below actually writes
    // user_account by email — an existing (provider_key, sub) link
    // resolves straight to its user_ref and never touches email uniqueness.
    // The lock still needs to be held for the whole transaction (not just
    // the None branch) because which branch runs is itself decided by a
    // read a moment ago; without holding it up front, a concurrent
    // first-login for the same email could interleave between this
    // function's existing-link check and its own first-login branch.
    if !attome_auth::email_identity::try_lock_email(&mut tx, &email).await? {
        return Err(AppError::Forbidden);
    }

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind(provider_key)
    .bind(sub)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let user_id = match existing {
        Some(user_id) => {
            // Federation proves identity, never mutates administrative state
            // (P-account-state-enforcement) — stamp last_login only. A
            // disabled account is caught below by reject_if_user_inactive,
            // not reactivated here.
            sqlx::query(
                "UPDATE user_account
                 SET last_login = now()
                 WHERE id = $1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;

            sqlx::query(
                "UPDATE user_identity SET email = $1
                 WHERE provider_key = $2 AND provider_sub = $3",
            )
            .bind(&email)
            .bind(provider_key)
            .bind(sub)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;

            user_id
        }
        None => {
            // First time this (provider, sub) has been seen — JIT-link to an
            // existing account by email, or create one. The OIDC login only
            // ever reaches here already-trusted (see `link_oidc_identity`'s
            // doc comment), so the account is stamped `email_verified`.
            //
            // reject_if_email_disabled closes the partial-unique-index
            // resurrection hole for this federated path too — without it, a
            // disabled row sits outside 0024's partial index and this
            // ON CONFLICT would silently INSERT a brand-new active account
            // with the same email (P-account-state-enforcement).
            reject_if_email_disabled(&mut tx, &email).await?;
            reject_if_linking_would_bypass_existing_credential(&mut tx, &email, provider_key)
                .await?;

            // Q1-T8: a link-only provider never creates the account.
            if *mode == LinkMode::LinkOnly {
                let known: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM user_account WHERE email = $1 AND is_active IS NOT FALSE",
                )
                .bind(&email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                if known.is_none() {
                    return Err(AppError::Conflict("no_linked_account"));
                }
            }

            let (user_id, created): (Uuid, bool) = sqlx::query_as(
                "INSERT INTO user_account (id, email, created_at, last_login, is_active, email_verified)
                 VALUES (uuidv7(), $1, now(), now(), true, true)
                 ON CONFLICT (email) WHERE is_active DO UPDATE
                     SET last_login = now(), email_verified = true
                 RETURNING id, (xmax = 0)",
            )
            .bind(&email)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

            // Q1-T8: a created account gets the provider's default role in the
            // same transaction. (A provider's default role never carries
            // `system.admin`; the provider admin refuses it at save.)
            if let (
                true,
                LinkMode::Create {
                    default_role: Some(role),
                },
            ) = (created, mode)
            {
                sqlx::query(
                    "INSERT INTO user_account_mm_role (user_ref, role_ref)                      SELECT $1, id FROM role WHERE id = $2 AND is_deleted = false",
                )
                .bind(user_id)
                .bind(role)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }

            sqlx::query(
                "INSERT INTO user_identity (id, user_ref, provider_key, provider_sub, email)
                 VALUES (uuidv7(), $1, $2, $3, $4)",
            )
            .bind(user_id)
            .bind(provider_key)
            .bind(sub)
            .bind(&email)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;

            user_id
        }
    };

    // Defense in depth against a concurrent admin disable racing this same
    // login/link (P-account-state-enforcement) — covers both branches above.
    reject_if_user_inactive(&mut tx, user_id).await?;
    // D-786: an existing (provider, sub) link resolves by id, not email.
    reject_if_service_account(&mut tx, user_id).await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::{
        is_reserved_service_email, refuse_reserved_service_email, service_email_change_refused,
        validate_systemuser_record,
    };
    use serde_json::json;

    fn body(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn generic_crud_cannot_set_a_reserved_email() {
        let registry = attome_core::meta_registry::EntityMetaRegistry::default();
        for email in [
            "metric-service@internal.attome",
            " Squatter@INTERNAL.attome ",
        ] {
            assert!(
                validate_systemuser_record(&body(json!({ "email": email })), &registry).is_err(),
                "{email} must be refused"
            );
        }
        assert!(
            validate_systemuser_record(&body(json!({ "email": "a@example.test" })), &registry)
                .is_ok()
        );
        assert!(validate_systemuser_record(&body(json!({ "user_name": "x" })), &registry).is_ok());
        assert!(validate_systemuser_record(&body(json!({ "email": null })), &registry).is_ok());
    }

    #[test]
    fn a_service_principal_email_cannot_change() {
        let svc = "metric-service@internal.attome";
        assert!(service_email_change_refused(
            svc,
            &json!("attacker@example.test")
        ));
        assert!(service_email_change_refused(svc, &json!(null)));
        assert!(service_email_change_refused(
            svc,
            &json!("other@internal.attome")
        ));
        // Resending the same address (normalized) is a full-form save: allowed.
        assert!(!service_email_change_refused(
            svc,
            &json!(" Metric-Service@internal.attome")
        ));
        // An ordinary user's email stays editable.
        assert!(!service_email_change_refused(
            "a@example.test",
            &json!("b@example.test")
        ));
    }

    #[test]
    fn refuse_reserved_service_email_is_a_validation_error() {
        assert!(matches!(
            refuse_reserved_service_email("workflow-system@internal.attome"),
            Err(attome_types::AppError::Validation(_))
        ));
        assert!(refuse_reserved_service_email("a@example.test").is_ok());
    }

    #[test]
    fn service_principal_addresses_are_reserved_case_insensitively() {
        assert!(is_reserved_service_email("metric-service@internal.attome"));
        assert!(is_reserved_service_email(
            " Workflow-System@INTERNAL.Attome "
        ));
        assert!(is_reserved_service_email(
            "trd-trader-profile-system@internal.attome"
        ));
        assert!(!is_reserved_service_email("someone@attome.example"));
        assert!(!is_reserved_service_email("internal.attome@example.test"));
    }
}

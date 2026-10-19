//! Portal and portal-user provisioning (D-576). **Business logic only**: every
//! function runs on the caller's open transaction, so the HTTP handlers in
//! [`crate::admin`] can commit the change and its D-542 security event
//! together, and the integration tests can drive the same code on a plain
//! transaction.
//!
//! These are the only writers of the fields [`crate::guard`] refuses to
//! generic CRUD, and the only code that creates or deletes a portal user's
//! credential row. A user's entity row and credential row are always created
//! and removed in the same transaction.
//!
//! Concurrency: each operation takes a transaction-scoped advisory lock in
//! [`crate::ADVISORY_LOCK_NAMESPACE`] before reading, so two admins racing on
//! the same keyword, email or record serialize, and the loser gets a
//! `Conflict` rather than a duplicate. Row-version checks guard the settings
//! update against a stale read.

use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::keyword;

/// `webportal.portal_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortalType {
    /// Public pages, forms, status lookup and web chat; no login at all.
    Anonymous,
    /// Everything behind login.
    Authenticated,
    /// Public pages plus a login area.
    Mixed,
}

impl PortalType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Authenticated => "authenticated",
            Self::Mixed => "mixed",
        }
    }

    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "anonymous" => Ok(Self::Anonymous),
            "authenticated" => Ok(Self::Authenticated),
            "mixed" => Ok(Self::Mixed),
            other => Err(AppError::internal(format!(
                "webportal.portal_type holds an unknown value '{other}'"
            ))),
        }
    }

    pub fn has_users(self) -> bool {
        !matches!(self, Self::Anonymous)
    }
}

/// `webportal.mfa_policy` (R10). `null` in the column means `optional`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum MfaPolicy {
    /// Users may enroll a TOTP authenticator; an enrolled user must use it.
    #[default]
    Optional,
    /// Every user must enroll before the portal serves them anything but the
    /// MFA enrollment and logout routes.
    Required,
}

impl MfaPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    fn parse(s: Option<&str>) -> Result<Self, AppError> {
        match s {
            None | Some("optional") => Ok(Self::Optional),
            Some("required") => Ok(Self::Required),
            Some(other) => Err(AppError::internal(format!(
                "webportal.mfa_policy holds an unknown value '{other}'"
            ))),
        }
    }
}

/// `webportal_user.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortalUserStatus {
    /// Provisioned, no password set yet.
    Invited,
    Active,
    Disabled,
}

impl PortalUserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "invited" => Ok(Self::Invited),
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            other => Err(AppError::internal(format!(
                "webportal_user.status holds an unknown value '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PortalDetail {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub keyword: String,
    pub portal_type: PortalType,
    pub is_enabled: bool,
    pub owning_team_ref: Option<Uuid>,
    pub mfa_policy: MfaPolicy,
    pub row_version: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PortalUserDetail {
    pub id: Uuid,
    pub webportal_id: Uuid,
    pub name: String,
    /// D-777: optional when the user has a username.
    pub email: Option<String>,
    /// D-777: the login username (case kept); optional when the user has an
    /// email.
    pub username: Option<String>,
    pub status: PortalUserStatus,
    pub row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPortal {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub keyword: String,
    pub portal_type: PortalType,
    /// Defaults to false: a new portal serves nothing until it is enabled.
    #[serde(default)]
    pub is_enabled: bool,
    /// The staff team that owns records portal users create (D-576 item 7).
    #[serde(default)]
    pub owning_team_ref: Option<Uuid>,
    #[serde(default)]
    pub mfa_policy: MfaPolicy,
}

/// Every field optional except `row_version`. `owning_team_ref` distinguishes
/// "absent" (unchanged) from `null` (cleared).
#[derive(Debug, Deserialize, ToSchema)]
pub struct PortalSettingsPatch {
    pub row_version: i64,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub portal_type: Option<PortalType>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default, with = "double_option")]
    #[schema(value_type = Option<Uuid>)]
    pub owning_team_ref: Option<Option<Uuid>>,
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
}

/// D-777: at least one of `email` and `username`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPortalUser {
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(d).map(Some)
    }
}

pub(crate) async fn lock(conn: &mut PgConnection, key: String) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another request is changing this web portal; retry",
        ))
    }
}

fn required_text(value: &str, field: &str, max: usize) -> Result<String, AppError> {
    let v = value.trim();
    if v.is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    if v.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(v.to_owned())
}

/// Lowercased login email. Deliberately a shape check only; ownership of the
/// address is proven by the verification step at invitation acceptance.
pub(crate) fn normalize_email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && matches!(email.split_once('@'), Some((local, domain))
            if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.'));
    if valid {
        Ok(email)
    } else {
        Err(AppError::Validation("email is not a valid address".into()))
    }
}

/// D-777: a login identifier as typed: an email when it contains `@`,
/// otherwise a username. Both are compared lowercased.
pub fn login_key(identifier: &str) -> LoginKey {
    let id = identifier.trim();
    if id.contains('@') {
        LoginKey::Email(id.to_lowercase())
    } else {
        LoginKey::Username(id.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginKey {
    Email(String),
    Username(String),
}

/// The identifiers of a new account, checked and normalized.
struct Identifiers {
    email: Option<String>,
    /// As stored (case kept).
    username: Option<String>,
}

impl Identifiers {
    fn username_lower(&self) -> Option<String> {
        self.username.as_deref().map(str::to_ascii_lowercase)
    }
}

async fn check_identifiers(
    conn: &mut PgConnection,
    portal_id: Uuid,
    email: Option<&str>,
    username: Option<&str>,
) -> Result<Identifiers, AppError> {
    let email = match email.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => Some(normalize_email(e)?),
        None => None,
    };
    let username = match username.map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => {
            let policy = crate::policy::load(conn, portal_id).await?;
            Some(
                policy
                    .check_username(u)
                    .map_err(|why| AppError::Validation(why.message()))?,
            )
        }
        None => None,
    };
    if email.is_none() && username.is_none() {
        return Err(AppError::Validation(
            "a web portal user needs an email or a username".into(),
        ));
    }
    Ok(Identifiers { email, username })
}

/// Takes the advisory locks for a new account's identifiers and reports
/// which one is already used by a live account of the portal, if any. The
/// unique indexes on the credential are the guarantee; this is the friendly
/// path.
async fn claim_identifiers(
    conn: &mut PgConnection,
    portal_id: Uuid,
    ids: &Identifiers,
) -> Result<Option<&'static str>, AppError> {
    if let Some(email) = &ids.email {
        lock(
            conn,
            format!("attome-portal/user-email:{portal_id}:{email}"),
        )
        .await?;
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM webportal_user \
             WHERE webportal_ref = $1 AND lower(email) = $2 AND is_active IS NOT FALSE)",
        )
        .bind(portal_id)
        .bind(email)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if taken {
            return Ok(Some("this web portal already has a user with this email"));
        }
    }
    if let Some(username) = ids.username_lower() {
        lock(
            conn,
            format!("attome-portal/user-username:{portal_id}:{username}"),
        )
        .await?;
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM webportal_credential \
             WHERE webportal_id = $1 AND login_username_lower = $2)",
        )
        .bind(portal_id)
        .bind(&username)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if taken {
            return Ok(Some(
                "this web portal already has a user with this username",
            ));
        }
    }
    Ok(None)
}

/// A unique-index violation on the credential, as the Conflict it means.
fn credential_conflict(e: sqlx::Error) -> AppError {
    if !attome_db::is_unique_violation(&e) {
        return AppError::internal(e);
    }
    let constraint = e.as_database_error().and_then(|d| d.constraint());
    if constraint == Some("webportal_credential_login_username_uq") {
        AppError::Conflict("this web portal already has a user with this username")
    } else {
        AppError::Conflict("this web portal already has a user with this email")
    }
}

async fn ensure_team_exists(conn: &mut PgConnection, team_id: Uuid) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM team WHERE id = $1 AND is_active IS NOT FALSE)",
    )
    .bind(team_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::Validation(
            "owning_team_ref does not name an active team".into(),
        ))
    }
}

/// Keywords are unique across every portal row, soft-deleted ones included,
/// so a generic restore can never bring back a second portal on the same URL.
async fn ensure_keyword_free(
    conn: &mut PgConnection,
    keyword: &str,
    except: Option<Uuid>,
) -> Result<(), AppError> {
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM webportal \
         WHERE keyword = $1 AND ($2::uuid IS NULL OR id <> $2))",
    )
    .bind(keyword)
    .bind(except)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if taken {
        Err(AppError::Conflict("a web portal already uses this keyword"))
    } else {
        Ok(())
    }
}

type PortalRow = (
    Uuid,
    String,
    Option<String>,
    String,
    String,
    Option<bool>,
    Option<Uuid>,
    Option<String>,
    i64,
);

const PORTAL_COLUMNS: &str = "id, name, description, keyword, portal_type, is_enabled, \
                              owning_team_ref, mfa_policy, row_version";

fn portal_from_row(r: PortalRow) -> Result<PortalDetail, AppError> {
    Ok(PortalDetail {
        id: r.0,
        name: r.1,
        description: r.2,
        keyword: r.3,
        portal_type: PortalType::parse(&r.4)?,
        is_enabled: r.5.unwrap_or(false),
        owning_team_ref: r.6,
        mfa_policy: MfaPolicy::parse(r.7.as_deref())?,
        row_version: r.8,
    })
}

/// A live (not soft-deleted) portal, or `NotFound`.
pub(crate) async fn load_portal(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<PortalDetail, AppError> {
    let row: Option<PortalRow> = sqlx::query_as(&format!(
        "SELECT {PORTAL_COLUMNS} FROM webportal WHERE id = $1 AND is_active IS NOT FALSE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    portal_from_row(row.ok_or(AppError::NotFound)?)
}

/// Revokes every session of every user of `portal_id` (D-576 item 8).
async fn bump_portal_epochs(conn: &mut PgConnection, portal_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE webportal_credential \
         SET auth_epoch = auth_epoch + 1, updated_at = NOW() WHERE webportal_id = $1",
    )
    .bind(portal_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

pub async fn create_portal(
    conn: &mut PgConnection,
    actor: Uuid,
    new: NewPortal,
) -> Result<PortalDetail, AppError> {
    let name = required_text(&new.name, "name", 200)?;
    let keyword = keyword::normalize(&new.keyword).map_err(AppError::Validation)?;
    if let Some(team) = new.owning_team_ref {
        ensure_team_exists(conn, team).await?;
    }

    lock(conn, format!("attome-portal/keyword:{keyword}")).await?;
    ensure_keyword_free(conn, &keyword, None).await?;

    let row: PortalRow = sqlx::query_as(&format!(
        "INSERT INTO webportal \
           (name, description, keyword, portal_type, is_enabled, owning_team_ref, mfa_policy, \
            created_by, modified_by, modified_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $8, $7, $7, NOW()) \
         RETURNING {PORTAL_COLUMNS}"
    ))
    .bind(&name)
    .bind(
        new.description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty()),
    )
    .bind(&keyword)
    .bind(new.portal_type.as_str())
    .bind(new.is_enabled)
    .bind(new.owning_team_ref)
    .bind(actor)
    .bind(new.mfa_policy.as_str())
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    portal_from_row(row)
}

pub async fn update_portal_settings(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    patch: PortalSettingsPatch,
) -> Result<PortalDetail, AppError> {
    lock(conn, format!("attome-portal/portal:{portal_id}")).await?;
    let current = load_portal(conn, portal_id).await?;
    if current.row_version != patch.row_version {
        return Err(AppError::VersionConflict);
    }

    let keyword = match patch.keyword.as_deref() {
        Some(raw) => keyword::normalize(raw).map_err(AppError::Validation)?,
        None => current.keyword.clone(),
    };
    if keyword != current.keyword {
        lock(conn, format!("attome-portal/keyword:{keyword}")).await?;
        ensure_keyword_free(conn, &keyword, Some(portal_id)).await?;
    }
    let portal_type = patch.portal_type.unwrap_or(current.portal_type);
    let is_enabled = patch.is_enabled.unwrap_or(current.is_enabled);
    let owning_team_ref = patch.owning_team_ref.unwrap_or(current.owning_team_ref);
    let mfa_policy = patch.mfa_policy.unwrap_or(current.mfa_policy);
    if let Some(team) = owning_team_ref
        && Some(team) != current.owning_team_ref
    {
        ensure_team_exists(conn, team).await?;
    }

    let row: Option<PortalRow> = sqlx::query_as(&format!(
        "UPDATE webportal SET keyword = $3, portal_type = $4, is_enabled = $5, \
           owning_team_ref = $6, mfa_policy = $8, modified_by = $7, modified_at = NOW(), \
           row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND is_active IS NOT FALSE \
         RETURNING {PORTAL_COLUMNS}"
    ))
    .bind(portal_id)
    .bind(patch.row_version)
    .bind(&keyword)
    .bind(portal_type.as_str())
    .bind(is_enabled)
    .bind(owning_team_ref)
    .bind(actor)
    .bind(mfa_policy.as_str())
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let updated = portal_from_row(row.ok_or(AppError::VersionConflict)?)?;

    // Disabling a portal, or turning it anonymous (no users), ends every
    // session its users hold.
    let disabled = current.is_enabled && !updated.is_enabled;
    let lost_users = current.portal_type.has_users() && !updated.portal_type.has_users();
    if disabled || lost_users {
        bump_portal_epochs(conn, portal_id).await?;
    }
    Ok(updated)
}

type UserRow = (
    Uuid,
    Option<Uuid>,
    String,
    Option<String>,
    Option<String>,
    String,
    i64,
);

const USER_COLUMNS: &str = "id, webportal_ref, name, email, username, status, row_version";

fn user_from_row(r: UserRow) -> Result<PortalUserDetail, AppError> {
    Ok(PortalUserDetail {
        id: r.0,
        webportal_id: r
            .1
            .ok_or_else(|| AppError::internal("webportal_user row without webportal_ref"))?,
        name: r.2,
        email: r.3,
        username: r.4,
        status: PortalUserStatus::parse(&r.5)?,
        row_version: r.6,
    })
}

/// A live user of `portal_id`, or `NotFound` (also when the user belongs to a
/// different portal, so ids can't be probed across portals).
async fn load_user(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<PortalUserDetail, AppError> {
    let row: Option<UserRow> = sqlx::query_as(&format!(
        "SELECT {USER_COLUMNS} FROM webportal_user \
         WHERE id = $1 AND webportal_ref = $2 AND is_active IS NOT FALSE"
    ))
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    user_from_row(row.ok_or(AppError::NotFound)?)
}

/// Provisions a portal user as `invited`, with an empty credential row. The
/// password is set when the invitation is accepted (Phase 2).
pub async fn create_user(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    new: NewPortalUser,
) -> Result<PortalUserDetail, AppError> {
    let name = required_text(&new.name, "name", 200)?;
    let portal = load_portal(conn, portal_id).await?;
    if !portal.portal_type.has_users() {
        return Err(AppError::Validation(
            "an anonymous web portal has no users".into(),
        ));
    }
    let ids = check_identifiers(
        conn,
        portal_id,
        new.email.as_deref(),
        new.username.as_deref(),
    )
    .await?;
    if let Some(taken) = claim_identifiers(conn, portal_id, &ids).await? {
        return Err(AppError::Conflict(taken));
    }

    let row: UserRow = sqlx::query_as(&format!(
        "INSERT INTO webportal_user \
           (name, email, username, webportal_ref, status, created_by, modified_by, modified_at) \
         VALUES ($1, $2, $3, $4, 'invited', $5, $5, NOW()) \
         RETURNING {USER_COLUMNS}"
    ))
    .bind(&name)
    .bind(&ids.email)
    .bind(&ids.username)
    .bind(portal_id)
    .bind(actor)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let user = user_from_row(row)?;

    // D-588 item 4, D-777: the unique indexes on (webportal_id,
    // login_email_lower) and (webportal_id, login_username_lower) are the
    // guarantee; the advisory locks above are the friendly path.
    sqlx::query(
        "INSERT INTO webportal_credential \
           (webportal_user_id, webportal_id, login_email_lower, login_username_lower) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user.id)
    .bind(portal_id)
    .bind(&ids.email)
    .bind(ids.username_lower())
    .execute(&mut *conn)
    .await
    .map_err(credential_conflict)?;
    Ok(user)
}

/// Creates an `active`, email-verified account from a verified signup or an
/// OIDC first login (D-588 items 2-3). No staff user is involved, so
/// `created_by` stays NULL (D-579). `password_hash` is `None` for an account
/// that signs in only through OIDC. `None` when the address already has a
/// live account in this portal (the caller creates nothing).
pub async fn create_verified_user(
    conn: &mut PgConnection,
    portal_id: Uuid,
    name: &str,
    email_lower: &str,
    password_hash: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    create_verified_account(
        conn,
        portal_id,
        name,
        Some(email_lower),
        None,
        password_hash,
    )
    .await
}

/// D-777: [`create_verified_user`] for any identifiers: an `active`
/// account with an email, a username, or both. `email_verified` is TRUE:
/// the caller proved the email (signup link, identity provider) or there is
/// none to prove. `None` when an identifier is already used by a live
/// account of the portal (the caller creates nothing); a concurrent create
/// of the same identifier loses on the unique index as a Conflict.
pub async fn create_verified_account(
    conn: &mut PgConnection,
    portal_id: Uuid,
    name: &str,
    email: Option<&str>,
    username: Option<&str>,
    password_hash: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    let name = required_text(name, "name", 200)?;
    let ids = check_identifiers(conn, portal_id, email, username).await?;
    if claim_identifiers(conn, portal_id, &ids).await?.is_some() {
        return Ok(None);
    }
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO webportal_user (name, email, username, webportal_ref, status, modified_at) \
         VALUES ($1, $2, $3, $4, 'active', NOW()) RETURNING id",
    )
    .bind(&name)
    .bind(&ids.email)
    .bind(&ids.username)
    .bind(portal_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO webportal_credential \
           (webportal_user_id, webportal_id, login_email_lower, login_username_lower, \
            password_hash, password_changed_at, email_verified) \
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 IS NULL THEN NULL ELSE NOW() END, TRUE)",
    )
    .bind(user_id)
    .bind(portal_id)
    .bind(&ids.email)
    .bind(ids.username_lower())
    .bind(password_hash)
    .execute(&mut *conn)
    .await
    .map_err(credential_conflict)?;
    Ok(Some(user_id))
}

/// D-588 item 4: fills `login_email_lower` on credentials created before
/// migration 0489. Idempotent. Where two live accounts of one portal share an
/// address (possible only before the index existed), the older keeps it and
/// the rest stay NULL with a warning, for an operator to resolve.
pub async fn backfill_login_emails(db: &sqlx::PgPool) -> Result<(), AppError> {
    let filled = sqlx::query(
        "UPDATE webportal_credential c SET login_email_lower = pick.email \
         FROM ( \
           SELECT DISTINCT ON (u.webportal_ref, lower(u.email)) \
                  u.id, lower(u.email) AS email \
           FROM webportal_user u \
           WHERE u.is_active IS NOT FALSE AND u.email IS NOT NULL \
           ORDER BY u.webportal_ref, lower(u.email), u.created_at, u.id \
         ) pick \
         WHERE c.webportal_user_id = pick.id AND c.login_email_lower IS NULL \
           AND NOT EXISTS (SELECT 1 FROM webportal_credential o \
                           WHERE o.webportal_id = c.webportal_id \
                             AND o.login_email_lower = pick.email)",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webportal_credential c \
         JOIN webportal_user u ON u.id = c.webportal_user_id \
         WHERE c.login_email_lower IS NULL AND u.email IS NOT NULL \
           AND u.is_active IS NOT FALSE",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if filled > 0 {
        tracing::info!(
            filled,
            "attome-portal: backfilled portal login emails (D-588)"
        );
    }
    if missing > 0 {
        tracing::warn!(
            missing,
            "attome-portal: portal credentials share a login email with another account of the \
             same portal and were left without one; resolve the duplicates (D-588 item 4)"
        );
    }
    Ok(())
}

/// Enables or disables a portal user. Disabling bumps the credential epoch,
/// so every session the user holds ends at once. Enabling returns the user to
/// `active` if a password is set, otherwise to `invited`. Idempotent.
pub async fn set_user_enabled(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    user_id: Uuid,
    enabled: bool,
) -> Result<PortalUserDetail, AppError> {
    lock(conn, format!("attome-portal/user:{user_id}")).await?;
    let current = load_user(conn, portal_id, user_id).await?;

    let target = if enabled {
        let has_password: Option<bool> = sqlx::query_scalar(
            "SELECT password_hash IS NOT NULL FROM webportal_credential \
             WHERE webportal_user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let has_password = has_password
            .ok_or_else(|| AppError::internal("webportal_user has no credential row"))?;
        if has_password {
            PortalUserStatus::Active
        } else {
            PortalUserStatus::Invited
        }
    } else {
        PortalUserStatus::Disabled
    };
    if target == current.status {
        return Ok(current);
    }

    let row: UserRow = sqlx::query_as(&format!(
        "UPDATE webportal_user SET status = $2, modified_by = $3, modified_at = NOW(), \
           row_version = row_version + 1 \
         WHERE id = $1 RETURNING {USER_COLUMNS}"
    ))
    .bind(user_id)
    .bind(target.as_str())
    .bind(actor)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    if target == PortalUserStatus::Disabled {
        sqlx::query(
            "UPDATE webportal_credential \
             SET auth_epoch = auth_epoch + 1, updated_at = NOW() WHERE webportal_user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    user_from_row(row)
}

/// Removes a portal user: the entity row is soft-deleted and disabled, and
/// the credential row is deleted outright, which ends every session. A
/// generic restore of the entity row brings back a profile with no
/// credential, which cannot log in.
pub async fn delete_user(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    lock(conn, format!("attome-portal/user:{user_id}")).await?;
    load_user(conn, portal_id, user_id).await?;

    sqlx::query(
        "UPDATE webportal_user SET is_active = FALSE, status = 'disabled', \
           modified_by = $2, modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM webportal_credential WHERE webportal_user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

// ── Admin reads and erasure (plan §9.5 G-8, G-14) ─────────────────────────────

/// A page of portals, newest first.
pub async fn list_portals(
    conn: &mut PgConnection,
    page: i64,
    page_size: i64,
) -> Result<(Vec<PortalDetail>, i64), AppError> {
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM webportal WHERE is_active IS NOT FALSE")
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    let rows: Vec<PortalRow> = sqlx::query_as(&format!(
        "SELECT {PORTAL_COLUMNS} FROM webportal WHERE is_active IS NOT FALSE \
         ORDER BY id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(portal_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((items, total))
}

/// A page of one portal's users (erased and deleted users excluded), newest
/// first.
pub async fn list_users(
    conn: &mut PgConnection,
    portal_id: Uuid,
    page: i64,
    page_size: i64,
) -> Result<(Vec<PortalUserDetail>, i64), AppError> {
    load_portal(conn, portal_id).await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webportal_user \
         WHERE webportal_ref = $1 AND is_active IS NOT FALSE",
    )
    .bind(portal_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<UserRow> = sqlx::query_as(&format!(
        "SELECT {USER_COLUMNS} FROM webportal_user \
         WHERE webportal_ref = $1 AND is_active IS NOT FALSE \
         ORDER BY id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(portal_id)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(user_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((items, total))
}

/// What a portal user's data export (G-14) needs from this crate: the user's
/// email, which is the DSR subject reference and matches their profile row,
/// and their consent history as JSON rows (`webportal_consent` is an
/// infrastructure table, so no DSR scope can name it). `NotFound` for a user
/// that is not a live member of `portal_id` (erased users included).
pub async fn export_inputs(
    conn: &mut PgConnection,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<(&'static str, String, Vec<String>), AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT email, username FROM webportal_user \
         WHERE id = $1 AND webportal_ref = $2 AND is_active IS NOT FALSE",
    )
    .bind(user_id)
    .bind(portal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // D-777: the subject is the email, or the username of an account that
    // has none.
    let (field, subject) = match row.ok_or(AppError::NotFound)? {
        (Some(email), _) => ("email", email),
        (None, Some(username)) => ("username", username),
        (None, None) => return Err(AppError::internal("portal user without email or username")),
    };
    let consent: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(c)::text FROM ( \
             SELECT id, webportal_id, webportal_user_id, terms_version, privacy_version, \
                    accepted_at \
             FROM webportal_consent WHERE webportal_user_id = $1 \
             ORDER BY accepted_at, id) c",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((field, subject, consent))
}

/// One erasure request, as staff see it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErasureRequest {
    pub id: Uuid,
    pub webportal_user_id: Uuid,
    /// `open`, `completed` or `rejected`.
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub handled_by: Option<Uuid>,
    pub handled_at: Option<chrono::DateTime<chrono::Utc>>,
}

type ErasureRow = (
    Uuid,
    Uuid,
    String,
    chrono::DateTime<chrono::Utc>,
    Option<Uuid>,
    Option<chrono::DateTime<chrono::Utc>>,
);

fn erasure_from_row(r: ErasureRow) -> ErasureRequest {
    ErasureRequest {
        id: r.0,
        webportal_user_id: r.1,
        status: r.2,
        requested_at: r.3,
        handled_by: r.4,
        handled_at: r.5,
    }
}

/// A page of a portal's erasure requests, open ones first.
pub async fn list_erasure_requests(
    conn: &mut PgConnection,
    portal_id: Uuid,
    page: i64,
    page_size: i64,
) -> Result<(Vec<ErasureRequest>, i64), AppError> {
    load_portal(conn, portal_id).await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webportal_erasure_request WHERE webportal_id = $1",
    )
    .bind(portal_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<ErasureRow> = sqlx::query_as(
        "SELECT id, webportal_user_id, status, requested_at, handled_by, handled_at \
         FROM webportal_erasure_request WHERE webportal_id = $1 \
         ORDER BY (status = 'open') DESC, requested_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(portal_id)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((rows.into_iter().map(erasure_from_row).collect(), total))
}

/// Columns of `webportal_user` an erasure never blanks: identity and
/// bookkeeping, plus the two it overwrites with placeholders.
const ERASURE_KEEPS: &[&str] = &["webportal_ref", "status", "name", "email"];

/// Erases a portal user (G-14): scrubs the profile's personal fields **in
/// place**, keeping the id so the portal user field on their records and
/// their `Initiator::PortalUser` audit rows still resolve (to "Erased user").
/// Every credential, session, token, recovery code, OIDC link, role
/// assignment and pending signup goes. Consent records stay as evidence of
/// what was accepted (they hold versions and times, not personal data). The
/// open erasure request, if any, is completed; otherwise one is recorded as
/// completed, so every erasure leaves a request row.
///
/// Returns the erasure request id.
pub async fn erase_user(
    conn: &mut PgConnection,
    registry: &attome_core::EntityMetaRegistry,
    actor: Uuid,
    portal_id: Uuid,
    user_id: Uuid,
) -> Result<Uuid, AppError> {
    lock(conn, format!("attome-portal/user:{user_id}")).await?;
    // D-777: an account may have no email.
    let email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM webportal_user WHERE id = $1 AND webportal_ref = $2")
            .bind(user_id)
            .bind(portal_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    let Some(email) = email else {
        return Err(AppError::NotFound);
    };

    // Every admin-added field is personal data until shown otherwise; blank
    // each one the table lets us (a NOT NULL column keeps its value and is
    // reported, never guessed at).
    let nullable: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'webportal_user' \
           AND is_nullable = 'YES'",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let mut blanks = Vec::new();
    if let Some(meta) = registry.get("webportal_user") {
        for attr in &meta.attrs {
            let name = attr.logicalname.as_str();
            if attome_core::ALL_SYSTEM_COLS.contains(&name) || ERASURE_KEEPS.contains(&name) {
                continue;
            }
            if nullable.iter().any(|c| c == name) {
                blanks.push(format!("{} = NULL", attome_core::quote_ident(name)));
            } else {
                tracing::warn!(
                    field = %name,
                    "portal user erasure: NOT NULL field kept; review it for personal data"
                );
            }
        }
    }
    let blanks = if blanks.is_empty() {
        String::new()
    } else {
        format!(", {}", blanks.join(", "))
    };
    sqlx::query(&format!(
        "UPDATE webportal_user SET name = 'Erased user', email = $3, \
           is_active = FALSE, status = 'disabled', modified_by = $2, modified_at = NOW(), \
           row_version = row_version + 1{blanks} \
         WHERE id = $1"
    ))
    .bind(user_id)
    .bind(actor)
    .bind(format!("erased-{user_id}@erased.invalid"))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    for table in [
        "webportal_credential",
        "webportal_refresh_token",
        "webportal_token",
        "webportal_mfa_recovery_code",
        "webportal_identity",
        "webportal_user_role",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE webportal_user_id = $1"))
            .bind(user_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    }
    if let Some(email) = email {
        sqlx::query("DELETE FROM webportal_signup WHERE webportal_id = $1 AND email_lower = $2")
            .bind(portal_id)
            .bind(email.trim().to_lowercase())
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    }

    let completed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE webportal_erasure_request \
         SET status = 'completed', handled_by = $2, handled_at = NOW() \
         WHERE webportal_user_id = $1 AND status = 'open' RETURNING id",
    )
    .bind(user_id)
    .bind(actor)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = completed {
        return Ok(id);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webportal_erasure_request \
           (id, webportal_id, webportal_user_id, status, handled_by, handled_at) \
         VALUES ($1, $2, $3, 'completed', $4, NOW())",
    )
    .bind(id)
    .bind(portal_id)
    .bind(user_id)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Rejects an open erasure request (for example, a legal hold). The account
/// is untouched.
pub async fn reject_erasure(
    conn: &mut PgConnection,
    actor: Uuid,
    portal_id: Uuid,
    request_id: Uuid,
) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE webportal_erasure_request \
         SET status = 'rejected', handled_by = $3, handled_at = NOW() \
         WHERE id = $1 AND webportal_id = $2 AND status = 'open'",
    )
    .bind(request_id)
    .bind(portal_id)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_shape() {
        assert_eq!(
            normalize_email(" Ada@Example.COM ").unwrap(),
            "ada@example.com"
        );
        for bad in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "a da@example.com",
            "ada@.com",
            "ada@example.",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn owning_team_patch_distinguishes_absent_from_null() {
        let absent: PortalSettingsPatch = serde_json::from_str(r#"{"row_version":1}"#).unwrap();
        assert_eq!(absent.owning_team_ref, None);
        let cleared: PortalSettingsPatch =
            serde_json::from_str(r#"{"row_version":1,"owning_team_ref":null}"#).unwrap();
        assert_eq!(cleared.owning_team_ref, Some(None));
    }

    #[test]
    fn only_anonymous_portals_have_no_users() {
        assert!(!PortalType::Anonymous.has_users());
        assert!(PortalType::Authenticated.has_users());
        assert!(PortalType::Mixed.has_users());
    }
}

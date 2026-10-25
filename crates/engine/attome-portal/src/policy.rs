//! A portal's account policy (D-588 items 2-3, plan G-11): signup mode and
//! domains, the role a self-registered user gets, which OIDC providers it
//! offers, the terms and privacy versions users must accept, and which of
//! their own profile fields users may edit. Plus the per-portal request limits
//! (plan §9.5 G-4, G-13; migration 0495): the page-size cap, the client-address
//! allowlist and the portal-wide record-route ceiling.
//!
//! Stored in the portal-owned `webportal_auth_policy` (migration 0492).
//! A portal with no row has every default: invite-only, no OIDC, no consent
//! requirement, no self-editable fields.

use attome_core::{AttrInfo, FieldType};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

/// Fields a user can never edit on their own profile, whatever the policy.
/// `name` included (owner decision 2026-09-28): staff with update rights on
/// `webportal_user` rename a portal user through the generic entity API.
pub(crate) const NEVER_SELF_EDITABLE: &[&str] = &[
    "id",
    "name",
    "email",
    "username",
    "status",
    "webportal_ref",
    "name_hash",
    "created_by",
    "modified_by",
    "created_at",
    "modified_at",
    "owner_ref",
    "owner_type",
    "org_ref",
    "is_active",
    "row_version",
];

/// Whether a user may ever be allowed to edit `attr` on their own profile.
///
/// Never a lookup: a lookup on `webportal_user` can be a grant condition's
/// `value_ref` source (`@portal_user.company_ref`, D-574), so a user who could
/// set it would pick their own row scope. Never a file (no portal file route)
/// or a formula (computed). Never a sensitive or write-restricted field (staff
/// field security, D-507: a grant needs `allow_sensitive` for those; the
/// profile has no such opt-in). Never a field in [`NEVER_SELF_EDITABLE`].
pub(crate) fn self_editable(attr: &AttrInfo) -> bool {
    !NEVER_SELF_EDITABLE.contains(&attr.logicalname.as_str())
        && attr.field_type() != FieldType::Lookup
        && !attr.is_file_backed()
        && !attr.is_formula()
        && !attr.requires_field_write_grant()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    #[default]
    InviteOnly,
    SelfService,
    DomainAllowlist,
}

impl SignupMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InviteOnly => "invite_only",
            Self::SelfService => "self_service",
            Self::DomainAllowlist => "domain_allowlist",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "self_service" => Self::SelfService,
            "domain_allowlist" => Self::DomainAllowlist,
            _ => Self::InviteOnly,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthPolicy {
    #[serde(default)]
    pub signup_mode: SignupMode,
    /// Lowercase email domains, e.g. `example.com`.
    #[serde(default)]
    pub signup_domains: Vec<String>,
    /// The portal role a self-registered or OIDC-created user gets.
    #[serde(default)]
    pub signup_role_ref: Option<Uuid>,
    /// Keys into the deployment's `portal.oidc_providers` config.
    #[serde(default)]
    pub oidc_providers: Vec<String>,
    #[serde(default)]
    pub terms_version: Option<String>,
    #[serde(default)]
    pub privacy_version: Option<String>,
    /// `webportal_user` fields a user may edit on their own profile.
    #[serde(default)]
    pub editable_profile_fields: Vec<String>,
    /// The largest page a portal list returns, 1 to 100 (R10, G-13).
    #[serde(default = "default_page_size_cap")]
    pub page_size_cap: i16,
    /// Client addresses allowed to reach the portal, as CIDRs or single
    /// addresses. Empty means any address. Outside it, every portal route
    /// answers the same 404 as an unknown portal (G-13).
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// Portal-wide ceiling on record-route requests per minute (G-4).
    #[serde(default = "default_records_rpm")]
    pub records_rpm: i32,
    /// D-777: username length, in characters (defaults 3 and 12).
    #[serde(default = "default_username_min_len")]
    pub username_min_len: i16,
    #[serde(default = "default_username_max_len")]
    pub username_max_len: i16,
    /// D-777: words no username may contain (case-insensitive).
    #[serde(default)]
    pub username_blocked_words: Vec<String>,
    /// D-777: whole usernames nobody may take (case-insensitive), e.g.
    /// "admin", "support", staff names.
    #[serde(default)]
    pub username_reserved: Vec<String>,
    /// D-779: the portal's own servers (S2S clients granted
    /// `webportal.trusted_login`) may sign users in with a password and
    /// create accounts for free usernames. Off by default.
    #[serde(default)]
    pub trusted_server_login: bool,
    /// Echo it back on the next write (optimistic concurrency).
    #[serde(default)]
    pub row_version: i64,
}

pub const DEFAULT_PAGE_SIZE_CAP: i16 = 100;
pub const DEFAULT_RECORDS_RPM: i32 = 6000;

fn default_page_size_cap() -> i16 {
    DEFAULT_PAGE_SIZE_CAP
}

fn default_records_rpm() -> i32 {
    DEFAULT_RECORDS_RPM
}

pub const DEFAULT_USERNAME_MIN_LEN: i16 = 3;
pub const DEFAULT_USERNAME_MAX_LEN: i16 = 12;

fn default_username_min_len() -> i16 {
    DEFAULT_USERNAME_MIN_LEN
}

fn default_username_max_len() -> i16 {
    DEFAULT_USERNAME_MAX_LEN
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            signup_mode: SignupMode::default(),
            signup_domains: Vec::new(),
            signup_role_ref: None,
            oidc_providers: Vec::new(),
            terms_version: None,
            privacy_version: None,
            editable_profile_fields: Vec::new(),
            page_size_cap: DEFAULT_PAGE_SIZE_CAP,
            allowed_cidrs: Vec::new(),
            records_rpm: DEFAULT_RECORDS_RPM,
            username_min_len: DEFAULT_USERNAME_MIN_LEN,
            username_max_len: DEFAULT_USERNAME_MAX_LEN,
            username_blocked_words: Vec::new(),
            username_reserved: Vec::new(),
            trusted_server_login: false,
            row_version: 0,
        }
    }
}

impl AuthPolicy {
    /// Whether a new account for `email_lower` may be created by signup (or
    /// by an OIDC first login).
    pub fn admits_new_account(&self, email_lower: &str) -> bool {
        match self.signup_mode {
            SignupMode::InviteOnly => false,
            SignupMode::SelfService => true,
            SignupMode::DomainAllowlist => email_lower
                .rsplit_once('@')
                .is_some_and(|(_, domain)| self.signup_domains.iter().any(|d| d == domain)),
        }
    }

    /// Whether a consent version is required at all.
    pub fn requires_consent(&self) -> bool {
        self.terms_version.is_some() || self.privacy_version.is_some()
    }

    /// D-777: checks a username against this portal's rules and returns it
    /// as stored (trimmed; case kept). Its lowercase form is the login key.
    /// Rules: `username_min_len..=username_max_len` characters; ASCII
    /// letters, digits, space, `_` and `-`; starts and ends with a letter or
    /// digit; no two spaces in a row; not all digits; contains no blocked
    /// word and isn't a reserved name (both case-insensitive).
    pub fn check_username(&self, raw: &str) -> Result<String, UsernameRejected> {
        let name = raw.trim();
        let len = name.chars().count();
        if len < self.username_min_len as usize || len > self.username_max_len as usize {
            return Err(UsernameRejected::Length {
                min: self.username_min_len,
                max: self.username_max_len,
            });
        }
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-';
        let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        if !name.chars().all(allowed)
            || !edge(name.chars().next())
            || !edge(name.chars().last())
            || name.contains("  ")
            || name.chars().all(|c| c.is_ascii_digit())
        {
            return Err(UsernameRejected::Characters);
        }
        let lower = name.to_ascii_lowercase();
        if self
            .username_reserved
            .iter()
            .any(|r| r.trim().to_ascii_lowercase() == lower)
        {
            return Err(UsernameRejected::NotAllowed);
        }
        // Also compared without separators, so "a d m i n" or "ad_min"
        // can't slip past a blocked "admin".
        let squashed: String = lower
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if self.username_blocked_words.iter().any(|w| {
            let w = w.trim().to_ascii_lowercase();
            !w.is_empty() && (lower.contains(&w) || squashed.contains(&w))
        }) {
            return Err(UsernameRejected::NotAllowed);
        }
        Ok(name.to_string())
    }
}

/// Why [`AuthPolicy::check_username`] refused a username. `NotAllowed`
/// deliberately doesn't say which list matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameRejected {
    Length { min: i16, max: i16 },
    Characters,
    NotAllowed,
}

impl UsernameRejected {
    pub fn message(self) -> String {
        match self {
            Self::Length { min, max } => format!("a username has {min} to {max} characters"),
            Self::Characters => "a username uses letters, digits, spaces, _ and -, starts and \
                                 ends with a letter or digit, and isn't only digits"
                .into(),
            Self::NotAllowed => "that username isn't allowed".into(),
        }
    }
}

type PolicyRow = (
    String,
    Vec<String>,
    Option<Uuid>,
    Vec<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
    i16,
    Vec<String>,
    i32,
    i16,
    i16,
    Vec<String>,
    Vec<String>,
    bool,
    i64,
);

pub async fn load(conn: &mut PgConnection, webportal_id: Uuid) -> Result<AuthPolicy, AppError> {
    let row: Option<PolicyRow> = sqlx::query_as(
        "SELECT signup_mode, signup_domains, signup_role_ref, oidc_providers, \
                terms_version, privacy_version, editable_profile_fields, \
                page_size_cap, allowed_cidrs, records_rpm, username_min_len, \
                username_max_len, username_blocked_words, username_reserved, \
                trusted_server_login, row_version \
         FROM webportal_auth_policy WHERE webportal_id = $1",
    )
    .bind(webportal_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(match row {
        None => AuthPolicy::default(),
        Some(r) => AuthPolicy {
            signup_mode: SignupMode::parse(&r.0),
            signup_domains: r.1,
            signup_role_ref: r.2,
            oidc_providers: r.3,
            terms_version: r.4,
            privacy_version: r.5,
            editable_profile_fields: r.6,
            page_size_cap: r.7,
            allowed_cidrs: r.8,
            records_rpm: r.9,
            username_min_len: r.10,
            username_max_len: r.11,
            username_blocked_words: r.12,
            username_reserved: r.13,
            trusted_server_login: r.14,
            row_version: r.15,
        },
    })
}

fn validate(policy: &AuthPolicy, known_providers: &[String]) -> Result<(), AppError> {
    for d in &policy.signup_domains {
        let ok = !d.is_empty()
            && d.len() <= 253
            && d.contains('.')
            && d.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
        if !ok {
            return Err(AppError::Validation(format!(
                "signup domain {d:?} is not a lowercase domain name"
            )));
        }
    }
    if policy.signup_mode == SignupMode::DomainAllowlist && policy.signup_domains.is_empty() {
        return Err(AppError::Validation(
            "domain_allowlist needs at least one signup domain".into(),
        ));
    }
    for p in &policy.oidc_providers {
        if !known_providers.iter().any(|k| k == p) {
            return Err(AppError::Validation(format!(
                "no OIDC provider {p:?} is configured in portal.oidc_providers"
            )));
        }
    }
    if !(1..=DEFAULT_PAGE_SIZE_CAP).contains(&policy.page_size_cap) {
        return Err(AppError::Validation(format!(
            "page_size_cap must be between 1 and {DEFAULT_PAGE_SIZE_CAP}"
        )));
    }
    if !(60..=100_000).contains(&policy.records_rpm) {
        return Err(AppError::Validation(
            "records_rpm must be between 60 and 100000".into(),
        ));
    }
    attome_server::middleware::ip_allowlist::validate_cidr_list(&policy.allowed_cidrs)
        .map_err(AppError::Validation)?;
    if !(1..=64).contains(&policy.username_min_len)
        || !(1..=64).contains(&policy.username_max_len)
        || policy.username_min_len > policy.username_max_len
    {
        return Err(AppError::Validation(
            "username lengths must be 1 to 64, and the minimum no larger than the maximum".into(),
        ));
    }
    for f in &policy.editable_profile_fields {
        if NEVER_SELF_EDITABLE.contains(&f.as_str()) {
            return Err(AppError::Validation(format!(
                "{f:?} can never be edited by the portal user"
            )));
        }
    }
    Ok(())
}

/// Every self-editable field must exist on `webportal_user` and pass
/// [`self_editable`].
fn check_editable_profile_fields(fields: &[String], attrs: &[AttrInfo]) -> Result<(), AppError> {
    for f in fields {
        let Some(attr) = attrs.iter().find(|a| &a.logicalname == f) else {
            return Err(AppError::Validation(format!(
                "webportal_user has no field {f:?}"
            )));
        };
        if !self_editable(attr) {
            return Err(AppError::Validation(format!(
                "{f:?} can't be self-editable: lookup, file and formula fields never are \
                 (a lookup on the portal user can scope what the user sees)"
            )));
        }
    }
    Ok(())
}

/// Replaces the policy under optimistic concurrency. `known_providers` are the
/// deployment's configured OIDC provider keys; `profile_fields` the
/// `webportal_user` attributes that exist today.
pub async fn save(
    conn: &mut PgConnection,
    webportal_id: Uuid,
    policy: &AuthPolicy,
    known_providers: &[String],
    profile_fields: &[AttrInfo],
) -> Result<AuthPolicy, AppError> {
    validate(policy, known_providers)?;
    check_editable_profile_fields(&policy.editable_profile_fields, profile_fields)?;
    if let Some(role) = policy.signup_role_ref {
        let ok: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM webportal_role WHERE id = $1 AND webportal_id = $2)",
        )
        .bind(role)
        .bind(webportal_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if !ok {
            return Err(AppError::Validation(
                "signup_role_ref is not a role of this portal".into(),
            ));
        }
    }
    let mut domains = policy.signup_domains.clone();
    domains.sort();
    domains.dedup();
    let row_version: Option<i64> = sqlx::query_scalar(
        "INSERT INTO webportal_auth_policy AS p \
           (webportal_id, signup_mode, signup_domains, signup_role_ref, oidc_providers, \
            terms_version, privacy_version, editable_profile_fields, \
            page_size_cap, allowed_cidrs, records_rpm, username_min_len, username_max_len, \
            username_blocked_words, username_reserved, trusted_server_login, row_version, \
            updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $10, $11, $12, $13, $14, $15, $16, $17, 0, \
                 NOW()) \
         ON CONFLICT (webportal_id) DO UPDATE SET \
           signup_mode = EXCLUDED.signup_mode, signup_domains = EXCLUDED.signup_domains, \
           signup_role_ref = EXCLUDED.signup_role_ref, oidc_providers = EXCLUDED.oidc_providers, \
           terms_version = EXCLUDED.terms_version, privacy_version = EXCLUDED.privacy_version, \
           editable_profile_fields = EXCLUDED.editable_profile_fields, \
           page_size_cap = EXCLUDED.page_size_cap, allowed_cidrs = EXCLUDED.allowed_cidrs, \
           records_rpm = EXCLUDED.records_rpm, \
           username_min_len = EXCLUDED.username_min_len, \
           username_max_len = EXCLUDED.username_max_len, \
           username_blocked_words = EXCLUDED.username_blocked_words, \
           username_reserved = EXCLUDED.username_reserved, \
           trusted_server_login = EXCLUDED.trusted_server_login, \
           row_version = p.row_version + 1, updated_at = NOW() \
         WHERE p.row_version = $9 \
         RETURNING row_version",
    )
    .bind(webportal_id)
    .bind(policy.signup_mode.as_str())
    .bind(&domains)
    .bind(policy.signup_role_ref)
    .bind(&policy.oidc_providers)
    .bind(&policy.terms_version)
    .bind(&policy.privacy_version)
    .bind(&policy.editable_profile_fields)
    .bind(policy.row_version)
    .bind(policy.page_size_cap)
    .bind(&policy.allowed_cidrs)
    .bind(policy.records_rpm)
    .bind(policy.username_min_len)
    .bind(policy.username_max_len)
    .bind(&policy.username_blocked_words)
    .bind(&policy.username_reserved)
    .bind(policy.trusted_server_login)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let row_version = row_version.ok_or(AppError::VersionConflict)?;
    Ok(AuthPolicy {
        signup_domains: domains,
        row_version,
        ..policy.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: SignupMode, domains: &[&str]) -> AuthPolicy {
        AuthPolicy {
            signup_mode: mode,
            signup_domains: domains.iter().map(|d| d.to_string()).collect(),
            ..AuthPolicy::default()
        }
    }

    #[test]
    fn new_accounts_follow_the_signup_mode() {
        assert!(!policy(SignupMode::InviteOnly, &[]).admits_new_account("a@x.com"));
        assert!(policy(SignupMode::SelfService, &[]).admits_new_account("a@x.com"));
        let p = policy(SignupMode::DomainAllowlist, &["x.com"]);
        assert!(p.admits_new_account("a@x.com"));
        assert!(!p.admits_new_account("a@evil-x.com"));
        assert!(!p.admits_new_account("a@sub.x.com"));
    }

    #[test]
    fn validation_refuses_bad_domains_unknown_providers_and_protected_fields() {
        let known = vec!["entra".to_string()];
        assert!(validate(&policy(SignupMode::DomainAllowlist, &[]), &known).is_err());
        assert!(validate(&policy(SignupMode::SelfService, &["X.com"]), &known).is_err());
        let p = AuthPolicy {
            oidc_providers: vec!["google".into()],
            ..AuthPolicy::default()
        };
        assert!(validate(&p, &known).is_err());
        let p = AuthPolicy {
            editable_profile_fields: vec!["email".into()],
            ..AuthPolicy::default()
        };
        assert!(validate(&p, &known).is_err());
        let p = AuthPolicy {
            oidc_providers: vec!["entra".into()],
            editable_profile_fields: vec!["phone".into()],
            ..AuthPolicy::default()
        };
        assert!(validate(&p, &known).is_ok());
    }

    #[test]
    fn request_limits_are_bounded_g4_g13() {
        let known = Vec::new();
        assert!(validate(&AuthPolicy::default(), &known).is_ok());
        for cap in [0, 101] {
            let p = AuthPolicy {
                page_size_cap: cap,
                ..AuthPolicy::default()
            };
            assert!(validate(&p, &known).is_err(), "cap {cap}");
        }
        for rpm in [59, 100_001] {
            let p = AuthPolicy {
                records_rpm: rpm,
                ..AuthPolicy::default()
            };
            assert!(validate(&p, &known).is_err(), "rpm {rpm}");
        }
        let p = AuthPolicy {
            allowed_cidrs: vec!["10.0.0.0/8".into(), "2001:db8::1".into()],
            ..AuthPolicy::default()
        };
        assert!(validate(&p, &known).is_ok());
        let p = AuthPolicy {
            allowed_cidrs: vec!["10.0.0.0/33".into()],
            ..AuthPolicy::default()
        };
        assert!(validate(&p, &known).is_err());
    }
}

/// The self-editable profile list (D-588, web-portal plan Phase 11): a lookup
/// on the portal user can scope what the user sees (a grant's `value_ref`),
/// so it is never self-editable; nor is a file, a formula or an identity
/// field.
#[cfg(test)]
mod self_edit_tests {
    use super::*;

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    fn profile() -> Vec<AttrInfo> {
        vec![
            attr("name", 3),
            attr("phone", 3),
            attr("email", 3),
            attr("status", 1),
            attr("company_ref", 11),
            attr("avatar", 12),
            attr("score", 16),
            AttrInfo {
                is_sensitive: true,
                ..attr("staff_note", 3)
            },
            AttrInfo {
                is_write_restricted: true,
                ..attr("tier", 3)
            },
        ]
    }

    #[test]
    fn only_plain_fields_can_be_self_editable() {
        let attrs = profile();
        assert!(check_editable_profile_fields(&["phone".to_owned()], &attrs).is_ok());
        for refused in [
            "name",
            "email",
            "status",
            "company_ref",
            "avatar",
            "score",
            "staff_note",
            "tier",
            "ghost",
        ] {
            assert!(
                check_editable_profile_fields(&[refused.to_owned()], &attrs).is_err(),
                "{refused} was accepted"
            );
        }
    }
}

#[cfg(test)]
mod username_tests {
    use super::*;

    fn rules() -> AuthPolicy {
        AuthPolicy {
            username_blocked_words: vec!["admin".into(), "Rude".into()],
            username_reserved: vec!["Support".into(), "mod".into()],
            ..AuthPolicy::default()
        }
    }

    #[test]
    fn a_valid_username_is_kept_as_typed_but_trimmed() {
        assert_eq!(rules().check_username("  Zezima ").unwrap(), "Zezima");
        assert_eq!(
            rules().check_username("Iron_Man 99").unwrap(),
            "Iron_Man 99"
        );
        assert_eq!(rules().check_username("a-b").unwrap(), "a-b");
    }

    #[test]
    fn length_follows_the_portal_rules() {
        let p = rules();
        assert_eq!(
            p.check_username("ab"),
            Err(UsernameRejected::Length { min: 3, max: 12 })
        );
        assert!(p.check_username("abcdefghijkl").is_ok());
        assert!(p.check_username("abcdefghijklm").is_err());
        let long = AuthPolicy {
            username_max_len: 20,
            ..AuthPolicy::default()
        };
        assert!(long.check_username("abcdefghijklm").is_ok());
    }

    #[test]
    fn characters_edges_spaces_and_all_digits_are_refused() {
        let p = rules();
        for bad in [
            "bob!", "_bob", "bob-", "bo  b", "ünï", "1234", "bob@x", "b\tob",
        ] {
            assert_eq!(
                p.check_username(bad),
                Err(UsernameRejected::Characters),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn reserved_names_and_blocked_words_are_refused_case_insensitively() {
        let p = rules();
        for bad in [
            "support",
            "SUPPORT",
            "Mod",
            "admin",
            "TheAdmin1",
            "ad_min",
            "a d m i n",
            "rudeboy",
        ] {
            assert_eq!(
                p.check_username(bad),
                Err(UsernameRejected::NotAllowed),
                "{bad:?} was accepted"
            );
        }
        // A reserved name is refused only whole; a blocked word anywhere.
        assert!(p.check_username("Moderna").is_ok());
        assert!(p.check_username("Supporter").is_ok());
    }
}

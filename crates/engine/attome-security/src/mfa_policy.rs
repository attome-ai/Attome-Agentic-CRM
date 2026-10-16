//! A person's effective second-factor policy (roadmap Q5-T2), compiled from
//! the `role_auth_policy` rows of their roles: the strictest mode wins, only
//! factors every role allows remain, the shortest grace and remember-device
//! periods apply, and one role asking for phishing-resistant factors is
//! enough. An administrator always needs a strong second factor, now.

use std::collections::BTreeSet;

use attome_db::DbPool;
use attome_types::AppError;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaMode {
    Off,
    Optional,
    Required,
}

impl MfaMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    Passkey,
    Push,
    Totp,
    Recovery,
    Email,
    Sms,
    WhatsApp,
}

impl FactorKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "passkey" => Some(Self::Passkey),
            "push" => Some(Self::Push),
            "totp" => Some(Self::Totp),
            "recovery" => Some(Self::Recovery),
            "email" => Some(Self::Email),
            "sms" => Some(Self::Sms),
            "whatsapp" => Some(Self::WhatsApp),
            _ => None,
        }
    }

    /// Codes sent over a channel an attacker can intercept or redirect.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Email | Self::Sms | Self::WhatsApp)
    }
}

/// One role's stored policy.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RolePolicyRow {
    pub mfa_mode: String,
    pub mfa_factors: Vec<String>,
    pub mfa_grace_days: i32,
    pub remember_device_days: i32,
    pub phishing_resistant_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveMfaPolicy {
    pub mode: MfaMode,
    pub factors: BTreeSet<FactorKind>,
    pub grace_days: i32,
    pub remember_device_days: i32,
    pub phishing_resistant_only: bool,
}

/// The factors a deployment allows when no role narrows them.
fn all_factors() -> BTreeSet<FactorKind> {
    [
        FactorKind::Passkey,
        FactorKind::Push,
        FactorKind::Totp,
        FactorKind::Recovery,
    ]
    .into_iter()
    .collect()
}

/// Compiles one policy; `deployment_floor` (`off`, `optional`, `required`)
/// is what a role set to `inherit` means.
pub fn compile(
    role_policies: &[RolePolicyRow],
    is_admin: bool,
    deployment_floor: &str,
) -> EffectiveMfaPolicy {
    if is_admin {
        return EffectiveMfaPolicy {
            mode: MfaMode::Required,
            factors: [FactorKind::Passkey, FactorKind::Totp, FactorKind::Recovery]
                .into_iter()
                .collect(),
            grace_days: 0,
            remember_device_days: 0,
            phishing_resistant_only: role_policies.iter().any(|r| r.phishing_resistant_only),
        };
    }
    let floor = MfaMode::parse(deployment_floor).unwrap_or(MfaMode::Optional);
    let mut mode = if role_policies.is_empty() {
        floor
    } else {
        MfaMode::Off
    };
    let mut factors: Option<BTreeSet<FactorKind>> = None;
    let mut grace_days: Option<i32> = None;
    let mut remember: Option<i32> = None;
    let mut phishing_resistant_only = false;
    for row in role_policies {
        let role_mode = MfaMode::parse(&row.mfa_mode).unwrap_or(floor);
        mode = mode.max(role_mode);
        let allowed: BTreeSet<FactorKind> = row
            .mfa_factors
            .iter()
            .filter_map(|f| FactorKind::parse(f))
            .collect();
        factors = Some(match factors {
            None => allowed,
            Some(so_far) => so_far.intersection(&allowed).copied().collect(),
        });
        grace_days = Some(grace_days.map_or(row.mfa_grace_days, |g| g.min(row.mfa_grace_days)));
        remember = Some(remember.map_or(row.remember_device_days, |d| {
            d.min(row.remember_device_days)
        }));
        phishing_resistant_only |= row.phishing_resistant_only;
    }
    let mut factors = factors.unwrap_or_else(all_factors);
    if phishing_resistant_only {
        factors.retain(|f| *f == FactorKind::Passkey || *f == FactorKind::Recovery);
    }
    EffectiveMfaPolicy {
        mode,
        factors,
        grace_days: grace_days.unwrap_or(7).max(0),
        remember_device_days: remember.unwrap_or(30).max(0),
        phishing_resistant_only,
    }
}

/// The policy rows of every role `user_id` holds, directly or through a
/// team; a role with no row contributes nothing.
pub async fn load_role_policies(
    db: &DbPool,
    user_id: Uuid,
) -> Result<Vec<RolePolicyRow>, AppError> {
    sqlx::query_as(
        "SELECT p.mfa_mode, p.mfa_factors, p.mfa_grace_days, p.remember_device_days, \
                p.phishing_resistant_only \
           FROM role_auth_policy p \
          WHERE p.role_ref IN ( \
                SELECT ur.role_ref FROM user_account_mm_role ur \
                 WHERE ur.user_ref = $1 AND NOT ur.is_deleted \
                UNION \
                SELECT rt.role_ref FROM user_account_mm_team ut \
                  JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND NOT rt.is_deleted \
                 WHERE ut.user_ref = $1 AND NOT ut.is_deleted)",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(mode: &str, factors: &[&str], grace: i32) -> RolePolicyRow {
        RolePolicyRow {
            mfa_mode: mode.into(),
            mfa_factors: factors.iter().map(|f| (*f).to_owned()).collect(),
            mfa_grace_days: grace,
            remember_device_days: 30,
            phishing_resistant_only: false,
        }
    }

    #[test]
    fn strictest_role_wins() {
        let p = compile(
            &[
                row("optional", &["passkey", "totp", "sms"], 7),
                row("required", &["passkey", "totp"], 3),
            ],
            false,
            "off",
        );
        assert_eq!(p.mode, MfaMode::Required);
        assert_eq!(
            p.factors,
            [FactorKind::Passkey, FactorKind::Totp]
                .into_iter()
                .collect()
        );
        assert_eq!(p.grace_days, 3);
    }

    #[test]
    fn admin_always_required_without_weak_factors() {
        let p = compile(&[row("off", &["sms", "email"], 30)], true, "off");
        assert_eq!(p.mode, MfaMode::Required);
        assert!(p.factors.iter().all(|f| !f.is_weak()));
        assert_eq!(p.grace_days, 0);
        assert_eq!(p.remember_device_days, 0);
    }

    #[test]
    fn inherit_uses_deployment_floor() {
        let p = compile(&[row("inherit", &["totp"], 7)], false, "required");
        assert_eq!(p.mode, MfaMode::Required);
        let none = compile(&[], false, "optional");
        assert_eq!(none.mode, MfaMode::Optional);
        let mut strict = row("optional", &["passkey", "totp", "recovery"], 7);
        strict.phishing_resistant_only = true;
        let p = compile(&[strict], false, "off");
        assert!(!p.factors.contains(&FactorKind::Totp));
    }
}

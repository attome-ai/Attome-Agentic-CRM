//! F9-T8: the partner portal's roles, and which partner a member belongs to.
//!
//! A portal role belongs to one portal, so these cannot be seeded at boot:
//! [`role_grants`] is the definition, and `attome partner portal-roles` sends
//! it through the portal admin API, which validates and audits each grant.
//!
//! Every grant but the published resources is bound to
//! `webportal_user.partner_account_ref`. No client sets that field: assigning
//! a partner role ([`bind_member`]) derives it from the person's contact, in
//! the role assignment's transaction, and refuses a person with no partner
//! contact or past the account's `partner_user_limit`.
//!
//! The grants read only. A partner writes through the partner routes, which
//! take the account from the session. `mdf_request` and `mdf_claim` hold no
//! partner field, so no row condition can scope them, and they have no grant.

use attome_types::AppError;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::roles::{ConditionSpec, FieldSpec, GrantSpec};

/// What every member's grants compare `partner_account_ref` with.
pub const MEMBER_ACCOUNT: &str = "@portal_user.partner_account_ref";
/// The role that sees all of its partner's numbers.
pub const PARTNER_ADMIN: &str = "partner_admin";
/// The role that works deals.
pub const PARTNER_SALES: &str = "partner_sales";
/// The role that reads certifications and resources.
pub const PARTNER_SERVICE: &str = "partner_service";

fn fields(names: &[&str]) -> Vec<FieldSpec> {
    names
        .iter()
        .map(|name| FieldSpec {
            field: (*name).to_owned(),
            can_read: true,
            can_write: false,
            can_filter: false,
            allow_sensitive: false,
        })
        .collect()
}

fn read(condition: ConditionSpec, names: &[&str]) -> GrantSpec {
    GrantSpec {
        can_read: true,
        can_create: false,
        can_update: false,
        can_delete: false,
        conditions: vec![condition],
        fields: fields(names),
    }
}

/// The member's own account's rows of an entity.
fn own(names: &[&str]) -> GrantSpec {
    read(
        ConditionSpec {
            field: "partner_account_ref".to_owned(),
            operator: "eq".to_owned(),
            value: None,
            value_ref: Some(MEMBER_ACCOUNT.to_owned()),
        },
        names,
    )
}

fn published(names: &[&str]) -> GrantSpec {
    read(
        ConditionSpec {
            field: "is_published".to_owned(),
            operator: "eq".to_owned(),
            value: Some(Value::Bool(true)),
            value_ref: None,
        },
        names,
    )
}

/// Each role with its grants. Pure.
pub fn role_grants() -> Vec<(&'static str, Vec<(&'static str, GrantSpec)>)> {
    let registrations = || {
        own(&[
            "customer_name",
            "amount",
            "expected_close",
            "status",
            "protection_ends_on",
        ])
    };
    let leads = || own(&["partner_status", "partner_accept_by"]);
    let deals = || own(&["name", "stage", "amount", "close_date"]);
    let certifications = || own(&["name", "issued_on", "expires_on"]);
    let resources = || published(&["name", "kind", "description", "url"]);
    vec![
        (
            PARTNER_ADMIN,
            vec![
                ("deal_registration", registrations()),
                ("lead", leads()),
                ("opportunity", deals()),
                ("partner_certification", certifications()),
                ("partner_resource", resources()),
                ("mdf_fund", own(&["fiscal_year", "amount"])),
                (
                    "partner_performance_snapshot",
                    own(&[
                        "as_of",
                        "pipeline",
                        "won_revenue",
                        "win_rate",
                        "avg_accept_hours",
                        "certified_people",
                        "mdf_spent",
                    ]),
                ),
            ],
        ),
        (
            PARTNER_SALES,
            vec![
                ("deal_registration", registrations()),
                ("lead", leads()),
                ("opportunity", deals()),
                ("partner_resource", resources()),
            ],
        ),
        (
            PARTNER_SERVICE,
            vec![
                ("partner_certification", certifications()),
                ("partner_resource", resources()),
            ],
        ),
    ]
}

/// The API call that creates a role, as `attome partner portal-roles` sends it.
/// Pure.
pub fn role_body(name: &str) -> Value {
    json!({ "name": name })
}

/// Binds a member to their partner account when `role` is a partner role.
/// Runs in the role assignment's transaction, so a refusal leaves no role.
pub async fn bind_member(conn: &mut PgConnection, user: Uuid, role: Uuid) -> Result<(), AppError> {
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM webportal_role WHERE id = $1")
        .bind(role)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !name.is_some_and(|n| [PARTNER_ADMIN, PARTNER_SALES, PARTNER_SERVICE].contains(&n.as_str()))
    {
        return Ok(());
    }
    let partner: Option<(Uuid, Option<f64>)> = sqlx::query_as(
        "SELECT a.id, a.partner_user_limit::float8 FROM webportal_user u \
           JOIN contact c ON c.id = u.contact_ref \
           JOIN account a ON a.id = c.account_ref \
          WHERE u.id = $1 AND a.is_partner = true",
    )
    .bind(user)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((partner, limit)) = partner else {
        return Err(AppError::Validation(
            "a partner role needs a portal user whose contact is at a partner account".into(),
        ));
    };
    crate::roles::lock(&mut *conn, format!("attome-portal/partner-seats:{partner}")).await?;
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webportal_user \
          WHERE partner_account_ref = $1 AND id <> $2 AND is_active IS NOT FALSE",
    )
    .bind(partner)
    .bind(user)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if limit.is_some_and(|limit| others as f64 >= limit) {
        return Err(AppError::Validation(
            "this partner has reached its portal user limit".into(),
        ));
    }
    sqlx::query("UPDATE webportal_user SET partner_account_ref = $2 WHERE id = $1")
        .bind(user)
        .bind(partner)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(spec: &GrantSpec) -> bool {
        spec.conditions
            .iter()
            .any(|c| c.value_ref.as_deref() == Some(MEMBER_ACCOUNT))
    }

    #[test]
    fn only_published_resources_are_unbound() {
        for (_, grants) in role_grants() {
            for (entity, spec) in grants {
                assert!(
                    bound(&spec) || entity == "partner_resource",
                    "{entity} is not bound to the member's account"
                );
            }
        }
    }

    #[test]
    fn grants_only_read_and_never_show_a_lookup() {
        for (_, grants) in role_grants() {
            for (entity, spec) in grants {
                assert!(
                    spec.can_read && !spec.can_create && !spec.can_update && !spec.can_delete,
                    "{entity}"
                );
                assert!(
                    spec.fields
                        .iter()
                        .all(|f| !f.can_write && !f.field.ends_with("_ref")),
                    "{entity}"
                );
            }
        }
    }

    #[test]
    fn mdf_requests_and_claims_are_not_granted() {
        for (_, grants) in role_grants() {
            assert!(
                grants
                    .iter()
                    .all(|(entity, _)| !["mdf_request", "mdf_claim"].contains(entity))
            );
        }
    }
}

//! Q4-T1: `auth.ldap`, signing in against an LDAP directory (Active
//! Directory or OpenLDAP) over TLS, and the directory groups that give roles.

use serde::Deserialize;

use crate::Secret;
use crate::config::helpers::default_true;

#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct LdapSection {
    /// Q4-T1: the directory, `ldaps://dc.example.com:636`, or
    /// `ldap://dc.example.com:389` with `start_tls`. Plain LDAP without TLS
    /// stops boot: the person's password crosses this connection.
    pub url: String,
    /// Q4-T1: upgrade an `ldap://` connection with StartTLS before anything
    /// is sent. Ignored for `ldaps://`.
    #[serde(default)]
    pub start_tls: bool,
    /// Q4-T1: a PEM file of the certificate authorities the directory's
    /// certificate is checked against. Unset, the public web roots.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Q4-T1: the service account that looks people up, e.g.
    /// `CN=attome,OU=Service,DC=example,DC=com`.
    pub bind_dn: String,
    /// Q4-T1: the service account's password; `${VAR}`, never committed.
    pub bind_password: Secret,
    /// Q4-T1: where people are looked up, e.g. `DC=example,DC=com`.
    pub base_dn: String,
    /// Q4-T1: the search for one person, with `{username}` standing for what
    /// they typed (escaped). The default finds an Active Directory account
    /// by `sAMAccountName` or `userPrincipalName`.
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    /// Q4-T1: the attribute holding the person's email address, which is
    /// their Attome account.
    #[serde(default = "default_email_attribute")]
    pub email_attribute: String,
    /// Q4-T1: the attribute listing the groups the person belongs to.
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,
    /// Q4-T1: seconds for each step with the directory (connect, bind,
    /// search) before the sign-in answers that the directory is unavailable.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Q4-T1: create the Attome account the first time a person signs in.
    /// Off, only people who already have an account (with no other sign-in
    /// method) may sign in through the directory.
    #[serde(default = "default_true")]
    pub create_users: bool,
    /// Q4-T1: the roles a directory group gives, each `{"group": "<group
    /// DN>", "role": "<role name>"}`. Group names compare without regard to
    /// case. A role carrying system administration is never given this way.
    #[serde(default)]
    pub group_roles: Vec<LdapGroupRole>,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct LdapGroupRole {
    /// The group's distinguished name, as the group attribute lists it.
    pub group: String,
    /// The Attome role's name.
    pub role: String,
}

fn default_user_filter() -> String {
    "(|(sAMAccountName={username})(userPrincipalName={username}))".to_owned()
}

fn default_email_attribute() -> String {
    "mail".to_owned()
}

fn default_group_attribute() -> String {
    "memberOf".to_owned()
}

fn default_timeout_secs() -> u64 {
    10
}

/// Hand-rolled so `bind_password` stays redacted.
impl std::fmt::Debug for LdapSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapSection")
            .field("url", &self.url)
            .field("start_tls", &self.start_tls)
            .field("ca_file", &self.ca_file)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &self.bind_password)
            .field("base_dn", &self.base_dn)
            .field("user_filter", &self.user_filter)
            .field("email_attribute", &self.email_attribute)
            .field("group_attribute", &self.group_attribute)
            .field("timeout_secs", &self.timeout_secs)
            .field("create_users", &self.create_users)
            .field("group_roles", &self.group_roles)
            .finish()
    }
}

impl LdapSection {
    /// Q4-T1: what `AppConfig::validate` refuses: a URL that is not
    /// `ldaps://` or `ldap://` with StartTLS, a filter without `{username}`,
    /// a timeout of zero, and an empty service account.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let url = self.url.trim().to_ascii_lowercase();
        if url.starts_with("ldap://") {
            if !self.start_tls {
                problems.push(
                    "auth.ldap.url is plain ldap:// without auth.ldap.start_tls; passwords would cross the network unencrypted"
                        .to_owned(),
                );
            }
        } else if !url.starts_with("ldaps://") {
            problems.push("auth.ldap.url must start with ldaps:// or ldap://".to_owned());
        }
        if !self.user_filter.contains("{username}") {
            problems.push("auth.ldap.user_filter must contain {username}".to_owned());
        }
        if self.timeout_secs == 0 {
            problems.push("auth.ldap.timeout_secs must be above zero".to_owned());
        }
        if self.bind_dn.trim().is_empty() || self.bind_password.is_empty() {
            problems.push("auth.ldap.bind_dn and auth.ldap.bind_password are required".to_owned());
        }
        if self.base_dn.trim().is_empty() {
            problems.push("auth.ldap.base_dn is required".to_owned());
        }
        problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(url: &str, start_tls: bool) -> LdapSection {
        LdapSection {
            url: url.to_owned(),
            start_tls,
            ca_file: None,
            bind_dn: "cn=svc".to_owned(),
            bind_password: Secret::new("pw".to_owned()),
            base_dn: "dc=example,dc=com".to_owned(),
            user_filter: default_user_filter(),
            email_attribute: default_email_attribute(),
            group_attribute: default_group_attribute(),
            timeout_secs: 10,
            create_users: true,
            group_roles: Vec::new(),
        }
    }

    #[test]
    fn plain_ldap_without_start_tls_is_refused() {
        assert!(section("ldaps://dc:636", false).problems().is_empty());
        assert!(section("ldap://dc:389", true).problems().is_empty());
        assert_eq!(section("ldap://dc:389", false).problems().len(), 1);
        assert_eq!(section("http://dc", false).problems().len(), 1);
    }

    #[test]
    fn the_filter_needs_the_username() {
        let mut s = section("ldaps://dc", false);
        s.user_filter = "(uid=bob)".to_owned();
        assert_eq!(s.problems().len(), 1);
    }

    #[test]
    fn the_password_is_never_printed() {
        let s = section("ldaps://dc", false);
        assert!(!format!("{s:?}").contains("\"pw\""));
    }
}

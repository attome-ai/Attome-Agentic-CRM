//! Q4-T1: signing in against an LDAP directory (Active Directory or
//! OpenLDAP), and the roles its groups give.
//!
//! The service account (`auth.ldap.bind_dn`) looks the person up by what
//! they typed, then a second connection binds as the person's own entry with
//! their password: the directory checks the password, Attome never sees a
//! hash. The groups come from the person's group attribute (`memberOf`).
//!
//! The connection is always encrypted: `ldaps://`, or `ldap://` upgraded with
//! StartTLS; `auth.ldap` refuses anything else at boot
//! ([`attome_config::LdapSection::problems`]). The certificate is checked
//! against `auth.ldap.ca_file`, or the public web roots.
//!
//! An empty password is refused before the directory is asked: a simple
//! bind with a DN and no password is an anonymous bind, which many
//! directories accept (RFC 4513 §5.1.2). An unknown person, two entries for
//! one name, and a wrong password all answer [`LdapError::InvalidCredentials`];
//! a directory that cannot be reached, or refuses the service account,
//! answers [`LdapError::Unavailable`]. Neither carries the password.

use std::sync::Arc;
use std::time::Duration;

use attome_config::{LdapGroupRole, LdapSection};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, ldap_escape};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};

/// The longest username and password a sign-in may send.
const MAX_USERNAME_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 1024;

/// `invalidCredentials` (RFC 4511 appendix A).
const RC_INVALID_CREDENTIALS: u32 = 49;

/// The person the directory signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUser {
    /// The person's entry.
    pub dn: String,
    /// The first value of `auth.ldap.email_attribute`, if any.
    pub email: Option<String>,
    /// Every value of `auth.ldap.group_attribute`.
    pub groups: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// No such person, more than one, or a wrong password.
    #[error("the username or password is wrong")]
    InvalidCredentials,
    /// The directory cannot be reached, timed out, or refused the service
    /// account. The text names the step, never a credential.
    #[error("the directory is unavailable: {0}")]
    Unavailable(String),
    /// `auth.ldap` cannot be used as configured.
    #[error("auth.ldap is not usable: {0}")]
    Config(String),
}

/// A configured directory, ready to sign people in.
pub struct Directory {
    settings: LdapSection,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Directory {
    /// Reads `auth.ldap.ca_file` (when set) and builds the TLS settings.
    pub async fn load(settings: &LdapSection) -> Result<Self, LdapError> {
        let problems = settings.problems();
        if !problems.is_empty() {
            return Err(LdapError::Config(problems.join("; ")));
        }
        let ca = match &settings.ca_file {
            Some(path) => Some(
                tokio::fs::read(path)
                    .await
                    .map_err(|e| LdapError::Config(format!("auth.ldap.ca_file {path:?}: {e}")))?,
            ),
            None => None,
        };
        Ok(Self {
            settings: settings.clone(),
            tls: tls_config(ca.as_deref())?,
        })
    }

    /// The TLS settings, for a test that seeds the directory over the same
    /// trust.
    #[doc(hidden)]
    pub fn tls_config_for_tests(&self) -> Arc<ClientConfig> {
        self.tls.clone()
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.settings.timeout_secs)
    }

    /// Checks `password` for the person `username` names and reads their
    /// email address and groups.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<DirectoryUser, LdapError> {
        let username = username.trim();
        if username.is_empty()
            || username.len() > MAX_USERNAME_LEN
            || username.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > MAX_PASSWORD_LEN
        {
            return Err(LdapError::InvalidCredentials);
        }
        let found = self.find(username).await?;
        self.bind_as(&found.dn, password).await?;
        Ok(found)
    }

    /// The service account's search for the one entry `username` names.
    async fn find(&self, username: &str) -> Result<DirectoryUser, LdapError> {
        let mut ldap = self.connect().await?;
        let bound = ldap
            .with_timeout(self.timeout())
            .simple_bind(&self.settings.bind_dn, self.settings.bind_password.expose())
            .await
            .map_err(|e| unavailable("service bind", e))?;
        if bound.rc != 0 {
            let _ = ldap.unbind().await;
            return Err(LdapError::Unavailable(format!(
                "the directory refused the service account (result {})",
                bound.rc
            )));
        }
        let filter = user_filter(&self.settings.user_filter, username);
        let attributes = [
            self.settings.email_attribute.as_str(),
            self.settings.group_attribute.as_str(),
        ];
        let searched = ldap
            .with_timeout(self.timeout())
            .search(&self.settings.base_dn, Scope::Subtree, &filter, attributes)
            .await
            .map_err(|e| unavailable("search", e))?;
        let _ = ldap.unbind().await;
        let (entries, result) = searched.success().map_err(|e| unavailable("search", e))?;
        tracing::debug!(rc = result.rc, "ldap: person searched");
        let mut people = entries
            .into_iter()
            .filter(|entry| !entry.is_ref())
            .map(SearchEntry::construct);
        let (Some(entry), None) = (people.next(), people.next()) else {
            return Err(LdapError::InvalidCredentials);
        };
        Ok(DirectoryUser {
            email: values(&entry, &self.settings.email_attribute)
                .into_iter()
                .next(),
            groups: values(&entry, &self.settings.group_attribute),
            dn: entry.dn,
        })
    }

    /// A fresh connection bound as `dn` with `password`.
    async fn bind_as(&self, dn: &str, password: &str) -> Result<(), LdapError> {
        let mut ldap = self.connect().await?;
        let bound = ldap
            .with_timeout(self.timeout())
            .simple_bind(dn, password)
            .await
            .map_err(|e| unavailable("bind", e))?;
        let _ = ldap.unbind().await;
        match bound.rc {
            0 => Ok(()),
            RC_INVALID_CREDENTIALS => Err(LdapError::InvalidCredentials),
            rc => {
                // A locked, expired or disabled account answers its own code;
                // the person is still not signed in.
                tracing::info!(rc, "ldap: the directory refused the person's bind");
                Err(LdapError::InvalidCredentials)
            }
        }
    }

    async fn connect(&self) -> Result<Ldap, LdapError> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.timeout())
            .set_config(self.tls.clone())
            .set_starttls(
                self.settings.start_tls
                    && self
                        .settings
                        .url
                        .trim()
                        .to_ascii_lowercase()
                        .starts_with("ldap://"),
            );
        let connecting = LdapConnAsync::with_settings(settings, self.settings.url.trim());
        let (conn, ldap) = tokio::time::timeout(self.timeout(), connecting)
            .await
            .map_err(|_| LdapError::Unavailable("connect timed out".to_owned()))?
            .map_err(|e| unavailable("connect", e))?;
        // The connection's own task; it ends when the handle is unbound or
        // dropped, so losing it loses nothing.
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::debug!(error = %e, "ldap: connection closed with an error");
            }
        });
        Ok(ldap)
    }
}

fn unavailable(step: &str, e: ldap3::LdapError) -> LdapError {
    LdapError::Unavailable(format!("{step}: {e}"))
}

/// Every value of `attribute` on `entry`, the name compared without regard
/// to case as LDAP does.
fn values(entry: &SearchEntry, attribute: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .flat_map(|(_, values)| values.iter().cloned())
        .collect()
}

/// `template` with `{username}` replaced by `username`, escaped so it can
/// only ever be a value (RFC 4515 §3). Pure.
pub fn user_filter(template: &str, username: &str) -> String {
    template.replace("{username}", &ldap_escape(username))
}

/// The role names `groups` give under `mapping`, sorted and without
/// repeats. Group names compare without regard to case or spaces around
/// their commas, as distinguished names do. Pure.
pub fn roles_for(groups: &[String], mapping: &[LdapGroupRole]) -> Vec<String> {
    let held: Vec<String> = groups.iter().map(|g| normalize_dn(g)).collect();
    let mut roles: Vec<String> = mapping
        .iter()
        .filter(|m| held.contains(&normalize_dn(&m.group)))
        .map(|m| m.role.clone())
        .collect();
    roles.sort();
    roles.dedup();
    roles
}

fn normalize_dn(dn: &str) -> String {
    dn.split(',')
        .map(|part| part.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// The TLS settings: the PEM authorities in `ca`, or the public web roots.
fn tls_config(ca: Option<&[u8]>) -> Result<Arc<ClientConfig>, LdapError> {
    let mut roots = RootCertStore::empty();
    match ca {
        Some(pem) => {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert =
                    cert.map_err(|e| LdapError::Config(format!("auth.ldap.ca_file: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| LdapError::Config(format!("auth.ldap.ca_file: {e}")))?;
            }
            if roots.is_empty() {
                return Err(LdapError::Config(
                    "auth.ldap.ca_file holds no certificate".to_owned(),
                ));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| LdapError::Config(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_config::Secret;

    fn mapping(group: &str, role: &str) -> LdapGroupRole {
        LdapGroupRole {
            group: group.to_owned(),
            role: role.to_owned(),
        }
    }

    fn section() -> LdapSection {
        serde_json::from_value(serde_json::json!({
            "url": "ldaps://127.0.0.1:1",
            "bind_dn": "cn=svc,dc=example,dc=com",
            "bind_password": "service-password",
            "base_dn": "dc=example,dc=com",
            "timeout_secs": 1,
        }))
        .expect("an ldap section")
    }

    #[test]
    fn the_username_can_only_be_a_value() {
        assert_eq!(
            user_filter("(uid={username})", "bob"),
            "(uid=bob)".to_owned()
        );
        assert_eq!(
            user_filter("(uid={username})", "*)(uid=*"),
            "(uid=\\2a\\29\\28uid=\\2a)".to_owned()
        );
        assert_eq!(
            user_filter(
                "(|(sAMAccountName={username})(userPrincipalName={username}))",
                "a\\b"
            ),
            "(|(sAMAccountName=a\\5cb)(userPrincipalName=a\\5cb))".to_owned()
        );
    }

    #[test]
    fn groups_give_the_mapped_roles_once() {
        let mapping = [
            mapping("CN=Sales,OU=Groups,DC=example,DC=com", "Sales"),
            mapping("cn=managers, ou=groups, dc=example, dc=com", "Manager"),
            mapping("CN=Sales Leads,OU=Groups,DC=example,DC=com", "Sales"),
            mapping("CN=Finance,OU=Groups,DC=example,DC=com", "Finance"),
        ];
        let groups = vec![
            "cn=sales,ou=groups,dc=example,dc=com".to_owned(),
            "CN=Managers,OU=Groups,DC=example,DC=com".to_owned(),
            "CN=Sales Leads,OU=Groups,DC=example,DC=com".to_owned(),
            "CN=Other,OU=Groups,DC=example,DC=com".to_owned(),
        ];
        assert_eq!(roles_for(&groups, &mapping), vec!["Manager", "Sales"]);
        assert!(roles_for(&[], &mapping).is_empty());
    }

    #[tokio::test]
    async fn an_empty_password_never_reaches_the_directory() {
        // The directory URL points nowhere: reaching it would be `Unavailable`.
        let directory = Directory::load(&section()).await.expect("loads");
        for (username, password) in [("bob", ""), ("", "pw"), ("  ", "pw"), ("bo\nb", "pw")] {
            assert!(matches!(
                directory.authenticate(username, password).await,
                Err(LdapError::InvalidCredentials)
            ));
        }
        assert!(matches!(
            directory.authenticate("bob", "pw").await,
            Err(LdapError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn plain_ldap_and_a_bad_ca_file_are_refused() {
        let mut plain = section();
        plain.url = "ldap://127.0.0.1:389".to_owned();
        assert!(matches!(
            Directory::load(&plain).await,
            Err(LdapError::Config(_))
        ));
        assert!(matches!(
            tls_config(Some(b"not a certificate")),
            Err(LdapError::Config(_))
        ));
    }

    #[test]
    fn nothing_prints_the_service_password() {
        let s = LdapSection {
            bind_password: Secret::new("service-password".to_owned()),
            ..section()
        };
        let directory = Directory {
            tls: tls_config(None).expect("web roots"),
            settings: s,
        };
        assert!(!format!("{directory:?}").contains("service-password"));
    }
}

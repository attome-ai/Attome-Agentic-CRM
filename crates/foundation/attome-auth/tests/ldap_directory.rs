//! Q4-T1: `attome_auth::ldap` against a real directory over LDAPS.
//!
//! Needs a throwaway OpenLDAP with the memberOf overlay, e.g.
//!
//! ```text
//! docker run -d --name attome-ldap-test --hostname localhost -p 6636:636 \
//!   -e LDAP_DOMAIN=example.test -e LDAP_ADMIN_PASSWORD=admin-test-pw \
//!   osixia/openldap:1.5.0
//! docker exec attome-ldap-test cat /container/service/slapd/assets/certs/ca.crt > ldap-ca.crt
//! ```
//!
//! then `TEST_LDAP_URL=ldaps://localhost:6636 TEST_LDAP_CA_FILE=ldap-ca.crt
//! TEST_LDAP_ADMIN_PASSWORD=admin-test-pw cargo test -p attome-auth --test
//! ldap_directory`. Without `TEST_LDAP_URL` every test says so and passes.
//! Each test adds its own uniquely named people and group.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashSet;

use attome_auth::ldap::{Directory, LdapError, roles_for};
use attome_config::{LdapGroupRole, LdapSection};
use ldap3::{LdapConnAsync, LdapConnSettings};

struct Env {
    url: String,
    ca_file: String,
    admin_dn: String,
    admin_password: String,
    base_dn: String,
}

fn env() -> Option<Env> {
    let url = std::env::var("TEST_LDAP_URL").ok()?;
    Some(Env {
        url,
        ca_file: std::env::var("TEST_LDAP_CA_FILE").expect("TEST_LDAP_CA_FILE"),
        admin_dn: std::env::var("TEST_LDAP_ADMIN_DN")
            .unwrap_or_else(|_| "cn=admin,dc=example,dc=test".to_owned()),
        admin_password: std::env::var("TEST_LDAP_ADMIN_PASSWORD")
            .expect("TEST_LDAP_ADMIN_PASSWORD"),
        base_dn: std::env::var("TEST_LDAP_BASE_DN")
            .unwrap_or_else(|_| "dc=example,dc=test".to_owned()),
    })
}

macro_rules! directory_env {
    () => {
        match env() {
            Some(env) => env,
            None => {
                eprintln!("TEST_LDAP_URL is not set; skipping");
                return;
            }
        }
    };
}

fn section(env: &Env) -> LdapSection {
    serde_json::from_value(serde_json::json!({
        "url": env.url,
        "ca_file": env.ca_file,
        "bind_dn": env.admin_dn,
        "bind_password": env.admin_password,
        "base_dn": env.base_dn,
        "user_filter": "(uid={username})",
        "timeout_secs": 5,
    }))
    .expect("an ldap section")
}

struct Person {
    uid: String,
    dn: String,
    email: String,
    group_dn: String,
}

/// Adds a person with `password`, and a group holding them, under `env`'s
/// base, both named for this test alone.
async fn seed(env: &Env, password: &str) -> Person {
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let uid = format!("user-{tag}");
    let dn = format!("uid={uid},{}", env.base_dn);
    let email = format!("{uid}@example.test");
    let group_dn = format!("cn=sales-{tag},{}", env.base_dn);

    let tls = Directory::load(&section(env))
        .await
        .expect("directory")
        .tls_config_for_tests();
    let settings = LdapConnSettings::new().set_config(tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &env.url)
        .await
        .expect("connect");
    tokio::spawn(async move { conn.drive().await });
    ldap.simple_bind(&env.admin_dn, &env.admin_password)
        .await
        .expect("admin bind")
        .success()
        .expect("admin bind accepted");
    ldap.add(
        &dn,
        vec![
            ("objectClass", HashSet::from(["inetOrgPerson"])),
            ("uid", HashSet::from([uid.as_str()])),
            ("cn", HashSet::from([uid.as_str()])),
            ("sn", HashSet::from(["Test"])),
            ("mail", HashSet::from([email.as_str()])),
            ("userPassword", HashSet::from([password])),
        ],
    )
    .await
    .expect("add person")
    .success()
    .expect("person added");
    let cn = format!("sales-{tag}");
    ldap.add(
        &group_dn,
        vec![
            ("objectClass", HashSet::from(["groupOfUniqueNames"])),
            ("cn", HashSet::from([cn.as_str()])),
            ("uniqueMember", HashSet::from([dn.as_str()])),
        ],
    )
    .await
    .expect("add group")
    .success()
    .expect("group added");
    let _ = ldap.unbind().await;
    Person {
        uid,
        dn,
        email,
        group_dn,
    }
}

#[tokio::test]
async fn q4_the_right_password_signs_in_with_email_and_groups() {
    let env = directory_env!();
    let person = seed(&env, "correct horse").await;
    let directory = Directory::load(&section(&env)).await.expect("directory");

    let found = directory
        .authenticate(&person.uid, "correct horse")
        .await
        .expect("signed in");
    assert!(found.dn.eq_ignore_ascii_case(&person.dn));
    assert_eq!(found.email.as_deref(), Some(person.email.as_str()));
    assert!(
        found
            .groups
            .iter()
            .any(|g| g.eq_ignore_ascii_case(&person.group_dn)),
        "memberOf lists the group: {:?}",
        found.groups
    );

    let mapping = [LdapGroupRole {
        group: person.group_dn.to_uppercase(),
        role: "Sales".to_owned(),
    }];
    assert_eq!(roles_for(&found.groups, &mapping), vec!["Sales"]);
}

#[tokio::test]
async fn q4_a_wrong_password_an_unknown_name_and_a_wildcard_are_refused() {
    let env = directory_env!();
    let person = seed(&env, "correct horse").await;
    let directory = Directory::load(&section(&env)).await.expect("directory");

    for (username, password) in [
        (person.uid.as_str(), "wrong"),
        (person.uid.as_str(), ""),
        ("nobody-at-all", "correct horse"),
        ("*", "correct horse"),
        ("user-*", "correct horse"),
    ] {
        assert!(
            matches!(
                directory.authenticate(username, password).await,
                Err(LdapError::InvalidCredentials)
            ),
            "{username:?} with {password:?} must be refused"
        );
    }
}

#[tokio::test]
async fn q4_a_certificate_from_an_unknown_authority_is_refused() {
    let env = directory_env!();
    let mut untrusted = section(&env);
    untrusted.ca_file = None; // the public web roots never signed the test CA
    let directory = Directory::load(&untrusted).await.expect("directory");
    assert!(matches!(
        directory.authenticate("anyone", "anything").await,
        Err(LdapError::Unavailable(_))
    ));
}

#[tokio::test]
async fn q4_a_refused_service_account_is_unavailable_not_a_wrong_password() {
    let env = directory_env!();
    let mut wrong = section(&env);
    wrong.bind_password = attome_config::Secret::new("not-the-password".to_owned());
    let directory = Directory::load(&wrong).await.expect("directory");
    assert!(matches!(
        directory.authenticate("anyone", "anything").await,
        Err(LdapError::Unavailable(_))
    ));
}

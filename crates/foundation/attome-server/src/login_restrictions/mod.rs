//! Q9-T1: where and when a person may sign in, from the roles they hold.
//!
//! Each role may restrict sign-in three ways: a network allow-list
//! (`role.ip_allowlist`, the same list `middleware::auth` enforces on every
//! request), working hours (a Z12 business calendar, `role_auth_policy.
//! login_calendar_ref`) and countries (`role_auth_policy.allowed_countries`,
//! ISO 3166 alpha-2 codes looked up in the offline [`geoip`] database).
//!
//! Each kind is checked on its own over the roles that set it, and the
//! roles that set it add up: a sign-in passes the network check when the
//! address is in any restricting role's list, the hours check when any
//! restricting role's calendar is working now, and the country check when
//! the address's country is in any restricting role's list. A role that
//! does not set a kind never loosens one that does. A person with no
//! restricting role is unaffected.
//!
//! Every check fails closed: an unknown caller address fails the network and
//! country checks, a calendar that cannot be loaded counts as closed (the
//! loader passes `Some(false)`), and a country rule with no GeoIP database
//! configured, or an address the database does not know, refuses.
//!
//! This module only decides. The roles are read by
//! `attome_security::sign_in_rules`; the refusal is enforced where a session
//! is issued, so password, MFA, OIDC and Google sign-ins all pass through it.

pub mod geoip;

use std::net::IpAddr;

use crate::middleware::ip_allowlist;

/// One held role's sign-in restrictions. An empty list, or `None` hours,
/// means the role does not restrict that kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleSignInRule {
    /// CIDR entries or bare addresses (`role.ip_allowlist`).
    pub networks: Vec<String>,
    /// Whether the role's sign-in calendar is working at the moment of the
    /// attempt; `None` when the role sets no calendar.
    pub within_hours: Option<bool>,
    /// ISO 3166 alpha-2 country codes, any case.
    pub countries: Vec<String>,
}

/// Why a sign-in was refused, in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Network,
    Hours,
    Country,
}

impl Refusal {
    /// A stable label for logs, metrics and the audit event's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Hours => "hours",
            Self::Country => "country",
        }
    }
}

/// Decides one sign-in. `country` is asked at most once, and only when a
/// role restricts countries.
pub fn evaluate(
    rules: &[RoleSignInRule],
    caller_ip: Option<IpAddr>,
    country: impl FnOnce(IpAddr) -> Option<String>,
) -> Result<(), Refusal> {
    let networks: Vec<&Vec<String>> = rules
        .iter()
        .map(|r| &r.networks)
        .filter(|list| !list.is_empty())
        .collect();
    if !networks.is_empty()
        && !caller_ip.is_some_and(|ip| networks.iter().any(|l| ip_allowlist::ip_in_any(ip, l)))
    {
        return Err(Refusal::Network);
    }

    let hours: Vec<bool> = rules.iter().filter_map(|r| r.within_hours).collect();
    if !hours.is_empty() && !hours.iter().any(|open| *open) {
        return Err(Refusal::Hours);
    }

    let countries: Vec<&String> = rules.iter().flat_map(|r| &r.countries).collect();
    if !countries.is_empty() {
        let found = caller_ip.and_then(country);
        let allowed =
            found.is_some_and(|code| countries.iter().any(|c| c.eq_ignore_ascii_case(&code)));
        if !allowed {
            return Err(Refusal::Country);
        }
    }
    Ok(())
}

/// True when `code` is two ASCII letters, the shape a country rule takes.
pub fn is_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn no_country(_: IpAddr) -> Option<String> {
        None
    }

    fn rule(networks: &[&str], within_hours: Option<bool>, countries: &[&str]) -> RoleSignInRule {
        RoleSignInRule {
            networks: networks.iter().map(|s| (*s).to_owned()).collect(),
            within_hours,
            countries: countries.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn login_restrictions_none_set_allows_everything() {
        assert_eq!(evaluate(&[], None, no_country), Ok(()));
        assert_eq!(
            evaluate(&[rule(&[], None, &[])], ip("198.51.100.1"), no_country),
            Ok(())
        );
    }

    #[test]
    fn login_restrictions_network_lists_add_up() {
        let rules = [
            rule(&["10.0.0.0/8"], None, &[]),
            rule(&["192.0.2.7"], None, &[]),
        ];
        assert_eq!(evaluate(&rules, ip("10.1.2.3"), no_country), Ok(()));
        assert_eq!(evaluate(&rules, ip("192.0.2.7"), no_country), Ok(()));
        assert_eq!(
            evaluate(&rules, ip("198.51.100.1"), no_country),
            Err(Refusal::Network)
        );
    }

    #[test]
    fn login_restrictions_unknown_address_fails_closed() {
        let rules = [rule(&["10.0.0.0/8"], None, &[])];
        assert_eq!(evaluate(&rules, None, no_country), Err(Refusal::Network));
        let rules = [rule(&[], None, &["SA"])];
        assert_eq!(
            evaluate(&rules, None, |_| Some("SA".into())),
            Err(Refusal::Country)
        );
    }

    #[test]
    fn login_restrictions_unrestricted_role_does_not_loosen() {
        let rules = [
            rule(&["10.0.0.0/8"], Some(false), &[]),
            rule(&[], None, &[]),
        ];
        assert_eq!(
            evaluate(&rules, ip("198.51.100.1"), no_country),
            Err(Refusal::Network)
        );
        assert_eq!(
            evaluate(&rules, ip("10.0.0.1"), no_country),
            Err(Refusal::Hours)
        );
    }

    #[test]
    fn login_restrictions_outside_hours_is_refused() {
        assert_eq!(
            evaluate(&[rule(&[], Some(false), &[])], None, no_country),
            Err(Refusal::Hours)
        );
        // One restricting role open now is enough.
        let rules = [rule(&[], Some(false), &[]), rule(&[], Some(true), &[])];
        assert_eq!(evaluate(&rules, None, no_country), Ok(()));
    }

    #[test]
    fn login_restrictions_country_rules() {
        let rules = [rule(&[], None, &["sa"]), rule(&[], None, &["AE"])];
        assert_eq!(
            evaluate(&rules, ip("203.0.113.1"), |_| Some("SA".into())),
            Ok(())
        );
        assert_eq!(
            evaluate(&rules, ip("203.0.113.1"), |_| Some("AE".into())),
            Ok(())
        );
        assert_eq!(
            evaluate(&rules, ip("203.0.113.1"), |_| Some("EG".into())),
            Err(Refusal::Country)
        );
        // No database, or an address it does not know.
        assert_eq!(
            evaluate(&rules, ip("203.0.113.1"), no_country),
            Err(Refusal::Country)
        );
    }

    #[test]
    fn login_restrictions_country_lookup_only_when_needed() {
        let rules = [rule(&["10.0.0.0/8"], None, &[])];
        let asked = std::cell::Cell::new(false);
        let r = evaluate(&rules, ip("10.0.0.1"), |_| {
            asked.set(true);
            None
        });
        assert_eq!(r, Ok(()));
        assert!(!asked.get());
    }

    #[test]
    fn login_restrictions_country_code_shape() {
        assert!(is_country_code("SA"));
        assert!(is_country_code("ae"));
        assert!(!is_country_code("SAU"));
        assert!(!is_country_code("1A"));
    }
}

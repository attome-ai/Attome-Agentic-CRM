//! M03 (Security & Identity) gap 2 / D-434 — per-role and per-API-key IP
//! allow-listing (`xrm_core_role.ip_allowlist`/`api_key.ip_allowlist`,
//! migration `0225_ip_allowlist.sql`).
//!
//! This module is pure CIDR matching only — no database, no request/state
//! knowledge. It exists so `middleware::auth` (where the actual enforcement
//! lives, immediately after each auth method resolves an identity — see that
//! module's `resolve_api_key` and `authn`'s cookie branch) has a single,
//! unit-tested primitive to call rather than hand-rolling prefix math at each
//! call site. The parsing and prefix math are attome-config's
//! (`attome_config::parse_ip_network`/`cidr_contains`, cleanup 3.6), the one
//! CIDR implementation in the workspace: an entry is `"a.b.c.d/nn"`,
//! `"host:.../nn"`, or a bare address (a full-length prefix). A malformed
//! entry is treated as "does not match," never as "matches everything," so a
//! typo'd CIDR in the allow-list fails closed instead of silently widening
//! access.

use std::net::IpAddr;

/// True iff `ip` falls inside the CIDR range `entry` describes. A malformed
/// `entry` never matches (fail closed). An IPv4-mapped IPv6 caller against a
/// plain IPv4 entry (or vice versa) is never implicitly widened — the two
/// families must match exactly as configured; an operator who wants to allow
/// both writes both forms explicitly.
pub(crate) fn cidr_matches(ip: IpAddr, entry: &str) -> bool {
    attome_config::cidr_contains(entry, ip)
}

/// True iff `ip` matches at least one entry in `allowlist`. An empty list is
/// never passed here — callers only invoke this once they've already
/// confirmed the list is non-empty (see `middleware::auth`), since an empty
/// or absent `ip_allowlist` column means "no restriction," a decision made
/// by the caller before reaching this function.
pub fn ip_in_any(ip: IpAddr, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| cidr_matches(ip, entry))
}

/// Validates a caller-supplied CIDR list at admin-write time (role/api-key
/// create/update handlers) — every entry must parse, so a typo is rejected
/// at save time rather than silently never matching at request time. Returns
/// the first invalid entry found, if any.
pub fn validate_cidr_list(entries: &[String]) -> Result<(), String> {
    for entry in entries {
        if attome_config::parse_ip_network(entry).is_none() {
            return Err(format!("'{entry}' is not a valid CIDR or IP address"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ipv4_address_matches_only_itself() {
        let ip: IpAddr = "203.0.113.4".parse().unwrap();
        assert!(cidr_matches(ip, "203.0.113.4"));
        assert!(!cidr_matches(ip, "203.0.113.5"));
    }

    #[test]
    fn ipv4_prefix_matches_every_address_in_range() {
        let network = "10.0.0.0/8";
        assert!(cidr_matches("10.1.2.3".parse().unwrap(), network));
        assert!(cidr_matches("10.255.255.255".parse().unwrap(), network));
        assert!(!cidr_matches("11.0.0.1".parse().unwrap(), network));
    }

    #[test]
    fn ipv4_slash_32_matches_only_the_exact_address() {
        assert!(cidr_matches(
            "203.0.113.4".parse().unwrap(),
            "203.0.113.4/32"
        ));
        assert!(!cidr_matches(
            "203.0.113.5".parse().unwrap(),
            "203.0.113.4/32"
        ));
    }

    #[test]
    fn ipv4_slash_0_matches_everything() {
        assert!(cidr_matches("1.2.3.4".parse().unwrap(), "0.0.0.0/0"));
        assert!(cidr_matches(
            "255.255.255.255".parse().unwrap(),
            "0.0.0.0/0"
        ));
    }

    #[test]
    fn ipv6_prefix_matches_in_range() {
        let network = "2001:db8::/32";
        assert!(cidr_matches("2001:db8::1".parse().unwrap(), network));
        assert!(!cidr_matches("2001:db9::1".parse().unwrap(), network));
    }

    #[test]
    fn bare_ipv6_address_matches_only_itself() {
        assert!(cidr_matches("2001:db8::7".parse().unwrap(), "2001:db8::7"));
        assert!(!cidr_matches("2001:db8::8".parse().unwrap(), "2001:db8::7"));
    }

    #[test]
    fn ipv6_slash_128_matches_only_the_exact_address() {
        assert!(cidr_matches("::1".parse().unwrap(), "::1/128"));
        assert!(!cidr_matches("::2".parse().unwrap(), "::1/128"));
    }

    #[test]
    fn a_malformed_entry_never_matches() {
        assert!(!cidr_matches("1.2.3.4".parse().unwrap(), "not-a-cidr"));
        assert!(!cidr_matches("1.2.3.4".parse().unwrap(), "1.2.3.4/99"));
        assert!(!cidr_matches("1.2.3.4".parse().unwrap(), "1.2.3.4/-1"));
        assert!(!cidr_matches("1.2.3.4".parse().unwrap(), ""));
    }

    #[test]
    fn ipv4_and_ipv6_families_never_cross_match() {
        assert!(!cidr_matches("1.2.3.4".parse().unwrap(), "::/0"));
        assert!(!cidr_matches("::1".parse().unwrap(), "0.0.0.0/0"));
    }

    #[test]
    fn ip_in_any_matches_any_single_entry() {
        let list = vec!["10.0.0.0/8".to_string(), "203.0.113.4/32".to_string()];
        assert!(ip_in_any("203.0.113.4".parse().unwrap(), &list));
        assert!(ip_in_any("10.5.5.5".parse().unwrap(), &list));
        assert!(!ip_in_any("8.8.8.8".parse().unwrap(), &list));
    }

    #[test]
    fn validate_cidr_list_rejects_the_first_bad_entry() {
        let ok = vec!["10.0.0.0/8".to_string(), "203.0.113.4".to_string()];
        assert!(validate_cidr_list(&ok).is_ok());

        let bad = vec!["10.0.0.0/8".to_string(), "garbage".to_string()];
        let err = validate_cidr_list(&bad).unwrap_err();
        assert!(err.contains("garbage"));
    }

    #[test]
    fn validate_cidr_list_accepts_an_empty_list() {
        assert!(validate_cidr_list(&[]).is_ok());
    }
}
